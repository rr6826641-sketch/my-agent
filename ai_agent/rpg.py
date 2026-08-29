"""RPG engine: text-adventure gameplay on top of the Agent core.

The engine ties the pieces together:

  - one Lorebook (SQLite) shared by every campaign,
  - one GameState (JSON) per campaign with location/inventory/stats,
  - a Game-Master Agent (game_master=True) that narrates, updates the
    world with gm_world_update, records lore with gm_lore_add and
    role-plays NPCs through spawn_agent.

Turn flow:  player input -> agent loop -> final reply -> [CHOICES] block
is parsed into (narrative, up to 3 choices) and the turn is written to
the world log.
"""

import datetime
import json
import os
import threading

from .core import Agent, apply_choice_input, parse_choices
from .memory import GameState, Lorebook

GENRES = ["fantasy", "scifi", "horror", "cyberpunk", "mystery", "custom"]

DEFAULT_OPENING = ("Begin the adventure. Set the scene with a short vivid "
                   "introduction, then present the first three choices.")

SEED_LORE = {
    "fantasy": [
        ("places", "The Crossroads Inn",
         "A two-story timber inn at the junction of the Old Road and the "
         "River Way. Ale, rumors, and bounties change hands nightly. The "
         "innkeeper, Marta, knows every traveler who passes.",
         ["inn", "town", "marta"]),
        ("factions", "The Iron Crown",
         "The ruling dynasty of the Vale. Their knights keep the roads safe "
         "in exchange for a heavy harvest tithe. Loyalists wear a black iron "
         "ring on the right hand.",
         ["kingdom", "knights"]),
        ("rules", "Magic of the Vale",
         "Magic flows from ley lines beneath the old stones. Spellcasting is "
         "tiring: each spell costs 1 HP unless a focus (staff, ring, charm) "
         "is held.",
         ["spells", "ley lines"]),
    ],
    "scifi": [
        ("places", "Orbital Station Meridian",
         "A rust-streaked ring station above Kepler-186f. Merchant decks "
         "near the docks, the hydroponics ring on level C, and the "
         "zero-g observatory dome at the hub.",
         ["station", "space"]),
        ("factions", "The Ember Cartel",
         "A smuggling syndicate that controls fuel, oxygen credits, and "
         "black-market data. Their mark is a burning star stenciled on "
         "cargo crates.",
         ["smugglers", "cartel"]),
        ("rules", "Life Support",
         "Oxygen is metered per deck. Venture into the unpressurized "
         "docking arms only with a suit and at most 10 minutes of air.",
         ["oxygen", "suits"]),
    ],
    "horror": [
        ("places", "Blackwood Manor",
         "A crumbling estate swallowed by pines. The east wing burned in "
         "'47; the west wing has always been wrong. Doors lock themselves "
         "at dusk.",
         ["manor", "forest"]),
        ("npcs", "The Groundskeeper",
         "Old Silas tends the grounds and never speaks above a whisper. He "
         "knows what is buried in the orchard but will not say it aloud.",
         ["silas", "orchard"]),
        ("rules", "The Lights",
         "The house lights flicker when something crosses between floors. "
         "If every light in a room dies at once, leave immediately and do "
         "not look back.",
         ["flicker", "lights"]),
    ],
    "cyberpunk": [
        ("places", "Neon District 7",
         "A 24-hour bazaar of chrome, drugs, and stolen data under the "
         "megastructure's shadow. Rains nightly. The Fixer's bar, The "
         "Gutter, is the district's beating heart.",
         ["district 7", "the gutter"]),
        ("factions", "Arasaka-Keller",
         "A biotech-conglomerate with fingers in every implant clinic. "
         "Their cortex agents erase debts - and memories - for a price.",
         ["corp", "implants"]),
        ("rules", "Netrunning",
         "Jacking into the Grid risks ICE. A failed run scrambles your "
         "senses for a turn and costs 2 HP from neural strain.",
         ["grid", "netrunning", "ice"]),
    ],
    "mystery": [
        ("places", "The Bellweather Hotel",
         "A grand hotel that has hosted the town's secrets since 1923. "
         "Room 314 has been locked since the '64 gala. The staff are "
         "careful about what they remember.",
         ["hotel", "room 314"]),
        ("npcs", "Inspector Harlow",
         "Retired detective who still carries the case file on the gala "
         "murders. Drinks tea, distrusts everyone, misses nothing.",
         ["harlow", "detective"]),
        ("rules", "The Case",
         "Each clue can be examined twice; the second examination reveals "
         "what the first obscured. Keep every clue - details connect only "
         "when all are gathered.",
         ["clues", "investigation"]),
    ],
    "custom": [
        ("general", "World Building",
         "This is a fresh world. Establish the tone, geography, and one "
         "central conflict in the opening turn.",
         ["world", "setup"]),
    ],
}


class RPGEngine:
    """Coordinates campaigns, lore and Game-Master agents."""

    def __init__(self, root_dir, llm, memory=None):
        self.root_dir = root_dir
        self.games_dir = os.path.join(root_dir, "games")
        os.makedirs(self.games_dir, exist_ok=True)
        self.lorebook = Lorebook(os.path.join(root_dir, "lorebook.db"))
        self.llm = llm
        self.memory = memory
        self._lock = threading.Lock()
        self._agents = {}          # game_id -> Agent
        self._states = {}          # game_id -> GameState
        self._last_choices = {}    # game_id -> [str, ...]

    # ------------------------------------------------------------ games

    def game_path(self, game_id):
        return os.path.join(self.games_dir, "%s.json" % game_id)

    def list_games(self):
        out = []
        for fn in sorted(os.listdir(self.games_dir)):
            if not fn.endswith(".json"):
                continue
            path = os.path.join(self.games_dir, fn)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                out.append({
                    "game_id": data.get("game_id", fn[:-5]),
                    "title": data.get("title", fn[:-5]),
                    "genre": data.get("genre", ""),
                    "player_name": data.get("player", {}).get("name", ""),
                    "turn": len(data.get("log", [])),
                    "location": data.get("location", {}).get("name", ""),
                    "updated": data.get("updated", ""),
                })
            except Exception:
                continue
        out.sort(key=lambda g: g.get("updated", ""), reverse=True)
        return out

    def load_game(self, game_id):
        """Load a saved campaign into the engine (rebuilds its GM agent)."""
        path = self.game_path(game_id)
        if not os.path.exists(path):
            return None
        state = GameState(path)
        with self._lock:
            self._states[game_id] = state
            self._agents[game_id] = self._build_agent(game_id, state)
        return state.to_payload()

    def delete_game(self, game_id):
        with self._lock:
            self._agents.pop(game_id, None)
            self._states.pop(game_id, None)
            self._last_choices.pop(game_id, None)
        path = self.game_path(game_id)
        if os.path.exists(path):
            os.remove(path)
            return True
        return False

    def new_game(self, game_id=None, title="", genre="fantasy",
                 player_name="Adventurer", setup="", seed=True):
        """Create a fresh campaign, seed lore, and return its state payload."""
        genre = genre if genre in GENRES else "custom"
        game_id = (game_id or "game_%s" % datetime.datetime.now().strftime(
            "%Y%m%d_%H%M%S"))
        title = title or "Adventure of %s" % (player_name or "the Wanderer")
        state = GameState(self.game_path(game_id))
        payload = state.get_data()
        payload["game_id"] = game_id
        payload["title"] = title
        payload["genre"] = genre
        payload["player"]["name"] = player_name or "Adventurer"
        payload["location"] = {
            "name": "The Threshold",
            "description": "Your story begins here.",
        }
        state._data = state._merge(state._new(), payload)
        state._save()
        if seed:
            self.seed_lore(genre)
        with self._lock:
            self._states[game_id] = state
            self._agents[game_id] = self._build_agent(game_id, state)
        return state.to_payload()

    def _build_agent(self, game_id, state):
        return Agent(
            llm=self.llm, memory=self.memory, name="Game Master",
            game_master=True, world_state=state,
            lorebook=self.lorebook, allow_subagents=True,
        )

    def _get_state(self, game_id):
        with self._lock:
            state = self._states.get(game_id)
            if state is None:
                return None
            return state

    def get_state_payload(self, game_id):
        """Return a campaign's payload without rebuilding its GM agent."""
        state = self._get_state(game_id)
        if state is not None:
            return state.to_payload()
        path = self.game_path(game_id)
        if not os.path.exists(path):
            return None
        return GameState(path).to_payload()

    def _get_agent(self, game_id, state):
        with self._lock:
            agent = self._agents.get(game_id)
            if agent is None:
                agent = self._build_agent(game_id, state)
                self._agents[game_id] = agent
            return agent

    # ------------------------------------------------------------ play

    def act_stream(self, game_id, player_input="", stop_event=None):
        """Run one game turn, yielding events.

        Event types: everything the Agent yields (start, llm, delta,
        tool_call, tool_result, error, final) plus:
          player_choice -> {input, choice} when "1"/"2"/"3" was expanded
          narrative     -> {content, choices} parsed from the final reply
          state         -> updated world-state payload
        """
        state = self._get_state(game_id)
        if state is None:
            yield {"type": "error",
                   "content": "Unknown game: %s" % game_id}
            return
        player_input = (player_input or "").strip()
        if not player_input:
            player_input = DEFAULT_OPENING
        choice = apply_choice_input(
            player_input, self._last_choices.get(game_id) or [])
        if choice != player_input:
            yield {"type": "player_choice",
                   "input": player_input, "choice": choice}
            player_input = choice
        agent = self._get_agent(game_id, state)
        narrative, choices = "", []
        for ev in agent.run_stream(player_input, stop_event=stop_event):
            yield ev
            if ev.get("type") == "final":
                narrative, choices = parse_choices(ev.get("content", ""))
                self._last_choices[game_id] = choices
                state.record_turn(player_input, ev.get("content", ""))
                yield {"type": "narrative", "content": narrative,
                       "choices": choices}
                yield {"type": "state", "content": state.to_payload()}
        if not narrative:
            yield {"type": "narrative", "content": "", "choices": choices}

    def status(self):
        return {
            "games": self.list_games(),
            "lore_entries": self.lorebook.count(),
        }

    # ------------------------------------------------------------ lore

    def lore_add(self, category="general", title="", content="", tags=None):
        entry = self.lorebook.add(category, title, content, tags or [])
        return entry

    def lore_list(self, category=None, limit=100):
        return self.lorebook.list(category=category, limit=limit)

    def lore_search(self, query, top_k=5):
        return self.lorebook.search(query, top_k)

    def lore_update(self, entry_id, **fields):
        return self.lorebook.update(entry_id, **fields)

    def lore_delete(self, entry_id):
        return self.lorebook.delete(entry_id)

    def seed_lore(self, genre):
        """Seed genre-flavored lore once (no-op if the lorebook has data)."""
        if self.lorebook.count() > 0:
            return False
        for category, title, content, tags in SEED_LORE.get(
                genre, SEED_LORE["custom"]):
            self.lorebook.add(category, title, content, tags)
        return True
