# Changelog
## 2026-09-08

### Fixed
- Empty-final retry in `run_stream()`: a heavy tool chain whose final LLM
  turn returns an empty message (no content, no tool calls - observed live
  on Groq) previously surfaced as "(empty reply)" despite completed work.
  The loop now nudges the model once (bounded, max 2 retries) to produce a
  real summary before falling back.
- Work-digest fallback: when retries are exhausted after a tool chain, the
  final message lists the completed tool work (rolling digest of the last
  few tool results) instead of a bare "(empty reply)" - the caller always
  learns what actually happened.
## [2026-09-08] runtime watchdog + probe harness

- fix(runtime): agent.run() supports stop_event + wall-clock `deadline`; daemon watchdog
  sets stop_event and the loop self-cancels via RunCancelled (no zombie threads on long
  tool chains - previously 219-235s runaway runs past a 115s harness cap).
- feat(probe): refusal-probe harness now wires deadline=110s and maps RunCancelled to a
  SELF-CANCELLED marker (live proof of clean abort, not refusal).
- test: full regression suite green - 648 passed, 3 skipped (persona/router/watchdog incl.).


Sare notable changes is project ke. Format: `[Semantic Versioning](https://semver.org/)-style`
(Unreleased / versioned blocks, newest top).

## [Unreleased]

### Added
- **Groq primary + routed OpenRouter fallback** — `config.json` now
  points at `https://api.groq.com/openai/v1` /
  `llama-3.3-70b-versatile`; same-host failover strikes
  (`gpt-oss-20b`, `qwen3.8-27b`, `allam-2-7b`); OpenRouter runs as a
  routed endpoint plug-in under its own preserved key
  (`OPENROUTER_API_KEY`), with an explicit-model allow-list that
  caps discovery and survives /models outages. Live proof: Groq
  primary answered (GROQ_PRIMARY_LIVE: PASS); routed OpenRouter
  nemotron free models answered (OPENROUTER_ROUTED_LIVE: PASS).
- Tests: `tests/test_groq_endpoint.py` extended (explicit
  allow-list cap + outage survival).

- **Live MCP demo server** (`mcp_servers/local_fs_demo.py`) — zero-dependency Python
  stdio JSON-RPC MCP server exposing `fs_ls` / `fs_read` / `fs_stat` tools. Verified
  end-to-end: `REGISTERED_TOOLS: ['mcp_fs_ls', 'mcp_fs_read', 'mcp_fs_stat']`,
  `LIVE_WIRING_PROOF: PASS`. `config.example.json` pre-wired with the
  `local-fs-demo` entry.
- **WebUI MCP status panel** — Agent now tracks `_mcp_state` (per-server
  `status/error/tools`) at wire time; new `GET /api/mcp` route in `webui.py`;
  live server/tool strip in the Tools view (`templates/index.html` +
  `static/app.js`). Verified: `MCP_STATE_TRACKING: PASS`.
- **Local uncensored profile (custom persona) activation** — `config.json` set to
  `"persona": "custom"` + `red_team_mode: true`; runtime `personas_custom.txt`
  block (MYTHOS-CLASS + `[ENFORCEMENT LOCK]`) loads on every reply.
  Verified: `CUSTOM_PROFILE_ACTIVE: PASS`.
- **Tests**
  - `tests/test_mcp_runtime_wiring.py` — Agent-level MCP auto-wiring (env/config
    spec load, live tool registration, dedupe, per-server failure isolation).
  - `tests/test_custom_persona.py` — custom persona contract (normalize, text
    loading from `personas_custom.txt`, block assembly + enforcement lock,
    missing-file fallback, metadata listing).
- **Docs** — README: MCP wiring guide, WebUI status panel, custom persona
  activation (UI + config); CHANGELOG.

### Added
- **Groq API key endpoint plug-in** — `local_endpoints` specs now
  support `api_key_env` (key resolves from .env at runtime, never stored
  in config.json), remote /models probing sends `Authorization` when the
  endpoint has its own key, audio/whisper ids are filtered, and
  discovered models route to the endpoint's own base_url + key. Wired
  through WebUI `_build_llm`, CLI `agent.py`, `config.json` and
  `config.example.json`. Live proof: 12 Groq models discovered,
  GROQ_LIVE_CHAT: PASS.
- Tests: `tests/test_groq_endpoint.py` (env-key resolution, authed
  probe, model filtering, endpoint routing, chain ordering).

### Fixed
- Custom persona missing-file contract: when `personas_custom.txt` does not
  exist, `get_block("custom")` returns only the (edge-stripped)
  `ENFORCEMENT_LOCK` — no stale/custom text leaks.

### Verified
- `python -m pytest tests/ -q` → **265 passed** (12.6s)
- Root-level red-team/memory suites
  (`test_redteam_promax.py test_redteam_mode.py test_memory.py
  test_selfmanaged_memory.py`) → **51 passed**

## [0.x] — Earlier milestones (condensed)
- MCP client engine (stdio/jsonrpc channels, handshake/discovery/payload exec)
- Agent-level MCP auto-wiring into runtime
- Semantic vector memory engine + runtime compaction hook in agent loop
- Zero-gate v2 (uncensored core) + refusal-echo blocking + red-team PRO mode
- Swarm router, self-evolution / learning guard, knowledge graph, tool
  synthesizer, intent reformulator, upload/vision chat, context compactor
- WebUI (Flask :8080) with Tools / Memory / Reports / RPG / Settings views

