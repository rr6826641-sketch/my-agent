# Changelog

Sare notable changes is project ke. Format: `[Semantic Versioning](https://semver.org/)-style`
(Unreleased / versioned blocks, newest top).

## [Unreleased]

### Added
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
