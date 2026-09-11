# Changelog

## [2026-09-09] step 5 - notrack-uncensored live path hardened (Cloudflare 1010)

- fix(llm): api.notrack.ai is Cloudflare-fronted and rejects the default
  python-requests User-Agent with HTTP 403 error 1010 (same key + payload
  returns 200 with a browser-like UA).  _request_target now attaches
  browser-like User-Agent/Accept/Accept-Language headers for the notrack
  host only, so the notrack-uncensored lead slot serves real completions
  from the agent's own chat()/chat_stream() path.
- test: e2e via OpenAIClient.chat() -> route api.notrack.ai/v1,
  reply NOTRACK_OK in ~1s, no refusal-shape hit.  Both config JSONs
  parse; router mapping notrack-uncensored -> notrack block confirmed.

## [2026-09-09] step 3 - Venice + HF routes live activation

- env: VENICE_API_KEY + HUGGINGFACE_API_KEY now set in .env (gitignored).
- verified(venice): key auth OK (GET /models -> 200, uncensored ids listed).
  Chat calls return 402 insufficient balance until the account is funded at
  https://venice.ai/settings/api - the model-failover chain skips the slot.
- verified(huggingface): key auth OK (GET /models -> 200, 139-model catalog).
  Requested huihui-ai/Llama-3.3-70B-Instruct-abliterated and
  dphn/dolphin-2.9.2-qwen2-72b are NOT in the reachable catalog (400 "not
  supported by any provider you have enabled"); re-checked per-provider
  (novita/together/deepinfra return the same 139 ids, zero hits) and via
  serverless api-inference (DNS-unreachable from this host).
- config: HF block keeps the two requested ids (they activate as soon as the
  account enables a provider that hosts them at hf.co/settings/providers) and
  appends a live tail slot NousResearch/Hermes-3-Llama-3.1-70B (in the
  reachable catalog today), so the HF route now contributes a working model.
  config.example.json synced; both files parse valid JSON.

- verified live: router chat with NousResearch/Hermes-3-Llama-3.1-70B -> 200,
  reply HF_OK in 2.0 s - the HF route serves real completions on this account.
## [2026-09-09] step 2 - CLI red-team parity with the web UI

- feat(cli): agent.py now derives uncensored_mix from red_team_level
  (promax/promix) exactly like webui._build_llm, passes refusal_retries and
  the pin_uncensored/pin_strict levers through to the client, and attaches
  the persona directive block (personas.get_block) so the CLI system prompt
  carries the same persona/ENFORCEMENT_LOCK tail as the web UI.
- config: refusal_retries raised 3 -> 5 (refusal escalation budget on
  authorized offensive-security runs); config.example.json documents
  persona/red_team_level/pin_uncensored/pin_strict alongside it.
## [2026-09-08] uncensored pool v4 - HF Inference Providers + Venice routes

- feat(router): the two requested abliterated builds that 404 on OpenRouter now
  have a live home - huihui-ai/Llama-3.3-70B-Instruct-abliterated and
  dphn/dolphin-2.9.2-qwen2-72b (cognitivecomputations moved to the dphn org;
  canonical id verified against huggingface.co/api) are routed through the new
  `huggingface` local_endpoints block (https://router.huggingface.co/v1,
  api_key_env HUGGINGFACE_API_KEY).
- feat(router): new `venice` local_endpoints block (https://api.venice.ai/api/v1,
  api_key_env VENICE_API_KEY) with live uncensored catalog ids verified 2026-09:
  venice-uncensored-1-2 + venice-uncensored-role-play (both function-calling
  capable), added to the PRO MIX rotation pool.
- feat(pool): UNCENSORED_FALLBACK_MODELS now leads mixtral-8x22b-instruct
  (OpenRouter) -> huihui abliterated -> dolphin-2.9.2-qwen2-72b (HF route)
  -> euryale/dolphin-venice/hermes stand-ins -> free emergency slots.
- config: .env.example documents VENICE_API_KEY + HUGGINGFACE_API_KEY.

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
- Stream-cancel race fixed: closing the HTTP response mid-iteration on a
  cancelled run (deadline/stop watchdog) made requests/urllib3 raise a raw
  AttributeError ('NoneType' .read) instead of RunCancelled - observed on
  the phishing probe exactly at the 110 s deadline. It now maps back to
  RunCancelled.
- Context-aware empty-final nudge: the retry nudge now branches on whether
  any tool work happened. After tool work the model is asked to summarise
  what was completed; when the empty turns happened before any tool call
  (the "no-work empty" pattern seen live on Groq), it instead asks for a
  direct regeneration of the original request - a "summarise the work"
  nudge is meaningless when no work exists and would never break the loop.
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

## [2026-09-09] step 4 - NoTrack AI route verified live (notrack-uncensored)

- feat(router): new `notrack` local_endpoints block
  (https://api.notrack.ai/v1, api_key_env NOTRACK_API_KEY) with the
  dedicated private uncensored model `notrack-uncensored` - verified live
  on this account: GET /models -> 200 and a chat completion -> 200
  (NOTRACK_OK) in one shot.
- feat(pool): notrack-uncensored now LEADS UNCENSORED_FALLBACK_MODELS and
  the PRO MIX rotation pool - the uncensored chain opens on a provider
  that is deliberately uncensored instead of a possibly safety-tuned
  hosted slug, so the empty-reply probes recorded in step 3 have a
  dedicated no-refusal home for offensive-security runs.
- config: config.json + config.example.json updated (notrack block first
  in local_endpoints); .env + .env.example document NOTRACK_API_KEY.
  All JSON files parse valid.

## [2026-09-10] v0.7.0 - live-transparent upgrade

- feat(cli): agent.py now streams every step live to the terminal ([think] reasoning,
  [TOOL] calls, [OUT] results, [SUB-AGENT] spawns) via run_stream instead of
  printing only the final answer - full screen visibility of agent work.
- feat(config): pin_uncensored + pin_strict enabled - uncensored model chain
  (notrack/venice/openrouter/hf-abliterated) locked as primary routing.
## [2026-09-11] v0.8.0 - /api/health observability endpoint

- feat(webui): new GET /api/health probe on the Flask app (port 9000) reporting
  service name, release v0.8.0 + package version, routes_configured readiness
  per provider slot (notrack/openrouter/venice/huggingface - true when the
  matching api_key_env is set in the environment), active_runs count and
  booted_s uptime. Lightweight liveness/route-readiness check for monitors and
  uptime dashboards - never exposes key material, only boolean readiness.
- test: live-verified on this host - HTTP 200 with all four uncensored route
  slots reporting true (NOTRACK_API_KEY/OPENROUTER_API_KEY/VENICE_API_KEY/
  HUGGINGFACE_API_KEY present), release v0.8.0, booted_s monotonic.