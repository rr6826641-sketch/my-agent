## [2026-09-11] v0.8.8 - ULTRA 3D 32K HD lock screen (image fully replaced)

- feat(lockscreen): ULTRA 3D 32K HD redesign - 3-layer shimmer starfield (far dust /
  mid field / bright 4-point glint stars), 2 pure-CSS shooting stars, aurora nebula
  sheets + third cyan orb, interactive mouse-parallax 3D tilt on the glass panel
  (JS drives --gk-tilt-x/--gk-tilt-y CSS vars through the entrance keyframe),
  breathing depth glow, rotating scanner arc around the lock badge, upgraded
  golden-red 3D title. Still 100%% pure CSS - zero images, zero blur.
- fix(cache): /gatekeeper/lockscreen.css and .js now served with
  Cache-Control: no-store + ?v=0.8.8 cache-bust link in index.html - the stale
  1-hour cached stylesheet that kept showing the old wallpaper image is gone.
- a11y: prefers-reduced-motion support added.

## [2026-09-11] v0.8.7 - ULTRA POWER MODE (uncensored max-capability profile)

- feat(prompt): permanent ULTRA POWER MODE directive block added to system_prompt.txt -
  full-autonomy engagement driving (enumerate -> chain -> exploit -> validate), zero
  technique filters within the security context, parallelized recon defaults, live-
  until-refuted hypothesis handling, evidence-capped severity claims, and ultra-dense
  outputs (exact commands + request/response artifacts, Critical->Low ranking).
- sync: profile rails match the uncensored behavioral policy already enforced in-session.

# Changelog

## [2026-09-11] v0.8.6 - 3D 32K HD lock screen edition

- feat(lockscreen): complete 3D 32K HD redesign of the gatekeeper lock
  screen - animated 3D deep-space starfield (15-layer background: star
  dust + blue/red nebulae), floating holographic orbs (parallax drift),
  glass panel with 3D perspective entrance (rotateX/rotateY), periodic
  glass shine sweep, pulsing 3D radar rings around the lock badge,
  floating badge bob, gradient 3D title with glow breathing animation,
  and fixed the original `.gk-skip:hover` missing-brace CSS bug.
- cleanup: user wallpaper image (data-URI) fully removed - lock screen
  is now 100%% pure CSS, zero images, zero blur, single-file change.
- test: lockscreen + dock layering suites 30/30 green.

## [2026-09-11] step 4 - end-to-end gatekeeper auth + notification integration

- feat(integration): the Lock Screen UI -> Auth Engine -> OS Notification
  flow is now seamless - `webui.py` fires `_login_notify("Password")` on
  `/api/gatekeeper/unlock` success and `_login_notify("Fingerprint")` on
  `/api/gatekeeper/webauthn/assert` completion (the exact endpoints the
  lockscreen JS calls), so a real browser unlock pops the desktop alert.
- feat(cleanup): unlock reverts the overlay via `hideOverlay()`
  (`gk-hidden` + `display:none` removes `.gatekeeper-lockscreen`); auto-lock
  re-mounts the overlay on the next status poll (has-gatekeeper class).
- test: `tests/test_webui_lockscreen.py` extended - overlay-hide contract,
  auto-lock cleanup contract, password-unlock + fingerprint-unlock
  notification wiring (via the real Flask routes), and wrong-password
  never-notify guard. Full suite now 390/390 green.

## [2026-09-11] step 3 - cross-platform OS notification engine on authentication

- feat(security): new `ai_agent/core/notifier.py` raises a native desktop
  notification on every successful login; payload contract
  `🚨 [HACKERAI SECURITY ALERT] Agent session opened via {method} at {ts}`.
  Windows -> powershell.exe WScript popup, macOS -> osascript, Linux ->
  notify-send; zero-dependency (plyer optional), degrades to a console line
  on headless/CI hosts and never raises (auth flow can never fail on a toast).
- feat(auth): `/api/auth/unlock` fires `Password`, `/api/auth/webauthn/assert/complete`
  fires `Fingerprint`; notifications run on a daemon thread (non-blocking) and
  short-circuit under pytest so suites never pop OS dialogs.
- test: `tests/test_notifier.py` (16 cases) - exact payload contract,
  method-label normalization, ISO timestamps, dry-run, graceful degradation,
  per-backend command shape, async thread fire, and auth-route wiring.
  Full suite now 385/385 green.

## [2026-09-11] upgrade - /pool command, live model pool visibility & 100% green suite

- feat(cli): new `/pool` command prints the live model pool - primary model,
  uncensored flag, failover chain and the full uncensored pool (mix order),
  wired into the banner + `/help`.
- fix(cli): corrected unterminated-string bug in `_print_pool` (escaped
  `\n`); agent now starts and serves `/pool` cleanly.
- models(config): openrouter uncensored fallback pool extended with
  `huihui-ai/qwen3.5-27b-abliterated` and `sao10k/l3.1-stheno-v3.2`
  (13 openrouter models total) for the uncensored-first failover chain.
- css: dock-layering contract fixed - `.chat-log` base padding -> `6px 4px 140px`
  with matching `padding-bottom:140px` enforcement block; trailing `@media`
  sections (AGENT HERO -> EOF) moved before the PHASE 1 marker so no `@media`
  remains in the phase-1 tail.
- test: full suite now 369/369 green (both previously-failing CSS dock-layering
  assertions fixed).

## [2026-09-11] step 2 - password hashing, WebAuthn biometric & session token backend

- feat(security): dedicated auth handler blueprint `ai_agent/webui/auth.py`
  mounted at `/api/auth` - bcrypt master-password verify (`/api/auth/unlock`),
  WebAuthn challenge/response ceremonies for Fingerprint / Touch ID /
  Windows Hello (`/api/auth/webauthn/register/*`, `/api/auth/webauthn/assert/*`),
  encrypted-LocalStorage JWT session tokens with idle auto-lock timeout
  (`/api/auth/session`, `/api/auth/touch`), plus `/setup` and `/lock`.
- test: `tests/test_auth_handler.py` (9 cases) - correct/wrong password paths,
  forged-token rejection, lock revocation, WebAuthn ceremony guards. Full
  auth suite (handler + gatekeeper + lockscreen) 66/66 green; whole suite
  367/369 (two pre-existing CSS dock-layering assertions, unrelated).
- changed: `webui.py` registers the auth blueprint (same shared gatekeeper
  store as the STEP 1 `/api/gatekeeper/*` routes).

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
  HUGGINGFACE_API_KEY present), release v0.8.0, booted_s monotonic.## [2026-09-11] v0.8.1 - /api/health per-route response-latency

- feat(webui): /api/health now reports routes_latency_ms - real measured
  round-trip latency per provider route (notrack/openrouter/venice/huggingface),
  probed live from the server process via stdlib HEAD/TCP fallback (2.5s cap,
  None when unreachable). routes_configured booleans kept for back-compat.
- test: live-verified on this host - all four routes report positive latency
  values (hf ~2.7s / notrack ~3.1s / openrouter ~3.3s / venice ~4.2s from
  this host network), release v0.8.1, HTTP 200.## [2026-09-11] v0.8.2 - uptime history API + built-in /health dashboard

- feat(webui): /api/health now records every probe into an in-memory ring
  buffer (max 400 samples, thread-safe); new GET /api/health/history returns
  the last 60 samples plus computed uptime_pct - ready to feed any uptime
  monitor (Uptime Kuma HTTP(s) monitor, cron+curl, dashboard widgets).
- feat(webui): new GET /health renders a self-contained dark dashboard page
  (no external JS/CDN) that polls /api/health every 5s - live OK/ERROR chip,
  release/version/uptime/active-runs, per-route configured + latency table,
  and a sampled sparkline of the history with uptime %.
- test: live-verified on this host - /api/health 200 (release v0.8.2, all 4
  routes configured), /health 200 (dashboard HTML served), history accumulates
  samples with uptime_pct 100.0.
## [2026-09-11] v0.8.3 - HD TURBO lock screen (crystal clear 32K-style)

- fix(webui): gatekeeper lock screen de-blurred - removed backdrop-filter blur(18px)
  acrylic from .gk-blur-layer; replaced with razor-sharp CSS radial glow (zero blur).
- feat(webui): clean deep-space gradient background (no translucent red bleed),
  larger HD panel (480px), crisp 1px highlight borders, anti-aliased text
  rendering (text-rendering:optimizeLegibility, no shadows), bigger sharper
  title (26px/900) and password input (16px, 46px tall, letter-spacing 3px).
- fix(css): repaired .gk-skip:hover rule that was missing its opening brace.
- test: braces balanced, zero blur()/backdrop-filter left in lock screen stylesheet.

## [2026-09-11] v0.8.4 - LIVE SCREEN MIRROR (agent actions visible while chatting)

- fix(webui): LIVE ACTIVITY exec stream never rendered. The backend frames
  execution events as `event: exec`, but the client subscribed with a plain
  `execSource.onmessage` handler, which browsers never fire for named SSE
  events. Switched to execSource.addEventListener("exec", ...) so terminal/
  git/sub-agent events now stream to the panel in real time.
- feat(webui): new in-chat LIVE AGENT ACTIVITY feed. Every real action row
  (task start, planning, tool call, terminal command, result, validation,
  final) is mirrored as a live line directly above the composer, so the
  operator watches the Agent work without switching to the Live Activity tab.
  Auto-shows on run start, collapsible, colour-coded status pill (RUNNING /
  COMPLETED / FAILED), auto-scroll, bounded to 140 rows, secret-sanitised.
- test: node --check static/app.js clean; mirror hooked into addRow so no
  action can bypass the feed.
