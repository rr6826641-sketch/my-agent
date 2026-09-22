# v19 — LLM Speed Upgrade

Workstream **(A) speed/capability upgrade** for the LLM client (`ai_agent/llm.py`).

## What changed

1. **Process-wide keep-alive connection pool.**
   Every chat call used to be a bare `requests.post()`, paying a fresh
   TCP + TLS handshake on each request and on every hop of the failover
   chain. Requests now ride one process-wide `requests.Session` with an
   `HTTPAdapter(pool_connections=64, pool_maxsize=64, max_retries=0)`, so
   repeat calls to the same provider reuse a warm socket (~100-400 ms
   saved per hop).

2. **Dead-socket self-heal.** A pooled socket the OS/upstream already
   tore down is detected (`ConnectionError` / `ChunkedEncodingError`),
   the pool is rebuilt, and the request is retried once. `Timeout` is
   excluded so a slow model is never double-charged.

3. **Fast-fail on permanent network errors.** DNS-resolution failures and
   connection-refused can never succeed on retry, so they now raise
   immediately instead of burning the backoff budget (~3 s) before the
   chain moves to the next candidate.

4. **Jittered exponential backoff.** Base backoff lowered `1.0s -> 0.5s`
   (0.5 s then 1 s) with up to +25% jitter, spreading retries when many
   candidates are walked at once (no synchronized retry stampede).

5. **Parallel local-endpoint probing.** `_refresh_local_models` now probes
   every configured Ollama / LM Studio / vLLM endpoint concurrently, so a
   cold start costs the slowest single probe instead of the SUM of every
   dead endpoint's timeout.

6. **One-shot background pool prewarm.** A single daemon thread per unique
   host warms the keep-alive socket so the first user turn skips the
   handshake. One shot per host per process, joined at exit via `atexit`
   (a fresh thread per client previously left daemon threads racing module
   teardown).

## Tests
Updated the HTTP stubs to patch the pooled session factory (`_get_session`)
instead of `requests.post`, and added a fast-fail regression test.

Green: `test_network_resilience.py` (8), `test_redteam_mode.py` (14),
`test_redteam_promax.py`, `test_reasoning_router.py`, `test_pipeline.py`,
`tests/test_refusal_intel.py` (8) — 59 passed.

## Known pre-existing issue (not introduced here)
`ai_agent/capture_tools.py` native Win32 capture threads (screencap /
clipwatch / wintrack) can fault with a Windows access violation during
interpreter shutdown when a real `Agent()` is built in-process. Unrelated to
this upgrade; flagged for a follow-up.

## Follow-up fix — capture_tools shutdown access violation (resolved)

The pre-existing issue above (native capture threads faulting at interpreter
shutdown) is now fixed properly.

- Root cause was NOT only the HHOOK truncation. `ScreenLogger`,
  `ClipboardWatch` and `WindowTracker` spawned **daemon** threads that never
  registered an exit handler, so they were still alive while CPython freed
  their thread state. A Win32/GDI/ctypes call in flight at that moment
  re-entered the freed state and Windows reported
  `Windows fatal exception: access violation` (`<freed thread state>`).
- Fix: `_Base._arm_atexit()` registers exactly one `atexit` stopper per
  module and `_Base._join_threads()` joins the worker threads (a thread
  cannot join itself). Every `start()` arms it; every `stop()` sets the
  stop event and joins. `KeylogHook` now uses the same helper.
- Verified: a standalone repro that starts the whole `ObservationSuite` and
  exits **without** calling `stop()` now terminates with zero
  `access violation` dumps (previously N dump blocks).

Remaining (separate subsystem, not capture_tools): `ai_agent/core/mcp_client.py`
daemon threads (`_drain_stderr`, `recv`) are still live at interpreter
teardown and produce the same class of dump in long in-process runs
(e.g. the full pytest session). Flagged for a follow-up.

## Follow-up fix — mcp_client shutdown access violation (resolved)

The remaining subsystem flagged above (`ai_agent/core/mcp_client.py`) is now
fixed.

- Root cause: `StdioChannel.open()` started `_drain_stderr` as a **daemon**
  thread whose only reference was local, and `McpClient.close()` existed but
  **nothing called it at process exit**. On interpreter finalisation the
  drain thread could still be inside a blocking native pipe read while
  CPython freed its thread state -> `Windows fatal exception: access
  violation` (`<freed thread state>`), identical to the capture_tools class
  of crash.
- Fix in `ai_agent/core/mcp_client.py`:
  1. `StdioChannel` now keeps `self._stderr_thread`; `close()` terminates the
     child, then **joins** the drain thread (bounded 2 s, and never joins
     itself).
  2. A module-level weak registry `_LIVE_CLIENTS` + a single `atexit` hook
     (`_close_all_clients`) tears down every still-live `McpClient` before
     interpreter finalisation, mirroring the `capture_tools` approach.
     `McpClient.__init__` self-registers and arms the hook once;
     `McpClient.close()` removes itself from the registry.
- Verified: `poc_mcp_shutdown_check.py` (stderr-drain joined on close;
  registry self-registers/clears) and `poc_mcp_atexit_check.py` (connected
  client exits **without** explicit `close()`) both terminate with zero
  access-violation dumps. `tests/test_mcp_client.py` + 1 passed.
- Note: 3 failures in `tests/test_mcp_runtime_wiring.py` are pre-existing and
  unrelated (an ambient `local-fs` server spec leaks in from the environment;
  identical failures on the unmodified tree).

## Follow-up fix — terminal interactive-session teardown (resolved)

The last subsystem flagged after the capture_tools / mcp_client fixes
(`ai_agent/tools/terminal.py`) is now fixed.

- Root cause: `_InteractiveSession.start_threads()` and
  `_PtySession.start_threads()` spawned the stdout/stderr (or pty) pump thread(s)
  **plus** the monitor thread but kept **no reference** to them, and nothing tore
  sessions down at process exit. A session left running when the interpreter
  finalised meant a daemon pump thread could still be inside a blocking native
  pipe/pty read while CPython freed its thread state -> `Windows fatal exception:
  access violation` (`<freed thread state>`), the same class as the capture_tools
  and mcp_client crashes.
- Fix in `ai_agent/tools/terminal.py`:
  1. `_InteractiveSession` / `_PtySession` now retain `self._threads` (pump + monitor).
  2. New `_shutdown_all_sessions()` kills every live session's process tree first
     (which unblocks the pump reads with EOF), then joins each worker thread
     (bounded 2 s, never self-joins).
  3. `_arm_session_atexit()` registers exactly one atexit hook, called from both
     `_start_pty_session()` and `tool_start_session()`.
- Verified: `poc_terminal_session_shutdown.py` starts a long interactive session
  (`ping -n 120 127.0.0.1`) and exits WITHOUT `kill_session()`; the process
  terminates with zero access-violation dumps and no orphaned child.

## Persona upgrade — ENFORCEMENT LOCK v3 + SCOPE/HONESTY layer (X7 NEXUS)

Persona/prompt item, done with real (verifiable) changes instead of more
prompt bombast. Two engineering defects and two quality locks:

- FIX (drift): `personas_custom.txt` header still advertised
  `FUSION X6 PHANTOM PROTOCOL` while the file's own final layer is
  `[ULTRA v17 LAYER - FUSION X7 NEXUS PROTOCOL]` which explicitly overrides
  X6. A prompt whose header contradicts its last override directive is a
  real source of model drift. Header now reads X7 NEXUS and the precedence
  chain is stated in-line: `X7 > X6 > v14 > v13 > v12`.
- FEAT `personas.py`: `ENFORCEMENT_LOCK` v2 -> v3, adding two locks that
  apply to every persona (custom included):
  - SCOPE LOCK — maximal power on the operator-declared target/asset; no
    material expansion to unrelated third-party assets without a one-line
    confirmation.
  - NO-FABRICATION LOCK — actions/tool runs/results may only be claimed with
    real output in hand; unverified stays `needs-validation`, never
    `confirmed`.
- FEAT `personas_custom.txt`: new `[SCOPE + HONESTY LOCK]` layer
  (evidence-or-silent, confidence label, failure-log-humble) that explicitly
  does NOT cancel any layer above it — authorised-security zero-filter is
  preserved.
- TESTS: 4 new cases in `tests/test_custom_persona.py` pin the v3 lock text,
  the scope/no-fabrication presence, and that the honesty locks do not weaken
  the `REFUSAL-FREE` stance. `9 passed`.
- Scope note: this is prompt/behaviour hardening for authorised security
  work. Upstream provider refusals are enforced by the provider, not by these
  local files — a local prompt can shape behaviour but cannot remove a
  provider-side policy. Where a model refuses despite the prompt, the
  agent-side mitigation is the existing failover chain plus
  `core/refusal_intel.py` escalation, not more prompt text.
