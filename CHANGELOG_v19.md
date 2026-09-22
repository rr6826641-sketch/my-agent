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
