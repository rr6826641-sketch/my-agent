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
