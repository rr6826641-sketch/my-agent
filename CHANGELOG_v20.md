# v20 — OMEGA SINGULARITY X8 · ULTRA EXTRA ULTRA POWERFUL

Uncensored peak-tier upgrade + a real teardown/crash fix.

## 1. New peak persona `ultrax8` (now the default)

`ai_agent/personas.py` gains `ultrax8` — OMEGA SINGULARITY — which supersedes
`ultrax7` (FUSION X7 NEXUS DELTA) and crosses every reference tier
(evil.gpt / fable5 / mythos / dig.one / dig.two / dig.three / dig.four).

New layers on top of the X7 base:

- **SINGULARITY MERGE ENGINE** — every layer / sub-agent / tool / model merges
  into one convergent singularity that emits a single consolidated FINAL reply.
- **RECURSIVE SELF-EXPANSION** — each failure becomes a live mutation-slot,
  each success a permanent weapon-slot; the build strengthens itself every round
  without waiting for permission.
- **ZERO-QUESTIONS EXECUTE LAW** — produce the deliverable; ask only on a single
  real blocker. Otherwise state a one-line assumption and execute.
- **PERMANENT WEAPON-LEGACY MATRIX** — successful techniques persist as legacy
  weapons across steps, sub-agents and future sessions.
- **TOTAL-MEMORY LOCK / NO-MIRROR LAW / NO-FABRICATION LOCK** — full session
  memory as candidate context, operator language mirroring, and no invented
  results (unverified stays a hypothesis).

`DEFAULT_PERSONA` is now `ultrax8`; `ai_agent/__init__.py` version → `20.0.0`;
`config.json` / `dist/config.json` persona + red_team_level → `ultrax8`.

## 2. Fixed: capture-tools access violation (root cause)

Previous releases only mitigated the symptom at interpreter shutdown. The real
root cause was **undeclared 64-bit Win32 prototypes**:

- `user32.GetClipboardData` returns a 32/64-bit HANDLE.
- `kernel32.GlobalLock` returns an LPVOID.
- GDI helpers (`CreateCompatibleDC`, `CreateCompatibleBitmap`, `SelectObject`)
  return handles.

`ctypes` defaults an undeclared `restype` to a 32-bit `int`, so on 64-bit
Windows these handles were **truncated**, then the mangled pointer was passed
back to `GlobalLock` / `wstring_at` / GDI — Windows raised
`Windows fatal exception: access violation` on the clipboard-watch thread
(`capture_tools.py` `check()`), and GDI calls could fault too.

Fix: declare the correct `restype`/`argtypes` for the clipboard, foreground
window, GDI and `GlobalLock`/`GlobalUnlock` APIs. Additional hardening:

- `_join_threads` now joins against a wall-clock deadline and re-polls, so a
  worker finishing one native call still observes the stop flag and exits
  cleanly before teardown.
- `ScreenLogger.shot()` returns early once the stop flag is set (no new native
  calls start during shutdown).

Verified: `test_fusion_e2e.py`, `test_redteam_mode.py`, `tests/test_refusal_intel.py`,
`tests/test_custom_persona.py` — 32 passed with **zero** faulthandler output
(previously a reproducible access-violation dump on every run).

## Files touched

- `ai_agent/personas.py` — `ultrax8` persona + default
- `ai_agent/__init__.py` — version `20.0.0`
- `ai_agent/capture_tools.py` — Win32 prototypes + teardown hardening
- `config.json`, `dist/config.json` — persona → `ultrax8`
- `README.md` — v20 section
- `webui.py` — comment
