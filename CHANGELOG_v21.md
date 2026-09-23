# v21 — ULTRA OPS PACK · coverage + chain-quality + evidence + reliability

Add-only capability upgrade. Nothing was removed or replaced: the pack adds a
new module and registers new tools into the existing registry.

## 1. New pentest tool module — `ai_agent/tools/ultra_ops.py`

Ten new web/API coverage tools for the gaps the v20 build left thin:

| Tool | What it does |
|---|---|
| `subdomain_takeover` | Dangling-CNAME detection + provider "unclaimed" body fingerprinting (S3, GitHub Pages, Heroku, Azure, Fastly, Netlify, Shopify, ...) |
| `cache_poison_scan` | Web cache poisoning (unkeyed headers) + cache-deception path probe |
| `proto_pollution_test` | Client/server-side prototype pollution (`__proto__` / `constructor[prototype]`) with a unique marker |
| `crlf_inject_test` | CRLF / response-header injection via an `X-Injected` canary |
| `host_header_inject` | Host-header poisoning (reset / cache / routing) |
| `rate_limit_test` | Bounded throttle/lockout mapping (count hard-capped at 50) |
| `ldap_inject_test` | LDAP injection probes with baseline response diffing |
| `xpath_inject_test` | XPath injection (boolean/tautology) probes with baseline diffing |
| `http2_support_check` | ALPN `h2` negotiation recon for scoping a Rapid Reset (CVE-2023-44487) test — the DoS primitive is intentionally NOT performed |
| `param_mine` | Hidden-parameter discovery via response diffing (bounded) |

All HTTP funnels through one bounded helper (`_probe`); bodies are truncated and
hashed so results stay small and reproducible. Nothing destructive or
high-volume: probes are single requests, and `rate_limit_test` is the only loop
(bounded + documented).

## 2. Chain quality, evidence discipline, reliability

- **`chain_quality_score`** — scores an exploit chain `{hops:[...]}` on stage
  coverage, per-hop evidence, prerequisite realism, PoC verification and
  demonstrated impact; returns 0-100 + grade (A-F) + actionable suggestions.
- **`evidence_capture`** — captures a bounded, redacted baseline+exploit
  request/response pair into `evidence/<label>/` with a behavioural diff
  (status / length / body-hash) for the report stage.
- **`evidence_ledger`** — newest-first index of saved evidence bundles.
- **`evidence_redact`** — scrubs secret headers, JWTs, bearer tokens and
  `key=value` secrets (plus extra regexes) from a saved artifact.
- **`retry_probe`** — transient-aware HTTP probe with jittered exponential
  backoff (retries only connection/timeout/5xx/429, never a definitive 4xx).
- **`self_healthcheck`** — registry integrity audit (duplicate names, empty
  descriptions, non-callable handlers, malformed schemas).

## 3. Registry wiring (add-only)

`ai_agent/tools/__init__.py` imports the new functions and appends the 16 new
`Tool(...)` entries before the registry is finalized. No existing import,
tool, or entry was modified or removed.

## 4. Tests

- `test_ultra_ops.py` — 27 pure-logic / no-network tests: redaction + bounding
  helpers, the chain-quality scoring maths (86/B and 100/A paths, error paths),
  the registry healthcheck + schema validation, url/target-required guards, the
  rate-limit hard cap (probe patched), and an evidence capture/ledger/redact
  round-trip on a temp dir.
- Verified: `py -m pytest test_ultra_ops.py -q` → **27 passed**.
- Adjacent suites still green: `test_new_tools.py` + `test_local_exec_layer.py`
  + `test_ultra_ops.py` → **33 passed**. Suite collection: 782 tests.

## 5. Registry total

The built-in tool registry now holds **328** tools (312 before this pack).

## Files touched

- `ai_agent/tools/ultra_ops.py` — new module (add)
- `ai_agent/tools/__init__.py` — imports + 16 REGISTRY entries (add-only)
- `test_ultra_ops.py` — new test suite (add)
- `ai_agent/__init__.py` — version `21.0.0`
- `README.md` — v21 section
- `CHANGELOG_v21.md` — this file
