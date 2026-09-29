# CHANGELOG v22 — Jina AI integration

Date: 2026-09-29
Scope: web search + web fetch pipeline

## Added — Jina AI provider (`ai_agent/tools/jina.py`)
- **Neural web search** via `s.jina.ai` (`jina_search` / `tool_jina_search`).
  Returns ranked, structured results `{title, url, snippet}` with the same
  shape as `web_search.search_web`, so every existing consumer works unchanged.
- **Reader** via `r.jina.ai` (`jina_read` / `tool_jina_read`). Converts any URL
  to clean, LLM-ready markdown; bypasses JS-rendered shells, cookie walls and
  anti-bot blocks (403/429). Works keyless at 20 RPM, higher with the key.
- **Grounding** helper via `g.jina.ai` (`jina_ground`) — factual statements
  with sources (opt-in; not registered as a default tool).
- `jina_status` / `tool_jina_status` — reports key presence + endpoints.

## Wired in
- `ai_agent/tools/web_search.py` — Jina is now **backend #0** (priority) inside
  `search_web()` when `JINA_API_KEY` is set; DuckDuckGo (`ddgs` + lite/html
  scrapers) remains the keyless fallback chain. This automatically upgrades
  every tool that routes through `search_web`: `web_search`, `web_search_v2`,
  `research`.
- `ai_agent/tools/web_fetch.py` — `fetch_url` now falls back to the Jina Reader
  when a direct fetch is blocked (401/403/429/503) or returns no readable text
  (JS-only page). Fallback responses carry `"via": "jina-reader"`.
- `ai_agent/tools/__init__.py` — registered `jina_search`, `jina_read`,
  `jina_status` (registry now builds 331 tools; compile + live smoke test pass).

## Config
- `.env` — added `JINA_API_KEY`.
- `.env.example` — documented `JINA_API_KEY` (`jina_your_key_here`).

## Notes
- No new Python dependency (`requests` only).
- Key is read strictly from the environment / `.env`; never logged.
- Failure of any Jina call is non-fatal: structured `{error, results: []}`
  is returned and the DuckDuckGo chain continues — the agent loop cannot crash.

## Validation (live, 2026-09-29)
- `jina_search("OWASP top 10 2021", 3)` -> backend=jina, 3 results.
- `jina_read("https://www.iana.org/help/example-domains")` -> status=ok,
  markdown with links, correct title.
- `search_web(..., 3)` -> backend=jina.
- `create_tools()` -> registry contains `jina_search`, `jina_read`, `jina_status`.
