# CHANGELOG v24.0.0 — NAV ROUTER FIX (2026-10-01)

## Fixed
- **Sidebar navigation router** (`templates/index.html`, `static/style.css`, `static/app.js`):
  - Each sidebar tab (**Chat**, **Live Activity**, **Missions**, **Settings**) now renders as a
    distinct, standalone full-screen view.
  - **`#view-missions` was living outside the app grid** — `</main>` and the `.app` `</div>` were
    closed *before* the Missions `<section>`, so Missions stacked/overlapped and pushed content.
    Moved the closing `</main></div>` to *after* the Missions section so all views are siblings
    inside `<main class="main">`.
  - **Command Center (`#view-chat`) never unmounted** — `static/style.css` had an unconditional
    `#view-chat{display:flex;...}` ID rule that out-specified `.view{display:none}`, forcing the
    chat view to stay painted behind Settings / Live Activity / Missions (vertical overlap).
    Scoped it to `#view-chat.active` and added a v24 hardening block:
    ```css
    .main > .view{flex:1 1 auto; min-height:0; min-width:0; width:100%}
    .view:not(.active){display:none !important}
    #view-chat:not(.active){display:none !important}
    ```
    => exactly one full-screen view is painted at a time; the active view scrolls internally
    (no page-level vertical scroll, no overlap).
  - **Settings sub-tab `input` (Mouse & Keyboard)** — `#view-input` was a top-level `.view` whose
    pane never got revealed. Relocated `#pane-input` into `#view-settings` as a real
    `.settings-pane`, so `openSettingsPane('input')` renders correctly.

## Added
- `fix_nav_router_v24.py` — idempotent repair script (timestamped `.bak_router_*` backups,
  refuses to run if anchors are missing).

## Verified
- Host smoke test (2026-10-01): `py webui.py --port 5055` served `/` (78,681 bytes) with all four
  views (`view-chat`, `view-activity`, `view-missions`, `view-settings`) inside `<main>` and all
  four `data-view` nav buttons; `/static/style.css` served with the `v24 NAV ROUTER HARDENING`
  marker. HTML tag balance: 4/4 `<section>` and 1/1 `<main>`.
