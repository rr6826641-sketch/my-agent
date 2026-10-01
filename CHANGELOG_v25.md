# CHANGELOG v25.0.0 — SETTINGS FULL-PAGE REDESIGN (2026-10-01)

## Changed
- **Settings = dedicated full-page panel** (`templates/index.html`, `static/style.css`, `static/app.js`):
  - **Naya "LLM Providers" tab** — provider select, base URL, API key, model select aur
    quick-picks ab General se nikal kar apne dedicated `#pane-llm` me rehte hain, apne
    "Save & Reload Agent" button (`#set-save-llm`) ke saath. Save logic ek hi shared
    `saveAgentSettings(msgEl)` function me refactor hua — dono buttons same validation
    (key/URL mismatch auto-route) flow use karte hain.
  - General tab ab sirf **Behavior** (auto/smart-router, mock, red-team, max iterations)
    aur **Persona** cards rakhta hai; description text update kiya.
  - Tab bar ab **sticky** hai (top of scroll), full-bleed dark gradient ke saath — full-page
    panel feel; panes view ke andar scroll karti hain (page-level scroll nahi).
  - Card grid hardening: `.panel{min-width:0; overflow-wrap:break-word}`, inputs
    `max-width:100%`, quick-picks wrap — cards kabhi track overflow nahi karte, is liye
    Chat composer / sidebar Task Board ke saath koi overlap possible nahi (alag view bhi hai).

## Fixed
- **".env file missing" warning ab dismissible** — banner restructured:
  `<span#env-warn-msg>` (JS text target) + `<button#env-warn-close>` ✕.
  `refreshStatus()` ab poora banner text replace nahi karta; dismissal state
  (`envWarnDismissed` + `envWarnLastText`) yaad rakhta hai — same error dubara
  poll par wapas nahi aata, naya/different error aaye to banner re-arm ho jata hai.
- Compact banner spacing (top-margin 12px, slimmer padding) — header-bar ke neeche
  neatly baithta hai, kisi view ko dhakka nahi deta.

## Notes
- `#set-save` (Behavior panel) ka purana inline listener `saveAgentSettings()` me move
  hua — behavior identical.
- Ye source-level fix hai: `dist/MyAgentUltra.exe` (v24 build) me tab tak nahi dikhega
  jab tak EXE rebuild na ho (v22/v24 wala convention).
