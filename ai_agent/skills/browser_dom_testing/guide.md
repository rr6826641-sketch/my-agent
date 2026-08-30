# Real-Browser DOM, SPA & Client-Side Security Testing

Use the Playwright engine (`browse_page`, `click_element`, `fill_form`,
`take_screenshot`, `capture_network_traffic`) whenever the target renders
content with JavaScript. Raw-HTTP tools cannot see DOM sinks, SPA routes or
client-side auth logic — the browser can.

## 1. When to switch from HTTP to browser testing

| Symptom in HTTP responses                      | Use browser tools                |
|------------------------------------------------|----------------------------------|
| Skeleton HTML, content injected by JS          | `browse_page` + `capture_network_traffic` |
| `location.hash` / `location.search` read by JS | DOM XSS workflow (section 2)     |
| Login/RBAC checks done in JS (client-side)     | `fill_form` auth-bypass flow (4) |
| Forms posting without CSRF token               | CSRF flow verification (5)       |
| `postMessage`, `window.name`, `localStorage`   | DOM XSS source mapping           |

## 2. DOM XSS verification workflow

1. **Map source → sink.** Sources: `location.hash`, `location.search`,
   `document.referrer`, `window.name`, `localStorage/sessionStorage`,
   `postMessage` events. Sinks: `innerHTML`, `outerHTML`, `document.write`,
   `eval`/`Function`/`setTimeout(string)`, `location`/`href` assignment,
   `jQuery .html()/.append()`, `insertAdjacentHTML`.
2. **Deliver the payload in the source.** For hash sources append the raw payload
   after `#` (`browse_page(uri + "#<img src=x onerror=...>")`); for query
   sources URL-encode it in the parameter. Do NOT encode the payload as HTML
   entities — the sink must parse it as markup.
3. **Detect execution** in the `browse_page` result:
   - `console_js_errors` shows thrown exceptions and page errors.
   - DOM mutations: use a payload that changes observable state, e.g.
     `onerror="document.title='XSS-FIRED'"`, then check the returned `title`.
   - `body_preview` shows sink output; `html_size` grows when nodes are injected.
4. **Confirm uniqueness** — the marker must appear only because of your payload.
   Re-run without the payload as a control.
5. **Escalate** in order of impact: `alert(1)` marker → steal
   `localStorage`/cookies via `fetch`/`Image` beacon → keylogging via
   `addEventListener('keydown')` → credential-harvest form injection.

## 3. SPA route & state testing

- Raw `browse_page` only renders the initial route. Click navigation with
  `click_element("#nav button[data-view='admin']")` to reach routes that are
  never requested over the network.
- Verify the state change in the **live page**: after a click, the returned
  `body_preview`/`title` reflects the new route without a page reload.
- Watch API calls with `capture_network_traffic(filter_substring="/api/")` to
  discover route-specific endpoints and the data they expose.
- If the SPA keeps state in `localStorage`, authenticate once via `fill_form`,
  then `browse_page` to deeper routes — no network token needed to spot
  client-side authorization gaps.

## 4. Client-side auth bypass

1. `fill_form` with `{"#username": "admin", "#password": "..."}` plus
   `submit_selector="#login-btn"` — confirm the success state appears in the
   page (`LOGGED_IN`, admin menu, etc.).
2. Inspect what "login" actually set: role flags in `localStorage`, JS
   variables, or DOM classes. If authorization is decided purely client-side,
   that is the bypass: `click_element` on admin-only buttons or reload a
   protected route without credentials.
3. Check whether the backend re-validates: after a client-side "admin" state,
   call the protected APIs and confirm the server enforces authorization, not
   just the frontend.

## 5. CSRF flow verification

1. Locate state-changing forms (profile, transfer, settings).
2. `fill_form` with victim-controlled values + `submit_selector`; then
   `capture_network_traffic(filter_substring="/api/", wait_ms=3000)`.
3. Inspect the captured POST: method, URL, status, and **request headers/body
   for an anti-CSRF token**. No token + SameSite=None/absent cookie +
   session-cookie auth ⇒ CSRF candidate (validate cross-origin in a fresh
   context if the app relies on cookies).
4. Screenshot the flow (`take_screenshot`) as PoC evidence.

## 6. Evidence discipline

- Always `take_screenshot` before/after the trigger — PNG proof of the sink
  output or the admin panel reached.
- Record the exact payload URL and the `console_js_errors` block in the report.
- `close_browser` after the session to free memory (one shared browser session
  is reused across calls).
