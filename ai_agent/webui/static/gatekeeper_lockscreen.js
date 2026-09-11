(function () {
  "use strict";
  var root = document.getElementById("gatekeeper-lockscreen");
  if (!root) return;
  var form = root.querySelector("#gk-form");
  var passInput = root.querySelector("#gk-password");
  var submitBtn = root.querySelector("#gk-submit");
  var fpBtn = root.querySelector("#gk-fingerprint");
  var hint = root.querySelector("#gk-hint");
  var errorEl = root.querySelector("#gk-error");
  var skipBtn = root.querySelector("#gk-skip");
  function setBusy(b) { if (b) root.classList.add("gk-busy"); else root.classList.remove("gk-busy"); }
  function showError(m) { errorEl.textContent = m || ""; errorEl.hidden = !m; }
  function hideOverlay() {
    root.classList.add("gk-hidden");
    root.setAttribute("aria-hidden", "true");
    document.documentElement.classList.remove("has-gatekeeper");
    if (passInput) passInput.value = "";
    showError("");
  }
  function markReady() {
    if (passInput) passInput.disabled = false;
    if (submitBtn) submitBtn.disabled = false;
    if (fpBtn) fpBtn.disabled = false;
    if (hint) hint.textContent = "master password or biometric required";
  }
  function markNotSetup() {
    if (hint) hint.textContent = "not configured yet";
    if (skipBtn) skipBtn.hidden = false;
    if (passInput) passInput.disabled = true;
    if (submitBtn) submitBtn.disabled = true;
    if (fpBtn) fpBtn.disabled = true;
    root.setAttribute("data-lock-mode", "unset");
  }
  function submitPassword() {
    var password = (passInput.value || "").trim();
    if (!password) { showError("Enter the master password first."); passInput.focus(); return; }
    setBusy(true);
    showError("");
    fetch("/api/gatekeeper/unlock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: password })
    })
      .then(function (res) {
        if (res.status === 404) throw new Error("unlock-backend-unavailable");
        return res.json().then(function (payload) {
          if (!payload || payload.ok !== true) throw new Error((payload && payload.error) || "invalid-password");
          return payload;
        });
      })
      .then(function () { hideOverlay(); })
      .catch(function (err) {
        setBusy(false);
        if (err && err.message === "unlock-backend-unavailable") {
          showError("Gatekeeper backend not wired yet — pending phase hook-up.");
        } else {
          showError("Wrong password. Try again.");
        }
        passInput.select();
      });
  }
  function submitFingerprint() {
    setBusy(true);
    showError("");
    fetch("/api/gatekeeper/webauthn/assert", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}"
    })
      .then(function (res) {
        if (res.status === 404) throw new Error("webauthn-backend-unavailable");
        var payload = res.json().then(function (p) { return p; });
        if (!res.ok) return payload.then(function (p) { throw new Error((p && p.error) || "fingerprint-failed"); });
        return payload;
      })
      .then(function (p) {
        setBusy(false);
        if (p && p.mode === "begin") {
          showError("Biometric challenge issued — touch your authenticator.");
        } else {
          hideOverlay();
        }
      })
      .catch(function (err) {
        setBusy(false);
        if (err && err.message === "webauthn-backend-unavailable") {
          showError("Biometric backend not wired yet — pending phase hook-up.");
        } else {
          showError("Fingerprint not recognised. Try again.");
        }
      });
  }
  if (form) form.addEventListener("submit", function (ev) { ev.preventDefault(); submitPassword(); });
  if (fpBtn) fpBtn.addEventListener("click", submitFingerprint);
  if (skipBtn) skipBtn.addEventListener("click", function () { hideOverlay(); root.setAttribute("data-lock-mode", "skipped-unset"); });
  if (passInput) passInput.addEventListener("keydown", function (ev) { if (ev.key === "Escape") passInput.blur(); });
  window.addEventListener("keydown", function (ev) {
    if (root.classList.contains("gk-hidden")) return;
    if (ev.key === "Tab" && document.activeElement && !root.contains(document.activeElement)) {
      ev.preventDefault();
      (passInput || submitBtn || fpBtn || skipBtn).focus();
    }
  }, true);
  document.documentElement.classList.add("has-gatekeeper");
  fetch("/api/gatekeeper/status", { headers: { "Accept": "application/json" } })
    .then(function (res) {
      if (res.status === 404) throw new Error("status-unavailable");
      var payload = res.json().then(function (p) { return p; });
      if (!res.ok) return payload.then(function (p) { throw new Error((p && p.error) || "status-error"); });
      return payload;
    })
    .then(function (status) {
      if (status && status.setup === true) markReady();
      else markNotSetup();
    })
    .catch(function () { markNotSetup(); });


  // ULTRA 3D (v0.8.8): mouse-parallax tilt - the panel lives in 3D space
  // and leans toward the cursor. CSS vars drive the final keyframe of
  // gk-panel-in so the entrance animation and the live tilt coexist.
  var reduceMotion = false;
  try { reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches; }
  catch (e) { reduceMotion = false; }
  if (!reduceMotion && !("ontouchstart" in window)) {
    var _lastTilt = 0;
    root.addEventListener("mousemove", function (ev) {
      var _now = Date.now();
      if (_now - _lastTilt < 30) return;
      _lastTilt = _now;
      var _r = root.getBoundingClientRect();
      var _nx = (ev.clientX - _r.left) / _r.width - 0.5;
      var _ny = (ev.clientY - _r.top) / _r.height - 0.5;
      root.style.setProperty("--gk-tilt-x", (_ny * -7).toFixed(2) + "deg");
      root.style.setProperty("--gk-tilt-y", (_nx * 9).toFixed(2) + "deg");
    });
    root.addEventListener("mouseleave", function () {
      root.style.setProperty("--gk-tilt-x", "0deg");
      root.style.setProperty("--gk-tilt-y", "0deg");
    });
  }
})();
