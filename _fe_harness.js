/* Feature E (v10.7) — VOICE INPUT/OUTPUT smoke harness.
 * Extracts the v10.7 voice <script> block from templates/index.html and runs it in a
 * Node vm with fake DOM / SpeechRecognition / speechSynthesis / fetch / mission stubs.
 * Assertions check grammar parse, mission control dispatch, TTS replies, mute, edge cases.
 */
"use strict";
const fs = require("fs");
const vm = require("vm");

const html = fs.readFileSync("templates/index.html", "utf8");

/* ---------- extract v10.7 voice script block ---------- */
const marker = "/* VOICE INPUT/OUTPUT (v10.7";
const mIdx = html.indexOf(marker);
if (mIdx < 0) { console.error("FATAL: voice block marker not found"); process.exit(1); }
const sIdx = html.lastIndexOf("<script>", mIdx);
const eIdx = html.indexOf("</script>", mIdx);
const code = html.slice(sIdx + "<script>".length, eIdx);
fs.writeFileSync("_fe_block.js", code);

/* ---------- fake DOM ---------- */
function makeEl(tag) {
  const el = {
    tagName: tag, value: "", textContent: "", innerHTML: "", className: "", disabled: false,
    childNodes: [], options: [], onclick: null, style: {},
    classList: { _s: {},
      toggle: function (n, f) { this._s[n] = (f === undefined) ? !this._s[n] : f; },
      contains: function (n) { return !!this._s[n]; } },
    appendChild: function (c) { this.childNodes.push(c); return c; },
    removeChild: function (c) { const i = this.childNodes.indexOf(c); if (i > -1) this.childNodes.splice(i, 1); return c; },
    setAttribute: function () {},
    get firstChild() { return this.childNodes[0]; },
    click: function () { if (typeof this.onclick === "function") this.onclick(); }
  };
  Object.defineProperty(el, "firstChild", { get: function () { return this.childNodes[0]; } });
  return el;
}

/* ---------- fresh sandbox per scenario ---------- */
function buildSandbox(opts) {
  opts = opts || {};
  const reg = {};
  ["#mc-voice", "#mc-voice-mute", "#voice-log", "#voice-st", "#voice-meta", "#mc-select",
   "#mc-start", "#mc-pause", "#mc-kill", "#mc-refresh"].forEach(s => { reg[s] = makeEl("div"); });

  const select = reg["#mc-select"];
  select.options.push({ value: "cpe_test", textContent: "cpe_test" });
  select.value = "cpe_test";
  /* fake-DOM artifact: real browser par <option> children auto-reflect in
     select.options - yahan appendChild ko bhi options mein push karo */
  select.appendChild = function (c) {
    this.childNodes.push(c);
    if (c && c.value !== undefined) this.options.push({ value: c.value, textContent: c.textContent });
    return c;
  };
  /* fake-DOM artifact: makeEl textContent khali hota hai, real HTML button
     text ("🎙 Voice") seed karo */
  reg["#mc-voice"].textContent = "🎙 Voice";

  const clicks = { start: 0, pause: 0, kill: 0, refresh: 0 };
  reg["#mc-start"].onclick = () => { clicks.start++; };
  reg["#mc-pause"].onclick = () => { clicks.pause++; };
  reg["#mc-kill"].onclick = () => { clicks.kill++; };
  reg["#mc-refresh"].onclick = () => { clicks.refresh++; };

  const synth = {
    spoke: [], cancelled: 0,
    speak(u) { this.spoke.push(String(u.text || "")); },
    cancel() { this.cancelled++; },
    getVoices() { return [{ lang: "en-IN" }, { lang: "hi-IN" }]; }
  };
  function FakeUtterance(t) { this.text = t; }
  function FakeSR() { FakeSR.last = this; this.started = false; this.aborted = false; }
  FakeSR.prototype.start = function () { this.started = true; };
  FakeSR.prototype.abort = function () { this.aborted = true; };

  const openUrls = [];
  let confirmReturn = (opts.confirmReturn === undefined) ? true : opts.confirmReturn;
  const fetchCalls = [];
  function fakeFetch(url, o) { fetchCalls.push(url); return Promise.resolve({ json: () => Promise.resolve(opts.fetchResp || { error: "none" }) }); }

  const sandbox = {
    window: {
      SpeechRecognition: opts.noSR ? undefined : FakeSR,
      webkitSpeechRecognition: undefined,
      speechSynthesis: opts.noSynth ? undefined : synth,
      confirm: () => confirmReturn,
      open: (u) => { openUrls.push(u); }
    },
    document: {
      querySelector: (sel) => reg[sel] || null,
      createElement: (t) => makeEl(t)
    },
    fetch: fakeFetch,
    SpeechSynthesisUtterance: FakeUtterance,
    console: console
  };
  sandbox.window.window = sandbox.window;
  sandbox.window.document = sandbox.document;
  sandbox.window.fetch = sandbox.fetch;
  return { sandbox, reg, clicks, spoken: synth.spoke, synth, openUrls, select, fetchCalls, confirmReturn };
}

/* ---------- runner ---------- */
let pass = 0, fail = 0;
const failures = [];
function assert(name, cond) {
  if (cond) { pass++; }
  else { fail++; failures.push(name); }
}
function run(tag, sandbox) {
  try { vm.runInNewContext(code, sandbox, { filename: tag }); return true; }
  catch (e) { assert(tag + "-eval", false); failures.push(tag + " THREW: " + e.message); return false; }
}
function lastSpoken(sb) { return sb.spoken[sb.spoken.length - 1] || ""; }

/* ================= SCENARIO 1 — full support ================= */
{
  const b = buildSandbox({});
  run("S1", b.sandbox);
  const VA = vm.runInNewContext("window.VoiceAssistant || null", b.sandbox);
  assert("S1: VoiceAssistant exposed", !!VA);
  assert("S1: supported=true with SR", VA && VA.supported === true);
  assert("S1: mic initial label", b.reg["#mc-voice"].textContent === "🎙 Voice");

  b.reg["#mc-voice"].onclick();
  assert("S1: rec started", vm.runInNewContext("window.SpeechRecognition.last.started === true", b.sandbox) === true);
  assert("S1: listening class toggled", b.reg["#mc-voice"].classList.contains("v-listening") === true);
  assert("S1: ST listening label", b.reg["#voice-st"].textContent === "listening…");

  vm.runInNewContext("window.SpeechRecognition.last.onresult({results:[[{transcript:'mission cpe_test start karo'}]]})", b.sandbox);
  assert("S1: start button clicked via voice", b.clicks.start === 1);
  assert("S1: spoken confirmation for start", /cpe_test start ho gayi/.test(lastSpoken(b)));
  assert("S1: user line logged", b.reg["#voice-log"].childNodes.length >= 1);
  assert("S1: TTS utterance has no emoji", !/[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}]/u.test(b.synth.spoke[0]));

  vm.runInNewContext("window.VoiceAssistant.handleText('pause karo')", b.sandbox);
  assert("S1: pause button clicked", b.clicks.pause === 1);
  assert("S1: spoken pause confirmation", /cpe_test pause ho gayi/.test(lastSpoken(b)));

  vm.runInNewContext("window.VoiceAssistant.handleText('kill karo')", b.sandbox);
  assert("S1: kill button clicked (confirmed)", b.clicks.kill === 1);
  assert("S1: spoken kill confirmation", /cpe_test kill ho gayi/.test(lastSpoken(b)));

  vm.runInNewContext("window.VoiceAssistant.handleText('stop')", b.sandbox);
  assert("S1: 'stop' maps to kill", b.clicks.kill === 2);

  vm.runInNewContext("window.VoiceAssistant.handleText('report banao')", b.sandbox);
  assert("S1: report URL opened", b.openUrls.indexOf("/api/missions/cpe_test/report") > -1);
  assert("S1: spoken report", /report khol raha/.test(lastSpoken(b)));

  vm.runInNewContext("window.VoiceAssistant.handleText('refresh')", b.sandbox);
  assert("S1: refresh clicked", b.clicks.refresh === 1);

  vm.runInNewContext("window.VoiceAssistant.handleText('help')", b.sandbox);
  assert("S1: help spoken", /Bolo:/.test(lastSpoken(b)));

  vm.runInNewContext("window.VoiceAssistant.handleText('kuch bhi bola')", b.sandbox);
  assert("S1: unknown reply spoken", /Samajh nahi/.test(lastSpoken(b)));

  const spokeBefore = b.spoken.length;
  vm.runInNewContext("window.SpeechRecognition.last.onresult({results:[[{transcript:''}]]})", b.sandbox);
  assert("S1: empty transcript ignored", b.spoken.length === spokeBefore);

  b.reg["#mc-voice"].onclick(); // listening was still true -> stop()
  assert("S1: second click aborts previous rec", vm.runInNewContext("window.SpeechRecognition.last.aborted === true", b.sandbox) === true);
  assert("S1: listening reset on stop", b.reg["#mc-voice"].classList.contains("v-listening") === false);
}

/* ================= SCENARIO 2 — kill cancel ================= */
{
  const b = buildSandbox({ confirmReturn: false });
  run("S2", b.sandbox);
  vm.runInNewContext("window.VoiceAssistant.handleText('mission cpe_test kill karo')", b.sandbox);
  assert("S2: kill NOT clicked when cancelled", b.clicks.kill === 0);
  assert("S2: cancel spoken", /Kill cancel/.test(lastSpoken(b)));
}

/* ================= SCENARIO 3 — unselected mission key ================= */
{
  const b = buildSandbox({});
  run("S3", b.sandbox);
  b.select.value = "";
  vm.runInNewContext("window.VoiceAssistant.handleText('mission 127.0.0.1 start')", b.sandbox);
  assert("S3: IP host key selected", b.select.value === "127.0.0.1");
  assert("S3: start clicked for unselected mission", b.clicks.start === 1);
  assert("S3: option appended for unknown key", b.select.options.some(o => o.value === "127.0.0.1"));
}

/* ================= SCENARIO 4 — no mission selected ================= */
{
  const b = buildSandbox({});
  run("S4", b.sandbox);
  b.select.value = "";
  vm.runInNewContext("window.VoiceAssistant.handleText('start karo')", b.sandbox);
  assert("S4: hint spoken when no mission selected", /Koi mission select nahi/.test(lastSpoken(b)));
  assert("S4: no start click", b.clicks.start === 0);
}

/* ================= SCENARIO 5 — status command ================= */
{
  const b = buildSandbox({ fetchResp: { phases: { recon: { status: "done" }, scan: { status: "running" }, vuln: { status: "pending" }, report: { status: "pending" } }, findings_logged: 2 } });
  run("S5", b.sandbox);
  vm.runInNewContext("window.VoiceAssistant.handleText('status batao')", b.sandbox);
  setTimeout(() => {
    const s = lastSpoken(b);
    assert("S5: status spoken has phases", /recon done/.test(s) && /scan running/.test(s));
    assert("S5: status spoken has findings", /Findings logged: 2/.test(s));
    assert("S5: status fetched right URL", b.fetchCalls.indexOf("/api/missions/cpe_test") > -1);
  }, 10);
}

/* ================= SCENARIO 6 — mute toggle ================= */
{
  const b = buildSandbox({});
  run("S6", b.sandbox);
  const before = b.spoken.length;
  vm.runInNewContext("window.VoiceAssistant.toggleMute()", b.sandbox);
  assert("S6: mute label", b.reg["#mc-voice-mute"].textContent === "🔇");
  assert("S6: muted() true", vm.runInNewContext("window.VoiceAssistant.muted() === true", b.sandbox) === true);
  vm.runInNewContext("window.VoiceAssistant.handleText('status batao')", b.sandbox);
  setTimeout(() => {
    assert("S6: no speak while muted", b.spoken.length === before);
    /* fake-DOM timing artifact: unmute ko yahan (async reply ke baad) karo,
       warna synchronous unmute "Voice reply on" pehle hi bol deta hai */
    vm.runInNewContext("window.VoiceAssistant.toggleMute()", b.sandbox);
    assert("S6: unmute label", b.reg["#mc-voice-mute"].textContent === "🔊");
    assert("S6: unmute speaks on-reply", /Voice reply on/.test(lastSpoken(b)));
  }, 10);
}

/* ================= SCENARIO 7 — recognition error + no-SR ================= */
{
  const b = buildSandbox({});
  run("S7", b.sandbox);
  b.reg["#mc-voice"].onclick();
  vm.runInNewContext("window.SpeechRecognition.last.onerror({})", b.sandbox);
  assert("S7: error -> fallback spoken", /Sun nahi paya/.test(lastSpoken(b)));
  assert("S7: listening reset on error", b.reg["#mc-voice"].classList.contains("v-listening") === false);

  const b2 = buildSandbox({ noSR: true });
  run("S7b", b2.sandbox);
  assert("S7b: supported=false without SR", vm.runInNewContext("window.VoiceAssistant.supported === false", b2.sandbox) === true);
  b2.reg["#mc-voice"].onclick();
  assert("S7b: unsupported hint spoken", /supported nahi/.test(lastSpoken(b2)));
  assert("S7b: meta updated", /Chrome\/Edge/.test(b2.reg["#voice-meta"].textContent));
}

/* ================= SCENARIO 8 — no speechSynthesis ================= */
{
  const b = buildSandbox({ noSynth: true });
  run("S8", b.sandbox);
  vm.runInNewContext("window.VoiceAssistant.handleText('mission cpe_test start karo')", b.sandbox);
  assert("S8: command still dispatched without synth", b.clicks.start === 1);
  assert("S8: no throw without synth", true);
}

/* ================= SCENARIO 9 — grammar edge cases ================= */
{
  const b = buildSandbox({});
  run("S9", b.sandbox);
  assert("S9: uppercase+punct normalized", vm.runInNewContext("window.VoiceAssistant.parse('MISSION CPE_TEST START KARO!').action === 'start'", b.sandbox) === true);
  assert("S9: key extracted from mission phrase", vm.runInNewContext("window.VoiceAssistant.parse('mission cpe_test start karo').key === 'cpe_test'", b.sandbox) === true);
  assert("S9: bare IP key", vm.runInNewContext("window.VoiceAssistant.parse('mission 127.0.0.1 start').key === '127.0.0.1'", b.sandbox) === true);
  assert("S9: pause not kill", vm.runInNewContext("window.VoiceAssistant.parse('pause').action === 'pause'", b.sandbox) === true);
  assert("S9: stop -> kill", vm.runInNewContext("window.VoiceAssistant.parse('stop').action === 'kill'", b.sandbox) === true);
  assert("S9: shuru -> start", vm.runInNewContext("window.VoiceAssistant.parse('shuru karo').action === 'start'", b.sandbox) === true);
  assert("S9: band -> kill", vm.runInNewContext("window.VoiceAssistant.parse('band karo').action === 'kill'", b.sandbox) === true);
  assert("S9: restart excluded from start", vm.runInNewContext("window.VoiceAssistant.parse('restart karo').action !== 'start'", b.sandbox) === true);
  assert("S9: empty -> null", vm.runInNewContext("window.VoiceAssistant.parse('   ') === null", b.sandbox) === true);
  assert("S9: raport variant -> report", vm.runInNewContext("window.VoiceAssistant.parse('raport banao').action === 'report'", b.sandbox) === true);
  assert("S9: madad -> help", vm.runInNewContext("window.VoiceAssistant.parse('madad').action === 'help'", b.sandbox) === true);
}

/* ================= SCENARIO 10 — log capped at 50 lines ================= */
{
  const b = buildSandbox({});
  run("S10", b.sandbox);
  for (let i = 0; i < 60; i++) vm.runInNewContext("window.VoiceAssistant.handleText('pause')", b.sandbox);
  assert("S10: log capped at 50", b.reg["#voice-log"].childNodes.length === 50);
}

/* ---------- finish ---------- */
setTimeout(() => {
  console.log("---- Feature E (v10.7) VOICE harness ----");
  console.log("PASS: " + pass + "   FAIL: " + fail);
  if (failures.length) { console.log("FAILURES:"); failures.forEach(f => console.log("  ✗ " + f)); process.exit(1); }
  else { console.log("ALL ASSERTIONS PASS"); }
}, 80);