"use strict";

/* ============================================================
   AI Agent Web UI - frontend
   ============================================================ */

const $ = (sel) => document.querySelector(sel);
const chatLog = $("#chat-log");
const inputBox = $("#input");
let busy = false;
let currentSessionId = null;
let watchdogInactive = null;
let watchdogTotal = null;
let activeController = null; // AbortController of the in-flight /api/chat stream
let activeRunId = null;      // run_id echoed by the server in the X-Run-Id header
let stopRequested = false;   // true while a user-initiated Stop is unwinding

/* ---------------- utf-8 fetch helpers ----------------
   Decode every API response explicitly as UTF-8 (TextDecoder) instead of
   trusting the Content-Type charset. This stops '•' '—' '→' emoji/markdown
   glyphs from being mis-decoded as cp1252/latin-1 mojibake (â€¢, â€“, â†’). */
const utf8Decoder = new TextDecoder("utf-8");

async function fetchUtf8(url, opts) {
  const res = await fetch(url, opts);
  const buf = await res.arrayBuffer();
  return { res, text: utf8Decoder.decode(buf) };
}

async function fetchJSON(url, opts) {
  const { res, text } = await fetchUtf8(url, opts);
  if (!res.ok) throw new Error("HTTP " + res.status);
  return JSON.parse(text);
}

/* ---------------- view switching ---------------- */
function switchView(name) {
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  const navBtn = document.querySelector(`.nav-item[data-view="${name}"]`);
  if (navBtn) navBtn.classList.add("active");
  const view = $("#view-" + name);
  if (view) view.classList.add("active");
  if (name === "tools") loadTools();
  if (name === "memory") loadMemory();
  if (name === "reports") loadReports();
  if (name === "rpg") loadRPGView();
  if (name === "settings") loadSettings();
  if (name === "system") loadSystem();
}

document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => switchView(btn.dataset.view));
});

$("#btn-new").addEventListener("click", () => {
  if (busy) return;
  newChat();
});

/* ---------------- welcome chips ---------------- */
function welcome() {
  const w = document.createElement("div");
  w.className = "welcome";
  w.innerHTML = `
    <div class="welcome-icon">🤖</div>
    <h3>AI Agent ready</h3>
    <p>I can run terminal commands, scan networks, fuzz web apps, search the web,
       manage files and remember things across sessions.</p>
    <div class="chips" id="chips2"></div>`;
  chatLog.appendChild(w);
  const chips = [
    ["📁 list files", "list files in current folder"],
    ["🔎 port scan", "port scan 127.0.0.1"],
    ["🖥️ system info", "system info"],
    ["🌐 subdomains", "subdomain_enum example.com"],
    ["🛠️ tools", "what tools do you have?"],
  ];
  const box = w.querySelector("#chips2");
  chips.forEach(([label, msg]) => {
    const b = document.createElement("button");
    b.className = "chip"; b.textContent = label;
    b.addEventListener("click", () => { sendMessage(msg); });
    box.appendChild(b);
  });
}

document.addEventListener("click", (e) => {
  if (e.target.classList && e.target.classList.contains("chip") && e.target.dataset.msg) {
    sendMessage(e.target.dataset.msg);
  }
});

/* ---------------- chat sessions (persistent history) ---------------- */
function newChat() {
  if (busy) return;
  currentSessionId = null;
  chatLog.innerHTML = "";
  welcome();
  loadSessions();
}

async function loadSessions() {
  try {
    const data = await fetchJSON("/api/sessions");
    renderSessions(data.sessions || []);
  } catch { /* ignore */ }
}

function renderSessions(list) {
  const box = $("#session-list");
  if (!box) return;
  box.innerHTML = "";
  if (!list.length) {
    const empty = document.createElement("div");
    empty.className = "session-empty";
    empty.textContent = "no saved chats yet";
    box.appendChild(empty);
    return;
  }
  list.forEach((s) => {
    const item = document.createElement("div");
    item.className = "session-item" + (s.id === currentSessionId ? " active" : "");
    item.title = s.title || "New chat";
    const title = document.createElement("span");
    title.className = "s-title";
    title.textContent = s.title || "New chat";
    const del = document.createElement("span");
    del.className = "s-del";
    del.textContent = "✕";
    del.title = "delete chat";
    del.addEventListener("click", (ev) => {
      ev.stopPropagation();
      deleteSession(s.id);
    });
    item.addEventListener("click", () => openSession(s.id));
    item.appendChild(title);
    item.appendChild(del);
    box.appendChild(item);
  });
}

async function deleteSession(id) {
  if (busy) return;
  try { await fetch("/api/sessions/" + encodeURIComponent(id), { method: "DELETE" }); } catch { /* ignore */ }
  if (id === currentSessionId) {
    currentSessionId = null;
    chatLog.innerHTML = "";
    welcome();
  }
  loadSessions();
}

async function openSession(id) {
  if (busy || id === currentSessionId) return;
  let s = null;
  try {
    const { res, text } = await fetchUtf8(
      "/api/sessions/" + encodeURIComponent(id) + "/open", { method: "POST" });
    if (!res.ok) return;
    s = JSON.parse(text);
  } catch { return; }
  currentSessionId = s.id;
  renderSession(s);
  loadSessions();
}

function renderSession(s) {
  chatLog.innerHTML = "";
  (s.messages || []).forEach((m) => {
    if (m.role === "assistant" && m.kind === "validation") {
      addValidationCard(m.status, m.finding, m.reason);
    } else if (m.role === "assistant" && m.kind === "validation_done") {
      addValidationSummary(m.content, m.verified, m.rejected, m.unverified, m.count);
    } else if (m.role === "assistant" && m.kind === "validation_spawned") {
      addValidationSpawned(m.reason, m.count);
    } else if (m.role === "tool" && m.validator) {
      addValidationToolCard(m.name || "?", typeof m.arguments === "string" ? m.arguments : JSON.stringify(m.arguments || ""));
      if (m.result != null) {
        const cards = chatLog.querySelectorAll(".toolcard.val-tool");
        const card = cards[cards.length - 1];
        if (card) {
          card.querySelector(".result").textContent = m.result;
          if (/error|failed|not installed|timed out/i.test(m.result)) card.classList.add("err");
        }
      }
    } else if (m.role === "user") {
      addUserMsg(m.content || "");
    } else if (m.role === "assistant") {
      const bubble = addAssistantBubble((m.kind === "error" ? "⚠️ " : "") + (m.content || ""));
      if (m.kind === "thinking") bubble.classList.add("thinking");
    } else if (m.role === "tool") {
      addToolCard(m.name || "?", typeof m.arguments === "string" ? m.arguments : JSON.stringify(m.arguments || ""));
      const cards = chatLog.querySelectorAll(".toolcard");
      const card = cards[cards.length - 1];
      if (card) {
        if (m.result != null) {
          card.querySelector(".result").textContent = m.result;
          if (/error|failed|not installed|timed out/i.test(m.result)) card.classList.add("err");
        }
        if (m.artifact) addArtifactBadge(card, m.artifact);
      }
    }
  });
  // rebuild the end-of-turn artifact panel from saved session state
  const seen = new Map();
  (s.artifacts || []).forEach((a) => seen.set(a.id || a.filename, a));
  (s.messages || []).forEach((m) => {
    if (m.artifact) seen.set(m.artifact.id || m.artifact.filename, m.artifact);
  });
  if (seen.size) renderArtifactsPanel([...seen.values()], s.id || currentSessionId);
  scrollDown();
}

/* ---------------- markdown-ish rendering ---------------- */
function escapeHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function mdToDom(text, el) {
  if (window.marked && typeof window.marked.parse === "function") {
    // marked.js: escape first so raw HTML from the model can never inject,
    // then parse GFM (headings, lists, tables, code fences, blockquotes).
    const safe = escapeHtml(text);
    el.innerHTML = marked.parse(safe, { gfm: true, breaks: false });
    el.querySelectorAll("pre").forEach((pre) => {
      if (pre.parentElement && pre.parentElement.classList.contains("codewrap")) return;
      const code = pre.querySelector("code");
      const wrap = document.createElement("div");
      wrap.className = "codewrap";
      const btn = document.createElement("button");
      btn.className = "copy-btn";
      btn.textContent = "copy";
      btn.addEventListener("click", () => {
        if (code) navigator.clipboard.writeText(code.textContent);
      });
      pre.parentNode.insertBefore(wrap, pre);
      wrap.appendChild(btn);
      wrap.appendChild(pre);
    });
    return;
  }
  // fallback: lightweight renderer if marked.min.js failed to load
  window.__mdBlocks = [];
  const blocks = [];
  let html = escapeHtml(text);
  html = html.replace(/```([\s\S]*?)```/g, (_, code) => {
    const id = blocks.length;
    blocks.push(code);
    return `<div class="codewrap"><button class="copy-btn">copy</button>
            <pre><code data-block="${id}">${escapeHtml(code)}</code></pre></div>`;
  });
  html = html.replace(/`([^`\n]+)`/g, "<code class='inline'>$1</code>");
  html = html.replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g,
    "<a href='$2' target='_blank' rel='noopener'>$1</a>");
  html = html.replace(/(^|\n)(#{1,6})\s+([^\n]+)/g, (m, pre, hashes, title) => {
    const level = Math.min(6, hashes.length + 2);
    return `${pre}<h${level}>${title}</h${level}>`;
  });
  html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/(https?:\/\/[^\s<>)]+)/g,
    "<a href='$1' target='_blank' rel='noopener'>$1</a>");
  el.innerHTML = html;
  el.querySelectorAll(".copy-btn").forEach((b) => {
    b.addEventListener("click", () => {
      const code = b.parentElement.querySelector("code[data-block]");
      if (code) navigator.clipboard.writeText(code.textContent);
    });
  });
}

/* ---------------- chat messages ---------------- */
function addUserMsg(text) {
  const m = document.createElement("div");
  m.className = "msg user";
  m.innerHTML = `<div class="avatar">🧑</div><div class="bubble">${escapeHtml(text)}</div>`;
  chatLog.appendChild(m);
  scrollDown();
}

function addAssistantBubble(text) {
  const m = document.createElement("div");
  m.className = "msg assistant";
  m.innerHTML = `<div class="avatar">🤖</div><div class="bubble"></div>`;
  mdToDom(text, m.querySelector(".bubble"));
  chatLog.appendChild(m);
  scrollDown();
  return m;
}

function addTyping() {
  const t = document.createElement("div");
  t.className = "typing"; t.id = "typing";
  t.innerHTML = `<span class="tdots">agent is working</span>`;
  chatLog.appendChild(t);
  scrollDown();
  return t;
}

function scrollDown() {
  chatLog.scrollTop = chatLog.scrollHeight;
}

function addRouteChip(label, reason) {
  const div = document.createElement("div");
  div.className = "route-chip";
  div.innerHTML =
    `<span class="route-ico">⚡</span><span class="route-txt"><b>${escapeHtml(label || "auto")}</b>` +
    (reason ? ` <span class="route-reason">· ${escapeHtml(reason)}</span>` : "") +
    `</span>`;
  chatLog.appendChild(div);
  scrollDown();
  return div;
}

function addToolCard(name, args) {
  const div = document.createElement("div");
  div.className = "toolcard";
  div.innerHTML = `
    <div class="toolcard-head">
      <span class="t-name">${escapeHtml(name)}</span>
      <span class="t-args">${escapeHtml(args || "{}")}</span>
      <span class="chev">▾</span>
    </div>
    <div class="toolcard-body"><pre class="result">…</pre></div>`;
  div.querySelector(".toolcard-head").addEventListener("click", () => {
    div.classList.toggle("open");
  });
  chatLog.appendChild(div);
  scrollDown();
  return div.querySelector(".result");
}

/* ---------------- structured artifact badges ---------------- */
function artifactBadgeHTML(a) {
  const id = (a && (a.id || a.filename)) || "";
  if (!id) return "";
  const tool = escapeHtml(a.tool || (id.split("_")[0] || "file"));
  const size = a.size_h ? ` <span class="artifact-size">${escapeHtml(a.size_h)}</span>` : "";
  // prefer the structured <chat>/<timestamp>/<file> url, fall back to the
  // legacy plain-filename route for backward compatibility
  const href = a.url ? String(a.url) : "/api/download/" + encodeURIComponent(id);
  return `<a class="artifact-badge" href="${href}" download title="Download ${escapeHtml(id)}">📄 ${tool}${size}</a>`;
}

function addArtifactBadge(container, a) {
  const html = artifactBadgeHTML(a);
  if (!html) return null;
  const wrap = document.createElement("div");
  wrap.className = "artifact-zone";
  wrap.innerHTML = html;
  (container || chatLog).appendChild(wrap);
  scrollDown();
  return wrap;
}

function renderArtifactsPanel(list, chatId) {
  const items = (list || []).filter((a) => a && (a.id || a.filename));
  if (!items.length) return null;
  const div = document.createElement("div");
  div.className = "artifact-panel";
  const rows = items.map((a) =>
    `<div class="artifact-row">${artifactBadgeHTML(a)}</div>`).join("");
  const report = chatId
    ? `<a class="artifact-report" href="/api/artifacts/${encodeURIComponent(chatId)}/report?download=1">⬇ Markdown Report</a>`
    : "";
  const archive = chatId
    ? `<a class="artifact-report" href="/api/artifacts/${encodeURIComponent(chatId)}/archive" title="Download all artifacts as one ZIP">🗜 All Artifacts (.zip)</a>`
    : "";
  div.innerHTML = `
    <div class="artifact-head">📦 ${items.length} artifact${items.length === 1 ? "" : "s"} saved</div>
    <div class="artifact-list">${rows}</div>
    <div class="artifact-actions">${report}${archive}</div>`;
  chatLog.appendChild(div);
  scrollDown();
  return div;
}

/* ---------------- executive report summary cards ---------------- */
async function loadReports() {
  const grid = $("#report-grid");
  if (!grid) return;
  grid.innerHTML = `<p class="muted report-empty">loading reports…</p>`;
  try {
    const data = await fetchJSON("/api/reports");
    const reports = data.reports || [];
    const badge = $("#badge-reports");
    if (badge) badge.textContent = reports.length;
    renderReports(reports);
  } catch {
    grid.innerHTML = `<p class="muted report-empty">⚠️ Reports load nahi hue — server check karein.</p>`;
  }
}

function renderReports(reports) {
  const grid = $("#report-grid");
  if (!grid) return;
  if (!reports.length) {
    grid.innerHTML = `<p class="muted report-empty">No reports yet — chat karein aur koi assessment chala kar pehla report banayein.</p>`;
    return;
  }
  grid.innerHTML = reports.map(reportCardHTML).join("");
  grid.querySelectorAll(".report-card").forEach((card) => {
    const box = card.querySelector(".report-summary");
    if (box && card.dataset.summary) mdToDom(card.dataset.summary, box);
  });
}

const REPORT_SEV = {
  critical: { cls: "sev-critical", label: "CRITICAL" },
  high:     { cls: "sev-high",     label: "HIGH" },
  medium:   { cls: "sev-medium",   label: "MEDIUM" },
  low:      { cls: "sev-low",      label: "LOW" },
  info:     { cls: "sev-info",     label: "INFO" },
};

function reportCardHTML(r) {
  const sev = REPORT_SEV[r.severity] || REPORT_SEV.info;
  const target = r.target
    ? `<span class="report-chip report-target" title="Target">🎯 ${escapeHtml(r.target)}</span>`
    : "";
  const meta = [
    r.updated ? `🕒 ${escapeHtml(r.updated)}` : "",
    `${r.artifacts} artifact${r.artifacts === 1 ? "" : "s"}`,
    `${r.message_count} msg`,
    r.total_size ? `📦 ${escapeHtml(r.total_size)}` : "",
  ].filter(Boolean).map((m) => `<span class="report-chip">${m}</span>`).join("");
  const tools = (r.tools || []).slice(0, 8).map((t) =>
    `<span class="report-chip report-tool" title="Tool used">🔧 ${escapeHtml(t)}</span>`).join("");
  const actions = [
    r.report_download_url
      ? `<a class="btn-primary report-btn" href="${r.report_download_url}" download>⬇ Markdown Report</a>`
      : "",
    r.archive_url
      ? `<a class="btn-ghost report-btn" href="${r.archive_url}" download title="All artifacts as one ZIP">🗜 Artifacts (.zip)</a>`
      : "",
    `<button class="btn-ghost report-btn" data-open="${r.chat_id}" title="Open this chat">💬 Open Chat</button>`,
  ].join("");
  return `<article class="report-card" data-summary="${escapeHtml(r.summary || "")}">
    <div class="report-head">
      <span class="report-sev ${sev.cls}">${sev.label}</span>
      <h3 class="report-title">${escapeHtml(r.title || "New chat")}</h3>
    </div>
    <div class="report-chips">${target}${meta}</div>
    <div class="report-summary"></div>
    ${tools ? `<div class="report-chips report-tools">${tools}</div>` : ""}
    <div class="report-actions">${actions}</div>
  </article>`;
}

/* ---------------- validation sub-agent cards ---------------- */
function valLabel(status) {
  const s = String(status || "unverified").toLowerCase();
  if (s === "verified") return { cls: "val-ok", ico: "✔", label: "Finding Verified" };
  if (s === "rejected") return { cls: "val-bad", ico: "✖", label: "False Positive Rejected" };
  return { cls: "val-warn", ico: "?", label: "Unverified" };
}

function addValidationHeader(count) {
  const div = document.createElement("div");
  div.className = "validation-card val-start";
  div.innerHTML =
    `<span class="val-ico">🛡</span><span class="val-body"><b>[VALIDATION SUB-AGENT]</b>` +
    ` re-verifying ${Number(count) || 0} finding(s)…</span>`;
  chatLog.appendChild(div);
  scrollDown();
  return div;
}

function addValidationSpawned(reason, count) {
  const div = document.createElement("div");
  div.className = "validation-card val-start";
  div.innerHTML =
    `<span class="val-ico">🛡</span><span class="val-body"><b>[VALIDATION SUB-AGENT]</b>` +
    ` spawned for ${Number(count) || 0} finding(s)` +
    (reason ? ` — ${escapeHtml(reason)}` : "") + `…</span>`;
  chatLog.appendChild(div);
  scrollDown();
  return div;
}

function addValidationToolCard(name, args) {
  const div = document.createElement("div");
  div.className = "toolcard val-tool";
  div.innerHTML = `
    <div class="toolcard-head">
      <span class="t-name">verify·${escapeHtml(name)}</span>
      <span class="t-args">${escapeHtml(args || "{}")}</span>
      <span class="chev">▾</span>
    </div>
    <div class="toolcard-body"><pre class="result">…</pre></div>`;
  div.querySelector(".toolcard-head").addEventListener("click", () => {
    div.classList.toggle("open");
  });
  chatLog.appendChild(div);
  scrollDown();
  return div.querySelector(".result");
}

function addValidationCard(status, finding, reason) {
  const v = valLabel(status);
  const div = document.createElement("div");
  div.className = "validation-card " + v.cls;
  div.innerHTML =
    `<span class="val-ico">${v.ico}</span>` +
    `<span class="val-body"><b>[VALIDATION SUB-AGENT]</b>` +
    ` <span class="val-label">${v.label}</span>` +
    (finding ? ` <span class="val-finding">${escapeHtml(finding)}</span>` : "") +
    (reason ? ` <span class="val-reason">${escapeHtml(reason)}</span>` : "") +
    `</span>`;
  chatLog.appendChild(div);
  scrollDown();
  return div;
}

function addValidationSummary(summary, verified, rejected, unverified, count) {
  const div = document.createElement("div");
  div.className = "validation-card val-done";
  div.innerHTML =
    `<span class="val-ico">✓</span>` +
    `<span class="val-body"><b>[VALIDATION SUB-AGENT]</b> ${escapeHtml(summary || "")}` +
    ` <span class="val-counts"><span class="val-ok">${Number(verified) || 0} verified</span>` +
    ` · <span class="val-bad">${Number(rejected) || 0} rejected</span>` +
    ` · <span class="val-warn">${Number(unverified) || 0} unverified</span></span></span>`;
  chatLog.appendChild(div);
  scrollDown();
  return div;
}

/* ---------------- send / SSE (fetch + AbortController) ---------------- */
// EventSource has no abort() API, so the stream is fetched as a raw
// ReadableStream and SSE frames are parsed by hand. That lets the Stop
// button cancel the in-flight fetch in real time via AbortController and
// report the exact run_id back to /api/chat/cancel so the backend unwinds
// the running LLM call / tool subprocess instead of leaving it alive.
function setStreaming(on) {
  const btn = $("#send");
  btn.classList.toggle("streaming", on);
  btn.disabled = false; // while streaming the button stays clickable = Stop
  btn.title = on ? "Stop" : "Send";
  btn.setAttribute("aria-label", on ? "Stop" : "Send");
}

function sendMessage(text) {
  if (busy || !text.trim()) return;
  const message = text.trim();
  inputBox.value = "";
  autosize();
  addUserMsg(message);
  let typing = addTyping();
  busy = true;
  stopRequested = false;
  setStreaming(true); // send arrow -> square stop icon
  $("#chat-hint").textContent = "working…";
  armWatchdogTotal(); // hard cap on the whole request
  armWatchdog();      // inactivity watchdog, re-armed on every SSE event

  const controller = new AbortController();
  activeController = controller;
  let finalAdded = false;
  let preview = null; // last "llm" bubble — upgraded to final instead of duplicating

  // clean end of stream: clear "working…", reset busy so the next message
  // can be sent immediately. Idempotent — watchdog + abort + error paths
  // can race, so the "working…" state can never stay stuck.
  function finish(note) {
    if (!busy) return;
    clearTimeout(watchdogInactive);
    clearTimeout(watchdogTotal);
    activeController = null;
    activeRunId = null;
    stopRequested = false;
    try { controller.abort(); } catch { /* already aborted */ }
    typing.remove();
    busy = false;
    setStreaming(false); // stop square -> send arrow
    $("#chat-hint").textContent = "";
    if (note && !finalAdded) {
      addAssistantBubble(note);
      finalAdded = true;
    }
    scrollDown();
    refreshStatus();
    loadSessions();
  }

  function armWatchdog() {
    clearTimeout(watchdogInactive);
    watchdogInactive = setTimeout(() => {
      finish("⚠️ connection stalled — no events for 5+ minutes, try again");
    }, 330000);
  }

  function armWatchdogTotal() {
    clearTimeout(watchdogTotal);
    watchdogTotal = setTimeout(() => {
      finish("⚠️ request timed out — stream released");
    }, 400000);
  }

  // one decoded SSE "data:" payload -> identical rendering to the old
  // EventSource onmessage handler.
  function handleEvent(e) {
    armWatchdog(); // any event counts as activity
    if (e.type === "start") return;

    if (e.type === "route") {
      // Smart Auto-Model Selector: show which model this answer uses
      addRouteChip(e.label, e.reason);
      return;
    }

    if (e.type === "notice") {
      // Red Team Mode: model declined once, client auto-retried with
      // authorization framing - surface that to the user.
      const div = document.createElement("div");
      div.className = "route-chip rt-notice";
      div.innerHTML = `<span class="route-ico">☠</span><span class="route-txt"><b>Red Team</b>` +
        ` <span class="route-reason">· ${escapeHtml(e.text || e.content || "auto-retry")}</span></span>`;
      chatLog.appendChild(div);
      scrollDown();
      return;
    }

    if (e.type === "llm") {
      // full assistant content before tool calls -> render as markdown
      typing.remove();
      const content = e.content || "";
      if (preview && preview.bubble.isConnected) {
        preview.text = content;
        mdToDom(content, preview.bubble.querySelector(".bubble"));
      } else {
        const b = addAssistantBubble(content);
        b.classList.add("thinking");
        preview = { bubble: b, text: content };
      }
    } else if (e.type === "delta") {
      // streaming token -> append to live bubble (typewriter effect)
      typing.remove();
      if (!preview || !preview.bubble.isConnected) {
        const b = addAssistantBubble("");
        b.classList.add("thinking");
        preview = { bubble: b, text: "" };
      }
      preview.text += e.content || "";
      preview.bubble.querySelector(".bubble").textContent = preview.text;
    } else if (e.type === "tool_call") {
      typing.remove();
      preview = null; // next assistant text gets a fresh bubble
      addToolCard(e.name, typeof e.arguments === "string" ? e.arguments : JSON.stringify(e.arguments || ""));
    } else if (e.type === "tool_result") {
      const cards = chatLog.querySelectorAll(".toolcard");
      const card = cards[cards.length - 1];
      if (card) {
        card.querySelector(".result").textContent = e.content || "(no output)";
        if (/error|failed|not installed|timed out/i.test(e.content || "")) {
          card.classList.add("err");
        }
        if (e.artifact) addArtifactBadge(card, e.artifact);
      }
      typing = addTyping();
    } else if (e.type === "final") {
      // one prompt -> exactly one response bubble
      typing.remove();
      const content = e.content || "";
      if (preview && preview.bubble.isConnected) {
        // live streamed bubble already shows the answer -> render as markdown
        mdToDom(content, preview.bubble.querySelector(".bubble"));
        preview.bubble.classList.remove("thinking");
      } else if (!finalAdded) {
        addAssistantBubble(content);
      }
      finalAdded = true;
      preview = null;
      finish(); // stream done — clear working…, reset busy, no auto-reconnect
    } else if (e.type === "error") {
      typing.remove();
      if (!finalAdded) {
        addAssistantBubble("⚠️ " + (e.content || "error"));
        finalAdded = true;
      }
      finish(); // e.g. server [timed out] — must also release busy
    } else if (e.type === "artifacts") {
      // end-of-turn panel: saved scan outputs + markdown report button
      typing.remove();
      renderArtifactsPanel(e.artifacts, e.chat_id);
    } else if (e.type === "task_board") {
      renderBoard(e.board); // silent background state, never chat clutter
    } else if (e.type === "validation_spawned") {
      // an independent validation sub-agent was spawned for critical/high
      // findings, complex bugs, or unresolved findings
      typing.remove();
      addValidationSpawned(e.reason, e.count);
    } else if (e.type === "validation_start") {
      // validator child began re-checking; preview (main answer) must survive
      typing.remove();
      addValidationHeader(e.count || 0);
    } else if (e.type === "validation_tool_call") {
      // NOTE: preview is intentionally NOT cleared here (unlike tool_call) —
      // the validator runs AFTER the main answer and the live final bubble
      // must stay intact.
      addValidationToolCard(e.name, typeof e.arguments === "string" ? e.arguments : JSON.stringify(e.arguments || "{}"));
      typing = addTyping();
    } else if (e.type === "validation_tool_result") {
      const cards = chatLog.querySelectorAll(".toolcard.val-tool");
      const card = cards[cards.length - 1];
      if (card) {
        card.querySelector(".result").textContent = e.content || "(no output)";
        if (/error|failed|not installed|timed out/i.test(e.content || "")) {
          card.classList.add("err");
        }
      }
      typing = addTyping();
    } else if (e.type === "validation") {
      typing.remove();
      addValidationCard(e.status, e.finding, e.reason);
    } else if (e.type === "validation_done") {
      typing.remove();
      addValidationSummary(e.summary, e.verified, e.rejected, e.unverified, e.count);
    }
    scrollDown();
  }

  // fetch + ReadableStream instead of EventSource so the request can be
  // aborted in real time (AbortController); EventSource has no abort.
  (async () => {
    let res;
    try {
      res = await fetch("/api/chat?message=" + encodeURIComponent(message),
                        { signal: controller.signal });
      if (!res.ok) throw new Error("HTTP " + res.status);
      if (!res.body) throw new Error("stream unavailable");
      activeRunId = res.headers.get("X-Run-Id") || null;
      const reader = res.body.getReader();
      const decoder = new TextDecoder("utf-8");
      let buf = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let sep;
        while ((sep = buf.indexOf("\n\n")) !== -1) {
          const block = buf.slice(0, sep);
          buf = buf.slice(sep + 2);
          let data = "";
          block.split("\n").forEach((line) => {
            if (line.startsWith("data:")) {
              data += (data ? "\n" : "") + line.slice(5).trim();
            }
          });
          if (!data) continue;
          let e;
          try { e = JSON.parse(data); } catch { continue; }
          handleEvent(e);
        }
      }
    } catch (err) {
      if (err && err.name === "AbortError" && stopRequested) {
        // user clicked Stop: /api/chat/cancel already told the backend to
        // unwind the LLM call / tool run, so just show a short note.
        if (!finalAdded) {
          addAssistantBubble("⏹ stopped");
          finalAdded = true;
        }
      } else if (!finalAdded) {
        addAssistantBubble("⚠️ connection error: " + (err && err.message ? err.message : "stream aborted"));
        finalAdded = true;
      }
    } finally {
      // stop may have raced the reader's last chunk -> still mark the UI
      // as stopped if nothing was rendered after the Stop click.
      if (stopRequested && !finalAdded) {
        addAssistantBubble("⏹ stopped");
        finalAdded = true;
      }
      finish(); // always release busy so the user can send the next message
    }
  })();
}

function stopStream() {
  if (!busy) return;
  stopRequested = true;
  const controller = activeController;
  const runId = activeRunId;
  activeController = null;
  activeRunId = null;
  try { if (controller) controller.abort(); } catch { /* ignore */ }
  // belt-and-suspenders: even if the abort raced ahead of the response
  // headers (no run_id yet), POSTing without a run_id cancels all active
  // runs. The backend worker raises RunCancelled, kills tool subprocesses
  // (kill_active_procs) and drops the run from _active_runs.
  fetch("/api/chat/cancel", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(runId ? { run_id: runId } : {}),
  }).catch(() => { /* backend already unwinding via the aborted connection */ });
}

/* ---------------- composer ---------------- */
function autosize() {
  inputBox.style.height = "auto";
  inputBox.style.height = Math.min(inputBox.scrollHeight, 160) + "px";
}
inputBox.addEventListener("input", autosize);
inputBox.addEventListener("keydown", (ev) => {
  if (ev.key === "Enter" && !ev.shiftKey) {
    ev.preventDefault();
    sendMessage(inputBox.value);
  }
});
$("#send").addEventListener("click", () => {
  if (busy) stopStream(); // streaming -> Stop button
  else sendMessage(inputBox.value);
});

/* ---------------- tools ---------------- */
let allTools = [];
async function loadTools() {
  const grid = $("#tool-grid");
  grid.innerHTML = '<p style="color:var(--muted)">loading…</p>';
  allTools = await fetchJSON("/api/tools");
  $("#tools-count").textContent = allTools.length + " tools registered";
  renderTools("");
}
function renderTools(q) {
  const grid = $("#tool-grid");
  grid.innerHTML = "";
  const list = allTools.filter((t) =>
    !q || t.name.toLowerCase().includes(q) || t.description.toLowerCase().includes(q));
  if (!list.length) {
    grid.innerHTML = '<p style="color:var(--muted)">no tools match</p>';
    return;
  }
  list.forEach((t) => {
    const card = document.createElement("div");
    card.className = "tool-card";
    const params = JSON.stringify(t.parameters || {}, null, 2);
    card.innerHTML = `
      <h4>${escapeHtml(t.name)}</h4>
      <p>${escapeHtml(t.description)}</p>
      <details><summary>parameters</summary><pre>${escapeHtml(params)}</pre></details>`;
    grid.appendChild(card);
  });
}
$("#tool-search").addEventListener("input", (e) => renderTools(e.target.value.toLowerCase()));

/* ---------------- memory ---------------- */
async function loadMemory() {
  const list = $("#memory-list");
  list.innerHTML = '<p style="color:var(--muted)">loading…</p>';
  const rows = await fetchJSON("/api/memory");
  $("#badge-memory").textContent = rows.length;
  list.innerHTML = "";
  if (!rows.length) {
    list.innerHTML = '<p style="color:var(--muted)">memory is empty — tell the agent to remember something.</p>';
    return;
  }
  rows.forEach((r) => {
    const item = document.createElement("div");
    item.className = "mem-item";
    item.innerHTML = `
      <div class="k">${escapeHtml(r.key)}</div>
      <div class="t">${escapeHtml(r.text)}</div>
      <div class="ts">${escapeHtml(r.ts || "")}</div>
      <button class="del" title="delete">✕</button>`;
    item.querySelector(".del").addEventListener("click", async () => {
      await fetch("/api/memory/" + encodeURIComponent(r.key), { method: "DELETE" });
      loadMemory();
    });
    list.appendChild(item);
  });
}
$("#mem-add").addEventListener("click", async () => {
  const key = $("#mem-key").value.trim();
  const text = $("#mem-text").value.trim();
  if (!key || !text) return;
  const res = await fetch("/api/memory", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key, text }),
  });
  if (res.ok) { $("#mem-key").value = ""; $("#mem-text").value = ""; loadMemory(); }
});

/* ---------------- settings ---------------- */
function fillModelSelect(catalog) {
  const sel = $("#set-model");
  sel.innerHTML = "";
  (catalog || []).forEach((m) => {
    const opt = document.createElement("option");
    opt.value = m.id;
    opt.textContent = m.label;
    if (m.tag === "recommended") opt.textContent += " ★";
    sel.appendChild(opt);
  });
  return sel;
}

async function loadSettings() {
  const s = await fetchJSON("/api/settings");
  // The key itself is never sent back - only whether it exists in .env.
  $("#set-key").value = "";
  $("#set-key").placeholder = s.has_key ? "✓ API key is saved in .env (leave blank to keep it)" : "sk-…  (no key set — will be saved to .env)";
  $("#set-url").value = s.base_url || "";
  fillModelSelect(s.catalog);
  $("#set-model").value = s.auto ? "auto" : (s.model || "auto");
  $("#set-auto").checked = !!s.auto;
  $("#set-mock").checked = !!s.mock;
  $("#set-redteam").checked = !!s.red_team_mode;
  $("#set-iter").value = s.max_iterations || 12;
}

// the Auto-Model Selector checkbox drives the model select
$("#set-auto").addEventListener("change", () => {
  $("#set-model").value = $("#set-auto").checked ? "auto" : $("#set-model").value;
});
$("#set-save").addEventListener("click", async () => {
  const msg = $("#set-msg");
  msg.textContent = "saving…";
  const res = await fetch("/api/settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      api_key: $("#set-key").value.trim(),
      base_url: $("#set-url").value.trim(),
      model: $("#set-model").value.trim(),
      auto: $("#set-auto").checked,
      mock: $("#set-mock").checked,
      red_team_mode: $("#set-redteam").checked,
      max_iterations: parseInt($("#set-iter").value, 10) || 12,
    }),
  });
  if (res.ok) {
    msg.textContent = "✅ saved — agent reloaded";
    setTimeout(() => (msg.textContent = ""), 2500);
    refreshStatus();
  } else {
    msg.textContent = "❌ failed to save";
  }
});

/* ---------------- system ---------------- */
async function loadSystem() {
  const box = $("#sys-box");
  box.textContent = "loading…";
  const s = await fetchJSON("/api/system");
  box.textContent = s.system + "\n\n" + s.ip + "\n\n" + s.disk;
}
$("#sys-refresh").addEventListener("click", loadSystem);

/* ---------------- status ---------------- */
async function refreshStatus() {
  try {
    const s = await fetchJSON("/api/status");
    const warn = $("#env-warn");
    if (warn) {
      if (s.key_error) {
        warn.textContent = "⚠️ " + s.key_error;
        warn.classList.remove("hidden");
      } else {
        warn.classList.add("hidden");
      }
    }
    const dot = $("#dot-mode");
    dot.className = "dot " + (s.mode === "live" ? "live" : "mock");
    if (s.mode === "auto") {
      dot.className = "dot live";
      $("#status-mode").textContent = "auto · smart router";
      $("#status-model").textContent = s.base_url || "";
      $("#pill-mode").textContent = "◐ AUTO · smart router";
    } else {
      $("#status-mode").textContent = s.mode === "live" ? "live · " + s.model : "mock mode";
      $("#status-model").textContent = s.mode === "live" ? s.base_url : "built-in test LLM";
      $("#pill-mode").textContent = (s.mode === "live" ? "● LIVE · " : "◐ MOCK · ") + s.model;
    }
    $("#pill-mode").className = "pill " + (s.mode === "mock" ? "mock" : "live");
    $("#badge-tools").textContent = s.tools;
  } catch { /* ignore */ }
}

refreshStatus();
setInterval(refreshStatus, 10000);

/* ---------------- RPG / Mythos Engine ---------------- */
let rpgGames = [];
let rpgCurrent = null;   // active game payload
let rpgBusy = false;
let rpgCtrl = null;      // AbortController of the in-flight turn stream
let rpgChoices = [];     // last parsed choices

function rpgScroll() {
  const s = $("#rpg-story");
  if (s) s.scrollTop = s.scrollHeight;
}

function rpgSetStreaming(on) {
  const btn = $("#rpg-send");
  btn.classList.toggle("streaming", on);
  btn.title = on ? "Stop" : "Act";
}

function rpgTypewriter() {
  const t = document.createElement("div");
  t.className = "rpg-msg gm thinking";
  t.id = "rpg-typing";
  t.innerHTML = `<div class="rpg-avatar">🎭</div><div class="rpg-bubble">the storyteller is weaving…</div>`;
  $("#rpg-story").appendChild(t);
  rpgScroll();
  return t;
}

function rpgAddPlayer(text) {
  const story = $("#rpg-story");
  const m = document.createElement("div");
  m.className = "rpg-msg player";
  m.innerHTML =
    `<div class="rpg-avatar">🧝</div><div class="rpg-bubble">${escapeHtml(text)}</div>`;
  story.appendChild(m);
  rpgScroll();
}

function rpgAddSystem(text) {
  const d = document.createElement("div");
  d.className = "rpg-note";
  d.textContent = text;
  $("#rpg-story").appendChild(d);
  rpgScroll();
}

function rpgNpcCard(name, text) {
  const card = document.createElement("div");
  card.className = "npc-card";
  card.innerHTML = `
    <div class="npc-avatar">🗣️</div>
    <div class="npc-body">
      <div class="npc-name">${escapeHtml(name)}</div>
      <div class="npc-dialogue"></div>
    </div>`;
  mdToDom(text, card.querySelector(".npc-dialogue"));
  return card;
}

function rpgRenderTurn(narrative, choices) {
  const story = $("#rpg-story");
  if (!story) return;
  const paras = (narrative || "").split(/\n{1,}/).map((p) => p.trim()).filter(Boolean);
  let pending = [];
  const flush = () => {
    if (!pending.length) return;
    const bubble = document.createElement("div");
    bubble.className = "rpg-msg gm";
    bubble.innerHTML = `<div class="rpg-avatar">🎭</div><div class="rpg-bubble"></div>`;
    mdToDom(pending.join("\n\n"), bubble.querySelector(".rpg-bubble"));
    story.appendChild(bubble);
    pending = [];
  };
  paras.forEach((p) => {
    // NPC line: **Name:** dialogue  (also **Name** — dialogue)
    const m = p.match(/^\*\*([^*]+?)\*\*\s*[:—]\s*(.+)$/);
    if (m) {
      flush();
      story.appendChild(rpgNpcCard(m[1].trim(), m[2].trim()));
    } else {
      pending.push(p);
    }
  });
  flush();
  rpgRenderChoices(choices || []);
  rpgScroll();
}

function rpgRenderChoices(choices) {
  const old = $("#rpg-choices");
  if (old) old.remove();
  const box = document.createElement("div");
  box.className = "rpg-choices";
  box.id = "rpg-choices";
  rpgChoices = choices || [];
  if (!rpgChoices.length) {
    box.innerHTML = `<div class="rpg-freeplay">✍️ kuch bhi type karein — yaada action is allowed.</div>`;
    $("#rpg-story").appendChild(box);
    return;
  }
  rpgChoices.forEach((c, i) => {
    const b = document.createElement("button");
    b.className = "choice-btn";
    b.innerHTML = `<span class="choice-num">${i + 1}</span><span class="choice-text">${escapeHtml(c)}</span>`;
    b.addEventListener("click", () => rpgPlay(c));
    box.appendChild(b);
  });
  $("#rpg-story").appendChild(box);
  rpgScroll();
}

function rpgRenderState(state) {
  const box = $("#rpg-state-box");
  if (!box || !state) return;
  const p = state.player || {};
  const st = p.stats || {};
  const hp = st.hp != null ? st.hp : "—";
  const hpMax = st.hp_max || hp;
  const hpPct = hpMax ? Math.max(0, Math.min(100, (hp / hpMax) * 100)) : 0;
  const loc = state.location || {};
  let inv = (state.inventory || []).map((i) => escapeHtml(i)).join(", ") || "empty";
  const npcs = Object.keys(state.npcs || {});
  let html = `
    <div class="stat-row"><span>⚔️ ${escapeHtml(p.name || "?")}</span><span>Lv ${st.level || 1}</span></div>
    <div class="hpbar"><div class="hpfill" style="width:${hpPct}%"></div></div>
    <div class="stat-row"><span>❤️ HP</span><span>${hp}/${hpMax}</span></div>
    <div class="stat-row"><span>🪙 Gold</span><span>${st.gold || 0}</span></div>
    <div class="stat-row"><span>✨ XP</span><span>${st.xp || 0}</span></div>
    <div class="stat-row"><span>📍 ${escapeHtml(loc.name || "?")}</span></div>
    <div class="stat-note">${escapeHtml(loc.description || "")}</div>
    <div class="stat-row"><span>🎒 ${inv}</span></div>`;
  if (npcs.length) {
    html += `<div class="stat-row"><span>🗣️ ${escapeHtml(npcs.join(", "))}</span></div>`;
  }
  box.innerHTML = html;
  if (state.game_id) {
    rpgCurrent = Object.assign({}, rpgCurrent, { turn: state.turn, updated: state.updated });
    const sels = $("#rpg-game-select");
    if (sels && state.game_id) sels.value = state.game_id;
  }
}

function rpgHandleEvent(e) {
  const story = $("#rpg-story");
  if (e.type === "start") return;
  if (e.type === "delta") {
    let t = $("#rpg-typing");
    if (!t) t = rpgTypewriter();
    const b = t.querySelector(".rpg-bubble");
    const txt = (b.dataset.acc || "") + (e.content || "");
    b.dataset.acc = txt;
    b.textContent = txt;
    rpgScroll();
    return;
  }
  if (e.type === "llm") {
    let t = $("#rpg-typing");
    if (!t) t = rpgTypewriter();
    const b = t.querySelector(".rpg-bubble");
    b.dataset.acc = e.content || "";
    b.textContent = e.content || "";
    rpgScroll();
    return;
  }
  if (e.type === "tool_call" || e.type === "tool_result") return; // GM keeps internal tool noise hidden
  if (e.type === "player_choice") return;
  if (e.type === "narrative") {
    const t = $("#rpg-typing");
    if (t) t.remove();
    rpgRenderTurn(e.content || "", e.choices || []);
    return;
  }
  if (e.type === "state") {
    rpgRenderState(e.content);
    return;
  }
  if (e.type === "final") return; // narrative event already rendered the turn
  if (e.type === "error") {
    const t = $("#rpg-typing");
    if (t) t.remove();
    rpgAddSystem("⚠️ " + (e.content || "error"));
    rpgRenderChoices(rpgChoices); // keep last choices usable
  }
}

async function rpgPlay(input) {
  if (rpgBusy) return;
  if (!rpgCurrent || !rpgCurrent.game_id) {
    rpgAddSystem("⚠️ pehle ek campaign load karein.");
    return;
  }
  const message = (input || "").trim();
  rpgAddPlayer(message || "*(the tale begins)*");
  rpgBusy = true;
  rpgSetStreaming(true);
  const ctrl = new AbortController();
  rpgCtrl = ctrl;
  try {
    const res = await fetch("/api/rpg/games/" + encodeURIComponent(rpgCurrent.game_id) + "/play", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input: message }),
      signal: ctrl.signal,
    });
    if (res.status === 409) {
      const d = await res.json().catch(() => ({}));
      rpgAddSystem("⏳ ek turn pehle se chal raha hai" + (d.error ? " — " + d.error : ""));
      rpgBusy = false;
      rpgSetStreaming(false);
      return;
    }
    if (!res.ok) throw new Error("HTTP " + res.status);
    if (!res.body) throw new Error("stream unavailable");
    const reader = res.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let buf = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let sep;
      while ((sep = buf.indexOf("\n\n")) !== -1) {
        const block = buf.slice(0, sep);
        buf = buf.slice(sep + 2);
        let data = "";
        block.split("\n").forEach((line) => {
          if (line.startsWith("data:")) data += (data ? "\n" : "") + line.slice(5).trim();
        });
        if (!data) continue;
        let ev;
        try { ev = JSON.parse(data); } catch { continue; }
        rpgHandleEvent(ev);
      }
    }
  } catch (err) {
    if (!(err && err.name === "AbortError")) {
      rpgAddSystem("⚠️ connection error: " + (err && err.message ? err.message : "stream aborted"));
    }
  } finally {
    rpgBusy = false;
    rpgCtrl = null;
    rpgSetStreaming(false);
    rpgScroll();
    rpgLoadLore();
  }
}

function rpgStop() {
  if (!rpgBusy) return;
  const ctrl = rpgCtrl;
  rpgCtrl = null;
  try { if (ctrl) ctrl.abort(); } catch { /* ignore */ }
  fetch("/api/rpg/games/" + encodeURIComponent(rpgCurrent.game_id) + "/cancel",
        { method: "POST" }).catch(() => {});
}

/* ---------- campaign management ---------- */
async function rpgRefreshGames() {
  try {
    const st = await fetchJSON("/api/rpg");
    rpgGames = st.games || [];
    $("#badge-rpg").textContent = rpgGames.length;
    const sel = $("#rpg-game-select");
    sel.innerHTML = "";
    if (!rpgGames.length) {
      const o = document.createElement("option");
      o.value = "";
      o.textContent = "— no campaigns —";
      sel.appendChild(o);
    }
    rpgGames.forEach((g) => {
      const o = document.createElement("option");
      o.value = g.game_id;
      o.textContent = `${g.title || g.game_id} · ${g.genre || "?"} · turn ${g.turn || 0}`;
      sel.appendChild(o);
    });
    if (rpgCurrent && rpgCurrent.game_id) sel.value = rpgCurrent.game_id;
  } catch { /* ignore */ }
}

async function loadRPGView() {
  await rpgRefreshGames();
  rpgLoadLore();
  const sel = $("#rpg-game-select");
  if (sel && sel.value) await rpgLoadGame(sel.value);
}

async function rpgLoadGame(id) {
  if (!id) return;
  try {
    const d = await fetchJSON("/api/rpg/games/" + encodeURIComponent(id) + "/load", { method: "POST" });
    rpgCurrent = d;
    const story = $("#rpg-story");
    const w = $("#rpg-welcome");
    if (w) w.remove();
    if (!story.querySelector(".rpg-msg, .rpg-note, .rpg-choices")) {
      const head = document.createElement("div");
      head.className = "rpg-msg gm";
      head.innerHTML = `<div class="rpg-avatar">🎭</div><div class="rpg-bubble"><b>${escapeHtml(d.title || "Adventure")}</b><br>${escapeHtml(d.player.name)} — ${escapeHtml(d.genre || "")}. Tumhari kahani yahin se shuru hoti hai.</div>`;
      story.appendChild(head);
    }
    rpgRenderState(d);
    rpgRefreshGames();
    rpgLoadLore();
    rpgScroll();
  } catch { rpgAddSystem("⚠️ campaign load nahi hua."); }
}

function rpgNewGame() {
  if (rpgBusy) return;
  $("#rpg-new-title").value = "";
  $("#rpg-new-player").value = "";
  $("#rpg-new-setup").value = "";
  $("#rpg-modal").hidden = false;
}

async function rpgStartGame() {
  const title = $("#rpg-new-title").value.trim();
  const genre = $("#rpg-new-genre").value;
  const player = $("#rpg-new-player").value.trim() || "Adventurer";
  const setup = $("#rpg-new-setup").value.trim();
  try {
    const d = await fetchJSON("/api/rpg/games", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title, genre, player_name: player, setup }),
    });
    $("#rpg-modal").hidden = true;
    const story = $("#rpg-story");
    const w = $("#rpg-welcome");
    if (w) w.remove();
    story.innerHTML = "";
    rpgCurrent = d;
    rpgRenderState(d);
    await rpgRefreshGames();
    rpgLoadLore();
    rpgPlay(setup || "");
  } catch (err) {
    rpgAddSystem("⚠️ campaign banane mein error: " + (err && err.message || "unknown"));
  }
}

async function rpgDeleteGame() {
  const id = $("#rpg-game-select").value;
  if (!id) return;
  if (!confirm("Is campaign ko delete karein? (permanent)")) return;
  await fetch("/api/rpg/games/" + encodeURIComponent(id), { method: "DELETE" }).catch(() => {});
  rpgCurrent = null;
  const story = $("#rpg-story");
  story.innerHTML = "";
  const w = document.createElement("div");
  w.className = "rpg-welcome";
  w.innerHTML = `<div class="welcome-icon">🐉</div><h3>Mythos Engine ready</h3><p>Nayi campaign banayein ya purani load karein.</p>`;
  story.appendChild(w);
  $("#rpg-state-box").innerHTML = `<p class="muted">no active campaign</p>`;
  rpgRefreshGames();
  rpgLoadLore();
}

/* ---------- lore ---------- */
async function rpgLoadLore() {
  const list = $("#rpg-lore-list");
  if (!list) return;
  try {
    const rows = await fetchJSON("/api/rpg/lore?limit=50");
    if (!rows.length) {
      list.innerHTML = `<p class="muted">lorebook khali hai</p>`;
      return;
    }
    list.innerHTML = "";
    rows.forEach((r) => {
      const item = document.createElement("div");
      item.className = "lore-item";
      item.innerHTML = `
        <div class="lore-head">
          <span class="lore-cat">${escapeHtml(r.category || "general")}</span>
          <b>${escapeHtml(r.title || "")}</b>
          <button class="del" title="delete">✕</button>
        </div>
        <div class="lore-body">${escapeHtml(r.content || "")}</div>`;
      item.querySelector(".del").addEventListener("click", async () => {
        await fetch("/api/rpg/lore/" + r.id, { method: "DELETE" }).catch(() => {});
        rpgLoadLore();
      });
      list.appendChild(item);
    });
  } catch { /* ignore */ }
}

let rpgLoreTimer = null;
$("#rpg-lore-q").addEventListener("input", (e) => {
  clearTimeout(rpgLoreTimer);
  const q = e.target.value.trim();
  rpgLoreTimer = setTimeout(async () => {
    const list = $("#rpg-lore-list");
    if (!q) return rpgLoadLore();
    try {
      const rows = await fetchJSON("/api/rpg/lore/search?q=" + encodeURIComponent(q));
      list.innerHTML = "";
      rows.forEach((r) => {
        const item = document.createElement("div");
        item.className = "lore-item hit";
        item.innerHTML = `
          <div class="lore-head"><span class="lore-cat">${escapeHtml(r.category || "")}</span><b>${escapeHtml(r.title || "")}</b></div>
          <div class="lore-body">${escapeHtml(r.content || "")}</div>`;
        list.appendChild(item);
      });
    } catch { /* ignore */ }
  }, 350);
});

$("#rpg-lore-new").addEventListener("keydown", async (ev) => {
  if (ev.key !== "Enter") return;
  const val = $("#rpg-lore-new").value.trim();
  if (!val) return;
  // format: "category: title — content"  (fallback: title only)
  let category = "general", title = val, content = "";
  const m = val.match(/^([\w-]+):\s*(.+)$/);
  if (m) { category = m[1]; title = m[2]; }
  const dash = title.indexOf("—");
  if (dash !== -1) { content = title.slice(dash + 1).trim(); title = title.slice(0, dash).trim(); }
  await fetch("/api/rpg/lore", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ category, title, content, tags: [category] }),
  }).catch(() => {});
  $("#rpg-lore-new").value = "";
  rpgLoadLore();
});

/* ---------------- reports wiring ---------------- */
$("#reports-refresh").addEventListener("click", loadReports);
$("#report-grid").addEventListener("click", (e) => {
  const btn = e.target.closest("[data-open]");
  if (!btn) return;
  switchView("chat");
  openSession(btn.dataset.open);
});

/* ---------- RPG event wiring ---------- */
$("#rpg-new").addEventListener("click", rpgNewGame);
$("#rpg-new-go").addEventListener("click", rpgStartGame);
$("#rpg-new-cancel").addEventListener("click", () => { $("#rpg-modal").hidden = true; });
$("#rpg-modal").addEventListener("click", (e) => { if (e.target === $("#rpg-modal")) $("#rpg-modal").hidden = true; });
$("#rpg-load").addEventListener("click", () => rpgLoadGame($("#rpg-game-select").value));
$("#rpg-delete").addEventListener("click", rpgDeleteGame);
$("#rpg-send").addEventListener("click", () => { if (rpgBusy) rpgStop(); else rpgPlay($("#rpg-input").value); });
$("#rpg-input").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter" && !ev.shiftKey) {
    ev.preventDefault();
    if (rpgBusy) rpgStop(); else rpgPlay($("#rpg-input").value);
  }
});
$("#rpg-input").addEventListener("input", () => {
  const el = $("#rpg-input");
  el.style.height = "auto";
  el.style.height = Math.min(el.scrollHeight, 160) + "px";
});
document.addEventListener("click", (e) => {
  if (e.target.classList && e.target.classList.contains("chip") && e.target.dataset.genre) {
    $("#rpg-new-genre").value = e.target.dataset.genre;
    rpgNewGame();
  }
});

/* ---------------- task board widget: silent state tracker ---------------- */
function renderBoard(board) {
  const w = document.getElementById("board-widget");
  if (!w || !board) return;
  const c = board.counts || {};
  const setN = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v || 0; };
  setN("b-todo", c.todo); setN("b-prog", c.in_progress); setN("b-done", c.completed);
  const ip = board.in_progress || [];
  const cur = document.getElementById("b-current");
  if (cur) cur.textContent = ip.length ? "▶ " + (ip[0].title || ip[0].id) : "idle";
  w.hidden = false;
}
async function refreshBoard() {
  try { renderBoard(await fetchJSON("/api/board")); } catch { /* no agent yet */ }
}

/* ---------------- boot: load saved chats ---------------- */
(async () => {
  await loadSessions();
  if (currentSessionId) openSession(currentSessionId);
  refreshBoard();
})();
