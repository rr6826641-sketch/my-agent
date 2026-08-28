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
document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
    $("#view-" + btn.dataset.view).classList.add("active");
    if (btn.dataset.view === "tools") loadTools();
    if (btn.dataset.view === "memory") loadMemory();
    if (btn.dataset.view === "settings") loadSettings();
    if (btn.dataset.view === "system") loadSystem();
  });
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
    if (m.role === "user") {
      addUserMsg(m.content || "");
    } else if (m.role === "assistant") {
      const bubble = addAssistantBubble((m.kind === "error" ? "⚠️ " : "") + (m.content || ""));
      if (m.kind === "thinking") bubble.classList.add("thinking");
    } else if (m.role === "tool") {
      addToolCard(m.name || "?", typeof m.arguments === "string" ? m.arguments : JSON.stringify(m.arguments || ""));
      if (m.result != null) {
        const cards = chatLog.querySelectorAll(".toolcard");
        const card = cards[cards.length - 1];
        if (card) {
          card.querySelector(".result").textContent = m.result;
          if (/error|failed|not installed|timed out/i.test(m.result)) card.classList.add("err");
        }
      }
    }
  });
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

/* ---------------- send / SSE ---------------- */
function sendMessage(text) {
  if (busy || !text.trim()) return;
  const message = text.trim();
  inputBox.value = "";
  autosize();
  addUserMsg(message);
  let typing = addTyping();
  busy = true;
  $("#send").disabled = true;
  $("#chat-hint").textContent = "working…";
  armWatchdogTotal(); // hard cap on the whole request
  armWatchdog();      // inactivity watchdog, re-armed on every SSE event

  const es = new EventSource("/api/chat?message=" + encodeURIComponent(message));
  let finalAdded = false;
  let preview = null; // last "llm" bubble — upgraded to final instead of duplicating

  // clean end of stream: clear "working…", reset busy so the next
  // message can be sent (manual es.close() does NOT fire onerror).
  // Idempotent — watchdog + error paths can race, so the "working…"
  // state can never stay stuck after a request finishes.
  function finish(note) {
    if (!busy) return;
    clearTimeout(watchdogInactive);
    clearTimeout(watchdogTotal);
    es.close();
    typing.remove();
    busy = false;
    $("#send").disabled = false;
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

  es.onmessage = (ev) => {
    let e;
    try { e = JSON.parse(ev.data); } catch { return; }
    armWatchdog(); // any event counts as activity
    if (e.type === "start") return;

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
    }
    scrollDown();
  };

  es.onerror = () => {
    if (!finalAdded) {
      addAssistantBubble("⚠️ connection closed");
      finalAdded = true;
    }
    finish(); // network drop — release busy so the user can retry
  };
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
$("#send").addEventListener("click", () => sendMessage(inputBox.value));

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
async function loadSettings() {
  const s = await fetchJSON("/api/settings");
  $("#set-key").value = s.api_key || "";
  $("#set-url").value = s.base_url || "";
  $("#set-model").value = s.model || "";
  $("#set-mock").checked = !!s.mock;
  $("#set-iter").value = s.max_iterations || 12;
}
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
      mock: $("#set-mock").checked,
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
    const dot = $("#dot-mode");
    dot.className = "dot " + (s.mode === "live" ? "live" : "mock");
    $("#status-mode").textContent = s.mode === "live" ? "live · " + s.model : "mock mode";
    $("#status-model").textContent = s.mode === "live" ? s.base_url : "built-in test LLM";
    $("#pill-mode").textContent = (s.mode === "live" ? "● LIVE · " : "◐ MOCK · ") + s.model;
    $("#pill-mode").className = "pill " + s.mode;
    $("#badge-tools").textContent = s.tools;
  } catch { /* ignore */ }
}

refreshStatus();
setInterval(refreshStatus, 10000);

/* ---------------- boot: load saved chats ---------------- */
(async () => {
  await loadSessions();
  if (currentSessionId) openSession(currentSessionId);
})();
