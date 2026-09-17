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

/* ============================================================
   Interaction Bar Controller  (Phase 2)
   Single source of truth for the three composer dropdowns
   (Access / Scope / Mode) plus the main text input.

   - State (access/scope/mode + typed draft) is hydrated from
     localStorage, so a page reload keeps the operator's choices.
   - Every selection change persists immediately, flashes the
     changed dropdown tile and rewrites the composer placeholder
     to match the active Mode (Auto / Step-By-Step / Research).
   - sendMessage() reads the current config through .get()
     instead of poking the DOM, so Access + Scope + Mode (Auto by
     default) always reach /api/chat in one consistent payload.
   ============================================================ */
const InteractionBarController = (() => {
  const LS_KEY = "hackerai.interactionbar.v1";
  const DEFAULTS = { access: "full", scope: "local", mode: "auto" };
  /* SCOPE DECISION (2026-09-07): global, NOT per-session.
     Access/Scope/Mode define the AGENT RUN POSTURE, not chat content -
     they are set_run_control() directives applied to every /api/chat run.
     Per-session persistence would silently reset Mode on a new chat (e.g.
     step-approval off mid-assessment) and desync the bar from the run.
     Sessions server-side are lightweight history records; a single global
     posture is predictable for a single-operator local tool.
     If per-session behavior is ever wanted: key LS_KEY per session id
     (hackerai.interactionbar.v1.<sid>) with DEFAULTS fallback. */
  const GROUPS = ["access", "scope", "mode"];
  const MODE_HINTS = {
    auto:     "Awaiting input — type a command or request…",
    step:     "Step-By-Step — the agent will pause and ask before each tool call",
    research: "Research-Only — the agent searches and reads, no commands run",
  };
  const state = { ...DEFAULTS };

  const el = (id) => document.getElementById(id);

  // accepted values come from the control: <select> options or
  // segmented-toggle buttons ([data-value]) - Mode is a seg toggle,
  // Access/Scope stay dropdowns.
  function allowedValues(group) {
    const c = el("ibar-" + group);
    if (!c) return [];
    if (c.tagName === "SELECT") return Array.from(c.options).map((o) => o.value);
    return Array.from(c.querySelectorAll("[data-value]")).map((b) => b.dataset.value);
  }
  function validValue(group, value) {
    return !!value && allowedValues(group).includes(value);
  }

  function save() {
    try { localStorage.setItem(LS_KEY, JSON.stringify(state)); } catch { /* storage blocked */ }
  }

  function load() {
    try {
      const raw = JSON.parse(localStorage.getItem(LS_KEY) || "null");
      if (raw && typeof raw === "object") {
        GROUPS.forEach((g) => { if (validValue(g, raw[g])) state[g] = raw[g]; });
        if (typeof raw.draft === "string") state.draft = raw.draft;
      }
    } catch { /* corrupt / blocked storage -> keep defaults */ }
  }

  // push state into the DOM: select values, bar dataset, placeholder
  function reflect() {
    const bar = el("interaction-bar");
    if (bar) {
      bar.dataset.access = state.access;
      bar.dataset.scope = state.scope;
      bar.dataset.mode = state.mode;
    }
    GROUPS.forEach((g) => {
      const c = el("ibar-" + g);
      if (!c) return;
      if (c.tagName === "SELECT") {
        if (c.value !== state[g]) c.value = state[g];
      } else {
        c.querySelectorAll("[data-value]").forEach((b) => {
          const on = b.dataset.value === state[g];
          b.classList.toggle("active", on);
          b.setAttribute("aria-pressed", on ? "true" : "false");
        });
      }
    });
    const input = el("input");
    if (input) {
      input.placeholder = MODE_HINTS[state.mode] || MODE_HINTS.auto;
      if (typeof state.draft === "string" && input.value !== state.draft) {
        input.value = state.draft;
        input.dispatchEvent(new Event("input", { bubbles: true })); // re-autosize
      }
    }
  }

  // short red pulse on the tile that just changed
  function flash(group) {
    const ctl = el("ibar-" + group);
    const tile = ctl && ctl.closest(".ibar-group");
    if (!tile) return;
    tile.classList.remove("ibar-flash");
    void tile.offsetWidth; // restart the animation
    tile.classList.add("ibar-flash");
    setTimeout(() => tile.classList.remove("ibar-flash"), 750);
  }

  function bind() {
    GROUPS.forEach((g) => {
      const c = el("ibar-" + g);
      if (!c) return;
      const commit = (v) => {
        if (validValue(g, v)) state[g] = v;
        save();
        reflect();
        flash(g);
      };
      if (c.tagName === "SELECT") {
        c.addEventListener("change", () => commit(c.value));
      } else {
        c.addEventListener("click", (ev) => {
          const btn = ev.target.closest("[data-value]");
          if (btn) commit(btn.dataset.value);
        });
      }
    });
    const input = el("input");
    if (input) {
      input.addEventListener("input", () => {
        state.draft = input.value;
        save();
      });
    }
  }

  load();
  reflect();
  bind();

  return {
    // config the backend should run with ({access,scope,mode})
    get() { return { access: state.access, scope: state.scope, mode: state.mode }; },
    // programmatic override (validated per group); returns new config
    set(partial) {
      Object.keys(partial || {}).forEach((g) => {
        if (GROUPS.includes(g) && validValue(g, partial[g])) state[g] = partial[g];
      });
      save();
      reflect();
      return this.get();
    },
    // called by sendMessage() once a message is consumed: the stored
    // textarea draft is dropped so a reload never re-sends old input
    messageSent() {
      if (state.draft) { state.draft = ""; save(); }
      const input = el("input");
      if (input) input.placeholder = MODE_HINTS[state.mode] || MODE_HINTS.auto;
    },
    // introspection hook for tests / console debugging
    _state() { return { ...state }; },
  };
})();

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
let currentSettingsPane = "general";

function openSettingsPane(name) {
  const tab = document.querySelector(`.settings-tab[data-subview="${name}"]`);
  if (!tab) return;
  document.querySelectorAll(".settings-tab").forEach((t) => {
    const on = t === tab;
    t.classList.toggle("active", on);
    t.setAttribute("aria-selected", on ? "true" : "false");
  });
  document.querySelectorAll(".settings-pane").forEach((p) => {
    const on = p.id === "pane-" + name;
    p.classList.toggle("active", on);
    p.setAttribute("aria-hidden", on ? "false" : "true");
    if (on) { const sc = p.querySelector(".pane-scroll"); if (sc) sc.scrollTop = 0; }
  });
  currentSettingsPane = name;
  if (name === "tools") loadTools();
  if (name === "memory") loadMemory();
  if (name === "reports") loadReports();
  if (name === "rpg") loadRPGView();
  if (name === "general") { loadSettings(); loadPersona(); }
  if (name === "system") loadSystem();
  if (name === "input") loadDesktopPanel();
}

function goToSettingsPane(name) {
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  const navBtn = document.querySelector('.nav-item[data-view="settings"]');
  if (navBtn) navBtn.classList.add("active");
  const view = $("#view-settings");
  if (view) view.classList.add("active");
  openSettingsPane(name);
}

function switchView(name) {
  if (name !== "settings" && ["tools", "memory", "reports", "rpg", "system", "input", "general"].indexOf(name) !== -1) {
    goToSettingsPane(name);
    return;
  }
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  const navBtn = document.querySelector(`.nav-item[data-view="${name}"]`);
  if (navBtn) navBtn.classList.add("active");
  const view = $("#view-" + name);
  if (view) view.classList.add("active");
  if (name === "chat") updateExportPill();
  if (name === "settings") openSettingsPane(currentSettingsPane);
}

document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => switchView(btn.dataset.view));
});

document.querySelectorAll(".settings-tab").forEach((btn) => {
  btn.addEventListener("click", () => openSettingsPane(btn.dataset.subview));
});

$("#btn-new").addEventListener("click", () => {
  if (busy) return;
  newChat();
});

function updateExportPill() {
  const pill = $("#pill-export");
  if (pill) pill.disabled = !currentSessionId;
}

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
  if (!(e.target instanceof Element)) return;
  const chip = e.target.closest(".chip[data-msg]");
  if (chip) sendMessage(chip.dataset.msg);
});

/* ---------------- chat sessions (persistent history) ---------------- */
function newChat() {
  if (busy) return;
  currentSessionId = null;
  chatLog.innerHTML = "";
  clearAttachTray();
  updateExportPill();
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
    clearAttachTray();
    updateExportPill();
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
  clearAttachTray();
  renderSession(s);
  updateExportPill();
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
/* message meta row: local timestamp + copy-to-clipboard button.
   Fully additive - never touches .avatar/.bubble structure, so all
   asserted strings in the UI contract stay byte-identical. */
function setupMsgMeta(m) {
  const meta = document.createElement("div");
  meta.className = "msg-meta";
  const time = document.createElement("time");
  time.className = "mm-time";
  time.textContent = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "mm-copy";
  btn.title = "Copy message";
  btn.setAttribute("aria-label", "Copy message");
  btn.textContent = "\u2398";
  btn.addEventListener("click", () => {
    const bubble = m.querySelector(".bubble");
    if (bubble && navigator.clipboard) {
      navigator.clipboard.writeText(bubble.textContent);
      btn.classList.add("copied");
      btn.textContent = "\u2713";
      setTimeout(() => { btn.classList.remove("copied"); btn.textContent = "\u2398"; }, 1200);
    }
  });
  meta.append(time, btn);
  m.appendChild(meta);
}

function addUserMsg(text) {
  const m = document.createElement("div");
  m.className = "msg user";
  m.innerHTML = `<div class="avatar">🧑</div><div class="bubble">${escapeHtml(text)}</div>`;
  chatLog.appendChild(m);
  setupMsgMeta(m);
  scrollDown();
}

function addAssistantBubble(text) {
  const m = document.createElement("div");
  m.className = "msg assistant";
  m.innerHTML = `<div class="avatar">🤖</div><div class="bubble"></div>`;
  mdToDom(text, m.querySelector(".bubble"));
  chatLog.appendChild(m);
  setupMsgMeta(m);
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

function scrollToBottom() {
  // Drive the viewport to the physically last pixel: the 120px dynamic
  // bottom padding on .chat-log keeps the final line clear of the
  // sticky composer dock, so the last rendered row is always visible.
  if (!chatLog) return;
  chatLog.scrollTop = chatLog.scrollHeight;
}
function scrollDown() { scrollToBottom(); }

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

/* 4-stage autonomous pipeline: header + per-stage status chips */
function addPipelineHeader(target, stageCount) {
  const div = document.createElement("div");
  div.className = "route-chip pipeline-header";
  div.dataset.target = target || "";
  div.innerHTML =
    `<span class="route-ico">🛡</span><span class="route-txt"><b>Autonomous Pipeline</b>` +
    ` <span class="route-reason">· ${escapeHtml(target || "?")} · 0/${stageCount || 4} stages</span></span>`;
  chatLog.appendChild(div);
  scrollDown();
  return div;
}

function addPipelineStage(num, title, status) {
  // update the pipeline header's stage counter + append a status chip
  const headers = chatLog.querySelectorAll(".pipeline-header");
  const header = headers[headers.length - 1];
  if (header) {
    const target = header.dataset.target || "?";
    const stages = header.querySelectorAll(".stage-chip").length;
    const done = header.querySelectorAll(".stage-chip.done").length +
      (status === "done" && !header.querySelector(`.stage-chip[data-num="${num}"].done`) ? 1 : 0);
    header.querySelector(".route-reason").textContent =
      ` · ${target} · ${done}/${Math.max(stages, num)} stages`;
  }
  const div = document.createElement("div");
  div.className = "route-chip stage-chip " + (status || "running");
  div.dataset.num = num || "";
  const ico = status === "done" ? "✅" : "⏳";
  div.innerHTML =
    `<span class="route-ico">${ico}</span><span class="route-txt"><b>Stage ${escapeHtml(String(num))}</b>` +
    ` <span class="route-reason">· ${escapeHtml(title || "")}${status === "done" ? " · complete" : " · running…"}</span></span>`;
  chatLog.appendChild(div);
  scrollDown();
  return div;
}

function addToolCard(name, args, parallel) {
  const div = document.createElement("div");
  div.className = "toolcard";
  div.innerHTML = `
    <div class="toolcard-head">
      <span class="t-name">${escapeHtml(name)}${parallel ? " <em class=par>⚡ parallel</em>" : ""}</span>
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
function addStepApproval(key, tool, argsText) {
  const div = document.createElement("div");
  div.className = "toolcard step-card";
  const h = document.createElement("div");
  h.className = "toolname";
  h.innerHTML = `<span class="step-ico">🛂</span> Step-By-Step Approval · <b>${escapeHtml(tool)}</b>`;
  const r = document.createElement("div");
  r.className = "result";
  r.textContent = typeof argsText === "string" ? argsText : JSON.stringify(argsText || "");
  const st = document.createElement("div");
  st.className = "step-status";
  st.textContent = "waiting for operator…";
  const b = document.createElement("div");
  b.className = "step-btns";
  const mk = (label, decision, cls) => {
    const btn = document.createElement("button");
    btn.className = "step-btn " + cls;
    btn.textContent = label;
    btn.onclick = () => {
      b.querySelectorAll("button").forEach(x => x.disabled = true);
      st.textContent = decision.indexOf("allow") === 0 ? "⏩ run continues (all allowed)"
                   : decision.indexOf("reject") === 0 ? "⛔ rejected — run continues (all rejected)"
                   : decision === "approve" ? "✅ approved — running" : "⛔ rejected";
      fetch("/api/chat/step", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key, decision })
      }).catch(() => { st.textContent = "⚠️ submit failed"; });
    };
    return btn;
  };
  b.append(mk("✅ Approve", "approve", "ok"),
           mk("⛔ Reject", "reject", "no"),
           mk("⏩ Run All", "allow_all", "all"),
           mk("🚫 Reject All", "reject_all", "no"));
  div.append(h, r, st, b);
  chatLog.appendChild(div);
  scrollDown();
}

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
    grid.innerHTML = `<p class="muted report-empty">⚠️ Reports failed to load — check the server.</p>`;
  }
}

function renderReports(reports) {
  const grid = $("#report-grid");
  if (!grid) return;
  if (!reports.length) {
    grid.innerHTML = `<p class="muted report-empty">No reports yet — run an assessment in chat to generate your first report.</p>`;
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

/* =============================================================
   LIVE AGENT ACTIVITY PANEL
   Renders REAL execution events only. Every timeline row / tool
   card / status change is driven by an actual lifecycle event from
   the running Agent:
     - /api/chat SSE        (task_started, planning, tool_call,
                             tool_result, final, error, pipeline_*,
                             validation_*, task_completed, task_failed)
     - /api/exec/stream SSE (terminal / git / sub-agent events with
                             real command + stdout, via EventStreamHub)
   Nothing is invented, faked, or hardcoded. Output is sanitized so
   secrets/keys/tokens never reach the panel.
   ============================================================= */
const ActivityPanel = (() => {
  const MAX_ROWS = 250, MAX_TOOLS = 60;
  let rows = [];        // timeline row elements (oldest first)
  let tools = [];       // tool card elements
  let openTools = [];   // stack of started-but-unfinished tool cards
  let runState = "WAITING";
  let stepCounter = 0;
  let totalSteps = 0;          // announced stage count (0 = unknown)
  let processingRow = null;  // "Processing result" row
  let thinkingRow = null;    // "Generating response" row
  let execSource = null;
  let execLine = 1;          // unique id for exec rows
  let userScrolled = false;  // user scrolled up -> pause auto-scroll
  let execLog = [];          // chronological execution log (EXECUTION LOG)
  const LOG_MAX = 600;

  const byId = (id) => document.getElementById(id);

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  // Redact obvious secrets so the panel never leaks credentials.
  function sanitizeRaw(s) {
    let out = String(s == null ? "" : s);
    out = out.replace(/(sk-[A-Za-z0-9_-]{8,})/g, "sk-••••••");
    out = out.replace(/(ghp_[A-Za-z0-9]{12,})/g, "ghp_••••••");
    out = out.replace(/((?:Bearer|Authorization|api[_-]?key|apikey|password|passwd|secret|token|client[_-]?secret)\s*[:=]\s*)(["']?)[A-Za-z0-9._\-]{6,}\2/gi, "$1••••••");
    return out;
  }
  const sanitize = sanitizeRaw;

  // EXECUTION LOG: chronological, user-safe history of REAL events.
  function logLine(type, tool, detail) {
    const line = { ts: tsNow(), type: String(type || "").toUpperCase(), tool: tool || "", detail: sanitize(String(detail || "")) };
    execLog.push(line);
    if (execLog.length > LOG_MAX) execLog.shift();
    const pre = byId("activity-log");
    if (!pre) return;
    pre.textContent = execLog.map((l) => l.ts + "  " + l.type.padEnd(20, " ") + (l.tool ? "[" + l.tool + "] " : "") + l.detail).join("\n");
    const cnt = byId("activity-log-count");
    if (cnt) cnt.textContent = execLog.length + " event" + (execLog.length === 1 ? "" : "s");
    const body = byId("activity-log-body");
    if (body && !body.hidden) body.scrollTop = body.scrollHeight;
  }

  // Auto-scroll helper: paused while the user browses history.
  function autoScrollToBottom(box) {
    if (!userScrolled && box) box.scrollTop = box.scrollHeight;
  }

  function tsNow() {
    return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }
  function fmtMs(ms) {
    if (!ms) return "";
    if (ms < 1000) return Math.round(ms) + "ms";
    return (ms / 1000).toFixed(1) + "s";
  }
  function shortArgs(args) {
    let s = (typeof args === "string" ? args : JSON.stringify(args));
    s = sanitize(s.length > 260 ? s.slice(0, 260) + "…" : s);
    return esc(s); // escape AFTER sanitize so HTML from args can't inject
  }

  function setStatus(state, text, cls) {
    runState = state;
    // legacy markup fallback (kept for compatibility)
    const pill = byId("activity-status-pill");
    const led = byId("activity-led");
    const txt = byId("activity-status-text");
    if (pill) pill.className = "pill " + (cls || "smart");
    if (led) led.className = "led " + (state === "RUNNING" ? "green" : state === "FAILED" ? "red" : state === "COMPLETED" ? "green" : "amber");
    if (txt) txt.textContent = text || state;
    // COMMAND CENTER status bar — LED, state text, LIVE badge, scanlines
    const st = byId("cc-status");
    const stx = byId("cc-state");
    const live = byId("cc-live");
    if (st) st.dataset.state = state || "IDLE";
    if (stx) stx.textContent = text || state || "IDLE";
    if (live) live.hidden = !(state === "RUNNING" || state === "PLANNING" || state === "WAITING" || state === "VERIFYING");
    const body = byId("activity-body");
    if (body) body.classList.toggle("cc-live-body", state === "RUNNING" || state === "PLANNING" || state === "VERIFYING");
  }

  // STEP COUNTER — real progress only: "STEP 3 / 7" when the run
  // announced a stage count, otherwise just "STEP 3". Never fabricates.
  function updateStepCounter() {
    const el = byId("cc-step");
    if (!el) return;
    el.textContent = totalSteps > 0 ? ("STEP " + stepCounter + " / " + totalSteps) : ("STEP " + stepCounter);
  }

  function emptyHint(on) {
    const el = byId("activity-empty");
    if (el) el.style.display = on ? "" : "none";
    const t = byId("activity-tools-empty");
    if (t) t.style.display = (tools.length === 0 && on) ? "" : "none";
  }

  // one timeline row. Returns {row, id, set}(set updates status/sub).
  function mirror(ico, title, sub, status) {
    const wrap = byId("live-feed"), list = byId("lf-list");
    if (!wrap || !list) return;
    wrap.hidden = false;
    const row = document.createElement("div");
    row.className = "lf-row lf-" + (status || "running");
    row.innerHTML = `<span class="lf-ico">${ico}</span>` +
      `<span class="lf-tx">${esc(title)}` +
      (sub ? ` <span class="lf-sub">${esc(sanitize(String(sub)))}</span>` : "") +
      `</span><span class="lf-ts">${esc(tsNow())}</span>`;
    list.appendChild(row);
    while (list.children.length > 140) list.removeChild(list.firstChild);
    list.scrollTop = list.scrollHeight;
    const pill = byId("lf-status");
    if (pill) {
      const txt = status === "completed" ? "COMPLETED"
                : status === "failed" ? "FAILED"
                : status === "waiting" ? "WAITING" : "RUNNING";
      pill.className = "lf-status lf-" + txt.toLowerCase();
      pill.innerHTML = '<i class="lf-led"></i>' + txt;
    }
  }

  function clearMirror() {
    const wrap = byId("live-feed"), list = byId("lf-list");
    if (list) list.innerHTML = "";
    if (wrap) wrap.hidden = true;
    const pill = byId("lf-status");
    if (pill) { pill.className = "lf-status"; pill.innerHTML = '<i class="lf-led"></i>IDLE'; }
  }

  function addRow(ico, title, sub, status, ts) {
    const box = byId("activity-timeline");
    if (!box) return null;
    emptyHint(false);
    const id = "ar" + (++execLine);
    const row = document.createElement("div");
    row.className = "act-row " + status;
    row.id = id;
    row.innerHTML =
      `<span class="act-ico">${ico}</span>` +
      `<span class="act-body"><b class="act-title">${esc(title)}</b>` +
      (sub ? `<span class="act-sub">${esc(sanitize(sub))}</span>` : "") +
      `</span><span class="act-ts">${esc(ts || tsNow())}</span>` +
      `<span class="act-st"></span>`;
    box.appendChild(row);
    rows.push(row);
    while (rows.length > MAX_ROWS) {
      const old = rows.shift();
      if (old && old.parentNode) old.parentNode.removeChild(old);
    }
    autoScrollToBottom(box); // auto-scroll to newest (paused after manual scroll-up)
    try { mirror(ico, title, sub, status); } catch (e) {}
    return {
      row, id,
      set(status, sub) {
        row.className = "act-row " + status;
        const subEl = row.querySelector(".act-sub");
        if (subEl && sub !== undefined) subEl.textContent = sanitize(sub);
        const st = row.querySelector(".act-st");
        if (st) st.textContent = status === "running" ? "RUNNING" : status === "completed" ? "COMPLETED" : status === "failed" ? "FAILED" : (status || "").toUpperCase();
      },
    };
  }

  // status chip used on tool cards
  function chip(state, text) {
    return `<span class="act-chip act-chip-${state}">${esc(text || state.toUpperCase())}</span>`;
  }

  // one tool card (TOOL EXECUTION column). Real tool_call / tool_result
  // events drive start and completion; terminal exec events update rows.
  function addToolCard(name, args, evId, status) {
    const box = byId("activity-tools");
    if (!box) return null;
    emptyHint(false);
    const card = document.createElement("div");
    const startedMs = Date.now();
    card.className = "act-tool act-tool-running";
    card.innerHTML =
      `<div class="act-tool-head"><b class="act-tool-name">${esc(name)}</b> ${chip("running", "RUNNING")}</div>` +
      `<div class="act-tool-body">` +
      `<div class="act-tool-row"><span class="act-tool-k">ACTION</span><span class="act-tool-v">${shortArgs(args)}</span></div>` +
      `<div class="act-tool-row"><span class="act-tool-k">START</span><span class="act-tool-v act-tool-ts">${esc(tsNow())}</span></div>` +
      `<pre class="act-tool-out"></pre>` +
      `</div>`;
    box.appendChild(card);
    tools.push(card);
    while (tools.length > MAX_TOOLS) {
      const old = tools.shift();
      if (old && old.parentNode) old.parentNode.removeChild(old);
    }
    const rec = { card, name, startedMs, startedAt: tsNow(), status: status || "running", evId };
    openTools.push(rec);
    return rec;
  }

  function findOpenTool(evId) {
    if (openTools.length) {
      // prefer the top of the stack (last started) — matches the real
      // execution order of the Agent's tool loop
      return openTools[openTools.length - 1];
    }
    return null;
  }

  function finishTool(rec, ok, output, evId) {
    if (!rec || !rec.card || !rec.card.isConnected) { openTools.shift(); return; }
    const idx = openTools.indexOf(rec);
    if (idx !== -1) openTools.splice(idx, 1);
    const state = ok ? "completed" : "failed";
    rec.card.className = "act-tool act-tool-" + state;
    const durMs = Date.now() - rec.startedMs;
    const head = rec.card.querySelector(".act-tool-head");
    if (head) {
      head.innerHTML = `<b class="act-tool-name">${esc(rec.name)}</b> ` +
        (ok ? chip("completed", "COMPLETED") : chip("failed", "FAILED"));
      const end = document.createElement("div");
      end.className = "act-tool-row";
      end.innerHTML = `<span class="act-tool-k">${ok ? "DONE" : "END"}</span><span class="act-tool-v act-tool-ts">${esc(tsNow())}${durMs >= 0 ? " · " + esc(fmtMs(durMs)) : ""}</span>`;
      rec.card.querySelector(".act-tool-body").appendChild(end);
    }
    const out = rec.card.querySelector(".act-tool-out");
    if (out) {
      const snippet = String(output || "").slice(0, 350);
      out.textContent = sanitize(snippet) || "(no output)";
      out.style.display = snippet ? "block" : "none";
    }
  }

  function showFinal(title, content, failed) {
    const box = byId("activity-final");
    if (!box) return;
    box.hidden = false;
    box.className = "activity-final" + (failed ? " activity-final-fail" : "");
    const head = box.querySelector(".activity-final-head");
    if (head) head.textContent = failed ? "✗ TASK FAILED — REASON" : title || "✓ TASK COMPLETED — FINAL RESULT";
    const body = byId("activity-final-body");
    if (body) body.textContent = sanitize(String(content || "").slice(0, 6000));
  }

  function closeExecStream() {
    if (execSource) {
      try { execSource.close(); } catch (e) { /* noop */ }
      execSource = null;
    }
  }

  // /api/exec/stream — REAL terminal / git / sub-agent execution events
  // from the backend EventStreamHub. Only events belonging to the current
  // run are shown, and step_type "tool" is skipped because chat SSE
  // already covers tool_call/tool_result (avoids duplicate entries).
  function openExecStream() {
    closeExecStream();
    try {
      execSource = new EventSource("/api/exec/stream?after=0");
      // FIX: backend sends `event: exec`, so onmessage never fired.
      execSource.addEventListener("exec", (msg) => {
        let evt;
        try { evt = JSON.parse(msg.data); } catch (e) { return; }
        if (evt.run_id && activeRunId && evt.run_id !== activeRunId) return;
        if (evt.step_type === "tool") return; // covered by chat lifecycle
        const cmd = sanitize(String(evt.command || evt.detail || evt.name || ""));
        const out = sanitize(String(evt.stdout || evt.stderr || ""));
        if (evt.status === "running") {
          logLine("EXEC_STARTED", evt.step_type || "exec", cmd.slice(0, 120));
          const r = addRow("⚙", (evt.step_type || "tool").toUpperCase() + " — running", cmd, "running");
          if (r) r.row.dataset.eid = "exec" + evt.ts;
        } else {
          const ok = evt.status !== "failed" && evt.status !== "cancelled";
          logLine("EXEC_" + (ok ? "COMPLETED" : "FAILED"), evt.step_type || "exec", (cmd + (out ? " — " + out.slice(0, 60) : "")).slice(0, 220));
          const rowsAll = byId("activity-timeline").querySelectorAll(".act-row");
          const last = rowsAll[rowsAll.length - 1];
          const r = addRow(ok ? "✓" : "✗", (evt.step_type || "tool").toUpperCase() + " — " + (ok ? "completed" : evt.status), cmd, ok ? "completed" : "failed");
          if (r && out) {
            const subEl = r.row.querySelector(".act-sub");
            if (subEl) subEl.textContent = out.slice(0, 160);
          }
          if (evt.duration_ms) {
            const tsEl = r.row.querySelector(".act-ts");
            if (tsEl) tsEl.textContent = tsNow() + " · " + fmtMs(evt.duration_ms);
          }
        }
      });
    } catch (e) {
      execSource = null;
    }
  }

  function reset() {
    closeExecStream();
    const t = byId("activity-timeline"); if (t) t.innerHTML = "";
    const tw = byId("activity-tools"); if (tw) tw.innerHTML = "";
    const fin = byId("activity-final"); if (fin) { fin.hidden = true; }
    rows = []; tools = []; openTools = [];
  execLog = [];
  const logPre = byId("activity-log"); if (logPre) logPre.textContent = "";
  const logCnt = byId("activity-log-count"); if (logCnt) logCnt.textContent = "0 events";
    stepCounter = 0; totalSteps = 0; processingRow = null; thinkingRow = null;
    clearMirror();
    emptyHint(true);
    updateStepCounter();
    setStatus("IDLE", "IDLE", "smart");
  }

  // Mapper: one REAL chat-SSE event -> panel updates. Called once per
  // event, from the existing stream handler. Pure real events only.
  const LOG_LBL = {
    task_started: "TASK_STARTED", planning: "PLANNING", route: "MODEL_ROUTED",
    pipeline_start: "PIPELINE_STARTED", stage_start: "STEP_STARTED",
    stage_complete: "STEP_COMPLETED", pipeline_done: "TASK_COMPLETED",
    final: "TASK_COMPLETED", llm: "GENERATING", delta: "PROCESSING",
    tool_call: "TOOL_STARTED", tool_result: "TOOL_COMPLETED",
    step_approval: "WAITING_APPROVAL", error: "TASK_FAILED",
    artifacts: "ARTIFACTS_SAVED", notice: "RETRY",
    task_completed: "TASK_COMPLETED", task_failed: "TASK_FAILED"
  };
  function onLifecycle(e) {
    const type = e.type;
    try {
      logLine(LOG_LBL[type] || type || "EVENT",
        (String(type).indexOf("tool") >= 0 ? String(e.name || "tool") : String(e.scope || "")),
        String(e.detail || e.reason || e.content || "").slice(0, 90));
      if (type === "task_started") {
        setStatus("RUNNING", "RUNNING", "smart");
        addRow("●", "Task started", "", "running");
        return;
      }
      if (type === "planning") {
        setStatus("PLANNING", "PLANNING", "smart");
        addRow("→", "Analyzing request — building execution plan", e.detail || "", "running");
        return;
      }
      if (type === "route") {
        addRow("→", "Model routed", "Smart Router → " + (e.label || e.model || "auto") + (e.reason ? " · " + e.reason : ""), "completed");
        return;
      }
      if (type === "pipeline_start") {
        stepCounter = 0;
        totalSteps = (e.stages || []).length || 0;
        updateStepCounter();
        pipeStep = 0;
        addRow("●", "Autonomous pipeline started", (e.target || "") + " · " + ((e.stages || []).length || 4) + " stages", "running");
        return;
      }
      if (type === "stage_start") {
        pipeStep = (e.num != null ? e.num : (pipeStep + 1));
        stepCounter = pipeStep;
        updateStepCounter();
        pipeRows[pipeStep] = addRow("→", "Stage " + pipeStep + ": " + (e.title || ""), "", "running");
        return;
      }
      if (type === "stage_complete") {
        const r = pipeRows[(e.num != null ? e.num : pipeStep)];
        if (r) r.set("completed", "✓ Stage finished");
        return;
      }
      if (type === "pipeline_done") {
        setStatus("COMPLETED", "COMPLETED", "smart");
        addRow("✓", "Task completed", "pipeline finished", "completed");
        showFinal("✓ TASK COMPLETED — FINAL RESULT", e.report || "");
        return;
      }
      if (type === "llm") {
        if (!thinkingRow) thinkingRow = addRow("○", "Generating response…", "", "running");
        return;
      }
      if (type === "delta") {
        if (!processingRow) processingRow = addRow("○", "Processing result…", "", "running");
        return;
      }
      if (type === "tool_call") {
        if (processingRow) { processingRow.set("completed", "✓ Result obtained"); processingRow = null; }
        if (thinkingRow) { thinkingRow.set("completed", "✓ Reasoning complete"); thinkingRow = null; }
        stepCounter += 1;
        updateStepCounter();
        const t = addRow("●", "Executing tool: " + (e.name || "tool"), "Step " + stepCounter + " — " + shortArgs(e.arguments), "running");
        const rec = addToolCard(e.name || "tool", e.arguments, e.id, "running");
        if (t && rec) rec.toolRow = t;
        return;
      }
      if (type === "tool_result") {
        const failed = /error|failed|not installed|timed out|exception/i.test(e.content || "");
        const rec = findOpenTool(null);
        if (rec) {
          finishTool(rec, !failed, e.content, e.id);
          if (rec.toolRow) rec.toolRow.set(failed ? "failed" : "completed", failed ? "✗ Tool failed" : "✓ Tool completed");
        } else {
          addRow(failed ? "✗" : "✓", "Tool result", !failed ? "✓ completed" : "✗ failed", failed ? "failed" : "completed");
        }
        return;
      }
      if (type === "step_approval") {
        addRow("⏸", "Waiting for operator approval", "Step-By-Step mode — ", "waiting");
        return;
      }
      if (type === "final") {
        setStatus("COMPLETED", "COMPLETED", "smart");
        if (processingRow) { processingRow.set("completed", "✓ Processing done"); processingRow = null; }
        if (thinkingRow) { thinkingRow.set("completed", "✓ Response generated"); thinkingRow = null; }
        addRow("✓", "Task completed — final response ready", "", "completed");
        showFinal("✓ TASK COMPLETED — FINAL RESULT", e.content || "");
        return;
      }
      if (type === "error") {
        setStatus("FAILED", "FAILED", "danger");
        addRow("✗", "Task failed", e.content || "run error", "failed");
        showFinal("✗ TASK FAILED — REASON", e.content || "run error", true);
        return;
      }
      if (type === "artifacts") {
        addRow("✓", "Artifacts saved", (e.artifacts || []).length + " output(s) stored", "completed");
        return;
      }
      if (type === "notice") {
        addRow("☠", "Red Team retry", e.text || e.content || "auto-retry", "completed");
        return;
      }
      if (type === "validation_spawned") {
        addRow("⇄", "Validation sub-agent spawned", e.reason || "", "running");
        return;
      }
      if (type === "validation_start") {
        addRow("⇄", "Validator re-checking findings", (e.count || 0) + " finding(s)", "running");
        return;
      }
      if (type === "validation_tool_call") {
        const t = addRow("●", "Validator tool: " + (e.name || "tool"), "VAL — " + shortArgs(e.arguments), "running");
        const rec = addToolCard("VAL " + (e.name || "tool"), e.arguments, e.id, "running");
        if (t && rec) rec.toolRow = t;
        return;
      }
      if (type === "validation_tool_result") {
        const failed = /error|failed|not installed|timed out/i.test(e.content || "");
        const rec = findOpenTool(null);
        if (rec) {
          finishTool(rec, !failed, e.content, e.id);
          if (rec.toolRow) rec.toolRow.set(failed ? "failed" : "completed", failed ? "✗ Tool failed" : "✓ Tool completed");
        }
        return;
      }
      if (type === "validation") {
        addRow("⇄", "Validator: " + (e.status || "finding"), e.finding ? (e.status === "rejected" ? "✗ " : "✓ ") + String(e.finding).slice(0, 140) : (e.reason || ""), e.status === "rejected" ? "failed" : "completed");
        return;
      }
      if (type === "validation_done") {
        setStatus("COMPLETED", "COMPLETED", "smart");
        addRow("✓", "Validation complete", (e.summary || "") + " · " + (Number(e.verified) || 0) + " verified", "completed");
        return;
      }
      if (type === "task_completed") {
        setStatus("COMPLETED", "COMPLETED", "smart");
        addRow("✓", "Task completed", e.note || (e.duration_ms ? "Duration " + fmtMs(e.duration_ms) : ""), "completed");
        return;
      }
      if (type === "task_failed") {
        setStatus("FAILED", "FAILED", "danger");
        addRow("✗", "Task failed", e.reason || "run failed", "failed");
        return;
      }
    } catch (err) {
      // the activity panel must NEVER break the chat stream
    }
  }

  // fin: called when the chat stream ends. Closes the exec stream and
  // reconciles the status pill if no terminal event arrived.
  function onStreamClosed() {
    closeExecStream();
    if (runState === "RUNNING") setStatus("WAITING", "STREAM CLOSED", "smart");
  }

  // track pipeline stage rows between events
  let pipeStep = 0;
  const pipeRows = {};

  const clearBtn = byId("activity-clear");
  if (clearBtn) clearBtn.addEventListener("click", reset);

  // ▼ LIVE scroll-jump: appears after a manual scroll-up; clicking it
  // jumps back to the newest event and resumes auto-scroll.
  const actBox = byId("activity-timeline");
  const liveBtn = byId("act-live-btn");
  if (actBox && liveBtn) {
    actBox.addEventListener("scroll", () => {
      const dist = actBox.scrollHeight - actBox.scrollTop - actBox.clientHeight;
      if (dist > 80) {
        userScrolled = true;
        if (liveBtn.hidden) liveBtn.hidden = false;
      } else if (userScrolled) {
        userScrolled = false;
        liveBtn.hidden = true;
      }
    });
    liveBtn.addEventListener("click", () => {
      userScrolled = false;
      actBox.scrollTop = actBox.scrollHeight;
      liveBtn.hidden = true;
    });
  }

  // EXECUTION LOG: collapsible chronological log of real events.
  const logToggle = byId("activity-log-toggle");
  const logBody = byId("activity-log-body");
  if (logToggle && logBody) {
    logToggle.addEventListener("click", () => {
      const wasCollapsed = logBody.hidden;
      logBody.hidden = !wasCollapsed;
      logToggle.setAttribute("aria-expanded", String(wasCollapsed));
      const lc = byId("activity-log-caret");
      if (lc) lc.textContent = wasCollapsed ? "▴" : "▾";
      if (wasCollapsed) logBody.scrollTop = logBody.scrollHeight;
    });
  }

  const lfToggle = byId("lf-toggle");
  if (lfToggle) lfToggle.addEventListener("click", function () {
    const list = byId("lf-list");
    if (!list) return;
    const collapsed = list.classList.toggle("lf-collapsed");
    lfToggle.textContent = collapsed ? "+" : "—";
  });

  return { reset, onLifecycle, onStreamClosed, openExecStream, setStatus };
})();

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
  ActivityPanel.reset(); // fresh LIVE ACTIVITY run for this message
  inputBox.value = "";
  autosize();
  InteractionBarController.messageSent();
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
    ActivityPanel.onStreamClosed(); // close the exec stream, reconcile status pill
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
      finish("⚠️ connection stalled — no events for 15+ minutes, try again");
    }, 930000);
  }

  function armWatchdogTotal() {
    clearTimeout(watchdogTotal);
    watchdogTotal = setTimeout(() => {
      finish("⚠️ request timed out — stream released");
    }, 3600000);
  }

  // one decoded SSE "data:" payload -> identical rendering to the old
  // EventSource onmessage handler.
  function handleEvent(e) {
    armWatchdog(); // any event counts as activity
    ActivityPanel.onLifecycle(e); // real events -> LIVE ACTIVITY panel
    if (e.type === "start") return;

    if (e.type === "route") {
      // Smart Auto-Model Selector: show which model this answer uses
      addRouteChip(e.label, e.reason);
      return;
    }

    if (e.type === "pipeline_start") {
      // 4-stage autonomous pipeline kicked off for a target
      typing.remove();
      addPipelineHeader(e.target || "", (e.stages || []).length);
      return;
    }
    if (e.type === "stage_start") {
      typing.remove();
      addPipelineStage(e.num, e.title || "", "running");
      return;
    }
    if (e.type === "stage_complete") {
      typing.remove();
      addPipelineStage(e.num, e.title || "", "done");
      return;
    }
    if (e.type === "pipeline_done") {
      typing.remove();
      addAssistantBubble((e.report || "") || "(empty pipeline report)");
      finalAdded = true;
      preview = null;
      finish();
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
      scrollToBottom(); // live stream: keep the growing bubble in view
    } else if (e.type === "tool_call") {
      typing.remove();
      preview = null; // next assistant text gets a fresh bubble
      addToolCard(e.name, typeof e.arguments === "string" ? e.arguments : JSON.stringify(e.arguments || ""), e.parallel);
    } else if (e.type === "step_approval") {
      // Step-By-Step mode: stream is paused until the operator answers
      typing.remove();
      addStepApproval(e.key, e.tool, e.arguments);
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
      scrollToBottom(); // finished render: snap to reveal the last line
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
      // single source of truth: Access / Scope / Mode state is owned by
      // the InteractionBarController (Mode defaults to Auto)
      const ctl = InteractionBarController.get();
      res = await fetch("/api/chat?message=" + encodeURIComponent(message) +
                        "&access=" + encodeURIComponent(ctl.access) +
                        "&scope=" + encodeURIComponent(ctl.scope) +
                        "&mode=" + encodeURIComponent(ctl.mode),
                        { signal: controller.signal });
      if (!res.ok) throw new Error("HTTP " + res.status);
      if (!res.body) throw new Error("stream unavailable");
      activeRunId = res.headers.get("X-Run-Id") || null;
      ActivityPanel.openExecStream(); // REAL terminal/git/sub-agent events
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

/* ============================================================
   Phase 1c - file upload UI: attach button / drag-drop / preview

   Files POST to /api/upload (validated server-side, UUID stored,
   linked to the active chat session). Images get an inline preview
   thumbnail; other types render as a labelled chip. Uploads stay
   bound to the session server-side and are analysed on the next
   turn (_attach_session_files: vision blocks / inline text).
   ============================================================ */
const attachInput = $("#attach-input");
const attachBtn = $("#btn-attach");
const attachTray = $("#attach-tray");
const composerIbar = document.querySelector(".composer-ibar");
let attachBusy = false;

const ATTACH_ALLOWED_EXT = new Set(["png", "jpg", "jpeg", "webp", "txt", "json", "pdf", "pcap"]);
const ATTACH_IMG_EXT = new Set(["png", "jpg", "jpeg", "webp"]);
const ATTACH_ICONS = {
  txt: "\ud83d\udcc4", json: "\u26c1", pdf: "\ud83d\udcd5", pcap: "\ud83d\uddc4",
  png: "\ud83d\uddbc", jpg: "\ud83d\uddbc", jpeg: "\ud83d\uddbc", webp: "\ud83d\uddbc"
};
const ATTACH_LABEL = {
  png: "PNG image", jpg: "JPEG image", jpeg: "JPEG image", webp: "WEBP image",
  txt: "Text file", json: "JSON file", pdf: "PDF document", pcap: "PCAP capture"
};

function attachExt(name) {
  const s = String(name || "");
  const i = s.lastIndexOf(".");
  return i >= 0 ? s.slice(i + 1).toLowerCase() : "";
}

function clearAttachTray() {
  if (!attachTray) return;
  attachTray.innerHTML = "";
  attachTray.hidden = true;
}

function trayNote(text, isErr) {
  if (!attachTray) return;
  clearAttachTray();
  attachTray.hidden = false;
  const n = document.createElement("div");
  n.className = "attach-chip" + (isErr ? " att-err" : "");
  n.textContent = text;
  n.style.cssText = "flex:1 1 100%; padding:6px 10px;";
  attachTray.appendChild(n);
}

function attachChipEl(rec) {
  const chip = document.createElement("div");
  chip.className = "attach-chip";
  const ext = (rec && rec.ext) || attachExt(rec && rec.original_name);
  const prev = document.createElement("span");
  prev.className = "att-prev";
  if (rec && rec.id && ATTACH_IMG_EXT.has(ext)) {
    const img = document.createElement("img");
    img.src = "/api/uploads/" + encodeURIComponent(rec.id);
    img.alt = "";
    prev.appendChild(img);
  } else {
    prev.textContent = (ATTACH_ICONS[ext] || "\ud83d\udcce");
  }
  const meta = document.createElement("span");
  meta.className = "att-meta";
  const nm = document.createElement("span");
  nm.className = "att-name";
  nm.title = (rec && rec.original_name) || "";
  nm.textContent = (rec && rec.original_name) || "file";
  const sub = document.createElement("span");
  sub.className = "att-sub";
  const sizeKB = Math.max(1, Math.round((rec && rec.size ? rec.size : 0) / 1024));
  sub.textContent = (ATTACH_LABEL[ext] || ((rec && rec.mime) || "file").split("/").pop().toUpperCase()) + " \u00b7 " + sizeKB + " KB";
  meta.appendChild(nm);
  meta.appendChild(sub);
  const rm = document.createElement("button");
  rm.type = "button";
  rm.className = "att-rm";
  rm.title = "Remove from tray";
  rm.setAttribute("aria-label", "Remove file");
  rm.textContent = "\u2715";
  rm.addEventListener("click", async () => {
    if (rm.disabled || chip.classList.contains("att-uploading")) return;
    const realId = rec && rec.id;
    // pending / placeholder chip (upload still running or failed): tray-only
    if (!realId) {
      chip.remove();
      if (!attachTray.childElementCount) attachTray.hidden = true;
      return;
    }
    // real server record: remove end-to-end so the file can never be
    // re-injected into the next turn via _attach_session_files()
    rm.disabled = true;
    chip.classList.add("att-rm-busy");
    try {
      let q = "/api/uploads/" + encodeURIComponent(realId);
      if (currentSessionId) q += "?sid=" + encodeURIComponent(currentSessionId);
      const res = await fetch(q, { method: "DELETE" });
      if (!res.ok) {
        throw new Error(res.status === 403 ? "owned by another session"
                                           : ("remove failed (HTTP " + res.status + ")"));
      }
      chip.remove();
      if (!attachTray.childElementCount) attachTray.hidden = true;
    } catch (err) {
      rm.disabled = false;
      chip.classList.remove("att-rm-busy");
      chip.classList.add("att-err");
      const sub = chip.querySelector(".att-sub");
      if (sub) sub.textContent = "✖ " + ((err && err.message) || "remove failed");
    }
  });
  chip.appendChild(prev);
  chip.appendChild(meta);
  chip.appendChild(rm);
  return chip;
}

async function uploadOneFile(file) {
  const fd = new FormData();
  fd.append("file", file);
  if (currentSessionId) fd.append("sid", currentSessionId);
  const res = await fetch("/api/upload", { method: "POST", body: fd });
  let data = {};
  try { data = await res.json(); } catch { /* non-JSON error body */ }
  if (!res.ok || !data.ok) {
    throw new Error((data && data.error) ? data.error : ("upload failed (HTTP " + res.status + ")"));
  }
  const rec = (data && data.upload) || {};
  // first-ever upload before any chat: server mints the active session
  if (!currentSessionId && rec.sid) {
    currentSessionId = rec.sid;
    updateExportPill();
    loadSessions();
  }
  return rec;
}

async function uploadFiles(fileList) {
  if (!attachTray || attachBusy) return;
  const files = Array.from(fileList || []).filter((f) => f && f.name);
  if (!files.length) return;
  const bad = files.find((f) => !ATTACH_ALLOWED_EXT.has(attachExt(f.name)));
  if (bad) {
    trayNote("Unsupported file: " + bad.name + " \u2014 allowed: PNG/JPG/WEBP/TXT/JSON/PDF/PCAP", true);
    return;
  }
  attachBusy = true;
  if (attachBtn) attachBtn.disabled = true;
  attachTray.hidden = false;
  for (const f of files) {
    const chip = attachChipEl({ original_name: f.name, ext: attachExt(f.name) });
    chip.classList.add("att-uploading");
    attachTray.appendChild(chip);
    try {
      const rec = await uploadOneFile(f);
      chip.remove();
      attachTray.appendChild(attachChipEl(rec));
    } catch (err) {
      chip.classList.remove("att-uploading");
      chip.classList.add("att-err");
      const sub = chip.querySelector(".att-sub");
      if (sub) sub.textContent = "\u2716 " + ((err && err.message) || "upload failed");
    }
  }
  attachBusy = false;
  if (attachBtn) attachBtn.disabled = false;
  if (!attachTray.childElementCount) attachTray.hidden = true;
}

if (attachBtn) {
  attachBtn.addEventListener("click", () => {
    if (!attachBusy && attachInput) attachInput.click();
  });
}
if (attachInput) {
  attachInput.addEventListener("change", () => {
    uploadFiles(attachInput.files);
    attachInput.value = ""; // allow picking the same file again later
  });
}

// drag & drop anywhere over the composer (only when actual files are
// dragged, so normal text drags inside the textarea keep working)
if (composerIbar) {
  let dragDepth = 0;
  const dragHasFiles = (ev) => {
    const types = (ev.dataTransfer && ev.dataTransfer.types) || [];
    return Array.prototype.indexOf.call(types, "Files") !== -1;
  };
  composerIbar.addEventListener("dragenter", (ev) => {
    if (!dragHasFiles(ev)) return;
    ev.preventDefault();
    dragDepth += 1;
    composerIbar.classList.add("drag-files");
  });
  composerIbar.addEventListener("dragover", (ev) => {
    if (!dragHasFiles(ev)) return;
    ev.preventDefault();
    if (ev.dataTransfer) ev.dataTransfer.dropEffect = "copy";
  });
  composerIbar.addEventListener("dragleave", (ev) => {
    if (!dragHasFiles(ev)) return;
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) composerIbar.classList.remove("drag-files");
  });
  composerIbar.addEventListener("drop", (ev) => {
    if (!dragHasFiles(ev)) return;
    ev.preventDefault();
    dragDepth = 0;
    composerIbar.classList.remove("drag-files");
    uploadFiles(ev.dataTransfer.files);
  });
}

/* ---------------- tools ---------------- */
let allTools = [];
async function loadTools() {
  const grid = $("#tool-grid");
  grid.innerHTML = '<p style="color:var(--muted)">loading…</p>';
  allTools = await fetchJSON("/api/tools");
  $("#tools-count").textContent = allTools.length + " tools registered";
  renderTools("");
  loadMcpStrip();
}
async function loadMcpStrip() {
  const strip = $("#mcp-strip");
  if (!strip) return;
  let data = null;
  try { data = await fetchJSON("/api/mcp"); } catch (e) { strip.style.display = "none"; return; }
  const servers = data.servers || {};
  const names = Object.keys(servers);
  const mcpTools = data.mcp_tools || [];
  if (!names.length && !mcpTools.length) { strip.style.display = "none"; return; }
  strip.style.display = "flex";
  strip.innerHTML = "";
  const chip = (txt, bg, fg, title) => {
    const s = document.createElement("span");
    s.style.cssText = "padding:2px 8px;border-radius:10px;color:" + fg + ";background:" + bg + ";border:1px solid " + fg + ";white-space:nowrap;";
    if (title) s.title = title;
    s.textContent = txt;
    return s;
  };
  strip.appendChild(chip("MCP", "#0f1420", "#7fd0ff", "Model Context Protocol servers"));
  names.forEach((n) => {
    const st = servers[n] || {};
    const ok = st.status === "ok";
    strip.appendChild(chip(ok ? "● " + n : "✕ " + n,
      ok ? "#08190f" : "#1f0d10", ok ? "#37e07a" : "#ff5a6a",
      (ok ? "connected" : "failed") + " · " + ((st.tools || []).join(", ") || "no tools") + (st.error ? " · " + st.error : "")));
  });
  if (mcpTools.length)
    strip.appendChild(chip(mcpTools.length + " mcp tool(s)", "#0f1118", "#8b95a8", mcpTools.join(", ")));
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

/* Uncensored model quick-picks: one click -> model select + auto off */
function renderQuickPicks(catalog) {
  const wrap = $("#model-quickpicks");
  if (!wrap) return;
  wrap.innerHTML = "";
  (catalog || []).filter((m) => m.uncensored).forEach((m) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "qp-chip";
    b.dataset.model = m.id;
    b.title = m.desc || m.label;
    b.textContent = "☠ " + m.label;
    b.addEventListener("click", () => {
      $("#set-auto").checked = false;
      const sel = $("#set-model");
      if (!sel.querySelector(`option[value="${CSS.escape(m.id)}"]`)) {
        const opt = document.createElement("option");
        opt.value = m.id;
        opt.textContent = m.label;
        sel.appendChild(opt);
      }
      sel.value = m.id;
      updateQuickPickActive();
    });
    wrap.appendChild(b);
  });
}

function updateQuickPickActive() {
  const wrap = $("#model-quickpicks");
  if (!wrap) return;
  const cur = $("#set-model").value;
  wrap.querySelectorAll(".qp-chip").forEach((b) => {
    b.classList.toggle("active", b.dataset.model === cur);
  });
}

async function loadSettings() {
  const s = await fetchJSON("/api/settings");
  // The key itself is never sent back - only whether it exists in .env.
  $("#set-key").value = "";
  $("#set-key").placeholder = s.has_key ? "✓ API key is saved in .env (leave blank to keep it)" : "sk-…  (no key set — will be saved to .env)";
  $("#set-url").value = s.base_url || "";
  fillModelSelect(s.catalog);
  renderQuickPicks(s.catalog);
  $("#set-model").value = s.auto ? "auto" : (s.model || "auto");
  updateQuickPickActive();
  $("#set-auto").checked = !!s.auto;
  $("#set-mock").checked = !!s.mock;
  $("#set-redteam").checked = !!s.red_team_mode;
  $("#set-iter").value = s.max_iterations || 12;
}

// the Auto-Model Selector checkbox drives the model select
$("#set-auto").addEventListener("change", () => {
  $("#set-model").value = $("#set-auto").checked ? "auto" : $("#set-model").value;
  updateQuickPickActive();
});
$("#set-model").addEventListener("change", updateQuickPickActive);
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

/* ---------------- Mouse & Keyboard Access (live input console) ---------------- */
async function deskCall(url, payload) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}),
  });
  let data = null;
  try { data = await res.json(); } catch (e) {}
  return { res, data };
}

function deskMsg(txt, isErr) {
  const m = $("#desk-msg");
  if (m) { m.textContent = String(txt); m.classList.toggle("err", !!isErr); }
}

function deskXY() {
  return {
    x: parseInt(($("#desk-x") || {}).value, 10) || 0,
    y: parseInt(($("#desk-y") || {}).value, 10) || 0,
  };
}

function setDeskXY(x, y, move) {
  const ix = $("#desk-x"), iy = $("#desk-y");
  if (ix && x != null) ix.value = Math.round(x);
  if (iy && y != null) iy.value = Math.round(y);
  const cur = $("#desk-cursor"), pad = $("#desk-mousepad");
  if (cur && pad && x != null && y != null) {
    const sw = window.screen.width || 1920, sh = window.screen.height || 1080;
    cur.style.left = Math.min(100, Math.max(0, (x / sw) * 100)) + "%";
    cur.style.top = Math.min(100, Math.max(0, (y / sh) * 100)) + "%";
  }
  if (move) deskMouse("move", { x: x != null ? Math.round(x) : deskXY().x, y: y != null ? Math.round(y) : deskXY().y, absolute: true });
}

async function deskMouse(action, payload) {
  const { res, data } = await deskCall("/api/desktop/mouse", Object.assign({ action }, payload || {}));
  if (res.ok && data && data.ok) {
    const pos = data.result && data.result.pos;
    const r = data.result || {};
    if (pos && pos.x != null) { setDeskXY(pos.x, pos.y, false); }
    deskMsg("🖱 " + action + " ✓" + (r.msg ? " — " + r.msg : "") + (pos && pos.x != null ? " @ " + pos.x + "," + pos.y : ""));
  } else {
    deskMsg("❌ mouse " + action + ": " + ((data && (data.error || (data.result && data.result.error))) || res.status), true);
  }
}

async function captureScreen(silent) {
  const img = $("#desk-shot");
  if (!img) return;
  deskMsg(silent ? "Capturing…" : "Capturing screen…");
  const { res, data } = await deskCall("/api/desktop/screen", {});
  if (res.ok && data && data.ok && data.result && data.result.url) {
    img.src = data.result.url + "?t=" + Date.now();
    img.style.display = "block";
    deskMsg("✅ Screen " + new Date().toLocaleTimeString() + " — click to move cursor");
  } else {
    deskMsg("❌ Capture failed: " + ((data && (data.error || (data.result && data.result.error))) || res.status), true);
  }
}

async function loadDesktopPanel() {
  const st = $("#desk-status");
  if (st) st.textContent = "checking…";
  deskMsg("Loading desktop status…");
  try {
    const d = await fetchJSON("/api/desktop/status");
    if (d && d.ok) {
      const dsk = d.desktop || {};
      if (st) st.textContent = "✅ connected — " + (dsk.tools && dsk.tools.length ? dsk.tools.length + " tools ready" : "ready");
      const pos = dsk.pos;
      if (pos && pos.x != null) setDeskXY(pos.x, pos.y, false);
      captureScreen(true);
    } else {
      if (st) st.textContent = "❌ " + ((d && d.error) || "not available");
      deskMsg("❌ Desktop connection failed", true);
    }
  } catch (err) {
    if (st) st.textContent = "❌ desktop API unreachable";
    deskMsg("❌ Desktop API unreachable: " + err, true);
  }
}

function deskClick(button, clicks) {
  const { x, y } = deskXY();
  deskCall("/api/desktop/mouse", { action: "click", button, clicks, x, y }).then(({ res, data }) => {
    if (res.ok && data && data.ok) deskMsg("🖱 " + button + " click ✓");
    else deskMsg("❌ click: " + ((data && (data.error || (data.result && data.result.error))) || res.status), true);
  });
}

function wireDesk() {
  const snap = $("#desk-snap"); if (snap) snap.addEventListener("click", () => captureScreen(false));
  const mv = $("#desk-move"); if (mv) mv.addEventListener("click", () => { const { x, y } = deskXY(); setDeskXY(x, y, true); });
  if ($("#desk-shot")) $("#desk-shot").addEventListener("click", (ev) => {
    const img = ev.currentTarget, r = img.getBoundingClientRect();
    if (!r.width || !img.naturalWidth) return;
    const sx = Math.round(((ev.clientX - r.left) / r.width) * img.naturalWidth);
    const sy = Math.round(((ev.clientY - r.top) / r.height) * img.naturalHeight);
    setDeskXY(sx, sy, false);
    deskMouse("move", { x: sx, y: sy, absolute: true });
  });
  if ($("#desk-mousepad")) $("#desk-mousepad").addEventListener("click", (ev) => {
    const pad = ev.currentTarget, r = pad.getBoundingClientRect();
    if (!r.width || !r.height) return;
    const sx = Math.round(((ev.clientX - r.left) / r.width) * (window.screen.width || 1920));
    const sy = Math.round(((ev.clientY - r.top) / r.height) * (window.screen.height || 1080));
    setDeskXY(sx, sy, false);
    deskMouse("move", { x: sx, y: sy, absolute: true });
  });
  const lc = $("#desk-lclick"); if (lc) lc.addEventListener("click", () => deskClick("left", 1));
  const rc = $("#desk-rclick"); if (rc) rc.addEventListener("click", () => deskClick("right", 1));
  const dc = $("#desk-dclick"); if (dc) dc.addEventListener("click", () => deskClick("left", 2));
  const su = $("#desk-scrollup"); if (su) su.addEventListener("click", () => deskMouse("scroll", { amount: 3, direction: "up" }));
  const sd = $("#desk-scrolldown"); if (sd) sd.addEventListener("click", () => deskMouse("scroll", { amount: 3, direction: "down" }));
  const dr = $("#desk-drag"); if (dr) dr.addEventListener("click", () => {
    const g = (id) => parseInt(($(id) || {}).value, 10) || 0;
    deskMouse("drag", { x1: g("#desk-dx1"), y1: g("#desk-dy1"), x2: g("#desk-dx2"), y2: g("#desk-dy2"), button: "left" });
  });
  const pr = $("#desk-press"); if (pr) pr.addEventListener("click", async () => {
    const key = ($("#desk-key") || {}).value || "enter";
    const { res, data } = await deskCall("/api/desktop/key", { action: "press", key });
    if (res.ok && data && data.ok) deskMsg("⌨ key " + key + " pressed ✓");
    else deskMsg("❌ key: " + ((data && (data.error || (data.result && data.result.error))) || res.status), true);
  });
  const hk = $("#desk-hotkey-btn"); if (hk) hk.addEventListener("click", async () => {
    const keys = ($("#desk-hotkey") || {}).value || "ctrl+shift+s";
    const { res, data } = await deskCall("/api/desktop/key", { action: "hotkey", keys });
    if (res.ok && data && data.ok) deskMsg("⚡ hotkey " + keys + " ✓");
    else deskMsg("❌ hotkey: " + ((data && (data.error || (data.result && data.result.error))) || res.status), true);
  });
  const send = $("#desk-send"); if (send) send.addEventListener("click", async () => {
    const ta = $("#desk-type");
    if (!ta || !ta.value) { deskMsg("Type karne ke liye text likho…", true); return; }
    const { res, data } = await deskCall("/api/desktop/key", { action: "type", text: ta.value });
    if (res.ok && data && data.ok) { deskMsg("⌨ typed " + ta.value.length + " chars ✓"); ta.value = ""; }
    else deskMsg("❌ type: " + ((data && (data.error || (data.result && data.result.error))) || res.status), true);
  });
  const cg = $("#desk-clip-get"); if (cg) cg.addEventListener("click", async () => {
    const { res, data } = await deskCall("/api/desktop/clipboard", { action: "get_text" });
    const out = $("#desk-clip-out");
    const r = (data && data.result) || {};
    if (res.ok && data && data.ok) {
      const info = JSON.stringify(r, null, 2);
      if (out) out.textContent = info;
      deskMsg("📋 Clipboard: " + (r.length != null ? r.length + " chars" : "ok"));
    } else {
      deskMsg("❌ clipboard: " + ((data && data.error) || res.status), true);
      if (out) out.textContent = ((data && data.error) || "error");
    }
  });
  const cs = $("#desk-clip-save"); if (cs) cs.addEventListener("click", async () => {
    const ta = $("#desk-clip-set");
    if (!ta || !ta.value) { deskMsg("Clipboard par set karne ke liye text likho…", true); return; }
    const { res, data } = await deskCall("/api/desktop/clipboard", { action: "set_text", text: ta.value });
    if (res.ok && data && data.ok) { deskMsg("📋 Clipboard set ✓ (" + ta.value.length + " chars)"); ta.value = ""; }
    else deskMsg("❌ clipboard set: " + ((data && data.error) || res.status), true);
  });
  const cc = $("#desk-clip-clear"); if (cc) cc.addEventListener("click", async () => {
    const { res, data } = await deskCall("/api/desktop/clipboard", { action: "clear" });
    if (res.ok && data && data.ok) { const o = $("#desk-clip-out"); if (o) o.textContent = "—"; deskMsg("🗑 Clipboard cleared"); }
    else deskMsg("❌ clipboard clear: " + ((data && data.error) || res.status), true);
  });
}
wireDesk();

/* ---------------- persona presets ---------------- */
async function loadPersona() {
  try {
    const p = await fetchJSON("/api/personas");
    const sel = $("#persona-select");
    sel.innerHTML = "";
    for (const item of (p.personas || [])) {
      const id = typeof item === "string" ? item : item.id;
      const label = typeof item === "string" ? item : (item.name || item.id);
      const opt = document.createElement("option");
      opt.value = id;
      opt.textContent = label;
      sel.appendChild(opt);
    }
    sel.value = p.current || "hackerai";
    $("#persona-custom").value = p.custom_text || "";
    syncPersonaCustom();
  } catch (e) { /* settings page still usable */ }
}

function syncPersonaCustom() {
  const ta = $("#persona-custom");
  const on = $("#persona-select").value === "custom";
  ta.style.display = on ? "" : "none";
  ta.disabled = !on;
}

$("#persona-select").addEventListener("change", syncPersonaCustom);

$("#persona-save").addEventListener("click", async () => {
  const msg = $("#persona-msg");
  msg.textContent = "saving...";
  try {
    const res = await fetch("/api/personas", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        persona: $("#persona-select").value,
        custom_text: $("#persona-custom").value,
      }),
    });
    if (!res.ok) throw new Error("save failed");
    msg.textContent = "✅ persona saved";
    setTimeout(() => (msg.textContent = ""), 2500);
  } catch (e) {
    msg.textContent = "❌ failed to save persona";
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
      $("#pill-mode").textContent = "AUTO • SMART ROUTER";
    } else {
      $("#status-mode").textContent = s.mode === "live" ? "live · " + s.model : "mock mode";
      $("#status-model").textContent = s.mode === "live" ? s.base_url : "built-in test LLM";
      $("#pill-mode").textContent = (s.mode === "live" ? "LIVE • " : "MOCK • ") + s.model;
    }
    $("#pill-mode").className = "pill " + (s.mode === "auto" ? "smart" : (s.mode === "mock" ? "mock" : "live"));
    $("#badge-tools").textContent = s.tools;
    updateRedTeamPill(s.red_team_mode, s.persona);
  } catch { /* ignore */ }
}

/* ---------------- chat export (Markdown pentest report) ---------------- */
$("#pill-export").addEventListener("click", () => {
  if (!currentSessionId) {
    const pill = $("#pill-export");
    const old = pill.textContent;
    pill.textContent = "no active chat";
    setTimeout(() => (pill.textContent = old), 1500);
    return;
  }
  window.location.href = "/api/sessions/" + encodeURIComponent(currentSessionId) + "/export";
});

/* ---------------- red team master switch (one-click evil profile) ---------------- */
let redTeamOn = false;
let redTeamBusy = false;

function updateRedTeamPill(on, persona) {
  redTeamOn = !!on;
  const pill = $("#pill-redteam");
  if (!pill) return;
  if (redTeamOn) {
    pill.textContent = "RED TEAM • " + String(persona || "promix").toUpperCase();
    pill.className = "pill redteam-on";
  } else {
    pill.textContent = "RED TEAM OFF";
    pill.className = "pill redteam-off";
  }
}

$("#pill-redteam").addEventListener("click", async () => {
  if (redTeamBusy) return;
  redTeamBusy = true;
  try {
    const res = await fetch("/api/redteam", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: !redTeamOn }),
    });
    if (res.ok) {
      const data = await res.json();
      updateRedTeamPill(data.red_team_mode, data.persona);
      // keep Settings checkbox in sync
      const cb = $("#set-redteam");
      if (cb) cb.checked = !!data.red_team_mode;
    }
  } catch { /* ignore */ } finally {
    redTeamBusy = false;
  }
});

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
    box.innerHTML = `<div class="rpg-freeplay">✍️ type anything — every action is allowed.</div>`;
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
    rpgAddSystem("⚠️ load a campaign first.");
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
      rpgAddSystem("⏳ a campaign turn is already running" + (d.error ? " — " + d.error : ""));
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
      head.innerHTML = `<div class="rpg-avatar">🎭</div><div class="rpg-bubble"><b>${escapeHtml(d.title || "Adventure")}</b><br>${escapeHtml(d.player.name)} — ${escapeHtml(d.genre || "")}. Your story begins here.</div>`;
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
    rpgAddSystem("⚠️ campaign creation error: " + (err && err.message || "unknown"));
  }
}

async function rpgDeleteGame() {
  const id = $("#rpg-game-select").value;
  if (!id) return;
  if (!confirm("Delete this campaign? (permanent)")) return;
  await fetch("/api/rpg/games/" + encodeURIComponent(id), { method: "DELETE" }).catch(() => {});
  rpgCurrent = null;
  const story = $("#rpg-story");
  story.innerHTML = "";
  const w = document.createElement("div");
  w.className = "rpg-welcome";
  w.innerHTML = `<div class="welcome-icon">🐉</div><h3>Mythos Engine ready</h3><p>Create a new campaign or load a saved one.</p>`;
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
      list.innerHTML = `<p class="muted">lorebook is empty</p>`;
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
let boardTick = null;
function stopBoardTick() { if (boardTick) { clearInterval(boardTick); boardTick = null; } }
function fmtElapsed(s) {
  s = Math.max(0, Math.floor(s));
  const m = Math.floor(s / 60), sec = s % 60;
  return (m ? m + "m " : "") + sec + "s";
}
function renderBoard(board) {
  const w = document.getElementById("board-widget");
  if (!w || !board) return;
  const c = board.counts || {};
  const setN = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v || 0; };
  setN("b-todo", c.todo); setN("b-prog", c.in_progress); setN("b-done", c.completed);
  const ip = board.in_progress || [];
  const cur = document.getElementById("b-current");
  const live = (board.tasks || []).filter((t) => t.status === "in_progress").pop();
  if (cur && live) {
    const tool = live.tool ? " (" + live.tool + ")" : "";
    const label = "▶ " + (live.title || live.id) + tool;
    const start = typeof live.started_at === "number" ? live.started_at : null;
    const upd = () => { cur.textContent = start ? label + " · " + fmtElapsed(Date.now() / 1000 - start) : label; };
    upd();
    stopBoardTick();
    boardTick = setInterval(upd, 1000);
  } else if (cur) {
    stopBoardTick();
    cur.textContent = ip.length ? "▶ " + (ip[0].title || ip[0].id) : "idle";
  }
  const fill = document.getElementById("b-progress-fill");
  const pct = document.getElementById("b-progress-pct");
  const prog = (live && typeof live.progress === "number") ? Math.max(0, Math.min(100, live.progress)) : 0;
  if (fill) fill.style.width = prog + "%";
  if (pct) pct.textContent = live ? Math.round(prog) + "%" : "";
  const list = document.getElementById("board-list");
  if (list) {
    const tasks = (board.tasks || []).slice(-5).reverse();
    list.innerHTML = tasks.map((t) =>
      `<div class="b-item ${t.status || ""}"><span class="b-dot"></span><span class="b-title">${escapeHtml(t.title || t.id)}</span></div>`
    ).join("");
  }
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

/* ============================================================
   Command Center dashboard glue (idle / pre-chat state)

   - watches #chat-log so `body.chat-active` mirrors whether a
     conversation is open (CSS contract: body:not(.chat-active)
     shows .cc-dash and hides .chat-log, and vice versa)
   - live clock, /api/dash polling (graceful fallback for older
     backends), gauge/stat/card filling, session list + recent
     activity rows, terminal lines, traffic-bar ambience
   ============================================================ */
(() => {
  const get = (id) => document.getElementById(id);
  const q = (sel) => document.querySelector(sel);
  const chatLogEl = get("chat-log");
  const bodyEl = document.body;

  /* ---------------- chat <-> dashboard visibility toggle ---------------- */
  function updateChatActive() {
    const active = !!chatLogEl && chatLogEl.childElementCount > 0;
    bodyEl.classList.toggle("chat-active", active);
  }
  if (chatLogEl && window.MutationObserver) {
    const mo = new MutationObserver(updateChatActive);
    mo.observe(chatLogEl, { childList: true });
  }
  // UI-FIX watchdog: re-evaluate every 500 ms so a streamed agent
  // response can NEVER stay hidden behind the dashboard if an observer
  // event was missed or fired during a session load/new-chat race.
  if (chatLogEl) setInterval(updateChatActive, 500);

  /* ---------------- live clock (header pill + statusbar) ---------------- */
  const pad = (n) => String(n).padStart(2, "0");
  const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  function tickClock() {
    const now = new Date();
    const hms = pad(now.getHours()) + ":" + pad(now.getMinutes()) + ":" + pad(now.getSeconds());
    const c1 = get("cc-clock");
    if (c1) c1.textContent = hms;
    const c2 = get("cc-clock2");
    if (c2) c2.textContent = hms + " · " + DAYS[now.getDay()] + " " +
      now.getDate() + " " + MONTHS[now.getMonth()];
  }
  tickClock();
  setInterval(tickClock, 1000);

  /* ---------------- small formatters ---------------- */
  function setTxt(node, val) {
    if (!node) return;
    node.textContent = (val === null || val === undefined || val === "")
      ? "—" : String(val);
  }
  function fmtUptime(s) {
    s = Math.max(0, Math.floor(Number(s) || 0));
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    if (d > 0) return d + "d " + h + "h";
    if (h > 0) return h + "h " + m + "m";
    if (m > 0) return m + "m " + sec + "s";
    return sec + "s";
  }
  function timeAgo(ts) {
    let t = Number(ts) || 0;
    if (!t) return "—";
    if (t > 1e12) t = t / 1000;                 // ms epoch -> seconds
    const diff = Math.max(0, Date.now() / 1000 - t);
    if (diff < 60) return "just now";
    if (diff < 3600) return Math.floor(diff / 60) + "m ago";
    if (diff < 86400) return Math.floor(diff / 3600) + "h ago";
    return Math.floor(diff / 86400) + "d ago";
  }
  function truncate(s, n) {
    s = String(s || "");
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
  }
  function modelLabel(model) {
    if (model === "auto") return "smart-auto";
    if (model === "mock-1") return "mock-1";
    return String(model || "?");
  }

  /* ---------------- gauges ---------------- */
  function setGauge(valId, fillId, pct, titleText, valueText) {
    const val = get(valId);
    const fill = get(fillId);
    pct = Math.max(0, Math.min(100, Number(pct) || 0));
    if (fill) fill.style.width = pct + "%";
    if (val) {
      val.textContent = valueText || Math.round(pct) + "%";
      if (titleText) val.title = titleText;
    }
  }
  // circular OPERATIONAL ring (conic-gradient arc driven by --ring)
  function setOpRing(pct) {
    const ring = get("op-ring");
    const val = get("op-val");
    pct = Math.max(0, Math.min(100, Number(pct) || 0));
    const deg = Math.round((pct / 100) * 360);
    if (ring) ring.style.setProperty("--ring", deg + "deg");
    if (val) val.textContent = Math.round(pct) + "%";
  }

  /* CPU fallback: gentle jitter walk (2-24%) when the OS counter is absent */
  const cpuSim = { v: 8 + Math.random() * 16, on: false, timer: null };
  function cpuJitterTick() {
    cpuSim.v = Math.max(2, Math.min(24, cpuSim.v + (Math.random() * 14 - 7)));
    setGauge("val-cpu", "g-cpu", cpuSim.v, "live load estimate");
  }
  function cpuJitterStart() {
    if (cpuSim.on) return;
    cpuSim.on = true;
    cpuJitterTick();
    cpuSim.timer = setInterval(cpuJitterTick, 1600);
  }
  function cpuJitterStop() {
    cpuSim.on = false;
    if (cpuSim.timer) { clearInterval(cpuSim.timer); cpuSim.timer = null; }
  }

  /* traffic bars ambience */
  function jitterTraffic() {
    const bars = document.querySelectorAll(".traffic .t-bars i");
    bars.forEach((b) => b.style.setProperty("--h", (8 + Math.random() * 88) + "%"));
  }

  /* ---------------- active sessions list (max 7, click to open) ---------------- */
  function fillSessions(list) {
    const box = get("cc-session-list");
    if (!box) return;
    const rows = (list || []).slice(0, 7);
    box.innerHTML = "";
    if (!rows.length) {
      const empty = document.createElement("div");
      empty.className = "ss-empty";
      empty.textContent = "no saved sessions yet";
      box.appendChild(empty);
      return;
    }
    rows.forEach((s) => {
      const item = document.createElement("div");
      item.className = "ss-item clickable";
      item.dataset.sid = s.id || "";
      item.title = (s.preview || "open this session");
      const ico = document.createElement("span");
      ico.className = "ss-ico";
      ico.textContent = "◷";
      const txt = document.createElement("div");
      txt.className = "ss-txt";
      const b = document.createElement("b");
      b.textContent = s.title || "New chat";
      const small = document.createElement("small");
      small.textContent = timeAgo(s.updated) + (s.count ? " · " + s.count + " msgs" : "");
      txt.appendChild(b);
      txt.appendChild(small);
      const go = document.createElement("span");
      go.className = "ss-go";
      go.textContent = "→";
      item.appendChild(ico);
      item.appendChild(txt);
      item.appendChild(go);
      box.appendChild(item);
    });
  }
  const sessBox = get("cc-session-list");
  if (sessBox) {
    sessBox.addEventListener("click", (e) => {
      const row = e.target instanceof Element ? e.target.closest(".ss-item[data-sid]") : null;
      if (!row || busy) return;
      openSession(row.dataset.sid);
    });
  }

  /* ---------------- recent activity rows (non-clickable) ---------------- */
  function fillActivity(st) {
    const box = get("cc-activity");
    if (!box) return;
    const nMem = Number(st.memory_entries) || 0;
    const modeTxt = st.mode === "mock" ? "mock engine"
      : (st.mode === "auto" ? "smart-auto router" : "live model");
    // Phase 4 dashboard telemetry: live swarm registry + knowledge graph.
    const sa = st.subagents || {};
    const saAvail = sa.available !== false && (Number(sa.tracked) > 0 || Number(sa.active) > 0);
    const saSub = saAvail
      ? Number(sa.active) + " active · " + Number(sa.running) + " running · " + Number(sa.tracked) + " tracked"
      : "standby (delegation idle)";
    const kn = st.knowledge || {};
    const knF = kn.findings || {};
    const knG = kn.graph;
    const knBits = [];
    if (knF && typeof knF.records === "number") {
      knBits.push(knF.records + (knF.records === 1 ? " finding" : " findings"));
      if (typeof knF.targets === "number" && knF.targets > 0) {
        knBits.push(knF.targets + (knF.targets === 1 ? " target" : " targets"));
      }
    }
    if (knG && typeof knG.edges === "number") {
      const tot = Object.keys(knG.nodes || {}).reduce((a, k) => a + (Number(knG.nodes[k]) || 0), 0);
      knBits.push(tot + " nodes · " + knG.edges + " edges");
    }
    const knSub = knBits.length ? knBits.join(" · ") : "no target data yet";
    const rows = [
      { ico: "🧠", title: "memory vault", sub: nMem + (nMem === 1 ? " note" : " notes") + " stored" },
      { ico: "☠", title: "red team", sub: st.red_team_mode ? "armed · level " + (st.red_team_level || "promax") : "standby" },
      { ico: "🛠", title: "tools", sub: (Number(st.tools) || 0) + " registered" },
      { ico: "🤖", title: "router", sub: modeTxt + " · " + modelLabel(st.model) },
      { ico: "🕸", title: "swarm · sub-agents", sub: saSub },
      { ico: "🕸", title: "knowledge graph", sub: knSub },
    ];
    box.innerHTML = "";
    rows.forEach((r) => {
      const item = document.createElement("div");
      item.className = "ss-item";
      const ico = document.createElement("span");
      ico.className = "ss-ico";
      ico.textContent = r.ico;
      const txt = document.createElement("div");
      txt.className = "ss-txt";
      const b = document.createElement("b");
      b.textContent = r.title;
      const small = document.createElement("small");
      small.textContent = r.sub;
      txt.appendChild(b);
      txt.appendChild(small);
      item.appendChild(ico);
      item.appendChild(txt);
      box.appendChild(item);
    });
  }

  /* ---------------- fill everything from one /api/dash payload ---------------- */
  function applyDash(d) {
    const st = d.status || {};
    const sys = d.sys || {};
    const toolsN = (typeof st.tools === "number" ? st.tools : (Number(st.tools) || 0));
    const modeTxt = st.mode === "mock" ? "MOCK MODE"
      : (st.mode === "auto" ? "SMART ROUTER" : "LIVE MODEL");

    // stat strip + terminal
    setTxt(get("cc-stat-uptime"), fmtUptime(d.uptime_s));
    setTxt(get("cc-stat-sessions"), Number(d.total_sessions) || 0);
    setTxt(get("cc-stat-model"), modelLabel(st.model));
    setTxt(get("cc-stat-tools"), toolsN);
    setTxt(get("cc-term-model"), modelLabel(st.model));
    setTxt(get("cc-term-tools"), toolsN);
    setTxt(get("cc-term-state"), modeTxt);

    // red-team terminal line (armed/standby)
    document.querySelectorAll(".term-line").forEach((ln) => {
      if (/red team/i.test(ln.textContent)) {
        const bb = ln.querySelector("b");
        if (bb) bb.textContent = st.red_team_mode ? ":: armed · " + (st.red_team_level || "promax") : ":: standby";
      }
    });

    // operational ring — 100% when the core is live (drives the conic arc)
    setOpRing(st.key_error || !st.mode ? 0 : (st.red_team_mode ? 100 : 100));

    // gauges — real metrics; cpu falls back to a jitter walk when absent
    if (sys.ram && typeof sys.ram.pct === "number") {
      setGauge("val-ram", "g-ram", sys.ram.pct, sys.ram.used_gb + " / " + sys.ram.total_gb + " GB used");
    }
    if (sys.disk && typeof sys.disk.pct === "number") {
      setGauge("val-disk", "g-disk", sys.disk.pct, sys.disk.used_gb + " / " + sys.disk.total_gb + " GB used");
    }
    if (typeof sys.cpu_pct === "number") {
      cpuJitterStop();
      setGauge("val-cpu", "g-cpu", sys.cpu_pct, "live load");
    } else {
      cpuJitterStart();
    }

    // six system cards
    const card = (idV, idS, val, sub) => { setTxt(get(idV), val); setTxt(get(idS), sub); };
    card("cc-os", "cc-os-sub", sys.os, sys.os_ver || "system info unavailable");
    card("cc-ip", "cc-ip-sub", sys.ip || sys.adapter_ip,
         sys.adapter_ip ? "adapter " + sys.adapter_ip
         : (sys.gateway ? "gw " + sys.gateway : (sys.ip6 || "resolving…")));
    card("cc-loc", "cc-loc-sub", sys.host || "this machine",
         (sys.machine || "machine") + (sys.cores ? " · " + sys.cores + " cores" : ""));
    card("cc-user", "cc-user-sub", sys.user, "local account");
    card("cc-shell", "cc-shell-sub", sys.shell || "cmd",
         sys.python ? "python " + sys.python : "webui build");
    card("cc-ver", "cc-ver-sub", d.version ? "v" + d.version : "—", "webui build");

    // bottom status bar
    // live swarm + knowledge-graph counters (Phase 4 dashboard telemetry)
    const _sa = st.subagents || {};
    const _kn = (st.knowledge || {}).findings || {};
    setTxt(get("cc-sb-agents"), Number(_sa.tracked) || 0);
    setTxt(get("cc-sb-kg"), Number(_kn.records) || 0);
    setTxt(get("cc-sb-mode"), modeTxt.toLowerCase() === "smart router" ? "auto" : (st.mode || "auto"));
    setTxt(get("cc-sb-extra"), st.red_team_mode
      ? "red team · " + (st.red_team_level || "promax")
      : "persona · " + truncate(st.persona, 22));
    setTxt(get("cc-sb-session"), (currentSessionId || "").slice(0, 6) || "—");
    setTxt(get("cc-sb-tools"), toolsN);

    fillSessions(d.recent);
    fillActivity(st);
  }

  /* ---------------- polling ---------------- */
  async function ccFill() {
    try {
      const d = await fetchJSON("/api/dash");
      applyDash(d);
    } catch {
      // older backend without /api/dash: degrade gracefully
      try {
        const [st, sess] = await Promise.all([
          fetchJSON("/api/status").catch(() => null),
          fetchJSON("/api/sessions").catch(() => null),
        ]);
        const list = sess && Array.isArray(sess.sessions) ? sess.sessions : [];
        applyDash({
          status: st,
          total_sessions: list.length,
          recent: list,
          version: null,
          uptime_s: null,
          sys: null,
        });
      } catch { /* keep placeholders */ }
    }
    jitterTraffic();
  }

  /* ---------------- LAUNCH AGENT ---------------- */
  const launchBtn = get("launch-agent");
  if (launchBtn) {
    launchBtn.addEventListener("click", () => {
      if (busy) return;
      newChat();
      updateChatActive();
      const stage = q(".cc-stage");
      const dash = get("cc-dash");
      if (stage) stage.scrollTop = 0;
      if (dash) dash.scrollTop = 0;
      if (inputBox) inputBox.focus();
    });
  }

  /* boot the dashboard: initial state + 10 s refresh */
  updateChatActive();
  jitterTraffic();
  ccFill();
  setInterval(ccFill, 10000);
})();


/* ---------------- Command Center quick actions + CTA ---------------- */
(() => {
  const $id = (id) => document.getElementById(id);
  const Q_MSG = {
    listfiles: "List the files and directories in the current working directory.",
    portscan: "Run a fast port scan on the target host and report open services.",
    sysinfo: "Show detailed system information (OS, user, shell, python, uptime).",
    subdomains: "Discover subdomains for the target domain.",
  };
  const cta = $id("cc-cta");
  if (cta) cta.addEventListener("click", () => {
    const stage = document.querySelector(".cc-stage");
    if (stage) stage.scrollTop = 0;
    if (inputBox) inputBox.focus();
  });
  document.querySelectorAll(".qc[data-action]").forEach((b) => {
    b.addEventListener("click", () => {
      const act = b.dataset.action;
      if (act === "tools") { goToSettingsPane("tools"); return; }
      if (inputBox) {
        inputBox.value = Q_MSG[act] || "";
        inputBox.focus();
        autosize();
      }
    });
  });
})();
/* ================= PHASE 2 - live execution blocks =================
   Real-time tool execution renderer: connects the chat viewport to the
   /api/exec/stream SSE fan-out from PHASE 1 and renders a dark-themed
   execution block for every command being run, e.g.

     [TERMINAL OUTPUT] nmap -sV 10.10.10.1      ▶ running
     $ ...live stdout line 1...
     [GIT] git status                            ✓ done (0)

   Blocks keyed by run_id: start frame creates the block, stdout/stderr
   frames stream into the <pre> bodies live (with auto-scroll), the
   terminal frame finalizes it with a status badge. Historical replay
   events older than 10 min are skipped so a fresh page load never
   floods the viewport with old runs. Fully additive to the chat log.
   ------------------------------------------------------------------ */
(() => {
  const LABELS = { terminal: "TERMINAL OUTPUT", git: "GIT",
                   subagent: "SUB-AGENT", tool: "TOOL", command: "COMMAND" };
  const ICONS  = { terminal: "🖥️", git: "🌿", subagent: "🤖", tool: "🧰", command: "⚡" };
  const blocks = new Map(); // run_id -> {card, out, err, status, done}
  const RETRY_MS = 2500;
  const STALE_AFTER_S = 600; // skip replay events older than 10 min

  function labelFor(stepType) {
    return LABELS[stepType] || (stepType || "tool").toUpperCase();
  }
  function iconFor(stepType) {
    return ICONS[stepType] || "▸";
  }
  function clean(text) {
    return String(text == null ? "" : text).replace(/\r\n/g, "\n");
  }

  function ensureBlock(evt) {
    const rid = evt.run_id;
    if (!rid || blocks.has(rid)) return blocks.get(rid);
    const card = document.createElement("div");
    card.className = "exec-block running";
    const st = evt.step_type || "tool";
    const head = document.createElement("div");
    head.className = "exec-head";
    const ico = document.createElement("span");
    ico.className = "exec-ico"; ico.textContent = iconFor(st);
    const tag = document.createElement("span");
    tag.className = "exec-tag"; tag.textContent = "[" + labelFor(st) + "]";
    const cmd = document.createElement("code");
    cmd.className = "exec-cmd"; cmd.textContent = clean(evt.command || "");
    const status = document.createElement("span");
    status.className = "exec-status running";
    status.textContent = evt.status === "running" ? "▶ running" : "● queued";
    head.append(ico, tag, cmd, status);
    const body = document.createElement("div");
    body.className = "exec-body";
    const out = document.createElement("pre");
    out.className = "exec-out";
    const err = document.createElement("pre");
    err.className = "exec-err";
    body.append(out, err);
    card.append(head, body);
    const typing = document.getElementById("typing");
    if (typing) chatLog.insertBefore(card, typing);
    else chatLog.appendChild(card);
    const b = { card, out, err, status, done: false };
    blocks.set(rid, b);
    scrollToBottom();
    return b;
  }

  function finalizeBlock(evt) {
    const rid = evt.run_id;
    const b = blocks.get(rid);
    if (!b || b.done) return;
    b.done = true;
    const st = evt.status; // completed | failed | cancelled
    b.card.classList.remove("running");
    b.card.classList.add(st || "done");
    b.status.className = "exec-status " + (st || "done");
    const label = st === "completed" ? "✓ done"
                : st === "failed"   ? "✗ failed"
                : st === "cancelled" ? "✕ cancelled" : "done";
    b.status.textContent = label + (evt.exit_code != null ? " (" + evt.exit_code + ")" : "");
    if (evt.duration_ms != null) {
      const ms = evt.duration_ms;
      const dur = document.createElement("span");
      dur.className = "exec-dur";
      dur.textContent = (ms >= 1000 ? (ms / 1000).toFixed(1) + "s" : ms + "ms");
      b.card.querySelector(".exec-head").appendChild(dur);
    }
    if (evt.stdout) b.out.textContent = clean(evt.stdout);
    if (evt.stderr) b.err.textContent = clean(evt.stderr);
    scrollToBottom();
  }

  function handleExec(evt) {
    if (!evt || typeof evt !== "object") return;
    // skip stale replay history so fresh loads never flood the viewport
    if (evt.ts && (Date.now() / 1000 - evt.ts) > STALE_AFTER_S) return;
    const b = ensureBlock(evt);
    if (!b) return;
    if (evt.stream === "stdout" && evt.stdout) {
      b.out.textContent = (b.out.textContent ? b.out.textContent + "\n" : "") + clean(evt.stdout);
      scrollToBottom();
    } else if (evt.stream === "stderr" && evt.stderr) {
      b.err.textContent = (b.err.textContent ? b.err.textContent + "\n" : "") + clean(evt.stderr);
      scrollToBottom();
    } else if (evt.stream === null && evt.status && evt.status !== "running") {
      finalizeBlock(evt); // terminal frame: completed / failed / cancelled
    }
  }

  let es = null;
  function connect() {
    if (es) { try { es.close(); } catch {} }
    es = new EventSource("/api/exec/stream");
    es.addEventListener("exec", (e) => {
      try { handleExec(JSON.parse(e.data)); } catch { /* skip malformed frame */ }
    });
    es.onopen = () => { /* connection established; blocks flow in */ };
    // EventSource reconnects natively on error - do NOT also reconnect
    // manually or duplicate connections would pile up.
    es.onerror = () => { /* handled by EventSource auto-reconnect */ };
  }

  // boot the stream once the chat log exists
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", connect);
  } else {
    connect();
  }
})();