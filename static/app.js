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
  if (name === "chat") updateExportPill();
  if (name === "settings") { loadSettings(); loadPersona(); }
  if (name === "system") loadSystem();
}

document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => switchView(btn.dataset.view));
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
      if (act === "tools") { switchView("tools"); return; }
      if (inputBox) {
        inputBox.value = Q_MSG[act] || "";
        inputBox.focus();
        autosize();
      }
    });
  });
})();
