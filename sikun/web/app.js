"use strict";

/* --- pywebview bridge readiness --------------------------------------- */

let _pywebviewReady = !!(window.pywebview && window.pywebview.api);
const _readyWaiters = [];
window.addEventListener("pywebviewready", () => {
  _pywebviewReady = true;
  _readyWaiters.splice(0).forEach((fn) => fn());
});

function whenReady() {
  return new Promise((resolve) => {
    if (_pywebviewReady) resolve();
    else _readyWaiters.push(resolve);
  });
}

async function api(name, ...args) {
  await whenReady();
  return window.pywebview.api[name](...args);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

/* --- Python -> JS push API (called by sikun/webapp.py via evaluate_js) - */

window.sikun = {
  pushEvent(ev) {
    appendEvent(ev);
  },
  pushBoard(board) {
    renderBoard(board);
  },
  setMeta(meta) {
    setMeta(meta);
  },
  setActivity(payload) {
    const busy = !!(payload && payload.activity);
    document.getElementById("tb-activity").textContent = busy ? "▸ " + payload.activity : "";
    document.getElementById("titlebar").classList.toggle("busy", busy);
  },
  setBusy(payload) {
    document.getElementById("titlebar").classList.toggle("busy", !!(payload && payload.busy));
  },
  showChoice(payload) {
    showChoice(payload);
  },
  hideChoice() {
    hideChoice();
  },
};

/* --- Dashboard: terminal transcript ------------------------------------ */

function appendEvent(ev) {
  const term = document.getElementById("terminal");
  const wasAtBottom = term.scrollHeight - term.scrollTop - term.clientHeight < 40;
  const line = document.createElement("div");
  line.className = "line";
  line.innerHTML = `<span class="ts">${escapeHtml(ev.ts || "")}</span><span class="body">${ev.html || ""}</span>`;
  term.appendChild(line);
  if (wasAtBottom) term.scrollTop = term.scrollHeight;
}

function setMeta(meta) {
  document.getElementById("tb-target").textContent = meta.target || "-";
  document.getElementById("side-target").textContent = meta.target || "-";
  document.getElementById("tb-mode").textContent = meta.mode || "-";
  document.getElementById("side-mode").textContent = meta.mode || "-";
}

/* --- Dashboard: SITREP sidebar ----------------------------------------- */

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

function renderBoard(b) {
  document.getElementById("tb-model").textContent = b.model || "-";
  const cost = "$" + (b.cost || 0).toFixed(4);
  document.getElementById("tb-cost").textContent = cost;
  document.getElementById("side-cost").textContent = cost;
  document.getElementById("side-phase").textContent = b.phase || "-";
  const cwdEl = document.getElementById("side-cwd");
  cwdEl.textContent = b.cwd || "~";
  cwdEl.title = b.cwd || "";
  document.getElementById("side-turns").textContent = b.turns || 0;
  document.getElementById("side-tools").textContent = b.tools || 0;
  const lastCmdEl = document.getElementById("side-lastcmd");
  lastCmdEl.textContent = b.last_cmd || "(idle)";
  lastCmdEl.title = b.last_cmd || "";

  renderSparkline(b.cost_history || []);
  renderPorts(b.ports || []);
  renderFindings(b.findings || {});
}

function renderSparkline(vals) {
  const svg = document.getElementById("cost-spark");
  if (!vals.length) {
    svg.innerHTML = "";
    return;
  }
  const w = 280, h = 32;
  const lo = Math.min(...vals), hi = Math.max(...vals);
  const span = hi - lo || 1;
  const step = w / Math.max(vals.length - 1, 1);
  const pts = vals
    .map((v, i) => `${(i * step).toFixed(1)},${(h - ((v - lo) / span) * h).toFixed(1)}`)
    .join(" ");
  svg.innerHTML = `<polyline points="${pts}" fill="none" stroke="#39ff88" stroke-width="1.5" />`;
}

function renderPorts(ports) {
  document.getElementById("port-count").textContent = `(${ports.length})`;
  const el = document.getElementById("port-list");
  if (!ports.length) {
    el.innerHTML = '<div class="empty">未検出</div>';
    return;
  }
  el.innerHTML = ports
    .map((p) => (
      `<div class="port-chip"><span class="p">${escapeHtml(String(p.port))}/${escapeHtml(p.protocol || "")}</span>` +
      `<span>${escapeHtml(p.service || "?")}</span></div>`
    ))
    .join("");
}

function renderFindings(findings) {
  const total = Object.values(findings).reduce((a, b) => a + b, 0);
  document.getElementById("finding-count").textContent = `(${total})`;
  const el = document.getElementById("finding-list");
  if (!total) {
    el.innerHTML = '<div class="empty">未検出</div>';
    return;
  }
  el.innerHTML = SEV_ORDER.filter((s) => findings[s])
    .map((s) => `<div class="finding-chip sev-${s}"><span>${s}</span><span>${findings[s]}</span></div>`)
    .join("");
}

/* --- Dashboard: input / interrupt / choice ------------------------------ */

document.getElementById("cmdline").addEventListener("keydown", (e) => {
  if (e.key !== "Enter") return;
  const el = e.target;
  const text = el.value.trim();
  if (!text) return;
  el.value = "";
  api("submit_instruction", text);
});

document.getElementById("stop-btn").addEventListener("click", () => {
  api("interrupt");
});

function showChoice(payload) {
  const bar = document.getElementById("choice-bar");
  bar.innerHTML = "";
  (payload.options || []).forEach((opt) => {
    const btn = document.createElement("button");
    btn.textContent = opt.label;
    if (opt.value === "reject" || opt.value === "stop") btn.classList.add("danger");
    btn.addEventListener("click", () => api("choose", opt.value));
    bar.appendChild(btn);
  });
  bar.style.display = "flex";
}

function hideChoice() {
  const bar = document.getElementById("choice-bar");
  bar.style.display = "none";
  bar.innerHTML = "";
  document.getElementById("cmdline").focus();
}

/* --- Nav switching ------------------------------------------------------ */

document.querySelectorAll(".nav-item").forEach((item) => {
  item.addEventListener("click", () => switchView(item.dataset.view));
});

function switchView(name) {
  document.querySelectorAll(".nav-item").forEach((i) => i.classList.toggle("active", i.dataset.view === name));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === "view-" + name));
  if (name === "reports") loadReports();
  if (name === "settings") loadProfiles();
}

/* --- Reports view --------------------------------------------------------- */

const REPORT_KIND_LABEL = { remediation: "修復", detection: "検知" };

async function loadReports() {
  const items = await api("list_reports");
  const container = document.getElementById("report-items");
  if (!items || !items.length) {
    container.innerHTML = '<div class="empty">remediations/ と detections/ にファイルがありません</div>';
    return;
  }
  container.innerHTML = "";
  for (const it of items) {
    const div = document.createElement("div");
    div.className = "report-item";
    div.innerHTML =
      `<span class="badge ${it.kind}">${REPORT_KIND_LABEL[it.kind] || it.kind}</span>` +
      `<div class="name">${escapeHtml(it.name)}</div>` +
      `<div class="meta">${escapeHtml(it.mtime)} ・ ${(it.size / 1024).toFixed(1)}KB</div>`;
    div.addEventListener("click", () => selectReport(it.kind, it.name, div));
    container.appendChild(div);
  }
}

async function selectReport(kind, name, el) {
  document.querySelectorAll(".report-item.active").forEach((e) => e.classList.remove("active"));
  el.classList.add("active");
  const res = await api("read_report", kind, name);
  document.getElementById("report-view-title").textContent = name;
  document.getElementById("report-view").textContent = res.ok ? res.content : "エラー: " + res.error;
}

/* --- Settings view --------------------------------------------------------- */

let currentProfile = null;

async function loadProfiles() {
  const names = await api("list_profiles");
  const container = document.getElementById("profile-items");
  if (!names || !names.length) {
    container.innerHTML = '<div class="empty">profiles/*.toml が見つかりません</div>';
    return;
  }
  container.innerHTML = "";
  for (const name of names) {
    const div = document.createElement("div");
    div.className = "profile-item";
    div.textContent = name;
    div.addEventListener("click", () => selectProfile(name, div));
    container.appendChild(div);
  }
}

async function selectProfile(name, el) {
  document.querySelectorAll(".profile-item.active").forEach((e) => e.classList.remove("active"));
  el.classList.add("active");
  currentProfile = name;
  const res = await api("read_profile", name);
  const ta = document.getElementById("profile-textarea");
  ta.disabled = false;
  ta.value = res.ok ? res.content : "";
  document.getElementById("settings-title").textContent = name + ".toml";
  document.getElementById("save-profile-btn").style.display = "inline-block";
  setProfileStatus("", "");
}

function setProfileStatus(text, cls) {
  const el = document.getElementById("profile-status");
  el.textContent = text;
  el.className = cls || "";
}

document.getElementById("save-profile-btn").addEventListener("click", async () => {
  if (!currentProfile) return;
  const content = document.getElementById("profile-textarea").value;
  const res = await api("save_profile", currentProfile, content);
  if (res.ok) setProfileStatus("保存しました", "ok");
  else setProfileStatus("エラー: " + res.error, "error");
});
