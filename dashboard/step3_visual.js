import { dashboardApi } from "./api/dashboardApi.js";

const POLL_MS = 100;
const ANIM_TICK_MS = 16;
const MAX_LOG_ITEMS = 36;

const canvas = document.getElementById("flowCanvas");
const ctx = canvas.getContext("2d");
const modelLabel = document.getElementById("modelLabel");
const runLabel = document.getElementById("runLabel");
const updatedLabel = document.getElementById("updatedLabel");
const counterGrid = document.getElementById("counterGrid");
const parentLog = document.getElementById("parentLog");
const shapLog = document.getElementById("shapLog");

const params = new URLSearchParams(window.location.search);
const state = {
  modelId: params.get("model_id") || "",
  modelVersion: params.get("model_version") || "",
  replayRunId: params.get("replay_run_id") || "",
  sinceTs: "",
  sinceEventId: "",
  polling: false,
  particles: [],
  parentItems: [],
  shapItems: [],
  incidentItems: [],
  nodes: {
    replay: { x: 0.08, y: 0.5, label: "Factory/Enterprise Network", kind: "factory" },
    parent: { x: 0.86, y: 0.5, label: "Parent Server", kind: "server_stack" },
    children: [],
  },
};

function nowIso() {
  return new Date().toISOString();
}

function fmtTs(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString();
}

function pushLog(list, row) {
  list.unshift(row);
  if (list.length > MAX_LOG_ITEMS) list.length = MAX_LOG_ITEMS;
}

function addParticle(from, to, kind, payload = {}) {
  state.particles.push({
    fromX: from.x,
    fromY: from.y,
    toX: to.x,
    toY: to.y,
    t: 0,
    speed: kind === "packet_transit" ? 0.032 : 0.042,
    kind,
    payload,
  });
}

function colorForKind(kind) {
  if (kind === "packet_transit") return "#58d0ff";
  if (kind === "child_alert") return "#ff7a46";
  if (kind === "escalation") return "#ffca54";
  if (kind === "review") return "#6ce89c";
  return "#8ea9ba";
}

function drawFactoryWireframe(x, y, radius) {
  const w = radius * 1.4;
  const h = radius * 1.0;
  const left = x - w / 2;
  const right = x + w / 2;
  const top = y - h / 2;
  const base = y + h / 2;

  ctx.beginPath();
  ctx.moveTo(left, base);
  ctx.lineTo(right, base);
  ctx.moveTo(left + w * 0.08, base);
  ctx.lineTo(left + w * 0.08, y);
  ctx.lineTo(x - w * 0.15, y);
  ctx.lineTo(x - w * 0.15, top + h * 0.18);
  ctx.lineTo(x - w * 0.02, y);
  ctx.lineTo(x + w * 0.1, top + h * 0.18);
  ctx.lineTo(x + w * 0.22, y);
  ctx.lineTo(right - w * 0.08, y);
  ctx.lineTo(right - w * 0.08, base);
  ctx.moveTo(left + w * 0.2, base);
  ctx.lineTo(left + w * 0.2, y + h * 0.12);
  ctx.moveTo(left + w * 0.34, base);
  ctx.lineTo(left + w * 0.34, y + h * 0.12);
  ctx.moveTo(left + w * 0.48, base);
  ctx.lineTo(left + w * 0.48, y + h * 0.12);
  ctx.stroke();
}

function drawRouterWireframe(x, y, radius) {
  const w = radius * 1.35;
  const h = radius * 0.72;
  const left = x - w / 2;
  const top = y - h / 2;

  ctx.beginPath();
  ctx.rect(left, top, w, h);
  ctx.moveTo(x, top - h * 0.45);
  ctx.lineTo(x, top);
  ctx.moveTo(x - w * 0.22, top - h * 0.3);
  ctx.lineTo(x, top - h * 0.45);
  ctx.lineTo(x + w * 0.22, top - h * 0.3);
  ctx.moveTo(left + w * 0.2, y + h * 0.1);
  ctx.lineTo(left + w * 0.8, y + h * 0.1);
  ctx.moveTo(left + w * 0.2, y - h * 0.12);
  ctx.lineTo(left + w * 0.8, y - h * 0.12);
  ctx.stroke();
}

function drawServerStackWireframe(x, y, radius) {
  const w = radius * 1.3;
  const h = radius * 1.1;
  const left = x - w / 2;
  const top = y - h / 2;
  const rowH = h / 3;

  ctx.beginPath();
  for (let i = 0; i < 3; i += 1) {
    const rowTop = top + i * rowH;
    ctx.rect(left, rowTop, w, rowH - 2);
    ctx.moveTo(left + w * 0.18, rowTop + rowH * 0.45);
    ctx.lineTo(left + w * 0.82, rowTop + rowH * 0.45);
    ctx.moveTo(left + w * 0.08, rowTop + rowH * 0.45);
    ctx.arc(left + w * 0.08, rowTop + rowH * 0.45, 1.8, 0, Math.PI * 2);
  }
  ctx.stroke();
}

function drawNode(node, color, radius = 26) {
  const x = node.x * canvas.width;
  const y = node.y * canvas.height;
  ctx.beginPath();
  ctx.fillStyle = color;
  ctx.arc(x, y, radius, 0, Math.PI * 2);
  ctx.fill();
  ctx.strokeStyle = "#d8e6ef";
  ctx.lineWidth = 1.6;
  if (node.kind === "factory") drawFactoryWireframe(x, y, radius);
  if (node.kind === "router") drawRouterWireframe(x, y, radius);
  if (node.kind === "server_stack") drawServerStackWireframe(x, y, radius);
  ctx.fillStyle = "#d8e6ef";
  ctx.font = "700 14px Space Grotesk, sans-serif";
  ctx.textAlign = "center";
  ctx.fillText(node.label, x, y + radius + 18);
}

function drawTopology() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "rgba(11,30,40,0.26)";
  for (let i = 0; i < canvas.width; i += 52) {
    ctx.fillRect(i, 0, 1, canvas.height);
  }
  for (let i = 0; i < canvas.height; i += 52) {
    ctx.fillRect(0, i, canvas.width, 1);
  }

  drawNode(state.nodes.replay, "#2c84a3", 32);
  drawNode(state.nodes.parent, "#2b7658", 32);
  for (const child of state.nodes.children) drawNode(child, "#1f4f66", 22);

  for (const child of state.nodes.children) {
    const x1 = state.nodes.replay.x * canvas.width;
    const y1 = state.nodes.replay.y * canvas.height;
    const x2 = child.x * canvas.width;
    const y2 = child.y * canvas.height;
    const x3 = state.nodes.parent.x * canvas.width;
    const y3 = state.nodes.parent.y * canvas.height;
    ctx.strokeStyle = "rgba(88,208,255,0.24)";
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(x1, y1);
    ctx.lineTo(x2, y2);
    ctx.stroke();
    ctx.strokeStyle = "rgba(255,202,84,0.2)";
    ctx.beginPath();
    ctx.moveTo(x2, y2);
    ctx.lineTo(x3, y3);
    ctx.stroke();
  }
}

function animate() {
  drawTopology();
  const next = [];
  for (const p of state.particles) {
    const t = Math.min(1, p.t + p.speed);
    const x = (p.fromX + (p.toX - p.fromX) * t) * canvas.width;
    const y = (p.fromY + (p.toY - p.fromY) * t) * canvas.height;
    ctx.beginPath();
    ctx.fillStyle = colorForKind(p.kind);
    ctx.arc(x, y, p.kind === "packet_transit" ? 4 : 6, 0, Math.PI * 2);
    ctx.fill();
    if (t < 1) {
      p.t = t;
      next.push(p);
    }
  }
  state.particles = next;
}

function renderCounters(counters = {}) {
  const urg = counters.urgency_counts || {};
  const rows = [
    ["Packet Events", counters.packet_flow_events || 0],
    ["Alert Events", counters.child_alert_events || 0],
    ["Parent Events", counters.parent_review_events || 0],
    ["Runtime SHAP", counters.runtime_shap_events || 0],
    ["Critical", urg.critical || 0],
    ["High", urg.high || 0],
  ];
  counterGrid.innerHTML = rows
    .map(
      ([label, value]) => `
      <article class="counter-card">
        <div class="label">${label}</div>
        <div class="value">${value}</div>
      </article>
    `
    )
    .join("");
}

function renderLogs() {
  parentLog.innerHTML = state.parentItems
    .map((row) => `<div class="log-item"><div class="time">${fmtTs(row.event_time)}</div><div>${row.child_id || "child"} ${row.event_type || "event"} ${row.recommendation ? `→ ${row.recommendation}` : ""}</div></div>`)
    .join("");
  shapLog.innerHTML = state.shapItems
    .map((row) => {
      const top = (row.payload?.top_features || []).slice(0, 3).map((x) => x.feature || "").filter(Boolean).join(", ");
      const status = row.status || row.payload?.details?.status || "";
      return `<div class="log-item"><div class="time">${fmtTs(row.event_time)}</div><div>${row.child_id || "child"} ${status}</div>${top ? `<div class="topf">${top}</div>` : ""}</div>`;
    })
    .join("");
  const incidentBox = document.getElementById("incidentLog");
  if (incidentBox) {
    incidentBox.innerHTML = state.incidentItems
      .map((row) => {
        const sev = row.severity || row.urgency || "low";
        const rec = row.recommendation || row.payload?.recommendation || "monitor_and_triage";
        return `<div class="log-item"><div class="time">${fmtTs(row.event_time)}</div><div><strong>${sev.toUpperCase()}</strong> ${row.child_id || "child"} → ${rec}</div></div>`;
      })
      .join("");
  }
}

function childNode(childId) {
  return state.nodes.children.find((n) => n.child_id === childId) || state.nodes.children[0];
}

function consumeFeed(feed) {
  const model = feed.model_version || state.modelVersion || "-";
  const run = feed.replay_run_id || state.replayRunId || "-";
  modelLabel.textContent = model;
  runLabel.textContent = run;
  updatedLabel.textContent = fmtTs(nowIso());
  state.modelVersion = feed.model_version || state.modelVersion;
  state.replayRunId = feed.replay_run_id || state.replayRunId;
  if (feed.cursor?.since_ts) state.sinceTs = feed.cursor.since_ts;
  if (feed.cursor?.since_event_id) state.sinceEventId = feed.cursor.since_event_id;
  if (Array.isArray(feed.child_status_snapshots) && feed.child_status_snapshots.length > 0) {
    recomputeNodes(feed.child_status_snapshots);
  }

  for (const ev of feed.packet_flow_events || []) {
    const child = childNode(ev.child_id);
    if (!child) continue;
    addParticle(state.nodes.replay, child, "packet_transit", ev.payload || {});
  }
  for (const ev of feed.child_alert_events || []) {
    const child = childNode(ev.child_id);
    if (!child) continue;
    addParticle(child, state.nodes.parent, ev.event_type === "escalation" ? "escalation" : "child_alert", ev.payload || {});
  }
  for (const ev of feed.parent_review_events || []) {
    pushLog(state.parentItems, ev);
    const child = childNode(ev.child_id);
    if (child) addParticle(child, state.nodes.parent, "review", ev.payload || {});
  }
  for (const ev of feed.runtime_shap_events || []) {
    pushLog(state.shapItems, ev);
  }
  for (const ev of feed.alert_events || []) {
    pushLog(state.incidentItems, ev);
  }
  renderCounters(feed.counters || {});
  renderLogs();
}

function recomputeNodes(children = []) {
  const sorted = [...children].sort((a, b) => String(a.child_id || "").localeCompare(String(b.child_id || "")));
  const count = Math.max(1, sorted.length);
  state.nodes.children = sorted.map((row, idx) => ({
    child_id: row.child_id,
    label: row.child_id,
    kind: "router",
    x: 0.37 + ((idx % 2) * 0.16),
    y: 0.12 + (0.74 * (idx + 1)) / (count + 1),
  }));
}

async function bootstrapChildren() {
  const childPayload = await dashboardApi.getStep3ChildStacks().catch(() => ({ children: [] }));
  recomputeNodes(childPayload.children || []);
}

async function poll() {
  if (state.polling) return;
  state.polling = true;
  try {
    const feed = await dashboardApi.getStep3VisualFeed({
      modelId: state.modelId,
      modelVersion: state.modelVersion,
      replayRunId: state.replayRunId,
      sinceTs: state.sinceTs,
      sinceEventId: state.sinceEventId,
      limit: 240,
    });
    consumeFeed(feed || {});
  } catch (_err) {
    // keep page alive under intermittent API errors
  } finally {
    state.polling = false;
  }
}

function resizeCanvas() {
  const bounds = canvas.getBoundingClientRect();
  const w = Math.max(800, Math.floor(bounds.width));
  const h = Math.max(540, Math.floor(bounds.height));
  canvas.width = w;
  canvas.height = h;
}

window.addEventListener("resize", resizeCanvas);

async function init() {
  resizeCanvas();
  await bootstrapChildren();
  renderCounters({});
  renderLogs();
  setInterval(() => animate(), ANIM_TICK_MS);
  await poll();
  setInterval(() => poll(), POLL_MS);
}

init();
