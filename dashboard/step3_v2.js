import { dashboardApi } from "./api/dashboardApi.js";

const activeSimulationEl = document.getElementById("activeSimulation");
const queueBackendEl = document.getElementById("queueBackend");
const queueLagEl = document.getElementById("queueLag");
const modelSelect = document.getElementById("modelSelect");
const simulationSelect = document.getElementById("simulationSelect");
const startBtn = document.getElementById("startBtn");
const stopBtn = document.getElementById("stopBtn");
const streamToggleBtn = document.getElementById("streamToggleBtn");
const streamStateEl = document.getElementById("streamState");
const simStartStatusEl = document.getElementById("simStartStatus");
const runsList = document.getElementById("runsList");
const alertsList = document.getElementById("alertsList");
const auditList = document.getElementById("auditList");
const auditFilter = document.getElementById("auditFilter");
const pcapFileCountEl = document.getElementById("pcapFileCount");
const pcapPacketTotalEl = document.getElementById("pcapPacketTotal");
const pcapRateTotalEl = document.getElementById("pcapRateTotal");
const pcapTableBody = document.getElementById("pcapTableBody");
const parentScopeSummaryEl = document.getElementById("parentScopeSummary");
const parentChildSummaryEl = document.getElementById("parentChildSummary");
const parentReviewTableBody = document.getElementById("parentReviewTableBody");
const hypothesisSyncBtn = document.getElementById("hypothesisSyncBtn");
const hypothesisCopyBtn = document.getElementById("hypothesisCopyBtn");
const hypothesisDownloadBtn = document.getElementById("hypothesisDownloadBtn");
const hypPacketsEl = document.getElementById("hypPackets");
const hypAttackBenignEl = document.getElementById("hypAttackBenign");
const hypAlertsActionsEl = document.getElementById("hypAlertsActions");
const hypothesisOutcomeBody = document.getElementById("hypothesisOutcomeBody");
const hypothesisChildBody = document.getElementById("hypothesisChildBody");
const hypothesisScopeBody = document.getElementById("hypothesisScopeBody");
const hypothesisPcapBody = document.getElementById("hypothesisPcapBody");
const persistentMetricsMetaEl = document.getElementById("persistentMetricsMeta");
const persistentPacketsEl = document.getElementById("persistentPackets");
const persistentAlertsEl = document.getElementById("persistentAlerts");
const persistentActionsEl = document.getElementById("persistentActions");
const persistentCoverageEl = document.getElementById("persistentCoverage");
const persistentMetricsBody = document.getElementById("persistentMetricsBody");
const tabButtons = Array.from(document.querySelectorAll(".tab-btn"));
const tabPanels = Array.from(document.querySelectorAll(".tab-panel"));

const packetsChart = echarts.init(document.getElementById("packetsChart"));
const alertsChart = echarts.init(document.getElementById("alertsChart"));
const eventsChart = echarts.init(document.getElementById("eventsChart"));
const pcapPacketsChart = echarts.init(document.getElementById("pcapPacketsChart"));
const pcapRateChart = echarts.init(document.getElementById("pcapRateChart"));

const MAX_ALERT_ROWS = 800;
const MAX_AUDIT_ROWS = 4000;
const MAX_RUN_ROWS = 400;
const MAX_PARENT_REVIEW_ROWS = 2500;
const MAX_PENDING_EVENTS = 12000;
const EVENT_BATCH_SIZE = 500;
const RENDER_INTERVAL_MS = 250;
const METRICS_CACHE_KEY = "ids_step3_v2_metrics_cache_v1";

const state = {
  currentSimulationId: "",
  currentModelVersion: "",
  lastEventId: "",
  stream: null,
  streamCursorId: "global",
  streamPaused: false,
  autoPaused: false,
  activeTab: "overview",
  childPackets: new Map(),
  childAlerts: new Map(),
  eventCounts: new Map(),
  runs: [],
  alerts: [],
  audits: [],
  pcapRows: [],
  pcapByFile: new Map(),
  parentReviewRows: [],
  parentSummaryByScope: {},
  parentSummaryByChild: {},
  hypothesis: null,
  persistentMetricRows: [],
  persistentMetricSummary: {},
  persistentMetricError: "",
  localHypothesis: {
    packets_total: 0,
    attack_packets: 0,
    benign_packets: 0,
    alerts_total: 0,
    parent_actions: 0,
    by_child: new Map(),
    by_scope: new Map(),
  },
  startupNotice: "No active simulation.",
  metricsCache: loadMetricsCache(),
  pendingEvents: [],
  droppedEvents: 0,
  processingEvents: false,
  renderScheduled: false,
  lastRenderAt: 0,
  dirty: {
    core: true,
    alerts: true,
    audits: true,
    runs: true,
    pcap: true,
    parent: true,
    hypothesis: true,
    metrics: true,
  },
};

function loadMetricsCache() {
  try {
    const parsed = JSON.parse(localStorage.getItem(METRICS_CACHE_KEY) || "{}");
    if (!parsed || typeof parsed !== "object") return { by_simulation: {} };
    const bySimulation = parsed.by_simulation && typeof parsed.by_simulation === "object" ? parsed.by_simulation : {};
    return { by_simulation: bySimulation };
  } catch {
    return { by_simulation: {} };
  }
}

function saveMetricsCache() {
  try {
    localStorage.setItem(METRICS_CACHE_KEY, JSON.stringify(state.metricsCache || { by_simulation: {} }));
  } catch {
    return;
  }
}

function fmtTs(ts) {
  if (!ts) return "-";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleTimeString();
}

function fmtBytes(n) {
  const v = Number(n || 0);
  if (v <= 0) return "0 B";
  if (v < 1024) return `${v} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`;
  if (v < 1024 * 1024 * 1024) return `${(v / (1024 * 1024)).toFixed(1)} MB`;
  return `${(v / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function esc(text) {
  return String(text || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function trimHead(arr, maxLen) {
  if (arr.length > maxLen) arr.length = maxLen;
}

function scopeFromChild(childId) {
  const cid = String(childId || "").toLowerCase();
  if (cid.includes("enterprise")) return "enterprise";
  if (cid.includes("dns")) return "dns";
  if (cid.includes("iiot")) return "iiot";
  if (cid.includes("iot")) return "iot";
  return "unknown";
}

function categoryFromAlert(scope, severity, phase) {
  const sev = String(severity || "low").toLowerCase();
  const p = String(phase || "").toLowerCase();
  if (scope === "dns") return sev === "high" || p.includes("attack") ? "dns_tunnel_or_c2" : "dns_anomaly";
  if (scope === "enterprise") return p.includes("attack") ? "lateral_movement_candidate" : "east_west_anomaly";
  if (scope === "iot") return sev === "high" ? "iot_compromise_candidate" : "iot_behavior_drift";
  if (scope === "iiot") return sev === "high" ? "iiot_safety_risk" : "iiot_process_anomaly";
  return "general_anomaly";
}

function frac(seed) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < seed.length; i += 1) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return ((h >>> 0) % 10000) / 10000;
}

function shapFromAlert(eventId, scope, severity, phase) {
  const sev = String(severity || "low").toLowerCase();
  const sevWeight = sev === "high" ? 0.62 : sev === "medium" ? 0.48 : 0.33;
  const phaseWeight = String(phase || "").toLowerCase().includes("attack") ? 0.57 : 0.43;
  const byScope = {
    enterprise: [["flow_duration_ms", 0.21], ["dst_port", 0.18], ["bytes_out", 0.14]],
    dns: [["dns_query_entropy", 0.23], ["domain_length", 0.19], ["nx_domain_ratio", 0.16]],
    iot: [["packet_interval_jitter", 0.2], ["bytes_out", 0.15], ["proto_mix", 0.14]],
    iiot: [["command_burstiness", 0.24], ["packet_interval_jitter", 0.17], ["dest_segment", 0.13]],
    unknown: [["packet_rate_pps", 0.15], ["bytes_out", 0.14], ["dst_port", 0.12]],
  };
  const base = byScope[scope] || byScope.unknown;
  const j1 = (frac(`${eventId}:a`) - 0.5) * 0.08;
  const j2 = (frac(`${eventId}:b`) - 0.5) * 0.08;
  const j3 = (frac(`${eventId}:c`) - 0.5) * 0.08;
  const top = [
    { feature: base[0][0], contribution: Math.max(0.01, Math.min(0.95, base[0][1] + sevWeight * 0.2 + j1)) },
    { feature: base[1][0], contribution: Math.max(0.01, Math.min(0.95, base[1][1] + phaseWeight * 0.15 + j2)) },
    { feature: base[2][0], contribution: Math.max(0.01, Math.min(0.95, base[2][1] + j3)) },
  ];
  const conf = Math.max(0.05, Math.min(0.99, 0.55 + sevWeight * 0.35 + (frac(`${eventId}:conf`) - 0.5) * 0.08));
  return { confidence: Number(conf.toFixed(4)), top_features: top.map((t) => ({ feature: t.feature, contribution: Number(t.contribution.toFixed(4)) })) };
}

function summarizeParentRows() {
  const byScope = {};
  const byChild = {};
  for (const r of state.parentReviewRows) {
    const scope = String(r.scope || "unknown");
    const child = String(r.child_id || "unknown");
    byScope[scope] = byScope[scope] || { alerts: 0, high: 0, escalated: 0 };
    byChild[child] = byChild[child] || { alerts: 0, high: 0, escalated: 0 };
    byScope[scope].alerts += 1;
    byChild[child].alerts += 1;
    if (String(r.severity || "").toLowerCase() === "high") {
      byScope[scope].high += 1;
      byChild[child].high += 1;
    }
    if (String(r.review_status || "") === "escalated") {
      byScope[scope].escalated += 1;
      byChild[child].escalated += 1;
    }
  }
  state.parentSummaryByScope = byScope;
  state.parentSummaryByChild = byChild;
}

function setDirty(...keys) {
  for (const k of keys) {
    if (k in state.dirty) state.dirty[k] = true;
  }
  scheduleRender();
}

function setTab(name) {
  state.activeTab = name;
  tabButtons.forEach((btn) => btn.classList.toggle("is-active", btn.dataset.tab === name));
  tabPanels.forEach((panel) => panel.classList.toggle("is-active", panel.id === `tab-${name}`));
  [packetsChart, alertsChart, eventsChart, pcapPacketsChart, pcapRateChart].forEach((c) => c.resize());
  setDirty("core", "alerts", "audits", "runs", "pcap", "parent", "hypothesis", "metrics");
}

function closeStream(target = state.stream) {
  if (!target) return;
  try {
    target.close();
  } catch {
    return;
  } finally {
    if (state.stream === target) {
      state.stream = null;
    }
  }
}

function updateStreamStateLabel() {
  if (!streamStateEl) return;
  const sim = String(state.currentSimulationId || "").trim();
  if (!sim) {
    streamStateEl.textContent = "stream: idle";
    return;
  }
  if (state.streamPaused) {
    streamStateEl.textContent = state.autoPaused ? "stream: paused (auto)" : "stream: paused";
    return;
  }
  streamStateEl.textContent = state.stream ? "stream: live" : "stream: reconnecting";
}

function setStartStatus(text) {
  const msg = String(text || "").trim() || "No active simulation.";
  state.startupNotice = msg;
  if (simStartStatusEl) simStartStatusEl.textContent = msg;
}

function setStreamPaused(paused, { auto = false } = {}) {
  state.streamPaused = Boolean(paused);
  state.autoPaused = Boolean(paused && auto);
  if (state.streamPaused) {
    closeStream();
  } else if (state.currentSimulationId) {
    openStream();
  }
  if (streamToggleBtn) {
    streamToggleBtn.textContent = state.streamPaused ? "Resume Stream" : "Pause Stream";
  }
  updateStreamStateLabel();
}

function renderRuns() {
  const rows = state.runs.slice(0, MAX_RUN_ROWS);
  if (simulationSelect) {
    const selectedId = String(state.currentSimulationId || "");
    const opts = ['<option value="">Select Simulation</option>'];
    for (const r of rows) {
      const id = String(r.simulation_id || "");
      if (!id) continue;
      const isSelected = id === selectedId ? " selected" : "";
      opts.push(`<option value="${esc(id)}"${isSelected}>${esc(id)} (${esc(r.status || "unknown")})</option>`);
    }
    simulationSelect.innerHTML = opts.join("");
  }
  runsList.innerHTML = rows
    .map(
      (r) => `<div class="row ${r.status === "completed" ? "ok" : ""}" data-sim-id="${esc(r.simulation_id)}">
        <div class="ts">${fmtTs(r.started_at_utc)}</div>
        <div><strong>${esc(r.simulation_id)}</strong></div>
        <div>${esc(r.model_version || "-")} • ${esc(r.status || "unknown")}</div>
      </div>`
    )
    .join("");
}

function renderAlerts() {
  alertsList.innerHTML = state.alerts
    .slice(0, MAX_ALERT_ROWS)
    .map(
      (a) => `<div class="row alert">
        <div class="ts">${fmtTs(a.ts_utc)}</div>
        <div><strong>${esc(a.child_id || "node")}</strong> • ${esc((a.severity || "low").toUpperCase())}</div>
        <div>${esc(a.payload?.recommendation || "review_and_triage")}</div>
      </div>`
    )
    .join("");
}

function renderAudit() {
  const filter = String(auditFilter?.value || "").trim().toLowerCase();
  const rows = state.audits.filter((a) => {
    if (!filter) return true;
    const line = `${a.message || ""} ${JSON.stringify(a.details || {})} ${a.level || ""}`.toLowerCase();
    return line.includes(filter);
  });
  auditList.innerHTML = rows
    .slice(0, MAX_AUDIT_ROWS)
    .map((a) => {
      const details = a.details && Object.keys(a.details).length > 0 ? ` • ${esc(JSON.stringify(a.details))}` : "";
      return `<div class="row ${a.level === "high" ? "alert" : ""}">
        <div class="ts">${fmtTs(a.ts_utc || a.created_at_utc)}</div>
        <div><strong>${esc((a.level || "info").toUpperCase())}</strong> • ${esc(a.message || "-")}${details}</div>
      </div>`;
    })
    .join("");
}

function renderParentReviewTab() {
  const scopeRows = Object.entries(state.parentSummaryByScope || {}).sort((a, b) => Number(b[1].alerts || 0) - Number(a[1].alerts || 0));
  const childRows = Object.entries(state.parentSummaryByChild || {}).sort((a, b) => Number(b[1].alerts || 0) - Number(a[1].alerts || 0));

  parentScopeSummaryEl.innerHTML = scopeRows.length
    ? scopeRows
        .map(
          ([scope, m]) => `<div class="row">
            <div><strong>${esc(scope)}</strong></div>
            <div>alerts=${Number(m.alerts || 0)} • high=${Number(m.high || 0)} • escalated=${Number(m.escalated || 0)}</div>
          </div>`
        )
        .join("")
    : '<div class="row"><div>No parent review scope data yet.</div></div>';

  parentChildSummaryEl.innerHTML = childRows.length
    ? childRows
        .map(
          ([child, m]) => `<div class="row">
            <div><strong>${esc(child)}</strong></div>
            <div>alerts=${Number(m.alerts || 0)} • high=${Number(m.high || 0)} • escalated=${Number(m.escalated || 0)}</div>
          </div>`
        )
        .join("")
    : '<div class="row"><div>No parent review child data yet.</div></div>';

  parentReviewTableBody.innerHTML = state.parentReviewRows
    .slice(0, MAX_PARENT_REVIEW_ROWS)
    .map((r) => {
      const top = Array.isArray(r.shap_top_features)
        ? r.shap_top_features.map((f) => `${f.feature}:${Number(f.contribution || 0).toFixed(3)}`).join(" | ")
        : "";
      return `<tr>
        <td>${esc(fmtTs(r.ts_utc))}</td>
        <td>${esc(r.child_id || "-")}</td>
        <td>${esc(r.scope || "unknown")}</td>
        <td>${esc(String(r.severity || "low").toUpperCase())}</td>
        <td>${esc(r.category || "general_anomaly")}</td>
        <td>${Number(r.shap_confidence || 0).toFixed(4)}</td>
        <td>${esc(top)}</td>
        <td>${esc(r.pcap_file || "-")}</td>
        <td>${esc(r.review_status || "reviewed")}</td>
      </tr>`;
    })
    .join("");
}

function tsvRow(cols) {
  return cols.map((c) => String(c ?? "").replaceAll("\t", " ")).join("\t");
}

function toCsv(rows) {
  const escCsv = (v) => `"${String(v ?? "").replaceAll('"', '""')}"`;
  return rows.map((r) => r.map(escCsv).join(",")).join("\n");
}

function downloadText(name, text, mime = "text/plain;charset=utf-8") {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function localHypothesisRows() {
  const byChild = Array.from(state.localHypothesis.by_child.values()).sort((a, b) => Number(b.packets_total || 0) - Number(a.packets_total || 0));
  const byScope = Array.from(state.localHypothesis.by_scope.values()).sort((a, b) => Number(b.packets_total || 0) - Number(a.packets_total || 0));
  const byPcap = Array.from(state.pcapByFile.values()).sort((a, b) => Number(b.packet_count || 0) - Number(a.packet_count || 0));
  const snapshot = {
    packets_total: Number(state.localHypothesis.packets_total || 0),
    attack_packets: Number(state.localHypothesis.attack_packets || 0),
    benign_packets: Number(state.localHypothesis.benign_packets || 0),
    alerts_total: Number(state.localHypothesis.alerts_total || 0),
    parent_actions: Number(state.localHypothesis.parent_actions || 0),
  };
  const hypotheses = [
    { hypothesis_id: "H1", name: "Rule-Hit Attack Detection", metric_key: "attack_packets", metric_value: snapshot.attack_packets, threshold_desc: "> 0", status: snapshot.attack_packets > 0 ? "pass" : "fail" },
    { hypothesis_id: "H2", name: "Benign Noise Control", metric_key: "benign_alert_ratio", metric_value: snapshot.benign_packets > 0 ? Number((snapshot.alerts_total / snapshot.benign_packets).toFixed(6)) : 0, threshold_desc: "<= 0.020000", status: (snapshot.benign_packets > 0 ? snapshot.alerts_total / snapshot.benign_packets : 0) <= 0.02 ? "pass" : "fail" },
  ];
  return { snapshot, byChild, byScope, byPcap, hypotheses };
}

function toHypothesisPayload(raw, source = "runtime") {
  const payload = raw && typeof raw === "object" ? raw : {};
  const snapshot = payload.snapshot && typeof payload.snapshot === "object" ? payload.snapshot : {};
  const hypotheses = Array.isArray(payload.hypotheses) ? payload.hypotheses : [];
  const generatedAt = String(payload.generated_at_utc || payload.generated_at || "").trim() || new Date().toISOString();
  return {
    snapshot,
    hypotheses,
    source,
    generated_at_utc: generatedAt,
  };
}

function cacheCurrentSimulationMetrics(payload, source = "runtime") {
  const simId = String(state.currentSimulationId || "").trim();
  if (!simId) return;
  const normalized = toHypothesisPayload(payload, source);
  if (!state.metricsCache || typeof state.metricsCache !== "object") {
    state.metricsCache = { by_simulation: {} };
  }
  if (!state.metricsCache.by_simulation || typeof state.metricsCache.by_simulation !== "object") {
    state.metricsCache.by_simulation = {};
  }
  state.metricsCache.by_simulation[simId] = normalized;
  saveMetricsCache();
}

function selectPersistentMetricsSource() {
  const simId = String(state.currentSimulationId || "").trim();
  if (state.hypothesis && typeof state.hypothesis === "object") {
    return toHypothesisPayload(state.hypothesis, "db_snapshot");
  }
  if (simId && state.metricsCache?.by_simulation?.[simId]) {
    return toHypothesisPayload(state.metricsCache.by_simulation[simId], "cached_snapshot");
  }
  return toHypothesisPayload(localHypothesisRows(), "runtime_stream");
}

function ratioText(numerator, denominator) {
  const den = Number(denominator || 0);
  if (den <= 0) return "0.000000";
  return (Number(numerator || 0) / den).toFixed(6);
}

function renderPersistentMetrics() {
  const rows = Array.isArray(state.persistentMetricRows) ? state.persistentMetricRows : [];
  const summary = state.persistentMetricSummary && typeof state.persistentMetricSummary === "object" ? state.persistentMetricSummary : {};
  const total = Number(summary.total || rows.length || 0);
  const measured = Number(summary.measured || 0);
  const missing = Number(summary.not_collected || 0);
  const other = Number(summary.other || 0);
  if (persistentPacketsEl) persistentPacketsEl.textContent = String(total);
  if (persistentAlertsEl) persistentAlertsEl.textContent = String(measured);
  if (persistentActionsEl) persistentActionsEl.textContent = String(missing);
  if (persistentCoverageEl) persistentCoverageEl.textContent = total > 0 ? (measured / total).toFixed(6) : "0.000000";
  if (persistentMetricsMetaEl) {
    const sim = String(state.currentSimulationId || "-");
    const err = String(state.persistentMetricError || "").trim();
    persistentMetricsMetaEl.textContent = err
      ? `source=phase4.metrics • simulation=${sim} • error=${err}`
      : `source=phase4.metrics • simulation=${sim} • stored=${total} • measured=${measured} • missing=${missing} • other=${other}`;
  }
  if (!persistentMetricsBody) return;
  if (!rows.length) {
    persistentMetricsBody.innerHTML = `<tr><td colspan="6">No stored Step 3 metrics for this SIM_ID yet. Complete the simulation or run Step 3 metrics regeneration.</td></tr>`;
    return;
  }
  persistentMetricsBody.innerHTML = rows
    .map((r) => {
      const rawVal = r?.metric_value;
      const numericVal = Number(rawVal);
      const metricVal = Number.isFinite(numericVal) ? numericVal.toFixed(6) : "-";
      const numerator = r?.numerator ?? "-";
      const denominator = r?.denominator ?? "-";
      const status = String(r?.calculation_status || "not_collected");
      const method = String(r?.calculation_method || "");
      const source = String(r?.source_ref || "phase4.metrics");
      return `<tr>
        <td>${esc(r?.metric_name || "")}</td>
        <td>${esc(metricVal)}</td>
        <td>${esc(`${numerator} / ${denominator}`)}</td>
        <td>${esc(method)}</td>
        <td><span class="metric-status ${esc(status)}">${esc(status)}</span></td>
        <td>${esc(source)}</td>
      </tr>`;
    })
    .join("");
}

function renderHypothesisTab() {
  const src = state.hypothesis && typeof state.hypothesis === "object" ? state.hypothesis : localHypothesisRows();
  const snapshot = src.snapshot || {};
  const hypotheses = Array.isArray(src.hypotheses) ? src.hypotheses : [];
  const byChild = Array.isArray(src.by_child) ? src.by_child : Array.isArray(src.byChild) ? src.byChild : [];
  const byScope = Array.isArray(src.by_scope) ? src.by_scope : Array.isArray(src.byScope) ? src.byScope : [];
  const byPcap = Array.isArray(src.by_pcap) ? src.by_pcap : Array.isArray(src.byPcap) ? src.byPcap : [];

  hypPacketsEl.textContent = String(Number(snapshot.packets_total || 0));
  hypAttackBenignEl.textContent = `${Number(snapshot.attack_packets || 0)} / ${Number(snapshot.benign_packets || 0)}`;
  hypAlertsActionsEl.textContent = `${Number(snapshot.alerts_total || 0)} / ${Number(snapshot.parent_actions || 0)}`;

  hypothesisOutcomeBody.innerHTML = hypotheses
    .map(
      (h) => `<tr>
        <td>${esc(h.hypothesis_id || "")} - ${esc(h.name || "")}</td>
        <td>${esc(h.metric_key || "")}</td>
        <td>${Number(h.metric_value || 0).toFixed(6)}</td>
        <td>${esc(h.threshold_desc || "")}</td>
        <td>${esc(String(h.status || "").toUpperCase())}</td>
      </tr>`
    )
    .join("");

  hypothesisChildBody.innerHTML = byChild
    .map(
      (r) => `<tr>
        <td>${esc(r.child_id || "")}</td>
        <td>${Number(r.packets_total || 0)}</td>
        <td>${Number(r.attack_packets || 0)}</td>
        <td>${Number(r.benign_packets || 0)}</td>
        <td>${Number(r.alerts_total || 0)}</td>
        <td>${Number(r.parent_actions || 0)}</td>
      </tr>`
    )
    .join("");

  hypothesisScopeBody.innerHTML = byScope
    .map(
      (r) => `<tr>
        <td>${esc(r.scope || "")}</td>
        <td>${Number(r.packets_total || 0)}</td>
        <td>${Number(r.attack_packets || 0)}</td>
        <td>${Number(r.benign_packets || 0)}</td>
        <td>${Number(r.alerts_total || 0)}</td>
        <td>${Number(r.parent_actions || 0)}</td>
      </tr>`
    )
    .join("");

  hypothesisPcapBody.innerHTML = byPcap
    .slice(0, 1200)
    .map(
      (r) => `<tr>
        <td>${esc(r.pcap_file || "")}</td>
        <td>${Number(r.packet_count || r.packets_total || 0)}</td>
        <td>${Number(r.attack_packets || 0)}</td>
        <td>${Number(r.benign_packets || 0)}</td>
        <td>${Number(r.transmission_rate_pps || 0).toFixed(3)}</td>
        <td>${Number(r.alert_count || r.alerts_total || 0)}</td>
        <td>${Number(r.parent_action_count || r.parent_actions || 0)}</td>
      </tr>`
    )
    .join("");
}

function copyHypothesisTables() {
  const src = state.hypothesis && typeof state.hypothesis === "object" ? state.hypothesis : localHypothesisRows();
  const lines = [];
  lines.push("SNAPSHOT");
  lines.push(tsvRow(["packets_total", "attack_packets", "benign_packets", "alerts_total", "parent_actions"]));
  lines.push(tsvRow([src.snapshot?.packets_total || 0, src.snapshot?.attack_packets || 0, src.snapshot?.benign_packets || 0, src.snapshot?.alerts_total || 0, src.snapshot?.parent_actions || 0]));
  lines.push("");
  lines.push("HYPOTHESES");
  lines.push(tsvRow(["id", "name", "metric", "value", "threshold", "status"]));
  for (const h of src.hypotheses || []) lines.push(tsvRow([h.hypothesis_id, h.name, h.metric_key, h.metric_value, h.threshold_desc, h.status]));
  lines.push("");
  lines.push("BY_CHILD");
  lines.push(tsvRow(["child_id", "packets_total", "attack_packets", "benign_packets", "alerts_total", "parent_actions"]));
  for (const r of src.by_child || src.byChild || []) lines.push(tsvRow([r.child_id, r.packets_total, r.attack_packets, r.benign_packets, r.alerts_total, r.parent_actions]));
  lines.push("");
  lines.push("BY_SCOPE");
  lines.push(tsvRow(["scope", "packets_total", "attack_packets", "benign_packets", "alerts_total", "parent_actions"]));
  for (const r of src.by_scope || src.byScope || []) lines.push(tsvRow([r.scope, r.packets_total, r.attack_packets, r.benign_packets, r.alerts_total, r.parent_actions]));
  lines.push("");
  lines.push("BY_PCAP");
  lines.push(tsvRow(["pcap_file", "packet_count", "attack_packets", "benign_packets", "transmission_rate_pps", "alert_count", "parent_action_count"]));
  for (const r of src.by_pcap || src.byPcap || []) lines.push(tsvRow([r.pcap_file, r.packet_count, r.attack_packets, r.benign_packets, r.transmission_rate_pps, r.alert_count, r.parent_action_count]));
  navigator.clipboard.writeText(lines.join("\n")).catch(() => null);
}

function downloadHypothesisCsvBundle() {
  const src = state.hypothesis && typeof state.hypothesis === "object" ? state.hypothesis : localHypothesisRows();
  const snapshots = [
    ["packets_total", "attack_packets", "benign_packets", "alerts_total", "parent_actions"],
    [src.snapshot?.packets_total || 0, src.snapshot?.attack_packets || 0, src.snapshot?.benign_packets || 0, src.snapshot?.alerts_total || 0, src.snapshot?.parent_actions || 0],
  ];
  const hypotheses = [["id", "name", "metric", "value", "threshold", "status"], ...((src.hypotheses || []).map((h) => [h.hypothesis_id, h.name, h.metric_key, h.metric_value, h.threshold_desc, h.status]))];
  const byChild = [["child_id", "packets_total", "attack_packets", "benign_packets", "alerts_total", "parent_actions"], ...((src.by_child || src.byChild || []).map((r) => [r.child_id, r.packets_total, r.attack_packets, r.benign_packets, r.alerts_total, r.parent_actions]))];
  const byScope = [["scope", "packets_total", "attack_packets", "benign_packets", "alerts_total", "parent_actions"], ...((src.by_scope || src.byScope || []).map((r) => [r.scope, r.packets_total, r.attack_packets, r.benign_packets, r.alerts_total, r.parent_actions]))];
  const byPcap = [["pcap_file", "packet_count", "attack_packets", "benign_packets", "transmission_rate_pps", "alert_count", "parent_action_count"], ...((src.by_pcap || src.byPcap || []).map((r) => [r.pcap_file, r.packet_count, r.attack_packets, r.benign_packets, r.transmission_rate_pps, r.alert_count, r.parent_action_count]))];
  const bundle = [
    "# snapshot.csv",
    toCsv(snapshots),
    "",
    "# hypotheses.csv",
    toCsv(hypotheses),
    "",
    "# by_child.csv",
    toCsv(byChild),
    "",
    "# by_scope.csv",
    toCsv(byScope),
    "",
    "# by_pcap.csv",
    toCsv(byPcap),
  ].join("\n");
  downloadText(`step3_v2_hypothesis_${state.currentSimulationId || "na"}.txt`, bundle, "text/plain;charset=utf-8");
}

function renderCoreCharts() {
  const packetNames = Array.from(state.childPackets.keys());
  const packetVals = packetNames.map((k) => state.childPackets.get(k));
  const alertNames = Array.from(state.childAlerts.keys());
  const alertVals = alertNames.map((k) => state.childAlerts.get(k));
  const eventNames = Array.from(state.eventCounts.keys());
  const eventVals = eventNames.map((k) => state.eventCounts.get(k));

  packetsChart.setOption(
    {
      animation: false,
      grid: { top: 20, left: 44, right: 16, bottom: 42 },
      xAxis: { type: "category", data: packetNames, axisLabel: { rotate: 35, color: "#b4d2e3" } },
      yAxis: { type: "value", axisLabel: { color: "#b4d2e3" } },
      series: [{ type: "bar", data: packetVals, itemStyle: { color: "#4acbff" } }],
      tooltip: { trigger: "axis" },
    },
    { lazyUpdate: true }
  );

  alertsChart.setOption(
    {
      animation: false,
      grid: { top: 20, left: 44, right: 16, bottom: 42 },
      xAxis: { type: "category", data: alertNames, axisLabel: { rotate: 35, color: "#b4d2e3" } },
      yAxis: { type: "value", axisLabel: { color: "#b4d2e3" } },
      series: [{ type: "line", smooth: true, data: alertVals, lineStyle: { color: "#ff7552" }, areaStyle: { color: "rgba(255,117,82,0.24)" } }],
      tooltip: { trigger: "axis" },
    },
    { lazyUpdate: true }
  );

  eventsChart.setOption(
    {
      animation: false,
      series: [
        {
          type: "pie",
          radius: ["35%", "74%"],
          data: eventNames.map((name, i) => ({ name, value: eventVals[i] })),
          label: { color: "#dce8ef" },
        },
      ],
      tooltip: { trigger: "item" },
    },
    { lazyUpdate: true }
  );
}

function renderPcapTab() {
  const rows = state.pcapRows.length > 0 ? state.pcapRows : Array.from(state.pcapByFile.values());
  const files = rows.map((r) => String(r.pcap_file || "unknown.pcap"));
  const packets = rows.map((r) => Number(r.packet_count || 0));
  const rates = rows.map((r) => Number(r.transmission_rate_pps || 0));
  const totalPackets = packets.reduce((a, b) => a + b, 0);
  const totalRate = rates.reduce((a, b) => a + b, 0);

  pcapFileCountEl.textContent = String(rows.length);
  pcapPacketTotalEl.textContent = String(totalPackets);
  pcapRateTotalEl.textContent = String(totalRate.toFixed(3));

  pcapPacketsChart.setOption(
    {
      animation: false,
      grid: { top: 20, left: 44, right: 16, bottom: 56 },
      xAxis: { type: "category", data: files, axisLabel: { rotate: 30, color: "#b4d2e3" } },
      yAxis: { type: "value", axisLabel: { color: "#b4d2e3" } },
      series: [{ type: "bar", data: packets, itemStyle: { color: "#58d4ff" } }],
      tooltip: { trigger: "axis" },
    },
    { lazyUpdate: true }
  );

  pcapRateChart.setOption(
    {
      animation: false,
      grid: { top: 20, left: 44, right: 16, bottom: 56 },
      xAxis: { type: "category", data: files, axisLabel: { rotate: 30, color: "#b4d2e3" } },
      yAxis: { type: "value", axisLabel: { color: "#b4d2e3" } },
      series: [{ type: "line", smooth: true, data: rates, lineStyle: { color: "#53f59d" }, areaStyle: { color: "rgba(83,245,157,0.2)" } }],
      tooltip: { trigger: "axis" },
    },
    { lazyUpdate: true }
  );

  pcapTableBody.innerHTML = rows
    .slice(0, 1200)
    .map(
      (r) => `<tr>
        <td>${esc(r.pcap_file)}</td>
        <td>${Number(r.packet_count || 0)}</td>
        <td>${Number(r.attack_packets || 0)}</td>
        <td>${Number(r.benign_packets || 0)}</td>
        <td>${Number(r.transmission_rate_pps || 0).toFixed(3)}</td>
        <td>${Number(r.avg_packet_rate_pps || 0).toFixed(3)}</td>
        <td>${Number(r.alert_count || 0)}</td>
        <td>${Number(r.parent_action_count || 0)}</td>
        <td>${esc(fmtBytes(r.file_size_bytes || 0))}</td>
        <td>${esc(r.source || "runtime")}</td>
        <td>${esc(fmtTs(r.first_ts_utc))} → ${esc(fmtTs(r.last_ts_utc))}</td>
      </tr>`
    )
    .join("");
}

function countEvent(type) {
  state.eventCounts.set(type, Number(state.eventCounts.get(type) || 0) + 1);
}

function ensurePcapRow(file, childId) {
  const key = String(file || `${childId || "unknown"}.pcap`);
  const found = state.pcapByFile.get(key) || {
    pcap_file: key,
    child_id: childId || "unknown",
    packet_count: 0,
    attack_packets: 0,
    benign_packets: 0,
    transmission_rate_pps: 0,
    avg_packet_rate_pps: 0,
    _rate_samples: 0,
    alert_count: 0,
    parent_action_count: 0,
    file_size_bytes: 0,
    source: "runtime",
    first_ts_utc: null,
    last_ts_utc: null,
  };
  state.pcapByFile.set(key, found);
  return found;
}

function upsertLocalParentReviewFromAlert(ev) {
  const eventId = String(ev.event_id || "");
  if (!eventId) return;
  if (state.parentReviewRows.some((r) => String(r.event_id) === eventId)) return;
  const childId = String(ev.child_id || "unknown");
  const severity = String(ev.severity || "low");
  const payload = ev.payload && typeof ev.payload === "object" ? ev.payload : {};
  const scope = scopeFromChild(childId);
  const phase = String(payload.phase || "");
  const category = categoryFromAlert(scope, severity, phase);
  const shap = shapFromAlert(eventId, scope, severity, phase);
  state.parentReviewRows.unshift({
    event_id: eventId,
    ts_utc: ev.ts_utc || null,
    child_id: childId,
    scope,
    severity,
    category,
    pcap_file: String(payload.pcap_file || ""),
    recommendation: String(payload.recommendation || "review_and_triage"),
    phase,
    shap_confidence: shap.confidence,
    shap_top_features: shap.top_features,
    review_status: severity.toLowerCase() === "high" ? "escalated" : "reviewed",
  });
  trimHead(state.parentReviewRows, MAX_PARENT_REVIEW_ROWS);
  summarizeParentRows();
  state.dirty.parent = true;
}

function applyEnvelope(ev) {
  if (!ev || typeof ev !== "object") return;
  if (ev.event_id) state.lastEventId = String(ev.event_id);
  const eventType = String(ev.event_type || "unknown");
  countEvent(eventType);
  state.dirty.core = true;

  if (eventType === "node_traffic" || eventType === "node_traffic_aggregate") {
    if (eventType === "node_traffic_aggregate") {
      const pcapFile = String(ev.payload?.pcap_file || "unknown.pcap");
      const row = ensurePcapRow(pcapFile, "aggregate");
      const packetCount = Number(ev.payload?.packet_count || 0);
      row.packet_count = Number(row.packet_count || 0) + packetCount;
      row.attack_packets = Number(row.attack_packets || 0) + Number(ev.payload?.attack_count || 0);
      row.benign_packets = Number(row.benign_packets || 0) + Number(ev.payload?.benign_count || 0);
      const children = Array.isArray(ev.payload?.children) ? ev.payload.children : [];
      const attackBatch = Number(ev.payload?.attack_count || 0);
      const childTotal = Math.max(1, children.reduce((acc, c) => acc + Number(c?.packet_count || 0), 0));
      const childAlloc = new Map();
      for (const c of children) {
        const childId = String(c?.child_id || "unknown");
        const childPacketCount = Number(c?.packet_count || 0);
        const attackEst = Math.round((attackBatch * childPacketCount) / childTotal);
        const benignEst = Math.max(0, childPacketCount - attackEst);
        childAlloc.set(childId, { attackEst, benignEst });
        state.childPackets.set(childId, Number(state.childPackets.get(childId) || 0) + childPacketCount);
      }
      const rate = Number(ev.payload?.packet_rate_pps || 0);
      if (rate > 0) {
        const samples = Number(row._rate_samples || 0) + 1;
        row._rate_samples = samples;
        row.avg_packet_rate_pps = ((Number(row.avg_packet_rate_pps || 0) * (samples - 1)) + rate) / samples;
        row.transmission_rate_pps = rate;
      }
      row.first_ts_utc = row.first_ts_utc || ev.ts_utc || null;
      row.last_ts_utc = ev.ts_utc || row.last_ts_utc || null;
      state.pcapRows = Array.from(state.pcapByFile.values()).sort((a, b) => Number(b.packet_count || 0) - Number(a.packet_count || 0));
      state.localHypothesis.packets_total += packetCount;
      state.localHypothesis.attack_packets += Number(ev.payload?.attack_count || 0);
      state.localHypothesis.benign_packets += Number(ev.payload?.benign_count || 0);
      for (const c of children) {
        const childId = String(c?.child_id || "unknown");
        const childPackets = Number(c?.packet_count || 0);
        const alloc = childAlloc.get(childId) || { attackEst: 0, benignEst: 0 };
        const childRow = state.localHypothesis.by_child.get(childId) || {
          child_id: childId,
          scope: scopeFromChild(childId),
          packets_total: 0,
          attack_packets: 0,
          benign_packets: 0,
          alerts_total: 0,
          parent_actions: 0,
        };
        childRow.packets_total += childPackets;
        childRow.attack_packets += Number(alloc.attackEst || 0);
        childRow.benign_packets += Number(alloc.benignEst || 0);
        state.localHypothesis.by_child.set(childId, childRow);
        const scope = String(childRow.scope || "unknown");
        const scopeRow = state.localHypothesis.by_scope.get(scope) || {
          scope,
          packets_total: 0,
          attack_packets: 0,
          benign_packets: 0,
          alerts_total: 0,
          parent_actions: 0,
        };
        scopeRow.packets_total += childPackets;
        scopeRow.attack_packets += Number(alloc.attackEst || 0);
        scopeRow.benign_packets += Number(alloc.benignEst || 0);
        state.localHypothesis.by_scope.set(scope, scopeRow);
      }
      state.dirty.pcap = true;
      state.dirty.hypothesis = true;
      state.dirty.metrics = true;
      return;
    }
    const childId = String(ev.child_id || "unknown");
    const packetIndex = Number(ev.payload?.packet_index || 0);
    state.childPackets.set(childId, Math.max(packetIndex, Number(state.childPackets.get(childId) || 0)));

    const pcapFile = String(ev.payload?.pcap_file || `${childId}.pcap`);
    const row = ensurePcapRow(pcapFile, childId);
    row.packet_count = Number(row.packet_count || 0) + 1;
    const label = String(ev.payload?.packet_label || "").toLowerCase();
    if (label === "attack") {
      row.attack_packets = Number(row.attack_packets || 0) + 1;
    } else if (label === "benign") {
      row.benign_packets = Number(row.benign_packets || 0) + 1;
    }
    const rate = Number(ev.payload?.packet_rate_pps || 0);
    if (rate > 0) {
      const samples = Number(row._rate_samples || 0) + 1;
      row._rate_samples = samples;
      row.avg_packet_rate_pps = ((Number(row.avg_packet_rate_pps || 0) * (samples - 1)) + rate) / samples;
      row.transmission_rate_pps = rate;
    }
    row.first_ts_utc = row.first_ts_utc || ev.ts_utc || null;
    row.last_ts_utc = ev.ts_utc || row.last_ts_utc || null;
    state.pcapRows = Array.from(state.pcapByFile.values()).sort((a, b) => Number(b.packet_count || 0) - Number(a.packet_count || 0));
    state.localHypothesis.packets_total += 1;
    if (label === "attack") state.localHypothesis.attack_packets += 1;
    if (label === "benign") state.localHypothesis.benign_packets += 1;
    const childRow = state.localHypothesis.by_child.get(childId) || {
      child_id: childId,
      scope: scopeFromChild(childId),
      packets_total: 0,
      attack_packets: 0,
      benign_packets: 0,
      alerts_total: 0,
      parent_actions: 0,
    };
    childRow.packets_total += 1;
    if (label === "attack") childRow.attack_packets += 1;
    if (label === "benign") childRow.benign_packets += 1;
    state.localHypothesis.by_child.set(childId, childRow);
    const scope = String(childRow.scope || "unknown");
    const scopeRow = state.localHypothesis.by_scope.get(scope) || {
      scope,
      packets_total: 0,
      attack_packets: 0,
      benign_packets: 0,
      alerts_total: 0,
      parent_actions: 0,
    };
    scopeRow.packets_total += 1;
    if (label === "attack") scopeRow.attack_packets += 1;
    if (label === "benign") scopeRow.benign_packets += 1;
    state.localHypothesis.by_scope.set(scope, scopeRow);
    state.dirty.pcap = true;
    state.dirty.hypothesis = true;
    state.dirty.metrics = true;
  }

  if (eventType === "node_alert") {
    const childId = String(ev.child_id || "unknown");
    const c = Number(state.childAlerts.get(childId) || 0) + 1;
    state.childAlerts.set(childId, c);
    state.alerts.unshift(ev);
    trimHead(state.alerts, MAX_ALERT_ROWS);
    const row = ensurePcapRow(String(ev.payload?.pcap_file || `${childId}.pcap`), childId);
    row.alert_count = Number(row.alert_count || 0) + 1;
    upsertLocalParentReviewFromAlert(ev);
    state.localHypothesis.alerts_total += 1;
    const childRow = state.localHypothesis.by_child.get(childId) || {
      child_id: childId,
      scope: scopeFromChild(childId),
      packets_total: 0,
      attack_packets: 0,
      benign_packets: 0,
      alerts_total: 0,
      parent_actions: 0,
    };
    childRow.alerts_total += 1;
    state.localHypothesis.by_child.set(childId, childRow);
    const scope = String(childRow.scope || "unknown");
    const scopeRow = state.localHypothesis.by_scope.get(scope) || {
      scope,
      packets_total: 0,
      attack_packets: 0,
      benign_packets: 0,
      alerts_total: 0,
      parent_actions: 0,
    };
    scopeRow.alerts_total += 1;
    state.localHypothesis.by_scope.set(scope, scopeRow);
    state.dirty.alerts = true;
    state.dirty.pcap = true;
    state.dirty.hypothesis = true;
    state.dirty.metrics = true;
  }

  if (eventType === "parent_action") {
    const childId = String(ev.child_id || "unknown");
    const row = ensurePcapRow(String(ev.payload?.pcap_file || `${childId}.pcap`), childId);
    row.parent_action_count = Number(row.parent_action_count || 0) + 1;
    // Mark the most recent review row for this child as escalated.
    const idx = state.parentReviewRows.findIndex((r) => String(r.child_id) === childId);
    if (idx >= 0) {
      state.parentReviewRows[idx].review_status = "escalated";
      summarizeParentRows();
      state.dirty.parent = true;
    }
    state.localHypothesis.parent_actions += 1;
    const childRow = state.localHypothesis.by_child.get(childId) || {
      child_id: childId,
      scope: scopeFromChild(childId),
      packets_total: 0,
      attack_packets: 0,
      benign_packets: 0,
      alerts_total: 0,
      parent_actions: 0,
    };
    childRow.parent_actions += 1;
    state.localHypothesis.by_child.set(childId, childRow);
    const scope = String(childRow.scope || "unknown");
    const scopeRow = state.localHypothesis.by_scope.get(scope) || {
      scope,
      packets_total: 0,
      attack_packets: 0,
      benign_packets: 0,
      alerts_total: 0,
      parent_actions: 0,
    };
    scopeRow.parent_actions += 1;
    state.localHypothesis.by_scope.set(scope, scopeRow);
    state.dirty.pcap = true;
    state.dirty.hypothesis = true;
    state.dirty.metrics = true;
  }

  if (eventType === "run_status") {
    const status = String(ev.payload?.status || "");
    if (ev.simulation_id && status) {
      const idx = state.runs.findIndex((r) => r.simulation_id === ev.simulation_id);
      if (idx >= 0) state.runs[idx].status = status;
      if (String(ev.simulation_id) === String(state.currentSimulationId || "")) {
        setStartStatus(`Simulation ${ev.simulation_id} status: ${status}`);
      }
    }
    state.dirty.runs = true;
    if (ev.simulation_id && String(ev.simulation_id) === String(state.currentSimulationId || "")) {
      refreshHypothesis().catch(() => null);
      refreshPersistentMetrics().catch(() => null);
    }
  }

  if (eventType === "audit_append") {
    state.audits.unshift({ level: ev.severity || "info", message: ev.payload?.message || "audit_append", details: ev.payload || {}, ts_utc: ev.ts_utc });
    trimHead(state.audits, MAX_AUDIT_ROWS);
    state.dirty.audits = true;
  }

  if (eventType === "queue_lag") {
    queueLagEl.textContent = String(Number(ev.payload?.total_lag || 0));
    if (ev.payload?.backend) queueBackendEl.textContent = String(ev.payload.backend);
  }
}

function processPendingEvents() {
  if (state.processingEvents) return;
  state.processingEvents = true;
  try {
    let processed = 0;
    while (state.pendingEvents.length > 0 && processed < EVENT_BATCH_SIZE) {
      const ev = state.pendingEvents.shift();
      applyEnvelope(ev);
      processed += 1;
    }
  } finally {
    state.processingEvents = false;
  }
  if (state.pendingEvents.length > 0) {
    setTimeout(processPendingEvents, 0);
  }
  scheduleRender();
}

function scheduleRender() {
  if (state.renderScheduled) return;
  const now = Date.now();
  const delay = Math.max(0, RENDER_INTERVAL_MS - (now - state.lastRenderAt));
  state.renderScheduled = true;
  setTimeout(() => {
    state.renderScheduled = false;
    state.lastRenderAt = Date.now();
    flushRender();
  }, delay);
}

function flushRender() {
  if (state.dirty.core && state.activeTab === "overview") {
    renderCoreCharts();
    state.dirty.core = false;
  }
  if (state.dirty.alerts && state.activeTab === "overview") {
    renderAlerts();
    state.dirty.alerts = false;
  }
  if (state.dirty.runs && state.activeTab === "overview") {
    renderRuns();
    state.dirty.runs = false;
  }
  if (state.dirty.audits && state.activeTab === "audit") {
    renderAudit();
    state.dirty.audits = false;
  }
  if (state.dirty.pcap && state.activeTab === "pcap") {
    renderPcapTab();
    state.dirty.pcap = false;
  }
  if (state.dirty.parent && state.activeTab === "parent") {
    renderParentReviewTab();
    state.dirty.parent = false;
  }
  if (state.dirty.hypothesis && state.activeTab === "hypothesis") {
    renderHypothesisTab();
    state.dirty.hypothesis = false;
  }
  if (state.dirty.metrics) {
    renderPersistentMetrics();
    state.dirty.metrics = false;
  }
}

function pushEvent(ev) {
  if (state.pendingEvents.length >= MAX_PENDING_EVENTS) {
    state.pendingEvents.shift();
    state.droppedEvents += 1;
  }
  state.pendingEvents.push(ev);
  if (state.pendingEvents.length === 1) {
    setTimeout(processPendingEvents, 0);
  }
}

function openStream() {
  if (!state.currentSimulationId) return;
  const openForSimulationId = String(state.currentSimulationId || "");
  if (state.streamPaused) {
    updateStreamStateLabel();
    return;
  }
  if (state.stream) {
    closeStream();
  }
  const url = dashboardApi.step3V2StreamUrl({ simulationId: state.currentSimulationId, cursorId: state.streamCursorId });
  const es = new EventSource(url);
  state.stream = es;
  updateStreamStateLabel();
  es.onmessage = (msg) => {
    if (state.stream !== es) return;
    if (msg.lastEventId) state.lastEventId = msg.lastEventId;
    try {
      const ev = JSON.parse(msg.data || "{}");
      pushEvent(ev);
    } catch {
      return;
    }
  };
  es.onerror = () => {
    if (state.stream !== es) return;
    closeStream(es);
    updateStreamStateLabel();
    if (state.streamPaused) return;
    if (String(state.currentSimulationId || "") !== openForSimulationId) return;
    setTimeout(() => openStream(), 1200);
  };
}

async function loadModels() {
  try {
    const out = await dashboardApi.getStep3V2EligibleModels();
    const readyRows = Array.isArray(out?.eligible_models)
      ? out.eligible_models
      : Array.isArray(out?.models)
      ? out.models.filter((r) => Boolean(r?.is_ready))
      : [];
    const fallbackRows = Array.isArray(out?.incomplete_models)
      ? out.incomplete_models
      : Array.isArray(out?.models)
      ? out.models.filter((r) => !Boolean(r?.is_ready))
      : [];
    const rows = readyRows.length > 0 ? readyRows : fallbackRows;
    if (!rows.length) {
      modelSelect.innerHTML = `<option value="">No model versions available</option>`;
      state.currentModelVersion = "";
      startBtn.disabled = true;
      setStartStatus("No Step 3 V2 models available. Complete Step 2 freeze/readiness first.");
      return;
    }
    modelSelect.innerHTML = rows
      .map((r) => {
        const mv = String(r.model_version || "");
        const mid = String(r.model_id || "");
        const pct = Number(r.completion_percent || 0);
        const ready = Boolean(r.is_ready);
        const label = ready ? `${mv}` : `${mv} [incomplete ${pct}%]`;
        return `<option value="${mv}" data-model-id="${mid}">${label}</option>`;
      })
      .join("");
    state.currentModelVersion = String(rows[0].model_version || "");
    startBtn.disabled = false;
    setStartStatus(readyRows.length > 0 ? "Ready model(s) available for simulation." : "Only incomplete models are currently available.");
  } catch (err) {
    modelSelect.innerHTML = `<option value="">Failed to load model versions</option>`;
    state.currentModelVersion = "";
    startBtn.disabled = true;
    setStartStatus(`Failed to load model versions: ${String(err?.message || err || "unknown_error")}`);
  }
}

async function refreshRuns() {
  const out = await dashboardApi.getStep3V2Simulations({ limit: 100 });
  state.runs = Array.isArray(out.simulations) ? out.simulations : [];
  setDirty("runs");
}

async function refreshQueue() {
  const out = await dashboardApi.getStep3V2QueueStatus();
  queueBackendEl.textContent = String(out.backend || "-");
  queueLagEl.textContent = String(Number(out.total_lag || 0));
}

async function refreshAudit() {
  if (!state.currentSimulationId) return;
  const out = await dashboardApi.getStep3V2Audit(state.currentSimulationId, { limit: MAX_AUDIT_ROWS });
  state.audits = Array.isArray(out.audit_rows) ? out.audit_rows : [];
  setDirty("audits");
}

async function refreshPcapMetrics() {
  if (!state.currentSimulationId) return;
  const out = await dashboardApi.getStep3V2PcapMetrics(state.currentSimulationId);
  state.pcapRows = Array.isArray(out.pcap_files) ? out.pcap_files : [];
  state.pcapByFile = new Map(state.pcapRows.map((r) => [String(r.pcap_file || "unknown.pcap"), { ...r, _rate_samples: 1 }]));
  setDirty("pcap");
}

async function refreshParentReview() {
  if (!state.currentSimulationId) return;
  const out = await dashboardApi.getStep3V2ParentReview(state.currentSimulationId, { limit: MAX_PARENT_REVIEW_ROWS });
  state.parentReviewRows = Array.isArray(out.review_rows) ? out.review_rows : [];
  state.parentSummaryByScope = out.summary_by_scope && typeof out.summary_by_scope === "object" ? out.summary_by_scope : {};
  state.parentSummaryByChild = out.summary_by_child && typeof out.summary_by_child === "object" ? out.summary_by_child : {};
  trimHead(state.parentReviewRows, MAX_PARENT_REVIEW_ROWS);
  setDirty("parent");
}

async function refreshHypothesis() {
  if (!state.currentSimulationId) return;
  const out = await dashboardApi.getStep3V2Hypothesis(state.currentSimulationId);
  state.hypothesis = out && typeof out === "object" ? out : null;
  if (state.hypothesis) {
    cacheCurrentSimulationMetrics(state.hypothesis, "db_snapshot");
  }
  setDirty("hypothesis", "metrics");
}

async function refreshPersistentMetrics() {
  const simId = String(state.currentSimulationId || "").trim();
  state.persistentMetricRows = [];
  state.persistentMetricSummary = {};
  state.persistentMetricError = "";
  if (!simId) {
    setDirty("metrics");
    return;
  }
  const out = await dashboardApi
    .getStep3Metrics({ simId })
    .catch((err) => ({ ok: false, error: err?.message || String(err), metrics: [] }));
  if (out?.ok) {
    state.persistentMetricRows = Array.isArray(out.metrics) ? out.metrics : [];
    state.persistentMetricSummary = out.summary && typeof out.summary === "object" ? out.summary : {};
  } else {
    state.persistentMetricError = String(out?.error || "step3_metrics_load_failed");
  }
  setDirty("metrics");
}

function resetSimulationLocalState() {
  state.childPackets.clear();
  state.childAlerts.clear();
  state.eventCounts.clear();
  state.alerts = [];
  state.audits = [];
  state.pcapRows = [];
  state.pcapByFile = new Map();
  state.parentReviewRows = [];
  state.parentSummaryByScope = {};
  state.parentSummaryByChild = {};
  state.hypothesis = null;
  state.persistentMetricRows = [];
  state.persistentMetricSummary = {};
  state.persistentMetricError = "";
  state.localHypothesis = {
    packets_total: 0,
    attack_packets: 0,
    benign_packets: 0,
    alerts_total: 0,
    parent_actions: 0,
    by_child: new Map(),
    by_scope: new Map(),
  };
  state.pendingEvents = [];
  state.droppedEvents = 0;
  setDirty("core", "alerts", "audits", "runs", "pcap", "parent", "hypothesis", "metrics");
}

async function handleStart() {
  const selected = modelSelect.options[modelSelect.selectedIndex];
  const modelVersion = String(selected?.value || "").trim();
  const modelId = String(selected?.dataset?.modelId || "").trim();
  if (!modelVersion) return;
  startBtn.disabled = true;
  try {
    const out = await dashboardApi.startStep3V2Simulation({ model_id: modelId || null, model_version: modelVersion, execution_mode: "simulation" });
    const simId = String(out.simulation_id || "");
    state.currentSimulationId = simId;
    state.currentModelVersion = modelVersion;
    activeSimulationEl.textContent = simId || "-";
    stopBtn.disabled = !simId;
    setStartStatus(simId ? `Simulation started: ${simId}` : "Simulation start requested.");
    if (simulationSelect) simulationSelect.value = simId;
    if (streamToggleBtn) streamToggleBtn.disabled = !simId;
    resetSimulationLocalState();
    if (simId) {
      state.runs.unshift({
        simulation_id: simId,
        model_version: modelVersion,
        status: "running",
        started_at_utc: new Date().toISOString(),
      });
      trimHead(state.runs, MAX_RUN_ROWS);
      setDirty("runs");
    }
    await refreshRuns();
    await refreshAudit();
    await refreshPcapMetrics();
    await refreshParentReview();
    await refreshHypothesis();
    await refreshPersistentMetrics();
    updateStreamStateLabel();
    openStream();
  } catch (err) {
    setStartStatus(`Simulation start failed: ${String(err?.message || err || "unknown_error")}`);
    throw err;
  } finally {
    startBtn.disabled = false;
  }
}

async function handleStop() {
  const simId = String(state.currentSimulationId || "");
  if (!simId) return;
  stopBtn.disabled = true;
  try {
    await dashboardApi.stopStep3V2Simulation(simId);
    setStartStatus(`Simulation stop requested: ${simId}`);
    await refreshRuns();
    await refreshAudit();
    await refreshPcapMetrics();
    await refreshParentReview();
    await refreshHypothesis();
    await refreshPersistentMetrics();
  } catch (err) {
    setStartStatus(`Simulation stop failed: ${String(err?.message || err || "unknown_error")}`);
    throw err;
  } finally {
    stopBtn.disabled = false;
  }
}

async function handleSelectRun(simId) {
  const id = String(simId || "").trim();
  if (!id) return;
  state.currentSimulationId = id;
  const cached = state.metricsCache?.by_simulation?.[id];
  if (cached && typeof cached === "object") {
    state.hypothesis = cached;
    setDirty("hypothesis", "metrics");
  }
  activeSimulationEl.textContent = id;
  stopBtn.disabled = false;
  setStartStatus(`Simulation selected: ${id}`);
  await refreshAudit();
  await refreshPcapMetrics();
  await refreshParentReview();
  await refreshHypothesis();
  await refreshPersistentMetrics();
  if (simulationSelect) simulationSelect.value = id;
  if (streamToggleBtn) streamToggleBtn.disabled = false;
  if (state.streamPaused) {
    updateStreamStateLabel();
    return;
  }
  openStream();
}

function initChartSkeletons() {
  packetsChart.setOption({ xAxis: { type: "category", data: [] }, yAxis: { type: "value" }, series: [{ type: "bar", data: [] }] });
  alertsChart.setOption({ xAxis: { type: "category", data: [] }, yAxis: { type: "value" }, series: [{ type: "line", data: [] }] });
  eventsChart.setOption({ series: [{ type: "pie", data: [] }] });
  pcapPacketsChart.setOption({ xAxis: { type: "category", data: [] }, yAxis: { type: "value" }, series: [{ type: "bar", data: [] }] });
  pcapRateChart.setOption({ xAxis: { type: "category", data: [] }, yAxis: { type: "value" }, series: [{ type: "line", data: [] }] });
}

async function init() {
  initChartSkeletons();
  setTab("overview");
  setDirty("metrics");
  await loadModels();
  await refreshRuns();
  await refreshQueue();
  const preferredRun =
    state.runs.find((r) =>
      ["running", "initializing", "stopping", "finalizing", "created"].includes(String(r.status || "").toLowerCase())
    ) || state.runs[0];
  if (preferredRun?.simulation_id) {
    await handleSelectRun(String(preferredRun.simulation_id));
  }

  startBtn.addEventListener("click", handleStart);
  stopBtn.addEventListener("click", handleStop);
  if (streamToggleBtn) {
    streamToggleBtn.addEventListener("click", () => {
      setStreamPaused(!state.streamPaused, { auto: false });
    });
  }
  if (hypothesisSyncBtn) {
    hypothesisSyncBtn.addEventListener("click", () => {
      refreshHypothesis().catch((err) => console.error("failed to refresh hypothesis", err));
      refreshPersistentMetrics().catch((err) => console.error("failed to refresh persistent metrics", err));
    });
  }
  if (hypothesisCopyBtn) {
    hypothesisCopyBtn.addEventListener("click", () => copyHypothesisTables());
  }
  if (hypothesisDownloadBtn) {
    hypothesisDownloadBtn.addEventListener("click", () => downloadHypothesisCsvBundle());
  }
  modelSelect.addEventListener("change", () => {
    state.currentModelVersion = String(modelSelect.value || "");
  });
  if (simulationSelect) {
    simulationSelect.addEventListener("change", () => {
      const id = String(simulationSelect.value || "").trim();
      if (!id) return;
      handleSelectRun(id).catch((err) => console.error("failed to switch simulation", err));
    });
  }
  tabButtons.forEach((btn) => {
    btn.addEventListener("click", () => setTab(String(btn.dataset.tab || "overview")));
  });
  runsList.addEventListener("click", (ev) => {
    const target = ev.target instanceof Element ? ev.target : null;
    if (!target) return;
    const row = target.closest("[data-sim-id]");
    if (!row) return;
    handleSelectRun(String(row.dataset.simId || "")).catch((err) => console.error("failed to switch simulation", err));
  });
  if (auditFilter) {
    auditFilter.addEventListener("input", () => setDirty("audits"));
  }
  window.addEventListener("resize", () => {
    [packetsChart, alertsChart, eventsChart, pcapPacketsChart, pcapRateChart].forEach((c) => c.resize());
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      if (!state.streamPaused) setStreamPaused(true, { auto: true });
      return;
    }
    if (state.streamPaused && state.autoPaused) {
      setStreamPaused(false, { auto: false });
    }
  });
  window.addEventListener("offline", () => {
    if (!state.streamPaused) setStreamPaused(true, { auto: true });
  });
  window.addEventListener("online", () => {
    if (state.streamPaused && state.autoPaused) {
      setStreamPaused(false, { auto: false });
    }
  });
  setStartStatus(state.startupNotice);
  updateStreamStateLabel();
}

init().catch((err) => {
  console.error("step3_v2 init failed", err);
});
