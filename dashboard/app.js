import { dashboardApi } from "./api/dashboardApi.js";
import { getResolvedApiBase } from "./api/http.js";
import { createStep3V2Tab } from "./step3_v2_tab.js";

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "step1", label: "Step 1" },
  { id: "step2", label: "Step 2" },
  { id: "step3", label: "Step 3" },
  { id: "metrics", label: "Metrics" },
  { id: "governance", label: "Governance/Audit" },
];
const STEP1_DATASET_IDS = ["ENT-01", "ENT-02", "DNS-01", "IOT-01", "IOT-02"];

const state = {
  activeTabId: TABS[0].id,
  status: null,
  governance: null,
  step1: null,
  step2: null,
  currentModelHeader: null,
  models: [],
  selectedModelVersion: "",
  selectedModelLabel: "",
  selectedModelLabelManual: false,
  step1Runs: [],
  selectedStep1RunId: "",
  step2Readiness: null,
  step2ExecutionMode: "continue_existing",
  selectedStep3ModelVersion: "",
  selectedStep3ModelId: "",
  step3ModelReadiness: null,
  step1RunId: "",
  step1History: [],
  step2RunId: "",
  step2ControlStatus: null,
  step2ControlEditing: false,
  step1HeaderStatus: null,
  step2HeaderStatus: null,
  step3HeaderStatus: null,
  step3HeaderProcess: null,
  step2VersionsFilterQ: "",
  step2VersionsFilterStatus: "all",
  step2SelectedDetailVersion: "",
  step2SelectedDetail: null,
  step3ReplayProfile: "default",
  step3PreparationRecord: null,
  step3PreparationFlowReport: null,
  step3Preparing: false,
  step3ReplayStarting: false,
  step4Status: null,
  step4Step1Runs: [],
  step4Step2Models: [],
  step4Step3Simulations: [],
  selectedStep4RunId: "",
  selectedStep4ModelVersion: "",
  selectedStep4ModelId: "",
  selectedStep4SimId: "",
  step4Hypothesis: null,
  step4PcapMetrics: null,
  step4LoadError: "",
  step3V2HeaderSim: null,
  step3V2HeaderCompletionPct: 0,
  step3V2HeaderCompletionText: "0.0%",
  step4HeaderStatus: "pending",
  metricsPrincipleReviewMd: "",
  metricsGeneratedMd: "",
  metricsStep1Runs: [],
  metricsStep3ReplayRuns: [],
  metricsStep4Step3Simulations: [],
  metricsSelectedStep3SimId: "",
  metricsSelectedStep4SimId: "",
  metricsStep3Rows: [],
  metricsStep3Summary: {},
  metricsStep3RowsError: "",
  metricsLoadError: "",
  /** Step 3 model dropdown rows (for poll-time readiness without re-fetching registry). */
  step3ModelChoicesCache: [],
};

const nav = document.getElementById("tabNav");
const content = document.getElementById("tabContent");
const globalStatus = document.getElementById("globalStatus");
const pipelineStepStatus = document.getElementById("pipelineStepStatus");
const manualRefreshBtn = document.getElementById("manualRefreshBtn");
const pollToggleBtn = document.getElementById("pollToggleBtn");
const tinyHeaderRefreshBtn = document.getElementById("tinyHeaderRefreshBtn");
const step3V2Tab = createStep3V2Tab({ src: "./step3_v2.html" });
let renderedTabId = "";

let pollTimer = null;
const POLL_PAUSED_KEY = "ids_dashboard_v1_polling_paused";
let pollingPaused = true;

function notice(msg, cls = "") {
  const d = document.createElement("div");
  d.className = `notice ${cls}`.trim();
  d.textContent = msg;
  globalStatus.prepend(d);
}

function makeSection(title, subtitle) {
  const tpl = document.getElementById("sectionTemplate").content.cloneNode(true);
  tpl.querySelector(".page-title").textContent = title;
  tpl.querySelector(".page-subtitle").textContent = subtitle;
  return tpl;
}

function table(headers, rows) {
  return `<div class="table-wrap"><table><thead><tr>${headers.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
}

function escapeHtml(s) {
  if (s == null || s === "") return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function roleBadge(role = "") {
  const raw = role || "";
  const r = raw.toLowerCase();
  if (r.includes("primary")) return `<span class="badge ok">TRAINING SOURCE</span>`;
  if (r.includes("cross")) return `<span class="badge warn">CROSS-TEST ONLY</span>`;
  if (r.includes("rule")) return `<span class="badge model">RULE SUPPORT</span>`;
  return `<span class="badge warn">${escapeHtml(raw || "ROLE")}</span>`;
}

function parseRunMetrics(run) {
  let m = run?.run_metrics;
  if (m == null) return {};
  if (typeof m === "string") {
    try {
      m = JSON.parse(m);
    } catch {
      return {};
    }
  }
  return typeof m === "object" && m !== null ? m : {};
}

function normalizeStatusLabel(raw) {
  const s = String(raw || "").trim().toLowerCase();
  if (["completed", "failed", "running", "queued", "pending", "partial", "skipped"].includes(s)) return s;
  if (s === "success" || s === "done" || s === "ok") return "completed";
  if (s === "error") return "failed";
  return s || "pending";
}

function selectedStep1HistoryRun() {
  const rid = String(state.step1RunId || "");
  const rows = Array.isArray(state.step1History) ? state.step1History : [];
  if (rid) {
    const found = rows.find((r) => String(r?.run_id || "") === rid);
    if (found) return found;
  }
  return rows[0] || null;
}

function synthesizeStep1SummaryFromHistory(historyRun) {
  const snap = historyRun && typeof historyRun.dataset_readiness_snapshot === "object" ? historyRun.dataset_readiness_snapshot : {};
  const out = {};
  for (const dsid of Object.keys(snap || {})) {
    const row = snap[dsid] && typeof snap[dsid] === "object" ? snap[dsid] : {};
    out[dsid] = {
      ok: row.ok === true,
      readiness: String(row.readiness || ""),
      normalized_rows: Number(row.rows || 0),
      failed_rows: Number(row.failed_rows || 0),
      file_summary: [],
      stage: row.ok ? "step1_dataset_coordinator" : "artifact_check",
      status: row.ok ? "completed" : "failed",
      returncode: row.ok ? 0 : 1,
    };
  }
  return out;
}

function resolveStep1DisplayStatus(run, metrics, historyRun) {
  const dbStatus = normalizeStatusLabel(run?.status);
  const histStatus = normalizeStatusLabel(historyRun?.status);
  if ((dbStatus === "running" || dbStatus === "queued" || dbStatus === "pending") && (histStatus === "completed" || histStatus === "failed")) {
    return histStatus;
  }
  if (dbStatus === "running" && metrics?.step1_all_datasets_strict_complete === true) {
    return "completed";
  }
  return dbStatus || histStatus || "pending";
}

function formatRunLabelFromTimestamp(ts) {
  if (!ts) return "";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "";
  const yy = String(d.getUTCFullYear()).slice(-2);
  const mm = String(d.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(d.getUTCDate()).padStart(2, "0");
  const hh = String(d.getUTCHours()).padStart(2, "0");
  const mi = String(d.getUTCMinutes()).padStart(2, "0");
  const ss = String(d.getUTCSeconds()).padStart(2, "0");
  return `${yy}${mm}${dd}-${hh}${mi}${ss}`;
}

function runLabel(run) {
  if (!run) return "";
  const metrics = parseRunMetrics(run);
  const stored = String(run.run_label || metrics.run_label || "").trim();
  if (stored) return stored;
  return formatRunLabelFromTimestamp(run.started_at_utc || run.started_at);
}

function runIdWithLabel(run) {
  if (!run) return "—";
  const rid = String(run.run_id || "—");
  const label = runLabel(run);
  return label ? `${label} (${rid})` : rid;
}

function statusBadgeHtml(status) {
  const st = String(status || "pending").toLowerCase();
  const cls = st === "completed" ? "ok" : st === "failed" ? "bad" : st === "running" ? "model" : "warn";
  return `<span class="badge ${cls}">${escapeHtml(st)}</span>`;
}

function latestRun(stepPayload) {
  if (!stepPayload) return null;
  if (stepPayload.db) return Object.assign({}, stepPayload.db, { _live: stepPayload.live || null });
  // Model-V1 status endpoints return a direct run payload (not `runs[]`).
  if (stepPayload.run_id || stepPayload.overall_status || Array.isArray(stepPayload.stages)) {
    return stepPayload;
  }
  return (stepPayload.runs || [])[0] || null;
}

function renderTopPipelineStatus() {
  if (!pipelineStepStatus) return;
  const s1 = latestRun(state.step1HeaderStatus || state.step1);
  const s2 = latestRun(state.step2HeaderStatus || state.step2);
  const s1Label = "Dataset Processing";
  const s2Label = "Model Training";
  const s3 = state.step3V2HeaderSim || null;
  const s3Status = s3 ? normalizeStep3StatusLabel(String(s3.status || "pending")) : "pending";
  const s4Status = normalizeStep4HeaderStatus(state.step4HeaderStatus, s3Status);
  const s3CompletionText = String(state.step3V2HeaderCompletionText || "0.0%");
  pipelineStepStatus.innerHTML = `<div class="status-mini-title">Overview Step Status</div>
    <div class="status-mini-row"><strong>Step 1</strong><span class="status-mini-id">${escapeHtml(s1Label)}</span><span class="status-mini-progress">-</span>${statusBadgeHtml(s1?.status || "pending")}</div>
    <div class="status-mini-row"><strong>Step 2</strong><span class="status-mini-id">${escapeHtml(s2Label)}</span><span class="status-mini-progress">-</span>${statusBadgeHtml(s2?.status || s2?.overall_status || "pending")}</div>
    <div class="status-mini-row"><strong>Step 3</strong><span class="status-mini-id">Simulation</span><span class="status-mini-progress">${escapeHtml(s3CompletionText)}</span>${statusBadgeHtml(s3Status)}</div>
    <div class="status-mini-row"><strong>Step 4</strong><span class="status-mini-id">Dissertation Metrics</span><span class="status-mini-progress">-</span>${statusBadgeHtml(s4Status)}</div>`;
}

function normalizeStep3StatusLabel(statusRaw) {
  const s = String(statusRaw || "").toLowerCase();
  if (s === "completed") return "completed";
  if (s === "failed" || s === "stopped") return "failed";
  if (s === "running" || s === "initializing" || s === "stopping" || s === "finalizing" || s === "created") return "running";
  return "pending";
}

function normalizeStep4HeaderStatus(step4Raw, step3Status) {
  const s4 = String(step4Raw || "").toLowerCase();
  if (["completed", "running", "failed", "pending"].includes(s4)) return s4;
  const s3 = String(step3Status || "pending").toLowerCase();
  if (s3 === "completed") return "completed";
  if (s3 === "failed") return "failed";
  if (s3 === "running") return "running";
  return "pending";
}

function resolveStep3HeaderSimulation(simulations) {
  const sims = Array.isArray(simulations) ? simulations : [];
  if (!sims.length) return null;
  const running = sims.find((s) => {
    const st = String(s?.status || "").toLowerCase();
    return st === "running" || st === "initializing" || st === "stopping" || st === "created";
  });
  return running || sims[0] || null;
}

function step3CompletionFromSimulation(sim) {
  const meta = sim && typeof sim.metadata === "object" && sim.metadata ? sim.metadata : {};
  const fds = meta.file_dispatch_state && typeof meta.file_dispatch_state === "object" ? meta.file_dispatch_state : {};
  const fileStates = fds.file_states && typeof fds.file_states === "object" ? fds.file_states : {};
  const fileKeys = Object.keys(fileStates);
  const totalFiles = fileKeys.length > 0
    ? fileKeys.length
    : (Array.isArray(meta.pcap_files) ? meta.pcap_files.length : 0);
  let completedFiles = 0;
  for (const fk of fileKeys) {
    const row = fileStates[fk] && typeof fileStates[fk] === "object" ? fileStates[fk] : {};
    const remaining = Number(row.remaining_packets || 0);
    if (remaining <= 0) completedFiles += 1;
  }
  completedFiles = Math.max(completedFiles, Number(fds.files_completed || 0));
  const pct = totalFiles > 0 ? Math.max(0, Math.min(100, (completedFiles / totalFiles) * 100)) : 0;
  return {
    totalFiles,
    completedFiles,
    pct,
    text: `${pct.toFixed(1)}% (${completedFiles}/${totalFiles || 0})`,
  };
}

function formatTaskError(r) {
  const parts = [];
  if (r.error) parts.push(`Error: ${r.error}`);
  if (r.stderr_tail) parts.push(`STDERR (tail):\n${r.stderr_tail}`);
  if (r.stdout_tail) parts.push(`STDOUT (tail):\n${r.stdout_tail}`);
  if (Array.isArray(r.job_errors) && r.job_errors.length) {
    parts.push(`Parallel job errors:\n${JSON.stringify(r.job_errors, null, 2)}`);
  }
  if (Array.isArray(r.file_summary) && r.file_summary.length) {
    parts.push(`File-level summary:\n${JSON.stringify(r.file_summary, null, 2)}`);
  }
  if (parts.length === 0) parts.push("(No stderr/stdout tail captured; check worker logs on the host.)");
  return parts.join("\n\n");
}

function uploadByDatasetId(datasetId) {
  return (state.status?.uploads || []).find((u) => u.dataset_id === datasetId) || {};
}

/** Prefer ``is_current`` in model list; else API header preview (registry_fallback). */
function applyModelSelectionFromRegistry(header) {
  const current = state.models.find((m) => m.is_current);
  if (!state.selectedModelVersion && current) {
    state.selectedModelVersion = current.model_version;
    if (!state.selectedModelLabelManual) {
      state.selectedModelLabel = String(current.model_name || "");
    }
    return;
  }
  if (
    !state.selectedModelVersion &&
    header &&
    header.current_model_version &&
    String(header.header_source || "").startsWith("registry_fallback")
  ) {
    state.selectedModelVersion = header.current_model_version;
    if (!state.selectedModelLabelManual) {
      state.selectedModelLabel = String((header.model || {}).model_name || "");
    }
  }
}

/** Baseline load used by Overview and full refresh. */
async function load() {
  const [status, governance, header, modelsPayload] = await Promise.all([
    dashboardApi.status(),
    dashboardApi.governanceSummary(),
    dashboardApi.getCurrentModelHeader(),
    dashboardApi.getModelVersions().catch(() => ({ models: [] })),
  ]);
  state.status = status;
  state.governance = governance;
  state.currentModelHeader = header;
  state.models = modelsPayload.models || [];
  applyModelSelectionFromRegistry(header);
  state.step1 = await dashboardApi.getStep1Status(state.step1RunId).catch(() => ({ ok: false, runs: [] }));
  state.step2 = await dashboardApi.getStep2Status(state.step2RunId).catch(() => ({ ok: false, runs: [] }));
}

async function loadForStep1() {
  const [status, listPayload, step1StatusPayload] = await Promise.all([
    dashboardApi.status(),
    dashboardApi.getModelV1Step1Runs().catch(() => ({ ok: false, runs: [] })),
    dashboardApi.getStep1Status("").catch(() => ({ ok: false, runs: [] })),
  ]);
  state.status = status;
  const runs = (listPayload.runs || []).slice().sort((a, b) => {
    const at = String(a?.started_at_utc || "");
    const bt = String(b?.started_at_utc || "");
    if (at === bt) return String(b?.run_id || "").localeCompare(String(a?.run_id || ""));
    return bt.localeCompare(at);
  });
  state.step1History = runs;
  const latestId = runs?.[0]?.run_id || "";
  const selectedStillExists = state.step1RunId && runs.some((r) => r.run_id === state.step1RunId);
  if (!selectedStillExists) state.step1RunId = latestId;
  const rid = state.step1RunId || latestId;
  const dbRuns = Array.isArray(step1StatusPayload?.runs) ? step1StatusPayload.runs : [];
  let selectedRun = rid ? dbRuns.find((r) => String(r?.run_id || "") === rid) || null : null;
  if (!selectedRun && rid) {
    const runPayload = await dashboardApi.getStep1Status(rid).catch(() => ({ ok: false }));
    selectedRun = latestRun(runPayload);
  }
  if (!selectedRun && dbRuns.length) selectedRun = dbRuns[0];
  state.step1 = selectedRun ? { ok: true, step: "step1", runs: [selectedRun] } : { ok: true, step: "step1", runs: [] };
}

async function loadForStep2() {
  const [status, modelsPayload, step1RunsPayload, header] = await Promise.all([
    dashboardApi.status(),
    dashboardApi
      .getModelVersions({
        q: state.step2VersionsFilterQ || "",
        status: state.step2VersionsFilterStatus || "all",
        sort: "created_at_desc",
      })
      .catch(() => ({ models: [] })),
    dashboardApi.getModelV1Step1Runs().catch(() => ({ runs: [] })),
    dashboardApi.getCurrentModelHeader().catch(() => null),
  ]);
  state.status = status;
  state.models = modelsPayload.models || [];
  state.currentModelHeader = header;
  applyModelSelectionFromRegistry(header);
  state.step1Runs = step1RunsPayload.runs || [];
  if (!state.selectedStep1RunId && state.step1Runs.length) state.selectedStep1RunId = state.step1Runs[0].run_id;
  if (state.step2SelectedDetailVersion) {
    state.step2SelectedDetail = await dashboardApi
      .getModelVersion(state.step2SelectedDetailVersion)
      .catch(() => state.step2SelectedDetail);
  }
  const prevStep2 = state.step2 || null;
  const latestModelV1 = await dashboardApi.getModelV1Step2Status("").catch(() => null);
  const latestGeneric = await dashboardApi.getStep2Status("").catch(() => ({ ok: false, runs: [] }));
  const latestId =
    latestModelV1?.run_id ||
    latestGeneric?.run_id ||
    latestGeneric?.db?.run_id ||
    latestGeneric?.runs?.[0]?.run_id ||
    "";
  if (!state.step2RunId && latestId) state.step2RunId = latestId;
  const rid = state.step2RunId || latestId;
  let nextStep2 = null;
  if (rid) {
    nextStep2 = await dashboardApi.getModelV1Step2Status(rid).catch(() => null);
  } else {
    nextStep2 = latestModelV1 || null;
  }
  const hasUsableStep2 = Boolean(
    nextStep2 && (nextStep2.run_id || nextStep2.db || (Array.isArray(nextStep2.stages) && nextStep2.stages.length))
  );
  if (hasUsableStep2) {
    state.step2 = nextStep2;
  } else if (prevStep2 && (prevStep2.run_id || prevStep2.db)) {
    // Keep last good payload to avoid Step 2 panel disappearing on transient empty responses.
    state.step2 = prevStep2;
  } else if (latestGeneric) {
    state.step2 = latestGeneric;
  } else {
    state.step2 = { ok: false, run_id: "", stages: [] };
  }
  if (state.selectedModelVersion && state.selectedStep1RunId) {
    state.step2Readiness = await dashboardApi
      .getStep2ReadinessWithStep1(state.selectedModelVersion, state.selectedStep1RunId)
      .catch(() => null);
  } else {
    state.step2Readiness = null;
  }
}

async function loadForGovernance() {
  const [governance, status, header] = await Promise.all([dashboardApi.governanceSummary(), dashboardApi.status(), dashboardApi.getCurrentModelHeader()]);
  state.governance = governance;
  state.status = status;
  state.currentModelHeader = header;
}

async function loadForStep4() {
  const [status, header, simsPayload] = await Promise.all([
    dashboardApi.status().catch(() => null),
    dashboardApi.getCurrentModelHeader().catch(() => null),
    dashboardApi.getStep3V2Simulations({ limit: 200 }).catch(() => ({ simulations: [] })),
  ]);
  if (status) state.status = status;
  state.currentModelHeader = header;
  state.step4LoadError = "";
  state.step4Step1Runs = [];
  state.step4Step2Models = [];
  state.step4Step3Simulations = Array.isArray(simsPayload?.simulations) ? simsPayload.simulations : [];
  const simIdSet = new Set(state.step4Step3Simulations.map((s) => String(s?.simulation_id || "")));
  if (!simIdSet.has(String(state.selectedStep4SimId || ""))) {
    state.selectedStep4SimId = String(state.step4Step3Simulations?.[0]?.simulation_id || "");
  }
  const step3SimIdForStep4 = String(state.selectedStep4SimId || "").trim();
  if (!step3SimIdForStep4) {
    state.step4Status = null;
    return;
  }
  const step4StatusRes = await dashboardApi
    .step4Status({
      step3V2SimId: step3SimIdForStep4,
    })
    .catch((err) => ({ ok: false, error: err?.message || String(err) }));
  state.step4Status = step4StatusRes?.ok ? step4StatusRes : null;
  if (state.step4Status) {
    state.selectedStep4ModelId = String(state.step4Status.resolved_model_id || "");
    state.selectedStep4ModelVersion = String(state.step4Status.resolved_model_version || "");
    state.selectedStep4RunId = String(state.step4Status.source_step1_run_id || "");
  }
  if (!step4StatusRes?.ok) {
    state.step4LoadError = `dissertation_status=${String(step4StatusRes?.error || "failed")}`;
  }
}

async function loadForMetrics() {
  state.metricsLoadError = "";
  const [principleSource, generatedSource, step1RunsPayload, step2StatusPayload, step3ReplayRunsPayload, step3V2SimsPayload] = await Promise.all([
    dashboardApi.getMetricsSource("metrics_principle_review").catch((e) => ({ ok: false, error: e?.message || String(e) })),
    dashboardApi.getMetricsSource("metrics").catch((e) => ({ ok: false, error: e?.message || String(e) })),
    dashboardApi.getModelV1Step1Runs().catch(() => ({ ok: false, runs: [] })),
    dashboardApi.getModelV1Step2Status("").catch(() => ({ ok: false })),
    dashboardApi.getStep3ReplayRuns().catch(() => ({ ok: false, runs: [] })),
    dashboardApi.getStep3V2Simulations({ limit: 200 }).catch(() => ({ ok: false, simulations: [] })),
  ]);
  if (!principleSource?.ok) {
    state.metricsLoadError = `principle_review_load_failed=${String(principleSource?.error || "unknown_error")}`;
  } else if (!generatedSource?.ok) {
    state.metricsLoadError = `metrics_md_load_failed=${String(generatedSource?.error || "unknown_error")}`;
  }
  state.metricsPrincipleReviewMd = String(principleSource?.content || "");
  state.metricsGeneratedMd = String(generatedSource?.content || "");
  state.metricsStep1Runs = Array.isArray(step1RunsPayload?.runs) ? step1RunsPayload.runs : [];
  state.metricsStep3ReplayRuns = Array.isArray(step3ReplayRunsPayload?.runs) ? step3ReplayRunsPayload.runs : [];
  state.metricsStep4Step3Simulations = Array.isArray(step3V2SimsPayload?.simulations) ? step3V2SimsPayload.simulations : [];
  if (!state.step2RunId) {
    state.step2RunId = String(step2StatusPayload?.run_id || step2StatusPayload?.db?.run_id || "").trim();
  }
  const step3SimIds = new Set(state.metricsStep4Step3Simulations.map((s) => String(s?.simulation_id || "")));
  if (!step3SimIds.has(String(state.metricsSelectedStep3SimId || ""))) {
    state.metricsSelectedStep3SimId = String(state.metricsStep4Step3Simulations?.[0]?.simulation_id || "");
  }
  state.metricsStep3Rows = [];
  state.metricsStep3Summary = {};
  state.metricsStep3RowsError = "";
  const step3MetricsSimId = String(state.metricsSelectedStep3SimId || "").trim();
  if (step3MetricsSimId) {
    const step3MetricsPayload = await dashboardApi
      .getStep3Metrics({ simId: step3MetricsSimId })
      .catch((e) => ({ ok: false, error: e?.message || String(e), metrics: [] }));
    if (step3MetricsPayload?.ok) {
      state.metricsStep3Rows = Array.isArray(step3MetricsPayload.metrics) ? step3MetricsPayload.metrics : [];
      state.metricsStep3Summary = step3MetricsPayload.summary && typeof step3MetricsPayload.summary === "object" ? step3MetricsPayload.summary : {};
    } else {
      state.metricsStep3RowsError = String(step3MetricsPayload?.error || "step3_metrics_load_failed");
    }
  }
  const simIds = new Set(state.metricsStep4Step3Simulations.map((s) => String(s?.simulation_id || "")));
  if (!simIds.has(String(state.metricsSelectedStep4SimId || ""))) {
    state.metricsSelectedStep4SimId = String(state.metricsStep4Step3Simulations?.[0]?.simulation_id || "");
  }
}

async function refreshHeaderStepStatusData() {
  const [step1Status, step2Status, modelsPayload, step3V2SimsPayload] = await Promise.all([
    dashboardApi.getStep1Status("").catch(() => ({ ok: false, runs: [] })),
    dashboardApi.getStep2Status("").catch(() => ({ ok: false, runs: [] })),
    dashboardApi.getModelVersions().catch(() => ({ models: [] })),
    dashboardApi.getStep3V2Simulations({ limit: 200 }).catch(() => ({ simulations: [] })),
  ]);
  state.step1HeaderStatus = step1Status;
  state.step2HeaderStatus = step2Status;
  state.models = modelsPayload.models || state.models || [];
  const sims = Array.isArray(step3V2SimsPayload?.simulations) ? step3V2SimsPayload.simulations : [];
  state.step3V2HeaderSim = resolveStep3HeaderSimulation(sims);
  const completion = step3CompletionFromSimulation(state.step3V2HeaderSim);
  state.step3V2HeaderCompletionPct = Number(completion.pct || 0);
  state.step3V2HeaderCompletionText = String(completion.text || "0.0%");
  if (state.step3V2HeaderSim) {
    state.step4HeaderStatus = normalizeStep3StatusLabel(String(state.step3V2HeaderSim.status || "pending"));
  } else {
    state.step4HeaderStatus = "pending";
  }
}

/** Lightweight header refresh: updates only Step 3 completion/status in top Overview card. */
async function refreshHeaderStep3CompletionTiny() {
  const step3V2SimsPayload = await dashboardApi.getStep3V2Simulations({ limit: 200 }).catch(() => ({ simulations: [] }));
  const sims = Array.isArray(step3V2SimsPayload?.simulations) ? step3V2SimsPayload.simulations : [];
  state.step3V2HeaderSim = resolveStep3HeaderSimulation(sims);
  const completion = step3CompletionFromSimulation(state.step3V2HeaderSim);
  state.step3V2HeaderCompletionPct = Number(completion.pct || 0);
  state.step3V2HeaderCompletionText = String(completion.text || "0.0%");
  if (state.step3V2HeaderSim) {
    state.step4HeaderStatus = normalizeStep3StatusLabel(String(state.step3V2HeaderSim.status || "pending"));
  } else {
    state.step4HeaderStatus = "pending";
  }
  renderTopPipelineStatus();
}

async function loadDataForActiveTab() {
  switch (state.activeTabId) {
    case "overview":
      await load();
      break;
    case "step1":
      await loadForStep1();
      break;
    case "step2":
      await loadForStep2();
      break;
    case "step3":
      break;
    case "governance":
      await loadForGovernance();
      break;
    case "metrics":
      await loadForMetrics();
      break;
    default:
      break;
  }
}

function renderModelHeaderCard() {
  const h = state.currentModelHeader || {};
  const src = h.header_source || "";
  let hint = "";
  if (src === "registry_fallback" || src === "registry_fallback_deprecated_only") {
    hint = `<p class="kv hint">model_registry has ${escapeHtml(String(h.registry_model_count ?? 0))} row(s) but none with <code>is_current</code>; values above are a preview of the newest row. Use Step 2 model actions to set current.</p>`;
  } else if (src === "empty" && Number(h.registry_model_count) === 0) {
    hint = `<p class="kv hint">No rows in <code>phase4.model_registry</code> yet; create a model from Step 2.</p>`;
  }
  return `<article class="card">
    <h3>Current Model Header</h3>
    <p><strong>${escapeHtml(String(h.banner || "Current Model: Not selected — choose or create a model version"))}</strong></p>
    <p class="kv">version=${escapeHtml(String(h.current_model_version || "—"))} status=${escapeHtml(String(h.model_status || "not_selected"))} frozen=${escapeHtml(String(h.frozen ?? false))}</p>
    <p class="kv">trained_at=${escapeHtml(String(h.trained_at || "—"))} active_rulepack=${escapeHtml(String(h.active_rulepack_version || "—"))}</p>
    <p class="kv">step2=${escapeHtml(String(h.step2_completion_status || "pending"))} last_run=${escapeHtml(String(h.last_run_status || "—"))}</p>
    ${hint}
  </article>`;
}

function renderOverview() {
  const sec = makeSection("Overview", "Model V1 step orchestrator with true parallel execution and governance constraints.");
  const body = sec.querySelector(".page-body");
  const s1 = latestRun(state.step1);
  const s2 = latestRun(state.step2);
  const activeModel = state.models.find((m) => m.model_version === state.selectedModelVersion) || state.models.find((m) => m.is_current) || null;
  const cards = [
    ["Step 1 status", s1?.status || "not started"],
    ["Step 2 status", s2?.status || "not started"],
    ["Parallel workers (step1)", s1?.effective_workers ?? "—"],
    ["Parallel workers (step2)", s2?.effective_workers ?? "—"],
    ["Leakage blocking", state.governance?.leakage_blocking ? "yes" : "no"],
    ["ENT-01 only training", "enforced"],
  ];
  const stepStatusRows = [
    `<tr><td>Step 1</td><td>${escapeHtml(runLabel(s1) || "—")}</td><td>${statusBadgeHtml(s1?.status || "pending")}</td></tr>`,
    `<tr><td>Step 2</td><td>${escapeHtml(activeModel?.model_name || activeModel?.model_version || state.selectedModelVersion || "—")}</td><td>${statusBadgeHtml(s2?.status || s2?.overall_status || "pending")}</td></tr>`,
  ];
  body.innerHTML = `<div class="grid cards">${renderModelHeaderCard()}${cards.map(([k, v]) => `<article class="card"><h3>${escapeHtml(k)}</h3><div>${escapeHtml(String(v))}</div></article>`).join("")}</div>
  <article class="card">
    <h3>Step Status</h3>
    ${table(["step", "id label", "current status"], stepStatusRows)}
  </article>`;
  return sec;
}

function buildStep1DatasetRows(colCount) {
  const run = latestRun(state.step1);
  const metrics = parseRunMetrics(run);
  let summary = metrics.dataset_summary || {};
  if (!summary || typeof summary !== "object" || Object.keys(summary).length === 0) {
    summary = synthesizeStep1SummaryFromHistory(selectedStep1HistoryRun());
  }
  const rows = [];
  for (const id of STEP1_DATASET_IDS) {
    const up = uploadByDatasetId(id);
    const r = summary[id];
    const files = Array.isArray(r?.file_summary) ? r.file_summary : [];
    const filesOk = files.filter((f) => f.ok).length;
    const filesTotal = files.length;
    const progressDoneRaw = Number(r?.progress_files_completed);
    const progressTotalRaw = Number(r?.progress_files_total);
    const hasProgress = Number.isFinite(progressDoneRaw) && Number.isFinite(progressTotalRaw) && progressTotalRaw > 0;
    const filesCell = hasProgress
      ? `${Math.max(0, Math.floor(progressDoneRaw))}/${Math.max(0, Math.floor(progressTotalRaw))}`
      : filesTotal
        ? `${filesOk}/${filesTotal}`
        : "—";
    const fileRowsOk = files.reduce((sum, f) => sum + Number(f?.normalized_rows || 0), 0);
    const fileRowsFail = files.reduce((sum, f) => sum + Number(f?.failed_rows || 0), 0);
    const strictRow =
      r && r.ok === true && String(r.readiness || "") === "completed"
        ? "yes"
        : r && (r.ok === false || String(r.readiness || "") !== "completed")
          ? "no"
          : "—";
    const trainGate =
      id === "ENT-01"
        ? r?.training_dataset_ok === true
          ? "yes"
          : r?.training_dataset_ok === false
            ? "no"
            : "—"
        : "—";
    const cells = [
      escapeHtml(id),
      escapeHtml(up.name || "—"),
      roleBadge(up.role || ""),
      r == null ? "—" : r.ok ? "yes" : "no",
      escapeHtml(r?.readiness != null ? String(r.readiness) : "—"),
      escapeHtml(strictRow),
      escapeHtml(trainGate),
      escapeHtml(filesCell),
      escapeHtml(String(fileRowsOk || 0)),
      escapeHtml(String(fileRowsFail || 0)),
      escapeHtml(
        r?.categorization_completion === true
          ? "true"
          : r?.categorization_completion === false
            ? "false"
            : "—"
      ),
      escapeHtml(r?.reconciliation?.ok === true ? "passed" : r?.reconciliation?.ok === false ? "failed" : "—"),
      escapeHtml(r?.db_split_counts ? JSON.stringify(r.db_split_counts) : "—"),
      escapeHtml(r?.stage != null ? String(r.stage) : "—"),
      escapeHtml(r?.status != null ? String(r.status) : "—"),
      r?.duration_s != null ? escapeHtml(String(r.duration_s)) : "—",
      r?.returncode != null ? escapeHtml(String(r.returncode)) : "—",
      escapeHtml(r?.worker_id != null ? String(r.worker_id) : "—"),
    ];
    rows.push(`<tr>${cells.map((c) => `<td>${c}</td>`).join("")}</tr>`);
    if (files.length) {
      const fh = ["filename", "ok", "rows_ok", "rows_fail", "detail"].map((h) => `<th>${escapeHtml(h)}</th>`).join("");
      const fr = files
        .map((f) => {
          const det = f.error || (f.normalized_rows != null ? `norm=${f.normalized_rows}` : "");
          return `<tr><td>${escapeHtml(f.filename || "")}</td><td>${f.ok ? "yes" : "no"}</td><td>${escapeHtml(String(f.normalized_rows ?? "—"))}</td><td>${escapeHtml(String(f.failed_rows ?? "—"))}</td><td>${escapeHtml(det)}</td></tr>`;
        })
        .join("");
      rows.push(`<tr class="step1-file-subrow"><td colspan="${colCount}"><div class="table-wrap step1-nested-files"><table><thead><tr>${fh}</tr></thead><tbody>${fr}</tbody></table></div></td></tr>`);
    }
    const fileLevelFail = files.some((f) => f.ok === false);
    const failed =
      r &&
      (r.ok === false ||
        r.status === "failed" ||
        fileLevelFail ||
        (typeof r.returncode === "number" && r.returncode !== 0));
    if (failed) {
      const tid = `step1-err-${id.replace(/[^a-zA-Z0-9_-]/g, "_")}`;
      rows.push(`<tr class="step1-error-subrow"><td colspan="${colCount}">
        <div class="error-log-block">
          <button type="button" class="copy-log-btn" data-copy="${tid}">Copy diagnostics</button>
          <textarea id="${tid}" class="error-log-textarea" data-log-dataset="${id}" readonly rows="8" spellcheck="false"></textarea>
        </div>
      </td></tr>`);
    }
  }
  return rows;
}

function wireStep1Textareas(sec) {
  const run = latestRun(state.step1);
  const metrics = parseRunMetrics(run);
  const summary = metrics.dataset_summary || {};
  sec.querySelectorAll("textarea.error-log-textarea[data-log-dataset]").forEach((el) => {
    const id = el.getAttribute("data-log-dataset");
    const r = summary[id];
    if (r) el.value = formatTaskError(r);
  });
}

function buildStep1Fragments() {
  const run = latestRun(state.step1);
  const m0 = parseRunMetrics(run);
  const historyRun = selectedStep1HistoryRun();
  const resolvedStatus = resolveStep1DisplayStatus(run, m0, historyRun);
  const allStrict = m0.step1_all_datasets_strict_complete === true ? "yes" : m0.step1_all_datasets_strict_complete === false ? "no" : "—";
  const totalBudget = m0?.effective_parallelism?.total_thread_budget ?? "—";
  const procWorkers = m0?.effective_parallelism?.max_file_workers ?? run?.effective_workers ?? "—";
  const ingestWorkers = m0?.effective_parallelism?.postgres_insert_workers ?? "—";
  const telemetry = run
    ? `<p class="kv">run_id=${escapeHtml(runIdWithLabel(run))} workflow_id=${escapeHtml(run.workflow_id || "")} status=${statusBadgeHtml(resolvedStatus)} worker_mode=${escapeHtml(run.worker_mode || "—")} requested=${escapeHtml(String(run.requested_workers ?? "—"))} effective=${escapeHtml(String(run.effective_workers ?? "—"))} combined_budget=${escapeHtml(String(totalBudget))} process_workers=${escapeHtml(String(procWorkers))} ingest_workers=${escapeHtml(String(ingestWorkers))} step1_all_strict=${escapeHtml(allStrict)}</p>`
    : `<p class="kv">No Step 1 run yet. Run Step 1 or open this tab after a run exists to see per-dataset results.</p>`;
  const mRows = Array.isArray(m0.step1_metric_results) ? m0.step1_metric_results : [];
  const metricRows = mRows.map((mr) => {
    const rawVal = mr?.metric_value;
    const numericVal = Number(rawVal);
    const metricVal = Number.isFinite(numericVal) ? numericVal.toFixed(6) : "—";
    return `<tr>
      <td>${escapeHtml(String(mr?.metric_name || "—"))}</td>
      <td>${escapeHtml(String(mr?.status || "—"))}</td>
      <td>${escapeHtml(metricVal)}</td>
      <td>${escapeHtml(String(mr?.numerator ?? "—"))}</td>
      <td>${escapeHtml(String(mr?.denominator ?? "—"))}</td>
    </tr>`;
  });
  const metricsTable = table(
    ["metric", "status", "value (6dp)", "numerator", "denominator"],
    metricRows.length ? metricRows : ["<tr><td colspan='5'>No Step 1 metric rows captured yet.</td></tr>"]
  );
  const step1MetricsGeneration = m0?.step1_metrics_generation && typeof m0.step1_metrics_generation === "object"
    ? m0.step1_metrics_generation
    : {};
  const step1MissingRequirements = Array.isArray(step1MetricsGeneration?.missing_requirements)
    ? step1MetricsGeneration.missing_requirements
    : [];
  const step1Warning = Boolean(step1MetricsGeneration?.warning || step1MissingRequirements.length);
  const step1MissingRows = step1MissingRequirements.map((r) => `<tr>
      <td>${escapeHtml(String(r?.metric_name || "—"))}</td>
      <td>${escapeHtml(String(r?.required_calculation_method || "—"))}</td>
      <td>${escapeHtml(String(r?.principle_status_in_review || "—"))}</td>
      <td>${escapeHtml(String(r?.required_data_note || "manual_data_required"))}</td>
    </tr>`);
  const step1MissingTable = table(
    ["metric", "required_calculation_method", "principle_status_in_review", "required_data_note"],
    step1MissingRows.length ? step1MissingRows : ["<tr><td colspan='4'>No missing requirements.</td></tr>"]
  );
  const step1MetricStatusHtml = `<p class="kv">${step1Warning ? `<span class="badge warn">completed_with_warning</span>` : `<span class="badge ok">completed</span>`}</p>
      <p class="kv">missing_required_metrics=${escapeHtml(String(step1MissingRequirements.length))}</p>`;
  const headers = [
    "dataset_id",
    "name",
    "role",
    "ok",
    "readiness",
    "Step 2 strict row",
    "ENT-01 train_src",
    "files_ok/total",
    "rows_ok",
    "rows_fail",
    "categorization",
    "reconciliation",
    "db_split_counts",
    "stage",
    "status",
    "duration_s",
    "returncode",
    "worker_id",
  ];
  const innerRows = buildStep1DatasetRows(headers.length);
  const datasetTable = table(headers, innerRows.length ? innerRows : [`<tr><td colspan='${headers.length}'>No rows.</td></tr>`]);
  const runRows = (state.step1History || []).map((r) => `<tr ${r.run_id === state.step1RunId ? 'class="row-selected"' : ""}>
    <td>${escapeHtml(runIdWithLabel(r))}</td>
    <td>${escapeHtml(String(r.status || "—"))}</td>
    <td>${escapeHtml(String(r.readiness_status || "—"))}</td>
    <td>${escapeHtml(String(r.started_at_utc || "—"))}</td>
    <td>${escapeHtml(String(r.completed_at_utc || "—"))}</td>
    <td>${escapeHtml(String(r.worker_mode || "—"))}</td>
    <td>${escapeHtml(String(r.effective_workers ?? "—"))}</td>
    <td><button type="button" class="step1-run-select" data-run-id="${escapeHtml(String(r.run_id || ""))}">Show Data</button></td>
  </tr>`);
  const historyTable = table(
    ["run_id label", "status", "readiness", "started_at", "completed_at", "worker_mode", "effective_workers", "action"],
    runRows.length ? runRows : ["<tr><td colspan='8'>No Step 1 runs found.</td></tr>"]
  );
  return { telemetry, datasetTable, historyTable, metricsTable, step1MetricStatusHtml, step1MissingTable };
}

function bindStep1Actions() {
  const btn = document.getElementById("runStep1Btn");
  if (btn) {
    btn.onclick = async () => {
      try {
        const r = await dashboardApi.runStep1({ worker_mode: "process" });
        state.step1RunId = r.run_id || "";
        notice(`Step 1 queued: ${state.step1RunId}`, "ok");
        await loadForStep1();
        await renderActiveTab();
      } catch (e) {
        notice(`Step 1 failed to start: ${e.message}`, "bad");
      }
    };
  }
  const metricsBtn = document.getElementById("rerunStep1MetricsBtn");
  if (metricsBtn) {
    metricsBtn.onclick = async () => {
      const rid = String(state.step1RunId || state.step1History?.[0]?.run_id || "").trim();
      if (!rid) {
        notice("No Step 1 run found for metrics regeneration.", "warn");
        return;
      }
      const prev = metricsBtn.textContent;
      metricsBtn.disabled = true;
      metricsBtn.textContent = "Regenerating...";
      try {
        const r = await dashboardApi.regenerateStep1Metrics({ run_id: rid });
        state.step1RunId = String(r?.run_id || rid);
        notice(`Step 1 metrics regenerated for ${state.step1RunId}.`, "ok");
        await loadForStep1();
        await renderActiveTab();
      } catch (e) {
        notice(`Step 1 metrics regeneration failed: ${e.message}`, "bad");
      } finally {
        metricsBtn.textContent = prev || "Re-run Step 1 Metrics";
        metricsBtn.disabled = false;
      }
    };
  }
  content.querySelectorAll(".step1-run-select").forEach((el) => {
    el.addEventListener("click", async () => {
      const rid = el.getAttribute("data-run-id") || "";
      if (!rid) return;
      state.step1RunId = rid;
      await loadForStep1();
      patchStep1Phases();
    });
  });
}

function renderStep1() {
  const sec = makeSection("Step 1", "Folder-driven CSV ingest with 25k chunking, process-pool normalization, and a combined processing+ingest worker budget.");
  const body = sec.querySelector(".page-body");
  const fragments = buildStep1Fragments();
  body.innerHTML = `<div class="actions">
    <button type="button" id="runStep1Btn">Run - Step 1</button>
    <button type="button" id="rerunStep1MetricsBtn">Re-run Step 1 Metrics</button>
  </div>
    <div id="step1TelemetryRegion" data-phase-region="step1-telemetry">${fragments.telemetry}</div>
    <article class="card" id="step1MetricStatusRegion" data-phase-region="step1-metric-status">
      <h3>Step 1 Metrics Generation Status</h3>
      ${fragments.step1MetricStatusHtml}
    </article>
    <article class="card" id="step1MetricsRegion" data-phase-region="step1-metrics">
      <h3>Step 1 Metrics (Run Scoped)</h3>
      ${fragments.metricsTable}
    </article>
    <article class="card" id="step1MissingRequirementsRegion" data-phase-region="step1-missing-requirements">
      <h3>Step 1 Missing Requirements</h3>
      ${fragments.step1MissingTable}
    </article>
    <div id="step1DatasetsRegion" data-phase-region="step1-datasets">${fragments.datasetTable}</div>
    <article class="card" id="step1HistoryRegion" data-phase-region="step1-history">
      <h3>Historical Runs</h3>
      ${fragments.historyTable}
    </article>`;
  wireStep1Textareas(sec);
  setTimeout(bindStep1Actions, 0);
  return sec;
}

function buildStep2ProcessHtml(s = {}) {
  const fmtTs = (v) => (v ? escapeHtml(String(v)) : "—");
  const fmtDur = (v) => (v == null ? "—" : `${escapeHtml(String(v))}s`);
  const progressBar = (p) => {
    const pct = Math.max(0, Math.min(100, Number(p || 0)));
    return `<div class="progress-wrap"><div class="progress-bar"><span style="width:${pct}%"></span></div><div class="kv">${pct.toFixed(1)}%</div></div>`;
  };
  const renderSubstage = (sub) => {
    const details = [];
    details.push(`<span>${statusBadgeHtml(sub.status)}</span>`);
    details.push(`<span class="kv">started: ${fmtTs(sub.started_at)}</span>`);
    details.push(`<span class="kv">finished: ${fmtTs(sub.finished_at)}</span>`);
    details.push(`<span class="kv">duration: ${fmtDur(sub.duration_s)}</span>`);
    if (sub.worker_count != null) details.push(`<span class="kv">workers: ${escapeHtml(String(sub.worker_count))}</span>`);
    if (sub.progress_percent != null) details.push(`<span class="kv">progress: ${escapeHtml(String(sub.progress_percent))}%</span>`);
    if (sub.row_count != null) details.push(`<span class="kv">rows: ${escapeHtml(String(sub.row_count))}</span>`);
    if (sub.source_row_count != null) details.push(`<span class="kv">source_rows: ${escapeHtml(String(sub.source_row_count))}</span>`);
    if (sub.prediction_count != null) details.push(`<span class="kv">predictions: ${escapeHtml(String(sub.prediction_count))}</span>`);
    if (sub.sampling_applied) details.push(`<span class="kv">sampled_eval=true</span>`);
    if (sub.note) details.push(`<span class="kv">${escapeHtml(String(sub.note))}</span>`);
    if (sub.error) details.push(`<span class="kv error">${escapeHtml(String(sub.error))}</span>`);
    const links = [];
    if (sub.artifact_url) links.push(`<a class="ghost-link" href="${escapeHtml(String(sub.artifact_url))}" target="_blank" rel="noopener">artifact</a>`);
    if (sub.audit_ref) links.push(`<a class="ghost-link" href="${escapeHtml(String(sub.audit_ref))}" target="_blank" rel="noopener">audit/log: ${escapeHtml(String(sub.audit_ref))}</a>`);
    return `<li class="process-substage">
      <div class="process-subhead"><strong>${escapeHtml(sub.label || sub.id || "substage")}</strong> ${statusBadgeHtml(sub.status)}</div>
      <div class="process-meta">${details.join("")}</div>
      ${links.length ? `<div class="process-links">${links.join("")}</div>` : ""}
    </li>`;
  };
  const renderStage = (stage, idx) => {
    const subrows = (stage.substages || []).map(renderSubstage).join("");
    return `<details class="process-stage" ${idx < 2 ? "open" : ""}>
      <summary>
        <span><strong>${escapeHtml(stage.label || stage.id || "stage")}</strong></span>
        ${statusBadgeHtml(stage.status)}
        <span class="kv">progress ${escapeHtml(String(stage.progress_percent ?? 0))}%</span>
      </summary>
      <div class="process-stage-body">
        <div class="process-meta">
          <span class="kv">started: ${fmtTs(stage.started_at)}</span>
          <span class="kv">finished: ${fmtTs(stage.finished_at)}</span>
          <span class="kv">duration: ${fmtDur(stage.duration_s)}</span>
          <span class="kv">workers: ${stage.worker_count != null ? escapeHtml(String(stage.worker_count)) : "—"}</span>
        </div>
        ${(stage.artifact_url || stage.stage_log_ref) ? `<div class="process-links">
          ${stage.artifact_url ? `<a class="ghost-link" href="${escapeHtml(String(stage.artifact_url))}" target="_blank" rel="noopener">artifact</a>` : ""}
          ${stage.stage_log_ref ? `<a class="ghost-link" href="${escapeHtml(String(stage.stage_log_ref))}" target="_blank" rel="noopener">audit/log: ${escapeHtml(String(stage.stage_log_ref))}</a>` : ""}
        </div>` : ""}
        <ul class="process-substages">${subrows || "<li class='kv'>No substages available.</li>"}</ul>
      </div>
    </details>`;
  };
  const cpuGov = s?.cpu_governor || {};
  const cpuTargetPct = Number(cpuGov.target_utilization || 0) * 100;
  const cpuBandPct = Number(cpuGov.band_pct || 0) * 100;
  const metricRowsRaw = (
    Array.isArray(s?.step2_metric_results) ? s.step2_metric_results : []
  ).filter((r) => String(r?.metric_name || "") !== "pareto_rank");
  const metricSummary = s?.step2_metric_results_summary || {};
  const metricRows = metricRowsRaw.map((r) => {
    const numeratorNum = Number(r?.numerator);
    const denominatorNum = Number(r?.denominator);
    let valueNum = Number(r?.metric_value);
    if (
      !Number.isFinite(valueNum) &&
      ["accuracy", "false_positive_rate", "false_negative_rate"].includes(String(r?.metric_name || "")) &&
      Number.isFinite(numeratorNum) &&
      Number.isFinite(denominatorNum) &&
      denominatorNum > 0
    ) {
      valueNum = numeratorNum / denominatorNum;
    }
    const value = Number.isFinite(valueNum) ? valueNum.toFixed(6) : "—";
    const unit = String(r?.unit || "");
    const numerator = Number.isFinite(numeratorNum) ? String(numeratorNum) : "—";
    const denominator = Number.isFinite(denominatorNum) ? String(denominatorNum) : "—";
    return `<tr>
      <td>${escapeHtml(String(r?.metric_name || "—"))}</td>
      <td>${statusBadgeHtml(String(r?.status || "not_collected"))}</td>
      <td>${escapeHtml(value)}</td>
      <td>${escapeHtml(unit || "—")}</td>
      <td>${escapeHtml(numerator)}</td>
      <td>${escapeHtml(denominator)}</td>
    </tr>`;
  });
  const metricTable = table(
    ["metric", "status", "value", "unit", "numerator", "denominator"],
    metricRows.length ? metricRows : ["<tr><td colspan='6'>No Step 2 metric rows found for this run.</td></tr>"]
  );
  const step2MetricsGeneration = s?.step2_metrics_generation || {};
  const step2MissingRequirements = Array.isArray(s?.step2_missing_requirements) ? s.step2_missing_requirements : [];
  const step2MetricsWarning = Boolean(s?.step2_metrics_warning || step2MetricsGeneration?.warning);
  const metricRowsError = String(s?.step2_metric_results_error || "").trim();
  const step2MissingRows = step2MissingRequirements.map((r) => `<tr>
      <td>${escapeHtml(String(r?.metric_name || "—"))}</td>
      <td>${escapeHtml(String(r?.required_calculation_method || "—"))}</td>
      <td>${escapeHtml(String(r?.principle_status_in_review || "—"))}</td>
      <td>${escapeHtml(String(r?.required_data_note || "manual_data_required"))}</td>
    </tr>`);
  const step2MissingTable = table(
    ["metric", "required_calculation_method", "principle_status_in_review", "required_data_note"],
    step2MissingRows.length ? step2MissingRows : ["<tr><td colspan='4'>No missing requirements.</td></tr>"]
  );
  if (!s?.run_id) return `<p class="kv">No Step 2 run yet.</p>`;
  return `<div class="grid cards">
      <article class="card"><h3>Current phase</h3><div>${escapeHtml(String(s.current_phase || "—"))}</div><p class="kv">overall: ${statusBadgeHtml(s.overall_status)}</p></article>
      <article class="card"><h3>Workers</h3><div>active=${escapeHtml(String(s.active_workers ?? "—"))} max=${escapeHtml(String(s.max_workers ?? "—"))}</div></article>
      <article class="card"><h3>Host CPU governor</h3><div>target=${cpuTargetPct > 0 ? `${cpuTargetPct.toFixed(1)}%` : "—"} ± ${cpuBandPct > 0 ? `${cpuBandPct.toFixed(1)}%` : "—"}</div><p class="kv">cap=${escapeHtml(String(cpuGov.thread_budget_max ?? "—"))} target_threads=${escapeHtml(String(cpuGov.thread_target ?? "—"))} reserved=${escapeHtml(String(cpuGov.reserved_threads ?? "—"))}</p></article>
      <article class="card"><h3>Model readiness</h3><div>${s.model_v1_ready ? `<span class="badge ok">Model V1 Ready</span>` : `<span class="badge warn">Not Ready</span>`}</div></article>
      <article class="card"><h3>Training lock</h3><div class="kv">${escapeHtml(String(s.training_source_lock || "Training source: ENT-01 train only"))}</div><div class="kv">ENT-02/IOT-02 are testing/support only</div></article>
      <article class="card"><h3>Metrics column</h3><div class="kv">rows=${escapeHtml(String(metricSummary.total ?? metricRowsRaw.length ?? 0))} collected=${escapeHtml(String(metricSummary.collected ?? 0))} proxy=${escapeHtml(String(metricSummary.proxy ?? 0))} missing=${escapeHtml(String(metricSummary.missing ?? 0))}</div></article>
    </div>
    <article class="card">
      <h3>Step 2 Metrics Generation Status</h3>
      <p class="kv">${step2MetricsWarning ? `<span class="badge warn">completed_with_warning</span>` : `<span class="badge ok">completed</span>`}</p>
      <p class="kv">missing_required_metrics=${escapeHtml(String(step2MissingRequirements.length))}</p>
    </article>
    <article class="card process-panel">
      <h3>Step 2 Process Completion Status</h3>
      ${progressBar(s.overall_progress_percent)}
      <p class="kv">run_id=${escapeHtml(runIdWithLabel(s))} workflow_id=${escapeHtml(String(s.workflow_id || "—"))}</p>
      <div class="process-tree">
        ${(s.stages || []).map(renderStage).join("") || "<p class='kv'>No stage data yet.</p>"}
      </div>
    </article>
    <article class="card">
      <h3>Step 2 Metrics (Postgres)</h3>
      ${metricRowsError ? `<p class="kv error">metrics_query_error=${escapeHtml(metricRowsError)}</p>` : ""}
      ${metricTable}
    </article>
    <article class="card">
      <h3>Step 2 Missing Requirements</h3>
      ${step2MissingTable}
    </article>
    <details><summary>Raw Step 2 status payload</summary><pre class="code">${escapeHtml(JSON.stringify(s, null, 2))}</pre></details>`;
}

function filteredStep2Models(models) {
  const q = String(state.step2VersionsFilterQ || "").trim().toLowerCase();
  const statusFilter = String(state.step2VersionsFilterStatus || "all").toLowerCase();
  const sorted = (models || []).slice().sort((a, b) => {
    const at = String(a?.created_at || "");
    const bt = String(b?.created_at || "");
    if (at === bt) return String(b?.model_version || "").localeCompare(String(a?.model_version || ""));
    return bt.localeCompare(at);
  });
  return sorted.filter((m) => {
    if (statusFilter !== "all" && String(m?.status || "").toLowerCase() !== statusFilter) return false;
    if (!q) return true;
    const hay = [m?.model_version, m?.model_name, m?.model_id].map((v) => String(v || "").toLowerCase()).join(" ");
    return hay.includes(q);
  });
}

function buildStep2VersionsHtml(models) {
  const statuses = ["all", ...Array.from(new Set((models || []).map((m) => String(m.status || "").toLowerCase()).filter(Boolean))).sort()];
  const filtered = filteredStep2Models(models);
  const rows = filtered.map((m) => `<tr ${m.model_version === state.selectedModelVersion ? 'class="row-selected"' : ""}>
    <td>${escapeHtml(String(m.model_version || "—"))}</td>
    <td>${escapeHtml(String(m.status || "—"))}</td>
    <td>${escapeHtml(String(m.created_at || "—"))}</td>
    <td>${escapeHtml(String(m.trained_at || "—"))}</td>
    <td><button type="button" class="version-show-data" data-mv="${escapeHtml(String(m.model_version || ""))}">Show Data</button></td>
  </tr>`);
  return `<article class="card" id="step2VersionsRegion" data-phase-region="step2-versions">
    <h3>Versions</h3>
    <div class="actions">
      <input id="step2VersionsFilterQ" type="text" placeholder="filter by version/name/id" value="${escapeHtml(state.step2VersionsFilterQ || "")}" />
      <select id="step2VersionsFilterStatus">
        ${statuses.map((s) => `<option value="${escapeHtml(s)}" ${s === String(state.step2VersionsFilterStatus || "all").toLowerCase() ? "selected" : ""}>${escapeHtml(s)}</option>`).join("")}
      </select>
    </div>
    ${table(["model_version", "status", "created_at", "trained_at", "action"], rows.length ? rows : ["<tr><td colspan='5'>No model versions found.</td></tr>"])}
  </article>`;
}

function buildStep2VersionDetailHtml() {
  const detail = state.step2SelectedDetail || null;
  if (!detail || !detail.model) {
    return `<article class="card" id="step2VersionDetailRegion" data-phase-region="step2-version-detail"><h3>Version Data</h3><p class="kv">Select a version and click Show Data.</p></article>`;
  }
  return `<article class="card" id="step2VersionDetailRegion" data-phase-region="step2-version-detail"><h3>Version Data</h3>
    <p class="kv">model_version=${escapeHtml(String(detail.model.model_version || "—"))} status=${escapeHtml(String(detail.model.status || "—"))}</p>
    <pre class="code">${escapeHtml(JSON.stringify(detail.model, null, 2))}</pre>
  </article>`;
}

function renderStep2() {
  const sec = makeSection("Step 2", "Phased pipeline: training → freeze → verifier → testing → SHAP → rules → publish → finalize.");
  const body = sec.querySelector(".page-body");
  const s = state.step2 || {};
  const models = state.models || [];
  const step1Runs = state.step1Runs || [];
  const readiness = state.step2Readiness || null;
  const activeModel = models.find((m) => m.model_version === state.selectedModelVersion) || models.find((m) => m.is_current) || null;
  if (!state.selectedModelVersion && activeModel?.model_version) state.selectedModelVersion = activeModel.model_version;
  if (!state.selectedModelLabelManual && !state.selectedModelLabel && activeModel?.model_name) state.selectedModelLabel = String(activeModel.model_name);
  const effectiveModelLabel = String(state.selectedModelLabel || activeModel?.model_name || "").trim();

  const runEnabled = Boolean(state.selectedStep1RunId && state.selectedModelVersion && effectiveModelLabel && readiness?.ready);
  const createEnabled = Boolean(state.selectedStep1RunId && String(state.selectedModelLabel || "").trim());
  const telemetry = buildStep2ProcessHtml(s);
  const versionsHtml = buildStep2VersionsHtml(models);
  const versionDetailHtml = buildStep2VersionDetailHtml();
  const controlStatusHtml = state.step2ControlStatus
    ? `<div class="step2-inline-status ${escapeHtml(String(state.step2ControlStatus.type || ""))}">${escapeHtml(String(state.step2ControlStatus.text || ""))}</div>`
    : "";
  body.innerHTML = `<article class="control-card">
    <h3>Controls</h3>
    <div class="table-wrap">
      <table class="control-table">
        <tbody>
          <tr>
            <td class="control-label">Model Label</td>
            <td>
              <input id="step2ModelLabelInput" type="text" value="${escapeHtml(String(state.selectedModelLabel || ""))}" placeholder="Enter model label" />
            </td>
            <td class="control-btn-col">
              <button type="button" id="step2CreateModelBtn" ${createEnabled ? "" : "disabled"}>Create Model</button>
            </td>
          </tr>
          <tr>
            <td class="control-label">Source Step 1 Run Id</td>
            <td>
              <select id="step2Step1RunSelect">
                <option value="">-- select Step 1 run --</option>
                ${step1Runs
                  .map((r) => `<option value="${escapeHtml(r.run_id)}" ${r.run_id === state.selectedStep1RunId ? "selected" : ""}>${escapeHtml(runIdWithLabel(r))} (${escapeHtml(r.status || "unknown")}, readiness=${escapeHtml(r.readiness_status || "blocked")})</option>`)
                  .join("")}
              </select>
            </td>
            <td class="control-btn-col">
              <button type="button" id="runStep2Btn" ${runEnabled ? "" : "disabled"}>Run Step 2</button>
            </td>
          </tr>
          <tr>
            <td class="control-label">Metrics</td>
            <td class="kv">Recompute and ingest Step 2 metrics for the selected/latest Step 2 run.</td>
            <td class="control-btn-col">
              <button type="button" id="rerunStep2MetricsBtn">Re-run Step 2 Metrics</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <p class="kv">Selected model: ${escapeHtml(String(state.selectedModelVersion || "—"))} | label: ${escapeHtml(effectiveModelLabel || "—")}</p>
    ${controlStatusHtml}
  </article>
  ${versionsHtml}
  ${versionDetailHtml}
  <div id="step2ProcessRegion" data-phase-region="step2-process">${telemetry}</div>`;
  setTimeout(() => {
    document.getElementById("step2ModelLabelInput")?.addEventListener("input", async (e) => {
      state.selectedModelLabel = String(e.target.value || "").trim();
      state.step2ControlEditing = true;
      state.selectedModelLabelManual = true;
      state.step2ControlStatus = null;
      const createBtn = document.getElementById("step2CreateModelBtn");
      if (createBtn) {
        createBtn.disabled = !(state.selectedStep1RunId && String(state.selectedModelLabel || "").trim());
      }
      const runBtn = document.getElementById("runStep2Btn");
      if (runBtn) {
        const canRun = Boolean(state.selectedStep1RunId && state.selectedModelVersion && String(state.selectedModelLabel || "").trim() && state.step2Readiness?.ready);
        runBtn.disabled = !canRun;
      }
    });
    document.getElementById("step2Step1RunSelect")?.addEventListener("change", async (e) => {
      state.selectedStep1RunId = e.target.value || "";
      if (state.selectedModelVersion && state.selectedStep1RunId) {
        state.step2Readiness = await dashboardApi
          .getStep2ReadinessWithStep1(state.selectedModelVersion, state.selectedStep1RunId)
          .catch(() => null);
      } else {
        state.step2Readiness = null;
      }
      await renderActiveTab();
    });
    document.getElementById("step2CreateModelBtn")?.addEventListener("click", async () => {
      try {
        state.step2ControlEditing = false;
        if (!state.selectedStep1RunId) throw new Error("Select a source Step 1 run_id first.");
        if (!String(state.selectedModelLabel || "").trim()) throw new Error("Model Label is required.");
        const r = await dashboardApi.prepareStep2Run({
          source_step1_run_id: state.selectedStep1RunId,
          model_execution_mode: "create_new",
          new_model_name: String(state.selectedModelLabel || "").trim(),
        });
        if (r?.model_version) {
          state.selectedModelVersion = r.model_version;
          state.selectedModelLabel = String(state.selectedModelLabel || "").trim();
          await dashboardApi.setCurrentModelVersion(r.model_version).catch(() => null);
        }
        state.step2ControlStatus = { type: "ok", text: `Success: model created (${r.model_version || "unknown"}).` };
        await loadForStep2();
        notice(`Model version ready: ${r.model_version || "(unknown)"}`, "ok");
        await renderActiveTab();
      } catch (e) {
        state.step2ControlEditing = false;
        state.step2ControlStatus = { type: "bad", text: `Create model failed: ${e.message}` };
        notice(`Create model version failed: ${e.message}`, "bad");
        await renderActiveTab();
      }
    });
    document.getElementById("runStep2Btn")?.addEventListener("click", async () => {
      try {
        state.step2ControlEditing = false;
        if (!state.selectedModelVersion) throw new Error("Select or create a model first.");
        if (!effectiveModelLabel) throw new Error("Model Label is required.");
        const s1 = latestRun(state.step1);
        const m1 = parseRunMetrics(s1);
        const modelVersionForRun = state.selectedModelVersion;
        const payload = { worker_mode: "process", model_version: modelVersionForRun, execution_mode: "continue_existing" };
        payload.source_step1_run_id = state.selectedStep1RunId;
        if (s1?.run_id && m1.step1_all_datasets_strict_complete === true) {
          payload.prerequisite_step1_run_id = s1.run_id;
        }
        const r = await dashboardApi.runStep2(payload);
        state.step2RunId = r.run_id || "";
        state.step2ControlStatus = { type: "ok", text: `Success: Step 2 queued (${state.step2RunId || "unknown"}).` };
        notice(`Step 2 queued: ${state.step2RunId}`, "ok");
        await loadForStep2();
        await renderActiveTab();
      } catch (e) {
        state.step2ControlEditing = false;
        state.step2ControlStatus = { type: "bad", text: `Run Step 2 failed: ${e.message}` };
        notice(`Step 2 failed to start: ${e.message}`, "bad");
        await renderActiveTab();
      }
    });
    document.getElementById("rerunStep2MetricsBtn")?.addEventListener("click", async (e) => {
      const btn = e.currentTarget;
      const rid = String(state.step2RunId || state.step2?.run_id || latestRun(state.step2)?.run_id || "").trim();
      if (!rid) {
        notice("No Step 2 run found for metrics regeneration.", "warn");
        return;
      }
      const prev = btn.textContent;
      btn.disabled = true;
      btn.textContent = "Regenerating...";
      try {
        const r = await dashboardApi.regenerateStep2Metrics({ run_id: rid });
        state.step2RunId = String(r?.run_id || rid);
        state.step2ControlStatus = { type: "ok", text: `Step 2 metrics regenerated (${state.step2RunId}).` };
        notice(`Step 2 metrics regenerated for ${state.step2RunId}.`, "ok");
        await loadForStep2();
        await renderActiveTab();
      } catch (err) {
        state.step2ControlStatus = { type: "bad", text: `Step 2 metrics regeneration failed: ${err.message}` };
        notice(`Step 2 metrics regeneration failed: ${err.message}`, "bad");
        await renderActiveTab();
      } finally {
        btn.textContent = prev || "Re-run Step 2 Metrics";
        btn.disabled = false;
      }
    });
    document.getElementById("step2VersionsFilterQ")?.addEventListener("input", (e) => {
      state.step2VersionsFilterQ = String(e.target.value || "");
      patchStep2VersionsRegion();
    });
    document.getElementById("step2VersionsFilterStatus")?.addEventListener("change", (e) => {
      state.step2VersionsFilterStatus = String(e.target.value || "all");
      patchStep2VersionsRegion();
    });
    sec.querySelectorAll(".version-show-data").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const mv = btn.getAttribute("data-mv") || "";
        if (!mv) return;
        state.selectedModelVersion = mv;
        state.step2SelectedDetailVersion = mv;
        state.step2SelectedDetail = await dashboardApi.getModelVersion(mv).catch(() => null);
        const row = (state.models || []).find((m) => m.model_version === mv);
        if (!state.selectedModelLabelManual && row?.model_name) state.selectedModelLabel = String(row.model_name);
        patchStep2VersionsRegion();
        patchStep2VersionDetailRegion();
      });
    });
  }, 0);
  return sec;
}

async function renderGovernanceAudit() {
  const sec = makeSection("Governance/Audit", "Leakage controls and full run audit trails.");
  const body = sec.querySelector(".page-body");
  const audit = await dashboardApi.getAudit().catch(() => ({ audit: [] }));
  const rows = (audit.audit || [])
    .slice(0, 80)
    .map((e) => `<tr><td>${escapeHtml(e.timestamp_utc || "")}</td><td>${escapeHtml(e.event_type || "")}</td><td>${escapeHtml(e.dataset_id || "")}</td><td>${escapeHtml(e.experiment_id || "")}</td><td>${escapeHtml(e.model_version || "")}</td></tr>`);
  body.innerHTML = `<article class="card"><h3>Leakage blocking</h3><p class="kv">${state.governance?.leakage_blocking ? "BLOCKED" : "CLEAR/REVIEW"}</p></article>
    ${table(["time", "event_type", "dataset_id", "experiment_id", "model_version"], rows.length ? rows : ["<tr><td colspan='5'>No audit events.</td></tr>"])}`;
  return sec;
}

async function renderModels() {
  const sec = makeSection("Models", "All Model V1 versions on the system with lifecycle and actions.");
  const body = sec.querySelector(".page-body");
  const modelsPayload = await dashboardApi.getModelVersions().catch(() => ({ models: [] }));
  const models = modelsPayload.models || [];
  const rows = models.map((m) => `<tr>
    <td>${escapeHtml(m.model_version)}</td>
    <td>${escapeHtml(m.model_name || "—")}</td>
    <td>${escapeHtml(m.model_type || "—")}</td>
    <td>${escapeHtml(m.status || "pending")}</td>
    <td>${escapeHtml(m.dataset_source || "—")}</td>
    <td>${escapeHtml(m.training_split || "—")}</td>
    <td>${escapeHtml(m.created_at || "—")}</td>
    <td>${escapeHtml(m.trained_at || "—")}</td>
    <td>${escapeHtml(m.frozen_at || "—")}</td>
    <td>${escapeHtml(m.artifact_root || "—")}</td>
    <td>${escapeHtml(m.rulepack_status || "—")}</td>
    <td>${escapeHtml(m.shap_status || "—")}</td>
    <td>${escapeHtml(m.last_error || "—")}</td>
    <td>${escapeHtml(String(m.is_current || false))}</td>
    <td>
      <button type="button" class="model-act" data-act="view" data-mv="${escapeHtml(m.model_version)}">View</button>
      <button type="button" class="model-act" data-act="set-current" data-mv="${escapeHtml(m.model_version)}">Set Current</button>
      <button type="button" class="model-act" data-act="continue" data-mv="${escapeHtml(m.model_version)}">Continue Step2</button>
      <button type="button" class="model-act" data-act="retry" data-mv="${escapeHtml(m.model_version)}">Retry</button>
      <button type="button" class="model-act" data-act="clone" data-mv="${escapeHtml(m.model_version)}">Clone</button>
      <button type="button" class="model-act" data-act="deprecate" data-mv="${escapeHtml(m.model_version)}">Deprecate</button>
    </td>
  </tr>`);
  body.innerHTML = `<div class="actions"><button type="button" id="modelsCreateBtn">Create New Model Version</button></div>
    ${table(["model_version","model_name","model_type","status","dataset_source","training_split","created_at","trained_at","frozen_at","artifact_path","rulepack_status","shap_status","last_error","active","actions"], rows.length ? rows : ["<tr><td colspan='15'>No models found.</td></tr>"])}
    <details><summary>Raw models payload</summary><pre class="code">${escapeHtml(JSON.stringify(modelsPayload, null, 2))}</pre></details>`;
  setTimeout(() => {
    document.getElementById("modelsCreateBtn")?.addEventListener("click", async () => {
      try {
        const r = await dashboardApi.createModelVersion({});
        if (r.model_version) await dashboardApi.setCurrentModelVersion(r.model_version);
        state.selectedModelVersion = r.model_version || "";
        notice(`Model created: ${r.model_version}`, "ok");
        await renderActiveTab();
      } catch (e) {
        notice(`Model create failed: ${e.message}`, "bad");
      }
    });
    sec.querySelectorAll(".model-act").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const mv = btn.getAttribute("data-mv");
        const act = btn.getAttribute("data-act");
        try {
          if (act === "set-current") await dashboardApi.setCurrentModelVersion(mv);
          else if (act === "clone") await dashboardApi.cloneModelVersion(mv, {});
          else if (act === "deprecate") await dashboardApi.deprecateModelVersion(mv);
          else if (act === "continue" || act === "retry") {
            state.selectedModelVersion = mv;
            state.activeTabId = "step2";
            setupTabs();
            await loadForStep2();
            await renderActiveTab();
            return;
          } else if (act === "view") {
            const detail = await dashboardApi.getModelVersion(mv);
            notice(`Model ${mv}: ${detail?.model?.status || "unknown"}`, "ok");
          }
          await renderActiveTab();
        } catch (e) {
          notice(`Model action failed: ${e.message}`, "bad");
        }
      });
    });
  }, 0);
  return sec;
}

async function renderStorageArtifacts() {
  const sec = makeSection("Storage/Artifacts", "Model V1 run artifacts, metrics, SHAP artifacts, and rulepack registry.");
  const body = sec.querySelector(".page-body");
  const [arts, mets, rules] = await Promise.all([dashboardApi.getArtifacts(), dashboardApi.getMetrics(), dashboardApi.getRulepacks()]);
  body.innerHTML = `<h3>SHAP Artifacts</h3><pre class="code">${escapeHtml(JSON.stringify(arts, null, 2))}</pre>
    <h3>Metrics</h3><pre class="code">${escapeHtml(JSON.stringify(mets, null, 2))}</pre>
    <h3>Rulepacks</h3><pre class="code">${escapeHtml(JSON.stringify(rules, null, 2))}</pre>`;
  return sec;
}

function splitMarkdownRow(rawLine) {
  return String(rawLine || "")
    .trim()
    .replace(/^\|/, "")
    .replace(/\|$/, "")
    .split("|")
    .map((c) => c.trim());
}

function parseMarkdownTablesByStep(mdText) {
  const out = { step1: [], step2: [], step3: [], step4: [] };
  const lines = String(mdText || "").split(/\r?\n/);
  let currentStep = "";
  for (let i = 0; i < lines.length; i += 1) {
    const line = String(lines[i] || "").trim();
    const stepMatch = line.match(/^#{1,6}\s*Step\s*([1-4])\b/i);
    if (stepMatch) {
      currentStep = `step${stepMatch[1]}`;
      continue;
    }
    if (!currentStep) continue;
    const nextLine = String(lines[i + 1] || "").trim();
    if (!line.startsWith("|") || !nextLine.startsWith("|")) continue;
    if (!/^(\|\s*[:\- ]+\s*)+\|?$/.test(nextLine)) continue;
    const headers = splitMarkdownRow(line);
    const rows = [];
    i += 2;
    while (i < lines.length) {
      const rowLine = String(lines[i] || "").trim();
      if (!rowLine.startsWith("|")) break;
      const cells = splitMarkdownRow(rowLine);
      if (cells.length) rows.push(cells);
      i += 1;
    }
    i -= 1;
    out[currentStep].push({ headers, rows });
  }
  return out;
}

function mapMetricRowsFromPrincipleReview(mdText) {
  const tablesByStep = parseMarkdownTablesByStep(mdText);
  const out = { step1: new Map(), step2: new Map(), step3: new Map(), step4: new Map() };
  for (const stepKey of Object.keys(out)) {
    for (const tbl of tablesByStep[stepKey] || []) {
      const headers = (tbl.headers || []).map((h) => String(h || "").trim().toLowerCase());
      const metricIdx = headers.indexOf("metric");
      if (metricIdx < 0) continue;
      const statusIdx = headers.indexOf("status");
      const principleIdx = headers.indexOf("required principle");
      const expectationIdx = headers.indexOf("principle expectation");
      for (const row of tbl.rows || []) {
        const metricName = String(row[metricIdx] || "").trim().replace(/^`|`$/g, "");
        if (!metricName || metricName === "---" || metricName.toLowerCase() === "none") continue;
        out[stepKey].set(metricName.toLowerCase(), {
          metric_name: metricName,
          principle_status: statusIdx >= 0 ? String(row[statusIdx] || "").trim() : "",
          required_principle: principleIdx >= 0 ? String(row[principleIdx] || "").trim() : "",
          principle_expectation: expectationIdx >= 0 ? String(row[expectationIdx] || "").trim() : "",
        });
      }
    }
  }
  return out;
}

function mapMetricRowsFromGeneratedMetrics(mdText) {
  const tablesByStep = parseMarkdownTablesByStep(mdText);
  const out = { step1: new Map(), step2: new Map(), step3: new Map(), step4: new Map() };
  for (const stepKey of Object.keys(out)) {
    for (const tbl of tablesByStep[stepKey] || []) {
      const headers = (tbl.headers || []).map((h) => String(h || "").trim().toLowerCase());
      const metricIdx = headers.indexOf("metric") >= 0 ? headers.indexOf("metric") : headers.indexOf("metric_name");
      if (metricIdx < 0) continue;
      const valueIdx = headers.indexOf("metric_value") >= 0 ? headers.indexOf("metric_value") : headers.indexOf("value");
      const statusIdx = headers.indexOf("status");
      const numeratorIdx = headers.indexOf("numerator");
      const denominatorIdx = headers.indexOf("denominator");
      const methodIdx = headers.indexOf("required_calculation_method");
      for (const row of tbl.rows || []) {
        const metricName = String(row[metricIdx] || "").trim().replace(/^`|`$/g, "");
        if (!metricName || metricName === "---" || metricName.toLowerCase() === "none") continue;
        out[stepKey].set(metricName.toLowerCase(), {
          metric_name: metricName,
          status: statusIdx >= 0 ? String(row[statusIdx] || "").trim() : "",
          metric_value: valueIdx >= 0 ? String(row[valueIdx] || "").trim() : "",
          numerator: numeratorIdx >= 0 ? String(row[numeratorIdx] || "").trim() : "",
          denominator: denominatorIdx >= 0 ? String(row[denominatorIdx] || "").trim() : "",
          required_calculation_method: methodIdx >= 0 ? String(row[methodIdx] || "").trim() : "",
        });
      }
    }
  }
  // Ownership shift: show model_version_traceability under Step 3 even if legacy metrics.md still emits it under Step 4.
  const mvTrace = out.step4.get("model_version_traceability");
  if (mvTrace && !out.step3.has("model_version_traceability")) {
    out.step3.set("model_version_traceability", mvTrace);
  }
  out.step4.delete("model_version_traceability");
  return out;
}

function metricStatusBadge(statusRaw) {
  const s = String(statusRaw || "").trim().toLowerCase();
  if (!s) return `<span class="badge warn">not_found</span>`;
  if (["measured", "collected_as_principle", "completed", "ok"].includes(s)) return `<span class="badge ok">${escapeHtml(s)}</span>`;
  if (["missing", "not_collected", "failed"].includes(s)) return `<span class="badge bad">${escapeHtml(s)}</span>`;
  if (["incorrect_principle", "pending", "partial", "not_applicable"].includes(s)) return `<span class="badge warn">${escapeHtml(s)}</span>`;
  return `<span class="badge model">${escapeHtml(s)}</span>`;
}

function buildMetricsStepSection(stepNum, requiredMap, generatedMap) {
  const stepKey = `step${stepNum}`;
  const requiredRows = Array.from((requiredMap[stepKey] || new Map()).values());
  const rows = requiredRows.map((req) => {
    const generated = (generatedMap[stepKey] || new Map()).get(String(req.metric_name || "").toLowerCase()) || null;
    return `<tr>
      <td>${escapeHtml(String(req.metric_name || ""))}</td>
      <td>${metricStatusBadge(req.principle_status || "missing")}</td>
      <td>${escapeHtml(String(req.required_principle || req.principle_expectation || "—"))}</td>
      <td>${generated ? metricStatusBadge(generated.status || "measured") : `<span class="badge warn">not_in_metrics_md</span>`}</td>
      <td>${escapeHtml(generated?.metric_value || "—")}</td>
      <td>${escapeHtml(generated?.numerator || "—")}</td>
      <td>${escapeHtml(generated?.denominator || "—")}</td>
      <td>${escapeHtml(generated?.required_calculation_method || "—")}</td>
    </tr>`;
  });
  return {
    requiredCount: requiredRows.length,
    measuredCount: rows.filter((r) => r.includes("badge ok")).length,
    tableHtml: table(
      ["metric", "principle_status", "required_principle", "generated_status", "generated_value", "numerator", "denominator", "calculation_method"],
      rows.length ? rows : ["<tr><td colspan='8'>No required metrics found for this step.</td></tr>"]
    ),
  };
}

function bindMetricsActions() {
  document.getElementById("rerunStep1MetricsTabBtn")?.addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    const rid = String(state.step1RunId || state.metricsStep1Runs?.[0]?.run_id || "").trim();
    if (!rid) {
      notice("No Step 1 run found for metrics regeneration.", "warn");
      return;
    }
    const prev = btn.textContent;
    btn.disabled = true;
    btn.textContent = "Regenerating...";
    try {
      await dashboardApi.regenerateStep1Metrics({ run_id: rid });
      notice(`Step 1 metrics regenerated for ${rid}.`, "ok");
      await loadForMetrics();
      await renderActiveTab();
    } catch (err) {
      notice(`Step 1 metrics regeneration failed: ${err.message}`, "bad");
    } finally {
      btn.textContent = prev || "Re-run Step 1 Metrics";
      btn.disabled = false;
    }
  });
  document.getElementById("rerunStep2MetricsTabBtn")?.addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    const rid = String(state.step2RunId || state.step2?.run_id || "").trim();
    if (!rid) {
      notice("No Step 2 run found for metrics regeneration.", "warn");
      return;
    }
    const prev = btn.textContent;
    btn.disabled = true;
    btn.textContent = "Regenerating...";
    try {
      await dashboardApi.regenerateStep2Metrics({ run_id: rid });
      notice(`Step 2 metrics regenerated for ${rid}.`, "ok");
      await loadForMetrics();
      await renderActiveTab();
    } catch (err) {
      notice(`Step 2 metrics regeneration failed: ${err.message}`, "bad");
    } finally {
      btn.textContent = prev || "Re-run Step 2 Metrics";
      btn.disabled = false;
    }
  });
  document.getElementById("metricsStep3ReplaySelect")?.addEventListener("change", async (e) => {
    state.metricsSelectedStep3SimId = String(e.target.value || "");
    await loadForMetrics();
    await renderActiveTab();
  });
  document.getElementById("rerunStep3MetricsTabBtn")?.addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    const simId = String(state.metricsSelectedStep3SimId || "").trim();
    if (!simId) {
      notice("No Step 3 sim_id found for metrics regeneration.", "warn");
      return;
    }
    const prev = btn.textContent;
    btn.disabled = true;
    btn.textContent = "Regenerating...";
    try {
      await dashboardApi.regenerateStep3Metrics({
        sim_id: simId,
      });
      notice(`Step 3 metrics regenerated for sim_id=${simId}.`, "ok");
      await loadForMetrics();
      await renderActiveTab();
    } catch (err) {
      notice(`Step 3 metrics regeneration failed: ${err.message}`, "bad");
    } finally {
      btn.textContent = prev || "Re-run Step 3 Metrics";
      btn.disabled = false;
    }
  });
}

async function renderMetrics() {
  const sec = makeSection(
    "Metrics",
    "Required metrics are sourced from metrics_principle_review.md and generated metrics are sourced from metrics.md."
  );
  const body = sec.querySelector(".page-body");
  const requiredMap = mapMetricRowsFromPrincipleReview(state.metricsPrincipleReviewMd);
  const generatedMap = mapMetricRowsFromGeneratedMetrics(state.metricsGeneratedMd);
  const step1Section = buildMetricsStepSection(1, requiredMap, generatedMap);
  const step2Section = buildMetricsStepSection(2, requiredMap, generatedMap);
  const step3Section = buildMetricsStepSection(3, requiredMap, generatedMap);
  const step3SimOptions = (state.metricsStep4Step3Simulations || [])
    .map((s) => {
      const simId = String(s?.simulation_id || "");
      const st = String(s?.status || "unknown");
      const mv = String(s?.model_version || "");
      return `<option value="${escapeHtml(simId)}" ${simId === String(state.metricsSelectedStep3SimId || "") ? "selected" : ""}>${escapeHtml(`${simId} | ${st} | model=${mv || "—"}`)}</option>`;
    })
    .join("");
  const step3StoredRows = (Array.isArray(state.metricsStep3Rows) ? state.metricsStep3Rows : []).map((r) => {
    const rawVal = r?.metric_value;
    const numericVal = Number(rawVal);
    const metricVal = Number.isFinite(numericVal) ? numericVal.toFixed(6) : "—";
    const numerator = r?.numerator ?? "—";
    const denominator = r?.denominator ?? "—";
    return `<tr>
      <td>${escapeHtml(String(r?.metric_name || "—"))}</td>
      <td>${escapeHtml(metricVal)}</td>
      <td>${escapeHtml(String(numerator))}</td>
      <td>${escapeHtml(String(denominator))}</td>
      <td>${statusBadgeHtml(String(r?.calculation_status || "not_collected"))}</td>
      <td>${escapeHtml(String(r?.principle_status || "—"))}</td>
      <td>${escapeHtml(String(r?.calculation_method || "—"))}</td>
      <td>${escapeHtml(String(r?.source_ref || "—"))}</td>
      <td>${escapeHtml(String(r?.updated_at_utc || "—"))}</td>
    </tr>`;
  });
  const step3StoredTable = table(
    ["metric", "value", "numerator", "denominator", "calc_status", "principle_status", "method", "source", "updated"],
    step3StoredRows.length
      ? step3StoredRows
      : [`<tr><td colspan="9">No stored Step 3 metrics for this SIM_ID yet. Run metrics generation or complete a Step 3 V2 simulation.</td></tr>`]
  );
  const step3Summary = state.metricsStep3Summary && typeof state.metricsStep3Summary === "object" ? state.metricsStep3Summary : {};
  body.innerHTML = `
    ${state.metricsLoadError ? `<p class="kv error">load_warning=${escapeHtml(state.metricsLoadError)}</p>` : ""}
    <article class="card">
      <h3>Source of Truth</h3>
      <p class="kv">required_metrics_source=docs/final_dissertation_docs/metrics_principle_review.md</p>
      <p class="kv">generated_metrics_source=docs/final_dissertation_docs/metrics.md</p>
    </article>
    <article class="card">
      <h3>Step 1 Metrics</h3>
      <div class="actions">
        <button type="button" id="rerunStep1MetricsTabBtn">Re-run Step 1 Metrics</button>
      </div>
      <p class="kv">required=${escapeHtml(String(step1Section.requiredCount))}</p>
      ${step1Section.tableHtml}
    </article>
    <article class="card">
      <h3>Step 2 Metrics</h3>
      <div class="actions">
        <button type="button" id="rerunStep2MetricsTabBtn">Re-run Step 2 Metrics</button>
      </div>
      <p class="kv">required=${escapeHtml(String(step2Section.requiredCount))}</p>
      ${step2Section.tableHtml}
    </article>
    <article class="card">
      <h3>Step 3 Metrics</h3>
      <div class="actions">
        <label>SIM_ID
          <select id="metricsStep3ReplaySelect">
            <option value="">-- select sim_id --</option>
            ${step3SimOptions}
          </select>
        </label>
        <button type="button" id="rerunStep3MetricsTabBtn">Re-run Step 3 Metrics</button>
      </div>
      <p class="kv">source=phase4.metrics step=step3 step_unique_id=${escapeHtml(String(state.metricsSelectedStep3SimId || "—"))}</p>
      <p class="kv">required=${escapeHtml(String(step3Section.requiredCount))} stored=${escapeHtml(String(step3Summary.total || state.metricsStep3Rows.length || 0))} measured=${escapeHtml(String(step3Summary.measured || 0))} missing=${escapeHtml(String(step3Summary.not_collected || 0))}</p>
      ${state.metricsStep3RowsError ? `<p class="kv error">step3_metrics_error=${escapeHtml(state.metricsStep3RowsError)}</p>` : ""}
      ${step3StoredTable}
    </article>
  `;
  setTimeout(bindMetricsActions, 0);
  return sec;
}

async function renderStep4() {
  const sec = makeSection(
    "Step 4",
    "SIM_ID-first dissertation metric extraction and completion tracking from metrics_principle_review.md (Step 1 metrics only)."
  );
  const body = sec.querySelector(".page-body");
  const step3Sims = Array.isArray(state.step4Step3Simulations) ? state.step4Step3Simulations : [];
  const selectedStep3 =
    step3Sims.find((s) => String(s?.simulation_id || "") === String(state.selectedStep4SimId || "")) || null;
  const dissertation = state.step4Status && typeof state.step4Status === "object" ? state.step4Status : {};
  const coverage = dissertation.metrics_required_coverage && typeof dissertation.metrics_required_coverage === "object"
    ? dissertation.metrics_required_coverage
    : {};
  const metricsSections = (Array.isArray(dissertation.metrics_required_sections) ? dissertation.metrics_required_sections : [])
    .filter((section) => {
      const key = String(section?.step_key || "").toLowerCase();
      const label = String(section?.step_label || "").toLowerCase();
      return key === "step1" || label.includes("step 1");
    });
  const totalRequired = Number(coverage.total_required || 0);
  const measuredCount = Number(coverage.measured_count || 0);
  const notCollectedCount = Number(coverage.not_collected_count || 0);
  const notApplicableCount = Number(coverage.not_applicable_count || 0);
  const completionPct = totalRequired > 0
    ? (((measuredCount + notApplicableCount) / totalRequired) * 100).toFixed(1)
    : "0.0";
  const hasStep4SimId = Boolean(String(state.selectedStep4SimId || "").trim());
  const canExtract = hasStep4SimId;
  const step4GateStatus = canExtract ? "completed" : "pending";
  const zipReady = Boolean(dissertation.step4_zip_download_ready);
  const zipLockReason = String(dissertation.step4_zip_lock_reason || "");
  const step3Status = String(selectedStep3?.status || "sim_id_missing");

  const completionStatus = (comp) => {
    const total = Number(comp?.total_required || 0);
    const missing = Number(comp?.not_collected_count || 0);
    if (total > 0 && missing === 0) return "completed";
    return "pending";
  };
  const renderMetricsRows = (rows) =>
    rows.length
      ? rows
          .map(
            (r) =>
              `<tr><td>${escapeHtml(String(r?.metric_name || ""))}</td><td>${escapeHtml(String(r?.value || "—"))}</td><td>${escapeHtml(String(r?.unit || ""))}</td><td>${statusBadgeHtml(String(r?.status || "not_collected"))}</td><td>${escapeHtml(String(r?.source_ref || ""))}</td><td>${escapeHtml(String(r?.measured_at_utc || "—"))}</td></tr>`
          )
          .join("")
      : `<tr><td colspan="6">No metrics in this subsection.</td></tr>`;

  const stepSectionSummaryRows = metricsSections.length
    ? metricsSections.map((section) => {
        const comp = section?.completion || {};
        return `<tr><td>${escapeHtml(String(section?.step_label || section?.step_key || ""))}</td><td>${escapeHtml(String(comp.total_required || 0))}</td><td>${escapeHtml(String(comp.measured_count || 0))}</td><td>${escapeHtml(String(comp.not_collected_count || 0))}</td><td>${escapeHtml(String(comp.not_applicable_count || 0))}</td><td>${escapeHtml(String(comp.completion_percent ?? 0))}%</td><td>${statusBadgeHtml(completionStatus(comp))}</td></tr>`;
      })
    : [`<tr><td colspan="7">No Step 1 metrics matrix found for this SIM_ID. Run extraction first.</td></tr>`];

  const sectionCardsHtml = metricsSections
    .map((section) => {
      const stepComp = section?.completion || {};
      const subsections = Array.isArray(section?.subsections) ? section.subsections : [];
      const subsectionHtml = subsections
        .map((sub) => {
          const subComp = sub?.completion || {};
          const metrics = Array.isArray(sub?.metrics) ? sub.metrics : [];
          return `
            <article class="card">
              <h3>${escapeHtml(String(sub?.subsection_label || sub?.subsection_key || ""))} ${statusBadgeHtml(completionStatus(subComp))}</h3>
              <p class="kv">required=${escapeHtml(String(subComp.total_required || 0))} measured=${escapeHtml(String(subComp.measured_count || 0))} missing=${escapeHtml(String(subComp.not_collected_count || 0))} completion=${escapeHtml(String(subComp.completion_percent ?? 0))}%</p>
              ${table(["metric", "value", "unit", "status", "source_ref", "measured_at_utc"], [renderMetricsRows(metrics)])}
            </article>
          `;
        })
        .join("");
      return `
        <article class="card">
          <h3>${escapeHtml(String(section?.step_label || section?.step_key || ""))} ${statusBadgeHtml(completionStatus(stepComp))}</h3>
          <p class="kv">required=${escapeHtml(String(stepComp.total_required || 0))} measured=${escapeHtml(String(stepComp.measured_count || 0))} missing=${escapeHtml(String(stepComp.not_collected_count || 0))} completion=${escapeHtml(String(stepComp.completion_percent ?? 0))}%</p>
        </article>
        ${subsectionHtml}
      `;
    })
    .join("");

  const step3SimOptions = step3Sims
    .map((s) => {
      const simId = String(s?.simulation_id || "");
      const st = String(s?.status || "unknown");
      const mv = String(s?.model_version || "");
      return `<option value="${escapeHtml(simId)}" ${simId === String(state.selectedStep4SimId || "") ? "selected" : ""}>${escapeHtml(`${simId} | ${st} | model=${mv || "—"}`)}</option>`;
    })
    .join("");
  body.innerHTML = `
    <article class="card">
      <h3>Step 4 Gate Lock (V2)</h3>
      <p class="kv">Gate rule: Step 3 V2 must provide a valid <code>sim_id</code>. Step 1/Step 2 lineage is auto-resolved from Postgres from this SIM_ID.</p>
      <div class="actions">
        <label>Step 3 V2 sim_id
          <select id="step4Step3SimSelect">
            <option value="">-- select sim_id --</option>
            ${step3SimOptions}
          </select>
        </label>
      </div>
      <div class="actions">
        <button type="button" id="step4RefreshSourcesBtn">Refresh Sources</button>
        <button type="button" id="runStep4ExtractionBtn" ${canExtract ? "" : "disabled"}>Extract Metrics Matrix</button>
        <button type="button" id="step4DownloadZipBtn" ${zipReady ? "" : "disabled"}>Download Dissertation ZIP</button>
        <button type="button" id="step4RefreshDownloadZipBtn" ${zipReady ? "" : "disabled"}>Refresh + Download ZIP</button>
      </div>
      <p class="kv">zip_download=${statusBadgeHtml(zipReady ? "completed" : "pending")} ${zipReady ? "ready" : escapeHtml(zipLockReason || "waiting_for_metrics_required_completion")}</p>
      ${state.step4LoadError ? `<p class="kv">load_warning=${escapeHtml(state.step4LoadError)}</p>` : ""}
    </article>
    <article class="card">
      <h3>Lineage + Extraction Status</h3>
      ${table(
        ["metric", "value"],
        [
          `<tr><td>selected_sim_id</td><td>${escapeHtml(String(selectedStep3?.simulation_id || "—"))}</td></tr>`,
          `<tr><td>step3_status</td><td>${escapeHtml(step3Status)}</td></tr>`,
          `<tr><td>step4_gate</td><td>${statusBadgeHtml(step4GateStatus)} ${canExtract ? "unlocked_via_sim_id" : "blocked_missing_sim_id"}</td></tr>`,
          `<tr><td>resolved_model_id</td><td>${escapeHtml(String(dissertation.resolved_model_id || "—"))}</td></tr>`,
          `<tr><td>resolved_model_version</td><td>${escapeHtml(String(dissertation.resolved_model_version || "—"))}</td></tr>`,
          `<tr><td>resolved_step1_run_id</td><td>${escapeHtml(String(dissertation.source_step1_run_id || "—"))}</td></tr>`,
          `<tr><td>resolved_step2_run_id</td><td>${escapeHtml(String(dissertation.source_step2_run_id || "—"))}</td></tr>`,
          `<tr><td>resolved_step3_sim_id</td><td>${escapeHtml(String(dissertation.step3_v2_sim_id || "—"))}</td></tr>`,
        ]
      )}
    </article>
    <article class="card">
      <h3>Step 1 Metrics Coverage (metrics_principle_review.md)</h3>
      ${table(
        ["metric", "value"],
        [
          `<tr><td>step4_runnable</td><td>${statusBadgeHtml(dissertation.step4_runnable ? "completed" : "pending")}</td></tr>`,
          `<tr><td>total_required</td><td>${escapeHtml(String(totalRequired))}</td></tr>`,
          `<tr><td>measured_count</td><td>${escapeHtml(String(measuredCount))}</td></tr>`,
          `<tr><td>not_collected_count</td><td>${escapeHtml(String(notCollectedCount))}</td></tr>`,
          `<tr><td>not_applicable_count</td><td>${escapeHtml(String(notApplicableCount))}</td></tr>`,
          `<tr><td>completion_percent</td><td>${escapeHtml(completionPct)}%</td></tr>`,
          `<tr><td>metrics_matrix_rows_in_db</td><td>${escapeHtml(String(coverage.row_count || 0))}</td></tr>`,
          `<tr><td>zip_ready</td><td>${statusBadgeHtml(zipReady ? "completed" : "pending")} ${zipReady ? "all required metrics gathered" : escapeHtml(zipLockReason || "metrics_pending")}</td></tr>`,
        ]
      )}
    </article>
    <article class="card">
      <h3>Step 1 Completion Summary</h3>
      ${table(
        ["step", "required", "measured", "missing", "not_applicable", "completion", "status"],
        stepSectionSummaryRows
      )}
    </article>
    ${sectionCardsHtml || `<article class="card"><h3>Step 1 Required Metrics</h3><p class="kv">No Step 1 metrics found. Run Step 4 extraction for this SIM_ID.</p></article>`}
  `;
  setTimeout(() => {
    document.getElementById("step4Step3SimSelect")?.addEventListener("change", async (e) => {
      state.selectedStep4SimId = String(e.target.value || "");
      await loadForStep4();
      await renderActiveTab();
    });
    document.getElementById("step4RefreshSourcesBtn")?.addEventListener("click", async () => {
      await loadForStep4();
      await renderActiveTab();
    });
    document.getElementById("runStep4ExtractionBtn")?.addEventListener("click", async () => {
      try {
        const simId = String(state.selectedStep4SimId || "").trim();
        if (!simId) throw new Error("step3_v2_sim_id_required");
        const refreshRes = await dashboardApi.runStep4Extraction({
          step3_v2_sim_id: simId,
        });
        if (!refreshRes?.ok) {
          throw new Error(String(refreshRes?.error || "step4_refresh_failed"));
        }
        await loadForStep4();
        const cov = (state.step4Status && state.step4Status.metrics_required_coverage) || {};
        notice(`Step 4 extraction updated for sim_id=${simId} (measured=${cov.measured_count || 0}/${cov.total_required || 0}).`, "ok");
        await renderActiveTab();
      } catch (e) {
        notice(`Step 4 extraction failed: ${e?.message || e}`, "bad");
      }
    });
    document.getElementById("step4DownloadZipBtn")?.addEventListener("click", () => {
      try {
        const simId = String(state.selectedStep4SimId || "").trim();
        if (!simId) throw new Error("step3_v2_sim_id_required");
        if (!zipReady) throw new Error(zipLockReason || "step4_zip_locked_metrics_incomplete");
        const url = dashboardApi.step4ExportZipUrl(
          {
            step3V2SimId: simId,
          },
          false
        );
        const a = document.createElement("a");
        a.href = url;
        a.target = "_blank";
        a.rel = "noopener";
        document.body.appendChild(a);
        a.click();
        a.remove();
      } catch (e) {
        notice(`Step 4 ZIP download failed: ${e?.message || e}`, "bad");
      }
    });
    document.getElementById("step4RefreshDownloadZipBtn")?.addEventListener("click", () => {
      try {
        const simId = String(state.selectedStep4SimId || "").trim();
        if (!simId) throw new Error("step3_v2_sim_id_required");
        if (!zipReady) throw new Error(zipLockReason || "step4_zip_locked_metrics_incomplete");
        const url = dashboardApi.step4ExportZipUrl(
          {
            step3V2SimId: simId,
          },
          true
        );
        const a = document.createElement("a");
        a.href = url;
        a.target = "_blank";
        a.rel = "noopener";
        document.body.appendChild(a);
        a.click();
        a.remove();
      } catch (e) {
        notice(`Step 4 ZIP refresh+download failed: ${e?.message || e}`, "bad");
      }
    });
  }, 0);
  return sec;
}

function step3PollInteractionActive() {
  const a = document.activeElement;
  const id = a?.id || "";
  return id === "step3ModelSelect" || id === "step3ReplayProfileSelect";
}

/** Operational Step 3 data (no model registry list) — used for poll-only partial refresh. */
async function fetchStep3LivePayloads() {
  const [status, children, rules, replay, simulation, processStatus] = await Promise.all([
    dashboardApi.getStep3Status().catch(() => ({ ok: false })),
    dashboardApi.getStep3ChildStacks().catch(() => ({ children: [] })),
    dashboardApi.getStep3RulesStatus().catch(() => ({ rules: [] })),
    dashboardApi.getStep3ReplayStatus().catch(() => ({ status: "idle" })),
    dashboardApi.getStep3SimulationStatus().catch(() => ({ ok: false })),
    dashboardApi
      .getStep3ProcessStatus({
        modelId: state.selectedStep3ModelId || "",
        modelVersion: state.selectedStep3ModelVersion || "",
      })
      .catch(() => ({ ok: false })),
  ]);
  return {
    status,
    children,
    rules,
    replay,
    simulation,
    processStatus,
  };
}

function buildStep3LiveRegionHtml(ctx) {
  const { status, children, rules, replay, simulation, step3Readiness, processStatus } = ctx;
  const rows = children.children || [];
  const running = rows.filter((c) => String(c.status || "").toLowerCase() === "running").length;
  const healthy = rows.filter((c) => String(c.health_status || "").toLowerCase() === "healthy").length;
  const rulesReady = (rules.rules || []).filter((r) => Boolean(r.ready)).length;
  const m = replay?.dissertation_metrics || {};
  const p1 = processStatus?.phase1 || {};
  const p2 = processStatus?.phase2 || {};
  const realtimeSignals = p2?.realtime_signals || {};
  const dm = p2?.dissertation_metrics || m || {};
  const hrm = p2?.high_recall_metrics || {};
  const p1Errors = Array.isArray(p1.errors) ? p1.errors : [];
  const p2Errors = Array.isArray(p2.errors) ? p2.errors : [];
  const p1Substages = Array.isArray(p1.substages) ? p1.substages : [];
  const p2Steps = Array.isArray(p2.steps) ? p2.steps : [];
  const p2AuditEvents = Array.isArray(p2.audit_step_progress_events) ? p2.audit_step_progress_events : [];
  const realtimeStep = p2Steps.find((s) => String(s?.name || "") === "realtime_shap_and_user_alert_status") || null;
  const visualUrl = p2.visual_dashboard_url || buildStep3VisualUrl(state.selectedStep3ModelVersion, replay?.replay_run_id || "");
  const visualReady = String(p1.status || "").toLowerCase() === "completed";
  const p1SubstageRows = p1Substages.length
    ? p1Substages
        .map(
          (s) => `<tr>
            <td>${escapeHtml(String(s.name || "stage"))}</td>
            <td>${statusBadgeHtml(s.status || "pending")}</td>
            <td>${escapeHtml(String(s.detail ? JSON.stringify(s.detail) : "—"))}</td>
          </tr>`
        )
        .join("")
    : "<tr><td colspan='3'>No phase-1 substages yet.</td></tr>";
  const p2StepsRows = p2Steps.length
    ? p2Steps
        .map(
          (s) => `<tr>
            <td>${escapeHtml(String(s.name || "step"))}</td>
            <td>${statusBadgeHtml(s.status || "pending")}</td>
            <td>${escapeHtml(String(s.detail ? JSON.stringify(s.detail) : "—"))}</td>
          </tr>`
        )
        .join("")
    : "<tr><td colspan='3'>No phase-2 steps yet.</td></tr>";
  const p2AuditRows = p2AuditEvents.length
    ? p2AuditEvents
        .map((e) => {
          const evSteps = Array.isArray(e?.steps) ? e.steps : [];
          const stepSummary = evSteps
            .map((s) => `${String(s?.name || "step")}:${String(s?.status || "pending")}`)
            .join(" | ");
          const errs = Array.isArray(e?.errors) ? e.errors : [];
          return `<tr>
            <td>${escapeHtml(String(e?.created_at || "—"))}</td>
            <td>${statusBadgeHtml(String(e?.phase2_state || "pending"))}</td>
            <td>${escapeHtml(String(e?.replay_status || "pending"))}</td>
            <td>${escapeHtml(stepSummary || "—")}</td>
            <td>${escapeHtml(errs.join(" | ") || "none")}</td>
          </tr>`;
        })
        .join("")
    : "<tr><td colspan='5'>No phase-2 audit snapshots yet.</td></tr>";
  const hrRuleHitsByScopeRows = Object.entries(hrm?.rule_hits_by_scope || {}).map(
    ([k, v]) => `<tr><td>${escapeHtml(String(k))}</td><td>${escapeHtml(String(v ?? 0))}</td></tr>`
  );
  const hrAlertsByChildRows = Object.entries(hrm?.alerts_by_child || {}).map(
    ([k, v]) => `<tr><td>${escapeHtml(String(k))}</td><td>${escapeHtml(String(v ?? 0))}</td></tr>`
  );
  const hrEscByFamilyRows = Object.entries(hrm?.escalations_by_rule_family || {}).map(
    ([k, v]) => `<tr><td>${escapeHtml(String(k))}</td><td>${escapeHtml(String(v ?? 0))}</td></tr>`
  );
  const hrFileDensityRows = Array.isArray(hrm?.per_file_alert_density)
    ? hrm.per_file_alert_density.map(
        (r) => `<tr>
          <td>${escapeHtml(String(r?.file_path || "—"))}</td>
          <td>${escapeHtml(String(r?.packets_total_in_file ?? 0))}</td>
          <td>${escapeHtml(String(r?.alerts_estimated ?? 0))}</td>
          <td>${escapeHtml(String(r?.alert_density ?? 0))}</td>
        </tr>`
      )
    : [];
  const validationReport = p2?.postgres_validation_report || {};
  const validationStatus = String(p2?.validation_status || validationReport?.status || "ok");
  const fileSummaries = Array.isArray(p2?.file_run_summaries) && p2.file_run_summaries.length
    ? p2.file_run_summaries
    : (Array.isArray(hrm?.rep01_transmission_by_file) ? hrm.rep01_transmission_by_file : []);
  const fileSummaryRows = fileSummaries.map((r) => {
    const total = Number(r?.packets_total_in_file ?? 0);
    const alerts = Number(r?.alerts_triggered ?? r?.rule_matches ?? 0);
    const alertsSent = Number(r?.alerts_sent_from_child ?? alerts);
    const alertsReceived = Number(r?.alerts_received_at_parent ?? alerts);
    const ratio = r?.alert_ratio != null
      ? Number(r.alert_ratio)
      : (total > 0 ? alerts / total : 0);
    return `<tr>
      <td>${escapeHtml(String(r?.file_name || r?.file_path || "—"))}</td>
      <td>${escapeHtml(String(r?.status || "prepared"))}</td>
      <td>${escapeHtml(String(total))}</td>
      <td>${escapeHtml(String(alerts))}</td>
      <td>${escapeHtml(String(alertsSent))}</td>
      <td>${escapeHtml(String(alertsReceived))}</td>
      <td>${escapeHtml(String(ratio))}</td>
      <td>${escapeHtml(String(r?.packets_attack_in_file ?? 0))}</td>
      <td>${escapeHtml(String(r?.packets_benign_in_file ?? 0))}</td>
      <td>${escapeHtml(String(r?.packets_transmitted ?? 0))}</td>
      <td>${escapeHtml(String(r?.packets_received ?? r?.packets_received_estimated ?? 0))}</td>
      <td>${escapeHtml(String(r?.packets_lost ?? r?.packets_lost_estimated ?? r?.packets_failed ?? 0))}</td>
      <td>${escapeHtml(String(r?.file_run_finished_at_ist || "—"))}</td>
    </tr>`;
  });
  return `
    <div class="grid cards">
      <article class="card"><h3>Phase 1 Status</h3>
        <p class="kv">state=${statusBadgeHtml(p1.status || "pending")} progress=${escapeHtml(String(p1.progress_percent ?? 0))}% steps=${escapeHtml(String(p1.steps_passed ?? 0))}/${escapeHtml(String(p1.steps_total ?? 0))}</p>
        <p class="kv">checks=${escapeHtml(String(p1.checks_passed ?? 0))}/${escapeHtml(String(p1.checks_total ?? 0))}</p>
        <p class="kv">child_stacks=${escapeHtml(String(rows.length))} running=${escapeHtml(String(running))} healthy=${escapeHtml(String(healthy))}</p>
        <p class="kv">rules_ready=${escapeHtml(String(rulesReady))} required_children=${escapeHtml(String(status.minimum_children_required ?? 10))}</p>
        <p class="kv">model_ready=${escapeHtml(String(Boolean(step3Readiness?.is_ready)))}</p>
        <p class="kv">prepare_status=${escapeHtml(String(p1.prepare_status || "—"))}</p>
        <p class="kv">errors=${escapeHtml(p1Errors.join(" | ") || "none")}</p>
      </article>
      <article class="card"><h3>Phase 2 Status</h3>
        <p class="kv">state=${statusBadgeHtml(p2.status || "pending")} progress=${escapeHtml(String(p2.progress_percent ?? 0))}% steps=${escapeHtml(String(p2.steps_passed ?? 0))}/${escapeHtml(String(p2.steps_total ?? 0))}</p>
        <p class="kv">simulation_running=${escapeHtml(String(Boolean(simulation?.process?.running)))} orchestration=${escapeHtml(String(status.orchestration || "—"))}</p>
        <p class="kv">replay_status=${escapeHtml(String(replay.status || "idle"))} active_streams=${escapeHtml(String(replay.active_streams ?? 0))}</p>
        <p class="kv">sim_id=${escapeHtml(String(p2.sim_id || replay.sim_id || replay.preparation_replay_id || "—"))} · replay_run_id=${escapeHtml(String(replay.replay_run_id || "—"))}</p>
        <p class="kv">run_id(step1)=${escapeHtml(String(p2.run_id || replay.run_id || "—"))} · prep_replay_id=${escapeHtml(String(replay.preparation_replay_id || "—"))}</p>
        <p class="kv">step3_audit_log=${escapeHtml(String(p2.step3_audit_log_path || "—"))}</p>
        <p class="kv">sim_created_ist=${escapeHtml(String(p2.sim_created_at_ist || "—"))} · sim_started_ist=${escapeHtml(String(p2.sim_started_at_ist || "—"))}</p>
        <p class="kv">sim_ended_ist=${escapeHtml(String(p2.sim_ended_at_ist || "—"))} · sim_completed_ist=${escapeHtml(String(p2.sim_completed_at_ist || "—"))}</p>
        <p class="kv">model_id=${escapeHtml(String(replay.model_id || "—"))} · model_version=${escapeHtml(String(replay.model_version || "—"))}</p>
        <p class="kv">metrics packets_sent=${escapeHtml(String(m.packets_sent_total ?? 0))} received=${escapeHtml(String(m.packets_received_total ?? 0))} dropped=${escapeHtml(String(m.packets_dropped_total ?? 0))}</p>
        <p class="kv">metrics alerts=${escapeHtml(String(m.alerts_total ?? 0))} escalations=${escapeHtml(String(m.escalations_total ?? 0))} delivery_ratio=${escapeHtml(String(m.delivery_ratio ?? 0))}</p>
        <p class="kv">errors=${escapeHtml(p2Errors.join(" | ") || "none")}</p>
        <p class="kv">${visualReady ? `<a href="${escapeHtml(visualUrl)}" target="_blank" rel="noopener noreferrer">Open Visual Dashboard</a>` : "Visual Dashboard unlocks after Phase 1 is completed."}</p>
      </article>
    </div>
    <div class="grid cards">
      <article class="card">
        <h3>Realtime SHAP + User Alerts</h3>
        <p class="kv">runtime_shap_events=${escapeHtml(String(realtimeSignals.runtime_shap_events ?? 0))} · user_alert_events=${escapeHtml(String(realtimeSignals.user_alert_events ?? 0))}</p>
        <p class="kv">child_alert_events=${escapeHtml(String(realtimeSignals.child_alert_events ?? 0))} · escalation_events=${escapeHtml(String(realtimeSignals.escalation_events ?? 0))}</p>
        <p class="kv">parent_review_events=${escapeHtml(String(realtimeSignals.parent_review_events ?? 0))}</p>
      </article>
      <article class="card">
        <h3>Dissertation Metrics</h3>
        <p class="kv">packets_sent=${escapeHtml(String(dm.packets_sent_total ?? 0))} received=${escapeHtml(String(dm.packets_received_total ?? 0))} dropped=${escapeHtml(String(dm.packets_dropped_total ?? 0))}</p>
        <p class="kv">alerts_total=${escapeHtml(String(dm.alerts_total ?? 0))} escalations_total=${escapeHtml(String(dm.escalations_total ?? 0))} mean_latency_ms=${escapeHtml(String(dm.mean_latency_ms ?? 0))}</p>
        <p class="kv">delivery_ratio=${escapeHtml(String(dm.delivery_ratio ?? 0))} rep01_files=${escapeHtml(String(dm.rep01_files_count ?? 0))} rep01_packets_total=${escapeHtml(String(dm.rep01_packets_total ?? 0))}</p>
      </article>
    </div>
    <article class="card">
      <h3>Realtime SHAP and User Alert Status</h3>
      ${table(
        ["field", "value"],
        [
          `<tr><td>step_name</td><td>${escapeHtml("realtime_shap_and_user_alert_status")}</td></tr>`,
          `<tr><td>status</td><td>${statusBadgeHtml(realtimeStep?.status || "pending")}</td></tr>`,
          `<tr><td>ok</td><td>${escapeHtml(String(Boolean(realtimeStep?.ok)))}</td></tr>`,
          `<tr><td>replay_run_id</td><td>${escapeHtml(String(realtimeSignals.replay_run_id || "—"))}</td></tr>`,
          `<tr><td>sim_id</td><td>${escapeHtml(String(p2.sim_id || replay.sim_id || "—"))}</td></tr>`,
          `<tr><td>run_id(step1)</td><td>${escapeHtml(String(p2.run_id || replay.run_id || "—"))}</td></tr>`,
          `<tr><td>runtime_shap_events</td><td>${escapeHtml(String(realtimeSignals.runtime_shap_events ?? 0))}</td></tr>`,
          `<tr><td>user_alert_events</td><td>${escapeHtml(String(realtimeSignals.user_alert_events ?? 0))}</td></tr>`,
          `<tr><td>child_alert_events</td><td>${escapeHtml(String(realtimeSignals.child_alert_events ?? 0))}</td></tr>`,
          `<tr><td>escalation_events</td><td>${escapeHtml(String(realtimeSignals.escalation_events ?? 0))}</td></tr>`,
          `<tr><td>parent_review_events</td><td>${escapeHtml(String(realtimeSignals.parent_review_events ?? 0))}</td></tr>`,
        ]
      )}
    </article>
    <article class="card">
      <h3>Phase 1 Sub-Stages</h3>
      ${table(["sub-stage", "status", "detail"], [p1SubstageRows])}
    </article>
    <article class="card">
      <h3>Phase 2 Step Progress</h3>
      ${table(["step", "status", "detail"], [p2StepsRows])}
    </article>
    <article class="card">
      <h3>Phase 2 Audit Log</h3>
      <p class="kv">audit_log_ref=${p2?.audit_log_ref ? `<a href="${escapeHtml(String(p2.audit_log_ref))}" target="_blank" rel="noopener noreferrer">Open replay timeline log</a>` : "—"}</p>
      ${table(["timestamp", "phase2_state", "replay_status", "steps", "errors"], [p2AuditRows])}
    </article>
    <article class="card">
      <h3>Postgres Validation (Non-Gating)</h3>
      <p class="kv">validation_status=${escapeHtml(validationStatus)}</p>
      <p class="kv">warnings=${escapeHtml(String((validationReport?.warnings || []).join(" | ") || "none"))}</p>
      <p class="kv">errors=${escapeHtml(String((validationReport?.errors || []).join(" | ") || "none"))}</p>
    </article>
    <article class="card">
      <h3>High-Recall Metrics</h3>
      <p class="kv">rule_hits_by_scope</p>
      ${table(["scope", "hits"], hrRuleHitsByScopeRows.length ? hrRuleHitsByScopeRows : ["<tr><td colspan='2'>No rule-hit scope data yet.</td></tr>"])}
      <p class="kv">alerts_by_child</p>
      ${table(["child", "alerts"], hrAlertsByChildRows.length ? hrAlertsByChildRows : ["<tr><td colspan='2'>No child alert data yet.</td></tr>"])}
      <p class="kv">escalations_by_rule_family</p>
      ${table(["rule_family", "escalations"], hrEscByFamilyRows.length ? hrEscByFamilyRows : ["<tr><td colspan='2'>No escalation family data yet.</td></tr>"])}
      <p class="kv">per_file_alert_density</p>
      ${table(
        ["file_path", "packets_total_in_file", "alerts_estimated", "alert_density"],
        hrFileDensityRows.length ? hrFileDensityRows : ["<tr><td colspan='4'>No per-file alert density data yet.</td></tr>"]
      )}
    </article>
    <article class="card">
      <h3>Per-PCAP Replay Summary (Finalized)</h3>
      ${table(
        ["file", "status", "total_packets", "alerts", "alert_sent", "alert_received", "alert_ratio", "attack_packets", "benign_packets", "transmitted", "received", "dropped", "file_end_update_ist"],
        fileSummaryRows.length ? fileSummaryRows : ["<tr><td colspan='13'>No per-file replay summary rows yet.</td></tr>"]
      )}
    </article>
  `;
}

function buildStep3VisualUrl(modelVersion, replayRunId) {
  const q = new URLSearchParams();
  const mv = String(modelVersion || "").trim();
  const rr = String(replayRunId || "").trim();
  if (mv) q.set("model_version", mv);
  if (rr) q.set("replay_run_id", rr);
  const qs = q.toString();
  return `./step3_visual.html${qs ? `?${qs}` : ""}`;
}

function step3Rate(success, total) {
  const t = Number(total || 0);
  const s = Number(success || 0);
  if (t <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((s / t) * 100)));
}

function step3RateBadge(rate) {
  if (rate >= 100) return "ok";
  if (rate >= 70) return "warn";
  return "bad";
}

function computeStep3PreparationMetrics({ status, children, rules, prepStatus, processStatus }) {
  const childRows = children?.children || [];
  const runningChildren = childRows.filter((c) => String(c.status || "").toLowerCase() === "running").length;
  const requiredChildren = Number(status?.minimum_children_required || 10);
  const childTotal = Math.max(requiredChildren, childRows.length || 0);
  const childRate = step3Rate(runningChildren, childTotal);

  const ruleRows = rules?.rules || [];
  const rulesReady = ruleRows.filter((r) => Boolean(r.ready)).length;
  const rulesTotal = Math.max(childRows.length, ruleRows.length || 0);
  const rulesRate = step3Rate(rulesReady, rulesTotal);

  const checks = prepStatus?.record?.checks || [];
  const checksPassed = checks.filter((c) => Boolean(c?.ok)).length;
  const checksRate = step3Rate(checksPassed, checks.length);
  const p1 = processStatus?.phase1 || {};
  const p1StepsTotal = Number(p1?.steps_total || 0);
  const p1StepsPassed = Number(p1?.steps_passed || 0);
  const p1StepsRate = step3Rate(p1StepsPassed, p1StepsTotal);

  const governanceChecks = checks.filter((c) => {
    const name = String(c?.name || "").toLowerCase();
    return name.includes("audit") || name.includes("governance") || name.includes("lineage");
  });
  const governancePassed = governanceChecks.filter((c) => Boolean(c?.ok)).length;
  const governanceRate = step3Rate(governancePassed, governanceChecks.length);

  return {
    childNodes: { success: runningChildren, total: childTotal, rate: childRate },
    rules: { success: rulesReady, total: rulesTotal, rate: rulesRate },
    verifier: { success: checksPassed, total: checks.length, rate: checksRate },
    governance: { success: governancePassed, total: governanceChecks.length, rate: governanceRate },
    substages: { success: p1StepsPassed, total: p1StepsTotal, rate: p1StepsRate },
  };
}

function buildStep3PreparationProgressHtml({ metrics, report, prepStatus }) {
  const prepRecord = prepStatus?.record || {};
  const prepResult = prepRecord?.prepare_result || {};
  const verifyResult = prepRecord?.verify_result || {};
  const dbSubstages = Array.isArray(verifyResult?.phase1_substages) && verifyResult.phase1_substages.length
    ? verifyResult.phase1_substages
    : (Array.isArray(prepResult?.phase1_substages) ? prepResult.phase1_substages : []);
  const steps = Array.isArray(report?.steps) && report.steps.length
    ? report.steps
    : dbSubstages.map((s) => ({
        name: s?.name || "substage",
        ok: Boolean(s?.ok),
        success: Boolean(s?.ok) ? 1 : 0,
        total: 1,
      }));
  const rows = steps.length
    ? steps
        .map((s) => {
          const r = step3Rate(s?.success || 0, s?.total || 0);
          const cls = step3RateBadge(r);
          return `<tr>
            <td>${escapeHtml(String(s?.name || "step"))}</td>
            <td><span class="badge ${cls}">${escapeHtml(String(Boolean(s?.ok)))}</span></td>
            <td>${escapeHtml(String(s?.success || 0))}/${escapeHtml(String(s?.total || 0))}</td>
            <td>${escapeHtml(String(r))}%</td>
          </tr>`;
        })
        .join("")
    : `<tr><td colspan="4">No preparation run yet for this model selection.</td></tr>`;
  const verifiedAt = prepStatus?.record?.verified_at || "—";
  const prepReplayId = prepStatus?.record?.preparation_replay_id || report?.preparation_replay_id || "—";
  return `
    <article class="card">
      <h3>Preparation Progress</h3>
      <p class="kv">child_nodes=${metrics.childNodes.success}/${metrics.childNodes.total} (${metrics.childNodes.rate}%) · rules=${metrics.rules.success}/${metrics.rules.total} (${metrics.rules.rate}%)</p>
      <p class="kv">verifier_checks=${metrics.verifier.success}/${metrics.verifier.total} (${metrics.verifier.rate}%) · audit_governance=${metrics.governance.success}/${metrics.governance.total} (${metrics.governance.rate}%)</p>
      <p class="kv">phase1_substages=${metrics.substages.success}/${metrics.substages.total} (${metrics.substages.rate}%)</p>
      <p class="kv">preparation_replay_id=${escapeHtml(String(prepReplayId))}</p>
      <p class="kv">latest_verification=${escapeHtml(String(verifiedAt))}</p>
      ${table(["Step", "OK", "Success", "Rate"], [rows])}
    </article>
  `;
}

async function patchStep3Phases() {
  if (state.activeTabId !== "step3") return false;
  const live = document.getElementById("step3LiveRegion");
  if (!live) return false;
  if (step3PollInteractionActive()) return true;
  const liveData = await fetchStep3LivePayloads();
  let step3Readiness = null;
  let prepStatus = null;
  if (state.selectedStep3ModelVersion) {
    [step3Readiness, prepStatus] = await Promise.all([
      dashboardApi.getStep3Readiness(state.selectedStep3ModelId, state.selectedStep3ModelVersion).catch(() => null),
      dashboardApi.getStep3PreparationStatus(state.selectedStep3ModelVersion).catch(() => null),
    ]);
  }
  state.step3ModelReadiness = step3Readiness;
  state.step3PreparationRecord = prepStatus?.record || null;
  const preparationOk = Boolean(prepStatus?.verified_ok);
  const modelIsStep3Ready = Boolean(
    (state.step3ModelChoicesCache || []).find((m) => m.model_version === state.selectedStep3ModelVersion)?.is_ready
  );
  const processStatus = liveData?.processStatus || {};
  const phase2State = String(processStatus?.phase2?.status || "").toLowerCase();
  const runBlockedByActiveReplay = phase2State === "running" || String(liveData?.replay?.status || "").toLowerCase() === "running";
  const canRunReplay = Boolean(state.selectedStep3ModelVersion && modelIsStep3Ready && !runBlockedByActiveReplay);
  live.innerHTML = buildStep3LiveRegionHtml({ ...liveData, step3Readiness, processStatus });
  const rb = document.getElementById("step3ReadinessBanner");
  if (rb) {
    const missingReq = step3Readiness?.missing_requirements || [];
    rb.innerHTML = `<p class="kv">completion=${escapeHtml(String(step3Readiness?.completion_percent ?? 0))}% ready=${escapeHtml(String(Boolean(step3Readiness?.is_ready)))}</p>
        <p class="kv">missing=${escapeHtml(missingReq.join(", ") || "none")}</p>`;
  }
  const pb = document.getElementById("step3PrepBanner");
  if (pb) {
    pb.textContent = `verifier=${String(preparationOk)} prep_replay_id=${state.step3PreparationRecord?.preparation_replay_id || "—"} last_check=${state.step3PreparationRecord?.verified_at || "—"}`;
  }
  const runBtn = document.getElementById("runStep3ReplayBtn");
  if (runBtn) {
    if (canRunReplay) runBtn.removeAttribute("disabled");
    else runBtn.setAttribute("disabled", "");
  }
  const visualFrame = document.getElementById("step3VisualFrame");
  if (visualFrame) {
    const nextSrc = buildStep3VisualUrl(state.selectedStep3ModelVersion, liveData?.replay?.replay_run_id || "");
    if (visualFrame.getAttribute("src") !== nextSrc) {
      visualFrame.setAttribute("src", nextSrc);
    }
  }
  const prepProgress = document.getElementById("step3PreparationProgressRegion");
  if (prepProgress) {
    const metrics = computeStep3PreparationMetrics({
      status: liveData.status,
      children: liveData.children,
      rules: liveData.rules,
      prepStatus,
      processStatus,
    });
    prepProgress.innerHTML = buildStep3PreparationProgressHtml({
      metrics,
      report: state.step3PreparationFlowReport,
      prepStatus,
    });
  }
  return true;
}

async function renderStep3() {
  const sec = makeSection("Step 3", "Unified simulation flow: one-click prepare + verify + replay with Postgres-backed live telemetry.");
  const body = sec.querySelector(".page-body");
  const [eligibleModels, status, children, rules, replay, simulation] = await Promise.all([
    dashboardApi.getStep3EligibleModels({ readyOnly: false }).catch(() => ({ eligible_models: [], incomplete_models: [] })),
    dashboardApi.getStep3Status().catch(() => ({ ok: false })),
    dashboardApi.getStep3ChildStacks().catch(() => ({ children: [] })),
    dashboardApi.getStep3RulesStatus().catch(() => ({ rules: [] })),
    dashboardApi.getStep3ReplayStatus().catch(() => ({ status: "idle" })),
    dashboardApi.getStep3SimulationStatus().catch(() => ({ ok: false })),
  ]);
  const eligibleOnly = eligibleModels.eligible_models || [];
  const incompleteOnly = eligibleModels.incomplete_models || [];
  const byVersion = new Map();
  for (const m of [...eligibleOnly, ...incompleteOnly]) {
    const mv = String(m?.model_version || "").trim();
    if (!mv) continue;
    const prev = byVersion.get(mv);
    if (!prev || (!prev.is_ready && m.is_ready)) byVersion.set(mv, m);
  }
  const step3ModelChoices = [...byVersion.values()].sort((a, b) => {
    if (Boolean(a.is_ready) !== Boolean(b.is_ready)) return a.is_ready ? -1 : 1;
    return String(a.model_version).localeCompare(String(b.model_version));
  });
  state.step3ModelChoicesCache = step3ModelChoices;
  const selStill = state.selectedStep3ModelVersion && step3ModelChoices.some((m) => m.model_version === state.selectedStep3ModelVersion);
  if (!selStill) {
    state.selectedStep3ModelVersion = "";
    state.selectedStep3ModelId = "";
  }
  const headerMv = String(state.currentModelHeader?.current_model_version || "").trim();
  const headerRow = headerMv ? step3ModelChoices.find((m) => m.model_version === headerMv) : null;
  if (!state.selectedStep3ModelVersion && headerRow) {
    state.selectedStep3ModelVersion = headerRow.model_version || "";
    state.selectedStep3ModelId = headerRow.model_id || "";
  }
  const firstReady = step3ModelChoices.find((m) => m.is_ready);
  if (!state.selectedStep3ModelVersion && firstReady) {
    state.selectedStep3ModelVersion = firstReady.model_version || "";
    state.selectedStep3ModelId = firstReady.model_id || "";
  }
  const selectedStep3Model = step3ModelChoices.find((m) => m.model_version === state.selectedStep3ModelVersion) || null;
  const step3Readiness = state.selectedStep3ModelVersion
    ? await dashboardApi.getStep3Readiness(state.selectedStep3ModelId, state.selectedStep3ModelVersion).catch(() => null)
    : null;
  state.step3ModelReadiness = step3Readiness;
  const prepStatus = state.selectedStep3ModelVersion
    ? await dashboardApi.getStep3PreparationStatus(state.selectedStep3ModelVersion).catch(() => null)
    : null;
  state.step3PreparationRecord = prepStatus?.record || null;
  const preparationOk = Boolean(prepStatus?.verified_ok);
  const modelIsStep3Ready = Boolean(selectedStep3Model?.is_ready);
  const processStatus = await dashboardApi
    .getStep3ProcessStatus({
      modelId: state.selectedStep3ModelId || "",
      modelVersion: state.selectedStep3ModelVersion || "",
    })
    .catch(() => ({ ok: false }));
  const phase2State = String(processStatus?.phase2?.status || "").toLowerCase();
  const runBlockedByActiveReplay = phase2State === "running" || String(replay?.status || "").toLowerCase() === "running";
  const canRunReplay = Boolean(state.selectedStep3ModelVersion && modelIsStep3Ready && !runBlockedByActiveReplay);
  const missingReq = step3Readiness?.missing_requirements || [];
  const prepMetricsCtx = computeStep3PreparationMetrics({
    status,
    children,
    rules,
    prepStatus,
    processStatus,
  });
  const prepProgressHtml = buildStep3PreparationProgressHtml({
    metrics: prepMetricsCtx,
    report: state.step3PreparationFlowReport,
    prepStatus,
  });
  const visualUrl = buildStep3VisualUrl(state.selectedStep3ModelVersion, replay?.replay_run_id || "");
  const liveHtml = buildStep3LiveRegionHtml({
    status,
    children,
    rules,
    replay,
    simulation,
    step3Readiness,
    processStatus,
  });
  body.innerHTML = `
    <div class="grid cards">
      <article class="card"><h3>Start Simulation</h3>
        <label>Model <span class="small">(frozen registry versions only; only replay-ready rows are enabled)</span>
          <select id="step3ModelSelect">
            <option value="">-- select model --</option>
            ${step3ModelChoices
              .map((m) => {
                const attrs = [];
                if (m.model_version === state.selectedStep3ModelVersion) attrs.push("selected");
                if (!m.is_ready) attrs.push("disabled");
                const pct = escapeHtml(String(m.completion_percent ?? 0));
                const mvRaw = String(m.model_version ?? "").trim();
                const mvDisp = escapeHtml(mvRaw || "—");
                const regSt = escapeHtml(String(m.registry_status ?? "").trim() || "—");
                const lab = m.is_ready
                  ? `${mvDisp} · status=${regSt} · ${pct}% (Step 3 ready)`
                  : `${mvDisp} · status=${regSt} · ${pct}% (not replay-ready)`;
                const extra = attrs.length ? ` ${attrs.join(" ")}` : "";
                return `<option value="${escapeHtml(mvRaw)}"${extra}>${lab}</option>`;
              })
              .join("")}
          </select>
        </label>
        <p class="kv">${step3ModelChoices.length ? "" : "No Step 3 candidate model versions found in registry with frozen/replay-ready status."}</p>
        <div id="step3ReadinessBanner">
        <p class="kv">completion=${escapeHtml(String(step3Readiness?.completion_percent ?? 0))}% ready=${escapeHtml(String(Boolean(step3Readiness?.is_ready)))}</p>
        <p class="kv">missing=${escapeHtml(missingReq.join(", ") || "none")}</p>
        </div>
        <p class="kv" id="step3PrepBanner">verifier=${escapeHtml(String(preparationOk))} prep_replay_id=${escapeHtml(state.step3PreparationRecord?.preparation_replay_id || "—")} last_check=${escapeHtml(state.step3PreparationRecord?.verified_at || "—")}</p>
        <label>Replay profile
          <select id="step3ReplayProfileSelect">
            <option value="default" ${state.step3ReplayProfile === "default" ? "selected" : ""}>default (phased)</option>
            <option value="random_single_chunk" ${state.step3ReplayProfile === "random_single_chunk" ? "selected" : ""}>random_single_chunk</option>
          </select>
        </label>
        <p class="kv small">Single-click flow: readiness check → prepare stacks/networks → verify → replay launch (single sim_id).</p>
        <button type="button" id="runStep3ReplayBtn" ${canRunReplay ? "" : "disabled"}>Start Simulation</button>
        <button type="button" id="stopStep3ReplayBtn">Stop Replay</button>
        <button type="button" id="stopStep3SimulationBtn">Stop Simulation</button>
        <p class="kv small">Stop Simulation removes all Step 3 child/factory containers and marks Step 3 runtime as halted/removed for a clean re-prepare.</p>
        <p class="kv small">Visual dashboard for live packet/alert/SHAP flow:</p>
        <p class="kv">${preparationOk ? `<a href="${escapeHtml(visualUrl)}" target="_blank" rel="noopener noreferrer">Open Visual Dashboard</a>` : "Start Simulation to run preparation/verification and unlock visual review."}</p>
      </article>
    </div>
    <div id="step3PreparationProgressRegion">${prepProgressHtml}</div>
    <p class="kv small">Only Phase 1 and Phase 2 controls are shown. Additional Step 3 details are hidden.</p>
    <div id="step3LiveRegion">${liveHtml}</div>
  `;
  setTimeout(() => {
    const modelSelect = document.getElementById("step3ModelSelect");
    if (modelSelect) modelSelect.onchange = async (e) => {
      const mv = e.target.value || "";
      const row = step3ModelChoices.find((m) => m.model_version === mv) || null;
      state.selectedStep3ModelVersion = mv;
      state.selectedStep3ModelId = row?.model_id || "";
      await renderActiveTab();
    };
    const replayProfileSelect = document.getElementById("step3ReplayProfileSelect");
    if (replayProfileSelect) replayProfileSelect.onchange = (e) => {
      state.step3ReplayProfile = e.target.value || "default";
    };
    const runReplayBtn = document.getElementById("runStep3ReplayBtn");
    if (runReplayBtn) runReplayBtn.onclick = async () => {
      if (state.step3ReplayStarting) return;
      state.step3ReplayStarting = true;
      runReplayBtn.disabled = true;
      try {
        if (!state.selectedStep3ModelVersion) throw new Error("Select a model first.");
        const resp = await dashboardApi.startStep3Simulation({
          replay_profile: state.step3ReplayProfile || "default",
          model_id: state.selectedStep3ModelId || undefined,
          model_version: state.selectedStep3ModelVersion,
          execution_mode: "simulation",
          strict_acceptance: false,
          detection_profile: "high_recall",
          alert_threshold_profile: "aggressive",
          window_sizes_s: [1, 5, 30],
          target_mode: "random_single",
          send_workers: 4,
        });
        if (!resp?.ok) throw new Error(resp?.error || "replay_start_failed");
        if (String(resp?.status || "").toLowerCase() === "completed") {
          notice(`Step 3 simulation completed (sent=${resp?.result?.sent ?? "?"}, targets=${resp?.result?.targets ?? "?"}).`, "ok");
        } else if (String(resp?.status || "").toLowerCase() === "accepted") {
          notice("Step 3 simulation accepted. Prepare + verify + replay are now running as one flow.", "ok");
        } else {
          notice("Step 3 simulation started.", "ok");
        }
        await patchStep3Phases();
      } catch (e) {
        notice(`Step 3 replay failed to start: ${e.message}`, "bad");
      } finally {
        state.step3ReplayStarting = false;
        runReplayBtn.disabled = false;
      }
    };
    const stopReplayBtn = document.getElementById("stopStep3ReplayBtn");
    if (stopReplayBtn) stopReplayBtn.onclick = async () => {
      try {
        const resp = await dashboardApi.stopStep3Replay();
        if (!resp?.ok) throw new Error(resp?.error || "replay_stop_failed");
        notice("Step 3 replay stop requested.", "ok");
        await patchStep3Phases();
      } catch (e) {
        notice(`Step 3 replay stop failed: ${e.message}`, "bad");
      }
    };
    const stopSimulationBtn = document.getElementById("stopStep3SimulationBtn");
    if (stopSimulationBtn) stopSimulationBtn.onclick = async () => {
      try {
        const resp = await dashboardApi.stopStep3Simulation();
        if (!resp?.ok) throw new Error(resp?.error || "simulation_stop_failed");
        const removedChildren = Number((resp?.removed_child_containers || []).length || 0);
        const removedFactories = Number((resp?.removed_factory_containers || []).length || 0);
        notice(`Step 3 simulation stopped. Removed child containers=${removedChildren}, factory containers=${removedFactories}.`, "ok");
        await renderActiveTab();
      } catch (e) {
        notice(`Step 3 simulation stop failed: ${e.message}`, "bad");
      }
    };
  }, 0);
  return sec;
}

function renderStep3V2Tab() {
  const sec = makeSection(
    "Step 3",
    "Step 3 V2 live simulation dashboard with controls, streams, charts, parent review, PCAP metrics, and hypothesis outputs."
  );
  const body = sec.querySelector(".page-body");
  body.innerHTML = `
    <div class="step3-v2-host-wrap">
      <div id="step3V2TabHost" class="step3-v2-host"></div>
    </div>
  `;
  return sec;
}

async function renderActiveTab() {
  if (renderedTabId === "step3") {
    step3V2Tab.onHide();
    step3V2Tab.destroy();
  }
  content.innerHTML = "";
  if (state.activeTabId === "overview") {
    renderedTabId = "overview";
    return content.appendChild(renderOverview());
  }
  if (state.activeTabId === "step1") {
    renderedTabId = "step1";
    return content.appendChild(renderStep1());
  }
  if (state.activeTabId === "step2") {
    renderedTabId = "step2";
    return content.appendChild(renderStep2());
  }
  if (state.activeTabId === "step3") {
    const sec = renderStep3V2Tab();
    content.appendChild(sec);
    const host = document.getElementById("step3V2TabHost");
    if (host) {
      step3V2Tab.mount(host);
      step3V2Tab.onShow();
    }
    renderedTabId = "step3";
    return;
  }
  if (state.activeTabId === "metrics") {
    renderedTabId = "metrics";
    return content.appendChild(await renderMetrics());
  }
  if (state.activeTabId === "governance") {
    renderedTabId = "governance";
    return content.appendChild(await renderGovernanceAudit());
  }
  renderedTabId = state.activeTabId;
}

function patchStep1Phases() {
  const telemetryEl = document.getElementById("step1TelemetryRegion");
  const metricStatusEl = document.getElementById("step1MetricStatusRegion");
  const metricsEl = document.getElementById("step1MetricsRegion");
  const missingReqEl = document.getElementById("step1MissingRequirementsRegion");
  const datasetsEl = document.getElementById("step1DatasetsRegion");
  const historyEl = document.getElementById("step1HistoryRegion");
  if (!telemetryEl || !datasetsEl || !historyEl || !metricsEl || !metricStatusEl || !missingReqEl) return false;
  const fragments = buildStep1Fragments();
  telemetryEl.innerHTML = fragments.telemetry;
  metricStatusEl.innerHTML = `<h3>Step 1 Metrics Generation Status</h3>${fragments.step1MetricStatusHtml}`;
  metricsEl.innerHTML = `<h3>Step 1 Metrics (Run Scoped)</h3>${fragments.metricsTable}`;
  missingReqEl.innerHTML = `<h3>Step 1 Missing Requirements</h3>${fragments.step1MissingTable}`;
  datasetsEl.innerHTML = fragments.datasetTable;
  historyEl.innerHTML = `<h3>Historical Runs</h3>${fragments.historyTable}`;
  wireStep1Textareas(content);
  bindStep1Actions();
  return true;
}

function patchStep2Phases() {
  const processEl = document.getElementById("step2ProcessRegion");
  const versionsPatched = patchStep2VersionsRegion();
  const detailPatched = patchStep2VersionDetailRegion();
  if (processEl) processEl.innerHTML = buildStep2ProcessHtml(state.step2 || {});
  return Boolean(processEl) || versionsPatched || detailPatched;
}

function patchStep2VersionsRegion() {
  const versionsEl = document.getElementById("step2VersionsRegion");
  if (!versionsEl) return false;
  versionsEl.outerHTML = buildStep2VersionsHtml(state.models || []);
  const root = document.getElementById("step2VersionsRegion");
  if (!root) return false;
  document.getElementById("step2VersionsFilterQ")?.addEventListener("input", (e) => {
    state.step2VersionsFilterQ = String(e.target.value || "");
    patchStep2VersionsRegion();
  });
  document.getElementById("step2VersionsFilterStatus")?.addEventListener("change", (e) => {
    state.step2VersionsFilterStatus = String(e.target.value || "all");
    patchStep2VersionsRegion();
  });
  root.querySelectorAll(".version-show-data").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const mv = btn.getAttribute("data-mv") || "";
      if (!mv) return;
      state.selectedModelVersion = mv;
      state.step2SelectedDetailVersion = mv;
      state.step2SelectedDetail = await dashboardApi.getModelVersion(mv).catch(() => null);
      patchStep2VersionsRegion();
      patchStep2VersionDetailRegion();
    });
  });
  return true;
}

function patchStep2VersionDetailRegion() {
  const detailEl = document.getElementById("step2VersionDetailRegion");
  if (!detailEl) return false;
  detailEl.outerHTML = buildStep2VersionDetailHtml();
  return true;
}

async function patchActiveTabPhases() {
  if (state.activeTabId === "step1") return patchStep1Phases();
  if (state.activeTabId === "step2") return patchStep2Phases();
  return false;
}

function setupTabs() {
  nav.innerHTML = "";
  for (const tab of TABS) {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = tab.label;
    if (tab.id === state.activeTabId) b.classList.add("active");
    b.addEventListener("click", async () => {
      const prevTabId = state.activeTabId;
      if (prevTabId === "step3" && tab.id !== "step3") {
        step3V2Tab.onHide();
      }
      state.activeTabId = tab.id;
      setupTabs();
      try {
        await loadDataForActiveTab();
        await renderActiveTab();
        startPolling();
      } catch (e) {
        notice(`Tab load failed: ${e.message}`, "bad");
      }
    });
    nav.appendChild(b);
  }
}

async function initializeDashboard() {
  try {
    setupTabs();
    await loadDataForActiveTab();
    await refreshHeaderStepStatusData();
    renderTopPipelineStatus();
    await renderActiveTab();
  } catch (e) {
    const base = getResolvedApiBase();
    const probe = base ? `${base}/dash_api/health` : `${window.location.origin}/dash_api/health`;
    console.error("[dashboard] initialize failed", {
      message: e?.message,
      stack: e?.stack,
      apiBase: base || "(same-origin; expects /dash_api on this host)",
      healthProbe: probe,
    });
    notice(`Failed to load dashboard data: ${e.message}`, "bad");
    notice(`API base: ${base || "(empty = same origin)"} — try ${probe}`, "bad");
  }
}

/** Poll only the visible tab; skip when the document is hidden. */
async function refreshActiveSectionSilent(force = false) {
  if (document.visibilityState !== "visible") return;
  try {
    if (!force && state.activeTabId === "step2" && state.step2ControlEditing) {
      await refreshHeaderStepStatusData();
      renderTopPipelineStatus();
      return;
    }
    await loadDataForActiveTab();
    await refreshHeaderStepStatusData();
    renderTopPipelineStatus();
    if (force) {
      await renderActiveTab();
      return;
    }
    const patched = await patchActiveTabPhases();
    if (!patched) await renderActiveTab();
  } catch {
    /* keep last good render; avoid spamming notices on background poll */
  }
}

function startPolling() {
  stopPolling();
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

function updatePollToggleUi() {
  if (!pollToggleBtn) return;
  pollToggleBtn.textContent = "Manual Refresh Only";
  pollToggleBtn.disabled = true;
}

function setPollingPaused(nextPaused) {
  pollingPaused = Boolean(nextPaused);
  try {
    if (pollingPaused) window.localStorage?.setItem(POLL_PAUSED_KEY, "1");
    else window.localStorage?.removeItem(POLL_PAUSED_KEY);
  } catch {
    // ignore localStorage failures
  }
  if (pollingPaused) stopPolling();
  else startPolling();
  updatePollToggleUi();
}

document.getElementById("tabContent")?.addEventListener("click", async (e) => {
  const btn = e.target.closest(".copy-log-btn");
  if (!btn || !content.contains(btn)) return;
  const tid = btn.getAttribute("data-copy");
  const ta = tid ? document.getElementById(tid) : null;
  if (!ta) return;
  ta.focus();
  ta.select();
  try {
    await navigator.clipboard.writeText(ta.value);
    notice("Log copied to clipboard.", "ok");
  } catch {
    try {
      document.execCommand("copy");
      notice("Log copied to clipboard.", "ok");
    } catch {
      notice("Copy failed; select the text manually.", "warn");
    }
  }
});

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState !== "visible" && state.activeTabId === "step3") {
    step3V2Tab.onHide();
  } else if (document.visibilityState === "visible" && state.activeTabId === "step3") {
    const host = document.getElementById("step3V2TabHost");
    if (host) {
      step3V2Tab.mount(host);
      step3V2Tab.onShow();
    }
  }
  stopPolling();
});

pollToggleBtn?.addEventListener("click", async () => {
  setPollingPaused(true);
  notice("Polling is disabled in manual-refresh mode.", "warn");
});

tinyHeaderRefreshBtn?.addEventListener("click", async () => {
  const prev = tinyHeaderRefreshBtn.textContent;
  tinyHeaderRefreshBtn.disabled = true;
  tinyHeaderRefreshBtn.textContent = "Updating...";
  try {
    await refreshHeaderStep3CompletionTiny();
    notice("Header Step 3 completion refreshed.", "ok");
  } catch {
    notice("Tiny refresh failed for header completion.", "bad");
  } finally {
    tinyHeaderRefreshBtn.textContent = prev || "Tiny Refresh";
    tinyHeaderRefreshBtn.disabled = false;
  }
});

manualRefreshBtn?.addEventListener("click", async () => {
  const prev = manualRefreshBtn.textContent;
  manualRefreshBtn.disabled = true;
  manualRefreshBtn.textContent = "Refreshing...";
  try {
    await refreshActiveSectionSilent(true);
    notice(`Refreshed ${state.activeTabId} module.`, "ok");
  } catch {
    notice(`Refresh failed for ${state.activeTabId} module.`, "bad");
  } finally {
    manualRefreshBtn.textContent = prev || "Refresh";
    manualRefreshBtn.disabled = false;
  }
});

try {
  await initializeDashboard();
} catch (bootErr) {
  console.error("[dashboard] bootstrap failed (unexpected)", bootErr);
  const strip = document.getElementById("globalStatus");
  if (strip) {
    const d = document.createElement("div");
    d.className = "notice bad";
    d.textContent = `Dashboard bootstrap failed: ${bootErr?.message || bootErr}. See browser Console.`;
    strip.prepend(d);
  }
}
updatePollToggleUi();
stopPolling();
