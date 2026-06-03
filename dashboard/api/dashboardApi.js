import { jsonFetch, resolveApiBase } from "./http.js";

/** Build `/dash_api/...` URL; base is resolved per request (not at module load). */
function dash(path) {
  const b = resolveApiBase();
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${b}/dash_api${p}`;
}

export const dashboardApi = {
  health: () => jsonFetch(dash("/health")),
  status: () => jsonFetch(dash("/status")),
  governanceSummary: () => jsonFetch(dash("/governance/summary")),
  step4Status: ({
    modelVersion = "",
    step1RunId = "",
    step2ModelId = "",
    step2RunId = "",
    step3V2SimId = "",
  } = {}) => {
    const qs = new URLSearchParams();
    if (modelVersion) qs.set("model_version", String(modelVersion));
    if (step1RunId) qs.set("step1_run_id", String(step1RunId));
    if (step2ModelId) qs.set("step2_model_id", String(step2ModelId));
    if (step2RunId) qs.set("step2_run_id", String(step2RunId));
    if (step3V2SimId) qs.set("step3_v2_sim_id", String(step3V2SimId));
    const q = qs.toString();
    return jsonFetch(`${resolveApiBase()}/dash_api/step4/status${q ? `?${q}` : ""}`);
  },
  runStep4Extraction: (payload = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/step4/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  step4ExportZipUrl: (
    {
      modelVersion = "",
      step1RunId = "",
      step2ModelId = "",
      step2RunId = "",
      step3V2SimId = "",
    } = {},
    refresh = false
  ) => {
    const qs = new URLSearchParams();
    if (modelVersion) qs.set("model_version", String(modelVersion));
    if (step1RunId) qs.set("step1_run_id", String(step1RunId));
    if (step2ModelId) qs.set("step2_model_id", String(step2ModelId));
    if (step2RunId) qs.set("step2_run_id", String(step2RunId));
    if (step3V2SimId) qs.set("step3_v2_sim_id", String(step3V2SimId));
    qs.set("refresh", refresh ? "1" : "0");
    return `${resolveApiBase()}/dash_api/step4/export.zip?${qs.toString()}`;
  },
  // Backward-compatible aliases.
  dissertationStatus: (modelVersion = "") =>
    jsonFetch(
      `${resolveApiBase()}/dash_api/dissertation/status${modelVersion ? `?model_version=${encodeURIComponent(modelVersion)}` : ""}`
    ),
  refreshDissertation: (payload = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/dissertation/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  queueIngest: (datasetId) => jsonFetch(dash(`/workflow/ingest?dataset_id=${encodeURIComponent(datasetId)}`), { method: "POST" }),
  runStep1: (payload = {}) =>
    jsonFetch(dash("/step1/run"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  regenerateStep1Metrics: (payload = {}) =>
    jsonFetch(dash("/step1/metrics/regenerate"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  getStep1Status: (runId = "") =>
    jsonFetch(`${resolveApiBase()}/dash_api/step1/status${runId ? `?run_id=${encodeURIComponent(runId)}` : ""}`),
  runStep2: (payload = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step2/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  regenerateStep2Metrics: (payload = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step2/metrics/regenerate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  regenerateStep3Metrics: (payload = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/metrics/regenerate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  getStep3Metrics: ({ simId = "" } = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/metrics?sim_id=${encodeURIComponent(String(simId || ""))}`),
  getStep2Status: (runId = "") =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step2/status${runId ? `?run_id=${encodeURIComponent(runId)}` : ""}`),
  /** Alias paths (same handler; optional `/api` prefix stripped server-side). */
  getModelV1Step2Status: (runId = "") =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step2/status${runId ? `?run_id=${encodeURIComponent(runId)}` : ""}`),
  postModelV1Step2Run: (payload = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step2/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  getModelV1Step2Training: (runId) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step2/training?run_id=${encodeURIComponent(runId)}`),
  getModelV1Step2Testing: (runId) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step2/testing?run_id=${encodeURIComponent(runId)}`),
  getModelV1Step2Shap: (runId) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step2/shap?run_id=${encodeURIComponent(runId)}`),
  getModelV1Step2Rules: (runId) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step2/rules?run_id=${encodeURIComponent(runId)}`),
  getModelV1Metrics: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/metrics`),
  getModelV1ShapSummary: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/shap/summary`),
  getModelV1RulesSummary: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/rules/summary`),
  getModelV1Rulepacks: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/rulepacks`),
  getModelV1AuditEvents: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/audit-events`),
  getArtifacts: () => jsonFetch(`${resolveApiBase()}/dash_api/artifacts`),
  getMetrics: () => jsonFetch(`${resolveApiBase()}/dash_api/metrics`),
  getMetricsSource: (doc) =>
    jsonFetch(`${resolveApiBase()}/dash_api/metrics/source?doc=${encodeURIComponent(String(doc || ""))}`),
  getRulepacks: () => jsonFetch(`${resolveApiBase()}/dash_api/rulepacks`),
  getAudit: () => jsonFetch(`${resolveApiBase()}/dash_api/audit`),
  getLogs: () => jsonFetch(`${resolveApiBase()}/dash_api/logs`),
  getDatasets: () => jsonFetch(`${resolveApiBase()}/dash_api/datasets`),
  getStep3Status: () => jsonFetch(`${resolveApiBase()}/dash_api/step3/status`),
  getCurrentModelHeader: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/current-model-header`),
  getModelV1Status: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/status`),
  getModelV1Step1Runs: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step1/runs`),
  getModelV1Step1Run: (runId) => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step1/runs/${encodeURIComponent(runId)}`),
  prepareStep2Run: (payload = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step2/prepare`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  getModelVersions: ({ q = "", status = "", sort = "created_at_desc" } = {}) => {
    const qp = new URLSearchParams();
    if (q) qp.set("q", q);
    if (status) qp.set("status", status);
    if (sort) qp.set("sort", sort);
    const suffix = qp.toString();
    return jsonFetch(`${resolveApiBase()}/dash_api/model-v1/models${suffix ? `?${suffix}` : ""}`);
  },
  createModelVersion: (payload = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/models`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  getModelVersion: (modelVersion) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/models/${encodeURIComponent(modelVersion)}`),
  setCurrentModelVersion: (modelVersion) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/models/${encodeURIComponent(modelVersion)}/set-current`, { method: "POST" }),
  cloneModelVersion: (modelVersion, payload = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/models/${encodeURIComponent(modelVersion)}/clone`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  deprecateModelVersion: (modelVersion) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/models/${encodeURIComponent(modelVersion)}/deprecate`, { method: "POST" }),
  getModelVersionArtifacts: (modelVersion) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/models/${encodeURIComponent(modelVersion)}/artifacts`),
  getModelVersionMetrics: (modelVersion) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/models/${encodeURIComponent(modelVersion)}/metrics`),
  getModelVersionAudit: (modelVersion) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/models/${encodeURIComponent(modelVersion)}/audit`),
  getStep2Readiness: (modelVersion) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step2/readiness?model_version=${encodeURIComponent(modelVersion)}`),
  getStep2ReadinessWithStep1: (modelVersion, sourceStep1RunId) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step2/readiness?model_version=${encodeURIComponent(modelVersion)}&source_step1_run_id=${encodeURIComponent(sourceStep1RunId)}`),
  getStep3ChildTemplates: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/child-templates`),
  getStep3EligibleModels: ({ readyOnly = true } = {}) =>
    jsonFetch(
      `${resolveApiBase()}/dash_api/model-v1/step3/eligible-models${readyOnly ? "?ready_only=1" : ""}`
    ),
  getStep3PreparationStatus: (modelVersion) =>
    jsonFetch(
      `${resolveApiBase()}/dash_api/model-v1/step3/preparation/status?model_version=${encodeURIComponent(modelVersion || "")}`
    ),
  verifyStep3Preparation: (payload = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/preparation/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  getStep3Readiness: (modelId = "", modelVersion = "") =>
    jsonFetch(
      `${resolveApiBase()}/dash_api/model-v1/step3/readiness?${modelId ? `model_id=${encodeURIComponent(modelId)}` : `model_version=${encodeURIComponent(modelVersion)}`}`
    ),
  prepareStep3: (payload = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/prepare`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  createStep3ChildStack: (payload = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/child-stacks`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  getStep3ChildStacks: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/child-stacks`),
  getStep3ChildStack: (childId) => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/child-stacks/${encodeURIComponent(childId)}`),
  startStep3ChildStack: (childId) => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/child-stacks/${encodeURIComponent(childId)}/start`, { method: "POST" }),
  stopStep3ChildStack: (childId) => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/child-stacks/${encodeURIComponent(childId)}/stop`, { method: "POST" }),
  restartStep3ChildStack: (childId) => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/child-stacks/${encodeURIComponent(childId)}/restart`, { method: "POST" }),
  removeStep3ChildStack: (childId) => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/child-stacks/${encodeURIComponent(childId)}/remove`, { method: "POST" }),
  getStep3ChildHealth: (childId) => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/child-stacks/${encodeURIComponent(childId)}/health`),
  deployStep3Rules: (payload = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/rules/deploy`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  getStep3RulesStatus: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/rules/status`),
  syncStep3ChildRules: (childId) => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/child-stacks/${encodeURIComponent(childId)}/rules/sync`, { method: "POST" }),
  runStep3Replay: (payload = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/simulation/start?async=1`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  getStep3ProcessStatus: ({ modelId = "", modelVersion = "" } = {}) => {
    const q = new URLSearchParams();
    if (modelId) q.set("model_id", modelId);
    if (modelVersion) q.set("model_version", modelVersion);
    const suffix = q.toString();
    return jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/process/status${suffix ? `?${suffix}` : ""}`);
  },
  getStep3ReplayStatus: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/replay/status`),
  stopStep3Replay: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/replay/stop`, { method: "POST" }),
  getStep3ReplayRuns: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/replay/runs`),
  getStep3Interactions: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/interactions`),
  getStep3ParentActions: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/parent-actions`),
  getStep3Alerts: ({ modelId = "", modelVersion = "", replayRunId = "", childId = "", urgency = "", status = "", limit = 300 } = {}) => {
    const q = new URLSearchParams();
    if (modelId) q.set("model_id", modelId);
    if (modelVersion) q.set("model_version", modelVersion);
    if (replayRunId) q.set("replay_run_id", replayRunId);
    if (childId) q.set("child_id", childId);
    if (urgency) q.set("urgency", urgency);
    if (status) q.set("status", status);
    if (limit) q.set("limit", String(limit));
    const suffix = q.toString();
    return jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/alerts${suffix ? `?${suffix}` : ""}`);
  },
  getStep3AnalystFeedback: ({ alertId = "", replayId = "", replayRunId = "", modelVersion = "", limit = 300 } = {}) => {
    const q = new URLSearchParams();
    if (alertId) q.set("alert_id", alertId);
    if (replayId) q.set("replay_id", replayId);
    if (replayRunId) q.set("replay_run_id", replayRunId);
    if (modelVersion) q.set("model_version", modelVersion);
    if (limit) q.set("limit", String(limit));
    const suffix = q.toString();
    return jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/analyst-feedback${suffix ? `?${suffix}` : ""}`);
  },
  submitStep3AnalystFeedback: (payload = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/analyst-feedback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  getStep3AuditEvents: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/audit-events`),
  getStep3AuditLog: ({ maxLines = 500 } = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/audit-log?max_lines=${encodeURIComponent(String(maxLines || 500))}`),
  getStep3NetworkStatus: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/network-status`),
  getStep3NetworkTopology: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/network-topology`),
  startStep3Simulation: (payload = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/simulation/start?async=1`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  stopStep3Simulation: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/simulation/stop`, { method: "POST" }),
  getStep3SimulationStatus: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/simulation/status`),
  runStep3Adapter: (payload = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/adapter/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  getStep3AdapterStatus: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/adapter/status`),
  getStep3AdapterLogs: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/adapter/logs`),
  getStep3ChildListenerStatus: (childId) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/child-stacks/${encodeURIComponent(childId)}/listener-status`),
  getStep3ChildManagementStatus: (childId) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/child-stacks/${encodeURIComponent(childId)}/management-status`),
  getStep3ReplayTimeline: (replayRunId = "") =>
    jsonFetch(
      `${resolveApiBase()}/dash_api/model-v1/step3/replay/timeline${replayRunId ? `?replay_run_id=${encodeURIComponent(replayRunId)}` : ""}`
    ),
  getStep3VisualFeed: ({ modelId = "", modelVersion = "", replayRunId = "", sinceTs = "", sinceEventId = "", limit = 200 } = {}) => {
    const q = new URLSearchParams();
    if (modelId) q.set("model_id", modelId);
    if (modelVersion) q.set("model_version", modelVersion);
    if (replayRunId) q.set("replay_run_id", replayRunId);
    if (sinceTs) q.set("since_ts", sinceTs);
    if (sinceEventId) q.set("since_event_id", sinceEventId);
    if (limit) q.set("limit", String(limit));
    const suffix = q.toString();
    return jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/visual-feed${suffix ? `?${suffix}` : ""}`);
  },
  getStep3ParentChildInteractions: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/parent-child-interactions`),
  getStep3V2EligibleModels: async () => {
    try {
      return await jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/v2/models/eligible`);
    } catch (err) {
      // Fallback when `/step3/v2/*` proxying is unavailable; reuse Step 3 readiness payload shape.
      const fallback = await jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/eligible-models?ready_only=0`);
      return {
        ok: Boolean(fallback?.ok ?? true),
        eligible_models: Array.isArray(fallback?.eligible_models) ? fallback.eligible_models : [],
        incomplete_models: Array.isArray(fallback?.incomplete_models) ? fallback.incomplete_models : [],
        total_models: Number(fallback?.total_models || 0),
        ready_only: false,
        source: "step3_eligible_models_fallback",
        fallback_reason: String(err?.message || "step3_v2_eligible_fetch_failed"),
      };
    }
  },
  startStep3V2Simulation: (payload = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/v2/simulations/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  stopStep3V2Simulation: (simulationId) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/v2/simulations/${encodeURIComponent(simulationId)}/stop`, {
      method: "POST",
    }),
  getStep3V2Simulations: ({ limit = 100 } = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/v2/simulations?limit=${encodeURIComponent(String(limit))}`),
  getStep3V2Simulation: (simulationId) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/v2/simulations/${encodeURIComponent(simulationId)}`),
  getStep3V2Audit: (simulationId, { limit = 1000 } = {}) =>
    jsonFetch(
      `${resolveApiBase()}/dash_api/model-v1/step3/v2/simulations/${encodeURIComponent(simulationId)}/audit?limit=${encodeURIComponent(
        String(limit)
      )}`
    ),
  getStep3V2PcapMetrics: (simulationId) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/v2/simulations/${encodeURIComponent(simulationId)}/pcap-metrics`),
  getStep3V2ParentReview: (simulationId, { limit = 500 } = {}) =>
    jsonFetch(
      `${resolveApiBase()}/dash_api/model-v1/step3/v2/simulations/${encodeURIComponent(simulationId)}/parent-review?limit=${encodeURIComponent(
        String(limit)
      )}`
    ),
  getStep3V2Hypothesis: (simulationId) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/v2/simulations/${encodeURIComponent(simulationId)}/hypothesis`),
  submitStep3V2MetricEvidence: (simulationId, payload = {}) =>
    jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/v2/simulations/${encodeURIComponent(simulationId)}/metrics/evidence`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  getStep3V2QueueStatus: () => jsonFetch(`${resolveApiBase()}/dash_api/model-v1/step3/v2/queue/status`),
  step3V2StreamUrl: ({ simulationId = "", cursorId = "global" } = {}) => {
    const q = new URLSearchParams();
    if (simulationId) q.set("simulation_id", simulationId);
    if (cursorId) q.set("cursor_id", cursorId);
    const suffix = q.toString();
    return `${resolveApiBase()}/dash_api/model-v1/step3/v2/stream${suffix ? `?${suffix}` : ""}`;
  },
};
