from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from services_parent.common.audit_event_types import (
    MODEL_V1_STEP1_COMPLETED,
    MODEL_V1_STEP1_FAILED,
    MODEL_V1_STEP2_COMPLETED,
    MODEL_V1_STEP2_DENIED,
    MODEL_V1_STEP2_FAILED,
)
from services_parent.common.parallel_runtime import resolve_parallel_runtime
from services_parent.common.project_cpu_governor import (
    acquire_project_heavy_workflow_slot,
    build_project_cpu_governor,
    plan_project_phase_parallelism,
    sample_host_cpu_utilization,
)
from services_parent.common.dissertation_metrics_export import persist_dissertation_metrics_ref
from services_parent.common.phase4_db import connect, write_audit_event
from services_parent.common.step_metrics_jobs import (
    generate_step1_metrics,
    generate_step2_metrics,
)
from services_parent.model_v1.artifacts import write_json_artifact
from services_parent.model_v1.db import (
    STEP1_CANONICAL_SCHEMA_VERSION,
    create_workflow_run,
    get_workflow_run,
    insert_cross_dataset_test_run,
    insert_h1_shap_triage_result,
    insert_model_per_class_metrics,
    insert_model_evaluation_run,
    insert_model_training_run,
    insert_results_shap_row,
    insert_rulepack_registry,
    upsert_rulepack_rule,
    count_rulepack_rules,
    insert_shap_artifact,
    insert_shap_log,
    list_inflight_workflow_runs,
    list_recent_workflow_runs,
    mark_rulepack_published,
    update_workflow_run,
    fetch_step1_dataset_split_counts,
)
from services_parent.model_v1.step1_processing import run_step1_dataset_task
from services_parent.model_v1 import step2_config
from services_parent.model_v1.step2_training import (
    freeze_model_artifact,
    run_integrity_verifier_task,
    run_rule_task,
    run_shap_task,
    run_testing_task,
    run_training_task,
)
from services_parent.model_v1.task_planner import (
    STEP1_DATASETS,
    STEP2_RULE_SCOPES,
    plan_step1_dataset_tasks,
    plan_step2_rule_tasks,
    plan_step2_shap_chunk_tasks,
    plan_step2_testing_tasks,
    summarize_task_results,
)
from services_parent.model_v1.worker_pool import run_parallel
from services_parent.model_v1.model_versions import ensure_model_artifact_layout, update_model_lifecycle
from services_parent.data_access.governed_data_access import (
    get_model_v1_split_row_counts,
)

_RUN_LOCK = threading.Lock()
_RUN_THREADS: dict[str, threading.Thread] = {}
_RUN_STATE: dict[str, dict[str, Any]] = {}
_TERMINAL_RUN_STATUSES = {"completed", "failed"}
STEP1_TOTAL_THREAD_BUDGET = 20
STEP1_PROCESS_POOL_WORKERS = 12


def _step3_cpu_governance_placeholder() -> dict[str, str]:
    return {"status": "measured_or_not_applicable", "reason": "simulation_runtime_operational_telemetry"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _actor() -> str:
    return "model-v1-workflow-coordinator"


def _is_uuid_like(value: str | None) -> bool:
    txt = str(value or "").strip()
    if not txt:
        return False
    try:
        uuid.UUID(txt)
        return True
    except Exception:
        return False


def _lookup_model_registry_model_id(model_version: str) -> str:
    mv = str(model_version or "").strip()
    if not mv:
        return ""
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT model_id::text
                    FROM phase4.model_registry
                    WHERE model_version = %(mv)s
                    ORDER BY created_at DESC
                    LIMIT 1;
                    """,
                    {"mv": mv},
                )
                row = cur.fetchone()
                return str((row or [""])[0] or "").strip()
    except Exception:
        return ""


def _resolve_step2_canonical_model_id(model_version: str, training_metrics: dict[str, Any] | None = None) -> tuple[str, str]:
    raw_model_id = str((training_metrics or {}).get("model_id") or "").strip()
    if _is_uuid_like(raw_model_id):
        return raw_model_id, "training_metrics.model_id"
    registry_model_id = _lookup_model_registry_model_id(model_version)
    if _is_uuid_like(registry_model_id):
        return registry_model_id, "model_registry.model_id"

    mv = str(model_version or "").strip()
    # Keep older local test/dev versions operational while enforcing strict UUIDs for canonical model_v1.* versions.
    if mv and not mv.startswith("model_v1."):
        if raw_model_id:
            return raw_model_id, "legacy_non_uuid_training_metrics_model_id"
        return mv, "legacy_non_uuid_model_version_fallback"
    return "", "unresolved"


def _set_run_state(run_id: str, payload: dict[str, Any]) -> None:
    with _RUN_LOCK:
        _RUN_STATE[run_id] = payload


def _patch_run_state(run_id: str, patch: dict[str, Any]) -> None:
    with _RUN_LOCK:
        current = dict(_RUN_STATE.get(run_id, {}))
        current.update(patch)
        _RUN_STATE[run_id] = current


def get_run_state(run_id: str) -> dict[str, Any] | None:
    with _RUN_LOCK:
        return dict(_RUN_STATE.get(run_id, {})) if run_id in _RUN_STATE else None


def reconcile_orphaned_workflow_runs(
    *,
    step_name: str | None = None,
    reason: str = "service_restart_or_missing_worker",
    limit: int = 200,
) -> dict[str, Any]:
    """
    Mark DB inflight runs as failed when no local worker state exists.

    Step1/Step2 orchestrators run in-process (threaded). After service restart,
    queued/running rows can be left behind in Postgres without a live worker.
    This reconciler keeps Postgres as source-of-truth for dashboard status.
    """
    checked = 0
    reconciled: list[str] = []
    skipped_live: list[str] = []
    errors: list[dict[str, str]] = []
    for row in list_inflight_workflow_runs(step_name=step_name, limit=limit):
        checked += 1
        run_id = str(row.get("run_id") or "")
        if not run_id:
            continue
        live = get_run_state(run_id)
        live_status = str((live or {}).get("status") or "").strip().lower()
        if live and live_status in {"queued", "running"}:
            skipped_live.append(run_id)
            continue
        previous_status = str(row.get("status") or "").strip().lower()
        try:
            update_workflow_run(
                run_id,
                status="failed",
                run_metrics={
                    "orphan_reconciled_at_utc": _now(),
                    "orphan_reconcile_reason": reason,
                    "orphan_previous_status": previous_status,
                },
                error_message=f"orphaned_{previous_status or 'inflight'}:{reason}",
                completed=True,
            )
            reconciled.append(run_id)
        except Exception as exc:
            errors.append({"run_id": run_id, "error": str(exc)})
    return {
        "ok": len(errors) == 0,
        "checked": checked,
        "reconciled": len(reconciled),
        "reconciled_run_ids": reconciled,
        "skipped_live": len(skipped_live),
        "errors": errors,
    }


def _check_step1_requirements(data_root: Path) -> tuple[bool, list[str]]:
    missing: list[str] = []
    for ds in STEP1_DATASETS:
        ds_dir = data_root / "raw_downloads" / ds
        if not ds_dir.exists() or not any(p.is_file() for p in ds_dir.rglob("*")):
            missing.append(ds)
    return (len(missing) == 0, missing)


def _parse_run_metrics(metrics: Any) -> dict[str, Any]:
    if isinstance(metrics, dict):
        return metrics
    if isinstance(metrics, str):
        try:
            out = json.loads(metrics)
            return out if isinstance(out, dict) else {}
        except Exception:
            return {}
    return {}


def _canonical_data_root(data_root: Path) -> str:
    try:
        return str(data_root.resolve())
    except OSError:
        return str(data_root)


def _compact_dataset_lineage_row(dataset_id: str, row: dict[str, Any]) -> dict[str, Any]:
    return {
        "dataset_id": dataset_id,
        "ok": row.get("ok"),
        "readiness": row.get("readiness"),
        "import_batch_id": row.get("import_batch_id"),
        "returncode": row.get("returncode"),
        "artifact_file_count": row.get("artifact_file_count"),
    }


def step1_dataset_lineage_hash(dataset_summary: dict[str, Any]) -> str:
    """Stable fingerprint of per-dataset Step 1 outcomes for Step 2 lineage binding."""
    payload = {
        ds: _compact_dataset_lineage_row(ds, dataset_summary.get(ds) or {})
        for ds in STEP1_DATASETS
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _resolve_step1_manifest_version(manifest: Path) -> str:
    """Best-effort manifest version string for run-scoped ingest lineage token."""
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            for key in ("manifest_version", "schema_version", "version"):
                v = str(payload.get(key) or "").strip()
                if v:
                    return v
    except Exception:
        pass
    try:
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        return f"sha256:{digest}"
    except Exception:
        return "unknown_manifest"


def _step1_ingest_lineage_token(*, run_id: str, data_root_canonical: str, manifest_version: str) -> str:
    raw = f"{run_id}|{data_root_canonical}|{manifest_version}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _step1_row_matches_data_root(row: dict[str, Any], want_root: str) -> bool:
    m = _parse_run_metrics(row.get("run_metrics"))
    stored = m.get("data_root_canonical") or m.get("data_root")
    if not stored:
        return False
    return _canonical_data_root(Path(str(stored))) == want_root


def _step1_candidate_strict_complete(row: dict[str, Any]) -> bool:
    if row.get("status") != "completed":
        return False
    m = _parse_run_metrics(row.get("run_metrics"))
    ds = m.get("dataset_summary") or {}
    return isinstance(ds, dict) and _step1_all_datasets_strict_complete(ds)


def _resolve_step1_prerequisite_for_step2(
    data_root: Path,
    *,
    explicit_step1_run_id: str | None,
) -> dict[str, Any]:
    """Bind Step 2 to a completed Step 1 run on the same data_root with a lineage hash."""
    want_root = _canonical_data_root(data_root)

    def pack(row: dict[str, Any]) -> dict[str, Any]:
        m = _parse_run_metrics(row.get("run_metrics"))
        ds = m.get("dataset_summary") or {}
        assert isinstance(ds, dict)
        return {
            "ok": True,
            "step1_run_id": str(row.get("run_id") or ""),
            "step1_lineage_hash": step1_dataset_lineage_hash(ds),
            "step1_completed_at_utc": str(row.get("completed_at_utc") or ""),
            "data_root_canonical": want_root,
        }

    if explicit_step1_run_id and explicit_step1_run_id.strip():
        rid = explicit_step1_run_id.strip()
        row = get_workflow_run(rid)
        if not row:
            return {"ok": False, "error": "step2_invalid_prerequisite_step1_run_id"}
        if row.get("step_name") != "step1":
            return {"ok": False, "error": "step2_prerequisite_run_is_not_step1"}
        if not _step1_candidate_strict_complete(row):
            return {"ok": False, "error": "step2_prerequisite_step1_not_strict_complete"}
        if not _step1_row_matches_data_root(row, want_root):
            return {"ok": False, "error": "step2_prerequisite_step1_data_root_mismatch"}
        return pack(row)

    for row in list_recent_workflow_runs(step_name="step1", limit=50):
        if not _step1_candidate_strict_complete(row):
            continue
        if not _step1_row_matches_data_root(row, want_root):
            continue
        return pack(row)

    return {"ok": False, "error": "step2_blocked_until_step1_all_datasets_strict_complete"}


def _verify_step1_lineage_at_runtime(lineage: dict[str, Any]) -> tuple[bool, str]:
    rid = str(lineage.get("step1_run_id") or "").strip()
    if not rid:
        return False, "missing_step1_run_id"
    row = get_workflow_run(rid)
    if not row:
        return False, "step1_run_not_found"
    if row.get("step_name") != "step1":
        return False, "not_step1_run"
    if not _step1_candidate_strict_complete(row):
        return False, "step1_strict_incomplete_at_runtime"
    m = _parse_run_metrics(row.get("run_metrics"))
    ds = m.get("dataset_summary") or {}
    if not isinstance(ds, dict):
        return False, "step1_dataset_summary_missing"
    h = step1_dataset_lineage_hash(ds)
    if h != lineage.get("step1_lineage_hash"):
        return False, "step1_lineage_hash_mismatch"
    return True, ""


def _emit_step2_denied(*, reason: str, context: dict[str, Any]) -> None:
    write_audit_event(
        event_type=MODEL_V1_STEP2_DENIED,
        actor=_actor(),
        artifact_refs=[],
        context={"reason": reason, **context},
        experiment_id="exp_model_v1_enterprise_baseline",
        model_version="v1",
    )


def _validate_training_input() -> tuple[bool, dict[str, Any]]:
    row_count = int((get_model_v1_split_row_counts() or {}).get("train") or 0)
    if row_count <= 0:
        return False, {"reason": "ENT-01 train partition returned zero rows", "row_count": row_count}
    return True, {"row_count": row_count}


def _validate_holdout_input() -> tuple[bool, dict[str, Any]]:
    row_count = int((get_model_v1_split_row_counts() or {}).get("test") or 0)
    if row_count <= 0:
        return False, {"reason": "ENT-01 holdout/test returned zero rows", "row_count": row_count}
    return True, {"row_count": row_count}


def _validate_model_artifact(path: Path | None, *, min_bytes: int = 1024) -> tuple[bool, str]:
    if not path:
        return False, "model_artifact_missing"
    if not path.exists():
        return False, "model_artifact_not_found"
    size = path.stat().st_size
    if size < min_bytes:
        return False, f"model_artifact_too_small:{size}"
    return True, ""


def _validate_non_placeholder_artifact(path: Path | None, *, min_bytes: int = 1024) -> tuple[bool, str]:
    ok, err = _validate_model_artifact(path, min_bytes=min_bytes)
    if not ok:
        return ok, err
    if path is None:
        return False, "model_artifact_missing"
    if path.suffix.lower() == ".bin":
        try:
            head = path.read_text(encoding="utf-8", errors="ignore")[:256].lower()
            if "artifact::" in head and "model_v1_artifact::" in head:
                return False, "model_artifact_placeholder_bin_rejected"
        except Exception:
            pass
    return True, ""


def _safe_float(val: Any) -> float:
    try:
        return float(val)
    except Exception:
        return 0.0


def _safe_int(val: Any) -> int:
    try:
        return int(val)
    except Exception:
        return 0


def _safe_ratio(numerator: Any, denominator: Any) -> float | None:
    den = _safe_float(denominator)
    if den <= 0:
        return None
    return _safe_float(numerator) / den


def _first_track_result(table: Any, primary_track: str) -> dict[str, Any]:
    if not isinstance(table, dict):
        return {}
    primary = table.get(primary_track)
    if isinstance(primary, dict):
        return primary
    for fallback in ("random_forest", "xgboost", "lightgbm"):
        row = table.get(fallback)
        if isinstance(row, dict):
            return row
    for row in table.values():
        if isinstance(row, dict):
            return row
    return {}


def _build_step2_metrics_principle_update(
    *,
    primary_track: str,
    within_dataset_results: dict[str, Any],
    cross_dataset_results: dict[str, Any],
    training_metrics: dict[str, Any],
    testing_results: list[dict[str, Any]],
    shap_stage_metrics: dict[str, Any],
    rep01_rule_validation: dict[str, Any],
) -> dict[str, Any]:
    def _row(value: Any, status: str, source_ref: str, note: str = "", numerator: Any = None, denominator: Any = None) -> dict[str, Any]:
        out = {
            "value": value,
            "status": status,
            "source_ref": source_ref,
        }
        if note:
            out["note"] = note
        if numerator is not None:
            out["numerator"] = numerator
        if denominator is not None:
            out["denominator"] = denominator
        return out

    within_rows = within_dataset_results.get("table_4_1_rows") if isinstance(within_dataset_results.get("table_4_1_rows"), dict) else {}
    primary_row = _first_track_result(within_rows, primary_track)

    def _ent01_primary_track_metrics_local() -> dict[str, Any]:
        for row in testing_results:
            if str(row.get("eval_target") or "") != "ent01_holdout":
                continue
            metrics = row.get("metrics") if isinstance(row.get("metrics"), dict) else {}
            track_results = (
                metrics.get("model_track_results")
                if isinstance(metrics.get("model_track_results"), dict)
                else {}
            )
            track_payload = _first_track_result(track_results, primary_track)
            if not isinstance(track_payload, dict):
                continue
            track_metrics = (
                track_payload.get("metrics")
                if isinstance(track_payload.get("metrics"), dict)
                else {}
            )
            if isinstance(track_metrics, dict) and track_metrics:
                return track_metrics
        return {}

    def _parse_square_confusion_matrix_local(raw: Any) -> list[list[float]]:
        if not isinstance(raw, list) or not raw:
            return []
        out: list[list[float]] = []
        for row in raw:
            if not isinstance(row, list):
                return []
            out.append([_safe_float(v) for v in row])
        n = len(out)
        if any(len(r) != n for r in out):
            return []
        return out

    def _macro_components_from_confusion_local(track_metrics: dict[str, Any]) -> dict[str, float]:
        cm = _parse_square_confusion_matrix_local(track_metrics.get("confusion_matrix"))
        if not cm:
            return {}
        n = len(cm)
        row_sum = [sum(r) for r in cm]
        col_sum = [sum(cm[r][c] for r in range(n)) for c in range(n)]
        total = sum(row_sum)
        fpr_sum = 0.0
        fnr_sum = 0.0
        for i in range(n):
            tp = _safe_float(cm[i][i])
            fp = _safe_float(col_sum[i] - tp)
            fn = _safe_float(row_sum[i] - tp)
            tn = _safe_float(total - tp - fp - fn)
            fpr_sum += _safe_ratio(fp, fp + tn) or 0.0
            fnr_sum += _safe_ratio(fn, fn + tp) or 0.0
        return {
            "class_count": float(n),
            "fpr_sum": float(fpr_sum),
            "fnr_sum": float(fnr_sum),
        }

    ent01_track_metrics = _ent01_primary_track_metrics_local()
    confusion_components = _macro_components_from_confusion_local(ent01_track_metrics)
    class_count_conf = _safe_int(confusion_components.get("class_count"))
    if class_count_conf <= 0:
        labels_fallback = ent01_track_metrics.get("labels")
        if isinstance(labels_fallback, list):
            class_count_conf = len(labels_fallback)
    if class_count_conf <= 0:
        per_class_fallback = ent01_track_metrics.get("per_class_metrics")
        if isinstance(per_class_fallback, list):
            class_count_conf = len(per_class_fallback)
    if class_count_conf <= 0:
        for key in ("class_count", "num_classes", "label_count"):
            cc = _safe_int(ent01_track_metrics.get(key))
            if cc > 0:
                class_count_conf = cc
                break
    if class_count_conf <= 0:
        for key in ("class_count", "num_classes", "label_count"):
            cc = _safe_int(primary_row.get(key))
            if cc > 0:
                class_count_conf = cc
                break

    fpr_value_source = primary_row.get("fpr")
    if fpr_value_source is None:
        fpr_value_source = ent01_track_metrics.get("fpr")
    fpr_den = confusion_components.get("class_count")
    if _safe_float(fpr_den) <= 0 and class_count_conf > 0:
        fpr_den = float(class_count_conf)
    if _safe_float(fpr_den) <= 0 and fpr_value_source is not None:
        fpr_den = 1.0
    fpr_num = confusion_components.get("fpr_sum")
    if fpr_num is None and fpr_value_source is not None and _safe_float(fpr_den) > 0:
        fpr_num = float(_safe_float(fpr_value_source)) * float(_safe_float(fpr_den))
    fpr_value = (
        _safe_ratio(fpr_num, fpr_den)
        if fpr_value_source is None
        else float(_safe_float(fpr_value_source))
    )

    fnr_value_source = primary_row.get("fnr")
    if fnr_value_source is None:
        fnr_value_source = ent01_track_metrics.get("fnr")
    fnr_den = confusion_components.get("class_count")
    if _safe_float(fnr_den) <= 0 and class_count_conf > 0:
        fnr_den = float(class_count_conf)
    if _safe_float(fnr_den) <= 0 and fnr_value_source is not None:
        fnr_den = 1.0
    fnr_num = confusion_components.get("fnr_sum")
    if fnr_num is None and fnr_value_source is not None and _safe_float(fnr_den) > 0:
        fnr_num = float(_safe_float(fnr_value_source)) * float(_safe_float(fnr_den))
    fnr_value = (
        _safe_ratio(fnr_num, fnr_den)
        if fnr_value_source is None
        else float(_safe_float(fnr_value_source))
    )

    def _feature_list_count_from_primary_track() -> int | None:
        model_tracks_local = training_metrics.get("model_tracks") if isinstance(training_metrics.get("model_tracks"), dict) else {}
        if not isinstance(model_tracks_local, dict):
            return None
        track = model_tracks_local.get(primary_track) if isinstance(model_tracks_local.get(primary_track), dict) else {}
        if not isinstance(track, dict) or not track:
            track = _first_track_result(model_tracks_local, primary_track)
        if not isinstance(track, dict) or not track:
            return None
        feature_list_path = str(track.get("feature_list_path") or "").strip()
        if not feature_list_path:
            return None
        try:
            payload = json.loads(Path(feature_list_path).read_text(encoding="utf-8"))
        except Exception:
            return None
        if isinstance(payload, list):
            return len([str(x) for x in payload])
        if isinstance(payload, dict):
            for key in ("features", "feature_list", "columns", "feature_names"):
                vals = payload.get(key)
                if isinstance(vals, list):
                    return len([str(x) for x in vals])
        return None

    cross_rows = [v for v in (cross_dataset_results or {}).values() if isinstance(v, dict)]
    cross_f1s: list[float] = []
    for row in cross_rows:
        table_42 = row.get("table_4_2_rows") if isinstance(row.get("table_4_2_rows"), dict) else {}
        track_row = _first_track_result(table_42, primary_track)
        f1 = track_row.get("f1")
        if f1 is None:
            continue
        cross_f1s.append(_safe_float(f1))
    internal_f1 = primary_row.get("f1")
    cross_dataset_robustness = None
    if internal_f1 is not None and cross_f1s:
        mean_external_f1 = float(sum(cross_f1s) / float(len(cross_f1s)))
        cross_dataset_robustness = _safe_ratio(mean_external_f1, internal_f1)

    inference_latency_ms = None
    for row in testing_results:
        if str(row.get("eval_target") or "") != "ent01_holdout":
            continue
        metrics = row.get("metrics") if isinstance(row.get("metrics"), dict) else {}
        pred_count = _safe_int(metrics.get("prediction_count"))
        duration_s = _safe_float(metrics.get("duration_s"))
        if pred_count > 0 and duration_s > 0:
            inference_latency_ms = (duration_s * 1000.0) / float(pred_count)
        break

    shap_duration_s = shap_stage_metrics.get("offline_compute_duration_s")
    if shap_duration_s is None:
        shap_duration_s = shap_stage_metrics.get("total_duration_s")
    feature_consistency = shap_stage_metrics.get("top_feature_consistency")
    recurrence_value = shap_stage_metrics.get("explanation_recurrence_score")
    recurrence_numerator = _safe_int(shap_stage_metrics.get("explanation_recurrence_repeated_patterns"))
    recurrence_denominator = _safe_int(shap_stage_metrics.get("explanation_recurrence_total_patterns"))
    recurrence_policy = str(shap_stage_metrics.get("explanation_recurrence_signature_policy") or "top5_with_sign")

    feature_reduction_ratio_value = training_metrics.get("feature_reduction_ratio")
    feature_count_after = _safe_int(training_metrics.get("feature_count"))
    feature_count_before = _safe_int(training_metrics.get("candidate_feature_count_before_selection"))
    if feature_count_before <= 0:
        feature_list_count = _feature_list_count_from_primary_track()
        feature_count_before = _safe_int(feature_list_count)
    feature_removed = max(feature_count_before - feature_count_after, 0) if feature_count_before > 0 else None
    if feature_reduction_ratio_value is None and feature_removed is not None and feature_count_before > 0:
        feature_reduction_ratio_value = float(feature_removed) / float(feature_count_before)
    feature_reduction_status = (
        "collected_as_principle"
        if feature_reduction_ratio_value is not None
        else "not_collected"
    )
    feature_reduction_note = ""
    if feature_reduction_ratio_value is None:
        feature_reduction_note = "missing before/after feature counts for derivation"

    sampled_packets = _safe_int(rep01_rule_validation.get("sampled_packets"))
    packets_with_detections = _safe_int(rep01_rule_validation.get("packets_with_detections"))
    detections_total = _safe_int(rep01_rule_validation.get("detections_total"))
    rule_hit_rate = _safe_ratio(packets_with_detections, sampled_packets)

    metrics: dict[str, dict[str, Any]] = {
        "precision": _row(primary_row.get("precision"), "collected_as_principle", "within_dataset_results.table_4_1_rows.<track>.precision"),
        "recall": _row(primary_row.get("recall"), "collected_as_principle", "within_dataset_results.table_4_1_rows.<track>.recall"),
        "macro_f1": _row(primary_row.get("macro_f1"), "collected_as_principle", "within_dataset_results.table_4_1_rows.<track>.macro_f1"),
        "false_positive_rate": _row(
            fpr_value,
            "collected_as_principle",
            "within_dataset_results.table_4_1_rows.<track>.fpr",
            numerator=fpr_num,
            denominator=fpr_den,
        ),
        "false_negative_rate": _row(
            fnr_value,
            "collected_as_principle",
            "within_dataset_results.table_4_1_rows.<track>.fnr",
            numerator=fnr_num,
            denominator=fnr_den,
        ),
        "cross_dataset_robustness": _row(cross_dataset_robustness, "collected_as_principle" if cross_dataset_robustness is not None else "not_collected", "within/cross_dataset_results"),
        "feature_reduction_ratio": _row(
            feature_reduction_ratio_value,
            feature_reduction_status,
            "training_result.metrics.feature_reduction_ratio|model_tracks.<primary>.feature_list_path",
            feature_reduction_note,
            feature_removed,
            feature_count_before if feature_count_before > 0 else None,
        ),
        "training_time_seconds": _row(training_metrics.get("duration_s"), "collected_as_principle", "training_result.metrics.duration_s"),
        "explanation_coverage": _row(
            (shap_stage_metrics.get("coverage_by_split") or {}).get("test")
            if isinstance(shap_stage_metrics.get("coverage_by_split"), dict)
            else shap_stage_metrics.get("chunk_feature_coverage"),
            "collected_as_principle",
            "shap_stage_metrics.coverage_by_split.test|chunk_feature_coverage",
        ),
        "rule_hit_rate": _row(rule_hit_rate, "collected_as_principle" if rule_hit_rate is not None else "not_collected", "rule_validation_summary.rep01_packet_validation", "", packets_with_detections, sampled_packets),
        "f1_score": _row(primary_row.get("f1"), "collected_as_principle", "within_dataset_results.table_4_1_rows.<track>.f1"),
        "accuracy": _row(primary_row.get("accuracy"), "collected_as_principle", "within_dataset_results.table_4_1_rows.<track>.accuracy"),
        "selected_feature_count": _row(training_metrics.get("feature_count"), "collected_as_principle", "training_result.metrics.feature_count"),
        "inference_latency_ms": _row(inference_latency_ms, "collected_as_principle" if inference_latency_ms is not None else "not_collected", "testing_results[ent01_holdout].metrics.{duration_s,prediction_count}"),
        "shap_generation_time_seconds": _row(shap_duration_s, "collected_as_principle" if shap_duration_s is not None else "not_collected", "shap_stage_metrics.offline_compute_duration_s"),
        "explanation_recurrence_score": _row(
            recurrence_value,
            "collected_as_principle" if recurrence_denominator > 0 else "not_collected",
            "shap_stage_metrics.explanation_recurrence_score",
            f"signature_policy={recurrence_policy}",
            recurrence_numerator if recurrence_denominator > 0 else None,
            recurrence_denominator if recurrence_denominator > 0 else None,
        ),
        "feature_contribution_stability": _row(feature_consistency, "collected_as_principle" if feature_consistency is not None else "not_collected", "shap_stage_metrics.top_feature_consistency"),
    }
    return {
        "generated_at_utc": _now(),
        "primary_track": primary_track,
        "rep01_summary": {
            "sampled_packets": sampled_packets,
            "packets_with_detections": packets_with_detections,
            "detections_total": detections_total,
        },
        "metrics": metrics,
    }


def _parse_json_tail(raw: str) -> dict[str, Any]:
    lines = [ln.strip() for ln in (raw or "").splitlines() if ln.strip()]
    for ln in reversed(lines):
        if not ln.startswith("{"):
            continue
        try:
            obj = json.loads(ln)
            if isinstance(obj, dict):
                return obj
        except Exception:
            continue
    return {}


def _run_rep01_rule_validation(
    *,
    data_root: Path,
    rulepack_dir: Path,
    run_id: str,
    model_version: str,
    sample_packets: int = 100,
) -> dict[str, Any]:
    script = Path(__file__).resolve().parents[2] / "scripts" / "validate_rep01_rules.py"
    if not script.exists():
        return {"ok": False, "error": "rep01_validation_script_missing", "script": str(script)}
    cmd = [
        sys.executable,
        str(script),
        "--data-root",
        str(data_root),
        "--rulepack-dir",
        str(rulepack_dir),
        "--run-id",
        str(run_id),
        "--model-version",
        str(model_version),
        "--sample-packets",
        str(max(1, int(sample_packets))),
    ]
    timeout_s = max(60, int(os.getenv("PROJECT_STEP2_REP01_VALIDATION_TIMEOUT_S", "300")))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "error": f"rep01_validation_timeout:{timeout_s}",
            "returncode": -9,
            "stdout_tail": "\n".join((exc.stdout or "").splitlines()[-20:]) if isinstance(exc.stdout, str) else "",
            "stderr_tail": "\n".join((exc.stderr or "").splitlines()[-20:]) if isinstance(exc.stderr, str) else "",
        }
    payload = _parse_json_tail(p.stdout or "")
    out = {
        "ok": bool(p.returncode == 0 and payload.get("ok")),
        "returncode": p.returncode,
        "stdout_tail": "\n".join((p.stdout or "").splitlines()[-20:]),
        "stderr_tail": "\n".join((p.stderr or "").splitlines()[-20:]),
        **({k: v for k, v in payload.items() if isinstance(k, str)} if isinstance(payload, dict) else {}),
    }
    if not isinstance(payload, dict) or not payload:
        out["error"] = "rep01_validation_payload_missing"
    return out


def _evaluate_supervised_training_quality(
    *,
    model_tracks: dict[str, Any],
    cfg: dict[str, Any],
) -> tuple[bool, dict[str, Any], str]:
    supervised_tracks = ("random_forest", "xgboost", "lightgbm")
    thresholds = {
        "min_macro_f1": _safe_float(cfg.get("PROJECT_STEP2_MIN_MACRO_F1")),
        "min_recall_macro": _safe_float(cfg.get("PROJECT_STEP2_MIN_RECALL_MACRO")),
        "min_precision_macro": _safe_float(cfg.get("PROJECT_STEP2_MIN_PRECISION_MACRO")),
        "max_predicted_class_ratio": _safe_float(cfg.get("PROJECT_STEP2_MAX_PREDICTED_CLASS_RATIO") or 0.995),
        "min_unique_pred_labels": max(1, _safe_int(cfg.get("PROJECT_STEP2_MIN_UNIQUE_PRED_LABELS") or 2)),
    }
    report: dict[str, Any] = {"thresholds": thresholds, "tracks": {}, "failed_tracks": []}
    for track_name in supervised_tracks:
        row = model_tracks.get(track_name) or {}
        metrics = row.get("metrics") or {}
        pred_dist = row.get("validation_predicted_label_distribution") or {}
        pred_dist_norm = {str(k): max(0, _safe_int(v)) for k, v in pred_dist.items()}
        pred_total = sum(pred_dist_norm.values())
        non_zero_labels = [k for k, v in pred_dist_norm.items() if v > 0]
        unique_pred_labels = len(non_zero_labels)
        max_pred_ratio = max((float(v) / float(pred_total) for v in pred_dist_norm.values()), default=0.0) if pred_total > 0 else 0.0
        macro_f1 = _safe_float(metrics.get("macro_f1") if metrics.get("macro_f1") is not None else metrics.get("f1_macro"))
        recall_macro = _safe_float(metrics.get("recall_macro"))
        precision_macro = _safe_float(metrics.get("precision_macro"))
        failures: list[str] = []
        if pred_total <= 0:
            failures.append("validation_predictions_missing")
        if unique_pred_labels < int(thresholds["min_unique_pred_labels"]):
            failures.append(
                f"degenerate_predicted_labels:{unique_pred_labels}<min:{int(thresholds['min_unique_pred_labels'])}"
            )
        if max_pred_ratio > float(thresholds["max_predicted_class_ratio"]):
            failures.append(
                f"predicted_class_ratio_exceeds_max:{max_pred_ratio:.6f}>{float(thresholds['max_predicted_class_ratio']):.6f}"
            )
        if macro_f1 < float(thresholds["min_macro_f1"]):
            failures.append(f"macro_f1_below_min:{macro_f1:.6f}<{float(thresholds['min_macro_f1']):.6f}")
        if recall_macro < float(thresholds["min_recall_macro"]):
            failures.append(f"recall_macro_below_min:{recall_macro:.6f}<{float(thresholds['min_recall_macro']):.6f}")
        if precision_macro < float(thresholds["min_precision_macro"]):
            failures.append(
                f"precision_macro_below_min:{precision_macro:.6f}<{float(thresholds['min_precision_macro']):.6f}"
            )
        track_report = {
            "validation_prediction_count": pred_total,
            "validation_predicted_label_distribution": pred_dist_norm,
            "unique_predicted_labels": unique_pred_labels,
            "max_predicted_class_ratio": max_pred_ratio,
            "macro_f1": macro_f1,
            "recall_macro": recall_macro,
            "precision_macro": precision_macro,
            "failures": failures,
        }
        report["tracks"][track_name] = track_report
        if failures:
            report["failed_tracks"].append(track_name)
    ok = len(report["failed_tracks"]) == 0
    reason = "ok" if ok else "training_quality_gate_failed"
    return ok, report, reason


def _evaluate_training_data_completeness(training_metrics: dict[str, Any]) -> tuple[bool, dict[str, Any], str]:
    source_counts = training_metrics.get("source_row_counts") or {}
    loaded_counts = training_metrics.get("loaded_row_counts") or {}
    declared = training_metrics.get("data_completeness") or {}
    report: dict[str, Any] = {"splits": {}, "failures": []}
    for split in ("train", "validation", "test"):
        src = _safe_int(source_counts.get(split))
        loaded = _safe_int(loaded_counts.get(split))
        if split in declared:
            declared_ok = bool(declared.get(split))
        else:
            declared_ok = src > 0 and src == loaded
        ok = src > 0 and loaded > 0 and src == loaded and declared_ok
        report["splits"][split] = {
            "source_row_count": src,
            "loaded_row_count": loaded,
            "declared_complete": declared_ok,
            "ok": ok,
        }
        if not ok:
            report["failures"].append(split)
    all_ok = len(report["failures"]) == 0
    reason = "ok" if all_ok else "training_data_completeness_failed"
    return all_ok, report, reason


def _compute_cross_dataset_deltas(testing_results: list[dict[str, Any]]) -> dict[str, Any]:
    baseline: dict[str, dict[str, float]] = {}
    for row in testing_results:
        if str(row.get("eval_target") or "") != "ent01_holdout":
            continue
        tracks = (row.get("metrics") or {}).get("model_track_results") or {}
        if not isinstance(tracks, dict):
            continue
        for track, payload in tracks.items():
            if not isinstance(payload, dict) or not payload.get("ok"):
                continue
            m = payload.get("metrics") or {}
            baseline[str(track)] = {
                "fpr": _safe_float(m.get("fpr")),
                "fnr": _safe_float(m.get("fnr")),
            }
    deltas: dict[str, Any] = {}
    for row in testing_results:
        target = str(row.get("eval_target") or "")
        if target == "ent01_holdout":
            continue
        tracks = (row.get("metrics") or {}).get("model_track_results") or {}
        if not isinstance(tracks, dict):
            continue
        per_track: dict[str, Any] = {}
        for track, payload in tracks.items():
            if not isinstance(payload, dict) or not payload.get("ok"):
                continue
            m = payload.get("metrics") or {}
            base = baseline.get(str(track))
            if not base:
                continue
            per_track[str(track)] = {
                "fpr_delta_vs_ent01": _safe_float(m.get("fpr")) - base["fpr"],
                "fnr_delta_vs_ent01": _safe_float(m.get("fnr")) - base["fnr"],
            }
        deltas[target] = per_track
    return deltas


def _extract_track_metrics_for_target(
    testing_results: list[dict[str, Any]],
    *,
    eval_target: str,
    primary_track: str,
) -> dict[str, float]:
    for row in testing_results:
        if str(row.get("eval_target") or "") != eval_target:
            continue
        metrics = row.get("metrics") or {}
        tracks = metrics.get("model_track_results") or {}
        if not isinstance(tracks, dict):
            continue
        track_payload = tracks.get(primary_track) if isinstance(tracks.get(primary_track), dict) else None
        if not isinstance(track_payload, dict):
            for fallback in ("random_forest", "xgboost", "lightgbm"):
                candidate = tracks.get(fallback)
                if isinstance(candidate, dict):
                    track_payload = candidate
                    break
        if not isinstance(track_payload, dict) or not track_payload.get("ok"):
            continue
        tm = track_payload.get("metrics") or {}
        if not isinstance(tm, dict):
            continue
        return {
            "macro_f1": _safe_float(tm.get("macro_f1") if tm.get("macro_f1") is not None else tm.get("f1")),
            "fnr": _safe_float(tm.get("fnr")),
            "fpr": _safe_float(tm.get("fpr")),
        }
    return {}


def _evaluate_cross_dataset_gates(
    testing_results: list[dict[str, Any]],
    *,
    primary_track: str,
) -> tuple[bool, dict[str, Any], list[str]]:
    thresholds = step2_config.evaluation_thresholds()
    report: dict[str, Any] = {"thresholds": thresholds, "targets": {}}
    gate_failures: list[str] = []
    for target, thr in thresholds.items():
        target_metrics = _extract_track_metrics_for_target(
            testing_results,
            eval_target=target,
            primary_track=primary_track,
        )
        target_ok = True
        failures: list[str] = []
        if not target_metrics:
            target_ok = False
            failures.append("missing_target_metrics")
        else:
            macro_f1 = _safe_float(target_metrics.get("macro_f1"))
            fnr = _safe_float(target_metrics.get("fnr"))
            fpr = _safe_float(target_metrics.get("fpr"))
            if macro_f1 < _safe_float(thr.get("macro_f1_min")):
                failures.append(f"{target}:macro_f1_below_min:{macro_f1:.6f}<{_safe_float(thr.get('macro_f1_min')):.6f}")
            if fnr > _safe_float(thr.get("fnr_max")):
                failures.append(f"{target}:fnr_above_max:{fnr:.6f}>{_safe_float(thr.get('fnr_max')):.6f}")
            if fpr > _safe_float(thr.get("fpr_max")):
                failures.append(f"{target}:fpr_above_max:{fpr:.6f}>{_safe_float(thr.get('fpr_max')):.6f}")
            target_ok = len(failures) == 0
        report["targets"][target] = {
            "ok": target_ok,
            "metrics": target_metrics,
            "failures": failures,
        }
        gate_failures.extend(failures)
    return len(gate_failures) == 0, report, gate_failures


def _collect_normalized_warnings(*chunks: str) -> list[str]:
    pat = re.compile(r"(feature names|no further splits with positive gain|stopped training because there are no more leaves)", re.I)
    out: list[str] = []
    for blob in chunks:
        for line in (blob or "").splitlines():
            line_s = line.strip()
            if not line_s:
                continue
            if pat.search(line_s):
                normalized = line_s
                if "feature names" in line_s.lower():
                    normalized = "lightgbm_feature_name_mismatch_warning"
                elif "no further splits with positive gain" in line_s.lower():
                    normalized = "lightgbm_no_positive_gain_warning"
                elif "stopped training because there are no more leaves" in line_s.lower():
                    normalized = "lightgbm_no_more_leaves_warning"
                if normalized not in out:
                    out.append(normalized)
    return out


def _normalize_top_features(values: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(values, list):
        return out
    for row in values:
        if not isinstance(row, dict):
            continue
        feature = str(row.get("feature") or "").strip()
        if not feature:
            continue
        out.append(
            {
                "feature": feature,
                "mean_abs_shap": _safe_float(row.get("mean_abs_shap")),
                "rank": int(row.get("rank") or 0),
            }
        )
    return out


def _pairwise_jaccard_mean(sets: list[set[str]]) -> float:
    if not sets:
        return 0.0
    if len(sets) == 1:
        return 1.0
    vals: list[float] = []
    for i in range(len(sets)):
        for j in range(i + 1, len(sets)):
            union = sets[i] | sets[j]
            inter = sets[i] & sets[j]
            vals.append((len(inter) / len(union)) if union else 1.0)
    return float(sum(vals) / len(vals)) if vals else 0.0


def _safe_signature_histogram(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    out: dict[str, int] = {}
    for k, v in value.items():
        key = str(k or "").strip()
        if not key:
            continue
        cnt = _safe_int(v)
        if cnt <= 0:
            continue
        out[key] = cnt
    return out


def _aggregate_shap_stage_metrics(
    shap_results: list[dict[str, Any]],
    *,
    model_id: str,
    model_version: str,
    top_k: int = 10,
) -> dict[str, Any]:
    split_rows: dict[str, int] = {}
    split_coverage_weighted: dict[str, float] = {}
    split_coverage_weight: dict[str, int] = {}
    feature_importance_sum: dict[str, float] = {}
    feature_sets: list[set[str]] = []
    signature_counts: dict[str, int] = {}
    signature_policy = "top5_with_sign"
    recurrence_total_patterns = 0
    total_duration_s = 0.0
    total_rows = 0
    rows_with_top_features = 0
    mean_abs_shap_total_weighted = 0.0
    mean_abs_shap_weight = 0
    ok_chunks = 0
    for row in shap_results:
        if not isinstance(row, dict):
            continue
        metrics = row.get("metrics") or {}
        if not isinstance(metrics, dict):
            metrics = {}
        split_name = str(row.get("split_name") or metrics.get("split_name") or "unknown")
        row_count = int(metrics.get("row_count") or 0)
        coverage = _safe_float(metrics.get("explanation_coverage"))
        split_rows[split_name] = split_rows.get(split_name, 0) + row_count
        split_coverage_weighted[split_name] = split_coverage_weighted.get(split_name, 0.0) + (coverage * row_count)
        split_coverage_weight[split_name] = split_coverage_weight.get(split_name, 0) + row_count
        total_duration_s += _safe_float(metrics.get("duration_s"))
        total_rows += row_count
        mean_abs = _safe_float(metrics.get("mean_abs_shap_total"))
        if row_count > 0:
            mean_abs_shap_total_weighted += mean_abs * row_count
            mean_abs_shap_weight += row_count
        top_features = _normalize_top_features(metrics.get("top_features"))
        if top_features:
            rows_with_top_features += row_count
            feature_sets.append({str(x["feature"]) for x in top_features if str(x["feature"])})
        for tf in top_features:
            feat = str(tf["feature"])
            feature_importance_sum[feat] = feature_importance_sum.get(feat, 0.0) + _safe_float(tf["mean_abs_shap"])
        sig_payload = (
            metrics.get("explanation_pattern_signatures")
            if isinstance(metrics.get("explanation_pattern_signatures"), dict)
            else {}
        )
        if isinstance(sig_payload, dict):
            signature_policy = str(sig_payload.get("signature_policy") or signature_policy)
            sig_hist = _safe_signature_histogram(sig_payload.get("signature_histogram"))
            if sig_hist:
                for sig, cnt in sig_hist.items():
                    signature_counts[sig] = int(signature_counts.get(sig, 0)) + int(cnt)
                recurrence_total_patterns += int(sum(sig_hist.values()))
            else:
                recurrence_total_patterns += _safe_int(sig_payload.get("total_patterns"))
        if row.get("ok"):
            ok_chunks += 1
    split_coverage: dict[str, float] = {}
    for k, weighted in split_coverage_weighted.items():
        w = int(split_coverage_weight.get(k, 0))
        split_coverage[k] = float(weighted / w) if w > 0 else 0.0
    global_top = [
        {"feature": k, "mean_abs_shap": float(v)}
        for k, v in sorted(feature_importance_sum.items(), key=lambda kv: kv[1], reverse=True)[: max(1, int(top_k))]
    ]
    weighted_mean_abs = (mean_abs_shap_total_weighted / mean_abs_shap_weight) if mean_abs_shap_weight > 0 else 0.0
    if signature_counts:
        recurrence_total_patterns = int(sum(signature_counts.values()))
    recurrence_repeated_patterns = int(sum(cnt for cnt in signature_counts.values() if int(cnt) > 1))
    recurrence_score = (
        float(recurrence_repeated_patterns) / float(recurrence_total_patterns)
        if recurrence_total_patterns > 0
        else None
    )
    return {
        "model_id": model_id,
        "model_version": model_version,
        "chunk_count": len(shap_results),
        "ok_chunk_count": ok_chunks,
        "total_rows": total_rows,
        "rows_with_top_features": rows_with_top_features,
        "chunk_feature_coverage": float(rows_with_top_features / total_rows) if total_rows > 0 else 0.0,
        "explanation_coverage_by_split": split_coverage,
        "row_count_by_split": split_rows,
        "global_top_features": global_top,
        "top_feature_consistency": _pairwise_jaccard_mean(feature_sets),
        "explanation_recurrence_signature_policy": signature_policy,
        "explanation_recurrence_total_patterns": int(recurrence_total_patterns),
        "explanation_recurrence_repeated_patterns": int(recurrence_repeated_patterns),
        "explanation_recurrence_score": recurrence_score,
        "weighted_mean_abs_shap_total": float(weighted_mean_abs),
        "total_duration_s": float(total_duration_s),
    }


def _persist_shap_metrics_to_db(
    *,
    run_id: str,
    workflow_id: str,
    experiment_id: str,
    model_id: str,
    model_version: str,
    frozen_manifest_path: str,
    shap_results: list[dict[str, Any]],
    shap_aggregate: dict[str, Any],
) -> dict[str, int]:
    shap_log_rows = 0
    results_shap_rows = 0
    h1_rows = 0
    for row in shap_results:
        if not isinstance(row, dict):
            continue
        metrics = row.get("metrics") or {}
        if not isinstance(metrics, dict):
            metrics = {}
        split_name = str(row.get("split_name") or metrics.get("split_name") or "unknown")
        partition_id = str(row.get("partition_id") or metrics.get("partition_id") or "")
        top_features = _normalize_top_features(metrics.get("top_features"))
        details = {
            "model_id": model_id,
            "model_version": model_version,
            "run_id": run_id,
            "workflow_id": workflow_id,
            "stage": "offline",
            "split_name": split_name,
            "partition_id": partition_id,
            "status": row.get("status"),
            "frozen_manifest": frozen_manifest_path,
            "metrics": metrics,
        }
        insert_shap_log(
            event_type="step2_shap_chunk_completed" if row.get("ok") else "step2_shap_chunk_failed",
            actor=_actor(),
            dataset_id="ENT-01",
            experiment_id=experiment_id,
            model_version=model_version,
            event_details_json=details,
            shap_stage="offline",
            top_features_json={"top_features": top_features},
            shap_artifact_path=str((row.get("artifact_path") or "")),
        )
        shap_log_rows += 1

    aggregate_details = {
        "model_id": model_id,
        "model_version": model_version,
        "run_id": run_id,
        "workflow_id": workflow_id,
        "stage": "offline",
        "frozen_manifest": frozen_manifest_path,
        "aggregate": shap_aggregate,
    }
    insert_shap_log(
        event_type="step2_shap_aggregate_completed",
        actor=_actor(),
        dataset_id="ENT-01",
        experiment_id=experiment_id,
        model_version=model_version,
        event_details_json=aggregate_details,
        shap_stage="offline",
        top_features_json={"top_features": shap_aggregate.get("global_top_features") or []},
        shap_artifact_path=frozen_manifest_path,
    )
    shap_log_rows += 1

    result_ctx = json.dumps(
        {
            "model_id": model_id,
            "model_version": model_version,
            "run_id": run_id,
            "workflow_id": workflow_id,
            "frozen_manifest": frozen_manifest_path,
        },
        sort_keys=True,
    )
    result_metrics = [
        (
            "offline_top_k_feature_coverage",
            str(shap_aggregate.get("chunk_feature_coverage")),
            "Share of SHAP-processed rows with top-k feature evidence.",
        ),
        (
            "offline_top_feature_consistency",
            str(shap_aggregate.get("top_feature_consistency")),
            "Average pairwise Jaccard overlap of top feature sets across SHAP chunks.",
        ),
        (
            "offline_explanation_coverage",
            str(shap_aggregate.get("explanation_coverage_by_split")),
            "Offline explanation coverage grouped by split.",
        ),
        (
            "offline_mean_abs_shap_total",
            str(shap_aggregate.get("weighted_mean_abs_shap_total")),
            "Weighted mean absolute SHAP magnitude across offline chunks.",
        ),
        (
            "offline_compute_duration_s",
            str(shap_aggregate.get("total_duration_s")),
            "Total offline SHAP compute duration in seconds.",
        ),
        (
            "runtime_explanation_coverage",
            "not_available_step2_runtime",
            "Runtime SHAP metrics are measured in Step 3 replay/runtime path, not in Step 2 offline pipeline.",
        ),
        (
            "runtime_latency_or_sampling",
            "not_available_step2_runtime",
            "Runtime SHAP latency is measured in Step 3 replay/runtime path, not in Step 2 offline pipeline.",
        ),
    ]
    for metric_name, value, interpretation in result_metrics:
        stage_name = "runtime" if metric_name.startswith("runtime_") else "offline"
        insert_results_shap_row(
            experiment_id=experiment_id,
            model_version=model_version,
            shap_stage=stage_name,
            input_desc=result_ctx,
            output_desc=metric_name,
            metric=metric_name,
            value=value,
            interpretation=interpretation,
        )
        results_shap_rows += 1

    insert_h1_shap_triage_result(
        experiment_id=experiment_id,
        model_version=model_version,
        explanation_coverage=str(shap_aggregate.get("chunk_feature_coverage")),
        top_features_consistency=str(shap_aggregate.get("top_feature_consistency")),
        explanation_clarity="not_available_step2_runtime",
        triage_support_score="not_available_step2_runtime",
        interpretation=(
            f"offline_shap_proxy model_id={model_id} run_id={run_id} "
            f"global_top_features={len(shap_aggregate.get('global_top_features') or [])}"
        ),
    )
    h1_rows += 1
    return {
        "shap_log_rows": shap_log_rows,
        "results_shap_rows": results_shap_rows,
        "h1_shap_triage_rows": h1_rows,
    }


def _sample_host_cpu_utilization(sample_interval_s: float) -> float | None:
    return sample_host_cpu_utilization(sample_interval_s)


def _build_step2_cpu_governor(cfg: dict[str, Any], effective_workers: int) -> dict[str, Any]:
    _ = cfg
    return build_project_cpu_governor(requested_workers=effective_workers)


def _plan_phase_parallelism(
    *,
    governor: dict[str, Any],
    phase: str,
    tasks_remaining: int,
    worker_threads: int,
    phase_max_workers: int,
    host_cpu_utilization: float | None,
) -> dict[str, Any]:
    return plan_project_phase_parallelism(
        governor=governor,
        phase=phase,
        tasks_remaining=tasks_remaining,
        worker_threads=worker_threads,
        phase_max_workers=phase_max_workers,
        host_cpu_utilization=host_cpu_utilization,
    )


def _run_phase_batches(
    *,
    phase: str,
    tasks: list[dict[str, Any]],
    fn: Any,
    worker_mode: str,
    worker_threads: int,
    phase_max_workers: int,
    governor: dict[str, Any],
    phase_patch: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    pending = list(tasks)
    all_results: list[dict[str, Any]] = []
    telemetry: list[dict[str, Any]] = []
    round_no = 0
    while pending:
        round_no += 1
        sampled_cpu = _sample_host_cpu_utilization(float(governor.get("sample_interval_s") or 0.35))
        plan = _plan_phase_parallelism(
            governor=governor,
            phase=phase,
            tasks_remaining=len(pending),
            worker_threads=worker_threads,
            phase_max_workers=phase_max_workers,
            host_cpu_utilization=sampled_cpu,
        )
        workers = int(plan["workers"])
        batch = pending[:workers]
        pending = pending[workers:]
        phase_patch(
            phase,
            "running",
            active_workers=workers,
            max_workers_phase=workers,
            host_cpu_governor=governor,
            host_cpu_round=plan,
        )
        for task in batch:
            task["worker_count"] = workers
            task["worker_threads"] = worker_threads
        batch_results = run_parallel(mode=worker_mode, max_workers=workers, fn=fn, tasks=batch)
        all_results.extend(batch_results)
        plan["round"] = round_no
        plan["tasks_scheduled"] = len(batch)
        telemetry.append(plan)
    return all_results, telemetry


def _step1_dataset_row_strict_complete(row: dict[str, Any]) -> bool:
    if not row.get("ok"):
        return False
    readiness = str(row.get("readiness") or "completed")
    return readiness == "completed"


def _step1_all_datasets_strict_complete(dataset_summary: dict[str, Any]) -> bool:
    for ds in STEP1_DATASETS:
        if not _step1_dataset_row_strict_complete(dataset_summary.get(ds) or {}):
            return False
    return True


def _run_step2_with_heavy_slot(**kwargs: Any) -> None:
    run_id = str(kwargs.get("run_id") or "")
    workflow_id = str(kwargs.get("workflow_id") or "")
    _patch_run_state(
        run_id,
        {
            "status": "queued",
            "queue_state": {"status": "waiting_for_heavy_slot"},
        },
    )
    with acquire_project_heavy_workflow_slot(
        run_id=run_id,
        workflow_id=workflow_id,
        step_name="step2",
    ) as queue_state:
        _patch_run_state(run_id, {"queue_state": queue_state})
        _run_step2(**kwargs, queue_state=queue_state)


def start_step1_async(
    *,
    data_root: Path,
    workflow_script: Path,
    manifest: Path,
    hybrid_policy: Path,
    requested_by: str,
    worker_mode: str,
    max_workers: int | None,
) -> dict[str, Any]:
    _ = max_workers  # Step 1 fast path: force fixed combined budget/process workers.
    requested_workers = STEP1_TOTAL_THREAD_BUDGET
    effective_workers = STEP1_PROCESS_POOL_WORKERS
    workflow_id = "model_v1_step1_dataset_processing"
    run_id = create_workflow_run(
        workflow_id=workflow_id,
        step_name="step1",
        requested_by=requested_by,
        worker_mode=worker_mode,
        requested_workers=requested_workers,
        effective_workers=effective_workers,
    )
    _set_run_state(
        run_id,
        {
            "run_id": run_id,
            "workflow_id": workflow_id,
            "step": "step1",
            "status": "queued",
            "worker_mode": worker_mode,
            "requested_workers": requested_workers,
            "effective_workers": effective_workers,
            "queued_tasks": len(STEP1_DATASETS),
            "running_tasks": 0,
            "completed_tasks": 0,
            "failed_tasks": 0,
            "started_at_utc": _now(),
            "dataset_summary": {},
            "queue_state": {"status": "waiting_for_heavy_slot"},
        },
    )
    th = threading.Thread(
        target=_run_step1,
        kwargs={
            "run_id": run_id,
            "workflow_id": workflow_id,
            "data_root": data_root,
            "workflow_script": workflow_script,
            "manifest": manifest,
            "hybrid_policy": hybrid_policy,
            "worker_mode": worker_mode,
            "effective_workers": effective_workers,
        },
        daemon=True,
    )
    with _RUN_LOCK:
        _RUN_THREADS[run_id] = th
    th.start()
    return {"ok": True, "run_id": run_id, "workflow_id": workflow_id, "status": "queued"}


def _run_step1(
    *,
    run_id: str,
    workflow_id: str,
    data_root: Path,
    workflow_script: Path,
    manifest: Path,
    hybrid_policy: Path,
    worker_mode: str,
    effective_workers: int,
) -> None:
    try:
        _ = effective_workers
        step1_chunk_workers = STEP1_PROCESS_POOL_WORKERS
        root_canon = _canonical_data_root(data_root)
        manifest_version = _resolve_step1_manifest_version(manifest)
        ingest_lineage_hash = _step1_ingest_lineage_token(
            run_id=run_id,
            data_root_canonical=root_canon,
            manifest_version=manifest_version,
        )
        cpu_governor = build_project_cpu_governor(requested_workers=STEP1_TOTAL_THREAD_BUDGET)
        _patch_run_state(
            run_id,
            {
                "status": "queued",
                "host_cpu_governor": cpu_governor,
                "queue_state": {"status": "waiting_for_heavy_slot"},
            },
        )
        with acquire_project_heavy_workflow_slot(
            run_id=run_id,
            workflow_id=workflow_id,
            step_name="step1",
        ) as queue_state:
            update_workflow_run(
                run_id,
                status="running",
                run_metrics={
                    "started_at_utc": _now(),
                    "cpu_governor": cpu_governor,
                    "queue_state": queue_state,
                    "data_root_canonical": root_canon,
                    "step1_manifest_version": manifest_version,
                    "step1_ingest_lineage_hash": ingest_lineage_hash,
                    "step3_cpu_governance": _step3_cpu_governance_placeholder(),
                },
            )
            _patch_run_state(
                run_id,
                {
                    "status": "running",
                    "queue_state": queue_state,
                    "running_tasks": len(STEP1_DATASETS),
                    "queued_tasks": 0,
                },
            )
            tasks = plan_step1_dataset_tasks(workflow_id=workflow_id, run_id=run_id)
            dataset_parallel = 1
            per_dataset_file_workers = step1_chunk_workers
            for t in tasks:
                t.update(
                    {
                        "raw_root": str(data_root / "raw_downloads"),
                        "data_root": str(data_root),
                        "manifest": str(manifest),
                        "hybrid_policy": str(hybrid_policy),
                        "max_file_workers": per_dataset_file_workers,
                        "file_executor": "process",
                        "step1_lineage_hash": ingest_lineage_hash,
                    }
                )
            plan = {
                "phase": "step1_dataset_processing_sequential",
                "workers": dataset_parallel,
                "worker_threads": per_dataset_file_workers,
                "tasks_remaining": len(tasks),
                "chunk_worker_threads": per_dataset_file_workers,
                "allocated_threads": dataset_parallel * per_dataset_file_workers,
                "action": "fixed_step1_combined_budget",
                "reason": "step1_process_pool_with_budgeted_ingest",
                "total_thread_budget": STEP1_TOTAL_THREAD_BUDGET,
            }
            dataset_workers = dataset_parallel
            results = run_parallel(mode=worker_mode, max_workers=dataset_workers, fn=run_step1_dataset_task, tasks=tasks)
        summary = summarize_task_results(results)
        dataset_summary = {r.get("dataset_id", "unknown"): r for r in results}
        db_counts = fetch_step1_dataset_split_counts(run_id)
        reconciliation: dict[str, Any] = {"datasets": {}, "ok": True}
        for ds, row in dataset_summary.items():
            expected = row.get("split_counts") or row.get("loaded_counts") or {}
            if not isinstance(expected, dict):
                expected = {}
            actual = db_counts.get(ds, {})
            mismatch = {}
            for split_name, exp in expected.items():
                if int(exp or 0) != int(actual.get(split_name, 0)):
                    mismatch[str(split_name)] = {
                        "expected": int(exp or 0),
                        "actual": int(actual.get(split_name, 0)),
                    }
            row["db_split_counts"] = actual
            row["reconciliation"] = {"ok": len(mismatch) == 0, "mismatch": mismatch}
            reconciliation["datasets"][ds] = row["reconciliation"]
            if mismatch:
                reconciliation["ok"] = False
        all_ok = _step1_all_datasets_strict_complete(dataset_summary)
        if not bool(reconciliation.get("ok")):
            all_ok = False
        status = "completed" if all_ok else "failed"
        lineage_hash = step1_dataset_lineage_hash(dataset_summary)
        step1_metrics_generation: dict[str, Any] = {
            "ok": False,
            "status": "not_run",
            "step": "step1",
            "run_id": run_id,
        }
        try:
            step1_metrics_generation = generate_step1_metrics(run_id=run_id)
        except Exception as step_metric_exc:
            print(
                f"[step1] final metric generation script failed run_id={run_id}: {step_metric_exc}",
                file=sys.stderr,
            )
            step1_metrics_generation = {
                "ok": False,
                "status": "failed",
                "warning": True,
                "step": "step1",
                "run_id": run_id,
                "error": str(step_metric_exc),
            }
        update_workflow_run(
            run_id,
            status=status,
            run_metrics={
                "cpu_governor": cpu_governor,
                "cpu_telemetry": [plan],
                "queue_state": queue_state,
                "effective_parallelism": {
                    "dataset_workers": dataset_workers,
                    "file_workers_per_dataset": per_dataset_file_workers,
                    "allocated_threads": int(plan.get("allocated_threads") or 0),
                },
                "step1_parallel_model": "coordinator_dataset_coordinators_file_workers",
                "step1_dataset_parallel": dataset_parallel,
                "step1_file_workers_per_dataset": per_dataset_file_workers,
                "step1_results": results,
                "task_summary": summary,
                "dataset_summary": dataset_summary,
                "step1_all_datasets_strict_complete": all_ok,
                "reconciliation": reconciliation,
                "data_root_canonical": root_canon,
                "step1_manifest_version": manifest_version,
                "step1_ingest_lineage_hash": ingest_lineage_hash,
                "step1_dataset_lineage_hash": lineage_hash,
                "step1_canonical_required_schema_version": STEP1_CANONICAL_SCHEMA_VERSION,
                "step1_metrics_generation": step1_metrics_generation,
                "completed_at_utc": _now(),
                "step3_cpu_governance": _step3_cpu_governance_placeholder(),
            },
            error_message=None if status == "completed" else ("step1_reconciliation_failed" if not reconciliation.get("ok") else "step1_not_all_datasets_completed"),
            completed=True,
        )
        _patch_run_state(
            run_id,
            {
                "status": status,
                "running_tasks": 0,
                "completed_tasks": summary["completed_tasks"],
                "failed_tasks": summary["failed_tasks"],
                "dataset_summary": dataset_summary,
                "step1_metrics_generation": step1_metrics_generation,
                "completed_at_utc": _now(),
            },
        )
        write_audit_event(
            event_type=MODEL_V1_STEP1_COMPLETED if status == "completed" else MODEL_V1_STEP1_FAILED,
            actor=_actor(),
            artifact_refs=[],
            context={
                "run_id": run_id,
                "workflow_id": workflow_id,
                "task_summary": summary,
                "data_root_canonical": root_canon,
                "step1_manifest_version": manifest_version,
                "step1_ingest_lineage_hash": ingest_lineage_hash,
                "step1_dataset_lineage_hash": lineage_hash,
                "step1_canonical_required_schema_version": STEP1_CANONICAL_SCHEMA_VERSION,
                "step1_metrics_generation": step1_metrics_generation,
            },
            experiment_id="exp_model_v1_enterprise_baseline",
            model_version="v1",
        )
    except Exception as exc:
        err_msg = f"step1_unhandled_exception:{exc}"
        tb = traceback.format_exc()
        try:
            update_workflow_run(
                run_id,
                status="failed",
                run_metrics={
                    "current_phase": "step1_failed_unhandled_exception",
                    "step1_unhandled_exception": str(exc),
                    "completed_at_utc": _now(),
                    "step3_cpu_governance": _step3_cpu_governance_placeholder(),
                },
                error_message=err_msg,
                completed=True,
            )
        except Exception:
            pass
        _patch_run_state(
            run_id,
            {
                "status": "failed",
                "running_tasks": 0,
                "completed_at_utc": _now(),
                "error": err_msg,
            },
        )
        try:
            write_audit_event(
                event_type=MODEL_V1_STEP1_FAILED,
                actor=_actor(),
                artifact_refs=[],
                context={
                    "run_id": run_id,
                    "workflow_id": workflow_id,
                    "error": str(exc),
                    "traceback": tb,
                },
                experiment_id="exp_model_v1_enterprise_baseline",
                model_version="v1",
            )
        except Exception:
            pass


def start_step2_async(
    *,
    data_root: Path,
    train_script: Path,
    evaluate_script: Path,
    shap_script: Path,
    rules_script: Path,
    requested_by: str,
    worker_mode: str,
    max_workers: int | None,
    prerequisite_step1_run_id: str | None = None,
    model_version: str = "v1",
    execution_mode: str = "continue_existing",
) -> dict[str, Any]:
    want_root = _canonical_data_root(data_root)
    ok, missing = _check_step1_requirements(data_root)
    if not ok:
        _emit_step2_denied(
            reason="step1_prereq_missing_artifacts",
            context={"missing_datasets": missing, "data_root_canonical": want_root},
        )
        return {"ok": False, "error": f"step1_prereq_missing_artifacts:{','.join(missing)}"}
    lineage = _resolve_step1_prerequisite_for_step2(
        data_root,
        explicit_step1_run_id=prerequisite_step1_run_id,
    )
    if not lineage.get("ok"):
        err = str(lineage.get("error") or "step2_lineage_unresolved")
        _emit_step2_denied(
            reason=err,
            context={
                "data_root_canonical": want_root,
                "explicit_prerequisite_step1_run_id": prerequisite_step1_run_id,
            },
        )
        return {"ok": False, "error": err}
    runtime = resolve_parallel_runtime(max_workers, strategy=f"{worker_mode}_pool")
    step2_cfg = step2_config.config_snapshot()
    cpu_governor = _build_step2_cpu_governor(step2_cfg, runtime.effective_workers)
    workflow_id = "model_v1_step2_train_rules"
    run_id = create_workflow_run(
        workflow_id=workflow_id,
        step_name="step2",
        requested_by=requested_by,
        worker_mode=worker_mode,
        requested_workers=runtime.requested_workers,
        effective_workers=runtime.effective_workers,
    )
    _set_run_state(
        run_id,
        {
            "run_id": run_id,
            "workflow_id": workflow_id,
            "step": "step2",
            "status": "queued",
            "worker_mode": worker_mode,
            "requested_workers": runtime.requested_workers,
            "effective_workers": runtime.effective_workers,
            "host_cpu_governor": cpu_governor,
            "queued_tasks": 1 + 1 + 5 + 16 + len(STEP2_RULE_SCOPES) + 2,
            "running_tasks": 0,
            "completed_tasks": 0,
            "failed_tasks": 0,
            "started_at_utc": _now(),
            "prerequisite_step1_run_id": lineage.get("step1_run_id"),
            "step1_lineage_hash": lineage.get("step1_lineage_hash"),
            "model_id": "",
            "model_version": model_version,
            "execution_mode": execution_mode,
            "queue_state": {"status": "waiting_for_heavy_slot"},
        },
    )
    th = threading.Thread(
        target=_run_step2_with_heavy_slot,
        kwargs={
            "run_id": run_id,
            "workflow_id": workflow_id,
            "data_root": data_root,
            "train_script": train_script,
            "evaluate_script": evaluate_script,
            "shap_script": shap_script,
            "rules_script": rules_script,
            "worker_mode": worker_mode,
            "effective_workers": runtime.effective_workers,
            "step1_lineage": lineage,
            "model_version": model_version,
            "execution_mode": execution_mode,
        },
        daemon=True,
    )
    with _RUN_LOCK:
        _RUN_THREADS[run_id] = th
    th.start()
    return {
        "ok": True,
        "run_id": run_id,
        "workflow_id": workflow_id,
        "status": "queued",
        "prerequisite_step1_run_id": lineage.get("step1_run_id"),
        "step1_lineage_hash": lineage.get("step1_lineage_hash"),
        "model_version": model_version,
        "execution_mode": execution_mode,
    }


def _run_step2(
    *,
    run_id: str,
    workflow_id: str,
    data_root: Path,
    train_script: Path,
    evaluate_script: Path,
    shap_script: Path,
    rules_script: Path,
    worker_mode: str,
    effective_workers: int,
    step1_lineage: dict[str, Any],
    model_version: str,
    execution_mode: str,
    queue_state: dict[str, Any] | None = None,
) -> None:
    cfg = step2_config.config_snapshot()
    cpu_governor = _build_step2_cpu_governor(cfg, effective_workers)
    cpu_telemetry: dict[str, Any] = {"training": [], "testing": [], "shap": [], "rule_generation": []}
    model_layout = ensure_model_artifact_layout(data_root, model_version)
    experiment_id = "exp_model_v1_enterprise_baseline"
    timeline: list[dict[str, Any]] = []
    gate_failures: list[str] = []
    canonical_model_id = ""

    def phase_patch(phase: str, phase_status: str, **kw: Any) -> None:
        timeline.append({"phase": phase, "status": phase_status, "at": _now()})
        _patch_run_state(
            run_id,
            {
                "current_phase": phase,
                "phase_status": phase_status,
                "step2_config": cfg,
                "host_cpu_governor": cpu_governor,
                **kw,
            },
        )

    def _compose_metrics(extra: dict[str, Any] | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model_id": canonical_model_id,
            "model_version": model_version,
            "execution_mode": execution_mode,
            "step2_config": cfg,
            "cpu_governor": cpu_governor,
            "cpu_telemetry": cpu_telemetry,
            "step2_timeline": timeline,
            "effective_parallelism": {},
            "prerequisite_step1_run_id": step1_lineage.get("step1_run_id"),
            "step1_lineage_hash": step1_lineage.get("step1_lineage_hash"),
            "step1_completed_at_utc": step1_lineage.get("step1_completed_at_utc"),
            "data_root_canonical": _canonical_data_root(data_root),
            "queue_state": queue_state or {"status": "acquired_without_queue"},
            "step3_cpu_governance": _step3_cpu_governance_placeholder(),
        }
        if extra:
            payload.update(extra)
        return payload

    def _build_testing_artifacts(
        *,
        testing_rows: list[dict[str, Any]],
        cross_gate_report: dict[str, Any],
        primary_track: str,
    ) -> dict[str, Any]:
        deltas_local = _compute_cross_dataset_deltas(testing_rows)
        within_local: dict[str, Any] = {}
        cross_local: dict[str, Any] = {}
        confusion_rows: dict[str, Any] = {}

        for row in testing_rows:
            et = str(row.get("eval_target") or "")
            rm = row.get("metrics") if isinstance(row.get("metrics"), dict) else {}
            if et == "ent01_holdout":
                within_local = {
                    **(rm.get("within_dataset_results") or {}),
                    "model_id": canonical_model_id,
                    "model_version": model_version,
                }
            else:
                cross_local[et] = {
                    **(rm.get("cross_dataset_results") or {}),
                    "model_id": canonical_model_id,
                    "model_version": model_version,
                }

            track_rows: dict[str, Any] = {}
            track_payloads = rm.get("model_track_results") if isinstance(rm.get("model_track_results"), dict) else {}
            for track_name, track_payload in track_payloads.items():
                if not isinstance(track_payload, dict):
                    continue
                track_metrics = track_payload.get("metrics") if isinstance(track_payload.get("metrics"), dict) else {}
                track_rows[str(track_name)] = {
                    "labels": track_metrics.get("labels"),
                    "confusion_matrix": track_metrics.get("confusion_matrix"),
                    "support": track_metrics.get("support"),
                    "macro_f1": track_metrics.get("macro_f1"),
                    "fpr": track_metrics.get("fpr"),
                    "fnr": track_metrics.get("fnr"),
                }
            if track_rows:
                confusion_rows[et] = track_rows

        for target, per_track in deltas_local.items():
            row = cross_local.get(target) or {}
            table = row.get("table_4_2_rows") if isinstance(row, dict) else None
            if isinstance(table, dict):
                for track_name, d in per_track.items():
                    if isinstance(table.get(track_name), dict):
                        table[track_name]["fpr_delta_vs_ent01"] = d.get("fpr_delta_vs_ent01")
                        table[track_name]["fnr_delta_vs_ent01"] = d.get("fnr_delta_vs_ent01")

        degradation_report_path = Path(model_layout["evaluation"]) / f"step2_degradation_report__{run_id}.json"
        confusion_metrics_path = Path(model_layout["evaluation"]) / f"step2_confusion_metrics__{run_id}.json"
        write_json_artifact(
            degradation_report_path,
            {
                "model_id": canonical_model_id,
                "model_version": model_version,
                "run_id": run_id,
                "workflow_id": workflow_id,
                "generated_at_utc": _now(),
                "primary_supervised_model": primary_track,
                "cross_dataset_gate": cross_gate_report,
                "cross_dataset_deltas": deltas_local,
                "within_dataset_results": within_local,
                "cross_dataset_results": cross_local,
            },
        )
        write_json_artifact(
            confusion_metrics_path,
            {
                "model_id": canonical_model_id,
                "model_version": model_version,
                "run_id": run_id,
                "workflow_id": workflow_id,
                "generated_at_utc": _now(),
                "by_eval_target": confusion_rows,
            },
        )
        return {
            "cross_dataset_deltas": deltas_local,
            "within_dataset_results": within_local,
            "cross_dataset_results": cross_local,
            "degradation_report_path": str(degradation_report_path),
            "confusion_metrics_path": str(confusion_metrics_path),
        }

    ok_lineage, verr = _verify_step1_lineage_at_runtime(step1_lineage)
    if not ok_lineage:
        timeline.append({"phase": "lineage_verify", "status": "failed", "at": _now()})
        update_workflow_run(
            run_id,
            status="failed",
            run_metrics=_compose_metrics({"started_at_utc": _now(), "step2_lineage_verification_error": verr}),
            error_message=f"step2_lineage_verify_failed:{verr}",
            completed=True,
        )
        _emit_step2_denied(
            reason=f"step2_lineage_verify_failed:{verr}",
            context={"run_id": run_id, "workflow_id": workflow_id, **step1_lineage},
        )
        _patch_run_state(
            run_id,
            {
                "status": "failed",
                "current_phase": "lineage_verify",
                "phase_status": "failed",
                "failed_tasks": 1,
            },
        )
        return

    canonical_model_id, canonical_model_id_source = _resolve_step2_canonical_model_id(model_version)
    if not canonical_model_id:
        reason = "step2_model_id_unresolved"
        update_model_lifecycle(model_version, status="failed", last_error=reason, created_by_run_id=run_id)
        update_workflow_run(
            run_id,
            status="failed",
            run_metrics=_compose_metrics(
                {
                    "started_at_utc": _now(),
                    "model_id_resolution": {
                        "source": canonical_model_id_source,
                        "model_version": model_version,
                    },
                }
            ),
            error_message=reason,
            completed=True,
        )
        phase_patch("training", "failed", active_workers=0, reason=reason)
        return

    training_threads = max(
        1,
        min(
            int(cpu_governor.get("thread_target") or 1),
            int(cpu_governor.get("thread_budget_max") or 1),
            int(cpu_governor.get("effective_thread_cap") or 1),
        ),
    )
    update_workflow_run(
        run_id,
        status="running",
        run_metrics=_compose_metrics(
            {
                "started_at_utc": _now(),
                "effective_parallelism": {"training_threads": training_threads},
            }
        ),
    )
    phase_patch(
        "training",
        "running",
        active_workers=1,
        max_workers_phase=training_threads,
        allocated_threads=training_threads,
    )
    ok_train_input, train_input = _validate_training_input()
    if not ok_train_input:
        reason = str(train_input.get("reason") or "training_input_invalid")
        update_model_lifecycle(model_version, status="failed", last_error=reason, created_by_run_id=run_id)
        update_workflow_run(
            run_id,
            status="failed",
            run_metrics=_compose_metrics({"training_input": train_input}),
            error_message=reason,
            completed=True,
        )
        phase_patch("training", "failed", active_workers=0, reason=reason)
        return

    training_result = run_training_task(
        {
            "task_id": str(uuid.uuid4()),
            "train_script": str(train_script),
            "experiment_id": experiment_id,
            "model_id": canonical_model_id,
            "model_version": model_version,
            "run_id": run_id,
            "model_root": str(Path(model_layout["training"]).parent),
            "worker_count": 1,
            "training_threads": training_threads,
        }
    )
    cpu_telemetry["training"].append(
        {
            "phase": "training",
            "allocated_threads": training_threads,
            "host_cpu_utilization": _sample_host_cpu_utilization(float(cpu_governor.get("sample_interval_s") or 0.35)),
            "action": "steady",
            "reason": "exclusive_training_phase",
        }
    )
    training_metrics = training_result.get("metrics") or {}
    training_model_id = str(training_metrics.get("model_id") or "").strip()
    if _is_uuid_like(training_model_id) and training_model_id != canonical_model_id:
        reason = "step2_training_model_id_mismatch"
        update_model_lifecycle(model_version, status="failed", last_error=reason, created_by_run_id=run_id)
        update_workflow_run(
            run_id,
            status="failed",
            run_metrics=_compose_metrics(
                {
                    "training_result": training_result,
                    "model_id_resolution": {
                        "source": canonical_model_id_source,
                        "resolved_model_id": canonical_model_id,
                        "training_metrics_model_id": training_model_id,
                    },
                }
            ),
            error_message=reason,
            completed=True,
        )
        phase_patch("training", "failed", active_workers=0, reason=reason)
        return
    training_metrics["model_id"] = canonical_model_id
    training_result["model_id"] = canonical_model_id
    training_result["metrics"] = training_metrics
    insert_model_training_run(
        run_id=run_id,
        model_version=model_version,
        experiment_id=experiment_id,
        status=training_result["status"],
        train_dataset_filter="dataset_source='ENT-01' AND split_name='train'",
        worker_mode=worker_mode,
        worker_count=1,
        metrics_json=training_metrics,
        model_id=canonical_model_id,
        source_step1_run_id=str(step1_lineage.get("step1_run_id") or ""),
        workflow_id=workflow_id,
        source_step1_lineage_hash=str(step1_lineage.get("step1_lineage_hash") or ""),
    )
    if not training_result.get("ok"):
        update_model_lifecycle(model_version, status="failed", last_error="training_failed", created_by_run_id=run_id)
        update_workflow_run(
            run_id,
            status="failed",
            run_metrics=_compose_metrics({"training_result": training_result}),
            error_message="training_failed",
            completed=True,
        )
        phase_patch("training", "failed", active_workers=0)
        return

    required_keys = [
        "model_tracks",
        "split_artifacts",
        "primary_supervised_model",
        "model_artifact_path",
        "preprocessing_artifact_path",
        "feature_list_path",
        "training_metrics_path",
        "label_column",
        "feature_count",
        "row_count",
        "source_row_counts",
        "loaded_row_counts",
        "data_completeness",
    ]
    missing_keys = [k for k in required_keys if training_metrics.get(k) in (None, "", {}, [])]
    if missing_keys:
        reason = f"training_contract_missing:{','.join(missing_keys)}"
        update_model_lifecycle(model_version, status="failed", last_error=reason, created_by_run_id=run_id)
        update_workflow_run(
            run_id,
            status="failed",
            run_metrics=_compose_metrics({"training_result": training_result}),
            error_message=reason,
            completed=True,
        )
        phase_patch("training", "failed", active_workers=0, reason=reason)
        return

    model_tracks = training_metrics.get("model_tracks") or {}
    split_artifacts = training_metrics.get("split_artifacts") or {}
    primary_supervised_model = str(training_metrics.get("primary_supervised_model") or "random_forest")
    label_column = str(training_metrics.get("label_column") or "label_harmonized")
    random_seed = int(training_metrics.get("random_seed") or cfg.get("PROJECT_STEP2_RANDOM_SEED") or 42)

    if not isinstance(model_tracks, dict) or not model_tracks:
        reason = "training_contract_model_tracks_missing"
        update_model_lifecycle(model_version, status="failed", last_error=reason, created_by_run_id=run_id)
        update_workflow_run(run_id, status="failed", run_metrics=_compose_metrics({"training_result": training_result}), error_message=reason, completed=True)
        phase_patch("training", "failed", active_workers=0, reason=reason)
        return

    data_complete_ok, data_completeness_report, data_completeness_reason = _evaluate_training_data_completeness(
        training_metrics
    )
    if not data_complete_ok:
        write_audit_event(
            event_type="step2_training_data_completeness_failed",
            actor=_actor(),
            artifact_refs=[],
            context={
                "run_id": run_id,
                "workflow_id": workflow_id,
                "data_completeness": data_completeness_report,
            },
            experiment_id=experiment_id,
            model_version=model_version,
        )
        update_model_lifecycle(model_version, status="failed", last_error=data_completeness_reason, created_by_run_id=run_id)
        update_workflow_run(
            run_id,
            status="failed",
            run_metrics=_compose_metrics(
                {
                    "training_result": training_result,
                    "training_data_completeness": data_completeness_report,
                }
            ),
            error_message=data_completeness_reason,
            completed=True,
        )
        phase_patch("training", "failed", active_workers=0, reason=data_completeness_reason)
        return

    expected_tracks = ["random_forest", "xgboost", "lightgbm", "isolation_forest"]
    for track in expected_tracks:
        if track not in model_tracks:
            reason = f"training_contract_missing_track:{track}"
            update_model_lifecycle(model_version, status="failed", last_error=reason, created_by_run_id=run_id)
            update_workflow_run(run_id, status="failed", run_metrics=_compose_metrics({"training_result": training_result}), error_message=reason, completed=True)
            phase_patch("training", "failed", active_workers=0, reason=reason)
            return

    split_paths = {}
    for split in ("train", "validation", "test"):
        p = str((split_artifacts.get(split) or {}).get("path") or "").strip()
        split_paths[split] = p
        if not p or not Path(p).exists():
            reason = f"split_snapshot_missing:{split}"
            update_model_lifecycle(model_version, status="failed", last_error=reason, created_by_run_id=run_id)
            update_workflow_run(run_id, status="failed", run_metrics=_compose_metrics({"training_result": training_result}), error_message=reason, completed=True)
            phase_patch("training", "failed", active_workers=0, reason=reason)
            return

    for track_name, track in model_tracks.items():
        if not isinstance(track, dict):
            reason = f"training_contract_invalid_track:{track_name}"
            update_model_lifecycle(model_version, status="failed", last_error=reason, created_by_run_id=run_id)
            update_workflow_run(run_id, status="failed", run_metrics=_compose_metrics({"training_result": training_result}), error_message=reason, completed=True)
            phase_patch("training", "failed", active_workers=0, reason=reason)
            return
        for key in ("model_artifact_path", "preprocessing_artifact_path", "feature_list_path", "training_metadata_path"):
            v = str(track.get(key) or "").strip()
            if not v or not Path(v).exists():
                reason = f"training_contract_track_artifact_missing:{track_name}:{key}"
                update_model_lifecycle(model_version, status="failed", last_error=reason, created_by_run_id=run_id)
                update_workflow_run(run_id, status="failed", run_metrics=_compose_metrics({"training_result": training_result}), error_message=reason, completed=True)
                phase_patch("training", "failed", active_workers=0, reason=reason)
                return

    primary_track_payload = _first_track_result(model_tracks, primary_supervised_model)
    primary_feature_list_path = str((primary_track_payload or {}).get("feature_list_path") or "").strip()
    if primary_feature_list_path:
        try:
            raw = json.loads(Path(primary_feature_list_path).read_text(encoding="utf-8"))
            if isinstance(raw, list):
                training_metrics.setdefault("candidate_feature_count_before_selection", int(len(raw)))
            elif isinstance(raw, dict):
                for key in ("features", "feature_list", "columns", "feature_names"):
                    vals = raw.get(key)
                    if isinstance(vals, list):
                        training_metrics.setdefault("candidate_feature_count_before_selection", int(len(vals)))
                        break
        except Exception:
            pass

    quality_ok, quality_gate, quality_reason = _evaluate_supervised_training_quality(
        model_tracks=model_tracks,
        cfg=cfg,
    )
    if not quality_ok:
        write_audit_event(
            event_type="step2_training_quality_gate_failed",
            actor=_actor(),
            artifact_refs=[],
            context={
                "run_id": run_id,
                "workflow_id": workflow_id,
                "quality_gate": quality_gate,
            },
            experiment_id=experiment_id,
            model_version=model_version,
        )
        update_model_lifecycle(model_version, status="failed", last_error=quality_reason, created_by_run_id=run_id)
        update_workflow_run(
            run_id,
            status="failed",
            run_metrics=_compose_metrics(
                {
                    "training_result": training_result,
                    "training_quality_gate": quality_gate,
                }
            ),
            error_message=quality_reason,
            completed=True,
        )
        phase_patch("training", "failed", active_workers=0, reason=quality_reason)
        return

    primary_track = model_tracks.get(primary_supervised_model) or {}
    model_artifact_path = str(primary_track.get("model_artifact_path") or training_metrics.get("model_artifact_path") or "").strip()
    model_artifact = Path(model_artifact_path) if model_artifact_path else None
    valid_artifact, artifact_error = _validate_non_placeholder_artifact(model_artifact)
    if not valid_artifact:
        update_model_lifecycle(model_version, status="failed", last_error=artifact_error, created_by_run_id=run_id)
        update_workflow_run(
            run_id,
            status="failed",
            run_metrics=_compose_metrics({"training_result": training_result}),
            error_message=artifact_error,
            completed=True,
        )
        phase_patch("training", "failed", active_workers=0, reason=artifact_error)
        return

    phase_patch("training", "completed", active_workers=0, model_artifact_path=model_artifact_path)
    update_model_lifecycle(model_version, status="trained", model_artifact_path=model_artifact_path, created_by_run_id=run_id)

    phase_patch("freeze", "running", active_workers=0)
    candidate_freeze_path = Path(model_layout["training"]) / f"model_v1_candidate_frozen__{run_id}.json"
    freeze_payload = {
        "run_id": run_id,
        "workflow_id": workflow_id,
        "model_id": canonical_model_id,
        "model_version": model_version,
        "experiment_id": experiment_id,
        "stage": "candidate_freeze",
        "frozen_at_utc": _now(),
        "prerequisite_step1_run_id": step1_lineage.get("step1_run_id"),
        "step1_lineage_hash": step1_lineage.get("step1_lineage_hash"),
        "train_filter": "dataset_source='ENT-01' AND split_name='train'",
        "primary_supervised_model": primary_supervised_model,
        "label_column": label_column,
        "random_seed": random_seed,
        "feature_count": int(training_metrics.get("feature_count") or 0),
        "split_artifacts": split_artifacts,
        "model_tracks": model_tracks,
        "base_model_artifact_path": model_artifact_path,
        "training_summary_path": str(training_metrics.get("training_metrics_path") or ""),
        "training_data_completeness": data_completeness_report,
        "training_quality_gate": quality_gate,
    }
    frozen_manifest_path = freeze_model_artifact(candidate_freeze_path, freeze_payload)
    phase_patch("freeze", "completed", model_artifact_path=frozen_manifest_path)
    write_audit_event(
        event_type="step2_model_frozen_candidate",
        actor=_actor(),
        artifact_refs=[frozen_manifest_path],
        context={"run_id": run_id, "workflow_id": workflow_id, "stage": "candidate_freeze"},
        experiment_id=experiment_id,
        model_version=model_version,
    )

    phase_patch("verifier", "running", active_workers=1, max_workers_phase=1)
    verifier_report_out = Path(data_root) / "outputs" / "model_integrity_reports"
    verifier_result = run_integrity_verifier_task(
        {
            "task_id": str(uuid.uuid4()),
            "verify_script": str(Path(__file__).resolve().parents[2] / "scripts" / "verify_step2_model_integrity.py"),
            "model_id": canonical_model_id,
            "model_version": model_version,
            "run_id": run_id,
            "data_root": str(data_root),
            "outputs_root": str(Path(data_root) / "outputs"),
            "report_out": str(verifier_report_out),
            "manifest": frozen_manifest_path,
            "stage": "pre_freeze",
        }
    )
    verifier_metrics = verifier_result.get("metrics") or {}
    integrity_verdict = str(verifier_metrics.get("verdict") or "UNKNOWN").upper()
    normalized_warnings = _collect_normalized_warnings(
        str(training_result.get("stderr_tail") or ""),
        str(verifier_result.get("stderr_tail") or ""),
        str(verifier_result.get("stdout_tail") or ""),
    )
    gate_action = "allow" if integrity_verdict == "PASS" else "block"
    integrity_block = {
        "model_id": canonical_model_id,
        "model_version": model_version,
        "stage": "pre_freeze",
        "verdict": integrity_verdict,
        "json_report": verifier_metrics.get("json_report"),
        "markdown_report": verifier_metrics.get("markdown_report"),
        "gate_action": gate_action,
        "verifier_returncode": verifier_result.get("returncode"),
        "verifier_stdout_tail": verifier_result.get("stdout_tail"),
        "verifier_stderr_tail": verifier_result.get("stderr_tail"),
        "verifier_error_message": verifier_metrics.get("error_message"),
        "verifier_error_type": verifier_metrics.get("error_type"),
        "normalized_warnings": normalized_warnings,
    }
    verifier_issues = verifier_metrics.get("issues")
    if isinstance(verifier_issues, list):
        warn_labels: list[str] = []
        fail_labels: list[str] = []
        fail_messages: list[str] = []
        for row in verifier_issues:
            if not isinstance(row, dict):
                continue
            level = str(row.get("level") or "").upper()
            if level not in {"WARN", "FAIL"}:
                continue
            check = str(row.get("check") or "unknown_check").strip() or "unknown_check"
            if level == "WARN":
                warn_labels.append(f"integrity_warn:{check}")
            if level == "FAIL":
                fail_labels.append(f"integrity_fail:{check}")
                msg = str(row.get("message") or "").strip()
                if msg:
                    fail_messages.append(msg)
        if warn_labels:
            integrity_block["warning_checks"] = sorted(set(warn_labels))
        if fail_labels:
            integrity_block["failure_checks"] = sorted(set(fail_labels))
        if fail_messages:
            integrity_block["failure_messages"] = sorted(set(fail_messages))
    phase_patch("verifier", "completed" if verifier_result.get("ok") else "failed", active_workers=0, integrity_verification=integrity_block)
    if not verifier_result.get("ok"):
        reason = "integrity_gate_execution_failed"
        update_model_lifecycle(model_version, status="failed", model_artifact_path=frozen_manifest_path, last_error=reason, created_by_run_id=run_id)
        update_workflow_run(
            run_id,
            status="failed",
            run_metrics=_compose_metrics(
                {
                    "training_result": training_result,
                    "integrity_verification": integrity_block,
                    "integrity_verifier_result": verifier_result,
                }
            ),
            error_message=reason,
            completed=True,
        )
        return
    if integrity_verdict != "PASS":
        reason = "integrity_gate_not_pass"
        gate_failures.append(f"integrity_verdict:{integrity_verdict}")
        warning_checks = integrity_block.get("warning_checks")
        if isinstance(warning_checks, list):
            gate_failures.extend([str(x) for x in warning_checks if str(x).strip()])
        failure_checks = integrity_block.get("failure_checks")
        if isinstance(failure_checks, list):
            gate_failures.extend([str(x) for x in failure_checks if str(x).strip()])
        write_audit_event(
            event_type="integrity_gate_failed",
            actor=_actor(),
            artifact_refs=[str(x) for x in [integrity_block.get("json_report"), integrity_block.get("markdown_report"), frozen_manifest_path] if x],
            context={
                "run_id": run_id,
                "workflow_id": workflow_id,
                "integrity_verification": integrity_block,
                "gate_failures": gate_failures,
            },
            experiment_id=experiment_id,
            model_version=model_version,
        )
        update_model_lifecycle(model_version, status="failed", model_artifact_path=frozen_manifest_path, last_error=reason, created_by_run_id=run_id)
        update_workflow_run(
            run_id,
            status="failed",
            run_metrics=_compose_metrics(
                {
                    "training_result": training_result,
                    "model_tracks": model_tracks,
                    "integrity_verification": integrity_block,
                    "frozen_manifest_path": frozen_manifest_path,
                    "gate_failures": gate_failures,
                }
            ),
            error_message=reason,
            completed=True,
        )
        return

    test_tasks = plan_step2_testing_tasks(workflow_id=workflow_id, run_id=run_id)
    test_worker_threads = max(
        1,
        min(
            20,
            int(cpu_governor.get("thread_budget_max") or 1),
        ),
    )
    rows_per_thread = 25000
    for t in test_tasks:
        t["evaluate_script"] = str(evaluate_script)
        t["worker_count"] = 1
        t["worker_threads"] = test_worker_threads
        t["eval_worker_threads"] = test_worker_threads
        t["rows_per_thread"] = rows_per_thread
        t["experiment_id"] = experiment_id
        t["model_id"] = canonical_model_id
        t["model_version"] = model_version
        t["frozen_manifest"] = frozen_manifest_path
    # Evaluation phase contract: one target process at a time.
    test_cap = 1
    phase_patch(
        "testing",
        "running",
        active_workers=min(1, test_cap),
        max_workers_phase=test_cap,
        allocated_threads=test_worker_threads,
    )
    testing_results, testing_cpu_rounds = _run_phase_batches(
        phase="testing",
        tasks=test_tasks,
        fn=run_testing_task,
        worker_mode=worker_mode,
        worker_threads=test_worker_threads,
        phase_max_workers=test_cap,
        governor=cpu_governor,
        phase_patch=phase_patch,
    )
    cpu_telemetry["testing"] = testing_cpu_rounds

    holdout_result = None
    for row in testing_results:
        et = str(row.get("eval_target") or "")
        row_metrics = row.get("metrics") if isinstance(row.get("metrics"), dict) else {}
        track_metrics = row_metrics.get("model_track_results") if isinstance(row_metrics.get("model_track_results"), dict) else {}
        if et == "ent01_holdout":
            insert_model_evaluation_run(
                run_id=run_id,
                model_version=model_version,
                experiment_id=experiment_id,
                dataset_id="ENT-01",
                split_name="test",
                status=str(row.get("status") or "failed"),
                metrics_json={
                    **(row.get("metrics") or {}),
                    "eval_target": et,
                    "task_error": row.get("error"),
                    "task_returncode": row.get("returncode"),
                    "task_stderr_tail": row.get("stderr_tail"),
                    "task_stdout_tail": row.get("stdout_tail"),
                },
                model_id=canonical_model_id,
                source_step1_run_id=str(step1_lineage.get("step1_run_id") or ""),
                workflow_id=workflow_id,
                source_step1_lineage_hash=str(step1_lineage.get("step1_lineage_hash") or ""),
            )
            for track_name, track_payload in track_metrics.items():
                if not isinstance(track_payload, dict):
                    continue
                tm = track_payload.get("metrics")
                if not isinstance(tm, dict):
                    continue
                try:
                    insert_model_per_class_metrics(
                        run_id=run_id,
                        model_version=model_version,
                        experiment_id=experiment_id,
                        dataset_id="ENT-01",
                        split_name="test",
                        evaluation_mode="within_dataset",
                        eval_target=et,
                        model_track=str(track_name),
                        metrics=tm,
                        model_id=canonical_model_id,
                    )
                except Exception as exc:
                    gate_failures.append(f"per_class_metrics_insert_failed:{et}:{track_name}:{exc}")
            holdout_result = row
        else:
            ds_map = {
                "dns01": ("DNS-01", "cross_test"),
                "iot01": ("IOT-01", "cross_test"),
                "ent02_support": ("ENT-02", "support_test"),
                "iot02_support": ("IOT-02", "support_test"),
            }
            ds_id, mode = ds_map.get(et, ("unknown", "unknown"))
            insert_cross_dataset_test_run(
                run_id=run_id,
                model_version=model_version,
                experiment_id=experiment_id,
                dataset_id=ds_id,
                evaluation_mode=mode,
                status=str(row.get("status") or "failed"),
                metrics_json={
                    **(row.get("metrics") or {}),
                    "eval_target": et,
                    "task_error": row.get("error"),
                    "task_returncode": row.get("returncode"),
                    "task_stderr_tail": row.get("stderr_tail"),
                    "task_stdout_tail": row.get("stdout_tail"),
                },
                model_id=canonical_model_id,
                source_step1_run_id=str(step1_lineage.get("step1_run_id") or ""),
                workflow_id=workflow_id,
                source_step1_lineage_hash=str(step1_lineage.get("step1_lineage_hash") or ""),
            )
            for track_name, track_payload in track_metrics.items():
                if not isinstance(track_payload, dict):
                    continue
                tm = track_payload.get("metrics")
                if not isinstance(tm, dict):
                    continue
                try:
                    insert_model_per_class_metrics(
                        run_id=run_id,
                        model_version=model_version,
                        experiment_id=experiment_id,
                        dataset_id=ds_id,
                        split_name=mode,
                        evaluation_mode=mode,
                        eval_target=et,
                        model_track=str(track_name),
                        metrics=tm,
                        model_id=canonical_model_id,
                    )
                except Exception as exc:
                    gate_failures.append(f"per_class_metrics_insert_failed:{et}:{track_name}:{exc}")

    holdout_prediction_count = 0
    holdout_ok = bool(holdout_result and holdout_result.get("ok"))
    if holdout_result and isinstance(holdout_result.get("metrics"), dict):
        holdout_prediction_count = int((holdout_result.get("metrics") or {}).get("prediction_count") or 0)
        model_track_results = (holdout_result.get("metrics") or {}).get("model_track_results") or {}
        if isinstance(model_track_results, dict):
            supervised_track_ok = [
                bool(v.get("ok"))
                for k, v in model_track_results.items()
                if k != "isolation_forest" and isinstance(v, dict)
            ]
            if supervised_track_ok and not all(supervised_track_ok):
                holdout_ok = False
    if holdout_prediction_count <= 0:
        holdout_ok = False

    primary_supervised_model = str(training_metrics.get("primary_supervised_model") or "random_forest")
    cross_dataset_gate_ok, cross_dataset_gate_report, cross_gate_failures = _evaluate_cross_dataset_gates(
        testing_results,
        primary_track=primary_supervised_model,
    )
    gate_failures.extend(cross_gate_failures)
    partial_testing = not all(r.get("ok") for r in testing_results)
    phase_patch(
        "testing",
        "completed" if (holdout_ok and cross_dataset_gate_ok) else "failed",
        active_workers=0,
        testing_partial=partial_testing,
        ent01_holdout_ok=holdout_ok,
        cross_dataset_gate_ok=cross_dataset_gate_ok,
    )
    testing_artifacts = _build_testing_artifacts(
        testing_rows=testing_results,
        cross_gate_report=cross_dataset_gate_report,
        primary_track=primary_supervised_model,
    )
    deltas = testing_artifacts.get("cross_dataset_deltas") or {}
    dissertation_within = testing_artifacts.get("within_dataset_results") or {}
    dissertation_cross = testing_artifacts.get("cross_dataset_results") or {}

    if not holdout_ok:
        update_model_lifecycle(model_version, status="failed", model_artifact_path=frozen_manifest_path, last_error="ent01_holdout_failed", created_by_run_id=run_id)
        update_workflow_run(
            run_id,
            status="failed",
            run_metrics=_compose_metrics(
                {
                    "training_result": training_result,
                    "integrity_verification": integrity_block,
                    "testing_results": testing_results,
                    "cross_dataset_gate": cross_dataset_gate_report,
                    "cross_dataset_deltas": deltas,
                    "within_dataset_results": dissertation_within,
                    "cross_dataset_results": dissertation_cross,
                    "gate_failures": gate_failures,
                    "model_artifact_path": frozen_manifest_path,
                    "degradation_report_path": testing_artifacts.get("degradation_report_path"),
                    "confusion_metrics_path": testing_artifacts.get("confusion_metrics_path"),
                }
            ),
            error_message="ent01_holdout_failed",
            completed=True,
        )
        return

    if not cross_dataset_gate_ok:
        update_model_lifecycle(
            model_version,
            status="failed",
            model_artifact_path=frozen_manifest_path,
            last_error="cross_dataset_gate_failed",
            created_by_run_id=run_id,
        )
        update_workflow_run(
            run_id,
            status="failed",
            run_metrics=_compose_metrics(
                {
                    "training_result": training_result,
                    "integrity_verification": integrity_block,
                    "testing_results": testing_results,
                    "cross_dataset_gate": cross_dataset_gate_report,
                    "cross_dataset_deltas": deltas,
                    "within_dataset_results": dissertation_within,
                    "cross_dataset_results": dissertation_cross,
                    "gate_failures": gate_failures,
                    "model_artifact_path": frozen_manifest_path,
                    "degradation_report_path": testing_artifacts.get("degradation_report_path"),
                    "confusion_metrics_path": testing_artifacts.get("confusion_metrics_path"),
                }
            ),
            error_message="cross_dataset_gate_failed",
            completed=True,
        )
        return

    shap_tasks = plan_step2_shap_chunk_tasks(workflow_id=workflow_id, run_id=run_id)
    shap_top_features_max = _safe_int(os.getenv("STEP2_SHAP_TOP_FEATURES_MAX") or 0)
    shap_worker_threads = max(1, step2_config.shap_worker_threads())
    for t in shap_tasks:
        t.update(
            {
                "shap_script": str(shap_script),
                "experiment_id": experiment_id,
                "model_id": canonical_model_id,
                "model_version": model_version,
                "worker_count": shap_worker_threads,
                "worker_threads": shap_worker_threads,
                "frozen_manifest": frozen_manifest_path,
                "top_k": shap_top_features_max,
            }
        )
    shap_cap = min(step2_config.shap_max_workers(), len(shap_tasks), int(cpu_governor.get("thread_budget_max") or 1))
    phase_patch(
        "shap",
        "running",
        active_workers=min(1, shap_cap),
        max_workers_phase=shap_cap,
        allocated_threads=min(shap_cap * shap_worker_threads, int(cpu_governor.get("thread_budget_max") or 1)),
    )
    shap_results, shap_cpu_rounds = _run_phase_batches(
        phase="shap",
        tasks=shap_tasks,
        fn=run_shap_task,
        worker_mode=worker_mode,
        worker_threads=shap_worker_threads,
        phase_max_workers=shap_cap,
        governor=cpu_governor,
        phase_patch=phase_patch,
    )
    cpu_telemetry["shap"] = shap_cpu_rounds
    for row in shap_results:
        chunk_path = Path(model_layout["shap"]) / f"shap__{row.get('partition_id') or 'chunk'}__{run_id}.json"
        row["artifact_path"] = str(chunk_path)
        ck = write_json_artifact(
            chunk_path,
            {
                "model_id": canonical_model_id,
                "model_version": model_version,
                "run_id": run_id,
                "partition_id": row.get("partition_id"),
                "split_name": row.get("split_name"),
                "metrics": row.get("metrics"),
                "frozen_manifest": frozen_manifest_path,
            },
        )
        insert_shap_artifact(
            run_id=run_id,
            model_version=model_version,
            dataset_id="ENT-01",
            split_name=str(row.get("split_name") or "unknown"),
            partition_id=str(row.get("partition_id") or ""),
            artifact_path=str(chunk_path),
            status=str(row.get("status") or "failed"),
            metadata={
                **(row.get("metrics") or {}),
                "model_id": canonical_model_id,
                "model_version": model_version,
                "checksum_sha256": ck,
                "frozen_manifest": frozen_manifest_path,
            },
            model_id=canonical_model_id,
            source_step1_run_id=str(step1_lineage.get("step1_run_id") or ""),
            workflow_id=workflow_id,
            source_step1_lineage_hash=str(step1_lineage.get("step1_lineage_hash") or ""),
        )
    try:
        shap_aggregate = _aggregate_shap_stage_metrics(
            shap_results,
            model_id=canonical_model_id,
            model_version=model_version,
            top_k=shap_top_features_max,
        )
        shap_db_writes = _persist_shap_metrics_to_db(
            run_id=run_id,
            workflow_id=workflow_id,
            experiment_id=experiment_id,
            model_id=canonical_model_id,
            model_version=model_version,
            frozen_manifest_path=frozen_manifest_path,
            shap_results=shap_results,
            shap_aggregate=shap_aggregate,
        )
    except Exception as exc:
        update_model_lifecycle(
            model_version,
            status="failed",
            model_artifact_path=frozen_manifest_path,
            last_error=f"shap_db_persist_failed:{exc}",
            created_by_run_id=run_id,
        )
        update_workflow_run(
            run_id,
            status="failed",
            run_metrics=_compose_metrics(
                {
                    "training_result": training_result,
                    "integrity_verification": integrity_block,
                    "testing_results": testing_results,
                    "shap_results": shap_results,
                    "model_artifact_path": frozen_manifest_path,
                }
            ),
            error_message="shap_db_persist_failed",
            completed=True,
        )
        phase_patch("shap", "failed", active_workers=0)
        return
    shap_ok = all(r.get("ok") for r in shap_results)
    phase_patch("shap", "completed" if shap_ok else "failed", active_workers=0)
    if not shap_ok:
        update_model_lifecycle(model_version, status="failed", model_artifact_path=frozen_manifest_path, last_error="shap_phase_failed", created_by_run_id=run_id)
        update_workflow_run(
            run_id,
            status="failed",
            run_metrics=_compose_metrics(
                {
                    "training_result": training_result,
                    "integrity_verification": integrity_block,
                    "testing_results": testing_results,
                    "shap_results": shap_results,
                    "model_artifact_path": frozen_manifest_path,
                }
            ),
            error_message="shap_phase_failed",
            completed=True,
        )
        return

    rule_inputs_path = Path(model_layout["evaluation"]) / f"step2_rule_inputs__{run_id}.json"
    write_json_artifact(
        rule_inputs_path,
        {
            "model_id": canonical_model_id,
            "model_version": model_version,
            "run_id": run_id,
            "workflow_id": workflow_id,
            "primary_supervised_model": str(training_metrics.get("primary_supervised_model") or "random_forest"),
            "cross_dataset_deltas": deltas,
            "testing_results": testing_results,
        },
    )

    rule_tasks = plan_step2_rule_tasks(workflow_id=workflow_id, run_id=run_id)
    rule_order = {scope: idx for idx, scope in enumerate(STEP2_RULE_SCOPES)}
    rule_tasks.sort(key=lambda t: rule_order.get(str(t.get("scope") or ""), 999))
    rule_worker_threads = max(1, step2_config.rule_worker_threads())
    detection_profile = str(os.getenv("STEP2_DETECTION_PROFILE", "high_recall")).strip().lower() or "high_recall"
    alert_threshold_profile = str(os.getenv("STEP2_ALERT_THRESHOLD_PROFILE", "aggressive")).strip().lower() or "aggressive"
    for t in rule_tasks:
        t.update(
            {
                "rules_script": str(rules_script),
                "experiment_id": experiment_id,
                "model_id": canonical_model_id,
                "model_version": model_version,
                "worker_count": rule_worker_threads,
                "worker_threads": rule_worker_threads,
                "frozen_manifest": frozen_manifest_path,
                "metrics_artifact": str(rule_inputs_path),
                "detection_profile": detection_profile,
                "alert_threshold_profile": alert_threshold_profile,
            }
        )
    rule_cap = min(step2_config.rule_max_workers(), len(rule_tasks))
    phase_patch(
        "rule_generation",
        "running",
        active_workers=min(1, rule_cap),
        max_workers_phase=rule_cap,
        allocated_threads=min(rule_cap * rule_worker_threads, int(cpu_governor.get("thread_budget_max") or 1)),
    )
    rule_results, rule_cpu_rounds = _run_phase_batches(
        phase="rule_generation",
        tasks=rule_tasks,
        fn=run_rule_task,
        worker_mode=worker_mode,
        worker_threads=rule_worker_threads,
        phase_max_workers=rule_cap,
        governor=cpu_governor,
        phase_patch=phase_patch,
    )
    cpu_telemetry["rule_generation"] = rule_cpu_rounds
    persisted_rule_counts: dict[str, int] = {}
    rule_insert_failures: list[str] = []
    rulepack_paths_by_scope: dict[str, str] = {}
    for row in rule_results:
        scope = str(row.get("scope") or "unknown")
        rules_payload = row.get("rules") if isinstance(row.get("rules"), list) else []
        artifact_path = Path(model_layout["rulepacks"]) / f"rulepack__{scope}__{run_id}.json"
        rulepack_paths_by_scope[scope] = str(artifact_path)
        checksum = write_json_artifact(
            artifact_path,
            {
                "model_id": canonical_model_id,
                "run_id": run_id,
                "workflow_id": workflow_id,
                "scope": scope,
                "model_version": model_version,
                "status": row.get("status"),
                "generated_at_utc": _now(),
                "frozen_manifest": frozen_manifest_path,
                "rule_count": int(row.get("rule_count") or len(rules_payload)),
                "checksums": row.get("checksums") or [],
                "rules": rules_payload,
                "errors": row.get("errors") or [],
            },
        )
        persisted_count = 0
        if row.get("ok"):
            for rule_row in rules_payload:
                if not isinstance(rule_row, dict):
                    continue
                checksum_sha256 = str(rule_row.get("checksum_sha256") or "").strip()
                if not checksum_sha256:
                    continue
                try:
                    upsert_rulepack_rule(
                        run_id=run_id,
                        workflow_id=workflow_id,
                        model_version=model_version,
                        rule_scope=scope,
                        rule_type=str(rule_row.get("rule_type") or "unspecified"),
                        condition_json=rule_row.get("condition_json") if isinstance(rule_row.get("condition_json"), dict) else {},
                        severity=str(rule_row.get("severity") or "medium"),
                        action=str(rule_row.get("action") or "monitor"),
                        evidence_sources=rule_row.get("evidence_sources") if isinstance(rule_row.get("evidence_sources"), list) else [],
                        status=str(rule_row.get("status") or "active"),
                        checksum_sha256=checksum_sha256,
                        model_id=canonical_model_id,
                        linked_model_version=str(rule_row.get("linked_model_version") or model_version),
                    )
                except Exception as exc:
                    rule_insert_failures.append(f"{scope}:rule_upsert_failed:{exc}")
            try:
                persisted_count = count_rulepack_rules(run_id=run_id, scope=scope)
            except Exception as exc:
                rule_insert_failures.append(f"{scope}:rule_count_failed:{exc}")
        insert_rulepack_registry(
            run_id=run_id,
            model_version=model_version,
            rulepack_version=f"model_v1.rules.{scope}.v1.0.0",
            scope=scope,
            status="completed" if row.get("ok") and persisted_count > 0 else "failed",
            artifact_path=str(artifact_path),
            checksum_sha256=checksum,
            metadata={
                **(row.get("metrics") or {}),
                "model_id": canonical_model_id,
                "model_version": model_version,
                "frozen_manifest": frozen_manifest_path,
                "rule_count": int(row.get("rule_count") or len(rules_payload)),
                "persisted_rule_count": persisted_count,
                "rule_errors": row.get("errors") or [],
            },
            model_id=canonical_model_id,
            source_step1_run_id=str(step1_lineage.get("step1_run_id") or ""),
            workflow_id=workflow_id,
            source_step1_lineage_hash=str(step1_lineage.get("step1_lineage_hash") or ""),
        )
        persisted_rule_counts[scope] = persisted_count
    required_scopes = set(STEP2_RULE_SCOPES)
    missing_rule_scopes = sorted([s for s in required_scopes if int(persisted_rule_counts.get(s) or 0) <= 0])
    rules_ok = all(r.get("ok") for r in rule_results) and len(rule_insert_failures) == 0 and len(missing_rule_scopes) == 0
    gate_failures.extend(rule_insert_failures)
    if missing_rule_scopes:
        gate_failures.append(f"missing_persisted_rule_scopes:{','.join(missing_rule_scopes)}")

    rep01_rule_validation = {
        "ok": False,
        "error": "rep01_validation_not_run",
        "sample_target": 100,
        "sampled_packets": 0,
        "intrusion_detected": False,
    }
    if rules_ok:
        rep01_rule_validation = _run_rep01_rule_validation(
            data_root=data_root,
            rulepack_dir=Path(model_layout["rulepacks"]),
            run_id=run_id,
            model_version=model_version,
            sample_packets=100,
        )
        if not rep01_rule_validation.get("ok"):
            rules_ok = False
            gate_failures.append("rep01_rule_validation_failed")
            if rep01_rule_validation.get("error"):
                gate_failures.append(f"rep01_validation_error:{rep01_rule_validation.get('error')}")
            if not bool(rep01_rule_validation.get("intrusion_detected")):
                gate_failures.append("rep01_intrusion_not_detected_on_100_packets")

    phase_patch("rule_generation", "completed" if rules_ok else "failed", active_workers=0)

    phase_patch("publishing", "running", active_workers=0)
    rules_published = False
    for row in rule_results:
        scope = str(row.get("scope") or "")
        if rules_ok and row.get("ok") and int(persisted_rule_counts.get(scope) or 0) > 0:
            mark_rulepack_published(run_id=run_id, scope=scope)
            rules_published = True
    phase_patch("publishing", "completed" if rules_ok else "failed")

    cross_dataset_ok = cross_dataset_gate_ok
    core_pipeline_ok = bool(training_result.get("ok")) and integrity_verdict == "PASS" and holdout_ok and cross_dataset_ok and shap_ok and rules_ok

    finalize_payload = {
        "model_id": canonical_model_id,
        "model_version": model_version,
        "trained": True,
        "candidate_frozen": True,
        "integrity_gate_verdict": integrity_verdict,
        "evaluated": holdout_ok,
        "shap_ok": shap_ok,
        "rules_published": rules_published and rules_ok,
        "cross_dataset_ok": cross_dataset_ok,
        "ready_for_step3_scaffold": core_pipeline_ok,
        "frozen_manifest_path": frozen_manifest_path,
    }
    finalize_path = Path(model_layout["dashboard_state"]) / f"step2_finalize__{run_id}.json"
    write_json_artifact(
        finalize_path,
        {
            "model_id": canonical_model_id,
            "model_version": model_version,
            "run_id": run_id,
            "status": finalize_payload,
        },
    )

    shap_stage_metrics = {
        "model_id": canonical_model_id,
        "model_version": model_version,
        "table_4_5_linkage_ready": shap_ok,
        "artifact_count": len(shap_results),
        "frozen_manifest_path": frozen_manifest_path,
        "db_write_counts": shap_db_writes,
        "coverage_by_split": shap_aggregate.get("explanation_coverage_by_split"),
        "row_count_by_split": shap_aggregate.get("row_count_by_split"),
        "chunk_feature_coverage": shap_aggregate.get("chunk_feature_coverage"),
        "top_feature_consistency": shap_aggregate.get("top_feature_consistency"),
        "explanation_recurrence_signature_policy": shap_aggregate.get("explanation_recurrence_signature_policy"),
        "explanation_recurrence_repeated_patterns": shap_aggregate.get("explanation_recurrence_repeated_patterns"),
        "explanation_recurrence_total_patterns": shap_aggregate.get("explanation_recurrence_total_patterns"),
        "explanation_recurrence_score": shap_aggregate.get("explanation_recurrence_score"),
        "global_top_features": shap_aggregate.get("global_top_features"),
        "weighted_mean_abs_shap_total": shap_aggregate.get("weighted_mean_abs_shap_total"),
        "offline_compute_duration_s": shap_aggregate.get("total_duration_s"),
        "runtime_evidence_mode": "measured_only",
    }
    rule_validation_summary = {
        "model_id": canonical_model_id,
        "model_version": model_version,
        "table_4_7_linkage_ready": rules_ok,
        "artifact_count": len(rule_results),
        "persisted_rule_counts_by_scope": persisted_rule_counts,
        "rulepack_paths_by_scope": rulepack_paths_by_scope,
        "missing_rule_scopes": missing_rule_scopes,
        "rule_insert_failures": rule_insert_failures,
        "rep01_packet_validation": rep01_rule_validation,
        "frozen_manifest_path": frozen_manifest_path,
    }
    governance_traceability = {
        "model_id": canonical_model_id,
        "model_version": model_version,
        "h1_5_traceability_ready": bool(step1_lineage.get("step1_run_id")) and bool(step1_lineage.get("step1_lineage_hash")),
        "source_step1_run_id": step1_lineage.get("step1_run_id"),
        "step1_lineage_hash": step1_lineage.get("step1_lineage_hash"),
        "integrity_gate": integrity_block,
        "gate_failures": gate_failures,
    }
    metrics_principle_update = _build_step2_metrics_principle_update(
        primary_track=primary_supervised_model,
        within_dataset_results=dissertation_within,
        cross_dataset_results=dissertation_cross,
        training_metrics=training_metrics,
        testing_results=testing_results,
        shap_stage_metrics=shap_stage_metrics,
        rep01_rule_validation=rep01_rule_validation,
    )
    metrics_map = metrics_principle_update.get("metrics") if isinstance(metrics_principle_update.get("metrics"), dict) else {}

    def _metric_value(name: str) -> Any:
        row = metrics_map.get(name)
        if not isinstance(row, dict):
            return None
        return row.get("value")

    training_metrics.setdefault("feature_reduction_ratio", _metric_value("feature_reduction_ratio"))
    rule_validation_summary.update(
        {
            "rule_hit_rate": _metric_value("rule_hit_rate"),
        }
    )
    shap_stage_metrics["explanation_recurrence_score"] = (
        _metric_value("explanation_recurrence_score")
        if _metric_value("explanation_recurrence_score") is not None
        else shap_stage_metrics.get("explanation_recurrence_score")
    )

    all_parts = [training_result] + testing_results + shap_results + rule_results
    failed = [x for x in all_parts if not x.get("ok")]
    status = "completed" if core_pipeline_ok else "failed"
    effective_parallelism = {
        "training_threads": training_threads,
        "testing": {"max_workers": test_cap, "worker_threads": test_worker_threads},
        "shap": {"max_workers": shap_cap, "worker_threads": shap_worker_threads},
        "rule_generation": {"max_workers": rule_cap, "worker_threads": rule_worker_threads},
    }

    phase_patch("finalize", "completed" if core_pipeline_ok else "failed", active_workers=0)
    metrics_path = Path(model_layout["evaluation"]) / f"step2_metrics__{run_id}.json"
    metrics_payload: dict[str, Any] = {
        "model_id": canonical_model_id,
        "model_version": model_version,
        "run_id": run_id,
        "workflow_id": workflow_id,
        "status": status,
        "cpu_governor": cpu_governor,
        "cpu_telemetry": cpu_telemetry,
        "queue_state": queue_state or {"status": "acquired_without_queue"},
        "effective_parallelism": effective_parallelism,
        "training_result": training_result,
        "model_tracks": model_tracks,
        "integrity_verification": integrity_block,
        "frozen_manifest_path": frozen_manifest_path,
        "testing_results": testing_results,
        "cross_dataset_gate": cross_dataset_gate_report,
        "degradation_report_path": testing_artifacts.get("degradation_report_path"),
        "confusion_metrics_path": testing_artifacts.get("confusion_metrics_path"),
        "shap_results": shap_results,
        "rule_results": rule_results,
        "within_dataset_results": dissertation_within,
        "cross_dataset_results": dissertation_cross,
        "cross_dataset_deltas": deltas,
        "shap_stage_metrics": shap_stage_metrics,
        "rule_validation_summary": rule_validation_summary,
        "governance_traceability": governance_traceability,
        "cross_dataset_robustness": _metric_value("cross_dataset_robustness"),
        "inference_latency_ms": _metric_value("inference_latency_ms"),
        "metrics_principle_review_update": metrics_principle_update,
        "finalize": finalize_payload,
        "gate_failures": gate_failures,
        "failed_count": len(failed),
        "model_artifact": frozen_manifest_path,
        "step2_timeline": timeline,
        "step3_cpu_governance": _step3_cpu_governance_placeholder(),
    }
    write_json_artifact(metrics_path, metrics_payload)
    metrics_payload["metrics_artifact_path"] = str(metrics_path)
    persist_dissertation_metrics_ref(metrics_payload)

    update_workflow_run(
        run_id,
        status=status,
        run_metrics={
            "metrics_artifact_path": str(metrics_path),
            "model_artifact_path": frozen_manifest_path,
            "finalize_path": str(finalize_path),
            "model_id": canonical_model_id,
            "model_version": model_version,
            "execution_mode": execution_mode,
            "failed_count": len(failed),
            "cpu_governor": cpu_governor,
            "cpu_telemetry": cpu_telemetry,
            "queue_state": queue_state or {"status": "acquired_without_queue"},
            "effective_parallelism": effective_parallelism,
            "model_tracks": model_tracks,
            "integrity_verification": integrity_block,
            "testing_results": testing_results,
            "cross_dataset_gate": cross_dataset_gate_report,
            "degradation_report_path": testing_artifacts.get("degradation_report_path"),
            "confusion_metrics_path": testing_artifacts.get("confusion_metrics_path"),
            "shap_results": shap_results,
            "rule_results": rule_results,
            "within_dataset_results": dissertation_within,
            "cross_dataset_results": dissertation_cross,
            "cross_dataset_deltas": deltas,
            "shap_stage_metrics": shap_stage_metrics,
            "rule_validation_summary": rule_validation_summary,
            "governance_traceability": governance_traceability,
            "cross_dataset_robustness": _metric_value("cross_dataset_robustness"),
            "inference_latency_ms": _metric_value("inference_latency_ms"),
            "metrics_principle_review_update": metrics_principle_update,
            "step2_timeline": timeline,
            "current_phase": "finalized",
            "model_v1_status": finalize_payload,
            "gate_failures": gate_failures,
            "step3_cpu_governance": _step3_cpu_governance_placeholder(),
        },
        error_message=None if status == "completed" else "step2_finalize_failed",
        completed=True,
    )
    update_model_lifecycle(
        model_version,
        status="frozen" if status == "completed" else "failed",
        model_artifact_path=frozen_manifest_path,
        metrics_artifact_path=str(metrics_path),
        last_error=None if status == "completed" else "step2_finalize_failed",
        is_frozen=True if status == "completed" else False,
        created_by_run_id=run_id,
    )
    step2_metrics_generation: dict[str, Any] = {
        "ok": False,
        "status": "not_run",
        "step": "step2",
        "run_id": run_id,
    }
    try:
        step2_metrics_generation = generate_step2_metrics(run_id=run_id)
        update_workflow_run(
            run_id,
            status=status,
            run_metrics=_compose_metrics(
                {
                    "step2_metrics_generation": step2_metrics_generation,
                    "integrity_verification": integrity_block,
                }
            ),
        )
    except Exception:
        traceback.print_exc()
        step2_metrics_generation = {
            "ok": False,
            "status": "failed",
            "warning": True,
            "step": "step2",
            "run_id": run_id,
        }
        try:
                update_workflow_run(
                    run_id,
                    status=status,
                    run_metrics=_compose_metrics(
                        {
                            "step2_metrics_generation": step2_metrics_generation,
                            "integrity_verification": integrity_block,
                        }
                    ),
                )
        except Exception:
            pass
    _patch_run_state(
        run_id,
        {
            "status": status,
            "running_tasks": 0,
            "completed_tasks": len(all_parts) - len(failed),
            "failed_tasks": len(failed),
            "completed_at_utc": _now(),
            "metrics_artifact_path": str(metrics_path),
            "model_artifact_path": frozen_manifest_path,
            "current_phase": "finalized",
            "model_v1_status": finalize_payload,
            "integrity_verification": integrity_block,
            "cpu_governor": cpu_governor,
            "cpu_telemetry": cpu_telemetry,
            "queue_state": queue_state or {"status": "acquired_without_queue"},
            "effective_parallelism": effective_parallelism,
            "step2_metrics_generation": step2_metrics_generation,
            "step3_cpu_governance": _step3_cpu_governance_placeholder(),
        },
    )
    write_audit_event(
        event_type=MODEL_V1_STEP2_COMPLETED if status == "completed" else MODEL_V1_STEP2_FAILED,
        actor=_actor(),
        artifact_refs=[str(metrics_path), frozen_manifest_path, str(finalize_path)],
        context={
            "run_id": run_id,
            "workflow_id": workflow_id,
                "failed_count": len(failed),
                "prerequisite_step1_run_id": step1_lineage.get("step1_run_id"),
                "step1_lineage_hash": step1_lineage.get("step1_lineage_hash"),
                "integrity_verification": integrity_block,
                "step2_metrics_generation": step2_metrics_generation,
            },
        experiment_id=experiment_id,
        model_version=model_version,
    )


def step3_placeholder_status() -> dict[str, Any]:
    from services_parent.model_v1.step3_simulation import step3_status

    live = step3_status()
    out = dict(live if isinstance(live, dict) else {})
    out["status_source"] = "live_step3_status"
    return out


def _to_float_or_none(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except Exception:
        return None


def _step1_fallback_dataset_summary_from_db(run_id: str) -> dict[str, Any]:
    dataset_summary: dict[str, dict[str, Any]] = {}
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        dataset_id,
                        COALESCE(NULLIF(source_file, ''), 'unknown') AS source_file,
                        COUNT(*)::bigint AS total_rows,
                        COUNT(*) FILTER (WHERE COALESCE(label_harmonized, '') <> '')::bigint AS rows_ok,
                        COUNT(*) FILTER (WHERE COALESCE(label_harmonized, '') = '')::bigint AS rows_fail
                    FROM phase4.dataset_splits
                    WHERE source_step1_run_id = %(rid)s::uuid
                    GROUP BY dataset_id, COALESCE(NULLIF(source_file, ''), 'unknown')
                    ORDER BY dataset_id, source_file;
                    """,
                    {"rid": run_id},
                )
                for dataset_id, source_file, total_rows, rows_ok, rows_fail in cur.fetchall():
                    dsid = str(dataset_id or "unknown")
                    summary = dataset_summary.setdefault(
                        dsid,
                        {
                            "ok": True,
                            "readiness": "running",
                            "stage": "step1_file_processing",
                            "status": "running",
                            "normalized_rows": 0,
                            "failed_rows": 0,
                            "split_counts": {},
                            "loaded_counts": {},
                            "file_summary": [],
                        },
                    )
                    file_total = int(total_rows or 0)
                    file_ok_rows = int(rows_ok or 0)
                    file_failed_rows = int(rows_fail or 0)
                    file_ok = file_total > 0 and file_failed_rows == 0
                    summary["ok"] = bool(summary.get("ok", True)) and file_ok
                    summary["normalized_rows"] = int(summary.get("normalized_rows") or 0) + file_ok_rows
                    summary["failed_rows"] = int(summary.get("failed_rows") or 0) + file_failed_rows
                    file_row = {
                        "dataset_id": dsid,
                        "filename": str(source_file or "unknown"),
                        "path": str(source_file or "unknown"),
                        "ok": file_ok,
                        "total_rows": file_total,
                        "normalized_rows": file_ok_rows,
                        "failed_rows": file_failed_rows,
                        "rows_ok": file_ok_rows,
                        "rows_fail": file_failed_rows,
                        "detail": f"db_rows={file_total}",
                    }
                    summary["file_summary"].append(file_row)
                cur.execute(
                    """
                    SELECT dataset_id, split_name, COUNT(*)::bigint
                    FROM phase4.dataset_splits
                    WHERE source_step1_run_id = %(rid)s::uuid
                    GROUP BY dataset_id, split_name;
                    """,
                    {"rid": run_id},
                )
                for dataset_id, split_name, cnt in cur.fetchall():
                    dsid = str(dataset_id or "unknown")
                    summary = dataset_summary.setdefault(
                        dsid,
                        {
                            "ok": False,
                            "readiness": "running",
                            "stage": "step1_file_processing",
                            "status": "running",
                            "normalized_rows": 0,
                            "failed_rows": 0,
                            "split_counts": {},
                            "loaded_counts": {},
                            "file_summary": [],
                        },
                    )
                    split = str(split_name or "").strip().lower()
                    count = int(cnt or 0)
                    summary["split_counts"][split] = count
                    summary["loaded_counts"][split] = count
    except Exception:
        return {}
    for summary in dataset_summary.values():
        ready = bool(summary.get("ok")) and int(summary.get("normalized_rows") or 0) > 0
        summary["readiness"] = "completed" if ready else ("partial" if int(summary.get("normalized_rows") or 0) > 0 else "running")
        summary["status"] = "completed" if ready else ("partial" if summary.get("readiness") == "partial" else "running")
    return dataset_summary


def _step1_fallback_metric_rows(run_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT metric, metric_value, numerator, denominator, calculation_status
                    FROM phase4.metrics
                    WHERE step = 'step1'
                      AND step_unique_id = %(rid)s
                    ORDER BY metric;
                    """,
                    {"rid": run_id},
                )
                for metric_name, metric_value, numerator, denominator, status in cur.fetchall():
                    rows.append(
                        {
                            "metric_name": str(metric_name or ""),
                            "metric_value": _to_float_or_none(metric_value),
                            "numerator": int(float(numerator or 0)),
                            "denominator": int(float(denominator or 0)),
                            "status": str(status or "not_collected"),
                        }
                    )
    except Exception:
        return []
    return rows


def _reconcile_dead_worker_thread(run_id: str, db_row: dict[str, Any] | None, live_raw: dict[str, Any] | None) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if not isinstance(db_row, dict):
        return db_row, live_raw
    status = str(db_row.get("status") or "").strip().lower()
    if status not in {"queued", "running"}:
        return db_row, live_raw
    step_name = str(db_row.get("step_name") or "").strip().lower()
    if step_name not in {"step1", "step2"}:
        return db_row, live_raw
    with _RUN_LOCK:
        th = _RUN_THREADS.get(run_id)
    if th is None or th.is_alive():
        return db_row, live_raw
    reason = "orphaned_running:worker_thread_dead"
    try:
        update_workflow_run(
            run_id,
            status="failed",
            run_metrics={
                "current_phase": f"{step_name}_failed_orphaned",
                "orphaned_reconcile_reason": reason,
                "completed_at_utc": _now(),
            },
            error_message=reason,
            completed=True,
        )
    except Exception:
        return db_row, live_raw
    _patch_run_state(
        run_id,
        {
            "status": "failed",
            "running_tasks": 0,
            "completed_at_utc": _now(),
            "error": reason,
        },
    )
    return get_workflow_run(run_id), get_run_state(run_id)


def status_for_run(run_id: str) -> dict[str, Any]:
    live_raw = get_run_state(run_id)
    db_row = get_workflow_run(run_id)
    db_row, live_raw = _reconcile_dead_worker_thread(run_id, db_row, live_raw)
    if isinstance(db_row, dict) and str(db_row.get("step_name") or "").strip().lower() == "step1":
        metrics = _parse_run_metrics(db_row.get("run_metrics"))
        if not isinstance(metrics.get("dataset_summary"), dict) or not metrics.get("dataset_summary"):
            fallback_summary = _step1_fallback_dataset_summary_from_db(run_id)
            if fallback_summary:
                metrics["dataset_summary"] = fallback_summary
                metrics["current_phase"] = str(metrics.get("current_phase") or "step1_dataset_processing")
        metrics["step1_metric_results"] = _step1_fallback_metric_rows(run_id)
        db_row = dict(db_row)
        db_row["run_metrics"] = metrics
    db_status = str((db_row or {}).get("status") or "").strip().lower() if isinstance(db_row, dict) else ""
    # DB terminal status is authoritative; live state is supplementary.
    live = None if db_status in _TERMINAL_RUN_STATUSES else live_raw
    run_label = ""
    if isinstance(db_row, dict):
        m = _parse_run_metrics(db_row.get("run_metrics"))
        run_label = str(m.get("run_label") or "")
    resolved_status = (
        db_status
        or str((live or {}).get("status") or "").strip().lower()
        or str((live_raw or {}).get("status") or "").strip().lower()
        or None
    )
    return {
        "ok": db_row is not None or live_raw is not None,
        "run_id": run_id,
        "run_label": run_label,
        "status_source": "db" if db_row is not None else ("live" if live_raw is not None else "none"),
        "status": resolved_status,
        "live": live,
        "live_supplementary": live_raw if live is None else None,
        "db": db_row,
    }
