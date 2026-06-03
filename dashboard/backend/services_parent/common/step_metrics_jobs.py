from __future__ import annotations

import math
import json
import os
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from services_parent.common.metrics_store import (
    load_metric_principles,
    purge_deprecated_metrics,
    upsert_step_metrics,
)
from services_parent.common.phase4_db import connect


def _parse_json(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        try:
            return int(float(value))
        except Exception:
            return 0


def _safe_float(value: Any) -> float:
    try:
        if value is None:
            return 0.0
        return float(value)
    except Exception:
        return 0.0


def _safe_ratio(numerator: Any, denominator: Any) -> float | None:
    d = _safe_float(denominator)
    if d <= 0:
        return None
    return _safe_float(numerator) / d


def _first_track_result(table: dict[str, Any], primary_track: str) -> dict[str, Any]:
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


def _parse_square_confusion_matrix(raw: Any) -> list[list[float]]:
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


def _macro_components_from_confusion(track_metrics: dict[str, Any]) -> dict[str, float]:
    cm = _parse_square_confusion_matrix(track_metrics.get("confusion_matrix"))
    if not cm:
        return {}
    n = len(cm)
    row_sum = [sum(r) for r in cm]
    col_sum = [sum(cm[r][c] for r in range(n)) for c in range(n)]
    total = sum(row_sum)
    tp_sum = 0.0
    precision_sum = 0.0
    recall_sum = 0.0
    f1_sum = 0.0
    fpr_sum = 0.0
    fnr_sum = 0.0
    for i in range(n):
        tp = _safe_float(cm[i][i])
        fp = _safe_float(col_sum[i] - tp)
        fn = _safe_float(row_sum[i] - tp)
        tn = _safe_float(total - tp - fp - fn)
        tp_sum += tp
        precision_i = _safe_ratio(tp, tp + fp) or 0.0
        recall_i = _safe_ratio(tp, tp + fn) or 0.0
        f1_i = _safe_ratio(2.0 * precision_i * recall_i, precision_i + recall_i) or 0.0
        fpr_i = _safe_ratio(fp, fp + tn) or 0.0
        fnr_i = _safe_ratio(fn, fn + tp) or 0.0
        precision_sum += precision_i
        recall_sum += recall_i
        f1_sum += f1_i
        fpr_sum += fpr_i
        fnr_sum += fnr_i
    return {
        "class_count": float(n),
        "total_predictions": float(total),
        "correct_predictions": float(tp_sum),
        "precision_sum": float(precision_sum),
        "recall_sum": float(recall_sum),
        "f1_sum": float(f1_sum),
        "fpr_sum": float(fpr_sum),
        "fnr_sum": float(fnr_sum),
    }


def _ent01_primary_track_metrics(
    testing_results: list[dict[str, Any]],
    *,
    primary_track: str,
) -> dict[str, Any]:
    for row in testing_results:
        if str(row.get("eval_target") or "") != "ent01_holdout":
            continue
        metrics = row.get("metrics") if isinstance(row.get("metrics"), dict) else {}
        track_results = (
            metrics.get("model_track_results") if isinstance(metrics.get("model_track_results"), dict) else {}
        )
        track_payload = _first_track_result(track_results, primary_track)
        if not isinstance(track_payload, dict):
            continue
        track_metrics = (
            track_payload.get("metrics") if isinstance(track_payload.get("metrics"), dict) else {}
        )
        if isinstance(track_metrics, dict) and track_metrics:
            return track_metrics
    return {}


def _feature_list_count_from_track_payload(track_payload: dict[str, Any]) -> int | None:
    if not isinstance(track_payload, dict):
        return None
    feature_list_path = str(track_payload.get("feature_list_path") or "").strip()
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


def _build_step2_metrics_from_run_metrics(run_metrics: dict[str, Any]) -> dict[str, dict[str, Any]]:
    def _row(
        value: Any,
        status: str,
        source_ref: str,
        note: str = "",
        numerator: Any = None,
        denominator: Any = None,
    ) -> dict[str, Any]:
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

    model_tracks = run_metrics.get("model_tracks") if isinstance(run_metrics.get("model_tracks"), dict) else {}
    primary_track = str(model_tracks.get("primary_supervised_model") or "random_forest")

    within_dataset_results = (
        run_metrics.get("within_dataset_results")
        if isinstance(run_metrics.get("within_dataset_results"), dict)
        else {}
    )
    cross_dataset_results = (
        run_metrics.get("cross_dataset_results")
        if isinstance(run_metrics.get("cross_dataset_results"), dict)
        else {}
    )
    training_result = run_metrics.get("training_result") if isinstance(run_metrics.get("training_result"), dict) else {}
    training_metrics = training_result.get("metrics") if isinstance(training_result.get("metrics"), dict) else {}
    testing_results = run_metrics.get("testing_results") if isinstance(run_metrics.get("testing_results"), list) else []
    shap_stage_metrics = run_metrics.get("shap_stage_metrics") if isinstance(run_metrics.get("shap_stage_metrics"), dict) else {}
    rule_validation_summary = (
        run_metrics.get("rule_validation_summary")
        if isinstance(run_metrics.get("rule_validation_summary"), dict)
        else {}
    )
    rep01_rule_validation = (
        rule_validation_summary.get("rep01_packet_validation")
        if isinstance(rule_validation_summary.get("rep01_packet_validation"), dict)
        else {}
    )

    within_rows = (
        within_dataset_results.get("table_4_1_rows")
        if isinstance(within_dataset_results.get("table_4_1_rows"), dict)
        else {}
    )
    primary_row = _first_track_result(within_rows, primary_track)
    ent01_track_metrics = _ent01_primary_track_metrics(testing_results, primary_track=primary_track)
    confusion_components = _macro_components_from_confusion(ent01_track_metrics)
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

    total_predictions_conf = confusion_components.get("total_predictions")
    if _safe_float(total_predictions_conf) <= 0:
        total_predictions_conf = ent01_track_metrics.get("support")
    if _safe_float(total_predictions_conf) <= 0:
        total_predictions_conf = primary_row.get("support")
    total_predictions_val = _safe_float(total_predictions_conf)

    def _value_or_ratio(value: Any, numerator: Any, denominator: Any) -> float | None:
        if value is not None:
            return float(_safe_float(value))
        ratio = _safe_ratio(numerator, denominator)
        if ratio is None:
            return None
        return float(ratio)

    accuracy_value = _value_or_ratio(
        primary_row.get("accuracy"),
        confusion_components.get("correct_predictions"),
        confusion_components.get("total_predictions"),
    )
    accuracy_den = confusion_components.get("total_predictions")
    if _safe_float(accuracy_den) <= 0:
        accuracy_den = total_predictions_val if total_predictions_val > 0 else None
    accuracy_num = confusion_components.get("correct_predictions")
    if _safe_float(accuracy_num) <= 0 and accuracy_value is not None and _safe_float(accuracy_den) > 0:
        accuracy_num = float(accuracy_value) * float(_safe_float(accuracy_den))
    accuracy_value = _value_or_ratio(accuracy_value, accuracy_num, accuracy_den)

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
    fpr_value = _value_or_ratio(fpr_value_source, fpr_num, fpr_den)

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
    fnr_value = _value_or_ratio(fnr_value_source, fnr_num, fnr_den)

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
    else:
        mean_external_f1 = None

    inference_latency_ms = None
    inference_latency_ms_num = None
    inference_latency_ms_den = None
    for row in testing_results:
        if str(row.get("eval_target") or "") != "ent01_holdout":
            continue
        metrics = row.get("metrics") if isinstance(row.get("metrics"), dict) else {}
        pred_count = _safe_int(metrics.get("prediction_count"))
        duration_s = _safe_float(metrics.get("duration_s"))
        if pred_count > 0 and duration_s > 0:
            inference_latency_ms_num = float(duration_s * 1000.0)
            inference_latency_ms_den = float(pred_count)
            inference_latency_ms = inference_latency_ms_num / inference_latency_ms_den
        break

    shap_duration_s = shap_stage_metrics.get("offline_compute_duration_s")
    if shap_duration_s is None:
        shap_duration_s = shap_stage_metrics.get("total_duration_s")
    feature_consistency = shap_stage_metrics.get("top_feature_consistency")

    sampled_packets = _safe_int(rep01_rule_validation.get("sampled_packets"))
    packets_with_detections = _safe_int(rep01_rule_validation.get("packets_with_detections"))
    rule_hit_rate = _safe_ratio(packets_with_detections, sampled_packets)
    precision_val = primary_row.get("precision")
    recall_val = primary_row.get("recall")
    f1_formula_num = None
    f1_formula_den = None
    if precision_val is not None and recall_val is not None:
        p = _safe_float(precision_val)
        r = _safe_float(recall_val)
        f1_formula_num = float(2.0 * p * r)
        f1_formula_den = float(p + r)

    coverage_by_split = (
        shap_stage_metrics.get("coverage_by_split")
        if isinstance(shap_stage_metrics.get("coverage_by_split"), dict)
        else {}
    )
    row_count_by_split = (
        shap_stage_metrics.get("row_count_by_split")
        if isinstance(shap_stage_metrics.get("row_count_by_split"), dict)
        else {}
    )
    explanation_coverage_value = (
        coverage_by_split.get("test")
        if isinstance(coverage_by_split, dict) and "test" in coverage_by_split
        else shap_stage_metrics.get("chunk_feature_coverage")
    )
    explanation_coverage_num = None
    explanation_coverage_den = None
    test_rows = _safe_int(row_count_by_split.get("test"))
    if test_rows > 0 and explanation_coverage_value is not None:
        explanation_coverage_den = float(test_rows)
        explanation_coverage_num = float(_safe_float(explanation_coverage_value) * explanation_coverage_den)
    elif explanation_coverage_value is not None:
        total_rows = _safe_int(sum(_safe_int(v) for v in row_count_by_split.values()))
        if total_rows > 0:
            explanation_coverage_den = float(total_rows)
            explanation_coverage_num = float(_safe_float(explanation_coverage_value) * explanation_coverage_den)

    recurrence_value = shap_stage_metrics.get("explanation_recurrence_score")
    recurrence_denominator = _safe_int(shap_stage_metrics.get("explanation_recurrence_total_patterns"))
    recurrence_numerator = _safe_int(shap_stage_metrics.get("explanation_recurrence_repeated_patterns"))
    recurrence_policy = str(shap_stage_metrics.get("explanation_recurrence_signature_policy") or "top5_with_sign")
    if recurrence_value is None and recurrence_denominator > 0:
        recurrence_value = _safe_ratio(recurrence_numerator, recurrence_denominator)

    feature_reduction_value = training_metrics.get("feature_reduction_ratio")
    feature_count_after = _safe_int(training_metrics.get("feature_count"))
    feature_count_before = _safe_int(training_metrics.get("candidate_feature_count_before_selection"))
    if feature_count_before <= 0:
        primary_track_payload = _first_track_result(model_tracks, primary_track)
        feature_count_before = _safe_int(_feature_list_count_from_track_payload(primary_track_payload))
    feature_reduction_num = None
    feature_reduction_den = None
    feature_reduction_note = ""
    if feature_count_before > 0:
        feature_reduction_den = float(feature_count_before)
        feature_reduction_num = float(max(feature_count_before - feature_count_after, 0))
    if feature_reduction_value is None and feature_reduction_den and feature_reduction_den > 0:
        feature_reduction_value = float(feature_reduction_num / feature_reduction_den)
    feature_reduction_status = "collected_as_principle" if feature_reduction_value is not None else "not_collected"
    if feature_reduction_value is None:
        feature_reduction_note = "missing before/after feature counts for derivation"

    return {
        "precision": _row(
            primary_row.get("precision"),
            "collected_as_principle",
            "within_dataset_results.table_4_1_rows.<track>.precision",
            numerator=confusion_components.get("precision_sum"),
            denominator=confusion_components.get("class_count"),
        ),
        "recall": _row(
            primary_row.get("recall"),
            "collected_as_principle",
            "within_dataset_results.table_4_1_rows.<track>.recall",
            numerator=confusion_components.get("recall_sum"),
            denominator=confusion_components.get("class_count"),
        ),
        "macro_f1": _row(
            primary_row.get("macro_f1"),
            "collected_as_principle",
            "within_dataset_results.table_4_1_rows.<track>.macro_f1",
            numerator=confusion_components.get("f1_sum"),
            denominator=confusion_components.get("class_count"),
        ),
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
        "cross_dataset_robustness": _row(
            cross_dataset_robustness,
            "collected_as_principle" if cross_dataset_robustness is not None else "not_collected",
            "within/cross_dataset_results",
            numerator=mean_external_f1,
            denominator=internal_f1,
        ),
        "feature_reduction_ratio": _row(
            feature_reduction_value,
            feature_reduction_status,
            "training_result.metrics.feature_reduction_ratio|model_tracks.<primary>.feature_list_path",
            feature_reduction_note,
            feature_reduction_num,
            feature_reduction_den,
        ),
        "training_time_seconds": _row(training_metrics.get("duration_s"), "collected_as_principle", "training_result.metrics.duration_s"),
        "explanation_coverage": _row(
            explanation_coverage_value,
            "collected_as_principle",
            "shap_stage_metrics.coverage_by_split.test|chunk_feature_coverage",
            numerator=explanation_coverage_num,
            denominator=explanation_coverage_den,
        ),
        "rule_hit_rate": _row(rule_hit_rate, "collected_as_principle" if rule_hit_rate is not None else "not_collected", "rule_validation_summary.rep01_packet_validation", "", packets_with_detections, sampled_packets),
        "f1_score": _row(
            primary_row.get("f1"),
            "collected_as_principle",
            "within_dataset_results.table_4_1_rows.<track>.f1",
            numerator=f1_formula_num,
            denominator=f1_formula_den,
        ),
        "accuracy": _row(
            accuracy_value,
            "collected_as_principle",
            "within_dataset_results.table_4_1_rows.<track>.accuracy",
            numerator=accuracy_num,
            denominator=accuracy_den,
        ),
        "selected_feature_count": _row(training_metrics.get("feature_count"), "collected_as_principle", "training_result.metrics.feature_count"),
        "inference_latency_ms": _row(
            inference_latency_ms,
            "collected_as_principle" if inference_latency_ms is not None else "not_collected",
            "testing_results[ent01_holdout].metrics.{duration_s,prediction_count}",
            numerator=inference_latency_ms_num,
            denominator=inference_latency_ms_den,
        ),
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


def _step_required_metrics(step: str) -> list[str]:
    return sorted((load_metric_principles().get(step) or {}).keys())


def _metric_worker_profile() -> dict[str, Any]:
    total_cores = int(os.getenv("METRICS_WORKER_TOTAL_CORES", "20") or 20)
    cpu_cap_pct = float(os.getenv("METRICS_WORKER_CPU_CAP_PCT", "0.80") or 0.80)
    total_cores = max(1, total_cores)
    cpu_cap_pct = min(1.0, max(0.1, cpu_cap_pct))
    max_threads = max(1, int(math.floor(total_cores * cpu_cap_pct)))
    return {
        "total_cores": total_cores,
        "cpu_cap_pct": cpu_cap_pct,
        "max_threads": max_threads,
    }


def _ingest_metrics_threaded(
    *,
    step: str,
    step_unique_id: str,
    metric_rows: dict[str, dict[str, Any]] | list[dict[str, Any]],
    lineage: dict[str, Any] | None = None,
    profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    worker_profile = profile if isinstance(profile, dict) else _metric_worker_profile()
    principles = load_metric_principles().get(step) or {}
    rows_by_metric: dict[str, dict[str, Any]] = {}

    if isinstance(metric_rows, dict):
        for metric_name, row in metric_rows.items():
            if not isinstance(row, dict):
                continue
            rows_by_metric[str(metric_name)] = dict(row)
    else:
        for row in metric_rows:
            if not isinstance(row, dict):
                continue
            metric_name = str(row.get("metric_name") or "").strip()
            if not metric_name:
                continue
            rows_by_metric[metric_name] = dict(row)

    for metric_name, principle in principles.items():
        if metric_name in rows_by_metric:
            rows_by_metric[metric_name].setdefault("principle_status", principle.principle_status)
            rows_by_metric[metric_name].setdefault("calculation_method", principle.calculation_method)
            continue
        rows_by_metric[metric_name] = {
            "metric_name": metric_name,
            "metric_value": None,
            "numerator": None,
            "denominator": None,
            "calculation_status": "not_collected",
            "principle_status": principle.principle_status,
            "calculation_method": principle.calculation_method,
            "source_ref": f"{step}_metrics_generation_missing",
        }

    rows = [rows_by_metric[k] for k in sorted(rows_by_metric.keys())]
    if not rows:
        return {"ingested_rows": 0, "worker_profile": profile}

    worker_count = min(int(worker_profile["max_threads"]), len(rows))
    chunks: list[list[dict[str, Any]]] = [[] for _ in range(worker_count)]
    for idx, row in enumerate(rows):
        chunks[idx % worker_count].append(row)
    chunks = [c for c in chunks if c]

    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=min(worker_count, len(chunks))) as ex:
        futures = [
            ex.submit(
                upsert_step_metrics,
                step=step,
                step_unique_id=step_unique_id,
                metric_rows=chunk,
                include_all_principle_metrics=False,
                lineage=lineage,
            )
            for chunk in chunks
        ]
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as exc:
                errors.append(str(exc))

    return {
        "ingested_rows": len(rows),
        "worker_profile": worker_profile,
        "ingest_worker_threads": min(worker_count, len(chunks)),
        "ingest_errors": errors,
    }


def _missing_requirements(step: str, missing_metrics: list[str]) -> list[dict[str, Any]]:
    principles = load_metric_principles().get(step) or {}
    out: list[dict[str, Any]] = []
    for metric_name in sorted(set(missing_metrics)):
        p = principles.get(metric_name)
        out.append(
            {
                "metric_name": metric_name,
                "required_calculation_method": (p.calculation_method if p else ""),
                "principle_status_in_review": (p.principle_status if p else "missing"),
                "required_data_note": "Need additional source data aligned to metrics_principle_review.md.",
            }
        )
    return out


def _threaded_collect(
    collectors: list[tuple[str, Any]],
    *,
    profile: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str], int]:
    if not collectors:
        return [], [], 0
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    worker_count = min(max(1, int(profile.get("max_threads") or 1)), len(collectors))
    with ThreadPoolExecutor(max_workers=worker_count) as ex:
        fut_map = {ex.submit(fn): metric_name for metric_name, fn in collectors}
        for fut in as_completed(fut_map):
            metric_name = fut_map[fut]
            try:
                row = fut.result()
                if isinstance(row, dict):
                    rows.append(row)
                else:
                    errors.append(f"{metric_name}:non_dict_row")
            except Exception as exc:
                errors.append(f"{metric_name}:{exc}")
    return rows, errors, worker_count


def _query_workflow_run(run_id: str, *, step_name: str) -> dict[str, Any] | None:
    rid = str(run_id or "").strip()
    if not rid:
        return None
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT run_id::text, workflow_id, step_name, status, run_metrics, completed_at_utc
                FROM phase4.workflow_runs
                WHERE run_id = %(rid)s::uuid
                  AND step_name = %(step_name)s
                LIMIT 1;
                """,
                {"rid": rid, "step_name": step_name},
            )
            row = cur.fetchone()
    if not row:
        return None
    return {
        "run_id": str(row[0] or ""),
        "workflow_id": str(row[1] or ""),
        "step_name": str(row[2] or ""),
        "status": str(row[3] or ""),
        "run_metrics": _parse_json(row[4]),
        "completed_at_utc": (row[5].isoformat() if row[5] is not None else ""),
    }


def _is_uuid_like(value: str | None) -> bool:
    txt = str(value or "").strip()
    if not txt:
        return False
    try:
        uuid.UUID(txt)
        return True
    except Exception:
        return False


def _resolve_step1_lineage_context(step1_run_id: str) -> dict[str, str]:
    out: dict[str, str] = {
        "step1_run_id": str(step1_run_id or "").strip(),
        "step2_run_id": "",
        "model_id": "",
        "replay_run_id": "",
        "step3_v2_sim_id": "",
    }
    rid = out["step1_run_id"]
    if not _is_uuid_like(rid):
        return out
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT run_id::text, run_metrics
                    FROM phase4.workflow_runs
                    WHERE step_name = 'step2'
                      AND (run_metrics->>'source_step1_run_id') = %(rid)s
                    ORDER BY started_at_utc DESC
                    LIMIT 1;
                    """,
                    {"rid": rid},
                )
                row = cur.fetchone()
                if row:
                    out["step2_run_id"] = str(row[0] or "").strip()
                    rm = _parse_json(row[1])
                    out["model_id"] = str(rm.get("model_id") or "").strip()
                if _is_uuid_like(out["model_id"]):
                    cur.execute(
                        """
                        SELECT replay_run_id::text
                        FROM phase4.step3_replay_metrics
                        WHERE model_id::text = %(mid)s
                        ORDER BY updated_at_utc DESC NULLS LAST, created_at_utc DESC NULLS LAST
                        LIMIT 1;
                        """,
                        {"mid": out["model_id"]},
                    )
                    rr = cur.fetchone()
                    if rr:
                        out["replay_run_id"] = str(rr[0] or "").strip()
                    cur.execute(
                        """
                        SELECT simulation_id::text
                        FROM phase4.step3_v2_simulations
                        WHERE model_id::text = %(mid)s
                        ORDER BY updated_at_utc DESC NULLS LAST, created_at_utc DESC NULLS LAST
                        LIMIT 1;
                        """,
                        {"mid": out["model_id"]},
                    )
                    sr = cur.fetchone()
                    if sr:
                        out["step3_v2_sim_id"] = str(sr[0] or "").strip()
    except Exception:
        return out
    return out


def _derive_step1_split_integrity_metric(*, run_id: str, run_metrics: dict[str, Any]) -> dict[str, Any]:
    # Primary/original source: authoritative Step1 rows in dataset_splits.
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT dataset_id, COUNT(*)::bigint
                FROM phase4.dataset_splits
                WHERE source_step1_run_id::text = %(rid)s
                GROUP BY dataset_id;
                """,
                {"rid": run_id},
            )
            grouped = cur.fetchall()
    denominator = len(grouped)
    numerator = sum(1 for _, cnt in grouped if int(cnt or 0) > 0)
    source = "phase4.dataset_splits grouped by dataset_id"
    if denominator <= 0:
        # Fallback only when Step1 rows are absent.
        reconciliation = run_metrics.get("reconciliation") if isinstance(run_metrics.get("reconciliation"), dict) else {}
        datasets = reconciliation.get("datasets") if isinstance(reconciliation.get("datasets"), dict) else {}
        denominator = 0
        numerator = 0
        for row in datasets.values():
            if not isinstance(row, dict):
                continue
            denominator += 1
            if bool(row.get("ok")):
                numerator += 1
        source = "phase4.workflow_runs.run_metrics.reconciliation.datasets.*.ok (fallback)"
    value = (float(numerator) / float(denominator)) if denominator > 0 else None
    return {
        "metric_name": "split_integrity_rate",
        "metric_value": value,
        "numerator": numerator if denominator > 0 else 0,
        "denominator": denominator if denominator > 0 else 0,
        "status": "measured" if denominator > 0 else "not_collected",
        "details_json": {
            "formula": "valid_splits / total_splits",
            "source": source,
            "run_id": run_id,
        },
    }


def _resolve_step1_lineage_hash_from_dataset_splits(run_id: str) -> str:
    rid = str(run_id or "").strip()
    if not rid:
        return ""
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT source_step1_lineage_hash, COUNT(*)::bigint AS cnt
                FROM phase4.dataset_splits
                WHERE source_step1_run_id::text = %(rid)s
                  AND COALESCE(source_step1_lineage_hash, '') <> ''
                GROUP BY source_step1_lineage_hash
                ORDER BY cnt DESC, source_step1_lineage_hash DESC
                LIMIT 1;
                """,
                {"rid": rid},
            )
            row = cur.fetchone()
    if not row:
        return ""
    return str(row[0] or "").strip()


def _derive_step1_audit_completeness_metric(*, run_id: str) -> dict[str, Any]:
    rid = str(run_id or "").strip()
    value: float | None = None
    numerator = 0
    denominator = 0
    dataset_ids: list[str] = []
    audit_table = "phase4.audit_log"
    required_events: list[str] = []
    run_started_at: str = ""
    run_completed_at: str = ""

    if _is_uuid_like(rid):
        with connect() as conn:
            with conn.cursor() as cur:
                # Compatibility: resolve between phase4.audit_logs and phase4.audit_log by run evidence.
                cur.execute(
                    """
                    SELECT
                      COALESCE(to_regclass('phase4.audit_logs')::text, '') AS plural_name,
                      COALESCE(to_regclass('phase4.audit_log')::text, '') AS singular_name;
                    """
                )
                trow = cur.fetchone() or ("", "")
                plural_name = str(trow[0] or "").strip()
                singular_name = str(trow[1] or "").strip()
                candidates = [tbl for tbl in (plural_name, singular_name) if tbl]
                audit_table = singular_name or plural_name or "phase4.audit_log"
                best_count = -1
                for tbl in candidates:
                    cur.execute(
                        f"""
                        SELECT COUNT(*)::bigint
                        FROM {tbl}
                        WHERE COALESCE(event_details_json->'context'->>'run_id', '') = %(rid)s;
                        """,
                        {"rid": rid},
                    )
                    c_row = cur.fetchone() or (0,)
                    c = int(c_row[0] or 0)
                    if c > best_count:
                        best_count = c
                        audit_table = tbl

                cur.execute(
                    """
                    SELECT run_metrics, started_at_utc, completed_at_utc
                    FROM phase4.workflow_runs
                    WHERE step_name = 'step1'
                      AND run_id = %(rid)s::uuid
                    LIMIT 1;
                    """,
                    {"rid": rid},
                )
                run_row = cur.fetchone()
                run_metrics = _parse_json(run_row[0]) if run_row else {}
                run_started_at = str(run_row[1].isoformat()) if run_row and run_row[1] is not None else ""
                run_completed_at = str(run_row[2].isoformat()) if run_row and run_row[2] is not None else ""
                ds_summary = run_metrics.get("dataset_summary") if isinstance(run_metrics.get("dataset_summary"), dict) else {}
                dataset_ids = sorted(str(k).strip() for k in ds_summary.keys() if str(k).strip())
                if not dataset_ids:
                    cur.execute(
                        """
                        SELECT DISTINCT dataset_id
                        FROM phase4.dataset_splits
                        WHERE source_step1_run_id::text = %(rid)s
                        ORDER BY dataset_id;
                        """,
                        {"rid": rid},
                    )
                    dataset_ids = [str(row[0]).strip() for row in cur.fetchall() if str(row[0]).strip()]

                checks = [("model_v1_step1_completed", None)]
                for dsid in dataset_ids:
                    checks.append(("dataset_process_started", dsid))
                    checks.append(("dataset_process_terminal", dsid))

                denominator = len(checks)
                if denominator > 0:
                    hits = 0
                    for event_type, dsid in checks:
                        matched = False
                        if event_type == "dataset_process_terminal":
                            required_events.extend(
                                [
                                    f"dataset_process_completed:{dsid}",
                                    f"dataset_process_partial_file_failures:{dsid}",
                                    f"dataset_process_failed:{dsid}",
                                ]
                            )
                            cur.execute(
                                f"""
                                SELECT 1
                                FROM {audit_table}
                                WHERE event_type IN (
                                  'dataset_process_completed',
                                  'dataset_process_partial_file_failures',
                                  'dataset_process_failed'
                                )
                                  AND COALESCE(event_details_json->'context'->>'run_id', '') = %(rid)s
                                  AND COALESCE(dataset_id, '') = %(dsid)s
                                LIMIT 1;
                                """,
                                {"rid": rid, "dsid": dsid},
                            )
                            matched = bool(cur.fetchone())
                            if (not matched) and run_started_at and run_completed_at:
                                cur.execute(
                                    f"""
                                    SELECT 1
                                    FROM {audit_table}
                                    WHERE event_type IN (
                                      'dataset_process_completed',
                                      'dataset_process_partial_file_failures',
                                      'dataset_process_failed'
                                    )
                                      AND step = 'step1'
                                      AND COALESCE(dataset_id, '') = %(dsid)s
                                      AND created_at >= %(started_at)s::timestamptz
                                      AND created_at <= %(completed_at)s::timestamptz
                                    LIMIT 1;
                                    """,
                                    {
                                        "dsid": dsid,
                                        "started_at": run_started_at,
                                        "completed_at": run_completed_at,
                                    },
                                )
                                matched = bool(cur.fetchone())
                        else:
                            required_events.append(f"{event_type}:{dsid or 'run'}")
                            cur.execute(
                                f"""
                                SELECT 1
                                FROM {audit_table}
                                WHERE event_type = %(event_type)s
                                  AND COALESCE(event_details_json->'context'->>'run_id', '') = %(rid)s
                                  AND (%(dsid)s = '' OR COALESCE(dataset_id, '') = %(dsid)s)
                                LIMIT 1;
                                """,
                                {"event_type": event_type, "rid": rid, "dsid": str(dsid or "")},
                            )
                            matched = bool(cur.fetchone())
                            if (not matched) and run_started_at and run_completed_at:
                                cur.execute(
                                    f"""
                                    SELECT 1
                                    FROM {audit_table}
                                    WHERE event_type = %(event_type)s
                                      AND step = 'step1'
                                      AND (%(dsid)s = '' OR COALESCE(dataset_id, '') = %(dsid)s)
                                      AND created_at >= %(started_at)s::timestamptz
                                      AND created_at <= %(completed_at)s::timestamptz
                                    LIMIT 1;
                                    """,
                                    {
                                        "event_type": event_type,
                                        "dsid": str(dsid or ""),
                                        "started_at": run_started_at,
                                        "completed_at": run_completed_at,
                                    },
                                )
                                matched = bool(cur.fetchone())
                        if matched:
                            hits += 1
                    numerator = hits
                    value = float(numerator) / float(denominator)

    return {
        "metric_name": "audit_completeness",
        "metric_value": value,
        "numerator": numerator,
        "denominator": denominator,
        "status": "measured" if denominator > 0 else "not_collected",
        "details_json": {
            "formula": "logged_events / expected_events",
            "source": f"{audit_table}(event_type,event_details_json.context,dataset_id)",
            "run_id": run_id,
            "required_events": required_events,
            "dataset_ids": dataset_ids,
        },
    }


def generate_step1_metrics(*, run_id: str) -> dict[str, Any]:
    from services_parent.model_v1.db import (
        derive_step1_canonical_mapping_completeness,
        derive_step1_dataset_lineage_coverage,
        derive_step1_domain_classification_accuracy,
        derive_step1_lineage_hash_consistency,
        derive_step1_schema_validation_success_rate,
        derive_step1_scope_assignment_confidence,
    )

    cleanup_counts = purge_deprecated_metrics(step="step1")
    run = _query_workflow_run(run_id, step_name="step1")
    if not run:
        return {"ok": False, "error": "step1_run_not_found", "run_id": run_id}
    run_metrics = run.get("run_metrics") if isinstance(run.get("run_metrics"), dict) else {}
    lineage_hash = str(
        run_metrics.get("step1_ingest_lineage_hash")
        or run_metrics.get("step1_dataset_lineage_hash")
        or ""
    ).strip()
    if not lineage_hash:
        lineage_hash = _resolve_step1_lineage_hash_from_dataset_splits(run_id)

    collectors: list[tuple[str, Any]] = [
        ("schema_validation_success_rate", lambda: derive_step1_schema_validation_success_rate(run_id=run_id)),
        ("domain_classification_accuracy", lambda: derive_step1_domain_classification_accuracy(run_id=run_id)),
        ("canonical_mapping_completeness", lambda: derive_step1_canonical_mapping_completeness(run_id=run_id)),
        ("dataset_lineage_coverage", lambda: derive_step1_dataset_lineage_coverage(run_id=run_id)),
        ("scope_assignment_confidence", lambda: derive_step1_scope_assignment_confidence(run_id=run_id)),
        ("split_integrity_rate", lambda: _derive_step1_split_integrity_metric(run_id=run_id, run_metrics=run_metrics)),
        (
            "lineage_hash_consistency",
            lambda: derive_step1_lineage_hash_consistency(run_id=run_id, step1_lineage_hash=lineage_hash),
        ),
        ("audit_completeness", lambda: _derive_step1_audit_completeness_metric(run_id=run_id)),
    ]

    profile = _metric_worker_profile()
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=min(profile["max_threads"], len(collectors))) as ex:
        fut_map = {ex.submit(fn): metric_name for metric_name, fn in collectors}
        for fut in as_completed(fut_map):
            metric_name = fut_map[fut]
            try:
                row = fut.result()
                if not isinstance(row, dict):
                    row = {}
                rows.append(
                    {
                        "metric_name": metric_name,
                        "metric_value": row.get("metric_value"),
                        "numerator": row.get("numerator"),
                        "denominator": row.get("denominator"),
                        "calculation_status": str(row.get("status") or "not_collected"),
                        "source_ref": "step1_runtime_derivation",
                        "details_json": row.get("details_json") if isinstance(row.get("details_json"), dict) else {},
                    }
                )
            except Exception as exc:
                errors.append(f"{metric_name}:{exc}")
                rows.append(
                    {
                        "metric_name": metric_name,
                        "metric_value": None,
                        "numerator": 0,
                        "denominator": 0,
                        "calculation_status": "not_collected",
                        "source_ref": "step1_runtime_derivation",
                        "details_json": {"error": str(exc)},
                    }
                )

    ingest = _ingest_metrics_threaded(
        step="step1",
        step_unique_id=run_id,
        metric_rows=rows,
        lineage={"run_id": run_id, "workflow_id": run.get("workflow_id"), "step_name": "step1"},
    )

    required = _step_required_metrics("step1")
    produced = {str(r.get("metric_name") or ""): r for r in rows if isinstance(r, dict)}
    missing = [m for m in required if str((produced.get(m) or {}).get("calculation_status") or "") != "measured"]
    warning = bool(missing or errors or list(ingest.get("ingest_errors") or []))
    return {
        "ok": True,
        "status": "completed_with_warning" if warning else "completed",
        "warning": warning,
        "step": "step1",
        "run_id": run_id,
        "worker_profile": profile,
        "required_metric_count": len(required),
        "produced_metric_count": len(rows),
        "ingested_metric_count": int(ingest.get("ingested_rows") or 0),
        "missing_metrics": missing,
        "missing_requirements": _missing_requirements("step1", missing),
        "errors": errors + list(ingest.get("ingest_errors") or []),
        "deprecated_metric_cleanup": cleanup_counts,
    }


def generate_step2_metrics(*, run_id: str) -> dict[str, Any]:
    cleanup_counts = purge_deprecated_metrics(step="step2")
    run = _query_workflow_run(run_id, step_name="step2")
    if not run:
        return {"ok": False, "error": "step2_run_not_found", "run_id": run_id}
    run_metrics = run.get("run_metrics") if isinstance(run.get("run_metrics"), dict) else {}
    model_id = str(run_metrics.get("model_id") or "").strip()
    model_version = str(run_metrics.get("model_version") or "").strip()
    metrics_update = (
        run_metrics.get("metrics_principle_review_update")
        if isinstance(run_metrics.get("metrics_principle_review_update"), dict)
        else {}
    )
    metrics_map_fallback = metrics_update.get("metrics") if isinstance(metrics_update.get("metrics"), dict) else {}
    metrics_map_primary = _build_step2_metrics_from_run_metrics(run_metrics)

    # Step 2 end-of-run payload is primary; legacy principle-update map is fallback/override
    # for runs generated by older code paths.
    metrics_map: dict[str, dict[str, Any]] = {}
    for metric_name in sorted(set(metrics_map_primary.keys()) | set(metrics_map_fallback.keys())):
        primary_row = metrics_map_primary.get(metric_name)
        fallback_row = metrics_map_fallback.get(metric_name)
        if isinstance(primary_row, dict):
            metrics_map[metric_name] = dict(primary_row)
            if isinstance(fallback_row, dict):
                for k, v in fallback_row.items():
                    if k not in metrics_map[metric_name] or metrics_map[metric_name].get(k) in (None, "", []):
                        metrics_map[metric_name][k] = v
        elif isinstance(fallback_row, dict):
            metrics_map[metric_name] = dict(fallback_row)

    profile = _metric_worker_profile()
    collectors: list[tuple[str, Any]] = []
    for metric_name, row in metrics_map.items():
        if not isinstance(row, dict):
            continue
        mname = str(metric_name or "").strip()
        if not mname:
            continue
        mrow = dict(row)
        value = mrow.get("value")
        numerator = mrow.get("numerator")
        denominator = mrow.get("denominator")
        if (
            value is None
            and mname in {"accuracy", "false_positive_rate", "false_negative_rate"}
            and _safe_ratio(numerator, denominator) is not None
        ):
            value = _safe_ratio(numerator, denominator)
        if (
            numerator is None
            and mname in {"accuracy", "false_positive_rate", "false_negative_rate"}
            and value is not None
            and _safe_float(denominator) > 0
        ):
            numerator = float(_safe_float(value) * _safe_float(denominator))
        if (
            mname in {"accuracy", "false_positive_rate", "false_negative_rate"}
            and value is not None
            and _safe_float(denominator) <= 0
        ):
            denominator = 1.0
            if numerator is None:
                numerator = float(_safe_float(value))
        collectors.append(
            (
                mname,
                lambda metric_name=mname, row=mrow, metric_value=value, metric_numerator=numerator, metric_denominator=denominator: {
                    "metric_name": metric_name,
                    "metric_value": metric_value,
                    "numerator": metric_numerator,
                    "denominator": metric_denominator,
                    "calculation_status": "measured" if metric_value is not None else "not_collected",
                    "principle_status": str(row.get("status") or ""),
                    "source_ref": str(row.get("source_ref") or "step2_metrics_principle_update"),
                    "details_json": {"note": str(row.get("note") or "")},
                },
            )
        )
    collected_rows, collector_errors, calc_threads = _threaded_collect(collectors, profile=profile)
    rows: dict[str, dict[str, Any]] = {
        str(row.get("metric_name") or ""): row for row in collected_rows if str(row.get("metric_name") or "").strip()
    }

    step_unique_id = model_id or run_id
    ingest = _ingest_metrics_threaded(
        step="step2",
        step_unique_id=step_unique_id,
        metric_rows=rows,
        lineage={
            "run_id": run_id,
            "model_id": model_id,
            "model_version": model_version,
            "workflow_id": run.get("workflow_id"),
        },
    )

    required = _step_required_metrics("step2")
    missing = [m for m in required if str((rows.get(m) or {}).get("calculation_status") or "") != "measured"]
    warning = bool(missing or collector_errors or list(ingest.get("ingest_errors") or []))
    return {
        "ok": True,
        "status": "completed_with_warning" if warning else "completed",
        "warning": warning,
        "step": "step2",
        "run_id": run_id,
        "model_id": model_id,
        "model_version": model_version,
        "worker_profile": profile,
        "calculation_worker_threads": calc_threads,
        "required_metric_count": len(required),
        "produced_metric_count": len(rows),
        "ingested_metric_count": int(ingest.get("ingested_rows") or 0),
        "missing_metrics": missing,
        "missing_requirements": _missing_requirements("step2", missing),
        "errors": collector_errors + list(ingest.get("ingest_errors") or []),
        "deprecated_metric_cleanup": cleanup_counts,
    }


def _step3_worker_profile() -> dict[str, Any]:
    # Step 3 metric generation is explicitly pinned to 20 worker threads.
    return {
        "total_cores": 20,
        "cpu_cap_pct": 1.0,
        "max_threads": 20,
    }


def _step3_metric_row(
    *,
    metric_name: str,
    metric_value: float | None,
    numerator: float | int | None,
    denominator: float | int | None,
    source_ref: str,
    calculation_method: str,
    principle_status: str,
    note: str = "",
    missing_requirements: list[str] | None = None,
    calculation_status: str | None = None,
    details_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    status = str(calculation_status or "").strip() or ("measured" if metric_value is not None else "not_collected")
    details: dict[str, Any] = {"formula": calculation_method}
    if note:
        details["note"] = note
    if missing_requirements:
        details["missing_requirements"] = list(missing_requirements)
    if isinstance(details_extra, dict):
        details.update(details_extra)
    return {
        "metric_name": metric_name,
        "metric_value": metric_value,
        "numerator": numerator,
        "denominator": denominator,
        "calculation_status": status,
        "principle_status": principle_status,
        "source_ref": source_ref,
        "details_json": details,
    }


def _ensure_step3_v2_metric_evidence_schema() -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS phase4.step3_v2_metric_evidence (
                    evidence_id uuid PRIMARY KEY,
                    simulation_id uuid NOT NULL REFERENCES phase4.step3_v2_simulations(simulation_id) ON DELETE CASCADE,
                    metric_name text NOT NULL,
                    evidence_kind text NOT NULL DEFAULT 'manual',
                    numerator double precision,
                    denominator double precision,
                    metric_value double precision,
                    source_ref text,
                    evidence_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
                    created_at_utc timestamptz NOT NULL DEFAULT now(),
                    updated_at_utc timestamptz NOT NULL DEFAULT now()
                );
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_step3_v2_metric_evidence_sim_metric ON phase4.step3_v2_metric_evidence(simulation_id, metric_name, updated_at_utc DESC);"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_step3_v2_metric_evidence_kind ON phase4.step3_v2_metric_evidence(metric_name, evidence_kind);"
            )
        conn.commit()


def _step3_v2_evidence_rows(cur: Any, *, sim_id: str) -> dict[str, dict[str, Any]]:
    _ensure_step3_v2_metric_evidence_schema()
    cur.execute(
        """
        SELECT
            metric_name,
            COALESCE(SUM(numerator), 0.0) AS numerator_sum,
            COALESCE(SUM(denominator), 0.0) AS denominator_sum,
            AVG(metric_value) FILTER (WHERE metric_value IS NOT NULL) AS metric_value_avg,
            COUNT(*) FILTER (WHERE metric_value IS NOT NULL) AS metric_value_count,
            COUNT(*) AS evidence_count,
            MAX(updated_at_utc) AS updated_at_utc,
            jsonb_agg(jsonb_build_object(
                'evidence_kind', evidence_kind,
                'numerator', numerator,
                'denominator', denominator,
                'metric_value', metric_value,
                'source_ref', source_ref,
                'evidence_payload', evidence_payload
            ) ORDER BY updated_at_utc DESC) AS evidence_rows
        FROM phase4.step3_v2_metric_evidence
        WHERE simulation_id = %(sid)s::uuid
        GROUP BY metric_name;
        """,
        {"sid": sim_id},
    )
    out: dict[str, dict[str, Any]] = {}
    for metric_name, numerator_sum, denominator_sum, value_avg, value_count, evidence_count, updated_at, evidence_rows in cur.fetchall() or []:
        num = _safe_float(numerator_sum)
        den = _safe_float(denominator_sum)
        if den > 0.0:
            value = num / den
            numerator = num
            denominator = den
        else:
            value = None
            numerator = None
            denominator = None
        out[str(metric_name or "").strip()] = {
            "metric_value": value,
            "numerator": numerator,
            "denominator": denominator,
            "evidence_count": _safe_int(evidence_count),
            "updated_at_utc": str(updated_at) if updated_at else "",
            "evidence_rows": evidence_rows if isinstance(evidence_rows, list) else [],
        }
    return out


def _step3_snapshot(*, replay_run_id: str) -> dict[str, Any]:
    out: dict[str, Any] = {
        "alerts_total": 0,
        "escalated_alerts": 0,
        "cross_scope_alerts": 0,
        "attack_alerts": 0,
        "benign_alerts": 0,
        "enriched_alerts": 0,
        "alert_rows_for_density": 0,
        "filled_context_fields": 0,
        "meta_alerts": 0,
        "prediction_confidence_avg": None,
        "recommendation_total": 0,
        "parent_actions_total": 0,
        "containment_attempts_actions": 0,
        "containment_success_actions": 0,
        "feedback_count": 0,
        "feedback_usefulness_avg": None,
        "feedback_triage_ms_avg": None,
        "feedback_false_positive": 0,
        "feedback_true_positive": 0,
        "feedback_total_responses": 0,
        "feedback_correct_responses": 0,
        "feedback_containment_attempts": 0,
        "feedback_containment_success": 0,
        "feedback_useful_meta_alerts": 0,
        "attack_packets_total": 0,
        "replay_packets_total": 0,
        "replay_stream_paths_total": 0,
        "isolated_paths": 0,
        "visible_paths": 0,
        "distributed_events": 0,
        "correlated_events": 0,
        "rule_hits_total": 0,
        "rule_hits_with_scope": 0,
        "rule_patterns_total": 0,
        "rule_patterns_recurring": 0,
        "traceable_rules_total": 0,
        "traceable_rules": 0,
        "rule_hits_for_precision": 0,
        "scope_correct_rules": 0,
        "temporal_alerts": 0,
        "temporal_upgraded_alerts": 0,
        "model_version": "",
        "model_id": "",
        "replay_ref": "",
        "metrics_payload": {},
    }
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT replay_run_id::text, model_id::text, model_version, preparation_replay_id::text, metrics
                FROM phase4.step3_replay_metrics
                WHERE replay_run_id = %(rid)s::uuid
                LIMIT 1;
                """,
                {"rid": replay_run_id},
            )
            base = cur.fetchone()
            if base:
                out["model_id"] = str(base[1] or "")
                out["model_version"] = str(base[2] or "")
                out["replay_ref"] = str(base[3] or base[0] or "")
                out["metrics_payload"] = _parse_json(base[4])

            cur.execute(
                """
                SELECT
                    COUNT(*)::bigint AS alerts_total,
                    COUNT(*) FILTER (WHERE parent_action_id IS NOT NULL OR COALESCE(urgency, '') IN ('high','critical'))::bigint AS escalated_alerts,
                    COUNT(*) FILTER (WHERE cross_scope_flag IS TRUE)::bigint AS cross_scope_alerts,
                    COUNT(*) FILTER (WHERE COALESCE(payload->>'packet_label','') = 'attack')::bigint AS attack_alerts,
                    COUNT(*) FILTER (WHERE COALESCE(payload->>'packet_label','') = 'benign')::bigint AS benign_alerts,
                    COUNT(*) FILTER (
                        WHERE COALESCE(expected_environment,'') <> ''
                          AND COALESCE(observed_environment,'') <> ''
                          AND COALESCE(escalation_reason,'') <> ''
                          AND payload <> '{}'::jsonb
                    )::bigint AS enriched_alerts,
                    COUNT(*) FILTER (
                        WHERE LOWER(COALESCE(payload->>'meta_alert','false')) IN ('1','true','yes')
                    )::bigint AS meta_alerts,
                    COALESCE(SUM(
                        (CASE WHEN COALESCE(expected_environment,'') <> '' THEN 1 ELSE 0 END) +
                        (CASE WHEN COALESCE(observed_environment,'') <> '' THEN 1 ELSE 0 END) +
                        (CASE WHEN COALESCE(escalation_reason,'') <> '' THEN 1 ELSE 0 END) +
                        (CASE WHEN COALESCE(shap_evidence_status,'') NOT IN ('','not_available') THEN 1 ELSE 0 END)
                    ), 0)::bigint AS filled_context_fields,
                    AVG(
                        CASE
                            WHEN JSONB_TYPEOF(payload->'prediction') = 'object'
                             AND COALESCE(payload->'prediction'->>'confidence','') ~ '^[0-9]+(\\.[0-9]+)?$'
                            THEN (payload->'prediction'->>'confidence')::double precision
                            ELSE NULL
                        END
                    ) AS prediction_confidence_avg
                FROM phase4.step3_alerts
                WHERE replay_run_id = %(rid)s::uuid;
                """,
                {"rid": replay_run_id},
            )
            alert_row = cur.fetchone() or (0, 0, 0, 0, 0, 0, 0, 0, None)
            out["alerts_total"] = int(alert_row[0] or 0)
            out["escalated_alerts"] = int(alert_row[1] or 0)
            out["cross_scope_alerts"] = int(alert_row[2] or 0)
            out["attack_alerts"] = int(alert_row[3] or 0)
            out["benign_alerts"] = int(alert_row[4] or 0)
            out["enriched_alerts"] = int(alert_row[5] or 0)
            out["meta_alerts"] = int(alert_row[6] or 0)
            out["filled_context_fields"] = int(alert_row[7] or 0)
            out["prediction_confidence_avg"] = float(alert_row[8]) if alert_row[8] is not None else None
            out["alert_rows_for_density"] = out["alerts_total"]

            cur.execute(
                """
                SELECT
                    COUNT(*)::bigint AS parent_actions_total,
                    COUNT(*) FILTER (WHERE COALESCE(action_type,'') = 'recommendation')::bigint AS recommendation_total,
                    COUNT(*) FILTER (WHERE LOWER(COALESCE(recommendation,'')) LIKE '%%isolate%%')::bigint AS containment_attempts,
                    COUNT(*) FILTER (
                        WHERE LOWER(COALESCE(recommendation,'')) LIKE '%%isolate%%'
                          AND COALESCE(status,'') IN ('completed','resolved','closed')
                    )::bigint AS containment_successes
                FROM phase4.parent_actions
                WHERE replay_run_id = %(rid)s::uuid;
                """,
                {"rid": replay_run_id},
            )
            action_row = cur.fetchone() or (0, 0, 0, 0)
            out["parent_actions_total"] = int(action_row[0] or 0)
            out["recommendation_total"] = int(action_row[1] or 0)
            out["containment_attempts_actions"] = int(action_row[2] or 0)
            out["containment_success_actions"] = int(action_row[3] or 0)

            cur.execute(
                """
                SELECT
                    COUNT(*)::bigint AS feedback_count,
                    AVG(usefulness_score)::double precision AS usefulness_avg,
                    AVG(triage_duration_ms)::double precision AS triage_ms_avg,
                    COUNT(*) FILTER (WHERE alert_verdict = 'false_positive')::bigint AS fp_count,
                    COUNT(*) FILTER (WHERE alert_verdict = 'true_positive')::bigint AS tp_count,
                    COUNT(*) FILTER (WHERE feedback_payload ? 'response_correct')::bigint AS total_responses,
                    COUNT(*) FILTER (WHERE LOWER(COALESCE(feedback_payload->>'response_correct','false')) IN ('1','true','yes'))::bigint AS correct_responses,
                    COUNT(*) FILTER (WHERE LOWER(COALESCE(feedback_payload->>'containment_attempt','false')) IN ('1','true','yes'))::bigint AS containment_attempts_fb,
                    COUNT(*) FILTER (WHERE LOWER(COALESCE(feedback_payload->>'containment_success','false')) IN ('1','true','yes'))::bigint AS containment_success_fb,
                    COUNT(*) FILTER (WHERE LOWER(COALESCE(feedback_payload->>'meta_alert_useful','false')) IN ('1','true','yes'))::bigint AS useful_meta_alerts
                FROM phase4.step3_analyst_feedback
                WHERE replay_run_id = %(rid)s::uuid
                   OR (%(ref)s <> '' AND COALESCE(replay_id::text, '') = %(ref)s);
                """,
                {"rid": replay_run_id, "ref": str(out["replay_ref"] or "")},
            )
            fb_row = cur.fetchone() or (0, None, None, 0, 0, 0, 0, 0, 0, 0)
            out["feedback_count"] = int(fb_row[0] or 0)
            out["feedback_usefulness_avg"] = float(fb_row[1]) if fb_row[1] is not None else None
            out["feedback_triage_ms_avg"] = float(fb_row[2]) if fb_row[2] is not None else None
            out["feedback_false_positive"] = int(fb_row[3] or 0)
            out["feedback_true_positive"] = int(fb_row[4] or 0)
            out["feedback_total_responses"] = int(fb_row[5] or 0)
            out["feedback_correct_responses"] = int(fb_row[6] or 0)
            out["feedback_containment_attempts"] = int(fb_row[7] or 0)
            out["feedback_containment_success"] = int(fb_row[8] or 0)
            out["feedback_useful_meta_alerts"] = int(fb_row[9] or 0)

            cur.execute(
                """
                SELECT
                    COALESCE(SUM(packets_attack_in_file), 0)::bigint AS attack_packets_total,
                    COALESCE(SUM(packets_total_in_file), 0)::bigint AS replay_packets_total
                FROM phase4.step3_replay_file_stats
                WHERE replay_run_id = %(rid)s::uuid;
                """,
                {"rid": replay_run_id},
            )
            fs_row = cur.fetchone() or (0, 0)
            out["attack_packets_total"] = int(fs_row[0] or 0)
            out["replay_packets_total"] = int(fs_row[1] or 0)

            cur.execute(
                """
                SELECT
                    COUNT(*)::bigint AS replay_stream_paths_total,
                    COUNT(*) FILTER (
                        WHERE LOWER(COALESCE(metadata->>'management_path_separate','false')) IN ('1','true','yes')
                    )::bigint AS isolated_paths
                FROM phase4.replay_streams
                WHERE replay_run_id = %(rid)s::uuid;
                """,
                {"rid": replay_run_id},
            )
            rs_row = cur.fetchone() or (0, 0)
            out["replay_stream_paths_total"] = int(rs_row[0] or 0)
            out["isolated_paths"] = int(rs_row[1] or 0)

            cur.execute(
                """
                SELECT COUNT(DISTINCT replay_stream_id)::bigint
                FROM phase4.step3_replay_flow_events
                WHERE replay_run_id = %(rid)s::uuid
                  AND replay_stream_id IS NOT NULL
                  AND event_kind IN ('packet_transit','replay_summary','child_alert','escalation');
                """,
                {"rid": replay_run_id},
            )
            out["visible_paths"] = int((cur.fetchone() or [0])[0] or 0)

            cur.execute(
                """
                WITH match_rows AS (
                    SELECT COALESCE(payload->>'packet_or_flow_id','') AS packet_or_flow_id, child_id
                    FROM phase4.step3_child_rule_matches
                    WHERE COALESCE(replay_id::text, '') = %(ref)s
                      AND COALESCE(payload->>'packet_or_flow_id','') <> ''
                ),
                grouped AS (
                    SELECT packet_or_flow_id, COUNT(DISTINCT child_id)::bigint AS child_cnt
                    FROM match_rows
                    GROUP BY packet_or_flow_id
                ),
                alert_rows AS (
                    SELECT DISTINCT COALESCE(payload->>'packet_or_flow_id','') AS packet_or_flow_id
                    FROM phase4.step3_alerts
                    WHERE replay_run_id = %(rid)s::uuid
                      AND COALESCE(payload->>'packet_or_flow_id','') <> ''
                )
                SELECT
                    COUNT(*) FILTER (WHERE child_cnt > 1)::bigint AS distributed_events,
                    COUNT(*) FILTER (
                        WHERE child_cnt > 1
                          AND packet_or_flow_id IN (SELECT packet_or_flow_id FROM alert_rows)
                    )::bigint AS correlated_events
                FROM grouped;
                """,
                {"rid": replay_run_id, "ref": str(out["replay_ref"] or "")},
            )
            corr_row = cur.fetchone() or (0, 0)
            out["distributed_events"] = int(corr_row[0] or 0)
            out["correlated_events"] = int(corr_row[1] or 0)

            cur.execute(
                """
                SELECT
                    COUNT(*)::bigint AS rule_hits_total,
                    COUNT(*) FILTER (WHERE COALESCE(payload->>'rule_scope','') <> '')::bigint AS rule_hits_with_scope
                FROM phase4.step3_child_rule_matches
                WHERE COALESCE(replay_id::text, '') = %(ref)s;
                """,
                {"ref": str(out["replay_ref"] or "")},
            )
            rm_row = cur.fetchone() or (0, 0)
            out["rule_hits_total"] = int(rm_row[0] or 0)
            out["rule_hits_with_scope"] = int(rm_row[1] or 0)
            out["rule_hits_for_precision"] = out["rule_hits_total"]

            cur.execute(
                """
                WITH sigs AS (
                    SELECT CONCAT_WS(
                        '|',
                        COALESCE(rule_id, ''),
                        COALESCE(payload->>'rule_scope', ''),
                        COALESCE(payload->'context'->>'cross_scope_flag', '')
                    ) AS sig
                    FROM phase4.step3_child_rule_matches
                    WHERE COALESCE(replay_id::text, '') = %(ref)s
                ),
                grouped AS (
                    SELECT sig, COUNT(*)::bigint AS cnt
                    FROM sigs
                    WHERE sig <> ''
                    GROUP BY sig
                )
                SELECT
                    COALESCE(SUM(cnt), 0)::bigint AS total_patterns,
                    COALESCE(SUM(CASE WHEN cnt > 1 THEN cnt - 1 ELSE 0 END), 0)::bigint AS recurring_patterns
                FROM grouped;
                """,
                {"ref": str(out["replay_ref"] or "")},
            )
            rec_row = cur.fetchone() or (0, 0)
            out["rule_patterns_total"] = int(rec_row[0] or 0)
            out["rule_patterns_recurring"] = int(rec_row[1] or 0)

            cur.execute(
                """
                SELECT
                    COUNT(*)::bigint AS total_rules,
                    COUNT(*) FILTER (
                        WHERE COALESCE(a.rulepack_version,'') <> ''
                          AND COALESCE(pa.rulepack_version,'') <> ''
                    )::bigint AS traceable_rules,
                    COUNT(*) FILTER (
                        WHERE COALESCE(a.expected_environment,'') = COALESCE(a.observed_environment,'')
                          AND COALESCE(a.expected_environment,'') <> ''
                    )::bigint AS scope_correct_rules
                FROM phase4.step3_alerts a
                LEFT JOIN phase4.parent_actions pa ON pa.parent_action_id = a.parent_action_id
                WHERE a.replay_run_id = %(rid)s::uuid;
                """,
                {"rid": replay_run_id},
            )
            tr_row = cur.fetchone() or (0, 0, 0)
            out["traceable_rules_total"] = int(tr_row[0] or 0)
            out["traceable_rules"] = int(tr_row[1] or 0)
            out["scope_correct_rules"] = int(tr_row[2] or 0)

            cur.execute(
                """
                SELECT
                    COUNT(*)::bigint AS temporal_alerts,
                    COUNT(*) FILTER (
                        WHERE parent_action_id IS NOT NULL
                          AND LOWER(COALESCE(escalation_reason,'')) LIKE '%%mismatch%%'
                    )::bigint AS temporal_upgraded_alerts
                FROM phase4.step3_alerts
                WHERE replay_run_id = %(rid)s::uuid;
                """,
                {"rid": replay_run_id},
            )
            t_row = cur.fetchone() or (0, 0)
            out["temporal_alerts"] = int(t_row[0] or 0)
            out["temporal_upgraded_alerts"] = int(t_row[1] or 0)
    return out


def _step3_stability_ratio(*, model_version: str) -> tuple[float | None, int, int]:
    mv = str(model_version or "").strip()
    if not mv:
        return None, 0, 0
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT rr.replay_run_id::text, COALESCE(SUM(rs.alerts_generated), 0)::bigint AS hits
                FROM phase4.replay_runs rr
                LEFT JOIN phase4.replay_streams rs
                       ON rs.replay_run_id = rr.replay_run_id
                WHERE rr.model_version = %(mv)s
                  AND COALESCE(rr.status, '') = 'completed'
                GROUP BY rr.replay_run_id
                ORDER BY rr.replay_run_id;
                """,
                {"mv": mv},
            )
            rows = cur.fetchall() or []
    hits = [int(r[1] or 0) for r in rows]
    if len(hits) < 2:
        return None, 0, len(hits)
    sorted_hits = sorted(hits)
    mid = len(sorted_hits) // 2
    if len(sorted_hits) % 2 == 0:
        median_hits = (sorted_hits[mid - 1] + sorted_hits[mid]) / 2.0
    else:
        median_hits = float(sorted_hits[mid])
    tolerance = max(1.0, median_hits * 0.10)
    stable = sum(1 for h in hits if abs(float(h) - median_hits) <= tolerance)
    ratio = _safe_ratio(stable, len(hits))
    return ratio, stable, len(hits)


def _step3_model_version_traceability(
    *,
    model_id: str,
    replay_run_id: str,
    simulation_id: str,
) -> tuple[float | None, int, int]:
    mid = str(model_id or "").strip()
    rid = str(replay_run_id or "").strip()
    sid = str(simulation_id or "").strip()
    if not (_is_uuid_like(mid) and _is_uuid_like(rid) and _is_uuid_like(sid)):
        return None, 0, 4

    present = 0
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT 1
                FROM phase4.model_registry
                WHERE model_id = %(mid)s::uuid
                LIMIT 1;
                """,
                {"mid": mid},
            )
            present += 1 if cur.fetchone() else 0

            cur.execute(
                """
                SELECT 1
                FROM phase4.workflow_runs
                WHERE step_name = 'step2'
                  AND COALESCE(run_metrics->>'model_id', '') = %(mid)s
                ORDER BY started_at_utc DESC
                LIMIT 1;
                """,
                {"mid": mid},
            )
            present += 1 if cur.fetchone() else 0

            cur.execute(
                """
                SELECT 1
                FROM phase4.replay_runs
                WHERE replay_run_id = %(rid)s::uuid
                  AND (
                        simulation_session_id = %(sid)s::uuid
                     OR preparation_replay_id = %(sid)s::uuid
                     OR replay_id = %(sid)s::uuid
                  )
                LIMIT 1;
                """,
                {"rid": rid, "sid": sid},
            )
            present += 1 if cur.fetchone() else 0

            cur.execute(
                """
                SELECT 1
                FROM phase4.step3_replay_metrics
                WHERE replay_run_id = %(rid)s::uuid
                  AND (
                        simulation_session_id = %(sid)s::uuid
                     OR preparation_replay_id = %(sid)s::uuid
                  )
                LIMIT 1;
                """,
                {"rid": rid, "sid": sid},
            )
            present += 1 if cur.fetchone() else 0

    return _safe_ratio(present, 4), present, 4


def _step3_v2_model_version_traceability(*, model_id: str, sim_id: str) -> tuple[float | None, int, int]:
    mid = str(model_id or "").strip()
    sid = str(sim_id or "").strip()
    if not (_is_uuid_like(mid) and _is_uuid_like(sid)):
        return None, 0, 3

    present = 0
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT 1
                FROM phase4.model_registry
                WHERE model_id = %(mid)s::uuid
                LIMIT 1;
                """,
                {"mid": mid},
            )
            present += 1 if cur.fetchone() else 0

            cur.execute(
                """
                SELECT 1
                FROM phase4.workflow_runs
                WHERE step_name = 'step2'
                  AND COALESCE(run_metrics->>'model_id', '') = %(mid)s
                ORDER BY started_at_utc DESC
                LIMIT 1;
                """,
                {"mid": mid},
            )
            present += 1 if cur.fetchone() else 0

            cur.execute(
                """
                SELECT 1
                FROM phase4.step3_v2_simulations
                WHERE simulation_id = %(sid)s::uuid
                  AND model_id = %(mid)s::uuid
                LIMIT 1;
                """,
                {"sid": sid, "mid": mid},
            )
            present += 1 if cur.fetchone() else 0

    return _safe_ratio(present, 3), present, 3


def _generate_step3_v2_metrics(*, sim_id: str) -> dict[str, Any]:
    sid = str(sim_id or "").strip()
    if not _is_uuid_like(sid):
        return {"ok": False, "error": "invalid_step3_v2_sim_id", "sim_id": sid}

    _ensure_step3_v2_metric_evidence_schema()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT simulation_id::text, model_id::text, model_version, status, metadata, isolation_type
                FROM phase4.step3_v2_simulations
                WHERE simulation_id = %(sid)s::uuid
                LIMIT 1;
                """,
                {"sid": sid},
            )
            sim_row = cur.fetchone()
            if not sim_row:
                return {"ok": False, "error": "step3_v2_simulation_not_found", "sim_id": sid}

            cur.execute(
                """
                SELECT
                    COUNT(*)::bigint AS packets_total,
                    COUNT(*) FILTER (WHERE COALESCE(packet_label, '') = 'attack')::bigint AS attack_packets,
                    COUNT(*) FILTER (WHERE COALESCE(packet_label, '') = 'benign')::bigint AS benign_packets,
                    COALESCE(SUM(rule_hit_count), 0)::bigint AS rule_hits_packets,
                    COUNT(DISTINCT child_id)::bigint AS child_count,
                    COUNT(DISTINCT pcap_file)::bigint AS pcap_count,
                    COUNT(DISTINCT pcap_file || ':' || child_id)::bigint AS visible_paths,
                    COUNT(DISTINCT COALESCE(payload->>'packet_or_flow_id', '')) FILTER (WHERE COALESCE(payload->>'packet_or_flow_id', '') <> '')::bigint AS packet_flow_ids,
                    COUNT(DISTINCT COALESCE(payload->>'packet_or_flow_id', '')) FILTER (
                        WHERE COALESCE(packet_label, '') = 'attack'
                          AND COALESCE(payload->>'packet_or_flow_id', '') <> ''
                    )::bigint AS attack_packet_flow_ids,
                    COUNT(*) FILTER (
                        WHERE payload ? 'isolation_valid'
                           OR payload ? 'isolated'
                           OR payload ? 'isolation_type'
                    )::bigint AS isolation_evidence_rows,
                    COUNT(*) FILTER (
                        WHERE LOWER(COALESCE(payload->>'isolation_valid', payload->>'isolated', '')) IN ('1','true','yes')
                           OR (
                                payload ? 'isolation_type'
                            AND LOWER(COALESCE(payload->>'isolation_type', '')) NOT IN ('', 'none', 'shared')
                           )
                    )::bigint AS isolated_packet_rows
                FROM phase4.step3_v2_child_packets
                WHERE simulation_id = %(sid)s::uuid;
                """,
                {"sid": sid},
            )
            packet_row = cur.fetchone() or (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

            cur.execute(
                """
                WITH a AS (
                    SELECT *, 1 AS weight
                    FROM phase4.step3_v2_alerts
                    WHERE simulation_id = %(sid)s::uuid
                ), normalized AS (
                    SELECT *,
                        COALESCE(payload->>'expected_environment', payload->>'expected_scope', '') AS expected_scope,
                        COALESCE(payload->>'observed_environment', payload->>'observed_scope', '') AS observed_scope,
                        LOWER(COALESCE(payload->>'cross_scope', payload->>'cross_scope_flag', 'false')) AS cross_scope_flag,
                        LOWER(COALESCE(payload->>'meta_alert', '')) AS meta_alert_flag,
                        LOWER(COALESCE(payload->>'temporal_alert', '')) AS temporal_alert_flag,
                        LOWER(COALESCE(payload->>'temporal_upgraded', payload->>'temporal_escalation_upgraded', '')) AS temporal_upgraded_flag,
                        LOWER(COALESCE(payload->>'cross_scope_detected', payload->>'mismatch_detected', '')) AS cross_scope_detected_flag,
                        LOWER(COALESCE(payload->>'escalated', payload->>'parent_escalated', payload->>'escalation_triggered', '')) AS escalated_flag,
                        LOWER(COALESCE(payload->>'false_positive', payload->>'is_false_positive', '')) AS false_positive_flag,
                        LOWER(COALESCE(payload->>'alert_verdict', payload->>'verdict', '')) AS verdict_raw,
                        LOWER(COALESCE(payload->>'explanation_useful', payload->>'explanation_usefulness', '')) AS explanation_useful_flag,
                        LOWER(COALESCE(payload->>'analyst_ready', payload->>'analyst_readiness', '')) AS analyst_ready_flag,
                        LOWER(COALESCE(payload->>'rule_true_positive', payload->>'true_rule_hit', '')) AS rule_true_positive_flag,
                        LOWER(COALESCE(payload->>'rule_scope_correct', payload->>'scope_correct', '')) AS rule_scope_correct_flag,
                        LOWER(COALESCE(payload->>'meta_alert_useful', payload->>'oversight_useful', '')) AS meta_alert_useful_flag,
                        COALESCE(payload->>'confidence', payload->>'prediction_confidence', payload->'prediction'->>'confidence', payload->'model_prediction'->>'confidence', '') AS confidence_raw,
                        COALESCE(payload->>'triage_duration_seconds', payload->>'triage_duration_s', '') AS triage_seconds_raw,
                        COALESCE(payload->>'triage_duration_ms', '') AS triage_ms_raw,
                        COALESCE(payload->>'rule_id', payload->>'rule_name', payload->>'rule_version', payload->>'rulepack_version', payload->>'rule_checksum', payload->>'rulepack_checksum', '') AS rule_lineage_raw,
                        COALESCE(payload->>'rule_version', payload->>'rulepack_version', payload->>'rule_checksum', payload->>'rulepack_checksum', '') AS rule_version_lineage_raw,
                        COALESCE(payload->>'packet_or_flow_id', '') AS packet_or_flow_id,
                        COALESCE(payload->>'explanation_pattern', payload->>'rule_id', recommendation, phase, '') AS pattern_key
                    FROM a
                )
                SELECT
                    COALESCE(SUM(weight), 0)::bigint AS alerts_total,
                    COUNT(*)::bigint AS alert_rows,
                    COALESCE(SUM(rule_hit_count), 0)::bigint AS rule_hits_alerts,
                    COALESCE(SUM(weight) FILTER (WHERE COALESCE(packet_label, '') = 'attack'), 0)::bigint AS attack_alerts,
                    COALESCE(SUM(weight) FILTER (WHERE COALESCE(packet_label, '') = 'benign'), 0)::bigint AS benign_alerts,
                    COALESCE(SUM(weight) FILTER (WHERE COALESCE(severity, '') IN ('high','critical')), 0)::bigint AS escalated_alerts,
                    COALESCE(SUM(weight) FILTER (
                        WHERE COALESCE(recommendation, '') <> ''
                          AND COALESCE(phase, '') <> ''
                          AND COALESCE(severity, '') <> ''
                          AND payload <> '{}'::jsonb
                    ), 0)::bigint AS enriched_alerts,
                    COALESCE(SUM(weight) FILTER (WHERE meta_alert_flag IN ('1','true','yes')), 0)::bigint AS meta_alerts,
                    COUNT(*) FILTER (WHERE payload ? 'meta_alert')::bigint AS meta_alert_tagged_rows,
                    COALESCE(SUM(weight) FILTER (
                        WHERE (expected_scope <> '' AND observed_scope <> '' AND expected_scope <> observed_scope)
                           OR cross_scope_flag IN ('1','true','yes')
                    ), 0)::bigint AS total_mismatches,
                    COALESCE(SUM(weight) FILTER (
                        WHERE ((expected_scope <> '' AND observed_scope <> '' AND expected_scope <> observed_scope)
                            OR cross_scope_flag IN ('1','true','yes'))
                          AND cross_scope_detected_flag IN ('1','true','yes')
                    ), 0)::bigint AS mismatches_detected,
                    COALESCE(SUM(weight) FILTER (WHERE temporal_alert_flag IN ('1','true','yes') OR COALESCE(phase, '') ILIKE '%%temporal%%'), 0)::bigint AS temporal_alerts,
                    COALESCE(SUM(weight) FILTER (
                        WHERE (temporal_alert_flag IN ('1','true','yes') OR COALESCE(phase, '') ILIKE '%%temporal%%')
                          AND temporal_upgraded_flag IN ('1','true','yes')
                    ), 0)::bigint AS temporal_upgraded_alerts,
                    COUNT(*) FILTER (
                        WHERE payload ? 'temporal_upgraded'
                           OR payload ? 'temporal_escalation_upgraded'
                    )::bigint AS temporal_upgrade_evidence_rows,
                    SUM(CASE WHEN confidence_raw ~ '^-?[0-9]+(\\.[0-9]+)?$' THEN confidence_raw::double precision ELSE NULL END) AS confidence_sum,
                    COUNT(*) FILTER (WHERE confidence_raw ~ '^-?[0-9]+(\\.[0-9]+)?$')::bigint AS confidence_count,
                    COALESCE(SUM(
                        (CASE WHEN COALESCE(recommendation, '') <> '' THEN 1 ELSE 0 END) +
                        (CASE WHEN COALESCE(phase, '') <> '' THEN 1 ELSE 0 END) +
                        (CASE WHEN COALESCE(severity, '') <> '' THEN 1 ELSE 0 END) +
                        (CASE WHEN payload <> '{}'::jsonb THEN 1 ELSE 0 END)
                    ), 0)::bigint AS filled_context_fields,
                    COALESCE(SUM(weight) FILTER (WHERE COALESCE(rule_lineage_raw, '') <> '' OR rule_hit_count > 0), 0)::bigint AS rule_linked_alerts,
                    COALESCE(SUM(weight) FILTER (WHERE COALESCE(rule_version_lineage_raw, '') <> ''), 0)::bigint AS traceable_rule_alerts,
                    COUNT(DISTINCT pattern_key) FILTER (WHERE COALESCE(pattern_key, '') <> '')::bigint AS total_patterns,
                    COUNT(DISTINCT packet_or_flow_id) FILTER (
                        WHERE COALESCE(packet_label, '') = 'attack'
                          AND packet_or_flow_id <> ''
                    )::bigint AS attack_alert_flow_ids,
                    COUNT(*) FILTER (
                        WHERE payload ? 'cross_scope_detected'
                           OR payload ? 'mismatch_detected'
                    )::bigint AS cross_scope_detection_evidence_rows,
                    COALESCE(SUM(weight) FILTER (WHERE escalated_flag IN ('1','true','yes') OR payload ? 'escalation_id'), 0)::bigint AS explicit_escalated_alerts,
                    COUNT(*) FILTER (
                        WHERE payload ? 'escalated'
                           OR payload ? 'parent_escalated'
                           OR payload ? 'escalation_triggered'
                           OR payload ? 'escalation_id'
                    )::bigint AS escalation_evidence_rows,
                    COALESCE(SUM(weight) FILTER (
                        WHERE (escalated_flag IN ('1','true','yes') OR payload ? 'escalation_id')
                          AND COALESCE(recommendation, '') <> ''
                    ), 0)::bigint AS recommendations_on_escalated_alerts,
                    COALESCE(SUM(weight) FILTER (
                        WHERE false_positive_flag IN ('1','true','yes')
                           OR verdict_raw = 'false_positive'
                    ), 0)::bigint AS false_positive_alerts,
                    COALESCE(SUM(weight) FILTER (
                        WHERE payload ? 'false_positive'
                           OR payload ? 'is_false_positive'
                           OR payload ? 'alert_verdict'
                           OR payload ? 'verdict'
                    ), 0)::bigint AS reviewed_false_positive_alerts,
                    COALESCE(SUM(weight) FILTER (
                        WHERE COALESCE(recommendation, '') <> ''
                           OR COALESCE(pattern_key, '') <> ''
                           OR payload ? 'explanation_useful'
                           OR payload ? 'explanation_usefulness'
                    ), 0)::bigint AS explanation_reviewed_alerts,
                    COALESCE(SUM(weight) FILTER (WHERE explanation_useful_flag IN ('1','true','yes')), 0)::bigint AS useful_explanation_alerts,
                    COALESCE(SUM(weight) FILTER (
                        WHERE payload ? 'analyst_ready'
                           OR payload ? 'analyst_readiness'
                    ), 0)::bigint AS analyst_reviewed_alerts,
                    COALESCE(SUM(weight) FILTER (WHERE analyst_ready_flag IN ('1','true','yes')), 0)::bigint AS analyst_ready_alerts,
                    COALESCE(SUM(weight) FILTER (WHERE rule_hit_count > 0 OR COALESCE(rule_lineage_raw, '') <> ''), 0)::bigint AS reviewed_rule_hits,
                    COALESCE(SUM(weight) FILTER (
                        WHERE (rule_hit_count > 0 OR COALESCE(rule_lineage_raw, '') <> '')
                          AND (
                                rule_true_positive_flag IN ('1','true','yes')
                             OR COALESCE(packet_label, '') = 'attack'
                          )
                    ), 0)::bigint AS true_rule_hits,
                    COALESCE(SUM(weight) FILTER (
                        WHERE payload ? 'rule_scope_correct'
                           OR payload ? 'scope_correct'
                           OR COALESCE(expected_scope, '') <> ''
                           OR COALESCE(observed_scope, '') <> ''
                    ), 0)::bigint AS reviewed_rule_scope_alerts,
                    COALESCE(SUM(weight) FILTER (
                        WHERE rule_scope_correct_flag IN ('1','true','yes')
                           OR (expected_scope <> '' AND observed_scope <> '' AND expected_scope = observed_scope)
                    ), 0)::bigint AS correctly_scoped_rule_alerts,
                    COALESCE(SUM(weight) FILTER (
                        WHERE escalated_flag IN ('1','true','yes')
                           OR payload ? 'escalation_id'
                    ), 0)::bigint AS reviewed_escalations,
                    COALESCE(SUM(weight) FILTER (
                        WHERE (escalated_flag IN ('1','true','yes') OR payload ? 'escalation_id')
                          AND COALESCE(recommendation, '') <> ''
                    ), 0)::bigint AS useful_escalations,
                    COALESCE(SUM(weight) FILTER (WHERE meta_alert_useful_flag IN ('1','true','yes')), 0)::bigint AS useful_meta_alerts,
                    COALESCE(SUM(CASE
                        WHEN triage_seconds_raw ~ '^-?[0-9]+(\\.[0-9]+)?$' THEN triage_seconds_raw::double precision
                        WHEN triage_ms_raw ~ '^-?[0-9]+(\\.[0-9]+)?$' THEN triage_ms_raw::double precision / 1000.0
                        ELSE NULL
                    END), 0.0) AS triage_seconds_sum,
                    COUNT(*) FILTER (
                        WHERE triage_seconds_raw ~ '^-?[0-9]+(\\.[0-9]+)?$'
                           OR triage_ms_raw ~ '^-?[0-9]+(\\.[0-9]+)?$'
                    )::bigint AS triage_duration_count
                FROM normalized;
                """,
                {"sid": sid},
            )
            alert_row = cur.fetchone() or (0,) * 45

            cur.execute(
                """
                WITH pa AS (
                    SELECT *, 1 AS weight
                    FROM phase4.step3_v2_parent_actions
                    WHERE simulation_id = %(sid)s::uuid
                )
                SELECT
                    COALESCE(SUM(weight), 0)::bigint,
                    COALESCE(SUM(weight) FILTER (
                        WHERE COALESCE(action, '') IN ('recommendation','review_and_triage')
                           OR LOWER(COALESCE(action, '')) LIKE '%%recommend%%'
                    ), 0)::bigint,
                    COALESCE(SUM(weight) FILTER (
                        WHERE LOWER(COALESCE(action, '')) LIKE '%%contain%%'
                           OR LOWER(COALESCE(action, '')) LIKE '%%isolate%%'
                    ), 0)::bigint,
                    COALESCE(SUM(weight) FILTER (WHERE LOWER(COALESCE(payload->>'response_correct','')) IN ('1','true','yes')), 0)::bigint,
                    COALESCE(SUM(weight) FILTER (WHERE payload ? 'response_correct'), 0)::bigint,
                    COALESCE(SUM(weight) FILTER (WHERE LOWER(COALESCE(payload->>'meta_alert','')) IN ('1','true','yes')), 0)::bigint,
                    COUNT(*) FILTER (WHERE payload ? 'meta_alert')::bigint,
                    COALESCE(SUM(weight) FILTER (
                        WHERE COALESCE(payload->>'rule_id', payload->>'rule_name', payload->>'rule_version', payload->>'rulepack_version', payload->>'rule_checksum', payload->>'rulepack_checksum', '') <> ''
                           OR rule_hit_count > 0
                    ), 0)::bigint,
                    COALESCE(SUM(weight) FILTER (
                        WHERE COALESCE(payload->>'rule_version', payload->>'rulepack_version', payload->>'rule_checksum', payload->>'rulepack_checksum', '') <> ''
                    ), 0)::bigint,
                    COALESCE(SUM(weight) FILTER (
                        WHERE LOWER(COALESCE(payload->>'containment_attempt','')) IN ('1','true','yes')
                           OR LOWER(COALESCE(payload->>'simulated_containment_attempt','')) IN ('1','true','yes')
                    ), 0)::bigint,
                    COALESCE(SUM(weight) FILTER (
                        WHERE LOWER(COALESCE(payload->>'containment_success','')) IN ('1','true','yes')
                    ), 0)::bigint,
                    COALESCE(SUM(weight) FILTER (
                        WHERE LOWER(COALESCE(payload->>'simulated_containment_success','')) IN ('1','true','yes')
                    ), 0)::bigint,
                    COALESCE(SUM(weight) FILTER (
                        WHERE LOWER(COALESCE(payload->>'meta_alert_useful','')) IN ('1','true','yes')
                    ), 0)::bigint,
                    COALESCE(SUM(CASE
                        WHEN COALESCE(payload->>'triage_duration_seconds', payload->>'triage_duration_s', '') ~ '^-?[0-9]+(\\.[0-9]+)?$'
                        THEN COALESCE(payload->>'triage_duration_seconds', payload->>'triage_duration_s', '')::double precision
                        WHEN COALESCE(payload->>'triage_duration_ms', '') ~ '^-?[0-9]+(\\.[0-9]+)?$'
                        THEN (payload->>'triage_duration_ms')::double precision / 1000.0
                        ELSE NULL
                    END), 0.0),
                    COUNT(*) FILTER (
                        WHERE COALESCE(payload->>'triage_duration_seconds', payload->>'triage_duration_s', '') ~ '^-?[0-9]+(\\.[0-9]+)?$'
                           OR COALESCE(payload->>'triage_duration_ms', '') ~ '^-?[0-9]+(\\.[0-9]+)?$'
                    )::bigint
                FROM pa;
                """,
                {"sid": sid},
            )
            action_row = cur.fetchone() or (0,) * 15

            cur.execute(
                """
                WITH events AS (
                    SELECT COALESCE(payload->>'packet_or_flow_id','') AS packet_or_flow_id, child_id, 'packet' AS source_kind
                    FROM phase4.step3_v2_child_packets
                    WHERE simulation_id = %(sid)s::uuid AND COALESCE(payload->>'packet_or_flow_id','') <> ''
                    UNION ALL
                    SELECT COALESCE(payload->>'packet_or_flow_id','') AS packet_or_flow_id, child_id, 'alert' AS source_kind
                    FROM phase4.step3_v2_alerts
                    WHERE simulation_id = %(sid)s::uuid AND COALESCE(payload->>'packet_or_flow_id','') <> ''
                ), distributed AS (
                    SELECT packet_or_flow_id,
                           COUNT(DISTINCT child_id) AS child_count,
                           COUNT(*) FILTER (WHERE source_kind = 'alert') AS alert_hits
                    FROM events
                    GROUP BY packet_or_flow_id
                    HAVING COUNT(DISTINCT child_id) > 1
                )
                SELECT
                    COUNT(*)::bigint AS distributed_events,
                    COUNT(*) FILTER (WHERE alert_hits > 0)::bigint AS correlated_events
                FROM distributed;
                """,
                {"sid": sid},
            )
            correlation_row = cur.fetchone() or (0, 0)

            cur.execute(
                """
                WITH patterns AS (
                    SELECT COALESCE(payload->>'explanation_pattern', payload->>'rule_id', recommendation, phase, '') AS pattern_key,
                           COUNT(*) AS row_count
                    FROM phase4.step3_v2_alerts
                    WHERE simulation_id = %(sid)s::uuid
                    GROUP BY 1
                    HAVING COALESCE(payload->>'explanation_pattern', payload->>'rule_id', recommendation, phase, '') <> ''
                )
                SELECT COUNT(*)::bigint, COUNT(*) FILTER (WHERE row_count > 1)::bigint
                FROM patterns;
                """,
                {"sid": sid},
            )
            recurrence_row = cur.fetchone() or (0, 0)

            evidence_rows = _step3_v2_evidence_rows(cur, sim_id=sid)

            model_id = str(sim_row[1] or "")
            model_version = str(sim_row[2] or "")
            cur.execute(
                """
                SELECT s.simulation_id::text,
                       COALESCE(a.payload->>'rule_checksum', a.payload->>'rulepack_checksum', a.payload->>'rule_version', a.payload->>'rulepack_version', a.payload->>'rule_id', '') AS rule_key,
                       COALESCE(SUM(GREATEST(COALESCE(a.rule_hit_count, 0), 1)), 0)::bigint AS rule_hits
                FROM phase4.step3_v2_simulations s
                LEFT JOIN phase4.step3_v2_alerts a ON a.simulation_id = s.simulation_id
                WHERE COALESCE(s.model_version, '') = %(model_version)s
                  AND COALESCE(s.status, '') = 'completed'
                  AND (
                        COALESCE(a.payload->>'rule_checksum', a.payload->>'rulepack_checksum', a.payload->>'rule_version', a.payload->>'rulepack_version', a.payload->>'rule_id', '') <> ''
                     OR COALESCE(a.rule_hit_count, 0) > 0
                  )
                GROUP BY s.simulation_id, rule_key
                ORDER BY s.simulation_id, rule_key;
                """,
                {"model_version": model_version},
            )
            stability_rows = [(str(r[0]), str(r[1] or ""), _safe_int(r[2])) for r in (cur.fetchall() or [])]

    sim_metadata = sim_row[4] if isinstance(sim_row[4], dict) else {}
    isolation_type = str(sim_row[5] or "").strip().lower()
    packets_total = _safe_int(packet_row[0])
    attack_packets = _safe_int(packet_row[1])
    rule_hits_packets = _safe_int(packet_row[3])
    child_count = _safe_int(packet_row[4])
    pcap_count = _safe_int(packet_row[5])
    visible_paths = _safe_int(packet_row[6])
    attack_packet_flow_ids = _safe_int(packet_row[8])
    isolation_evidence_rows = _safe_int(packet_row[9])
    isolated_packet_rows = _safe_int(packet_row[10])
    alerts_total = _safe_int(alert_row[0])
    alert_rows = _safe_int(alert_row[1])
    rule_hits_alerts = _safe_int(alert_row[2])
    attack_alerts = _safe_int(alert_row[3])
    benign_alerts = _safe_int(alert_row[4])
    escalated_alerts = _safe_int(alert_row[5])
    enriched_alerts = _safe_int(alert_row[6])
    meta_alerts = _safe_int(alert_row[7])
    meta_alert_tagged_rows = _safe_int(alert_row[8])
    total_mismatches = _safe_int(alert_row[9])
    mismatches_detected = _safe_int(alert_row[10])
    temporal_alerts = _safe_int(alert_row[11])
    temporal_upgraded_alerts = _safe_int(alert_row[12])
    temporal_upgrade_evidence_rows = _safe_int(alert_row[13])
    confidence_sum = _safe_float(alert_row[14]) if alert_row[14] is not None else None
    confidence_count = _safe_int(alert_row[15])
    filled_context_fields = _safe_int(alert_row[16])
    rule_linked_alerts = _safe_int(alert_row[17])
    traceable_rule_alerts = _safe_int(alert_row[18])
    attack_alert_flow_ids = _safe_int(alert_row[20])
    cross_scope_detection_evidence_rows = _safe_int(alert_row[21])
    explicit_escalated_alerts = _safe_int(alert_row[22])
    escalation_evidence_rows = _safe_int(alert_row[23])
    recommendations_on_escalated_alerts = _safe_int(alert_row[24])
    false_positive_alerts = _safe_int(alert_row[25])
    reviewed_false_positive_alerts = _safe_int(alert_row[26])
    explanation_reviewed_alerts = _safe_int(alert_row[27])
    useful_explanation_alerts = _safe_int(alert_row[28])
    analyst_reviewed_alerts = _safe_int(alert_row[29])
    analyst_ready_alerts = _safe_int(alert_row[30])
    reviewed_rule_hits = _safe_int(alert_row[31])
    true_rule_hits = _safe_int(alert_row[32])
    reviewed_rule_scope_alerts = _safe_int(alert_row[33])
    correctly_scoped_rule_alerts = _safe_int(alert_row[34])
    reviewed_escalations = _safe_int(alert_row[35])
    useful_escalations = _safe_int(alert_row[36])
    useful_meta_alerts = _safe_int(alert_row[37])
    triage_seconds_sum_alerts = _safe_float(alert_row[38])
    triage_duration_count_alerts = _safe_int(alert_row[39])
    parent_actions = _safe_int(action_row[0])
    recommendations = _safe_int(action_row[1])
    containment_actions = _safe_int(action_row[2])
    response_correct = _safe_int(action_row[3])
    response_total = _safe_int(action_row[4])
    meta_action_rows = _safe_int(action_row[5])
    meta_action_tagged_rows = _safe_int(action_row[6])
    rule_linked_actions = _safe_int(action_row[7])
    traceable_rule_actions = _safe_int(action_row[8])
    containment_attempts = _safe_int(action_row[9])
    containment_successes = _safe_int(action_row[10])
    simulated_containment_successes = _safe_int(action_row[11])
    useful_meta_actions = _safe_int(action_row[12])
    triage_seconds_sum_actions = _safe_float(action_row[13])
    triage_duration_count_actions = _safe_int(action_row[14])
    distributed_events = _safe_int(correlation_row[0])
    correlated_events = _safe_int(correlation_row[1])
    total_patterns = _safe_int(recurrence_row[0])
    recurring_patterns = _safe_int(recurrence_row[1])
    total_paths = pcap_count * child_count

    model_traceability, model_trace_num, model_trace_den = _step3_v2_model_version_traceability(
        model_id=model_id,
        sim_id=sid,
    )

    stability_value = None
    stability_num = None
    stability_den = None
    stability_vectors: dict[str, dict[str, int]] = {}
    for sim_key, rule_key, hit_count in stability_rows:
        skey = str(sim_key or "").strip()
        rkey = str(rule_key or "").strip()
        if not skey or not rkey:
            continue
        stability_vectors.setdefault(skey, {})[rkey] = _safe_int(hit_count)
    current_vector = stability_vectors.get(sid) or {}
    if current_vector and len(stability_vectors) >= 1:
        stable = sum(1 for vector in stability_vectors.values() if vector == current_vector)
        stability_num = stable
        stability_den = len(stability_vectors)
        stability_value = _safe_ratio(stability_num, stability_den)

    profile = _step3_worker_profile()
    principles = load_metric_principles().get("step3") or {}

    def _metadata_list(*keys: str) -> list[str]:
        for key in keys:
            raw = sim_metadata.get(key) if isinstance(sim_metadata, dict) else None
            if isinstance(raw, list):
                vals = [str(v).strip() for v in raw if str(v).strip()]
                if vals:
                    return vals
        return []

    required_context_fields = _metadata_list(
        "required_alert_context_fields",
        "required_context_fields",
        "step3_required_context_fields",
    )
    supported_context_fields = {"recommendation", "phase", "severity", "payload"}
    required_context_field_set = {str(v).strip() for v in required_context_fields}
    can_derive_context_fields = bool(required_context_field_set) and required_context_field_set == supported_context_fields
    required_context_field_count = len(required_context_field_set)

    replay_detection_value = None
    replay_detection_num = None
    replay_detection_den = None
    if attack_packet_flow_ids > 0:
        replay_detection_num = attack_alert_flow_ids
        replay_detection_den = attack_packet_flow_ids
        replay_detection_value = _safe_ratio(replay_detection_num, replay_detection_den)

    replay_isolation_value = None
    replay_isolation_num = None
    replay_isolation_den = None
    if packets_total > 0 and isolation_evidence_rows >= packets_total:
        replay_isolation_num = isolated_packet_rows
        replay_isolation_den = packets_total
        replay_isolation_value = _safe_ratio(replay_isolation_num, replay_isolation_den)

    cross_scope_value = None
    cross_scope_num = None
    cross_scope_den = None
    if total_mismatches > 0 and cross_scope_detection_evidence_rows > 0:
        cross_scope_num = mismatches_detected
        cross_scope_den = total_mismatches
        cross_scope_value = _safe_ratio(cross_scope_num, cross_scope_den)

    total_rule_linked_records = rule_linked_alerts + rule_linked_actions
    traceable_rule_records = traceable_rule_alerts + traceable_rule_actions
    rule_traceability_value = _safe_ratio(traceable_rule_records, total_rule_linked_records)
    explanation_usefulness_value = _safe_ratio(useful_explanation_alerts, explanation_reviewed_alerts)
    analyst_readiness_value = _safe_ratio(analyst_ready_alerts, analyst_reviewed_alerts)
    rule_precision_value = _safe_ratio(true_rule_hits, reviewed_rule_hits)
    rule_scope_value = _safe_ratio(correctly_scoped_rule_alerts, reviewed_rule_scope_alerts)
    escalation_usefulness_value = _safe_ratio(useful_escalations, reviewed_escalations)

    child_escalation_value = None
    child_escalation_num = None
    child_escalation_den = None
    if alerts_total > 0 and escalation_evidence_rows > 0:
        child_escalation_num = explicit_escalated_alerts
        child_escalation_den = alerts_total
        child_escalation_value = _safe_ratio(child_escalation_num, child_escalation_den)

    enrichment_value = None
    enrichment_num = None
    enrichment_den = None
    context_density_value = None
    context_density_num = None
    context_density_den = None
    if alerts_total > 0 and can_derive_context_fields:
        enrichment_num = enriched_alerts
        enrichment_den = alerts_total
        enrichment_value = _safe_ratio(enrichment_num, enrichment_den)
        context_density_num = filled_context_fields
        context_density_den = alert_rows * required_context_field_count
        context_density_value = _safe_ratio(context_density_num, context_density_den)

    temporal_value = None
    temporal_num = None
    temporal_den = None
    if temporal_alerts > 0 and temporal_upgrade_evidence_rows > 0:
        temporal_num = temporal_upgraded_alerts
        temporal_den = temporal_alerts
        temporal_value = _safe_ratio(temporal_num, temporal_den)

    recommendation_value = None
    recommendation_num = None
    recommendation_den = None
    if explicit_escalated_alerts > 0 and escalation_evidence_rows > 0:
        recommendation_num = recommendations_on_escalated_alerts
        recommendation_den = explicit_escalated_alerts
        recommendation_value = _safe_ratio(recommendation_num, recommendation_den)

    replay_fp_value = None
    replay_fp_num = None
    replay_fp_den = None
    if reviewed_false_positive_alerts > 0:
        replay_fp_num = false_positive_alerts
        replay_fp_den = reviewed_false_positive_alerts
        replay_fp_value = _safe_ratio(replay_fp_num, replay_fp_den)

    meta_total = alerts_total + parent_actions
    meta_tagged_rows_total = meta_alert_tagged_rows + meta_action_tagged_rows
    meta_alert_value = None
    meta_alert_num = None
    meta_alert_den = None
    if meta_total > 0 and meta_tagged_rows_total > 0:
        meta_alert_num = meta_alerts + meta_action_rows
        meta_alert_den = meta_total
        meta_alert_value = _safe_ratio(meta_alert_num, meta_alert_den)
    oversight_precision_value = _safe_ratio(useful_meta_alerts + useful_meta_actions, meta_alert_num)

    triage_confidence_value = None
    triage_confidence_num = None
    triage_confidence_den = None
    if confidence_count > 0 and confidence_sum is not None:
        triage_confidence_num = confidence_sum
        triage_confidence_den = confidence_count
        triage_confidence_value = _safe_ratio(triage_confidence_num, triage_confidence_den)
    triage_time_direct_num = triage_seconds_sum_alerts + triage_seconds_sum_actions
    triage_time_direct_den = triage_duration_count_alerts + triage_duration_count_actions
    triage_time_direct_value = _safe_ratio(triage_time_direct_num, triage_time_direct_den)
    replay_containment_value = _safe_ratio(containment_successes, containment_attempts)
    simulated_containment_value = _safe_ratio(simulated_containment_successes, containment_attempts)

    def _triage_duration_from_evidence() -> tuple[float | None, float | None, float | None, dict[str, Any] | None]:
        e = evidence_rows.get("mean_triage_time_proxy")
        if not e:
            return None, None, None, None
        total_seconds = 0.0
        count = 0.0
        for erow in e.get("evidence_rows") or []:
            if not isinstance(erow, dict):
                continue
            payload = erow.get("evidence_payload") if isinstance(erow.get("evidence_payload"), dict) else {}
            if payload.get("triage_duration_seconds") is not None:
                total_seconds += _safe_float(payload.get("triage_duration_seconds"))
                count += 1.0
            elif payload.get("triage_duration_s") is not None:
                total_seconds += _safe_float(payload.get("triage_duration_s"))
                count += 1.0
            elif payload.get("triage_duration_ms") is not None:
                total_seconds += _safe_float(payload.get("triage_duration_ms")) / 1000.0
                count += 1.0
            elif erow.get("numerator") is not None and _safe_float(erow.get("denominator")) > 0:
                total_seconds += _safe_float(erow.get("numerator"))
                count += _safe_float(erow.get("denominator"))
        if count <= 0:
            return None, None, None, e
        return _safe_ratio(total_seconds, count), total_seconds, count, e

    def evidence_value(metric_name: str) -> tuple[float | None, float | None, float | None, dict[str, Any] | None]:
        e = evidence_rows.get(metric_name)
        if not e:
            return None, None, None, None
        return e.get("metric_value"), e.get("numerator"), e.get("denominator"), e

    def row(
        metric_name: str,
        value: float | None,
        numerator: float | int | None,
        denominator: float | int | None,
        source_ref: str,
        method: str,
        *,
        note: str = "",
        missing: list[str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        principle = principles.get(metric_name)
        status = "collected_as_principle"
        return _step3_metric_row(
            metric_name=metric_name,
            metric_value=value,
            numerator=numerator,
            denominator=denominator,
            source_ref=source_ref,
            calculation_method=method,
            principle_status=status,
            note=note,
            missing_requirements=missing if value is None else None,
            details_extra=extra,
        )

    def evidence_or_missing(metric_name: str, method: str, missing: list[str], note: str = "") -> dict[str, Any]:
        value, numerator, denominator, e = evidence_value(metric_name)
        if value is not None:
            return row(
                metric_name,
                value,
                numerator,
                denominator,
                "phase4.step3_v2_metric_evidence",
                method,
                note=note or "Derived from explicit Step 3 V2 metric evidence rows.",
                extra={"evidence_count": e.get("evidence_count"), "evidence_updated_at_utc": e.get("updated_at_utc")} if e else None,
            )
        return row(metric_name, None, None, None, "phase4.step3_v2_metric_evidence", method, note=note, missing=missing)

    confidence_value, confidence_num, confidence_den, confidence_evidence = evidence_value("triage_decision_confidence")
    if triage_confidence_value is not None:
        triage_confidence = triage_confidence_value
        triage_confidence_source = "phase4.step3_v2_alerts.payload.confidence"
        triage_confidence_extra = {"confidence_records": confidence_count}
    else:
        triage_confidence = confidence_value
        triage_confidence_num = confidence_num
        triage_confidence_den = confidence_den
        triage_confidence_source = "phase4.step3_v2_metric_evidence"
        triage_confidence_extra = {"evidence_count": confidence_evidence.get("evidence_count")} if confidence_evidence else None

    triage_time_value, triage_time_num, triage_time_den, triage_time_evidence = _triage_duration_from_evidence()
    triage_time_source = "phase4.step3_v2_metric_evidence"
    triage_time_extra = {"evidence_count": triage_time_evidence.get("evidence_count")} if triage_time_evidence else None
    if triage_time_direct_value is not None:
        triage_time_value = triage_time_direct_value
        triage_time_num = triage_time_direct_num
        triage_time_den = triage_time_direct_den
        triage_time_source = "phase4.step3_v2_alerts.payload.triage_duration_ms|phase4.step3_v2_parent_actions.payload.triage_duration_ms"
        triage_time_extra = {"triage_duration_records": triage_time_direct_den}

    def direct_or_evidence(
        metric_name: str,
        value: float | None,
        numerator: float | int | None,
        denominator: float | int | None,
        source_ref: str,
        method: str,
        missing: list[str],
        *,
        note: str = "",
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if value is not None:
            return row(
                metric_name,
                value,
                numerator,
                denominator,
                source_ref,
                method,
                note=note,
                extra=extra,
            )
        return evidence_or_missing(metric_name, method, missing, note=note)

    metric_rows = {
        "replay_detection_rate": direct_or_evidence("replay_detection_rate", replay_detection_value, replay_detection_num, replay_detection_den, "phase4.step3_v2_child_packets.payload.packet_or_flow_id|phase4.step3_v2_alerts.payload.packet_or_flow_id", "detected_attacks / replay_attacks", ["attack replay packet_or_flow_id denominator", "detected attack alert packet_or_flow_id numerator"], note="Uses distinct attack packet/flow IDs, not alert-row counts."),
        "replay_isolation_validation": direct_or_evidence("replay_isolation_validation", replay_isolation_value, replay_isolation_num, replay_isolation_den, "phase4.step3_v2_child_packets.payload.{isolation_valid,isolated,isolation_type}", "isolated_replay_records / replay_records", ["per-record isolation evidence for every replay record"], note="Simulation-level isolation_type alone is not used as measured evidence."),
        "cross_scope_detection_rate": direct_or_evidence("cross_scope_detection_rate", cross_scope_value, cross_scope_num, cross_scope_den, "phase4.step3_v2_alerts.payload.{expected_environment,observed_environment,cross_scope_detected,mismatch_detected}", "mismatches_detected / total_mismatches", ["expected/observed scope mismatch labels", "explicit cross_scope_detected or mismatch_detected labels"]),
        "explanation_usefulness": direct_or_evidence("explanation_usefulness", explanation_usefulness_value, useful_explanation_alerts if explanation_reviewed_alerts > 0 else None, explanation_reviewed_alerts if explanation_reviewed_alerts > 0 else None, "phase4.step3_v2_alerts.payload.explanation_useful", "rubric_score / max_rubric_score", ["rubric_score", "max_rubric_score"], note="Simulation producer labels explanation usefulness from generated alert explanation/recommendation evidence."),
        "analyst_readiness_score": direct_or_evidence("analyst_readiness_score", analyst_readiness_value, analyst_ready_alerts if analyst_reviewed_alerts > 0 else None, analyst_reviewed_alerts if analyst_reviewed_alerts > 0 else None, "phase4.step3_v2_alerts.payload.analyst_ready", "weighted_rubric_average", ["rubric dimension scores", "rubric dimension weights"], note="Simulation producer labels analyst readiness for generated reviewed alerts."),
        "rule_precision": direct_or_evidence("rule_precision", rule_precision_value, true_rule_hits if reviewed_rule_hits > 0 else None, reviewed_rule_hits if reviewed_rule_hits > 0 else None, "phase4.step3_v2_alerts.payload.rule_true_positive|phase4.step3_v2_alerts.packet_label", "true_rule_hits / total_rule_hits", ["true_rule_hits", "total_rule_hits"]),
        "rule_scope_accuracy": direct_or_evidence("rule_scope_accuracy", rule_scope_value, correctly_scoped_rule_alerts if reviewed_rule_scope_alerts > 0 else None, reviewed_rule_scope_alerts if reviewed_rule_scope_alerts > 0 else None, "phase4.step3_v2_alerts.payload.{rule_scope_correct,expected_scope,observed_scope}", "correctly_scoped_rules / total_rules", ["expected rule scope labels", "matched rule scope labels"]),
        "rule_replay_stability": direct_or_evidence("rule_replay_stability", stability_value, stability_num, stability_den, "phase4.step3_v2_simulations|phase4.step3_v2_alerts.payload.rule_lineage", "stable_rule_hits / total_replays", ["at least two completed Step 3 V2 simulations for this model_version with rule lineage hit vectors"], note="Stable only when the SIM_ID rule-lineage hit vector exactly matches comparable completed simulations."),
        "rule_version_traceability": direct_or_evidence("rule_version_traceability", rule_traceability_value, traceable_rule_records if total_rule_linked_records > 0 else None, total_rule_linked_records if total_rule_linked_records > 0 else None, "phase4.step3_v2_alerts.payload.{rule_version,rulepack_version,rule_checksum,rulepack_checksum}|phase4.step3_v2_parent_actions.payload", "traceable_rules / total_rules", ["rule-linked alerts/actions with rule version or checksum lineage"]),
        "model_version_traceability": row("model_version_traceability", model_traceability, model_trace_num if model_traceability is not None else None, model_trace_den if model_traceability is not None else None, "phase4.model_registry|phase4.workflow_runs|phase4.step3_v2_simulations", "traceable_models / total_models", missing=["model_id", "model registry row", "Step 2 model lineage"]),
        "escalation_usefulness": direct_or_evidence("escalation_usefulness", escalation_usefulness_value, useful_escalations if reviewed_escalations > 0 else None, reviewed_escalations if reviewed_escalations > 0 else None, "phase4.step3_v2_alerts.payload.escalation_labels|phase4.step3_v2_alerts.recommendation", "useful_escalations / total_escalations", ["useful_escalations", "total_escalations"]),
        "child_escalation_rate": direct_or_evidence("child_escalation_rate", child_escalation_value, child_escalation_num, child_escalation_den, "phase4.step3_v2_alerts.payload.{escalated,parent_escalated,escalation_triggered,escalation_id}", "escalated_alerts / total_alerts", ["explicit child alert escalation labels"]),
        "enrichment_completeness": direct_or_evidence("enrichment_completeness", enrichment_value, enrichment_num, enrichment_den, "phase4.step3_v2_simulations.metadata.required_alert_context_fields|phase4.step3_v2_alerts", "enriched_alerts / total_alerts", ["governed required_alert_context_fields metadata", "alert rows with all required context fields"], note=f"required_alert_context_fields={required_context_fields or 'missing'}"),
        "mean_triage_time_proxy": row("mean_triage_time_proxy", triage_time_value, triage_time_num, triage_time_den, triage_time_source, "sum(triage_duration_seconds) / triaged_records", note="Accepts triage_duration_seconds, triage_duration_s, triage_duration_ms, or numerator seconds with denominator count from evidence rows.", missing=["triage_duration_seconds or triage_duration_ms evidence"], extra=triage_time_extra),
        "cross_child_correlation_capture": row("cross_child_correlation_capture", _safe_ratio(correlated_events, distributed_events), correlated_events if distributed_events > 0 else None, distributed_events if distributed_events > 0 else None, "phase4.step3_v2_child_packets.payload.packet_or_flow_id|phase4.step3_v2_alerts.payload.packet_or_flow_id", "correlated_events / distributed_events", missing=["packet_or_flow_id values distributed across multiple children"]),
        "temporal_escalation_usefulness": direct_or_evidence("temporal_escalation_usefulness", temporal_value, temporal_num, temporal_den, "phase4.step3_v2_alerts.payload.{temporal_alert,temporal_upgraded,temporal_escalation_upgraded}", "upgraded_temporal_alerts / temporal_alerts", ["temporal alert labels", "explicit temporal upgrade labels"]),
        "recommendation_rate": direct_or_evidence("recommendation_rate", recommendation_value, recommendation_num, recommendation_den, "phase4.step3_v2_alerts.payload.escalation_labels|phase4.step3_v2_alerts.recommendation", "recommendations / escalated_alerts", ["explicit escalated-alert labels", "recommendations linked on escalated alert rows"]),
        "replay_false_positive_rate": direct_or_evidence("replay_false_positive_rate", replay_fp_value, replay_fp_num, replay_fp_den, "phase4.step3_v2_alerts.payload.{false_positive,is_false_positive,alert_verdict,verdict}", "replay_fp / replay_total", ["explicit replay false-positive review labels"]),
        "replay_propagation_coverage": row("replay_propagation_coverage", _safe_ratio(visible_paths, total_paths), visible_paths if total_paths > 0 else None, total_paths if total_paths > 0 else None, "phase4.step3_v2_child_packets.{pcap_file,child_id}", "visible_replay_paths / total_paths", note="Total path policy: distinct PCAP files multiplied by distinct child nodes for the SIM_ID.", missing=["pcap files", "child packet paths"]),
        "replay_containment_success": direct_or_evidence("replay_containment_success", replay_containment_value, containment_successes if containment_attempts > 0 else None, containment_attempts if containment_attempts > 0 else None, "phase4.step3_v2_parent_actions.payload.{containment_attempt,containment_success}", "contained_attacks / replay_attacks", ["contained_attacks", "replay_attacks"]),
        "triage_decision_confidence": row("triage_decision_confidence", triage_confidence, triage_confidence_num, triage_confidence_den, triage_confidence_source, "avg_confidence", missing=["alert confidence values or triage confidence evidence"], extra=triage_confidence_extra),
        "alert_context_density": direct_or_evidence("alert_context_density", context_density_value, context_density_num, context_density_den, "phase4.step3_v2_simulations.metadata.required_alert_context_fields|phase4.step3_v2_alerts", "metadata_fields / max_fields", ["governed required_alert_context_fields metadata", "alert rows"], note=f"required_alert_context_fields={required_context_fields or 'missing'}"),
        "meta_alert_rate": direct_or_evidence("meta_alert_rate", meta_alert_value, meta_alert_num, meta_alert_den, "phase4.step3_v2_alerts.payload.meta_alert|phase4.step3_v2_parent_actions.payload.meta_alert", "meta_alerts / total_alerts", ["explicit meta_alert tags on alerts or actions"]),
        "oversight_precision_proxy": direct_or_evidence("oversight_precision_proxy", oversight_precision_value, (useful_meta_alerts + useful_meta_actions) if meta_alert_num else None, meta_alert_num if meta_alert_num else None, "phase4.step3_v2_alerts.payload.meta_alert_useful|phase4.step3_v2_parent_actions.payload.meta_alert_useful", "useful_meta_alerts / meta_alerts", ["useful_meta_alerts", "meta_alerts"]),
        "explanation_pattern_recurrence_score": row("explanation_pattern_recurrence_score", _safe_ratio(recurring_patterns, total_patterns), recurring_patterns if total_patterns > 0 else None, total_patterns if total_patterns > 0 else None, "phase4.step3_v2_alerts.payload.explanation_pattern|phase4.step3_v2_alerts.recommendation", "recurring_patterns / total_patterns", missing=["explanation pattern keys"]),
        "response_correctness_proxy": (
            row("response_correctness_proxy", _safe_ratio(response_correct, response_total), response_correct, response_total, "phase4.step3_v2_parent_actions.payload.response_correct", "correct_responses / total_responses")
            if response_total > 0
            else evidence_or_missing("response_correctness_proxy", "correct_responses / total_responses", ["response correctness labels"])
        ),
        "simulated_containment_success": direct_or_evidence("simulated_containment_success", simulated_containment_value, simulated_containment_successes if containment_attempts > 0 else None, containment_attempts if containment_attempts > 0 else None, "phase4.step3_v2_parent_actions.payload.{simulated_containment_attempt,simulated_containment_success}", "successful_containments / attempts", ["successful_containments", "containment attempts"]),
    }

    collectors = [(metric_name, lambda row_payload=row_payload: row_payload) for metric_name, row_payload in metric_rows.items()]
    collected_rows, collector_errors, calc_threads = _threaded_collect(collectors, profile=profile)
    rows = {
        str(r.get("metric_name") or ""): r for r in collected_rows if str(r.get("metric_name") or "").strip()
    }
    ingest = _ingest_metrics_threaded(
        step="step3",
        step_unique_id=sid,
        metric_rows=rows,
        lineage={
            "sim_id": sid,
            "step3_v2_sim_id": sid,
            "model_id": model_id,
            "model_version": model_version,
            "step3_metrics_source": "step3_v2",
            "simulation_status": str(sim_row[3] or ""),
            "simulation_isolation_type": isolation_type,
        },
        profile=profile,
    )

    required = _step_required_metrics("step3")
    missing = [m for m in required if str((rows.get(m) or {}).get("calculation_status") or "") != "measured"]
    warning = bool(missing or collector_errors or list(ingest.get("ingest_errors") or []))
    return {
        "ok": True,
        "status": "completed_with_warning" if warning else "completed",
        "warning": warning,
        "step": "step3",
        "sim_id": sid,
        "step_unique_id": sid,
        "model_id": model_id,
        "model_version": model_version,
        "worker_profile": profile,
        "calculation_worker_threads": calc_threads,
        "required_metric_count": len(required),
        "produced_metric_count": len(rows),
        "ingested_metric_count": int(ingest.get("ingested_rows") or 0),
        "missing_metrics": missing,
        "missing_requirements": _missing_requirements("step3", missing),
        "errors": collector_errors + list(ingest.get("ingest_errors") or []),
        "source": "step3_v2",
    }


def generate_step3_metrics(
    *,
    sim_id: str | None = None,
    replay_run_id: str | None = None,
) -> dict[str, Any]:
    sid = str(sim_id or "").strip()
    rid = str(replay_run_id or "").strip()
    if not sid and not rid:
        return {"ok": False, "error": "sim_id_or_replay_run_id_required"}
    with connect() as conn:
        with conn.cursor() as cur:
            row = None
            if sid and _is_uuid_like(sid):
                cur.execute(
                    """
                    SELECT replay_run_id::text, model_id::text, model_version, replay_id::text, preparation_replay_id::text, simulation_session_id::text, metrics
                    FROM phase4.step3_replay_metrics
                    WHERE replay_id = %(sid)s::uuid
                       OR preparation_replay_id = %(sid)s::uuid
                       OR simulation_session_id = %(sid)s::uuid
                    ORDER BY COALESCE(updated_at_utc, created_at_utc) DESC
                    LIMIT 1;
                    """,
                    {"sid": sid},
                )
                row = cur.fetchone()
            if row is None and sid:
                cur.execute(
                    """
                    SELECT replay_run_id::text, model_id::text, model_version, replay_id::text, preparation_replay_id::text, simulation_session_id::text, metrics
                    FROM phase4.step3_replay_metrics
                    WHERE replay_id::text = %(sid)s
                       OR preparation_replay_id::text = %(sid)s
                       OR simulation_session_id::text = %(sid)s
                    ORDER BY COALESCE(updated_at_utc, created_at_utc) DESC
                    LIMIT 1;
                    """,
                    {"sid": sid},
                )
                row = cur.fetchone()
    if not row:
        if sid and _is_uuid_like(sid):
            v2_result = _generate_step3_v2_metrics(sim_id=sid)
            if v2_result.get("ok"):
                return v2_result
        if rid and _is_uuid_like(rid):
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT replay_run_id::text, model_id::text, model_version, replay_id::text, preparation_replay_id::text, simulation_session_id::text, metrics
                        FROM phase4.step3_replay_metrics
                        WHERE replay_run_id = %(rid)s::uuid
                        LIMIT 1;
                        """,
                        {"rid": rid},
                    )
                    row = cur.fetchone()
        if row is None:
            return {
                "ok": False,
                "error": "step3_replay_metrics_not_found",
                "sim_id": sid,
                "replay_run_id": rid,
            }

    resolved_replay_run_id = str(row[0] or "").strip()
    resolved_sim_id = str(row[3] or row[4] or row[5] or "").strip()
    if not resolved_sim_id:
        return {
            "ok": False,
            "error": "step3_sim_id_missing_for_metrics",
            "replay_run_id": resolved_replay_run_id,
            "sim_id": sid,
        }

    step_unique_id = resolved_sim_id
    snapshot = _step3_snapshot(replay_run_id=resolved_replay_run_id)
    payload = snapshot.get("metrics_payload") if isinstance(snapshot.get("metrics_payload"), dict) else {}
    profile = _step3_worker_profile()
    principles = load_metric_principles().get("step3") or {}

    attack_den = _safe_int(snapshot.get("attack_packets_total"))
    if attack_den <= 0:
        attack_den = _safe_int(snapshot.get("attack_alerts"))
    detected_attacks = _safe_int(snapshot.get("feedback_true_positive"))
    if detected_attacks <= 0:
        detected_attacks = _safe_int(snapshot.get("attack_alerts"))
    replay_detection_rate = _safe_ratio(detected_attacks, attack_den)

    isolation_num = _safe_int(snapshot.get("isolated_paths"))
    isolation_den = _safe_int(snapshot.get("replay_stream_paths_total"))
    replay_isolation_validation = _safe_ratio(isolation_num, isolation_den)

    mismatch_den = _safe_int(snapshot.get("cross_scope_alerts"))
    mismatch_num = _safe_int(snapshot.get("escalated_alerts"))
    cross_scope_detection_rate = _safe_ratio(mismatch_num, mismatch_den)

    usefulness_avg = snapshot.get("feedback_usefulness_avg")
    explanation_usefulness = _safe_ratio(usefulness_avg, 5.0) if usefulness_avg is not None else None
    analyst_readiness_score = explanation_usefulness

    rule_precision_num = _safe_int(snapshot.get("feedback_true_positive"))
    rule_precision_den = _safe_int(snapshot.get("rule_hits_for_precision"))
    rule_precision = _safe_ratio(rule_precision_num, rule_precision_den)

    scope_num = _safe_int(snapshot.get("scope_correct_rules"))
    scope_den = _safe_int(snapshot.get("traceable_rules_total"))
    rule_scope_accuracy = _safe_ratio(scope_num, scope_den)

    stability_ratio, stability_num, stability_den = _step3_stability_ratio(
        model_version=str(snapshot.get("model_version") or "")
    )

    traceable_num = _safe_int(snapshot.get("traceable_rules"))
    traceable_den = _safe_int(snapshot.get("traceable_rules_total"))
    rule_version_traceability = _safe_ratio(traceable_num, traceable_den)
    model_traceability, model_traceability_num, model_traceability_den = _step3_model_version_traceability(
        model_id=str(snapshot.get("model_id") or ""),
        replay_run_id=resolved_replay_run_id,
        simulation_id=resolved_sim_id,
    )

    escalation_useful_num = _safe_int(snapshot.get("feedback_true_positive"))
    escalation_useful_den = _safe_int(snapshot.get("escalated_alerts"))
    escalation_usefulness = _safe_ratio(escalation_useful_num, escalation_useful_den)

    child_escalation_num = _safe_int(snapshot.get("escalated_alerts"))
    child_escalation_den = _safe_int(snapshot.get("alerts_total"))
    child_escalation_rate = _safe_ratio(child_escalation_num, child_escalation_den)

    enrich_num = _safe_int(snapshot.get("enriched_alerts"))
    enrich_den = _safe_int(snapshot.get("alerts_total"))
    enrichment_completeness = _safe_ratio(enrich_num, enrich_den)

    triage_ms = snapshot.get("feedback_triage_ms_avg")
    mean_triage_time_proxy = (float(triage_ms) / 1000.0) if triage_ms is not None else None

    corr_num = _safe_int(snapshot.get("correlated_events"))
    corr_den = _safe_int(snapshot.get("distributed_events"))
    cross_child_correlation_capture = _safe_ratio(corr_num, corr_den)

    temporal_num = _safe_int(snapshot.get("temporal_upgraded_alerts"))
    temporal_den = _safe_int(snapshot.get("temporal_alerts"))
    temporal_escalation_usefulness = _safe_ratio(temporal_num, temporal_den)

    recommendation_num = _safe_int(snapshot.get("recommendation_total"))
    recommendation_den = _safe_int(snapshot.get("escalated_alerts"))
    recommendation_rate = _safe_ratio(recommendation_num, recommendation_den)

    replay_fp_num = _safe_int(snapshot.get("feedback_false_positive"))
    replay_fp_den = _safe_int(snapshot.get("alerts_total"))
    replay_false_positive_rate = _safe_ratio(replay_fp_num, replay_fp_den)

    propagation_num = _safe_int(snapshot.get("visible_paths"))
    propagation_den = _safe_int(snapshot.get("replay_stream_paths_total"))
    replay_propagation_coverage = _safe_ratio(propagation_num, propagation_den)

    containment_num = _safe_int(snapshot.get("containment_success_actions"))
    containment_den = _safe_int(snapshot.get("attack_packets_total")) or _safe_int(snapshot.get("attack_alerts"))
    replay_containment_success = _safe_ratio(containment_num, containment_den)

    triage_decision_confidence = (
        float(snapshot["prediction_confidence_avg"]) if snapshot.get("prediction_confidence_avg") is not None else None
    )

    context_num = _safe_int(snapshot.get("filled_context_fields"))
    context_den = _safe_int(snapshot.get("alert_rows_for_density")) * 4
    alert_context_density = _safe_ratio(context_num, context_den)

    meta_num = _safe_int(snapshot.get("meta_alerts"))
    meta_den = _safe_int(snapshot.get("alerts_total"))
    meta_alert_rate = _safe_ratio(meta_num, meta_den)

    oversight_num = _safe_int(snapshot.get("feedback_useful_meta_alerts"))
    oversight_den = _safe_int(snapshot.get("meta_alerts"))
    oversight_precision_proxy = _safe_ratio(oversight_num, oversight_den)

    recurrence_num = _safe_int(snapshot.get("rule_patterns_recurring"))
    recurrence_den = _safe_int(snapshot.get("rule_patterns_total"))
    explanation_pattern_recurrence_score = _safe_ratio(recurrence_num, recurrence_den)

    response_num = _safe_int(snapshot.get("feedback_correct_responses"))
    response_den = _safe_int(snapshot.get("feedback_total_responses"))
    response_correctness_proxy = _safe_ratio(response_num, response_den)

    sim_containment_num = _safe_int(snapshot.get("feedback_containment_success"))
    sim_containment_den = _safe_int(snapshot.get("feedback_containment_attempts"))
    simulated_containment_success = _safe_ratio(sim_containment_num, sim_containment_den)

    metric_rows: dict[str, dict[str, Any]] = {
        "replay_detection_rate": _step3_metric_row(
            metric_name="replay_detection_rate",
            metric_value=replay_detection_rate,
            numerator=detected_attacks,
            denominator=attack_den,
            source_ref="phase4.step3_replay_file_stats|phase4.step3_alerts|phase4.step3_analyst_feedback",
            calculation_method="detected_attacks / replay_attacks",
            principle_status="incorrect_principle",
            note="Detection numerator uses true_positive feedback fallback to attack-labeled alerts.",
        ),
        "replay_isolation_validation": _step3_metric_row(
            metric_name="replay_isolation_validation",
            metric_value=replay_isolation_validation,
            numerator=isolation_num,
            denominator=isolation_den,
            source_ref="phase4.replay_streams.metadata.management_path_separate",
            calculation_method="isolated_replay_records / replay_records",
            principle_status="incorrect_principle",
            note="Proxy from stream-level management-path isolation flags.",
        ),
        "cross_scope_detection_rate": _step3_metric_row(
            metric_name="cross_scope_detection_rate",
            metric_value=cross_scope_detection_rate,
            numerator=mismatch_num,
            denominator=mismatch_den,
            source_ref="phase4.step3_alerts.cross_scope_flag|phase4.step3_alerts.parent_action_id",
            calculation_method="mismatches_detected / total_mismatches",
            principle_status="incorrect_principle",
            note="Proxy uses cross-scope alerts escalated to parent.",
        ),
        "explanation_usefulness": _step3_metric_row(
            metric_name="explanation_usefulness",
            metric_value=explanation_usefulness,
            numerator=usefulness_avg,
            denominator=5.0 if usefulness_avg is not None else None,
            source_ref="phase4.step3_analyst_feedback.usefulness_score",
            calculation_method="rubric_score / max_rubric_score",
            principle_status="incorrect_principle",
            note="Computed as normalized mean usefulness score.",
        ),
        "analyst_readiness_score": _step3_metric_row(
            metric_name="analyst_readiness_score",
            metric_value=analyst_readiness_score,
            numerator=usefulness_avg,
            denominator=5.0 if usefulness_avg is not None else None,
            source_ref="phase4.step3_analyst_feedback.usefulness_score",
            calculation_method="weighted_rubric_average",
            principle_status="incorrect_principle",
            note="Weighted rubric dimensions are unavailable; fallback to normalized usefulness average.",
        ),
        "rule_precision": _step3_metric_row(
            metric_name="rule_precision",
            metric_value=rule_precision,
            numerator=rule_precision_num,
            denominator=rule_precision_den,
            source_ref="phase4.step3_child_rule_matches|phase4.step3_analyst_feedback",
            calculation_method="true_rule_hits / total_rule_hits",
            principle_status="incorrect_principle",
            note="Proxy links true_positive feedback to rule-hit counts.",
        ),
        "rule_scope_accuracy": _step3_metric_row(
            metric_name="rule_scope_accuracy",
            metric_value=rule_scope_accuracy,
            numerator=scope_num,
            denominator=scope_den,
            source_ref="phase4.step3_alerts.{expected_environment,observed_environment}",
            calculation_method="correctly_scoped_rules / total_rules",
            principle_status="incorrect_principle",
            note="Proxy derived from expected vs observed environment equality.",
        ),
        "rule_replay_stability": _step3_metric_row(
            metric_name="rule_replay_stability",
            metric_value=stability_ratio,
            numerator=stability_num if stability_ratio is not None else None,
            denominator=stability_den if stability_ratio is not None else None,
            source_ref="phase4.replay_runs|phase4.replay_streams",
            calculation_method="stable_rule_hits / total_replays",
            principle_status="incorrect_principle",
            note="Stable replay defined as alert-hit counts within 10% of median for model_version.",
        ),
        "rule_version_traceability": _step3_metric_row(
            metric_name="rule_version_traceability",
            metric_value=rule_version_traceability,
            numerator=traceable_num,
            denominator=traceable_den,
            source_ref="phase4.step3_alerts.rulepack_version|phase4.parent_actions.rulepack_version",
            calculation_method="traceable_rules / total_rules",
            principle_status="incorrect_principle",
            note="Traceability proxy uses non-empty rulepack lineage across alert-action linkage.",
        ),
        "model_version_traceability": _step3_metric_row(
            metric_name="model_version_traceability",
            metric_value=model_traceability,
            numerator=model_traceability_num if model_traceability is not None else None,
            denominator=model_traceability_den if model_traceability is not None else None,
            source_ref="phase4.model_registry|phase4.workflow_runs|phase4.replay_runs|phase4.step3_replay_metrics",
            calculation_method="traceable_models / total_models",
            principle_status="collected_as_principle",
            note="Model traceability checks model registry, Step2 lineage, replay linkage, and Step3 metrics linkage.",
        ),
        "escalation_usefulness": _step3_metric_row(
            metric_name="escalation_usefulness",
            metric_value=escalation_usefulness,
            numerator=escalation_useful_num,
            denominator=escalation_useful_den,
            source_ref="phase4.step3_analyst_feedback.alert_verdict|phase4.step3_alerts",
            calculation_method="useful_escalations / total_escalations",
            principle_status="incorrect_principle",
            note="Useful escalations proxied by true_positive analyst verdicts.",
        ),
        "child_escalation_rate": _step3_metric_row(
            metric_name="child_escalation_rate",
            metric_value=child_escalation_rate,
            numerator=child_escalation_num,
            denominator=child_escalation_den,
            source_ref="phase4.step3_alerts.parent_action_id|phase4.step3_alerts",
            calculation_method="escalated_alerts / total_alerts",
            principle_status="collected_as_principle",
        ),
        "enrichment_completeness": _step3_metric_row(
            metric_name="enrichment_completeness",
            metric_value=enrichment_completeness,
            numerator=enrich_num,
            denominator=enrich_den,
            source_ref="phase4.step3_alerts.{expected_environment,observed_environment,escalation_reason,payload}",
            calculation_method="enriched_alerts / total_alerts",
            principle_status="collected_as_principle",
        ),
        "mean_triage_time_proxy": _step3_metric_row(
            metric_name="mean_triage_time_proxy",
            metric_value=mean_triage_time_proxy,
            numerator=triage_ms,
            denominator=1000.0 if triage_ms is not None else None,
            source_ref="phase4.step3_analyst_feedback.triage_duration_ms",
            calculation_method="avg(triage_duration_ms) / 1000",
            principle_status="collected_as_principle",
        ),
        "cross_child_correlation_capture": _step3_metric_row(
            metric_name="cross_child_correlation_capture",
            metric_value=cross_child_correlation_capture,
            numerator=corr_num,
            denominator=corr_den,
            source_ref="phase4.step3_child_rule_matches.payload.packet_or_flow_id|phase4.step3_alerts.payload.packet_or_flow_id",
            calculation_method="correlated_events / distributed_events",
            principle_status="incorrect_principle",
            note="Proxy tracks cross-child packet/flow IDs observed in alerts.",
        ),
        "temporal_escalation_usefulness": _step3_metric_row(
            metric_name="temporal_escalation_usefulness",
            metric_value=temporal_escalation_usefulness,
            numerator=temporal_num,
            denominator=temporal_den,
            source_ref="phase4.step3_alerts.escalation_reason|phase4.step3_alerts.parent_action_id",
            calculation_method="upgraded_temporal_alerts / temporal_alerts",
            principle_status="incorrect_principle",
            note="Temporal signal approximated via mismatch-tagged escalations.",
        ),
        "recommendation_rate": _step3_metric_row(
            metric_name="recommendation_rate",
            metric_value=recommendation_rate,
            numerator=recommendation_num,
            denominator=recommendation_den,
            source_ref="phase4.parent_actions.action_type|phase4.step3_alerts.parent_action_id",
            calculation_method="recommendations / escalated_alerts",
            principle_status="collected_as_principle",
        ),
        "replay_false_positive_rate": _step3_metric_row(
            metric_name="replay_false_positive_rate",
            metric_value=replay_false_positive_rate,
            numerator=replay_fp_num,
            denominator=replay_fp_den,
            source_ref="phase4.step3_analyst_feedback.alert_verdict|phase4.step3_alerts",
            calculation_method="replay_fp / replay_total",
            principle_status="collected_as_principle",
        ),
        "replay_propagation_coverage": _step3_metric_row(
            metric_name="replay_propagation_coverage",
            metric_value=replay_propagation_coverage,
            numerator=propagation_num,
            denominator=propagation_den,
            source_ref="phase4.step3_replay_flow_events.replay_stream_id|phase4.replay_streams",
            calculation_method="visible_replay_paths / total_paths",
            principle_status="incorrect_principle",
            note="Path visibility proxy uses replay flow-event stream coverage.",
        ),
        "replay_containment_success": _step3_metric_row(
            metric_name="replay_containment_success",
            metric_value=replay_containment_success,
            numerator=containment_num,
            denominator=containment_den,
            source_ref="phase4.parent_actions.recommendation|phase4.step3_replay_file_stats.packets_attack_in_file",
            calculation_method="contained_attacks / replay_attacks",
            principle_status="incorrect_principle",
            note="Containment inferred from isolate recommendations and terminal action status.",
        ),
        "triage_decision_confidence": _step3_metric_row(
            metric_name="triage_decision_confidence",
            metric_value=triage_decision_confidence,
            numerator=triage_decision_confidence,
            denominator=1.0 if triage_decision_confidence is not None else None,
            source_ref="phase4.step3_alerts.payload.prediction.confidence",
            calculation_method="avg_confidence",
            principle_status="collected_as_principle",
        ),
        "alert_context_density": _step3_metric_row(
            metric_name="alert_context_density",
            metric_value=alert_context_density,
            numerator=context_num,
            denominator=context_den,
            source_ref="phase4.step3_alerts.{expected_environment,observed_environment,escalation_reason,shap_evidence_status}",
            calculation_method="metadata_fields / max_fields",
            principle_status="incorrect_principle",
            note="Computed over four required alert-context fields.",
        ),
        "meta_alert_rate": _step3_metric_row(
            metric_name="meta_alert_rate",
            metric_value=meta_alert_rate,
            numerator=meta_num,
            denominator=meta_den,
            source_ref="phase4.step3_alerts.payload.meta_alert",
            calculation_method="meta_alerts / total_alerts",
            principle_status="incorrect_principle",
            note="Requires explicit meta-alert tagging in payload.",
        ),
        "oversight_precision_proxy": _step3_metric_row(
            metric_name="oversight_precision_proxy",
            metric_value=oversight_precision_proxy,
            numerator=oversight_num,
            denominator=oversight_den,
            source_ref="phase4.step3_analyst_feedback.feedback_payload.meta_alert_useful",
            calculation_method="useful_meta_alerts / meta_alerts",
            principle_status="incorrect_principle",
        ),
        "explanation_pattern_recurrence_score": _step3_metric_row(
            metric_name="explanation_pattern_recurrence_score",
            metric_value=explanation_pattern_recurrence_score,
            numerator=recurrence_num,
            denominator=recurrence_den,
            source_ref="phase4.step3_child_rule_matches.{rule_id,payload.rule_scope,payload.context.cross_scope_flag}",
            calculation_method="recurring_patterns / total_patterns",
            principle_status="incorrect_principle",
        ),
        "response_correctness_proxy": _step3_metric_row(
            metric_name="response_correctness_proxy",
            metric_value=response_correctness_proxy,
            numerator=response_num,
            denominator=response_den,
            source_ref="phase4.step3_analyst_feedback.feedback_payload.response_correct",
            calculation_method="correct_responses / total_responses",
            principle_status="incorrect_principle",
            note="Metric available only when response_correct is provided in analyst feedback payload.",
        ),
        "simulated_containment_success": _step3_metric_row(
            metric_name="simulated_containment_success",
            metric_value=simulated_containment_success,
            numerator=sim_containment_num,
            denominator=sim_containment_den,
            source_ref="phase4.step3_analyst_feedback.feedback_payload.{containment_attempt,containment_success}",
            calculation_method="successful_containments / attempts",
            principle_status="incorrect_principle",
            note="Metric available only when containment feedback keys are populated.",
        ),
    }

    # Preserve direct numeric metrics already emitted by replay runtime payload.
    for metric_name, metric_value in payload.items():
        m = str(metric_name or "").strip()
        if not m or m in metric_rows:
            continue
        if not isinstance(metric_value, (int, float)):
            continue
        principle = principles.get(m)
        metric_rows[m] = _step3_metric_row(
            metric_name=m,
            metric_value=float(metric_value),
            numerator=None,
            denominator=None,
            source_ref="phase4.step3_replay_metrics.metrics",
            calculation_method=(principle.calculation_method if principle else "runtime_metric_value"),
            principle_status=(principle.principle_status if principle else "incorrect_principle"),
        )

    collectors: list[tuple[str, Any]] = []
    for metric_name, row_payload in metric_rows.items():
        collectors.append((metric_name, lambda row=row_payload: row))
    collected_rows, collector_errors, calc_threads = _threaded_collect(collectors, profile=profile)
    rows: dict[str, dict[str, Any]] = {
        str(r.get("metric_name") or ""): r for r in collected_rows if str(r.get("metric_name") or "").strip()
    }

    ingest = _ingest_metrics_threaded(
        step="step3",
        step_unique_id=step_unique_id,
        metric_rows=rows,
        lineage={
            "replay_run_id": str(row[0] or ""),
            "model_id": str(row[1] or ""),
            "model_version": str(row[2] or ""),
            "replay_id": str(row[3] or ""),
            "preparation_replay_id": str(row[4] or ""),
            "simulation_session_id": str(row[5] or ""),
            "sim_id": resolved_sim_id,
        },
        profile=profile,
    )

    required = _step_required_metrics("step3")
    missing = [m for m in required if str((rows.get(m) or {}).get("calculation_status") or "") != "measured"]
    warning = bool(missing or collector_errors or list(ingest.get("ingest_errors") or []))
    return {
        "ok": True,
        "status": "completed_with_warning" if warning else "completed",
        "warning": warning,
        "step": "step3",
        "replay_run_id": resolved_replay_run_id,
        "sim_id": resolved_sim_id,
        "step_unique_id": step_unique_id,
        "worker_profile": profile,
        "calculation_worker_threads": calc_threads,
        "required_metric_count": len(required),
        "produced_metric_count": len(rows),
        "ingested_metric_count": int(ingest.get("ingested_rows") or 0),
        "missing_metrics": missing,
        "missing_requirements": _missing_requirements("step3", missing),
        "errors": collector_errors + list(ingest.get("ingest_errors") or []),
    }


def generate_step4_metrics(
    *,
    model_version: str | None = None,
    step1_run_id: str | None = None,
    step2_model_id: str | None = None,
    step2_run_id: str | None = None,
    step3_v2_sim_id: str | None = None,
) -> dict[str, Any]:
    from services_parent.common.dissertation_completion import refresh_dissertation_exports

    cleanup_counts = purge_deprecated_metrics(step="step1")
    payload = refresh_dissertation_exports(
        model_version,
        step1_run_id=step1_run_id,
        step2_model_id=step2_model_id,
        step2_run_id=step2_run_id,
        step3_v2_sim_id=step3_v2_sim_id,
    )
    if not payload.get("ok"):
        payload = dict(payload)
        payload["deprecated_metric_cleanup"] = cleanup_counts
        return payload
    status = payload.get("metrics_required_coverage") if isinstance(payload.get("metrics_required_coverage"), dict) else {}
    not_collected = int(status.get("not_collected_count") or 0)
    missing_requirements: list[str] = []
    if not_collected > 0:
        rows = payload.get("metrics_required_matrix_rows") if isinstance(payload.get("metrics_required_matrix_rows"), list) else []
        for row in rows:
            if not isinstance(row, dict):
                continue
            if str(row.get("status") or "") == "not_collected":
                missing_requirements.append(str(row.get("metric_name") or ""))
    payload = dict(payload)
    payload["step"] = "step4"
    payload["step4_metrics_generation_id"] = str(uuid.uuid4())
    payload["missing_metrics"] = sorted(set(missing_requirements))
    payload["missing_requirements"] = _missing_requirements("step4", payload["missing_metrics"])
    payload["worker_profile"] = _metric_worker_profile()
    payload["warning"] = bool(payload["missing_metrics"])
    payload["status"] = "completed_with_warning" if payload["warning"] else "completed"
    payload["deprecated_metric_cleanup"] = cleanup_counts
    return payload
