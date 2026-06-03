from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from services_parent.common.phase4_db import connect

STEP1_CANONICAL_SCHEMA_VERSION = "canonical_event_v1"
STEP1_CANONICAL_REQUIRED_FIELDS_V1 = [
    "event_id",
    "timestamp_utc",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_domain",
    "source_zone",
    "vector_class",
    "attack_category",
    "expected_environment",
    "observed_environment",
    "scope_match",
    "cross_scope_flag",
    "escalation_reason",
    "categorization_confidence",
    "adapter_version",
    "source_file",
    "source_path",
    "checksum",
    "label_harmonized",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_workflow_run(
    *,
    workflow_id: str,
    step_name: str,
    requested_by: str,
    worker_mode: str,
    requested_workers: int,
    effective_workers: int,
) -> str:
    run_id = str(uuid.uuid4())
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.workflow_runs (
                    run_id, workflow_id, step_name, status, requested_by, worker_mode,
                    requested_workers, effective_workers, started_at_utc, run_metrics
                )
                VALUES (
                    %(run_id)s::uuid, %(workflow_id)s, %(step_name)s, 'queued', %(requested_by)s,
                    %(worker_mode)s, %(requested_workers)s, %(effective_workers)s, now(),
                    jsonb_build_object('run_label', to_char(now() AT TIME ZONE 'UTC', 'YYMMDD-HH24MISS'))
                );
                """,
                {
                    "run_id": run_id,
                    "workflow_id": workflow_id,
                    "step_name": step_name,
                    "requested_by": requested_by,
                    "worker_mode": worker_mode,
                    "requested_workers": requested_workers,
                    "effective_workers": effective_workers,
                },
            )
        conn.commit()
    return run_id


def update_workflow_run(
    run_id: str,
    *,
    status: str,
    run_metrics: dict[str, Any] | None = None,
    error_message: str | None = None,
    completed: bool = False,
) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE phase4.workflow_runs
                SET status = %(status)s,
                    run_metrics = COALESCE(run_metrics, '{}'::jsonb) || %(run_metrics)s::jsonb,
                    error_message = %(error_message)s,
                    completed_at_utc = CASE WHEN %(completed)s THEN now() ELSE completed_at_utc END
                WHERE run_id = %(run_id)s::uuid;
                """,
                {
                    "run_id": run_id,
                    "status": status,
                    "run_metrics": json.dumps(run_metrics or {}),
                    "error_message": error_message,
                    "completed": completed,
                },
            )
        conn.commit()


def get_workflow_run(run_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT run_id::text, workflow_id, step_name, status, requested_by, worker_mode,
                       requested_workers, effective_workers, started_at_utc, completed_at_utc,
                       run_metrics, error_message
                FROM phase4.workflow_runs
                WHERE run_id = %(run_id)s::uuid;
                """,
                {"run_id": run_id},
            )
            row = cur.fetchone()
            if not row:
                return None
            cols = [d.name for d in cur.description]
            out = dict(zip(cols, row))
    for k in ("started_at_utc", "completed_at_utc"):
        if out.get(k) is not None:
            out[k] = out[k].isoformat()
    return out


def list_recent_workflow_runs(*, step_name: str | None = None, limit: int = 25) -> list[dict[str, Any]]:
    where = "WHERE step_name = %(step_name)s" if step_name else ""
    params: dict[str, Any] = {"limit": limit}
    if step_name:
        params["step_name"] = step_name
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT run_id::text, workflow_id, step_name, status, requested_by, worker_mode,
                       requested_workers, effective_workers, started_at_utc, completed_at_utc,
                       run_metrics, error_message
                FROM phase4.workflow_runs
                {where}
                ORDER BY started_at_utc DESC
                LIMIT %(limit)s;
                """,
                params,
            )
            cols = [d.name for d in cur.description]
            rows = [dict(zip(cols, row)) for row in cur.fetchall()]
    for row in rows:
        for k in ("started_at_utc", "completed_at_utc"):
            if row.get(k) is not None:
                row[k] = row[k].isoformat()
    return rows


def list_inflight_workflow_runs(*, step_name: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    where_clauses = ["status IN ('queued','running')", "completed_at_utc IS NULL"]
    params: dict[str, Any] = {"limit": limit}
    if step_name:
        where_clauses.append("step_name = %(step_name)s")
        params["step_name"] = step_name
    where_sql = "WHERE " + " AND ".join(where_clauses)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT run_id::text, workflow_id, step_name, status, requested_by, worker_mode,
                       requested_workers, effective_workers, started_at_utc, completed_at_utc,
                       run_metrics, error_message
                FROM phase4.workflow_runs
                {where_sql}
                ORDER BY started_at_utc DESC
                LIMIT %(limit)s;
                """,
                params,
            )
            cols = [d.name for d in cur.description]
            rows = [dict(zip(cols, row)) for row in cur.fetchall()]
    for row in rows:
        for k in ("started_at_utc", "completed_at_utc"):
            if row.get(k) is not None:
                row[k] = row[k].isoformat()
    return rows


def insert_model_training_run(
    *,
    run_id: str,
    model_version: str,
    experiment_id: str,
    status: str,
    train_dataset_filter: str,
    worker_mode: str,
    worker_count: int,
    metrics_json: dict[str, Any] | None = None,
    model_id: str | None = None,
    source_step1_run_id: str | None = None,
    workflow_id: str | None = None,
    source_step1_lineage_hash: str | None = None,
) -> str:
    training_run_id = str(uuid.uuid4())
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.model_training_runs (
                    training_run_id, run_id, model_version, experiment_id, status,
                    train_dataset_filter, worker_mode, worker_count, metrics_json,
                    model_id, source_step1_run_id, workflow_id, source_step1_lineage_hash
                )
                VALUES (
                    %(id)s::uuid, %(run_id)s::uuid, %(model_version)s, %(experiment_id)s, %(status)s,
                    %(filter)s, %(worker_mode)s, %(worker_count)s, %(metrics)s::jsonb,
                    %(model_id)s, %(source_step1_run_id)s, %(workflow_id)s, %(source_step1_lineage_hash)s
                );
                """,
                {
                    "id": training_run_id,
                    "run_id": run_id,
                    "model_version": model_version,
                    "experiment_id": experiment_id,
                    "status": status,
                    "filter": train_dataset_filter,
                    "worker_mode": worker_mode,
                    "worker_count": worker_count,
                    "metrics": json.dumps(metrics_json or {}),
                    "model_id": model_id,
                    "source_step1_run_id": source_step1_run_id,
                    "workflow_id": workflow_id,
                    "source_step1_lineage_hash": source_step1_lineage_hash,
                },
            )
        conn.commit()
    return training_run_id


def insert_model_evaluation_run(
    *,
    run_id: str,
    model_version: str,
    experiment_id: str,
    dataset_id: str,
    split_name: str,
    status: str,
    metrics_json: dict[str, Any] | None = None,
    model_id: str | None = None,
    source_step1_run_id: str | None = None,
    workflow_id: str | None = None,
    source_step1_lineage_hash: str | None = None,
) -> str:
    evaluation_run_id = str(uuid.uuid4())
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.model_evaluation_runs (
                    evaluation_run_id, run_id, model_version, experiment_id, dataset_id,
                    split_name, status, metrics_json, model_id, source_step1_run_id, workflow_id, source_step1_lineage_hash
                )
                VALUES (
                    %(id)s::uuid, %(run_id)s::uuid, %(model_version)s, %(experiment_id)s, %(dataset_id)s,
                    %(split)s, %(status)s, %(metrics)s::jsonb, %(model_id)s, %(source_step1_run_id)s, %(workflow_id)s, %(source_step1_lineage_hash)s
                );
                """,
                {
                    "id": evaluation_run_id,
                    "run_id": run_id,
                    "model_version": model_version,
                    "experiment_id": experiment_id,
                    "dataset_id": dataset_id,
                    "split": split_name,
                    "status": status,
                    "metrics": json.dumps(metrics_json or {}),
                    "model_id": model_id,
                    "source_step1_run_id": source_step1_run_id,
                    "workflow_id": workflow_id,
                    "source_step1_lineage_hash": source_step1_lineage_hash,
                },
            )
        conn.commit()
    return evaluation_run_id


def insert_cross_dataset_test_run(
    *,
    run_id: str,
    model_version: str,
    experiment_id: str,
    dataset_id: str,
    evaluation_mode: str,
    status: str,
    metrics_json: dict[str, Any] | None = None,
    model_id: str | None = None,
    source_step1_run_id: str | None = None,
    workflow_id: str | None = None,
    source_step1_lineage_hash: str | None = None,
) -> str:
    cross_id = str(uuid.uuid4())
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.cross_dataset_test_runs (
                    cross_test_run_id, run_id, model_version, experiment_id, dataset_id,
                    evaluation_mode, status, metrics_json, model_id, source_step1_run_id, workflow_id, source_step1_lineage_hash
                )
                VALUES (
                    %(id)s::uuid, %(run_id)s::uuid, %(model_version)s, %(experiment_id)s, %(dataset_id)s,
                    %(mode)s, %(status)s, %(metrics)s::jsonb, %(model_id)s, %(source_step1_run_id)s, %(workflow_id)s, %(source_step1_lineage_hash)s
                );
                """,
                {
                    "id": cross_id,
                    "run_id": run_id,
                    "model_version": model_version,
                    "experiment_id": experiment_id,
                    "dataset_id": dataset_id,
                    "mode": evaluation_mode,
                    "status": status,
                    "metrics": json.dumps(metrics_json or {}),
                    "model_id": model_id,
                    "source_step1_run_id": source_step1_run_id,
                    "workflow_id": workflow_id,
                    "source_step1_lineage_hash": source_step1_lineage_hash,
                },
            )
        conn.commit()
    return cross_id


def insert_model_per_class_metrics(
    *,
    run_id: str,
    model_version: str,
    experiment_id: str,
    dataset_id: str,
    split_name: str,
    evaluation_mode: str,
    eval_target: str,
    model_track: str,
    metrics: dict[str, Any],
    model_id: str | None = None,
) -> int:
    per_class = metrics.get("per_class_metrics") if isinstance(metrics, dict) else None
    if not isinstance(per_class, list) or not per_class:
        return 0
    inserted = 0
    confusion_matrix = metrics.get("confusion_matrix") if isinstance(metrics.get("confusion_matrix"), list) else []
    with connect() as conn:
        with conn.cursor() as cur:
            for row in per_class:
                if not isinstance(row, dict):
                    continue
                cur.execute(
                    """
                    INSERT INTO phase4.model_per_class_metrics (
                        metric_row_id, run_id, model_id, model_version, experiment_id, dataset_id,
                        split_name, evaluation_mode, eval_target, model_track, label,
                        precision, recall, f1, support, accuracy, macro_f1, weighted_f1, micro_f1,
                        fpr, far, fnr, confusion_matrix, metrics_json, created_at_utc
                    )
                    VALUES (
                        %(id)s::uuid, %(run_id)s::uuid, %(model_id)s, %(model_version)s, %(experiment_id)s, %(dataset_id)s,
                        %(split_name)s, %(evaluation_mode)s, %(eval_target)s, %(model_track)s, %(label)s,
                        %(precision)s, %(recall)s, %(f1)s, %(support)s, %(accuracy)s, %(macro_f1)s, %(weighted_f1)s, %(micro_f1)s,
                        %(fpr)s, %(far)s, %(fnr)s, %(confusion_matrix)s::jsonb, %(metrics_json)s::jsonb, now()
                    );
                    """,
                    {
                        "id": str(uuid.uuid4()),
                        "run_id": run_id,
                        "model_id": model_id,
                        "model_version": model_version,
                        "experiment_id": experiment_id,
                        "dataset_id": dataset_id,
                        "split_name": split_name,
                        "evaluation_mode": evaluation_mode,
                        "eval_target": eval_target,
                        "model_track": model_track,
                        "label": str(row.get("label") or ""),
                        "precision": row.get("precision"),
                        "recall": row.get("recall"),
                        "f1": row.get("f1"),
                        "support": row.get("support"),
                        "accuracy": metrics.get("accuracy"),
                        "macro_f1": metrics.get("macro_f1"),
                        "weighted_f1": metrics.get("weighted_f1"),
                        "micro_f1": metrics.get("micro_f1"),
                        "fpr": metrics.get("fpr"),
                        "far": metrics.get("far"),
                        "fnr": metrics.get("fnr"),
                        "confusion_matrix": json.dumps(confusion_matrix),
                        "metrics_json": json.dumps(metrics),
                    },
                )
                inserted += 1
        conn.commit()
    return inserted


def insert_shap_artifact(
    *,
    run_id: str,
    model_version: str,
    dataset_id: str,
    split_name: str,
    partition_id: str | None,
    artifact_path: str | None,
    status: str,
    metadata: dict[str, Any] | None = None,
    model_id: str | None = None,
    source_step1_run_id: str | None = None,
    workflow_id: str | None = None,
    source_step1_lineage_hash: str | None = None,
) -> str:
    shap_artifact_id = str(uuid.uuid4())
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.shap_artifacts (
                    shap_artifact_id, run_id, model_version, dataset_id, split_name,
                    partition_id, artifact_path, status, metadata, model_id, source_step1_run_id, workflow_id, source_step1_lineage_hash
                )
                VALUES (
                    %(id)s::uuid, %(run_id)s::uuid, %(model_version)s, %(dataset_id)s, %(split_name)s,
                    %(partition_id)s, %(artifact_path)s, %(status)s, %(metadata)s::jsonb,
                    %(model_id)s, %(source_step1_run_id)s, %(workflow_id)s, %(source_step1_lineage_hash)s
                );
                """,
                {
                    "id": shap_artifact_id,
                    "run_id": run_id,
                    "model_version": model_version,
                    "dataset_id": dataset_id,
                    "split_name": split_name,
                    "partition_id": partition_id,
                    "artifact_path": artifact_path,
                    "status": status,
                    "metadata": json.dumps(metadata or {}),
                    "model_id": model_id,
                    "source_step1_run_id": source_step1_run_id,
                    "workflow_id": workflow_id,
                    "source_step1_lineage_hash": source_step1_lineage_hash,
                },
            )
        conn.commit()
    return shap_artifact_id


def insert_shap_log(
    *,
    event_type: str,
    actor: str,
    dataset_id: str | None,
    experiment_id: str,
    model_version: str,
    event_details_json: dict[str, Any] | None = None,
    rule_version: str | None = None,
    replay_id: str | None = None,
    canonical_record_id: str | None = None,
    alert_id: str | None = None,
    shap_stage: str | None = None,
    top_features_json: dict[str, Any] | None = None,
    shap_artifact_path: str | None = None,
) -> int:
    row_id = 0
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.shap_logs (
                    event_type, actor, dataset_id, experiment_id, model_version,
                    rule_version, replay_id, event_details_json,
                    canonical_record_id, alert_id, shap_stage, top_features_json, shap_artifact_path
                )
                VALUES (
                    %(event_type)s, %(actor)s, %(dataset_id)s, %(experiment_id)s, %(model_version)s,
                    %(rule_version)s, %(replay_id)s, %(event_details_json)s::jsonb,
                    %(canonical_record_id)s::uuid, %(alert_id)s, %(shap_stage)s, %(top_features_json)s::jsonb, %(shap_artifact_path)s
                )
                RETURNING id;
                """,
                {
                    "event_type": event_type,
                    "actor": actor,
                    "dataset_id": dataset_id,
                    "experiment_id": experiment_id,
                    "model_version": model_version,
                    "rule_version": rule_version,
                    "replay_id": replay_id,
                    "event_details_json": json.dumps(event_details_json or {}),
                    "canonical_record_id": canonical_record_id,
                    "alert_id": alert_id,
                    "shap_stage": shap_stage,
                    "top_features_json": json.dumps(top_features_json or {}),
                    "shap_artifact_path": shap_artifact_path,
                },
            )
            row = cur.fetchone()
            row_id = int(row[0]) if row and row[0] is not None else 0
        conn.commit()
    return row_id


def insert_results_shap_row(
    *,
    experiment_id: str,
    model_version: str,
    shap_stage: str,
    input_desc: str,
    output_desc: str,
    metric: str,
    value: str,
    interpretation: str,
) -> int:
    row_id = 0
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.results_shap (
                    experiment_id, model_version, shap_stage, input_desc,
                    output_desc, metric, value, interpretation
                )
                VALUES (
                    %(experiment_id)s, %(model_version)s, %(shap_stage)s, %(input_desc)s,
                    %(output_desc)s, %(metric)s, %(value)s, %(interpretation)s
                )
                RETURNING id;
                """,
                {
                    "experiment_id": experiment_id,
                    "model_version": model_version,
                    "shap_stage": shap_stage,
                    "input_desc": input_desc,
                    "output_desc": output_desc,
                    "metric": metric,
                    "value": value,
                    "interpretation": interpretation,
                },
            )
            row = cur.fetchone()
            row_id = int(row[0]) if row and row[0] is not None else 0
        conn.commit()
    return row_id


def insert_h1_shap_triage_result(
    *,
    experiment_id: str,
    model_version: str,
    explanation_coverage: str,
    top_features_consistency: str,
    explanation_clarity: str,
    triage_support_score: str,
    interpretation: str,
) -> int:
    row_id = 0
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.h1_shap_triage_results (
                    experiment_id, model_version, explanation_coverage, top_features_consistency,
                    explanation_clarity, triage_support_score, interpretation
                )
                VALUES (
                    %(experiment_id)s, %(model_version)s, %(explanation_coverage)s, %(top_features_consistency)s,
                    %(explanation_clarity)s, %(triage_support_score)s, %(interpretation)s
                )
                RETURNING id;
                """,
                {
                    "experiment_id": experiment_id,
                    "model_version": model_version,
                    "explanation_coverage": explanation_coverage,
                    "top_features_consistency": top_features_consistency,
                    "explanation_clarity": explanation_clarity,
                    "triage_support_score": triage_support_score,
                    "interpretation": interpretation,
                },
            )
            row = cur.fetchone()
            row_id = int(row[0]) if row and row[0] is not None else 0
        conn.commit()
    return row_id


def insert_rulepack_registry(
    *,
    run_id: str,
    model_version: str,
    rulepack_version: str,
    scope: str,
    status: str,
    artifact_path: str | None,
    checksum_sha256: str | None,
    metadata: dict[str, Any] | None = None,
    model_id: str | None = None,
    source_step1_run_id: str | None = None,
    workflow_id: str | None = None,
    source_step1_lineage_hash: str | None = None,
) -> str:
    rulepack_id = str(uuid.uuid4())
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.rulepack_registry (
                    rulepack_id, run_id, model_version, rulepack_version,
                    scope, status, artifact_path, checksum_sha256, metadata,
                    model_id, source_step1_run_id, workflow_id, source_step1_lineage_hash
                )
                VALUES (
                    %(id)s::uuid, %(run_id)s::uuid, %(model_version)s, %(rulepack_version)s,
                    %(scope)s, %(status)s, %(artifact_path)s, %(checksum_sha256)s, %(metadata)s::jsonb,
                    %(model_id)s, %(source_step1_run_id)s, %(workflow_id)s, %(source_step1_lineage_hash)s
                );
                """,
                {
                    "id": rulepack_id,
                    "run_id": run_id,
                    "model_version": model_version,
                    "rulepack_version": rulepack_version,
                    "scope": scope,
                    "status": status,
                    "artifact_path": artifact_path,
                    "checksum_sha256": checksum_sha256,
                    "metadata": json.dumps(metadata or {}),
                    "model_id": model_id,
                    "source_step1_run_id": source_step1_run_id,
                    "workflow_id": workflow_id,
                    "source_step1_lineage_hash": source_step1_lineage_hash,
                },
            )
        conn.commit()
    return rulepack_id


def mark_rulepack_published(*, run_id: str, scope: str) -> None:
    patch = json.dumps({"published_at_utc": _now(), "published": True})
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE phase4.rulepack_registry
                SET status = 'published',
                    metadata = COALESCE(metadata, '{}'::jsonb) || %(patch)s::jsonb
                WHERE run_id = %(run_id)s::uuid AND scope = %(scope)s;
                """,
                {"run_id": run_id, "scope": scope, "patch": patch},
            )
        conn.commit()


def upsert_rulepack_rule(
    *,
    run_id: str,
    workflow_id: str,
    model_version: str,
    rule_scope: str,
    rule_type: str,
    condition_json: dict[str, Any],
    severity: str,
    action: str,
    evidence_sources: list[Any] | None,
    status: str,
    checksum_sha256: str,
    model_id: str | None = None,
    linked_model_version: str | None = None,
) -> str:
    """Idempotent upsert keyed by run/workflow/model/scope/checksum."""
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT rule_id::text
                FROM phase4.rulepack_rules
                WHERE run_id = %(run_id)s::uuid
                  AND COALESCE(workflow_id, '') = COALESCE(%(workflow_id)s, '')
                  AND model_version = %(model_version)s
                  AND rule_scope = %(rule_scope)s
                  AND checksum_sha256 = %(checksum_sha256)s
                LIMIT 1;
                """,
                {
                    "run_id": run_id,
                    "workflow_id": workflow_id,
                    "model_version": model_version,
                    "rule_scope": rule_scope,
                    "checksum_sha256": checksum_sha256,
                },
            )
            row = cur.fetchone()
            if row and row[0]:
                rule_id = str(row[0])
                cur.execute(
                    """
                    UPDATE phase4.rulepack_rules
                    SET rule_type = %(rule_type)s,
                        condition_json = %(condition_json)s::jsonb,
                        severity = %(severity)s,
                        action = %(action)s,
                        evidence_sources = %(evidence_sources)s::jsonb,
                        status = %(status)s,
                        model_id = COALESCE(%(model_id)s, phase4.rulepack_rules.model_id),
                        linked_model_version = %(linked_model_version)s,
                        finished_at_utc = now(),
                        error_message = NULL
                    WHERE rule_id = %(rule_id)s::uuid;
                    """,
                    {
                        "rule_id": rule_id,
                        "rule_type": rule_type,
                        "condition_json": json.dumps(condition_json or {}),
                        "severity": severity,
                        "action": action,
                        "evidence_sources": json.dumps(evidence_sources or []),
                        "status": status,
                        "model_id": model_id,
                        "linked_model_version": linked_model_version,
                    },
                )
            else:
                rule_id = str(uuid.uuid4())
                cur.execute(
                    """
                    INSERT INTO phase4.rulepack_rules (
                        rule_id, run_id, workflow_id, model_version, phase, rule_scope,
                        rule_type, condition_json, severity, action, evidence_sources,
                        model_id, linked_model_version, created_at_utc, finished_at_utc, status, checksum_sha256
                    )
                    VALUES (
                        %(rule_id)s::uuid, %(run_id)s::uuid, %(workflow_id)s, %(model_version)s, 'rule_generation', %(rule_scope)s,
                        %(rule_type)s, %(condition_json)s::jsonb, %(severity)s, %(action)s, %(evidence_sources)s::jsonb,
                        %(model_id)s, %(linked_model_version)s, now(), now(), %(status)s, %(checksum_sha256)s
                    );
                    """,
                    {
                        "rule_id": rule_id,
                        "run_id": run_id,
                        "workflow_id": workflow_id,
                        "model_version": model_version,
                        "rule_scope": rule_scope,
                        "rule_type": rule_type,
                        "condition_json": json.dumps(condition_json or {}),
                        "severity": severity,
                        "action": action,
                        "evidence_sources": json.dumps(evidence_sources or []),
                        "model_id": model_id,
                        "linked_model_version": linked_model_version,
                        "status": status,
                        "checksum_sha256": checksum_sha256,
                    },
                )
        conn.commit()
    return rule_id


def count_rulepack_rules(*, run_id: str, scope: str) -> int:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT count(*)::int
                FROM phase4.rulepack_rules
                WHERE run_id = %(run_id)s::uuid
                  AND rule_scope = %(scope)s;
                """,
                {"run_id": run_id, "scope": scope},
            )
            row = cur.fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def make_worker_log_context(
    *,
    run_id: str,
    workflow_id: str,
    dataset_id: str | None,
    worker_id: str,
    stage: str,
    status: str,
    started_at: str,
    completed_at: str | None = None,
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "workflow_id": workflow_id,
        "dataset_id": dataset_id,
        "worker_id": worker_id,
        "stage": stage,
        "status": status,
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "logged_at_utc": _now(),
    }


def fetch_step1_dataset_split_counts(source_step1_run_id: str) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT dataset_id, split_name, count(*)::int
                FROM phase4.dataset_splits
                WHERE source_step1_run_id::text = %(rid)s
                GROUP BY dataset_id, split_name;
                """,
                {"rid": source_step1_run_id},
            )
            for dataset_id, split_name, cnt in cur.fetchall():
                d = out.setdefault(str(dataset_id), {})
                d[str(split_name)] = int(cnt)
    return out


def derive_step1_lineage_hash_consistency(
    *,
    run_id: str,
    step1_lineage_hash: str,
) -> dict[str, Any]:
    expected_hash = str(step1_lineage_hash or "").strip()
    run_metrics = _load_step1_run_metrics(run_id)
    if not expected_hash:
        expected_hash = str(run_metrics.get("step1_ingest_lineage_hash") or "").strip()
    if not expected_hash:
        root = str(run_metrics.get("data_root_canonical") or run_metrics.get("data_root") or "").strip()
        manifest_version = str(run_metrics.get("step1_manifest_version") or "").strip()
        if root and manifest_version:
            expected_hash = hashlib.sha256(f"{run_id}|{root}|{manifest_version}".encode("utf-8")).hexdigest()
    if not expected_hash:
        expected_hash = str(run_metrics.get("step1_dataset_lineage_hash") or "").strip()

    with connect() as conn:
        with conn.cursor() as cur:
            if not expected_hash:
                cur.execute(
                    """
                    SELECT source_step1_lineage_hash, COUNT(*)::bigint AS cnt
                    FROM phase4.dataset_splits
                    WHERE source_step1_run_id::text = %(run_id)s
                      AND COALESCE(source_step1_lineage_hash, '') <> ''
                    GROUP BY source_step1_lineage_hash
                    ORDER BY cnt DESC, source_step1_lineage_hash DESC
                    LIMIT 1;
                    """,
                    {"run_id": run_id},
                )
                guess = cur.fetchone()
                expected_hash = str((guess or [""])[0] or "").strip()
            cur.execute(
                """
                SELECT
                    COUNT(*)::bigint AS denominator,
                    COUNT(*) FILTER (
                        WHERE COALESCE(source_step1_lineage_hash, '') <> ''
                    )::bigint AS non_empty_hash_rows,
                    COUNT(*) FILTER (
                        WHERE COALESCE(source_step1_lineage_hash, '') = %(lineage_hash)s
                    )::bigint AS numerator
                FROM phase4.dataset_splits
                WHERE source_step1_run_id::text = %(run_id)s;
                """,
                {"run_id": run_id, "lineage_hash": expected_hash},
            )
            row = cur.fetchone() or (0, 0, 0)
    denominator = int(row[0] or 0)
    non_empty_hash_rows = int(row[1] or 0)
    numerator = int(row[2] or 0) if expected_hash else 0
    value = (float(numerator) / float(denominator)) if (denominator > 0 and expected_hash) else None
    status = "measured" if (denominator > 0 and expected_hash) else "not_collected"
    return {
        "metric_name": "lineage_hash_consistency",
        "metric_value": value,
        "numerator": numerator,
        "denominator": denominator,
        "status": status,
        "details_json": {
            "formula": "matching_hashes / total_hashes",
            "source": "phase4.dataset_splits",
            "run_id": run_id,
            "step1_lineage_hash": expected_hash,
            "non_empty_hash_rows": non_empty_hash_rows,
            "missing_hash_rows": max(0, denominator - non_empty_hash_rows),
            "expected_hash_resolution": (
                "provided_or_run_metrics_or_derived_or_dominant_non_empty"
                if expected_hash
                else "unresolved"
            ),
        },
    }


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        try:
            return int(float(value))
        except Exception:
            return 0


def _round_six(value: float | None) -> float | None:
    if value is None:
        return None
    try:
        return round(float(value), 6)
    except Exception:
        return None


def _safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _load_step1_run_metrics(run_id: str) -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT run_metrics
                FROM phase4.workflow_runs
                WHERE step_name = 'step1' AND run_id = %(run_id)s::uuid
                LIMIT 1;
                """,
                {"run_id": run_id},
            )
            row = cur.fetchone()
    if not row:
        return {}
    payload = row[0]
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, str):
        try:
            parsed = json.loads(payload)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _dataset_splits_step1_file_summary(run_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    rid = str(run_id or "").strip()
    if not rid:
        return rows
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    dataset_id,
                    COALESCE(NULLIF(source_file, ''), 'unknown') AS source_file,
                    COUNT(*)::bigint AS total_rows,
                    COUNT(*) FILTER (WHERE COALESCE(label_harmonized, '') <> '')::bigint AS rows_ok,
                    COUNT(*) FILTER (WHERE COALESCE(label_harmonized, '') = '')::bigint AS rows_fail,
                    COUNT(*) FILTER (WHERE COALESCE(vector_class, '') <> '')::bigint AS vector_mapped_count
                FROM phase4.dataset_splits
                WHERE source_step1_run_id::text = %(run_id)s
                GROUP BY dataset_id, COALESCE(NULLIF(source_file, ''), 'unknown')
                ORDER BY dataset_id, source_file;
                """,
                {"run_id": rid},
            )
            for dataset_id, source_file, total_rows, rows_ok, rows_fail, vector_mapped_count in cur.fetchall():
                total_i = int(total_rows or 0)
                ok_i = int(rows_ok or 0)
                fail_i = int(rows_fail or 0)
                rows.append(
                    {
                        "dataset_id": str(dataset_id or "").strip() or "unknown",
                        "filename": str(source_file or "unknown"),
                        "path": str(source_file or "unknown"),
                        "ok": bool(total_i > 0 and fail_i == 0),
                        "total_rows": total_i,
                        "normalized_rows": ok_i,
                        "failed_rows": fail_i,
                        "rows_ok": ok_i,
                        "rows_fail": fail_i,
                        "vector_mapped_count": int(vector_mapped_count or 0),
                        "detail": f"dataset_splits_rows={total_i}",
                    }
                )
    return rows


def _iter_step1_file_summary(step1_metrics: dict[str, Any], *, run_id: str | None = None) -> list[dict[str, Any]]:
    if run_id:
        primary_rows = _dataset_splits_step1_file_summary(str(run_id or "").strip())
        if primary_rows:
            return primary_rows
    rows: list[dict[str, Any]] = []
    results = step1_metrics.get("step1_results")
    if isinstance(results, list):
        for dataset_row in results:
            if not isinstance(dataset_row, dict):
                continue
            file_summary = dataset_row.get("file_summary")
            if not isinstance(file_summary, list):
                continue
            dataset_id = str(dataset_row.get("dataset_id") or "").strip()
            for file_row in file_summary:
                if isinstance(file_row, dict):
                    merged = dict(file_row)
                    if dataset_id and not str(merged.get("dataset_id") or "").strip():
                        merged["dataset_id"] = dataset_id
                    rows.append(merged)
    return rows


def _ensure_default_canonical_required_fields(schema_version: str) -> None:
    if schema_version != STEP1_CANONICAL_SCHEMA_VERSION:
        return
    with connect() as conn:
        with conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO phase4.canonical_required_fields (
                    schema_version, field_name, is_required, created_at_utc, updated_at_utc
                )
                VALUES (%(schema_version)s, %(field_name)s, true, now(), now())
                ON CONFLICT (schema_version, field_name) DO NOTHING;
                """,
                [
                    {"schema_version": schema_version, "field_name": field_name}
                    for field_name in STEP1_CANONICAL_REQUIRED_FIELDS_V1
                ],
            )
        conn.commit()


def _load_required_fields_by_dataset(*, run_id: str, schema_version: str) -> dict[str, list[str]]:
    _ensure_default_canonical_required_fields(schema_version)
    required_global: set[str] = set()
    overrides: dict[str, dict[str, bool]] = {}
    dataset_ids: set[str] = set()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT field_name
                FROM phase4.canonical_required_fields
                WHERE schema_version = %(schema_version)s
                  AND is_required = true;
                """,
                {"schema_version": schema_version},
            )
            required_global = {
                str(row[0]).strip()
                for row in cur.fetchall()
                if str(row[0]).strip()
            }
            cur.execute(
                """
                SELECT DISTINCT dataset_id
                FROM phase4.dataset_splits
                WHERE source_step1_run_id::text = %(run_id)s;
                """,
                {"run_id": run_id},
            )
            dataset_ids = {
                str(row[0]).strip()
                for row in cur.fetchall()
                if str(row[0]).strip()
            }
            if dataset_ids:
                cur.execute(
                    """
                    SELECT dataset_id, field_name, is_required
                    FROM phase4.dataset_required_field_overrides
                    WHERE schema_version = %(schema_version)s
                      AND dataset_id = ANY(%(dataset_ids)s);
                    """,
                    {"schema_version": schema_version, "dataset_ids": list(dataset_ids)},
                )
                for dataset_id, field_name, is_required in cur.fetchall():
                    ds = str(dataset_id).strip()
                    field = str(field_name).strip()
                    if not ds or not field:
                        continue
                    overrides.setdefault(ds, {})[field] = bool(is_required)

    if not required_global:
        required_global = set(STEP1_CANONICAL_REQUIRED_FIELDS_V1)

    out: dict[str, list[str]] = {}
    for dataset_id in dataset_ids:
        required = set(required_global)
        for field_name, is_required in overrides.get(dataset_id, {}).items():
            if is_required:
                required.add(field_name)
            else:
                required.discard(field_name)
        out[dataset_id] = sorted(required)
    return out


def upsert_step1_file_field_coverage(
    *,
    run_id: str,
    dataset_id: str,
    source_file: str,
    schema_version: str,
    total_rows: int,
    required_field_count: int,
    mapped_fields: int,
    required_fields: int,
    missing_by_field_json: dict[str, Any],
) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.step1_file_field_coverage (
                    run_id, dataset_id, source_file, schema_version, total_rows,
                    required_field_count, mapped_fields, required_fields,
                    missing_by_field_json, measured_at_utc, updated_at_utc
                )
                VALUES (
                    %(run_id)s::uuid, %(dataset_id)s, %(source_file)s, %(schema_version)s, %(total_rows)s,
                    %(required_field_count)s, %(mapped_fields)s, %(required_fields)s,
                    %(missing_by_field_json)s::jsonb, now(), now()
                )
                ON CONFLICT (run_id, dataset_id, source_file) DO UPDATE
                SET schema_version = EXCLUDED.schema_version,
                    total_rows = EXCLUDED.total_rows,
                    required_field_count = EXCLUDED.required_field_count,
                    mapped_fields = EXCLUDED.mapped_fields,
                    required_fields = EXCLUDED.required_fields,
                    missing_by_field_json = EXCLUDED.missing_by_field_json,
                    measured_at_utc = now(),
                    updated_at_utc = now();
                """,
                {
                    "run_id": run_id,
                    "dataset_id": dataset_id,
                    "source_file": source_file,
                    "schema_version": schema_version,
                    "total_rows": int(total_rows),
                    "required_field_count": int(required_field_count),
                    "mapped_fields": int(mapped_fields),
                    "required_fields": int(required_fields),
                    "missing_by_field_json": json.dumps(missing_by_field_json or {}),
                },
            )
        conn.commit()


def derive_step1_schema_validation_success_rate(
    *,
    run_id: str,
) -> dict[str, Any]:
    metrics = _load_step1_run_metrics(run_id)
    file_rows = _iter_step1_file_summary(metrics, run_id=run_id)
    denominator = 0
    numerator = 0
    for row in file_rows:
        denominator += 1
        ok = bool(row.get("ok"))
        failed_rows = _safe_int(row.get("failed_rows") or row.get("rows_fail") or 0)
        if ok and failed_rows == 0:
            numerator += 1
    value = (float(numerator) / float(denominator)) if denominator > 0 else None
    status = "measured" if denominator > 0 else "not_collected"
    return {
        "metric_name": "schema_validation_success_rate",
        "metric_value": value,
        "numerator": numerator,
        "denominator": denominator,
        "status": status,
        "details_json": {
            "formula": "valid_files / total_files",
            "valid_file_rule": "ok=true and failed_rows=0",
            "source": "phase4.dataset_splits primary; phase4.workflow_runs.run_metrics.step1_results[*].file_summary fallback",
            "run_id": run_id,
        },
    }


def derive_step1_failed_input_archive_coverage(
    *,
    run_id: str,
) -> dict[str, Any]:
    metrics = _load_step1_run_metrics(run_id)
    file_rows: list[dict[str, Any]] = []
    results = metrics.get("step1_results")
    if isinstance(results, list):
        for dataset_row in results:
            if not isinstance(dataset_row, dict):
                continue
            file_summary = dataset_row.get("file_summary")
            if not isinstance(file_summary, list):
                continue
            dataset_id = str(dataset_row.get("dataset_id") or "").strip()
            for file_row in file_summary:
                if not isinstance(file_row, dict):
                    continue
                merged = dict(file_row)
                if dataset_id and not str(merged.get("dataset_id") or "").strip():
                    merged["dataset_id"] = dataset_id
                file_rows.append(merged)

    denominator = 0
    numerator = 0
    rows_with_failed_inputs = 0
    rows_with_direct_archive_count = 0
    rows_missing_direct_archive_count = 0
    for row in file_rows:
        failed_rows = _safe_int(row.get("failed_rows") or row.get("rows_fail") or 0)
        if failed_rows <= 0:
            continue
        rows_with_failed_inputs += 1
        denominator += failed_rows
        if "archived_failed_rows" in row:
            archived_rows = max(0, _safe_int(row.get("archived_failed_rows")))
            numerator += min(archived_rows, failed_rows)
            rows_with_direct_archive_count += 1
        else:
            rows_missing_direct_archive_count += 1

    has_direct_counts = rows_with_failed_inputs > 0 and rows_missing_direct_archive_count == 0
    value = (float(numerator) / float(denominator)) if (denominator > 0 and has_direct_counts) else None
    status = "measured" if (denominator > 0 and has_direct_counts) else "not_collected"
    return {
        "metric_name": "failed_input_archive_coverage",
        "metric_value": value,
        "numerator": numerator,
        "denominator": denominator,
        "status": status,
        "details_json": {
            "formula": "archived_failed_inputs / failed_inputs",
            "archived_rule": "direct sum(archived_failed_rows) from step1_results.file_summary",
            "source": "phase4.workflow_runs.run_metrics.step1_results[*].file_summary",
            "run_id": run_id,
            "rows_with_failed_inputs": rows_with_failed_inputs,
            "rows_with_direct_archive_count": rows_with_direct_archive_count,
            "rows_missing_direct_archive_count": rows_missing_direct_archive_count,
        },
    }


def derive_step1_dataset_lineage_coverage(
    *,
    run_id: str,
) -> dict[str, Any]:
    metrics = _load_step1_run_metrics(run_id)
    expected_hash = str(
        metrics.get("step1_ingest_lineage_hash")
        or metrics.get("step1_dataset_lineage_hash")
        or ""
    ).strip()
    processed_datasets: list[str] = []
    lineage_by_dataset: dict[str, dict[str, int]] = {}
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT dataset_id
                FROM phase4.dataset_splits
                WHERE source_step1_run_id::text = %(run_id)s;
                """,
                {"run_id": run_id},
            )
            processed_datasets = [str(row[0]).strip() for row in cur.fetchall() if str(row[0] or "").strip()]
            cur.execute(
                """
                SELECT
                    dataset_id,
                    COUNT(*)::bigint AS total_rows,
                    COUNT(*) FILTER (
                        WHERE (
                            CASE
                                WHEN %(expected_hash)s <> '' THEN COALESCE(source_step1_lineage_hash, '') = %(expected_hash)s
                                ELSE COALESCE(source_step1_lineage_hash, '') <> ''
                            END
                        )
                    )::bigint AS lineage_rows
                FROM phase4.dataset_splits
                WHERE source_step1_run_id::text = %(run_id)s
                GROUP BY dataset_id;
                """,
                {"run_id": run_id, "expected_hash": expected_hash},
            )
            for dataset_id, total_rows, lineage_rows in cur.fetchall():
                lineage_by_dataset[str(dataset_id)] = {
                    "total_rows": int(total_rows or 0),
                    "lineage_rows": int(lineage_rows or 0),
                }
    if not processed_datasets:
        dataset_summary = metrics.get("dataset_summary")
        if isinstance(dataset_summary, dict):
            processed_datasets = [str(k).strip() for k in dataset_summary.keys() if str(k).strip()]
    if not processed_datasets:
        results = metrics.get("step1_results")
        if isinstance(results, list):
            seen: set[str] = set()
            for item in results:
                if not isinstance(item, dict):
                    continue
                dataset_id = str(item.get("dataset_id") or "").strip()
                if dataset_id and dataset_id not in seen:
                    seen.add(dataset_id)
                    processed_datasets.append(dataset_id)

    denominator = len(processed_datasets)
    numerator = 0
    dataset_breakdown: dict[str, Any] = {}
    for dataset_id in processed_datasets:
        counts = lineage_by_dataset.get(dataset_id, {"total_rows": 0, "lineage_rows": 0})
        total_rows = int(counts.get("total_rows") or 0)
        lineage_rows = int(counts.get("lineage_rows") or 0)
        covered = total_rows > 0 and total_rows == lineage_rows
        if covered:
            numerator += 1
        dataset_breakdown[dataset_id] = {
            "total_rows": total_rows,
            "lineage_rows": lineage_rows,
            "covered": covered,
        }

    value = (float(numerator) / float(denominator)) if denominator > 0 else None
    status = "measured" if denominator > 0 else "not_collected"
    return {
        "metric_name": "dataset_lineage_coverage",
        "metric_value": value,
        "numerator": numerator,
        "denominator": denominator,
        "status": status,
        "details_json": {
            "formula": "lineage_logged / datasets",
            "coverage_rule": (
                "dataset covered when all run rows have source_step1_lineage_hash equal to step1_ingest_lineage_hash"
                if expected_hash
                else "dataset covered when all run rows have non-empty source_step1_lineage_hash"
            ),
            "source": "phase4.dataset_splits primary; phase4.workflow_runs.run_metrics.dataset_summary fallback",
            "run_id": run_id,
            "expected_lineage_hash": expected_hash,
            "dataset_breakdown": dataset_breakdown,
        },
    }


def derive_step1_scope_assignment_confidence(
    *,
    run_id: str,
) -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*) FILTER (WHERE categorization_confidence IS NOT NULL)::bigint AS sample_count,
                    AVG(categorization_confidence)::double precision AS avg_confidence
                FROM phase4.dataset_splits
                WHERE source_step1_run_id::text = %(run_id)s;
                """,
                {"run_id": run_id},
            )
            row = cur.fetchone() or (0, None)
    sample_count = int(row[0] or 0)
    avg_confidence = float(row[1]) if row[1] is not None else None
    status = "measured" if sample_count > 0 else "not_collected"
    return {
        "metric_name": "scope_assignment_confidence",
        "metric_value": avg_confidence,
        "numerator": sample_count,
        "denominator": sample_count,
        "status": status,
        "details_json": {
            "formula": "avg_model_confidence",
            "source": "phase4.dataset_splits.categorization_confidence",
            "run_id": run_id,
            "sample_count": sample_count,
        },
    }


def derive_step1_domain_classification_accuracy(
    *,
    run_id: str,
) -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                WITH rows AS (
                    SELECT
                        ds.dataset_id,
                        COALESCE(NULLIF(ds.source_file, ''), 'unknown') AS source_file,
                        LOWER(COALESCE(ds.source_domain, '')) AS observed_domain,
                        COALESCE(
                            NULLIF(LOWER(BTRIM(dr.domain)), ''),
                            CASE
                                WHEN LOWER(ds.dataset_id) LIKE 'ent-%%' THEN 'enterprise'
                                WHEN LOWER(ds.dataset_id) LIKE 'dns-%%' THEN 'dns'
                                WHEN LOWER(ds.dataset_id) LIKE 'iot-%%' THEN 'iiot'
                                WHEN LOWER(ds.dataset_id) LIKE 'rep-%%' THEN 'mixed'
                                WHEN LOWER(ds.dataset_id) LIKE 'ref-%%' THEN 'enterprise'
                                ELSE ''
                            END
                        ) AS expected_domain
                    FROM phase4.dataset_splits ds
                    LEFT JOIN phase4.dataset_registry dr
                      ON dr.dataset_id = ds.dataset_id
                    WHERE ds.source_step1_run_id::text = %(run_id)s
                )
                SELECT
                    dataset_id,
                    source_file,
                    expected_domain,
                    COUNT(*)::bigint AS total_rows,
                    COUNT(*) FILTER (
                        WHERE expected_domain <> '' AND observed_domain = expected_domain
                    )::bigint AS correct_rows
                FROM rows
                GROUP BY dataset_id, source_file, expected_domain
                ORDER BY dataset_id, source_file;
                """,
                {"run_id": run_id},
            )
            grouped = cur.fetchall()

    denominator = 0
    numerator = 0
    file_breakdown: list[dict[str, Any]] = []
    for dataset_id, source_file, expected_domain, total_rows, correct_rows in grouped:
        total = int(total_rows or 0)
        correct = int(correct_rows or 0)
        denominator += total
        numerator += correct
        file_breakdown.append(
            {
                "dataset_id": str(dataset_id),
                "source_file": str(source_file),
                "expected_domain": str(expected_domain or ""),
                "total_rows": total,
                "correct_domain_labels": correct,
            }
        )

    value = (float(numerator) / float(denominator)) if denominator > 0 else None
    status = "measured" if denominator > 0 else "not_collected"
    return {
        "metric_name": "domain_classification_accuracy",
        "metric_value": value,
        "numerator": numerator,
        "denominator": denominator,
        "status": status,
        "details_json": {
            "formula": "correct_domain_labels / total_records",
            "source": "phase4.dataset_splits + phase4.dataset_registry",
            "run_id": run_id,
            "record_weighted": True,
            "file_breakdown": file_breakdown,
        },
    }


def derive_step1_canonical_mapping_completeness(
    *,
    run_id: str,
    schema_version: str = STEP1_CANONICAL_SCHEMA_VERSION,
) -> dict[str, Any]:
    metrics = _load_step1_run_metrics(run_id)
    file_rows = _iter_step1_file_summary(metrics, run_id=run_id)
    required_by_dataset = _load_required_fields_by_dataset(
        run_id=run_id,
        schema_version=schema_version,
    )
    default_required = list(STEP1_CANONICAL_REQUIRED_FIELDS_V1)

    total_required_fields = 0
    total_mapped_fields = 0
    processed_rows = 0
    per_file_breakdown: list[dict[str, Any]] = []

    for row in file_rows:
        if not bool(row.get("ok")):
            continue
        dataset_id = str(row.get("dataset_id") or "").strip() or "unknown"
        source_file = str(row.get("filename") or row.get("path") or "unknown").strip() or "unknown"
        total_rows = _safe_int(row.get("total_rows"))
        required_fields = required_by_dataset.get(dataset_id, default_required)
        required_field_count = len(required_fields)
        required_instances = total_rows * required_field_count

        missing_raw = _safe_dict(row.get("missing_required_field_counts"))
        if not missing_raw and total_rows > 0:
            # Fallback for runs where file_summary evidence is unavailable: infer missing counts from dataset_splits.
            with connect() as conn:
                with conn.cursor() as cur:
                    allowed_cols = {
                        "canonical_record_id",
                        "source_row_id",
                        "created_at",
                        "source_zone",
                        "expected_environment",
                        "protocol_family",
                        "source_domain",
                        "vector_class",
                        "attack_category",
                        "observed_environment",
                        "scope_match",
                        "cross_scope_flag",
                        "escalation_reason",
                        "categorization_confidence",
                        "adapter_version",
                        "source_file",
                        "source_path",
                        "checksum",
                        "label_harmonized",
                    }
                    for field in required_fields:
                        col = {
                            "event_id": "canonical_record_id",
                            "timestamp_utc": "created_at",
                            "source_ip": "source_zone",
                            "destination_ip": "expected_environment",
                            "protocol": "protocol_family",
                        }.get(field, field)
                        if col not in allowed_cols:
                            missing_raw[field] = total_rows
                            continue
                        if col == "cross_scope_flag":
                            cur.execute(
                                """
                                SELECT COUNT(*)::bigint
                                FROM phase4.dataset_splits
                                WHERE source_step1_run_id::text = %(run_id)s
                                  AND dataset_id = %(dataset_id)s
                                  AND COALESCE(NULLIF(source_file, ''), 'unknown') = %(source_file)s
                                  AND cross_scope_flag IS NULL;
                                """,
                                {"run_id": run_id, "dataset_id": dataset_id, "source_file": source_file},
                            )
                        elif col == "created_at":
                            cur.execute(
                                """
                                SELECT 0::bigint;
                                """
                            )
                        else:
                            cur.execute(
                                f"""
                                SELECT COUNT(*)::bigint
                                FROM phase4.dataset_splits
                                WHERE source_step1_run_id::text = %(run_id)s
                                  AND dataset_id = %(dataset_id)s
                                  AND COALESCE(NULLIF(source_file, ''), 'unknown') = %(source_file)s
                                  AND COALESCE(BTRIM(CAST({col} AS text)), '') = '';
                                """,
                                {"run_id": run_id, "dataset_id": dataset_id, "source_file": source_file},
                            )
                        missing_raw[field] = int((cur.fetchone() or (0,))[0] or 0)
        missing_by_field: dict[str, int] = {}
        missing_instances = 0
        for field in required_fields:
            cnt = max(0, _safe_int(missing_raw.get(field)))
            if cnt > 0:
                missing_by_field[field] = cnt
            missing_instances += cnt

        mapped_instances = max(required_instances - missing_instances, 0)
        total_required_fields += required_instances
        total_mapped_fields += mapped_instances
        processed_rows += total_rows

        upsert_step1_file_field_coverage(
            run_id=run_id,
            dataset_id=dataset_id,
            source_file=source_file,
            schema_version=schema_version,
            total_rows=total_rows,
            required_field_count=required_field_count,
            mapped_fields=mapped_instances,
            required_fields=required_instances,
            missing_by_field_json=missing_by_field,
        )
        per_file_breakdown.append(
            {
                "dataset_id": dataset_id,
                "source_file": source_file,
                "total_rows": total_rows,
                "required_field_count": required_field_count,
                "mapped_fields": mapped_instances,
                "required_fields": required_instances,
            }
        )

    value = (
        float(total_mapped_fields) / float(total_required_fields)
        if total_required_fields > 0
        else None
    )
    status = "measured" if total_required_fields > 0 else "not_collected"
    return {
        "metric_name": "canonical_mapping_completeness",
        "metric_value": value,
        "numerator": total_mapped_fields,
        "denominator": total_required_fields,
        "status": status,
        "details_json": {
            "formula": "mapped_fields / required_fields",
            "source": "phase4.dataset_splits primary; phase4.workflow_runs.run_metrics.step1_results[*].file_summary fallback + phase4.canonical_required_fields + phase4.step1_file_field_coverage",
            "run_id": run_id,
            "schema_version": schema_version,
            "processed_rows": processed_rows,
            "per_file_breakdown": per_file_breakdown,
        },
    }

