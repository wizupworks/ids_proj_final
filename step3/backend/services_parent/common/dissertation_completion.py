"""Dissertation Chapter 4/H1 completion aggregation and exports.

Builds measured dissertation artifacts from Step 2 / Step 3 persisted data,
writes CSV exports, and refreshes Chapter 4 + H1 result tables.
"""

from __future__ import annotations

import csv
import json
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from services_parent.common.governance_summary import build_leakage_checks_from_db
from services_parent.common.metrics_store import (
    is_deprecated_metric,
    purge_deprecated_metrics,
    upsert_step_metrics,
)
from services_parent.common.phase4_db import connect

DEFAULT_EXPERIMENT_ID = "exp_model_v1_enterprise_baseline"

CSV_FIELDS: dict[str, list[str]] = {
    "detection_metrics.csv": [
        "run_id",
        "model_id",
        "model_version",
        "dataset_id",
        "split_name",
        "evaluation_type",
        "model_track",
        "precision",
        "recall",
        "f1",
        "macro_f1",
        "micro_f1",
        "weighted_f1",
        "accuracy",
        "fpr",
        "far",
        "fnr",
        "measured_at_utc",
    ],
    "per_class_metrics.csv": [
        "run_id",
        "model_id",
        "model_version",
        "dataset_id",
        "split_name",
        "evaluation_type",
        "model_track",
        "label",
        "precision",
        "recall",
        "f1",
        "support",
        "measured_at_utc",
    ],
    "confusion_matrix.csv": [
        "run_id",
        "model_id",
        "model_version",
        "dataset_id",
        "split_name",
        "evaluation_type",
        "model_track",
        "confusion_matrix_json",
        "measured_at_utc",
    ],
    "cross_dataset_robustness.csv": [
        "run_id",
        "model_id",
        "model_version",
        "dataset_id",
        "evaluation_type",
        "model_track",
        "precision",
        "recall",
        "f1",
        "macro_f1",
        "micro_f1",
        "weighted_f1",
        "accuracy",
        "fpr",
        "far",
        "fnr",
        "measured_at_utc",
    ],
    "shap_explanations.csv": [
        "shap_log_id",
        "model_version",
        "replay_id",
        "alert_id",
        "shap_stage",
        "status",
        "evidence_status",
        "top_features_json",
        "created_at",
    ],
    "replay_phase_results.csv": [
        "replay_run_id",
        "replay_id",
        "phase_name",
        "phase_order",
        "packets_sent",
        "packets_dropped",
        "alerts_generated",
        "escalations_generated",
        "parent_decisions",
        "shap_coverage",
        "latency_ms",
        "throughput_eps",
        "status",
    ],
    "operational_metrics.csv": [
        "run_id",
        "model_id",
        "model_version",
        "replay_run_id",
        "metric_name",
        "metric_value",
        "metric_unit",
        "metric_source",
        "measured_at_utc",
    ],
    "governance_traceability.csv": [
        "run_id",
        "model_id",
        "model_version",
        "source_step1_run_id",
        "source_step2_run_id",
        "replay_run_id",
        "replay_id",
        "rulepack_version",
        "pcap_artifact_id",
        "alert_id",
        "shap_log_id",
        "feedback_id",
        "checksum_ref",
        "freeze_status",
    ],
    "within_dataset_results.csv": ["model", "dataset", "precision", "recall", "f1", "macro_f1", "fpr", "fnr", "interpretation"],
    "cross_dataset_results.csv": [
        "train_source",
        "test_source",
        "domain",
        "precision",
        "recall",
        "f1",
        "macro_f1",
        "fpr_change",
        "fnr_change",
        "interpretation",
    ],
    "categorization_results.csv": ["metric", "value", "evidence_source", "interpretation"],
    "cross_scope_results.csv": [
        "child_scope",
        "observed_vector_class",
        "expected_scope",
        "scope_match",
        "escalated",
        "parent_outcome",
        "correct",
    ],
    "shap_results.csv": ["shap_stage", "input", "output", "metric", "value", "interpretation"],
    "rule_validation_results.csv": [
        "rule_layer",
        "evidence_source",
        "example_rule_logic",
        "trigger_count",
        "valid_trigger_count",
        "precision",
        "action",
    ],
    "replay_results.csv": [
        "replay_phase",
        "input_source",
        "alert_count",
        "cross_scope_count",
        "parent_review_completion",
        "explanation_coverage",
        "key_observation",
    ],
    "governance_results.csv": ["governance_metric", "evidence_source", "value", "interpretation"],
    "h1_workflow_results.csv": [
        "experiment_id",
        "model_version",
        "dataset",
        "alert_count",
        "filtered_alerts",
        "parent_review_completion",
        "triage_proxy",
        "interpretation",
    ],
    "h2_categorization_results.csv": [
        "experiment_id",
        "model_version",
        "dataset",
        "domain_accuracy",
        "protocol_coverage",
        "vector_coverage",
        "scope_match_accuracy",
        "interpretation",
    ],
    "h3_cross_scope_results.csv": [
        "experiment_id",
        "model_version",
        "child_scope",
        "observed_behavior",
        "expected_scope",
        "cross_scope_detected",
        "escalation_correct",
        "severity_level",
        "interpretation",
    ],
    "h4_shap_results.csv": [
        "experiment_id",
        "model_version",
        "explanation_coverage",
        "top_features_consistency",
        "explanation_clarity",
        "triage_support_score",
        "interpretation",
    ],
    "h5_governance_results.csv": [
        "experiment_id",
        "model_version",
        "metric",
        "evidence_source",
        "status",
        "completeness_pct",
        "interpretation",
    ],
}

EVAL_DOMAIN = {
    "ent01_holdout": "enterprise",
    "dns01": "dns",
    "iot01": "iot",
    "ent02_support": "enterprise",
    "iot02_support": "iiot",
}
EVAL_TEST_SOURCE = {
    "ent01_holdout": "ENT-01",
    "dns01": "DNS-01",
    "iot01": "IOT-01",
    "ent02_support": "ENT-02",
    "iot02_support": "IOT-02",
}


@dataclass
class DissertationBundle:
    resolved_model_version: str
    resolved_model_id: str
    source_step1_run_id: str
    source_step2_run_id: str
    replay_status: str
    experiment_id: str
    step2_run_id: str
    replay_run_id: str
    step3_v2_sim_id: str
    replay_metrics: dict[str, Any]
    csv_rows: dict[str, list[dict[str, Any]]]
    lineage_resolution: dict[str, Any]
    metrics_required_catalog: list[dict[str, Any]]
    metrics_required_matrix: list[dict[str, Any]]
    metrics_required_summary: dict[str, int]


HYPOTHESIS_TABLE_COLUMNS: dict[str, list[str]] = {
    "h1_1": [
        "model_version",
        "dataset",
        "alert_count",
        "filtered_alerts",
        "parent_review_completion",
        "triage_proxy",
        "interpretation",
    ],
    "h1_2": [
        "dataset",
        "domain_accuracy",
        "protocol_coverage",
        "vector_coverage",
        "scope_match_accuracy",
        "interpretation",
    ],
    "h1_3": [
        "child_scope",
        "observed_behavior",
        "expected_scope",
        "cross_scope_detected",
        "escalation_correct",
        "severity_level",
        "interpretation",
    ],
    "h1_4": [
        "model_version",
        "explanation_coverage",
        "top_features_consistency",
        "explanation_clarity",
        "triage_support_score",
        "interpretation",
    ],
    "h1_5": [
        "metric",
        "evidence_source",
        "status",
        "completeness_pct",
        "interpretation",
    ],
}

METRICS_REQUIRED_MATRIX_FIELDS = [
    "metric_name",
    "value",
    "unit",
    "status",
    "source_kind",
    "source_ref",
    "lineage_step1_run_id",
    "lineage_step2_run_id",
    "lineage_model_id",
    "lineage_model_version",
    "lineage_sim_id",
    "measured_at_utc",
]
METRICS_REQUIRED_STATUS_VALUES = {"measured", "not_collected", "not_applicable"}
METRICS_REQUIRED_DOC_RELATIVE = Path("docs/final_dissertation_docs/metrics_required.md")
METRICS_PRINCIPLE_REVIEW_DOC_RELATIVE = Path("docs/final_dissertation_docs/metrics_principle_review.md")
STEP1_PRINCIPLE_SECTION_LABEL = "STEP 1 / Ingestion, Validation, Governance, Categorization"
STEP1_METRIC_UNIT_OVERRIDES: dict[str, str] = {
    "schema_validation_success_rate": "ratio",
    "split_integrity_rate": "ratio",
    "canonical_mapping_completeness": "ratio",
    "audit_completeness": "ratio",
    "model_version_traceability": "ratio",
    "domain_classification_accuracy": "ratio",
    "lineage_hash_consistency": "ratio",
    "dataset_lineage_coverage": "ratio",
    "scope_assignment_confidence": "ratio",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _chapter4_dirs() -> list[Path]:
    root = _repo_root()
    return [
        root / "docs" / "results" / "chapter4",
        root / "data" / "outputs" / "phase4" / "metrics" / "chapter4",
    ]


def _parse_json_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _fmt_num(value: Any, places: int = 6) -> str:
    if value is None or value == "":
        return ""
    try:
        n = float(value)
    except Exception:
        return str(value)
    if abs(n - int(n)) < 1e-12:
        return str(int(n))
    return f"{n:.{places}f}".rstrip("0").rstrip(".")


def _fmt_pct(num: Any, den: Any) -> str:
    try:
        n = float(num or 0)
        d = float(den or 0)
    except Exception:
        return ""
    if d <= 0:
        return ""
    return _fmt_num(n / d, places=6)


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except Exception:
        return 0


def _child_scope_from_child_id(child_id: str | None) -> str:
    cid = str(child_id or "").strip().lower()
    if "enterprise" in cid:
        return "enterprise"
    if "dns" in cid:
        return "dns"
    if "iiot" in cid:
        return "iiot"
    if "iot" in cid:
        return "iot"
    return "unknown"


def _write_csv(path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, "") for k in fields})


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sanitize_slug(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", str(value or "").strip())
    return cleaned.strip("_") or "latest"


def _is_uuid_like(value: str | None) -> bool:
    v = str(value or "").strip()
    return bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", v))


def _to_utc_iso(value: Any) -> str:
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            return ""
    return ""


def _nested_get(payload: Any, path: list[str]) -> Any:
    cur = payload
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _non_empty_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() != ""
    return True


def _display_to_unit(display_format: str, store_format: str) -> str:
    disp = str(display_format or "").strip().lower()
    store = str(store_format or "").strip().lower()
    if "percent" in disp:
        return "ratio"
    if "millisecond" in disp:
        return "ms"
    if "second" in disp:
        return "seconds"
    if "integer" in disp or "bigint" in store:
        return "count"
    if "decimal" in disp:
        return "ratio"
    return ""


def _metrics_required_doc_path() -> Path:
    return _repo_root() / METRICS_REQUIRED_DOC_RELATIVE


def _metrics_principle_review_doc_path() -> Path:
    return _repo_root() / METRICS_PRINCIPLE_REVIEW_DOC_RELATIVE


def _is_principle_certainty_yes(raw_value: str) -> bool:
    norm = str(raw_value or "").strip().lower()
    if norm == "yes":
        return True
    if norm.startswith("yes (derived"):
        return True
    if norm.startswith("yes (with correct query basis"):
        return True
    return False


def _load_principle_certainty_eligible_metrics() -> set[str]:
    path = _metrics_principle_review_doc_path()
    if not path.is_file():
        return set()

    eligible: set[str] = set()
    metric_idx = -1
    gen_idx = -1

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not (line.startswith("|") and line.endswith("|")):
            continue
        parts = [p.strip() for p in line.strip("|").split("|")]
        if not parts:
            continue
        if parts[0].lower() == "metric" and "can generate from existing data?" in [p.lower() for p in parts]:
            metric_idx = 0
            gen_idx = [p.lower() for p in parts].index("can generate from existing data?")
            continue
        if metric_idx < 0 or gen_idx < 0:
            continue
        if len(parts) <= max(metric_idx, gen_idx):
            continue
        metric_name = str(parts[metric_idx] or "").strip()
        can_generate = str(parts[gen_idx] or "").strip()
        if not re.fullmatch(r"[a-z][a-z0-9_]*", metric_name):
            continue
        if is_deprecated_metric("step1", metric_name):
            continue
        if _is_principle_certainty_yes(can_generate):
            eligible.add(metric_name)
    return eligible


def _parse_md_table_cells(line: str) -> list[str]:
    return [p.strip() for p in str(line or "").strip().strip("|").split("|")]


def _is_md_separator_row(cells: list[str]) -> bool:
    if not cells:
        return False
    for cell in cells:
        stripped = str(cell or "").strip()
        if not stripped:
            continue
        if not re.fullmatch(r"[:\- ]+", stripped):
            return False
    return True


def _infer_metric_unit_from_principle(metric_name: str, expectation: str) -> str:
    override = STEP1_METRIC_UNIT_OVERRIDES.get(str(metric_name or "").strip())
    if override:
        return override
    expr = str(expectation or "").strip().lower()
    if "millisecond" in expr:
        return "ms"
    if "second" in expr or "duration" in expr:
        return "seconds"
    if "/" in expr or "ratio" in expr or "average" in expr or "avg" in expr:
        return "ratio"
    return ""


def _load_step1_metric_rows_from_principle_review() -> list[dict[str, Any]]:
    path = _metrics_principle_review_doc_path()
    if not path.is_file():
        return []

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    in_step1 = False
    in_table = False
    metric_idx = -1
    expectation_idx = -1
    assoc_idx = -1

    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = str(raw or "").strip()
        if not stripped:
            continue
        if stripped.lower().startswith("## step "):
            in_step1 = stripped.lower().startswith("## step 1")
            in_table = False
            continue
        if not in_step1:
            continue
        if not (stripped.startswith("|") and stripped.endswith("|")):
            continue

        cells = _parse_md_table_cells(stripped)
        cells_l = [c.lower() for c in cells]
        if cells_l and cells_l[0] == "metric" and "principle expectation" in cells_l:
            metric_idx = cells_l.index("metric")
            expectation_idx = cells_l.index("principle expectation")
            assoc_idx = (
                cells_l.index("associated tables (if generatable)")
                if "associated tables (if generatable)" in cells_l
                else -1
            )
            in_table = True
            continue
        if not in_table or _is_md_separator_row(cells):
            continue
        if metric_idx < 0 or len(cells) <= metric_idx:
            continue

        metric_name = str(cells[metric_idx] or "").strip()
        if not re.fullmatch(r"[a-z][a-z0-9_]*", metric_name):
            continue
        if is_deprecated_metric("step1", metric_name):
            continue
        if metric_name in seen:
            continue
        seen.add(metric_name)

        expectation = str(cells[expectation_idx] if expectation_idx >= 0 and len(cells) > expectation_idx else "").strip()
        associated_tables = str(cells[assoc_idx] if assoc_idx >= 0 and len(cells) > assoc_idx else "").strip()
        source_kind = "postgres_relational"
        assoc_l = associated_tables.lower()
        if "workflow_runs" in assoc_l and "dataset_splits" not in assoc_l:
            source_kind = "postgres_json"
        rows.append(
            {
                "metric_name": metric_name,
                "group": STEP1_PRINCIPLE_SECTION_LABEL,
                "source_kind": source_kind,
                "source_table_or_file": associated_tables or "phase4.metrics",
                "source_field": metric_name,
                "unit": _infer_metric_unit_from_principle(metric_name, expectation),
                "status_rule": "measured_if_value_present_else_not_collected",
                "is_required_metric": True,
            }
        )
    return rows


def _load_step1_metric_results_evidence(
    cur: Any,
    *,
    step1_run_id: str,
    step1_metrics: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    rid = str(step1_run_id or "").strip()

    if _is_uuid_like(rid):
        cur.execute(
            """
            SELECT metric, metric_value, calculation_status, details_json, updatedat
            FROM phase4.metrics
            WHERE step = 'step1'
              AND step_unique_id = %(rid)s
            ORDER BY updatedat DESC, createdat DESC;
            """,
            {"rid": rid},
        )
        for metric_name, metric_value, status, details_json, measured_at_utc in cur.fetchall() or []:
            mname = str(metric_name or "").strip()
            if not re.fullmatch(r"[a-z][a-z0-9_]*", mname):
                continue
            if is_deprecated_metric("step1", mname):
                continue
            if mname in out:
                continue
            details = _parse_json_dict(details_json)
            out[mname] = {
                "metric_name": mname,
                "value": metric_value,
                "status": str(status or "").strip().lower(),
                "source_ref": str(details.get("source_ref") or details.get("source") or "phase4.metrics"),
                "measured_at_utc": _to_utc_iso(measured_at_utc),
            }

    return out


def _derive_split_integrity_rate(step1_metrics: dict[str, Any]) -> float | None:
    reconciliation = _parse_json_dict(step1_metrics.get("reconciliation"))
    datasets = reconciliation.get("datasets")
    if not isinstance(datasets, dict) or not datasets:
        return None
    total = 0
    valid = 0
    for row in datasets.values():
        if not isinstance(row, dict):
            continue
        total += 1
        if bool(row.get("ok")):
            valid += 1
    if total <= 0:
        return None
    return float(valid) / float(total)


def _derive_cross_dataset_robustness(step2_metrics: dict[str, Any], track: str) -> float | None:
    within = _parse_json_dict(step2_metrics.get("within_dataset_results"))
    cross = _parse_json_dict(step2_metrics.get("cross_dataset_results"))
    table_41 = _parse_json_dict(within.get("table_4_1_rows"))
    internal = _nested_get(table_41, [track, "f1"])
    try:
        internal_f1 = float(internal)
    except Exception:
        return None
    if internal_f1 <= 0:
        return None

    external_values: list[float] = []
    for target, payload in cross.items():
        if str(target or "").strip() == "ent01_holdout":
            continue
        rows = _parse_json_dict(payload).get("table_4_2_rows")
        track_row = _parse_json_dict(rows).get(track) if isinstance(rows, dict) else None
        try:
            f1 = float((_parse_json_dict(track_row)).get("f1"))
        except Exception:
            continue
        external_values.append(f1)
    if not external_values:
        return None
    external_mean = sum(external_values) / float(len(external_values))
    return external_mean / internal_f1


def _derive_rule_hit_rate(step2_metrics: dict[str, Any]) -> float | None:
    summary = _parse_json_dict(step2_metrics.get("rule_validation_summary"))
    rep01 = _parse_json_dict(summary.get("rep01_packet_validation"))
    sampled = _safe_int(rep01.get("sampled_packets"))
    if sampled <= 0:
        return None
    packets_with_hits = rep01.get("packets_with_detections")
    detections_total = rep01.get("detections_total")
    if _non_empty_value(packets_with_hits):
        return float(_safe_int(packets_with_hits)) / float(sampled)
    if _non_empty_value(detections_total):
        return float(_safe_int(detections_total)) / float(sampled)
    return None


def _audit_event_present(cur: Any, *, event_type: str, run_id: str = "", replay_id: str = "", simulation_id: str = "") -> bool:
    cur.execute(
        """
        SELECT 1
        FROM phase4.audit_log
        WHERE event_type = %(event_type)s
          AND (
            (%(run_id)s <> '' AND COALESCE(event_details_json->'context'->>'run_id', '') = %(run_id)s)
            OR (%(replay_id)s <> '' AND (COALESCE(replay_id::text, '') = %(replay_id)s OR COALESCE(event_details_json->'context'->>'replay_run_id', '') = %(replay_id)s))
            OR (%(simulation_id)s <> '' AND (COALESCE(replay_id::text, '') = %(simulation_id)s OR COALESCE(event_details_json->'context'->>'simulation_id', '') = %(simulation_id)s))
          )
        LIMIT 1;
        """,
        {
            "event_type": str(event_type or ""),
            "run_id": str(run_id or ""),
            "replay_id": str(replay_id or ""),
            "simulation_id": str(simulation_id or ""),
        },
    )
    return bool(cur.fetchone())


def _derive_audit_completeness(
    cur: Any,
    *,
    step1_run_id: str,
    step2_run_id: str,
    replay_run_id: str,
    step3_v2_sim_id: str,
) -> float | None:
    s1 = str(step1_run_id or "").strip()
    s2 = str(step2_run_id or "").strip()
    rid = str(replay_run_id or "").strip()
    sid = str(step3_v2_sim_id or "").strip()

    if sid and _is_uuid_like(sid):
        if not (_is_uuid_like(s1) and _is_uuid_like(s2)):
            return None
        checks = [
            _audit_event_present(cur, event_type="model_v1_step1_completed", run_id=s1),
            _audit_event_present(cur, event_type="model_v1_step2_completed", run_id=s2),
            _audit_event_present(cur, event_type="step3_v2_simulation_started", simulation_id=sid),
            _audit_event_present(cur, event_type="step3_v2_simulation_stopped", simulation_id=sid),
        ]
    elif rid and _is_uuid_like(rid):
        if not (_is_uuid_like(s1) and _is_uuid_like(s2)):
            return None
        checks = [
            _audit_event_present(cur, event_type="model_v1_step1_completed", run_id=s1),
            _audit_event_present(cur, event_type="model_v1_step2_completed", run_id=s2),
            _audit_event_present(cur, event_type="replay_started", replay_id=rid),
            _audit_event_present(cur, event_type="replay_completed", replay_id=rid),
        ]
    else:
        return None
    return float(sum(1 for x in checks if x)) / float(len(checks))


def _derive_model_version_traceability(
    cur: Any,
    *,
    model_id: str,
    step1_run_id: str,
    step2_run_id: str,
    replay_run_id: str,
    step3_v2_sim_id: str,
) -> float | None:
    mid = str(model_id or "").strip()
    s1 = str(step1_run_id or "").strip()
    s2 = str(step2_run_id or "").strip()
    rid = str(replay_run_id or "").strip()
    sid = str(step3_v2_sim_id or "").strip()
    if not (_is_uuid_like(mid) and _is_uuid_like(s1) and _is_uuid_like(s2)):
        return None
    if not (_is_uuid_like(rid) or _is_uuid_like(sid)):
        return None

    present = 0
    cur.execute(
        """
        SELECT 1 FROM phase4.model_registry
        WHERE model_id = %(mid)s::uuid
        LIMIT 1;
        """,
        {"mid": mid},
    )
    present += 1 if cur.fetchone() else 0

    cur.execute(
        """
        SELECT 1 FROM phase4.workflow_runs
        WHERE step_name='step1' AND run_id = %(rid)s::uuid
        LIMIT 1;
        """,
        {"rid": s1},
    )
    present += 1 if cur.fetchone() else 0

    cur.execute(
        """
        SELECT 1 FROM phase4.workflow_runs
        WHERE step_name='step2' AND run_id = %(rid)s::uuid
        LIMIT 1;
        """,
        {"rid": s2},
    )
    present += 1 if cur.fetchone() else 0

    if _is_uuid_like(rid):
        cur.execute(
            """
            SELECT 1 FROM phase4.replay_runs
            WHERE replay_run_id = %(rid)s::uuid
            LIMIT 1;
            """,
            {"rid": rid},
        )
    else:
        cur.execute(
            """
            SELECT 1 FROM phase4.step3_v2_simulations
            WHERE simulation_id = %(sid)s::uuid
            LIMIT 1;
            """,
            {"sid": sid},
        )
    present += 1 if cur.fetchone() else 0
    return float(present) / 4.0


def _derive_alert_level_explanation_coverage(cur: Any, *, replay_run_id: str) -> float | None:
    rid = str(replay_run_id or "").strip()
    if not _is_uuid_like(rid):
        return None
    cur.execute(
        """
        SELECT
            COUNT(*)::bigint,
            COUNT(*) FILTER (
                WHERE COALESCE(shap_evidence_status, '') = 'measured'
                   OR shap_evidence_id IS NOT NULL
            )::bigint
        FROM phase4.step3_alerts
        WHERE replay_run_id = %(rid)s::uuid;
        """,
        {"rid": rid},
    )
    total, explained = cur.fetchone() or (0, 0)
    total_i = _safe_int(total)
    if total_i <= 0:
        return None
    return float(_safe_int(explained)) / float(total_i)


def _derive_child_escalation_rate(
    cur: Any,
    *,
    replay_run_id: str,
    step3_v2_sim_id: str,
    step3_metrics: dict[str, Any],
) -> float | None:
    alerts_total = _safe_int(step3_metrics.get("alerts_total"))
    escalations_total = _safe_int(step3_metrics.get("escalations_total"))
    if alerts_total > 0:
        return float(escalations_total) / float(alerts_total)

    rid = str(replay_run_id or "").strip()
    sid = str(step3_v2_sim_id or "").strip()
    if _is_uuid_like(rid):
        cur.execute(
            """
            SELECT
                COUNT(*)::bigint,
                (SELECT COUNT(*)::bigint FROM phase4.parent_actions WHERE replay_run_id = %(rid)s::uuid)
            FROM phase4.step3_alerts
            WHERE replay_run_id = %(rid)s::uuid;
            """,
            {"rid": rid},
        )
        alerts_total, escalations_total = cur.fetchone() or (0, 0)
        alerts_i = _safe_int(alerts_total)
        if alerts_i <= 0:
            return None
        return float(_safe_int(escalations_total)) / float(alerts_i)
    if _is_uuid_like(sid):
        cur.execute(
            """
            SELECT
                COALESCE(SUM(alert_count), 0)::bigint,
                (SELECT COALESCE(SUM(action_count), 0)::bigint FROM phase4.step3_v2_parent_actions WHERE simulation_id = %(sid)s::uuid)
            FROM phase4.step3_v2_alerts
            WHERE simulation_id = %(sid)s::uuid;
            """,
            {"sid": sid},
        )
        alerts_total, escalations_total = cur.fetchone() or (0, 0)
        alerts_i = _safe_int(alerts_total)
        if alerts_i <= 0:
            return None
        return float(_safe_int(escalations_total)) / float(alerts_i)
    return None


def _derive_enrichment_completeness(cur: Any, *, replay_run_id: str) -> float | None:
    rid = str(replay_run_id or "").strip()
    if not _is_uuid_like(rid):
        return None
    cur.execute(
        """
        SELECT
            COUNT(*)::bigint,
            COUNT(*) FILTER (
                WHERE COALESCE(expected_environment, '') <> ''
                  AND COALESCE(observed_environment, '') <> ''
                  AND COALESCE(escalation_reason, '') <> ''
                  AND payload IS NOT NULL
                  AND payload::text <> '{}'::text
            )::bigint
        FROM phase4.step3_alerts
        WHERE replay_run_id = %(rid)s::uuid;
        """,
        {"rid": rid},
    )
    total, enriched = cur.fetchone() or (0, 0)
    total_i = _safe_int(total)
    if total_i <= 0:
        return None
    return float(_safe_int(enriched)) / float(total_i)


def _derive_recommendation_rate(
    cur: Any,
    *,
    replay_run_id: str,
    step3_v2_sim_id: str,
    step3_metrics: dict[str, Any],
) -> float | None:
    rid = str(replay_run_id or "").strip()
    sid = str(step3_v2_sim_id or "").strip()
    escalations_total = _safe_int(step3_metrics.get("escalations_total"))

    if _is_uuid_like(rid):
        cur.execute(
            """
            SELECT COUNT(*)::bigint
            FROM phase4.parent_actions
            WHERE replay_run_id = %(rid)s::uuid
              AND COALESCE(LOWER(action_type), '') = 'recommendation';
            """,
            {"rid": rid},
        )
        rec_count = _safe_int((cur.fetchone() or [0])[0])
        if escalations_total <= 0:
            cur.execute(
                """
                SELECT COUNT(*)::bigint
                FROM phase4.parent_actions
                WHERE replay_run_id = %(rid)s::uuid;
                """,
                {"rid": rid},
            )
            escalations_total = _safe_int((cur.fetchone() or [0])[0])
        if escalations_total <= 0:
            return None
        return float(rec_count) / float(escalations_total)

    if _is_uuid_like(sid):
        cur.execute(
            """
            SELECT COALESCE(SUM(action_count), 0)::bigint
            FROM phase4.step3_v2_parent_actions
            WHERE simulation_id = %(sid)s::uuid
              AND COALESCE(LOWER(action), '') = 'recommendation';
            """,
            {"sid": sid},
        )
        rec_count = _safe_int((cur.fetchone() or [0])[0])
        if escalations_total <= 0:
            cur.execute(
                """
                SELECT COALESCE(SUM(action_count), 0)::bigint
                FROM phase4.step3_v2_parent_actions
                WHERE simulation_id = %(sid)s::uuid;
                """,
                {"sid": sid},
            )
            escalations_total = _safe_int((cur.fetchone() or [0])[0])
        if escalations_total <= 0:
            return None
        return float(rec_count) / float(escalations_total)
    return None


def _load_metrics_required_catalog() -> list[dict[str, Any]]:
    # Step 4 dashboard/extraction authority is metrics_principle_review.md Step 1 rows only.
    return _load_step1_metric_rows_from_principle_review()


def _query_latest_step2(cur: Any, model_version: str | None) -> dict[str, Any]:
    if model_version:
        cur.execute(
            """
            SELECT run_id::text, workflow_id, status, run_metrics, started_at_utc, completed_at_utc
            FROM phase4.workflow_runs
            WHERE step_name='step2' AND (run_metrics->>'model_version') = %(mv)s
            ORDER BY COALESCE(completed_at_utc, started_at_utc) DESC, run_id DESC
            LIMIT 1;
            """,
            {"mv": str(model_version)},
        )
    else:
        cur.execute(
            """
            SELECT run_id::text, workflow_id, status, run_metrics, started_at_utc, completed_at_utc
            FROM phase4.workflow_runs
            WHERE step_name='step2'
            ORDER BY COALESCE(completed_at_utc, started_at_utc) DESC, run_id DESC
            LIMIT 1;
            """
        )
    row = cur.fetchone()
    if not row:
        return {}
    metrics = _parse_json_dict(row[3])
    return {
        "run_id": str(row[0] or ""),
        "workflow_id": str(row[1] or ""),
        "status": str(row[2] or ""),
        "metrics": metrics,
    }


def _query_latest_step3(cur: Any, model_version: str | None) -> dict[str, Any]:
    if model_version:
        cur.execute(
            """
            SELECT rm.replay_run_id::text, COALESCE(rm.model_version, rr.model_version), rm.metrics,
                   rr.status, rr.replay_profile, rr.metadata
            FROM phase4.step3_replay_metrics rm
            INNER JOIN phase4.replay_runs rr ON rr.replay_run_id = rm.replay_run_id
            WHERE COALESCE(rm.model_version, rr.model_version) = %(mv)s
            ORDER BY COALESCE(rm.updated_at_utc, rm.created_at_utc) DESC
            LIMIT 1;
            """,
            {"mv": str(model_version)},
        )
    else:
        cur.execute(
            """
            SELECT rm.replay_run_id::text, COALESCE(rm.model_version, rr.model_version), rm.metrics,
                   rr.status, rr.replay_profile, rr.metadata
            FROM phase4.step3_replay_metrics rm
            INNER JOIN phase4.replay_runs rr ON rr.replay_run_id = rm.replay_run_id
            ORDER BY COALESCE(rm.updated_at_utc, rm.created_at_utc) DESC
            LIMIT 1;
            """
        )
    row = cur.fetchone()
    if not row:
        return {}
    metrics = _parse_json_dict(row[2])
    meta = _parse_json_dict(row[5])
    replay_run_id = str(row[0] or "")
    timeline = {"runtime_shap_events": 0, "user_alert_events": 0, "parent_review_events": 0}
    if replay_run_id:
        cur.execute(
            """
            SELECT
              COALESCE(
                SUM(
                  CASE
                    WHEN COALESCE(stage, '') ILIKE '%%shap%%'
                      OR COALESCE(payload::text, '') ILIKE '%%runtime_shap%%'
                    THEN 1 ELSE 0
                  END
                ),
                0
              )::bigint,
              COALESCE(
                SUM(
                  CASE
                    WHEN COALESCE(stage, '') ILIKE '%%alert%%'
                      OR COALESCE(payload::text, '') ILIKE '%%alert%%'
                    THEN 1 ELSE 0
                  END
                ),
                0
              )::bigint,
              COALESCE(
                SUM(
                  CASE
                    WHEN COALESCE(stage, '') ILIKE '%%review%%'
                      OR COALESCE(payload::text, '') ILIKE '%%parent_review%%'
                    THEN 1 ELSE 0
                  END
                ),
                0
              )::bigint
            FROM phase4.step3_timeline_events
            WHERE replay_run_id = %(rid)s::uuid;
            """,
            {"rid": replay_run_id},
        )
        t = cur.fetchone() or (0, 0, 0)
        timeline = {
            "runtime_shap_events": int(t[0] or 0),
            "user_alert_events": int(t[1] or 0),
            "parent_review_events": int(t[2] or 0),
        }
    return {
        "replay_run_id": replay_run_id,
        "model_version": str(row[1] or ""),
        "status": str(row[3] or ""),
        "replay_profile": str(row[4] or "default"),
        "metrics": metrics,
        "metadata": meta,
        "timeline": timeline,
    }


def _query_step2_by_run_id(cur: Any, run_id: str) -> dict[str, Any]:
    rid = str(run_id or "").strip()
    if not _is_uuid_like(rid):
        return {}
    cur.execute(
        """
        SELECT run_id::text, workflow_id, status, run_metrics
        FROM phase4.workflow_runs
        WHERE step_name='step2' AND run_id = %(rid)s::uuid
        LIMIT 1;
        """,
        {"rid": rid},
    )
    row = cur.fetchone()
    if not row:
        return {}
    return {
        "run_id": str(row[0] or ""),
        "workflow_id": str(row[1] or ""),
        "status": str(row[2] or ""),
        "metrics": _parse_json_dict(row[3]),
    }


def _query_step1_by_run_id(cur: Any, run_id: str) -> dict[str, Any]:
    rid = str(run_id or "").strip()
    if not _is_uuid_like(rid):
        return {}
    cur.execute(
        """
        SELECT run_id::text, workflow_id, status, run_metrics, started_at_utc, completed_at_utc
        FROM phase4.workflow_runs
        WHERE step_name='step1' AND run_id = %(rid)s::uuid
        LIMIT 1;
        """,
        {"rid": rid},
    )
    row = cur.fetchone()
    if not row:
        return {}
    return {
        "run_id": str(row[0] or ""),
        "workflow_id": str(row[1] or ""),
        "status": str(row[2] or ""),
        "metrics": _parse_json_dict(row[3]),
        "started_at_utc": _to_utc_iso(row[4]),
        "completed_at_utc": _to_utc_iso(row[5]),
    }


def _query_step2_by_lineage(
    cur: Any,
    *,
    model_id: str,
    model_version: str | None = None,
    source_step1_run_id: str | None = None,
) -> dict[str, Any]:
    mid = str(model_id or "").strip()
    mv = str(model_version or "").strip()
    s1 = str(source_step1_run_id or "").strip()
    if not _is_uuid_like(mid) or not mv or not _is_uuid_like(s1):
        return {}
    params: dict[str, Any] = {"mid": mid, "mv": mv, "s1": s1}

    cur.execute(
        """
        WITH strict_lineage_step2_runs AS (
            SELECT run_id
            FROM phase4.model_training_runs
            WHERE run_id IS NOT NULL
              AND model_id = %(mid)s
              AND model_version = %(mv)s
              AND source_step1_run_id = %(s1)s
            UNION
            SELECT run_id
            FROM phase4.model_evaluation_runs
            WHERE run_id IS NOT NULL
              AND model_id = %(mid)s
              AND model_version = %(mv)s
              AND source_step1_run_id = %(s1)s
            UNION
            SELECT run_id
            FROM phase4.cross_dataset_test_runs
            WHERE run_id IS NOT NULL
              AND model_id = %(mid)s
              AND model_version = %(mv)s
              AND source_step1_run_id = %(s1)s
        )
        SELECT run_id::text, workflow_id, status, run_metrics
        FROM phase4.workflow_runs
        WHERE step_name='step2'
          AND run_id IN (SELECT run_id FROM strict_lineage_step2_runs)
        ORDER BY completed_at_utc DESC NULLS LAST, run_id DESC
        LIMIT 1;
        """,
        params,
    )
    row = cur.fetchone()
    if not row:
        return {}
    return {
        "run_id": str(row[0] or ""),
        "workflow_id": str(row[1] or ""),
        "status": str(row[2] or ""),
        "metrics": _parse_json_dict(row[3]),
    }


def _query_latest_step2_for_model_id(
    cur: Any,
    model_id: str,
    *,
    model_version: str | None = None,
    source_step1_run_id: str | None = None,
) -> dict[str, Any]:
    mid = str(model_id or "").strip()
    if not _is_uuid_like(mid):
        return {}
    params: dict[str, Any] = {"mid": mid}
    where = ["step_name='step2'", "(run_metrics->>'model_id') = %(mid)s"]
    if model_version:
        params["mv"] = str(model_version).strip()
        where.append("(run_metrics->>'model_version') = %(mv)s")
    source_step1_valid = bool(source_step1_run_id and _is_uuid_like(source_step1_run_id))
    row = None
    if source_step1_valid:
        params_s1 = dict(params)
        params_s1["s1"] = str(source_step1_run_id).strip()
        where_s1 = list(where) + ["(run_metrics->>'source_step1_run_id') = %(s1)s"]
        cur.execute(
            f"""
            SELECT run_id::text, workflow_id, status, run_metrics
            FROM phase4.workflow_runs
            WHERE {' AND '.join(where_s1)}
            ORDER BY COALESCE(completed_at_utc, started_at_utc) DESC, run_id DESC
            LIMIT 1;
            """,
            params_s1,
        )
        row = cur.fetchone()
    if not row:
        cur.execute(
            f"""
            SELECT run_id::text, workflow_id, status, run_metrics
            FROM phase4.workflow_runs
            WHERE {' AND '.join(where)}
            ORDER BY COALESCE(completed_at_utc, started_at_utc) DESC, run_id DESC
            LIMIT 1;
            """,
            params,
        )
        row = cur.fetchone()
    if not row and model_version:
        # Legacy compatibility: some historical Step2 runs stored model_id as model_version.
        where_legacy = ["step_name='step2'", "(run_metrics->>'model_version') = %(mv)s"]
        params_legacy: dict[str, Any] = {"mv": str(model_version).strip()}
        if source_step1_run_id and _is_uuid_like(source_step1_run_id):
            params_legacy_s1 = dict(params_legacy)
            params_legacy_s1["s1"] = str(source_step1_run_id).strip()
            where_legacy_s1 = list(where_legacy) + ["(run_metrics->>'source_step1_run_id') = %(s1)s"]
            cur.execute(
                f"""
                SELECT run_id::text, workflow_id, status, run_metrics
                FROM phase4.workflow_runs
                WHERE {' AND '.join(where_legacy_s1)}
                ORDER BY COALESCE(completed_at_utc, started_at_utc) DESC, run_id DESC
                LIMIT 1;
                """,
                params_legacy_s1,
            )
            row = cur.fetchone()
        if not row:
            cur.execute(
                f"""
                SELECT run_id::text, workflow_id, status, run_metrics
                FROM phase4.workflow_runs
                WHERE {' AND '.join(where_legacy)}
                ORDER BY COALESCE(completed_at_utc, started_at_utc) DESC, run_id DESC
                LIMIT 1;
                """,
                params_legacy,
            )
            row = cur.fetchone()
    if not row:
        return {}
    return {
        "run_id": str(row[0] or ""),
        "workflow_id": str(row[1] or ""),
        "status": str(row[2] or ""),
        "metrics": _parse_json_dict(row[3]),
    }


def _query_model_registry_by_model_id(cur: Any, model_id: str) -> dict[str, Any]:
    mid = str(model_id or "").strip()
    if not _is_uuid_like(mid):
        return {}
    cur.execute(
        """
        SELECT model_id::text, model_version, source_step1_run_id
        FROM phase4.model_registry
        WHERE model_id = %(mid)s::uuid
        ORDER BY created_at DESC
        LIMIT 1;
        """,
        {"mid": mid},
    )
    row = cur.fetchone()
    if not row:
        return {}
    return {
        "model_id": str(row[0] or ""),
        "model_version": str(row[1] or ""),
        "source_step1_run_id": str(row[2] or ""),
    }


def _query_step3_v2_by_sim_id(cur: Any, simulation_id: str) -> dict[str, Any]:
    sid = str(simulation_id or "").strip()
    if not _is_uuid_like(sid):
        return {}
    cur.execute(
        """
        SELECT simulation_id::text, model_id::text, model_version, status, metadata
        FROM phase4.step3_v2_simulations
        WHERE simulation_id = %(sid)s::uuid
        LIMIT 1;
        """,
        {"sid": sid},
    )
    row = cur.fetchone()
    if not row:
        return {}
    metadata = _parse_json_dict(row[4])
    file_states = (
        metadata.get("file_dispatch_state", {}).get("file_states")
        if isinstance(metadata.get("file_dispatch_state"), dict)
        else {}
    )
    rep01_packets_total = 0
    if isinstance(file_states, dict):
        for st in file_states.values():
            if isinstance(st, dict):
                rep01_packets_total += _safe_int(st.get("total_packets"))

    cur.execute(
        """
        SELECT
            COUNT(*)::bigint AS packets_total,
            COUNT(*) FILTER (WHERE COALESCE(packet_label, '') = 'attack')::bigint AS attack_packets,
            COUNT(*) FILTER (WHERE COALESCE(packet_label, '') = 'benign')::bigint AS benign_packets,
            MAX(ts_utc)
        FROM phase4.step3_v2_child_packets
        WHERE simulation_id = %(sid)s::uuid;
        """,
        {"sid": sid},
    )
    p_total, p_attack, p_benign, p_latest = (cur.fetchone() or (0, 0, 0, None))
    label_packets_total = _safe_int(p_total)
    label_attack = _safe_int(p_attack)
    label_benign = _safe_int(p_benign)
    if label_packets_total <= 0:
        cur.execute(
            """
            SELECT
                COUNT(*)::bigint AS packets_total,
                COUNT(*) FILTER (WHERE COALESCE(payload->>'packet_label', '') = 'attack')::bigint AS attack_packets,
                COUNT(*) FILTER (WHERE COALESCE(payload->>'packet_label', '') = 'benign')::bigint AS benign_packets,
                MAX(ts_utc)
            FROM phase4.step3_v2_events
            WHERE simulation_id = %(sid)s::uuid
              AND event_type = 'node_traffic';
            """,
            {"sid": sid},
        )
        p_total, p_attack, p_benign, p_latest = (cur.fetchone() or (0, 0, 0, None))
        label_packets_total = _safe_int(p_total)
        label_attack = _safe_int(p_attack)
        label_benign = _safe_int(p_benign)
    if label_packets_total <= 0 and isinstance(file_states, dict):
        t_packets = 0
        t_attack = 0
        t_benign = 0
        for st in file_states.values():
            if not isinstance(st, dict):
                continue
            total_packets = _safe_int(st.get("total_packets"))
            remaining_packets = _safe_int(st.get("remaining_packets"))
            dispatched_packets = _safe_int(st.get("dispatched_packets"))
            processed_packets = max(dispatched_packets, total_packets - max(remaining_packets, 0))
            t_packets += max(0, min(total_packets, processed_packets))
            t_attack += _safe_int(st.get("attack_packets"))
            t_benign += _safe_int(st.get("benign_packets"))
        label_packets_total = t_packets
        label_attack = t_attack
        label_benign = t_benign
    label_coverage_rate: float | None = None
    if label_packets_total > 0:
        label_coverage_rate = float((label_attack + label_benign) / float(max(1, label_packets_total)))

    cur.execute(
        """
        SELECT COALESCE(SUM(alert_count), 0)::bigint, COUNT(*)::bigint
        FROM phase4.step3_v2_alerts
        WHERE simulation_id = %(sid)s::uuid;
        """,
        {"sid": sid},
    )
    alert_sum, alert_rows = (cur.fetchone() or (0, 0))
    alerts_total = _safe_int(alert_sum) if _safe_int(alert_sum) > 0 else _safe_int(alert_rows)

    cur.execute(
        """
        SELECT COALESCE(SUM(action_count), 0)::bigint, COUNT(*)::bigint
        FROM phase4.step3_v2_parent_actions
        WHERE simulation_id = %(sid)s::uuid;
        """,
        {"sid": sid},
    )
    action_sum, action_rows = (cur.fetchone() or (0, 0))
    escalations_total = _safe_int(action_sum) if _safe_int(action_sum) > 0 else _safe_int(action_rows)

    scope_hits: dict[str, int] = {}
    cur.execute(
        """
        SELECT COALESCE(child_id, 'unknown') AS child_id,
               COALESCE(SUM(alert_count), 0)::bigint AS hit_sum,
               COUNT(*)::bigint AS row_count
        FROM phase4.step3_v2_alerts
        WHERE simulation_id = %(sid)s::uuid
        GROUP BY 1;
        """,
        {"sid": sid},
    )
    for child_id, hit_sum, row_count in cur.fetchall() or []:
        scope = _child_scope_from_child_id(str(child_id or "unknown"))
        hits = _safe_int(hit_sum) if _safe_int(hit_sum) > 0 else _safe_int(row_count)
        scope_hits[scope] = scope_hits.get(scope, 0) + hits

    escalations_by_scope: dict[str, int] = {}
    cur.execute(
        """
        SELECT COALESCE(child_id, 'unknown') AS child_id,
               COALESCE(SUM(action_count), 0)::bigint AS action_sum,
               COUNT(*)::bigint AS row_count
        FROM phase4.step3_v2_parent_actions
        WHERE simulation_id = %(sid)s::uuid
        GROUP BY 1;
        """,
        {"sid": sid},
    )
    for child_id, action_sum_i, row_count in cur.fetchall() or []:
        scope = _child_scope_from_child_id(str(child_id or "unknown"))
        actions = _safe_int(action_sum_i) if _safe_int(action_sum_i) > 0 else _safe_int(row_count)
        escalations_by_scope[scope] = escalations_by_scope.get(scope, 0) + actions

    phase_packets: dict[str, int] = {}
    cur.execute(
        """
        SELECT
            COALESCE(NULLIF(phase, ''), COALESCE(NULLIF(payload->>'phase', ''), 'runtime')) AS phase_name,
            COUNT(*)::bigint AS packets_total
        FROM phase4.step3_v2_child_packets
        WHERE simulation_id = %(sid)s::uuid
        GROUP BY 1;
        """,
        {"sid": sid},
    )
    for phase_name, packets_total in cur.fetchall() or []:
        phase_key = str(phase_name or "runtime")
        phase_packets[phase_key] = phase_packets.get(phase_key, 0) + _safe_int(packets_total)

    phase_alerts: dict[str, int] = {}
    cur.execute(
        """
        SELECT
            COALESCE(NULLIF(phase, ''), COALESCE(NULLIF(payload->>'phase', ''), 'runtime')) AS phase_name,
            COALESCE(SUM(alert_count), 0)::bigint AS alert_sum,
            COUNT(*)::bigint AS row_count
        FROM phase4.step3_v2_alerts
        WHERE simulation_id = %(sid)s::uuid
        GROUP BY 1;
        """,
        {"sid": sid},
    )
    for phase_name, alert_sum_i, row_count in cur.fetchall() or []:
        phase_key = str(phase_name or "runtime")
        phase_alerts[phase_key] = _safe_int(alert_sum_i) if _safe_int(alert_sum_i) > 0 else _safe_int(row_count)

    phase_escalations: dict[str, int] = {}
    cur.execute(
        """
        SELECT
            COALESCE(NULLIF(payload->>'phase', ''), 'runtime') AS phase_name,
            COALESCE(SUM(action_count), 0)::bigint AS action_sum,
            COUNT(*)::bigint AS row_count
        FROM phase4.step3_v2_parent_actions
        WHERE simulation_id = %(sid)s::uuid
        GROUP BY 1;
        """,
        {"sid": sid},
    )
    for phase_name, action_sum_i, row_count in cur.fetchall() or []:
        phase_key = str(phase_name or "runtime")
        phase_escalations[phase_key] = _safe_int(action_sum_i) if _safe_int(action_sum_i) > 0 else _safe_int(row_count)

    phase_names = set(phase_packets.keys()) | set(phase_alerts.keys()) | set(phase_escalations.keys())
    phase_rows: list[dict[str, Any]] = []
    for idx, phase_name in enumerate(sorted(phase_names), start=1):
        phase_rows.append(
            {
                "phase_name": phase_name,
                "phase_order": idx,
                "packets_sent": phase_packets.get(phase_name, 0),
                "packets_dropped": 0,
                "alerts_generated": phase_alerts.get(phase_name, 0),
                "escalations_generated": phase_escalations.get(phase_name, 0),
            }
        )

    completion_reason = str(metadata.get("completion_reason") or "").strip().lower()
    sim_status = str(row[3] or "").strip().lower()
    status = sim_status
    if sim_status == "stopped" and completion_reason == "all_rep01_files_completed":
        status = "completed"

    return {
        "simulation_id": str(row[0] or ""),
        "model_id": str(row[1] or ""),
        "model_version": str(row[2] or ""),
        "status": status,
        "raw_status": sim_status,
        "metadata": metadata,
        "metrics": {
            "rep01_packets_total": rep01_packets_total,
            "alerts_total": alerts_total,
            "escalations_total": escalations_total,
            "label_coverage_rate": label_coverage_rate,
            "execution_mode": "simulation",
            "rule_hits_by_scope": scope_hits,
            "rule_hits_by_family": dict(scope_hits),
            "escalations_by_rule_family": escalations_by_scope,
            "phase_rows": phase_rows,
        },
        "timeline": {
            "runtime_shap_events": 0,
            "user_alert_events": alerts_total,
            "parent_review_events": escalations_total,
            "step3_v2_measured_at_utc": _to_utc_iso(p_latest),
        },
    }


def _query_rule_scope_stats(cur: Any, model_version: str) -> dict[str, dict[str, Any]]:
    if not model_version:
        return {}
    cur.execute(
        """
        SELECT
          rule_scope,
          COUNT(*)::bigint AS n,
          MIN(COALESCE(action, '')) AS action,
          MIN(CASE WHEN condition_json IS NULL THEN '' ELSE LEFT(condition_json::text, 220) END) AS sample_logic
        FROM phase4.rulepack_rules
        WHERE model_version = %(mv)s
        GROUP BY rule_scope;
        """,
        {"mv": model_version},
    )
    out: dict[str, dict[str, Any]] = {}
    for scope, n, action, sample in cur.fetchall() or []:
        out[str(scope or "global")] = {
            "count": int(n or 0),
            "action": str(action or "monitor") or "monitor",
            "sample_logic": str(sample or ""),
        }
    return out


def _build_csv_rows(
    *,
    step2: dict[str, Any],
    step3: dict[str, Any],
    rule_scopes: dict[str, dict[str, Any]],
    leakage_checks: list[dict[str, Any]],
    model_version: str,
    model_id: str,
    experiment_id: str,
) -> dict[str, list[dict[str, Any]]]:
    metrics = step2.get("metrics") if isinstance(step2.get("metrics"), dict) else {}
    within = metrics.get("within_dataset_results") if isinstance(metrics.get("within_dataset_results"), dict) else {}
    cross = metrics.get("cross_dataset_results") if isinstance(metrics.get("cross_dataset_results"), dict) else {}
    deltas = metrics.get("cross_dataset_deltas") if isinstance(metrics.get("cross_dataset_deltas"), dict) else {}
    shap = metrics.get("shap_stage_metrics") if isinstance(metrics.get("shap_stage_metrics"), dict) else {}
    rule_summary = metrics.get("rule_validation_summary") if isinstance(metrics.get("rule_validation_summary"), dict) else {}
    gov = metrics.get("governance_traceability") if isinstance(metrics.get("governance_traceability"), dict) else {}

    replay_metrics = step3.get("metrics") if isinstance(step3.get("metrics"), dict) else {}
    replay_timeline = step3.get("timeline") if isinstance(step3.get("timeline"), dict) else {}

    rows: dict[str, list[dict[str, Any]]] = {name: [] for name in CSV_FIELDS}

    t41 = within.get("table_4_1_rows") if isinstance(within.get("table_4_1_rows"), dict) else {}
    within_dataset_id = str(within.get("dataset_id") or "ENT-01")
    for track, vals in t41.items():
        vals = vals if isinstance(vals, dict) else {}
        rows["within_dataset_results.csv"].append(
            {
                "model": str(track or "model"),
                "dataset": within_dataset_id,
                "precision": _fmt_num(vals.get("precision")),
                "recall": _fmt_num(vals.get("recall")),
                "f1": _fmt_num(vals.get("f1")),
                "macro_f1": _fmt_num(vals.get("macro_f1")),
                "fpr": _fmt_num(vals.get("fpr")),
                "fnr": _fmt_num(vals.get("fnr")),
                "interpretation": "Measured within-dataset holdout performance from Step 2.",
            }
        )

    for target, payload in cross.items():
        if str(target) == "ent01_holdout":
            continue
        table_rows = payload.get("table_4_2_rows") if isinstance(payload, dict) and isinstance(payload.get("table_4_2_rows"), dict) else {}
        for track, vals in table_rows.items():
            vals = vals if isinstance(vals, dict) else {}
            delta = deltas.get(str(target), {}) if isinstance(deltas, dict) else {}
            delta_track = delta.get(str(track), {}) if isinstance(delta, dict) else {}
            rows["cross_dataset_results.csv"].append(
                {
                    "train_source": "ENT-01",
                    "test_source": EVAL_TEST_SOURCE.get(str(target), str(payload.get("dataset_id") or target)),
                    "domain": EVAL_DOMAIN.get(str(target), str(target)),
                    "precision": _fmt_num(vals.get("precision")),
                    "recall": _fmt_num(vals.get("recall")),
                    "f1": _fmt_num(vals.get("f1")),
                    "macro_f1": _fmt_num(vals.get("macro_f1")),
                    "fpr_change": _fmt_num(vals.get("fpr_delta_vs_ent01", delta_track.get("fpr_delta_vs_ent01"))),
                    "fnr_change": _fmt_num(vals.get("fnr_delta_vs_ent01", delta_track.get("fnr_delta_vs_ent01"))),
                    "interpretation": "Measured frozen-model cross-dataset generalization.",
                }
            )

    cross_targets = len(rows["cross_dataset_results.csv"])
    persisted_scope_counts = rule_summary.get("persisted_rule_counts_by_scope") if isinstance(rule_summary.get("persisted_rule_counts_by_scope"), dict) else {}
    rows["categorization_results.csv"] = [
        {
            "metric": "cross_dataset_targets_evaluated",
            "value": str(cross_targets),
            "evidence_source": "phase4.workflow_runs.run_metrics.cross_dataset_results",
            "interpretation": "Higher target coverage improves domain interpretation evidence breadth.",
        },
        {
            "metric": "rule_scopes_persisted",
            "value": str(sum(1 for v in persisted_scope_counts.values() if _safe_int(v) > 0)),
            "evidence_source": "phase4.workflow_runs.run_metrics.rule_validation_summary",
            "interpretation": "Rule scope coverage indicates downstream categorization support breadth.",
        },
        {
            "metric": "step2_gate_failures_count",
            "value": str(len(metrics.get("gate_failures") or [])),
            "evidence_source": "phase4.workflow_runs.run_metrics.gate_failures",
            "interpretation": "Lower gate failures indicate stronger governance-aligned categorization/training flow.",
        },
    ]

    scope_hits = replay_metrics.get("rule_hits_by_scope") if isinstance(replay_metrics.get("rule_hits_by_scope"), dict) else {}
    escalations_by_scope = replay_metrics.get("escalations_by_rule_family") if isinstance(replay_metrics.get("escalations_by_rule_family"), dict) else {}
    for scope, hits in sorted(scope_hits.items()):
        esc = _safe_int(escalations_by_scope.get(scope))
        is_cross = str(scope) == "cross_scope"
        escalated = esc > 0
        correctness = (is_cross and escalated) or ((not is_cross) and (not escalated))
        rows["cross_scope_results.csv"].append(
            {
                "child_scope": str(scope),
                "observed_vector_class": "mixed_runtime",
                "expected_scope": str(scope),
                "scope_match": "cross_scope" if is_cross else "in_scope",
                "escalated": "yes" if escalated else "no",
                "parent_outcome": "reviewed" if _safe_int(replay_timeline.get("parent_review_events")) > 0 else "not_reviewed",
                "correct": "yes" if correctness else "no",
            }
        )

    coverage_by_split = shap.get("coverage_by_split") if isinstance(shap.get("coverage_by_split"), dict) else {}
    for split, cov in coverage_by_split.items():
        rows["shap_results.csv"].append(
            {
                "shap_stage": "offline",
                "input": str(split),
                "output": "coverage",
                "metric": "explanation_coverage",
                "value": _fmt_num(cov),
                "interpretation": "Measured SHAP coverage by split from Step 2 artifacts.",
            }
        )
    rows["shap_results.csv"].append(
        {
            "shap_stage": "offline",
            "input": "global",
            "output": "consistency",
            "metric": "top_feature_consistency",
            "value": _fmt_num(shap.get("top_feature_consistency")),
            "interpretation": "Measured SHAP top-feature consistency from Step 2 artifacts.",
        }
    )

    for scope, info in sorted(rule_scopes.items()):
        hits = _safe_int(scope_hits.get(scope))
        rows["rule_validation_results.csv"].append(
            {
                "rule_layer": scope,
                "evidence_source": "model_v1_rulepack",
                "example_rule_logic": str(info.get("sample_logic") or ""),
                "trigger_count": str(hits),
                "valid_trigger_count": str(max(hits, 0)),
                "precision": "",
                "action": str(info.get("action") or "monitor"),
            }
        )

    rep_profile = str(step3.get("replay_profile") or replay_metrics.get("execution_mode") or "simulation")
    alert_total = _safe_int(replay_metrics.get("alerts_total"))
    cross_scope_hits = _safe_int(scope_hits.get("cross_scope"))
    shap_events = _safe_int(replay_timeline.get("runtime_shap_events"))
    review_events = _safe_int(replay_timeline.get("parent_review_events"))
    rows["replay_results.csv"].append(
        {
            "replay_phase": rep_profile,
            "input_source": "REP-01",
            "alert_count": str(alert_total),
            "cross_scope_count": str(cross_scope_hits),
            "parent_review_completion": _fmt_pct(review_events, max(alert_total, 1)) if alert_total > 0 else "1",
            "explanation_coverage": "1" if shap_events > 0 else "0",
            "key_observation": f"rep01_packets_total={_safe_int(replay_metrics.get('rep01_packets_total'))}",
        }
    )

    phase_rows = replay_metrics.get("phase_rows") if isinstance(replay_metrics.get("phase_rows"), list) else []
    if not step3.get("replay_run_id") and phase_rows:
        for phase_row in phase_rows:
            pname = str(phase_row.get("phase_name") or "runtime")
            rows["replay_phase_results.csv"].append(
                {
                    "replay_run_id": str(step3.get("simulation_id") or ""),
                    "replay_id": str(step3.get("simulation_id") or ""),
                    "phase_name": pname,
                    "phase_order": _fmt_num(phase_row.get("phase_order"), places=0),
                    "packets_sent": _fmt_num(phase_row.get("packets_sent"), places=0),
                    "packets_dropped": _fmt_num(phase_row.get("packets_dropped"), places=0),
                    "alerts_generated": _fmt_num(phase_row.get("alerts_generated"), places=0),
                    "escalations_generated": _fmt_num(phase_row.get("escalations_generated"), places=0),
                    "parent_decisions": _fmt_num(phase_row.get("escalations_generated"), places=0),
                    "shap_coverage": "",
                    "latency_ms": "",
                    "throughput_eps": "",
                    "status": str(step3.get("status") or "completed"),
                }
            )

    fail_checks = [c for c in leakage_checks if str(c.get("check_status") or "") == "fail"]
    rows["governance_results.csv"] = [
        {
            "governance_metric": "leakage_checks_failed",
            "evidence_source": "phase4.leakage_guard_results",
            "value": str(len(fail_checks)),
            "interpretation": "0 indicates governance leakage checks are currently passing.",
        },
        {
            "governance_metric": "traceability_h1_5_ready",
            "evidence_source": "phase4.workflow_runs.run_metrics.governance_traceability",
            "value": "1" if gov.get("h1_5_traceability_ready") else "0",
            "interpretation": "1 indicates Step 1→Step 2 lineage linkage is recorded.",
        },
        {
            "governance_metric": "replay_run_linked",
            "evidence_source": "phase4.step3_replay_metrics",
            "value": "1" if step3.get("replay_run_id") else "0",
            "interpretation": "1 indicates replay evidence linked to model_version.",
        },
    ]

    rows["h1_workflow_results.csv"].append(
        {
            "experiment_id": experiment_id,
            "model_version": model_version,
            "dataset": "REP-01",
            "alert_count": str(alert_total),
            "filtered_alerts": str(max(alert_total - _safe_int(replay_metrics.get("escalations_total")), 0)),
            "parent_review_completion": _fmt_pct(review_events, max(alert_total, 1)) if alert_total > 0 else "1",
            "triage_proxy": f"runtime_shap_events={shap_events}",
            "interpretation": "Measured workflow efficiency proxy from replay runtime telemetry.",
        }
    )

    total_scope_hits = sum(_safe_int(v) for v in scope_hits.values())
    cross_scope_hits = _safe_int(scope_hits.get("cross_scope"))
    in_scope_hits = max(total_scope_hits - cross_scope_hits, 0)
    protocol_coverage = len([k for k, v in scope_hits.items() if _safe_int(v) > 0])
    vector_coverage = len([k for k, v in (replay_metrics.get("rule_hits_by_family") or {}).items() if _safe_int(v) > 0])
    rows["h2_categorization_results.csv"].append(
        {
            "experiment_id": experiment_id,
            "model_version": model_version,
            "dataset": "ENT-01+DNS-01+IOT-01",
            "domain_accuracy": _fmt_pct(in_scope_hits, total_scope_hits) if total_scope_hits > 0 else "",
            "protocol_coverage": _fmt_num(protocol_coverage, places=0),
            "vector_coverage": _fmt_num(vector_coverage, places=0),
            "scope_match_accuracy": _fmt_pct(in_scope_hits, total_scope_hits) if total_scope_hits > 0 else "",
            "interpretation": "Measured replay-scope categorization proxy from expected-vs-observed scope outcomes.",
        }
    )

    for r in rows["cross_scope_results.csv"]:
        rows["h3_cross_scope_results.csv"].append(
            {
                "experiment_id": experiment_id,
                "model_version": model_version,
                "child_scope": r.get("child_scope"),
                "observed_behavior": r.get("observed_vector_class"),
                "expected_scope": r.get("expected_scope"),
                "cross_scope_detected": "yes" if str(r.get("scope_match")) == "cross_scope" else "no",
                "escalation_correct": r.get("correct"),
                "severity_level": "high" if str(r.get("escalated")) == "yes" else "low",
                "interpretation": "Cross-scope runtime observation from Step 3 replay evidence.",
            }
        )

    rows["h4_shap_results.csv"].append(
        {
            "experiment_id": experiment_id,
            "model_version": model_version,
            "explanation_coverage": "1" if shap_events > 0 else "0",
            "top_features_consistency": _fmt_num(shap.get("top_feature_consistency")),
            "explanation_clarity": "",
            "triage_support_score": _fmt_pct(shap_events, max(alert_total, 1)) if alert_total > 0 else "",
            "interpretation": "Runtime+offline SHAP availability and stability metrics.",
        }
    )

    for gr in rows["governance_results.csv"]:
        value = str(gr.get("value") or "")
        try:
            pct = _fmt_num(float(value) * 100, places=2) if value not in {"", "0", "1"} else ("100" if value == "1" else "0")
        except Exception:
            pct = ""
        rows["h5_governance_results.csv"].append(
            {
                "experiment_id": experiment_id,
                "model_version": model_version,
                "metric": gr.get("governance_metric"),
                "evidence_source": gr.get("evidence_source"),
                "status": "pass" if value in {"0", "1"} else "measured",
                "completeness_pct": pct,
                "interpretation": gr.get("interpretation"),
            }
        )

    return rows


def _augment_csv_rows_with_measured_data(
    cur: Any,
    rows: dict[str, list[dict[str, Any]]],
    *,
    model_version: str,
    model_id: str,
    source_step1_run_id: str,
    source_step2_run_id: str,
    replay_run_id: str,
    step3_v2_sim_id: str,
) -> None:
    if _is_uuid_like(source_step2_run_id):
        cur.execute(
            """
            SELECT run_id::text, model_id, model_version, dataset_id, split_name, evaluation_mode, eval_target, model_track,
                   label, precision, recall, f1, support, accuracy, macro_f1, weighted_f1, micro_f1, fpr, far, fnr,
                   confusion_matrix, created_at_utc
            FROM phase4.model_per_class_metrics
            WHERE run_id = %(rid)s::uuid
            ORDER BY created_at_utc DESC;
            """,
            {"rid": source_step2_run_id},
        )
    else:
        cur.execute(
            """
            SELECT run_id::text, model_id, model_version, dataset_id, split_name, evaluation_mode, eval_target, model_track,
                   label, precision, recall, f1, support, accuracy, macro_f1, weighted_f1, micro_f1, fpr, far, fnr,
                   confusion_matrix, created_at_utc
            FROM phase4.model_per_class_metrics
            WHERE model_version = %(mv)s
            ORDER BY created_at_utc DESC;
            """,
            {"mv": model_version},
        )
    pcm_rows = cur.fetchall() or []
    detection_seen: set[tuple[str, str, str, str]] = set()
    confusion_seen: set[tuple[str, str, str, str]] = set()
    for r in pcm_rows:
        run_id = str(r[0] or "")
        eval_key = (run_id, str(r[3] or ""), str(r[4] or ""), str(r[7] or ""))
        if eval_key not in detection_seen:
            detection_seen.add(eval_key)
            rows["detection_metrics.csv"].append(
                {
                    "run_id": run_id,
                    "model_id": str(r[1] or model_id),
                    "model_version": str(r[2] or model_version),
                    "dataset_id": str(r[3] or ""),
                    "split_name": str(r[4] or ""),
                    "evaluation_type": str(r[5] or ""),
                    "model_track": str(r[7] or ""),
                    "precision": _fmt_num(r[9]),
                    "recall": _fmt_num(r[10]),
                    "f1": _fmt_num(r[11]),
                    "macro_f1": _fmt_num(r[14]),
                    "micro_f1": _fmt_num(r[16]),
                    "weighted_f1": _fmt_num(r[15]),
                    "accuracy": _fmt_num(r[13]),
                    "fpr": _fmt_num(r[17]),
                    "far": _fmt_num(r[18]),
                    "fnr": _fmt_num(r[19]),
                    "measured_at_utc": r[21].isoformat() if r[21] else "",
                }
            )
            if str(r[5] or "").strip().lower() != "within_dataset":
                rows["cross_dataset_robustness.csv"].append(
                    {
                        "run_id": run_id,
                        "model_id": str(r[1] or model_id),
                        "model_version": str(r[2] or model_version),
                        "dataset_id": str(r[3] or ""),
                        "evaluation_type": str(r[5] or ""),
                        "model_track": str(r[7] or ""),
                        "precision": _fmt_num(r[9]),
                        "recall": _fmt_num(r[10]),
                        "f1": _fmt_num(r[11]),
                        "macro_f1": _fmt_num(r[14]),
                        "micro_f1": _fmt_num(r[16]),
                        "weighted_f1": _fmt_num(r[15]),
                        "accuracy": _fmt_num(r[13]),
                        "fpr": _fmt_num(r[17]),
                        "far": _fmt_num(r[18]),
                        "fnr": _fmt_num(r[19]),
                        "measured_at_utc": r[21].isoformat() if r[21] else "",
                    }
                )
        rows["per_class_metrics.csv"].append(
            {
                "run_id": run_id,
                "model_id": str(r[1] or model_id),
                "model_version": str(r[2] or model_version),
                "dataset_id": str(r[3] or ""),
                "split_name": str(r[4] or ""),
                "evaluation_type": str(r[5] or ""),
                "model_track": str(r[7] or ""),
                "label": str(r[8] or ""),
                "precision": _fmt_num(r[9]),
                "recall": _fmt_num(r[10]),
                "f1": _fmt_num(r[11]),
                "support": _fmt_num(r[12], places=0),
                "measured_at_utc": r[21].isoformat() if r[21] else "",
            }
        )
        cm_key = (run_id, str(r[3] or ""), str(r[4] or ""), str(r[7] or ""))
        if cm_key not in confusion_seen:
            confusion_seen.add(cm_key)
            rows["confusion_matrix.csv"].append(
                {
                    "run_id": run_id,
                    "model_id": str(r[1] or model_id),
                    "model_version": str(r[2] or model_version),
                    "dataset_id": str(r[3] or ""),
                    "split_name": str(r[4] or ""),
                    "evaluation_type": str(r[5] or ""),
                    "model_track": str(r[7] or ""),
                    "confusion_matrix_json": json.dumps(r[20] or []),
                    "measured_at_utc": r[21].isoformat() if r[21] else "",
                }
            )

    shap_params: dict[str, Any] = {"mv": model_version}
    shap_where = "WHERE model_version = %(mv)s"
    if replay_run_id:
        shap_where += " AND COALESCE(replay_id,'') = %(replay_id)s"
        shap_params["replay_id"] = replay_run_id
    elif step3_v2_sim_id:
        shap_where += " AND COALESCE(replay_id,'') IN ('', %(sim_id)s)"
        shap_params["sim_id"] = step3_v2_sim_id
    cur.execute(
        f"""
        SELECT id, model_version, replay_id, alert_id, shap_stage, top_features_json, event_details_json, created_at
        FROM phase4.shap_logs
        {shap_where}
        ORDER BY created_at DESC;
        """,
        shap_params,
    )
    for sid, mv, rid, aid, stage, topf, detail, created_at in cur.fetchall() or []:
        d = _parse_json_dict(detail)
        rows["shap_explanations.csv"].append(
            {
                "shap_log_id": str(sid or ""),
                "model_version": str(mv or model_version),
                "replay_id": str(rid or ""),
                "alert_id": str(aid or ""),
                "shap_stage": str(stage or ""),
                "status": str((d.get("status") or d.get("event_status") or "")),
                "evidence_status": str((d.get("evidence_status") or "")),
                "top_features_json": json.dumps(topf or {}),
                "created_at": created_at.isoformat() if created_at else "",
            }
        )

    if replay_run_id:
        cur.execute(
            """
            SELECT phase_id::text, phase_name, phase_order, packets_sent, packets_dropped, pcap_artifact_id::text,
                   started_at_utc, finished_at_utc
            FROM phase4.step3_replay_phases
            WHERE replay_run_id = %(rid)s::uuid
            ORDER BY phase_order ASC, created_at_utc ASC;
            """,
            {"rid": replay_run_id},
        )
        replay_phase_rows = cur.fetchall() or []
        for pid, pname, pord, psent, pdrop, pcap_id, started_at, finished_at in replay_phase_rows:
            cur.execute(
                """
                SELECT
                    COALESCE(SUM(alerts_generated),0)::bigint,
                    COALESCE(SUM(escalations_generated),0)::bigint,
                    COALESCE(AVG(latency_ms),0)::numeric
                FROM phase4.replay_streams
                WHERE replay_run_id = %(rid)s::uuid
                  AND replay_phase = %(phase)s;
                """,
                {"rid": replay_run_id, "phase": str(pname or "")},
            )
            stats = cur.fetchone() or (0, 0, 0)
            cur.execute(
                """
                SELECT COUNT(*)::bigint
                FROM phase4.parent_actions
                WHERE replay_run_id = %(rid)s::uuid;
                """,
                {"rid": replay_run_id},
            )
            parent_decisions = int((cur.fetchone() or [0])[0] or 0)
            cur.execute(
                """
                SELECT
                    COUNT(*)::bigint,
                    COUNT(*) FILTER (WHERE shap_evidence_status = 'measured')::bigint
                FROM phase4.step3_alerts
                WHERE replay_run_id = %(rid)s::uuid
                  AND COALESCE(payload->'context'->>'replay_phase','') = %(phase)s;
                """,
                {"rid": replay_run_id, "phase": str(pname or "")},
            )
            arow = cur.fetchone() or (0, 0)
            alerts_total = int(arow[0] or 0)
            shap_measured = int(arow[1] or 0)
            duration_s = None
            if started_at and finished_at:
                duration_s = max(0.0, (finished_at - started_at).total_seconds())
            throughput_eps = (float(psent or 0) / duration_s) if duration_s and duration_s > 0 else 0.0
            rows["replay_phase_results.csv"].append(
                {
                    "replay_run_id": replay_run_id,
                    "replay_id": replay_run_id,
                    "phase_name": str(pname or ""),
                    "phase_order": _fmt_num(pord, places=0),
                    "packets_sent": _fmt_num(psent, places=0),
                    "packets_dropped": _fmt_num(pdrop, places=0),
                    "alerts_generated": _fmt_num(stats[0], places=0),
                    "escalations_generated": _fmt_num(stats[1], places=0),
                    "parent_decisions": _fmt_num(parent_decisions, places=0),
                    "shap_coverage": _fmt_pct(shap_measured, alerts_total),
                    "latency_ms": _fmt_num(stats[2]),
                    "throughput_eps": _fmt_num(throughput_eps),
                    "status": "completed" if finished_at else "running",
                }
            )

    if source_step1_run_id:
        cur.execute(
            """
            SELECT started_at_utc, completed_at_utc
            FROM phase4.workflow_runs
            WHERE run_id = %(rid)s::uuid
            LIMIT 1;
            """,
            {"rid": source_step1_run_id},
        )
        r = cur.fetchone()
        if r and r[0] and r[1]:
            rows["operational_metrics.csv"].append(
                {
                    "run_id": source_step1_run_id,
                    "model_id": model_id,
                    "model_version": model_version,
                    "replay_run_id": replay_run_id,
                    "metric_name": "ingestion_duration",
                    "metric_value": _fmt_num(max(0.0, (r[1] - r[0]).total_seconds())),
                    "metric_unit": "seconds",
                    "metric_source": "workflow_runs.step1",
                    "measured_at_utc": r[1].isoformat(),
                }
            )

    if source_step2_run_id:
        cur.execute(
            """
            SELECT started_at_utc, completed_at_utc, run_metrics
            FROM phase4.workflow_runs
            WHERE run_id = %(rid)s::uuid
            LIMIT 1;
            """,
            {"rid": source_step2_run_id},
        )
        r2 = cur.fetchone()
        if r2 and r2[0] and r2[1]:
            rows["operational_metrics.csv"].append(
                {
                    "run_id": source_step2_run_id,
                    "model_id": model_id,
                    "model_version": model_version,
                    "replay_run_id": replay_run_id,
                    "metric_name": "training_evaluation_duration",
                    "metric_value": _fmt_num(max(0.0, (r2[1] - r2[0]).total_seconds())),
                    "metric_unit": "seconds",
                    "metric_source": "workflow_runs.step2",
                    "measured_at_utc": r2[1].isoformat(),
                }
            )
            rm = _parse_json_dict(r2[2] or {})
            tr = _parse_json_dict((_parse_json_dict(rm.get("training_result"))).get("metrics"))
            if tr.get("duration_s") is not None:
                rows["operational_metrics.csv"].append(
                    {
                        "run_id": source_step2_run_id,
                        "model_id": model_id,
                        "model_version": model_version,
                        "replay_run_id": replay_run_id,
                        "metric_name": "training_duration",
                        "metric_value": _fmt_num(tr.get("duration_s")),
                        "metric_unit": "seconds",
                        "metric_source": "training_result.metrics",
                        "measured_at_utc": r2[1].isoformat(),
                    }
                )
            sm = _parse_json_dict(rm.get("shap_stage_metrics"))
            if sm.get("offline_compute_duration_s") is not None:
                rows["operational_metrics.csv"].append(
                    {
                        "run_id": source_step2_run_id,
                        "model_id": model_id,
                        "model_version": model_version,
                        "replay_run_id": replay_run_id,
                        "metric_name": "shap_generation_duration",
                        "metric_value": _fmt_num(sm.get("offline_compute_duration_s")),
                        "metric_unit": "seconds",
                        "metric_source": "shap_stage_metrics",
                        "measured_at_utc": r2[1].isoformat(),
                    }
                )

    if replay_run_id:
        cur.execute(
            """
            SELECT metrics, updated_at_utc
            FROM phase4.step3_replay_metrics
            WHERE replay_run_id = %(rid)s::uuid
            LIMIT 1;
            """,
            {"rid": replay_run_id},
        )
        rm3 = cur.fetchone()
        if rm3:
            m3 = _parse_json_dict(rm3[0] or {})
            measured_at = rm3[1].isoformat() if rm3[1] else ""
            for name, unit in (
                ("delivery_ratio", "ratio"),
                ("mean_latency_ms", "ms"),
                ("alerts_total", "count"),
                ("escalations_total", "count"),
                ("packets_sent_total", "count"),
                ("packets_received_total", "count"),
                ("packets_dropped_total", "count"),
            ):
                if m3.get(name) is None:
                    continue
                rows["operational_metrics.csv"].append(
                    {
                        "run_id": source_step2_run_id or source_step1_run_id,
                        "model_id": model_id,
                        "model_version": model_version,
                        "replay_run_id": replay_run_id,
                        "metric_name": name,
                        "metric_value": _fmt_num(m3.get(name)),
                        "metric_unit": unit,
                        "metric_source": "step3_replay_metrics",
                        "measured_at_utc": measured_at,
                    }
                )

    if replay_run_id:
        cur.execute(
            """
            SELECT
                COUNT(*)::bigint,
                COUNT(*) FILTER (WHERE shap_helped = true)::bigint,
                COALESCE(AVG(usefulness_score), 0)::numeric
            FROM phase4.step3_analyst_feedback
            WHERE model_version = %(mv)s
              AND replay_run_id = %(rid)s::uuid;
            """,
            {"mv": model_version, "rid": replay_run_id},
        )
    elif step3_v2_sim_id:
        cur.execute(
            """
            SELECT
                COUNT(*)::bigint,
                COUNT(*) FILTER (WHERE shap_helped = true)::bigint,
                COALESCE(AVG(usefulness_score), 0)::numeric
            FROM phase4.step3_analyst_feedback
            WHERE model_version = %(mv)s
              AND replay_run_id IS NULL;
            """,
            {"mv": model_version},
        )
    else:
        cur.execute(
            """
            SELECT
                COUNT(*)::bigint,
                COUNT(*) FILTER (WHERE shap_helped = true)::bigint,
                COALESCE(AVG(usefulness_score), 0)::numeric
            FROM phase4.step3_analyst_feedback
            WHERE model_version = %(mv)s;
            """,
            {"mv": model_version},
        )
    fb = cur.fetchone() or (0, 0, 0)
    feedback_count = int(fb[0] or 0)
    feedback_shap_helped = int(fb[1] or 0)
    feedback_avg_usefulness = float(fb[2] or 0.0)
    if rows.get("h4_shap_results.csv"):
        row = rows["h4_shap_results.csv"][0]
        row["explanation_clarity"] = _fmt_num(feedback_avg_usefulness if feedback_count > 0 else "")
        row["triage_support_score"] = _fmt_pct(feedback_shap_helped, feedback_count) if feedback_count > 0 else row.get("triage_support_score")
        row["interpretation"] = (
            "Measured SHAP coverage with analyst feedback-linked triage usefulness evidence."
            if feedback_count > 0
            else "Measured SHAP coverage; analyst feedback not yet recorded for this replay/model."
        )

    rr = None
    if replay_run_id:
        cur.execute(
            """
            SELECT rr.active_rulepack_version, rr.replay_id::text, rr.model_version, rr.source_step1_run_id,
                   rr.source_step2_workflow_id, mr.is_frozen, mr.status
            FROM phase4.replay_runs rr
            LEFT JOIN phase4.model_registry mr ON mr.model_version = rr.model_version
            WHERE rr.replay_run_id = %(rid)s::uuid
            LIMIT 1;
            """,
            {"rid": replay_run_id},
        )
        rr = cur.fetchone()
    rulepack_version = str(rr[0] or "") if rr else ""
    replay_id = str(rr[1] or replay_run_id or "") if rr else (replay_run_id or "")
    freeze_status = "frozen" if rr and bool(rr[5]) else (str(rr[6] or "") if rr else "")
    cur.execute(
        """
        SELECT a.alert_id::text, a.pcap_artifact_id::text, a.shap_evidence_id, fb.feedback_id::text, a.payload
        FROM phase4.step3_alerts a
        LEFT JOIN phase4.step3_analyst_feedback fb ON fb.alert_id = a.alert_id
        WHERE a.replay_run_id = %(rid)s::uuid
        ORDER BY a.created_at_utc DESC;
        """,
        {"rid": replay_run_id},
    ) if replay_run_id else None
    alert_rows = cur.fetchall() if replay_run_id else []
    if not alert_rows:
        rows["governance_traceability.csv"].append(
            {
                "run_id": source_step2_run_id or source_step1_run_id,
                "model_id": model_id,
                "model_version": model_version,
                "source_step1_run_id": source_step1_run_id,
                "source_step2_run_id": source_step2_run_id,
                "replay_run_id": replay_run_id,
                "replay_id": replay_id,
                "rulepack_version": rulepack_version,
                "pcap_artifact_id": "",
                "alert_id": "",
                "shap_log_id": "",
                "feedback_id": "",
                "checksum_ref": "",
                "freeze_status": freeze_status,
            }
        )
    for aid, pcap_id, shap_id, feedback_id, payload in alert_rows:
        pl = _parse_json_dict(payload)
        checksum_ref = str((_parse_json_dict(pl.get("context"))).get("checksum") or "")
        rows["governance_traceability.csv"].append(
            {
                "run_id": source_step2_run_id or source_step1_run_id,
                "model_id": model_id,
                "model_version": model_version,
                "source_step1_run_id": source_step1_run_id,
                "source_step2_run_id": source_step2_run_id,
                "replay_run_id": replay_run_id,
                "replay_id": replay_id,
                "rulepack_version": rulepack_version,
                "pcap_artifact_id": str(pcap_id or ""),
                "alert_id": str(aid or ""),
                "shap_log_id": str(shap_id or ""),
                "feedback_id": str(feedback_id or ""),
                "checksum_ref": checksum_ref,
                "freeze_status": freeze_status,
            }
        )


def _replace_rows_for_model(cur: Any, table: str, model_version: str, rows: list[dict[str, Any]]) -> int:
    cur.execute(f"DELETE FROM {table} WHERE model_version = %(mv)s;", {"mv": model_version})
    if not rows:
        return 0
    cols = list(rows[0].keys())
    col_sql = ", ".join(cols)
    val_sql = ", ".join([f"%({c})s" for c in cols])
    sql = f"INSERT INTO {table} ({col_sql}) VALUES ({val_sql});"
    for row in rows:
        cur.execute(sql, row)
    return len(rows)


def _persist_results_tables(
    cur: Any,
    model_version: str,
    model_id: str,
    source_step1_run_id: str,
    source_step2_run_id: str,
    replay_run_id: str,
    experiment_id: str,
    rows: dict[str, list[dict[str, Any]]],
) -> dict[str, int]:
    counts: dict[str, int] = {}
    lineage = {
        "model_id": model_id,
        "source_step1_run_id": source_step1_run_id,
        "source_step2_run_id": source_step2_run_id,
        "replay_run_id": replay_run_id,
    }

    counts["phase4.results_within_dataset"] = _replace_rows_for_model(
        cur,
        "phase4.results_within_dataset",
        model_version,
        [
            {
                **lineage,
                "experiment_id": experiment_id,
                "model_version": model_version,
                "model": r.get("model"),
                "dataset": r.get("dataset"),
                "precision": r.get("precision"),
                "recall": r.get("recall"),
                "f1": r.get("f1"),
                "macro_f1": r.get("macro_f1"),
                "fpr": r.get("fpr"),
                "fnr": r.get("fnr"),
                "interpretation": r.get("interpretation"),
            }
            for r in rows.get("within_dataset_results.csv", [])
        ],
    )
    counts["phase4.results_cross_dataset"] = _replace_rows_for_model(
        cur,
        "phase4.results_cross_dataset",
        model_version,
        [
            {
                **lineage,
                "experiment_id": experiment_id,
                "model_version": model_version,
                "train_source": r.get("train_source"),
                "test_source": r.get("test_source"),
                "domain": r.get("domain"),
                "precision": r.get("precision"),
                "recall": r.get("recall"),
                "f1": r.get("f1"),
                "macro_f1": r.get("macro_f1"),
                "fpr_change": r.get("fpr_change"),
                "fnr_change": r.get("fnr_change"),
                "interpretation": r.get("interpretation"),
            }
            for r in rows.get("cross_dataset_results.csv", [])
        ],
    )
    counts["phase4.results_categorization"] = _replace_rows_for_model(
        cur,
        "phase4.results_categorization",
        model_version,
        [
            {
                **lineage,
                "experiment_id": experiment_id,
                "model_version": model_version,
                "metric": r.get("metric"),
                "value": r.get("value"),
                "evidence_source": r.get("evidence_source"),
                "interpretation": r.get("interpretation"),
            }
            for r in rows.get("categorization_results.csv", [])
        ],
    )
    counts["phase4.results_cross_scope"] = _replace_rows_for_model(
        cur,
        "phase4.results_cross_scope",
        model_version,
        [
            {
                **lineage,
                "experiment_id": experiment_id,
                "model_version": model_version,
                "child_scope": r.get("child_scope"),
                "observed_vector_class": r.get("observed_vector_class"),
                "expected_scope": r.get("expected_scope"),
                "scope_match": r.get("scope_match"),
                "escalated": r.get("escalated"),
                "parent_outcome": r.get("parent_outcome"),
                "correct": r.get("correct"),
            }
            for r in rows.get("cross_scope_results.csv", [])
        ],
    )
    counts["phase4.results_shap"] = _replace_rows_for_model(
        cur,
        "phase4.results_shap",
        model_version,
        [
            {
                **lineage,
                "experiment_id": experiment_id,
                "model_version": model_version,
                "shap_stage": r.get("shap_stage"),
                "input_desc": r.get("input"),
                "output_desc": r.get("output"),
                "metric": r.get("metric"),
                "value": r.get("value"),
                "interpretation": r.get("interpretation"),
            }
            for r in rows.get("shap_results.csv", [])
        ],
    )
    counts["phase4.results_rule_validation"] = _replace_rows_for_model(
        cur,
        "phase4.results_rule_validation",
        model_version,
        [
            {
                **lineage,
                "experiment_id": experiment_id,
                "model_version": model_version,
                "rule_layer": r.get("rule_layer"),
                "evidence_source": r.get("evidence_source"),
                "example_rule_logic": r.get("example_rule_logic"),
                "trigger_count": r.get("trigger_count"),
                "valid_trigger_count": r.get("valid_trigger_count"),
                "precision": r.get("precision"),
                "action": r.get("action"),
            }
            for r in rows.get("rule_validation_results.csv", [])
        ],
    )
    counts["phase4.results_replay"] = _replace_rows_for_model(
        cur,
        "phase4.results_replay",
        model_version,
        [
            {
                **lineage,
                "experiment_id": experiment_id,
                "model_version": model_version,
                "replay_phase": r.get("replay_phase"),
                "input_source": r.get("input_source"),
                "alert_count": r.get("alert_count"),
                "cross_scope_count": r.get("cross_scope_count"),
                "parent_review_completion": r.get("parent_review_completion"),
                "explanation_coverage": r.get("explanation_coverage"),
                "key_observation": r.get("key_observation"),
            }
            for r in rows.get("replay_results.csv", [])
        ],
    )
    counts["phase4.results_governance"] = _replace_rows_for_model(
        cur,
        "phase4.results_governance",
        model_version,
        [
            {
                **lineage,
                "experiment_id": experiment_id,
                "model_version": model_version,
                "governance_metric": r.get("governance_metric"),
                "evidence_source": r.get("evidence_source"),
                "value": r.get("value"),
                "interpretation": r.get("interpretation"),
            }
            for r in rows.get("governance_results.csv", [])
        ],
    )

    counts["phase4.h1_workflow_efficiency_results"] = _replace_rows_for_model(
        cur,
        "phase4.h1_workflow_efficiency_results",
        model_version,
        [
            {
                **lineage,
                "experiment_id": experiment_id,
                "model_version": model_version,
                "model_version_label": model_version,
                "dataset": r.get("dataset"),
                "alert_count": r.get("alert_count"),
                "filtered_alerts": r.get("filtered_alerts"),
                "parent_review_completion": r.get("parent_review_completion"),
                "triage_proxy": r.get("triage_proxy"),
                "interpretation": r.get("interpretation"),
            }
            for r in rows.get("h1_workflow_results.csv", [])
        ],
    )
    counts["phase4.h1_categorization_results"] = _replace_rows_for_model(
        cur,
        "phase4.h1_categorization_results",
        model_version,
        [
            {
                **lineage,
                "experiment_id": experiment_id,
                "model_version": model_version,
                "dataset": r.get("dataset"),
                "domain_accuracy": r.get("domain_accuracy"),
                "protocol_coverage": r.get("protocol_coverage"),
                "vector_coverage": r.get("vector_coverage"),
                "scope_match_accuracy": r.get("scope_match_accuracy"),
                "interpretation": r.get("interpretation"),
            }
            for r in rows.get("h2_categorization_results.csv", [])
        ],
    )
    counts["phase4.h1_cross_scope_results"] = _replace_rows_for_model(
        cur,
        "phase4.h1_cross_scope_results",
        model_version,
        [
            {
                **lineage,
                "experiment_id": experiment_id,
                "model_version": model_version,
                "child_scope": r.get("child_scope"),
                "observed_behavior": r.get("observed_behavior"),
                "expected_scope": r.get("expected_scope"),
                "cross_scope_detected": r.get("cross_scope_detected"),
                "escalation_correct": r.get("escalation_correct"),
                "severity_level": r.get("severity_level"),
                "interpretation": r.get("interpretation"),
            }
            for r in rows.get("h3_cross_scope_results.csv", [])
        ],
    )
    counts["phase4.h1_shap_triage_results"] = _replace_rows_for_model(
        cur,
        "phase4.h1_shap_triage_results",
        model_version,
        [
            {
                **lineage,
                "experiment_id": experiment_id,
                "model_version": model_version,
                "explanation_coverage": r.get("explanation_coverage"),
                "top_features_consistency": r.get("top_features_consistency"),
                "explanation_clarity": r.get("explanation_clarity"),
                "triage_support_score": r.get("triage_support_score"),
                "interpretation": r.get("interpretation"),
            }
            for r in rows.get("h4_shap_results.csv", [])
        ],
    )
    counts["phase4.h1_governance_traceability_results"] = _replace_rows_for_model(
        cur,
        "phase4.h1_governance_traceability_results",
        model_version,
        [
            {
                **lineage,
                "experiment_id": experiment_id,
                "model_version": model_version,
                "metric": r.get("metric"),
                "evidence_source": r.get("evidence_source"),
                "status": r.get("status"),
                "completeness_pct": r.get("completeness_pct"),
                "interpretation": r.get("interpretation"),
            }
            for r in rows.get("h5_governance_results.csv", [])
        ],
    )
    return counts


def _resolve_step4_context(
    cur: Any,
    requested_model_version: str | None = None,
    requested_step1_run_id: str | None = None,
    requested_step2_model_id: str | None = None,
    requested_step2_run_id: str | None = None,
    requested_step3_v2_sim_id: str | None = None,
) -> dict[str, Any]:
    resolved_model_version = str(requested_model_version or "").strip()
    requested_step1_run_id = str(requested_step1_run_id or "").strip()
    requested_step2_model_id = str(requested_step2_model_id or "").strip()
    requested_step2_run_id = str(requested_step2_run_id or "").strip()
    requested_step3_v2_sim_id = str(requested_step3_v2_sim_id or "").strip()

    if requested_step1_run_id and not _is_uuid_like(requested_step1_run_id):
        raise RuntimeError("invalid_step1_run_id")
    if requested_step2_run_id and not _is_uuid_like(requested_step2_run_id):
        raise RuntimeError("invalid_step2_run_id")
    if requested_step2_model_id and not _is_uuid_like(requested_step2_model_id):
        raise RuntimeError("invalid_step2_model_id")
    if requested_step3_v2_sim_id and not _is_uuid_like(requested_step3_v2_sim_id):
        raise RuntimeError("invalid_step3_v2_sim_id")
    if requested_step1_run_id:
        cur.execute(
            """
            SELECT 1
            FROM phase4.workflow_runs
            WHERE step_name='step1' AND run_id = %(rid)s::uuid
            LIMIT 1;
            """,
            {"rid": requested_step1_run_id},
        )
        if not cur.fetchone():
            raise RuntimeError("step1_run_not_found")

    step3_v2 = _query_step3_v2_by_sim_id(cur, requested_step3_v2_sim_id) if requested_step3_v2_sim_id else {}
    if requested_step3_v2_sim_id and not step3_v2:
        raise RuntimeError("step3_v2_sim_not_found")

    step3_v2_model_id = str(step3_v2.get("model_id") or "").strip()
    if requested_step2_model_id and step3_v2_model_id and requested_step2_model_id != step3_v2_model_id:
        raise RuntimeError("step3_v2_model_id_mismatch")
    selected_model_id = requested_step2_model_id or step3_v2_model_id
    if requested_step3_v2_sim_id and not selected_model_id:
        raise RuntimeError("step3_v2_sim_model_id_missing")
    model_row = _query_model_registry_by_model_id(cur, selected_model_id) if selected_model_id else {}
    if requested_step2_model_id and not model_row:
        raise RuntimeError("step2_model_not_found")
    if requested_step3_v2_sim_id and selected_model_id and not model_row:
        raise RuntimeError("model_registry_missing_for_sim_model")

    model_row_mv = str(model_row.get("model_version") or "").strip()
    step3_v2_mv = str(step3_v2.get("model_version") or "").strip()
    if model_row_mv:
        if resolved_model_version and model_row_mv != resolved_model_version:
            raise RuntimeError("step2_model_version_mismatch")
        resolved_model_version = model_row_mv
    if step3_v2_mv:
        if resolved_model_version and step3_v2_mv != resolved_model_version:
            raise RuntimeError("step3_v2_model_version_mismatch")
        resolved_model_version = step3_v2_mv

    source_step1_hint = requested_step1_run_id or str(model_row.get("source_step1_run_id") or "").strip()
    model_step1_run_id = str(model_row.get("source_step1_run_id") or "").strip()
    if requested_step1_run_id and model_step1_run_id and requested_step1_run_id != model_step1_run_id:
        raise RuntimeError("step1_run_model_mismatch")

    step2_selection_rule = "latest_step2_fallback"
    if requested_step2_run_id:
        step2 = _query_step2_by_run_id(cur, requested_step2_run_id)
        step2_selection_rule = "step2_by_run_id"
        if not step2:
            raise RuntimeError("step2_run_not_found")
    elif selected_model_id and requested_step3_v2_sim_id:
        step2 = _query_step2_by_lineage(
            cur,
            model_id=selected_model_id,
            model_version=resolved_model_version or None,
            source_step1_run_id=source_step1_hint or None,
        )
        step2_selection_rule = "step2_by_strict_lineage(model_id,model_version,source_step1_run_id)"
        if not step2:
            raise RuntimeError("step2_run_not_found_for_sim_lineage")
    elif selected_model_id:
        step2 = _query_latest_step2_for_model_id(
            cur,
            selected_model_id,
            model_version=resolved_model_version or None,
            source_step1_run_id=source_step1_hint or None,
        )
        step2_selection_rule = "step2_by_model_id_latest"
        if not step2:
            raise RuntimeError("step2_run_not_found_for_model")
    else:
        step2 = _query_latest_step2(cur, resolved_model_version or None)
        step2_selection_rule = "latest_step2_fallback"
    metrics = step2.get("metrics") if isinstance(step2.get("metrics"), dict) else {}

    step2_metrics_model_id = str(metrics.get("model_id") or "").strip()
    step2_metrics_mv = str(metrics.get("model_version") or "").strip()
    step2_legacy_model_id = bool(step2_metrics_model_id) and step2_metrics_model_id in {
        step2_metrics_mv,
        str(resolved_model_version or "").strip(),
    }
    if selected_model_id and step2_metrics_model_id and selected_model_id != step2_metrics_model_id and not step2_legacy_model_id:
        raise RuntimeError("step2_run_model_id_mismatch")
    if step3_v2_model_id and step2_metrics_model_id and step3_v2_model_id != step2_metrics_model_id and not step2_legacy_model_id:
        raise RuntimeError("step2_run_step3_v2_model_mismatch")

    if step2_metrics_mv:
        if resolved_model_version and step2_metrics_mv != resolved_model_version:
            raise RuntimeError("step2_run_model_version_mismatch")
        resolved_model_version = step2_metrics_mv
    if not resolved_model_version:
        raise RuntimeError("no_step2_model_version_found")

    model_id = (
        selected_model_id
        or str(model_row.get("model_id") or "").strip()
        or str(metrics.get("model_id") or "").strip()
        or str(step3_v2.get("model_id") or "").strip()
        or resolved_model_version
    )

    source_step1_run_id = (
        source_step1_hint
        or str(model_row.get("source_step1_run_id") or "").strip()
        or str(metrics.get("source_step1_run_id") or "").strip()
    )
    metrics_step1_run_id = str(metrics.get("source_step1_run_id") or "").strip()
    if requested_step1_run_id and metrics_step1_run_id and requested_step1_run_id != metrics_step1_run_id:
        raise RuntimeError("step1_run_step2_mismatch")

    replay_run_id = ""
    replay_status = ""
    step3: dict[str, Any] = {}
    step3_v2_sim_id = ""

    if step3_v2:
        step3 = step3_v2
        step3_v2_sim_id = str(step3_v2.get("simulation_id") or "")
        replay_status = str(step3_v2.get("status") or "").strip()
    else:
        step3 = _query_latest_step3(cur, resolved_model_version)
        replay_run_id = str(step3.get("replay_run_id") or "")
        replay_status = str(step3.get("status") or "").strip()

    if replay_run_id and not source_step1_run_id:
        cur.execute(
            """
            SELECT source_step1_run_id
            FROM phase4.replay_runs
            WHERE replay_run_id = %(rid)s::uuid
            LIMIT 1;
            """,
            {"rid": replay_run_id},
        )
        rr = cur.fetchone()
        if rr:
            source_step1_run_id = str(rr[0] or "").strip()

    experiment_id = str(
        metrics.get("training_result", {}).get("metrics", {}).get("experiment_id")
        or metrics.get("training_result", {}).get("experiment_id")
        or DEFAULT_EXPERIMENT_ID
    ).strip() or DEFAULT_EXPERIMENT_ID

    lineage_resolution = {
        "requested_model_version": str(requested_model_version or "").strip(),
        "requested_step1_run_id": requested_step1_run_id,
        "requested_step2_model_id": requested_step2_model_id,
        "requested_step2_run_id": requested_step2_run_id,
        "requested_step3_v2_sim_id": requested_step3_v2_sim_id,
        "resolved_model_id": model_id,
        "resolved_model_version": resolved_model_version,
        "resolved_step1_run_id": source_step1_run_id,
        "resolved_step2_run_id": str(step2.get("run_id") or ""),
        "resolved_replay_run_id": replay_run_id,
        "resolved_step3_v2_sim_id": step3_v2_sim_id,
        "step2_selection_rule": step2_selection_rule,
        "resolved_at_utc": datetime.now(timezone.utc).isoformat(),
    }

    return {
        "resolved_model_version": resolved_model_version,
        "resolved_model_id": model_id,
        "source_step1_run_id": source_step1_run_id,
        "source_step2_run_id": str(step2.get("run_id") or ""),
        "replay_run_id": replay_run_id,
        "replay_status": replay_status,
        "step3_v2_sim_id": step3_v2_sim_id,
        "experiment_id": experiment_id,
        "step2": step2,
        "step3": step3,
        "step1": _query_step1_by_run_id(cur, source_step1_run_id) if _is_uuid_like(source_step1_run_id) else {},
        "lineage_resolution": lineage_resolution,
        "requested": {
            "model_version": str(requested_model_version or "").strip(),
            "step1_run_id": requested_step1_run_id,
            "step2_model_id": requested_step2_model_id,
            "step2_run_id": requested_step2_run_id,
            "step3_v2_sim_id": requested_step3_v2_sim_id,
        },
    }


def _lineage_filter_sql(context: dict[str, Any], *, include_replay: bool = True) -> tuple[str, dict[str, Any]]:
    params: dict[str, Any] = {
        "mv": str(context.get("resolved_model_version") or ""),
    }
    clauses = ["model_version = %(mv)s"]
    model_id = str(context.get("resolved_model_id") or "").strip()
    step1_run_id = str(context.get("source_step1_run_id") or "").strip()
    step2_run_id = str(context.get("source_step2_run_id") or "").strip()
    replay_run_id = str(context.get("replay_run_id") or "").strip()

    if model_id:
        clauses.append("model_id = %(mid)s")
        params["mid"] = model_id
    if step1_run_id:
        clauses.append("source_step1_run_id = %(s1)s")
        params["s1"] = step1_run_id
    if step2_run_id:
        clauses.append("source_step2_run_id = %(s2)s")
        params["s2"] = step2_run_id
    if include_replay and replay_run_id:
        clauses.append("replay_run_id = %(rr)s")
        params["rr"] = replay_run_id
    return " AND ".join(clauses), params


def _fetch_hypothesis_tables(cur: Any, context: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {
        "h1_1": [],
        "h1_2": [],
        "h1_3": [],
        "h1_4": [],
        "h1_5": [],
    }
    where_lineage, params_lineage = _lineage_filter_sql(context, include_replay=True)
    cur.execute(
        f"""
        SELECT
          model_version, dataset, alert_count, filtered_alerts, parent_review_completion, triage_proxy, interpretation
        FROM phase4.h1_workflow_efficiency_results
        WHERE {where_lineage}
        ORDER BY id ASC;
        """,
        params_lineage,
    )
    out["h1_1"] = [
        {
            "model_version": str(r[0] or ""),
            "dataset": str(r[1] or ""),
            "alert_count": str(r[2] or ""),
            "filtered_alerts": str(r[3] or ""),
            "parent_review_completion": str(r[4] or ""),
            "triage_proxy": str(r[5] or ""),
            "interpretation": str(r[6] or ""),
        }
        for r in (cur.fetchall() or [])
    ]

    cur.execute(
        f"""
        SELECT
          dataset, domain_accuracy, protocol_coverage, vector_coverage, scope_match_accuracy, interpretation
        FROM phase4.h1_categorization_results
        WHERE {where_lineage}
        ORDER BY id ASC;
        """,
        params_lineage,
    )
    out["h1_2"] = [
        {
            "dataset": str(r[0] or ""),
            "domain_accuracy": str(r[1] or ""),
            "protocol_coverage": str(r[2] or ""),
            "vector_coverage": str(r[3] or ""),
            "scope_match_accuracy": str(r[4] or ""),
            "interpretation": str(r[5] or ""),
        }
        for r in (cur.fetchall() or [])
    ]

    cur.execute(
        f"""
        SELECT
          child_scope, observed_behavior, expected_scope, cross_scope_detected,
          escalation_correct, severity_level, interpretation
        FROM phase4.h1_cross_scope_results
        WHERE {where_lineage}
        ORDER BY id ASC;
        """,
        params_lineage,
    )
    out["h1_3"] = [
        {
            "child_scope": str(r[0] or ""),
            "observed_behavior": str(r[1] or ""),
            "expected_scope": str(r[2] or ""),
            "cross_scope_detected": str(r[3] or ""),
            "escalation_correct": str(r[4] or ""),
            "severity_level": str(r[5] or ""),
            "interpretation": str(r[6] or ""),
        }
        for r in (cur.fetchall() or [])
    ]

    cur.execute(
        f"""
        SELECT
          model_version, explanation_coverage, top_features_consistency,
          explanation_clarity, triage_support_score, interpretation
        FROM phase4.h1_shap_triage_results
        WHERE {where_lineage}
        ORDER BY id ASC;
        """,
        params_lineage,
    )
    out["h1_4"] = [
        {
            "model_version": str(r[0] or ""),
            "explanation_coverage": str(r[1] or ""),
            "top_features_consistency": str(r[2] or ""),
            "explanation_clarity": str(r[3] or ""),
            "triage_support_score": str(r[4] or ""),
            "interpretation": str(r[5] or ""),
        }
        for r in (cur.fetchall() or [])
    ]

    cur.execute(
        f"""
        SELECT
          metric, evidence_source, status, completeness_pct, interpretation
        FROM phase4.h1_governance_traceability_results
        WHERE {where_lineage}
        ORDER BY id ASC;
        """,
        params_lineage,
    )
    out["h1_5"] = [
        {
            "metric": str(r[0] or ""),
            "evidence_source": str(r[1] or ""),
            "status": str(r[2] or ""),
            "completeness_pct": str(r[3] or ""),
            "interpretation": str(r[4] or ""),
        }
        for r in (cur.fetchall() or [])
    ]
    return out


def _fetch_csv_status(cur: Any, context: dict[str, Any]) -> list[dict[str, Any]]:
    model_version = str(context.get("resolved_model_version") or "")
    step2_run_id = str(context.get("source_step2_run_id") or "").strip()
    replay_run_id = str(context.get("replay_run_id") or "").strip()
    step3_v2_sim_id = str(context.get("step3_v2_sim_id") or "").strip()
    where_lineage, params_lineage = _lineage_filter_sql(context, include_replay=True)

    table_map = {
        "detection_metrics.csv": "phase4.model_per_class_metrics",
        "per_class_metrics.csv": "phase4.model_per_class_metrics",
        "confusion_matrix.csv": "phase4.model_per_class_metrics",
        "cross_dataset_robustness.csv": "phase4.cross_dataset_test_runs",
        "shap_explanations.csv": "phase4.shap_logs",
        "replay_phase_results.csv": "phase4.step3_replay_phases",
        "operational_metrics.csv": "phase4.step3_replay_metrics",
        "governance_traceability.csv": "phase4.step3_alerts",
        "within_dataset_results.csv": "phase4.results_within_dataset",
        "cross_dataset_results.csv": "phase4.results_cross_dataset",
        "categorization_results.csv": "phase4.results_categorization",
        "cross_scope_results.csv": "phase4.results_cross_scope",
        "shap_results.csv": "phase4.results_shap",
        "rule_validation_results.csv": "phase4.results_rule_validation",
        "replay_results.csv": "phase4.results_replay",
        "governance_results.csv": "phase4.results_governance",
        "h1_workflow_results.csv": "phase4.h1_workflow_efficiency_results",
        "h2_categorization_results.csv": "phase4.h1_categorization_results",
        "h3_cross_scope_results.csv": "phase4.h1_cross_scope_results",
        "h4_shap_results.csv": "phase4.h1_shap_triage_results",
        "h5_governance_results.csv": "phase4.h1_governance_traceability_results",
    }
    out: list[dict[str, Any]] = []
    for file_name, fields in CSV_FIELDS.items():
        table_name = table_map.get(file_name)
        count = 0
        if table_name == "phase4.model_per_class_metrics":
            if _is_uuid_like(step2_run_id):
                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM phase4.model_per_class_metrics
                    WHERE run_id = %(rid)s::uuid;
                    """,
                    {"rid": step2_run_id},
                )
            else:
                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM phase4.model_per_class_metrics
                    WHERE model_version = %(mv)s;
                    """,
                    {"mv": model_version},
                )
            count = int((cur.fetchone() or [0])[0] or 0)
        elif table_name == "phase4.cross_dataset_test_runs":
            if _is_uuid_like(step2_run_id):
                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM phase4.cross_dataset_test_runs
                    WHERE run_id = %(rid)s::uuid;
                    """,
                    {"rid": step2_run_id},
                )
            else:
                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM phase4.cross_dataset_test_runs
                    WHERE model_version = %(mv)s;
                    """,
                    {"mv": model_version},
                )
            count = int((cur.fetchone() or [0])[0] or 0)
        elif table_name == "phase4.shap_logs":
            if replay_run_id:
                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM phase4.shap_logs
                    WHERE model_version = %(mv)s
                      AND COALESCE(replay_id, '') = %(replay_id)s;
                    """,
                    {"mv": model_version, "replay_id": replay_run_id},
                )
            elif step3_v2_sim_id:
                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM phase4.shap_logs
                    WHERE model_version = %(mv)s
                      AND COALESCE(replay_id, '') IN ('', %(sim_id)s);
                    """,
                    {"mv": model_version, "sim_id": step3_v2_sim_id},
                )
            else:
                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM phase4.shap_logs
                    WHERE model_version = %(mv)s;
                    """,
                    {"mv": model_version},
                )
            count = int((cur.fetchone() or [0])[0] or 0)
        elif table_name == "phase4.step3_replay_phases":
            if _is_uuid_like(replay_run_id):
                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM phase4.step3_replay_phases
                    WHERE replay_run_id = %(rid)s::uuid;
                    """,
                    {"rid": replay_run_id},
                )
                count = int((cur.fetchone() or [0])[0] or 0)
            elif _is_uuid_like(step3_v2_sim_id):
                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM (
                        SELECT COALESCE(NULLIF(phase, ''), COALESCE(NULLIF(payload->>'phase', ''), 'runtime')) AS phase_name
                        FROM phase4.step3_v2_alerts
                        WHERE simulation_id = %(sid)s::uuid
                        GROUP BY 1
                    ) q;
                    """,
                    {"sid": step3_v2_sim_id},
                )
                count = int((cur.fetchone() or [0])[0] or 0)
            else:
                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM phase4.step3_replay_phases rp
                    INNER JOIN phase4.replay_runs rr ON rr.replay_run_id = rp.replay_run_id
                    WHERE rr.model_version = %(mv)s;
                    """,
                    {"mv": model_version},
                )
                count = int((cur.fetchone() or [0])[0] or 0)
        elif table_name == "phase4.step3_replay_metrics":
            if _is_uuid_like(replay_run_id):
                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM phase4.step3_replay_metrics
                    WHERE replay_run_id = %(rid)s::uuid;
                    """,
                    {"rid": replay_run_id},
                )
            elif step3_v2_sim_id:
                count = 1
            else:
                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM phase4.step3_replay_metrics
                    WHERE model_version = %(mv)s;
                    """,
                    {"mv": model_version},
                )
                count = int((cur.fetchone() or [0])[0] or 0)
        elif table_name == "phase4.step3_alerts":
            if _is_uuid_like(replay_run_id):
                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM phase4.step3_alerts
                    WHERE replay_run_id = %(rid)s::uuid;
                    """,
                    {"rid": replay_run_id},
                )
                count = int((cur.fetchone() or [0])[0] or 0)
            elif _is_uuid_like(step3_v2_sim_id):
                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM phase4.step3_v2_alerts
                    WHERE simulation_id = %(sid)s::uuid;
                    """,
                    {"sid": step3_v2_sim_id},
                )
                count = int((cur.fetchone() or [0])[0] or 0)
            else:
                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM phase4.step3_alerts a
                    INNER JOIN phase4.replay_runs rr ON rr.replay_run_id = a.replay_run_id
                    WHERE rr.model_version = %(mv)s;
                    """,
                    {"mv": model_version},
                )
                count = int((cur.fetchone() or [0])[0] or 0)
        elif table_name in {
            "phase4.results_within_dataset",
            "phase4.results_cross_dataset",
            "phase4.results_categorization",
            "phase4.results_cross_scope",
            "phase4.results_shap",
            "phase4.results_rule_validation",
            "phase4.results_replay",
            "phase4.results_governance",
            "phase4.h1_workflow_efficiency_results",
            "phase4.h1_categorization_results",
            "phase4.h1_cross_scope_results",
            "phase4.h1_shap_triage_results",
            "phase4.h1_governance_traceability_results",
        }:
            cur.execute(
                f"SELECT COUNT(*)::bigint FROM {table_name} WHERE {where_lineage};",
                params_lineage,
            )
            count = int((cur.fetchone() or [0])[0] or 0)
        elif table_name:
            cur.execute(
                f"""
                SELECT COUNT(*)::bigint
                FROM {table_name}
                WHERE model_version = %(mv)s;
                """,
                {"mv": model_version},
            )
            count = int((cur.fetchone() or [0])[0] or 0)
        out.append(
            {
                "file": file_name,
                "required_columns": len(fields),
                "row_count": count,
                "has_data": count > 0,
            }
        )
    mstatus = _fetch_metrics_required_status(cur, context)
    out.append(
        {
            "file": "metrics_required_matrix.csv",
            "required_columns": len(METRICS_REQUIRED_MATRIX_FIELDS),
            "row_count": int(mstatus.get("row_count") or 0),
            "has_data": int(mstatus.get("row_count") or 0) > 0,
        }
    )
    out.append(
        {
            "file": "metrics_required_matrix.json",
            "required_columns": 0,
            "row_count": int(mstatus.get("row_count") or 0),
            "has_data": int(mstatus.get("row_count") or 0) > 0,
        }
    )
    out.append(
        {
            "file": "lineage_resolution.json",
            "required_columns": 0,
            "row_count": 1 if _non_empty_value(context.get("resolved_model_version")) else 0,
            "has_data": bool(_non_empty_value(context.get("resolved_model_version"))),
        }
    )
    return out


def _ensure_metrics_required_matrix_table(cur: Any) -> None:
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS phase4.results_metrics_required_matrix (
            id bigserial PRIMARY KEY,
            metric_name text NOT NULL,
            value text,
            unit text,
            status text NOT NULL,
            source_kind text,
            source_ref text,
            lineage_step1_run_id text,
            lineage_step2_run_id text,
            lineage_model_id text,
            lineage_model_version text,
            lineage_sim_id text,
            measured_at_utc timestamptz,
            metric_group text,
            status_rule text,
            generated_at_utc timestamptz NOT NULL DEFAULT now()
        );
        """
    )
    cur.execute(
        """
        ALTER TABLE IF EXISTS phase4.results_metrics_required_matrix
        ADD COLUMN IF NOT EXISTS generated_at_utc timestamptz NOT NULL DEFAULT now();
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_results_metrics_required_lineage
            ON phase4.results_metrics_required_matrix(
                lineage_model_version, lineage_model_id, lineage_step1_run_id, lineage_step2_run_id, lineage_sim_id
            );
        """
    )


def _build_metrics_required_matrix(
    cur: Any,
    *,
    context: dict[str, Any],
    csv_rows: dict[str, list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    catalog = _load_metrics_required_catalog()
    if not catalog:
        return [], [], {"total_required": 0, "measured_count": 0, "not_collected_count": 0, "not_applicable_count": 0}

    step1 = context.get("step1") if isinstance(context.get("step1"), dict) else {}
    step2 = context.get("step2") if isinstance(context.get("step2"), dict) else {}
    step3 = context.get("step3") if isinstance(context.get("step3"), dict) else {}
    step1_metrics = step1.get("metrics") if isinstance(step1.get("metrics"), dict) else {}
    step2_metrics = step2.get("metrics") if isinstance(step2.get("metrics"), dict) else {}
    step3_metrics = step3.get("metrics") if isinstance(step3.get("metrics"), dict) else {}
    step3_timeline = step3.get("timeline") if isinstance(step3.get("timeline"), dict) else {}
    governance_traceability = (
        step2_metrics.get("governance_traceability")
        if isinstance(step2_metrics.get("governance_traceability"), dict)
        else {}
    )
    shap_stage_metrics = (
        step2_metrics.get("shap_stage_metrics")
        if isinstance(step2_metrics.get("shap_stage_metrics"), dict)
        else {}
    )
    training_metrics = _nested_get(step2_metrics, ["training_result", "metrics"])
    training_metrics = training_metrics if isinstance(training_metrics, dict) else {}
    step2_primary_track = str(training_metrics.get("primary_supervised_model") or "random_forest").strip() or "random_forest"
    certainty_eligible_metrics = _load_principle_certainty_eligible_metrics()

    step2_completed_at = ""
    if _is_uuid_like(context.get("source_step2_run_id")):
        cur.execute(
            """
            SELECT completed_at_utc
            FROM phase4.workflow_runs
            WHERE run_id = %(rid)s::uuid
            LIMIT 1;
            """,
            {"rid": context.get("source_step2_run_id")},
        )
        step2_completed_at = _to_utc_iso((cur.fetchone() or [None])[0])
    step1_completed_at = str(step1.get("completed_at_utc") or "")
    step3_measured_at = str(step3_timeline.get("step3_v2_measured_at_utc") or "")

    evidence: dict[str, dict[str, Any]] = {}

    def _set_evidence(
        metric_name: str,
        *,
        value: Any,
        unit: str,
        source_kind: str,
        source_ref: str,
        measured_at: str,
        priority: int,
    ) -> None:
        if not _non_empty_value(value):
            return
        prev = evidence.get(metric_name)
        if prev and int(prev.get("_priority") or 999) <= priority:
            return
        evidence[metric_name] = {
            "_priority": priority,
            "value": value,
            "unit": unit,
            "source_kind": source_kind,
            "source_ref": source_ref,
            "measured_at_utc": measured_at,
        }

    def _load_unified_metrics(step_name: str, step_unique_id: str) -> list[dict[str, Any]]:
        sid = str(step_unique_id or "").strip()
        if not sid:
            return []
        cur.execute(
            """
            SELECT metric, metric_value, status, calculation_status, details_json, updatedat
            FROM phase4.metrics
            WHERE step = %(step)s
              AND step_unique_id = %(sid)s
            ORDER BY updatedat DESC;
            """,
            {"step": step_name, "sid": sid},
        )
        out_rows: list[dict[str, Any]] = []
        for metric, metric_value, status, calculation_status, details_json, updated_at in cur.fetchall() or []:
            out_rows.append(
                {
                    "metric_name": str(metric or ""),
                    "metric_value": metric_value,
                    "status": str(status or ""),
                    "calculation_status": str(calculation_status or ""),
                    "details_json": _parse_json_dict(details_json),
                    "updatedat": _to_utc_iso(updated_at),
                }
            )
        return out_rows

    unified_sources = [
        ("step1", str(context.get("source_step1_run_id") or ""), step1_completed_at),
        ("step2", str(context.get("resolved_model_id") or ""), step2_completed_at),
        (
            "step3",
            (
                str(context.get("step3_v2_sim_id") or "")
                or str(context.get("replay_run_id") or "")
            ),
            step3_measured_at,
        ),
    ]
    for step_name, sid, default_measured_at in unified_sources:
        for row in _load_unified_metrics(step_name, sid):
            metric_name = str(row.get("metric_name") or "")
            if not metric_name:
                continue
            calc_status = str(row.get("calculation_status") or "").strip().lower()
            if calc_status != "measured":
                continue
            details = row.get("details_json") if isinstance(row.get("details_json"), dict) else {}
            _set_evidence(
                metric_name,
                value=row.get("metric_value"),
                unit=str(details.get("unit") or ""),
                source_kind="postgres_relational",
                source_ref=str(details.get("source_ref") or "phase4.metrics"),
                measured_at=str(row.get("updatedat") or default_measured_at),
                priority=-2,
            )

    # Priority -1: Step 1 run-scoped persisted metrics are fallback source for Step 1 rows.
    step1_metric_evidence = _load_step1_metric_results_evidence(
        cur,
        step1_run_id=str(context.get("source_step1_run_id") or ""),
        step1_metrics=step1_metrics,
    )
    for metric_name, row in step1_metric_evidence.items():
        row_status = str(row.get("status") or "").strip().lower()
        if row_status and row_status != "measured":
            continue
        _set_evidence(
            metric_name,
            value=row.get("value"),
            unit=STEP1_METRIC_UNIT_OVERRIDES.get(metric_name, "ratio"),
            source_kind="postgres_relational",
            source_ref=str(row.get("source_ref") or "phase4.metrics"),
            measured_at=str(row.get("measured_at_utc") or step1_completed_at),
            priority=-1,
        )

    # Priority 0: certainty-eligible deterministic derivations (yes / yes-derived).
    split_integrity = _derive_split_integrity_rate(step1_metrics)
    _set_evidence(
        "split_integrity_rate",
        value=split_integrity,
        unit="ratio",
        source_kind="postgres_json",
        source_ref="phase4.workflow_runs.run_metrics.reconciliation.datasets.*.ok",
        measured_at=step1_completed_at or step2_completed_at,
        priority=0,
    )

    audit_completeness = _derive_audit_completeness(
        cur,
        step1_run_id=str(context.get("source_step1_run_id") or ""),
        step2_run_id=str(context.get("source_step2_run_id") or ""),
        replay_run_id=str(context.get("replay_run_id") or ""),
        step3_v2_sim_id=str(context.get("step3_v2_sim_id") or ""),
    )
    _set_evidence(
        "audit_completeness",
        value=audit_completeness,
        unit="ratio",
        source_kind="postgres_relational",
        source_ref="phase4.audit_log(event_type,event_details_json.context)",
        measured_at=step3_measured_at or step2_completed_at or step1_completed_at,
        priority=0,
    )

    cross_dataset_ratio = _derive_cross_dataset_robustness(step2_metrics, step2_primary_track)
    _set_evidence(
        "cross_dataset_robustness",
        value=cross_dataset_ratio,
        unit="ratio",
        source_kind="postgres_json",
        source_ref="phase4.workflow_runs.run_metrics.{within_dataset_results,cross_dataset_results}",
        measured_at=step2_completed_at or step1_completed_at,
        priority=0,
    )

    alert_level_expl_coverage = _derive_alert_level_explanation_coverage(
        cur,
        replay_run_id=str(context.get("replay_run_id") or ""),
    )
    if _non_empty_value(alert_level_expl_coverage):
        _set_evidence(
            "explanation_coverage",
            value=alert_level_expl_coverage,
            unit="ratio",
            source_kind="postgres_relational",
            source_ref="phase4.step3_alerts.{shap_evidence_status,shap_evidence_id}",
            measured_at=step3_measured_at or step2_completed_at,
            priority=0,
        )
    else:
        offline_cov = _nested_get(shap_stage_metrics, ["coverage_by_split", "test"])
        _set_evidence(
            "explanation_coverage",
            value=offline_cov,
            unit="ratio",
            source_kind="postgres_json",
            source_ref="phase4.workflow_runs.run_metrics.shap_stage_metrics.coverage_by_split.test",
            measured_at=step2_completed_at or step1_completed_at,
            priority=0,
        )

    rule_hit_rate = _derive_rule_hit_rate(step2_metrics)
    _set_evidence(
        "rule_hit_rate",
        value=rule_hit_rate,
        unit="ratio",
        source_kind="postgres_json",
        source_ref="phase4.workflow_runs.run_metrics.rule_validation_summary.rep01_packet_validation",
        measured_at=step2_completed_at or step1_completed_at,
        priority=0,
    )

    child_escalation_rate = _derive_child_escalation_rate(
        cur,
        replay_run_id=str(context.get("replay_run_id") or ""),
        step3_v2_sim_id=str(context.get("step3_v2_sim_id") or ""),
        step3_metrics=step3_metrics,
    )
    _set_evidence(
        "child_escalation_rate",
        value=child_escalation_rate,
        unit="ratio",
        source_kind="postgres_relational",
        source_ref="phase4.step3_replay_metrics|phase4.step3_alerts|phase4.parent_actions|phase4.step3_v2_*",
        measured_at=step3_measured_at or step2_completed_at,
        priority=0,
    )

    enrichment_completeness = _derive_enrichment_completeness(
        cur,
        replay_run_id=str(context.get("replay_run_id") or ""),
    )
    _set_evidence(
        "enrichment_completeness",
        value=enrichment_completeness,
        unit="ratio",
        source_kind="postgres_relational",
        source_ref="phase4.step3_alerts.{expected_environment,observed_environment,escalation_reason,payload}",
        measured_at=step3_measured_at or step2_completed_at,
        priority=0,
    )

    recommendation_rate = _derive_recommendation_rate(
        cur,
        replay_run_id=str(context.get("replay_run_id") or ""),
        step3_v2_sim_id=str(context.get("step3_v2_sim_id") or ""),
        step3_metrics=step3_metrics,
    )
    _set_evidence(
        "recommendation_rate",
        value=recommendation_rate,
        unit="ratio",
        source_kind="postgres_relational",
        source_ref="phase4.parent_actions|phase4.step3_v2_parent_actions",
        measured_at=step3_measured_at or step2_completed_at,
        priority=0,
    )

    # Priority 1: relational measurements.
    if _is_uuid_like(context.get("source_step2_run_id")):
        cur.execute(
            """
            SELECT precision, recall, f1, macro_f1, fpr, fnr, accuracy, created_at_utc
            FROM phase4.model_per_class_metrics
            WHERE run_id = %(rid)s::uuid
              AND COALESCE(evaluation_mode, '') = 'within_dataset'
              AND COALESCE(model_track, '') = %(track)s
            ORDER BY created_at_utc DESC
            LIMIT 1;
            """,
            {"rid": context.get("source_step2_run_id"), "track": step2_primary_track},
        )
        perf = cur.fetchone()
        if not perf:
            cur.execute(
                """
                SELECT precision, recall, f1, macro_f1, fpr, fnr, accuracy, created_at_utc
                FROM phase4.model_per_class_metrics
                WHERE run_id = %(rid)s::uuid
                  AND COALESCE(evaluation_mode, '') = 'within_dataset'
                ORDER BY created_at_utc DESC
                LIMIT 1;
                """,
                {"rid": context.get("source_step2_run_id")},
            )
            perf = cur.fetchone()
        if perf:
            measured_at = _to_utc_iso(perf[7]) or step2_completed_at
            _set_evidence("precision", value=perf[0], unit="ratio", source_kind="postgres_relational", source_ref="phase4.model_per_class_metrics.precision", measured_at=measured_at, priority=1)
            _set_evidence("recall", value=perf[1], unit="ratio", source_kind="postgres_relational", source_ref="phase4.model_per_class_metrics.recall", measured_at=measured_at, priority=1)
            _set_evidence("f1_score", value=perf[2], unit="ratio", source_kind="postgres_relational", source_ref="phase4.model_per_class_metrics.f1", measured_at=measured_at, priority=1)
            _set_evidence("macro_f1", value=perf[3], unit="ratio", source_kind="postgres_relational", source_ref="phase4.model_per_class_metrics.macro_f1", measured_at=measured_at, priority=1)
            _set_evidence("false_positive_rate", value=perf[4], unit="ratio", source_kind="postgres_relational", source_ref="phase4.model_per_class_metrics.fpr", measured_at=measured_at, priority=1)
            _set_evidence("false_negative_rate", value=perf[5], unit="ratio", source_kind="postgres_relational", source_ref="phase4.model_per_class_metrics.fnr", measured_at=measured_at, priority=1)
            _set_evidence("accuracy", value=perf[6], unit="ratio", source_kind="postgres_relational", source_ref="phase4.model_per_class_metrics.accuracy", measured_at=measured_at, priority=1)

        cur.execute(
            """
            SELECT metrics_json, completed_at_utc
            FROM phase4.model_training_runs
            WHERE run_id = %(rid)s::uuid
            ORDER BY COALESCE(completed_at_utc, started_at_utc) DESC
            LIMIT 1;
            """,
            {"rid": context.get("source_step2_run_id")},
        )
        tr = cur.fetchone()
        if tr:
            trm = _parse_json_dict(tr[0])
            measured_at = _to_utc_iso(tr[1]) or step2_completed_at
            _set_evidence("selected_feature_count", value=trm.get("feature_count"), unit="count", source_kind="postgres_relational", source_ref="phase4.model_training_runs.metrics_json.feature_count", measured_at=measured_at, priority=1)
            _set_evidence("feature_reduction_ratio", value=trm.get("feature_reduction_ratio"), unit="ratio", source_kind="postgres_relational", source_ref="phase4.model_training_runs.metrics_json.feature_reduction_ratio", measured_at=measured_at, priority=1)
            _set_evidence("training_time_seconds", value=trm.get("duration_s"), unit="seconds", source_kind="postgres_relational", source_ref="phase4.model_training_runs.metrics_json.duration_s", measured_at=measured_at, priority=1)
            _set_evidence("pareto_rank", value=trm.get("pareto_rank"), unit="count", source_kind="postgres_relational", source_ref="phase4.model_training_runs.metrics_json.pareto_rank", measured_at=measured_at, priority=1)

        cur.execute(
            """
            SELECT metrics_json, completed_at_utc
            FROM phase4.model_evaluation_runs
            WHERE run_id = %(rid)s::uuid
            ORDER BY COALESCE(completed_at_utc, started_at_utc) DESC
            LIMIT 1;
            """,
            {"rid": context.get("source_step2_run_id")},
        )
        er = cur.fetchone()
        if er:
            em = _parse_json_dict(er[0])
            measured_at = _to_utc_iso(er[1]) or step2_completed_at
            _set_evidence("inference_latency_ms", value=em.get("inference_latency_ms"), unit="ms", source_kind="postgres_relational", source_ref="phase4.model_evaluation_runs.metrics_json.inference_latency_ms", measured_at=measured_at, priority=1)
            _set_evidence("cross_dataset_robustness", value=em.get("cross_dataset_robustness"), unit="ratio", source_kind="postgres_relational", source_ref="phase4.model_evaluation_runs.metrics_json.cross_dataset_robustness", measured_at=measured_at, priority=1)

        cur.execute(
            """
            SELECT metrics_json, completed_at_utc
            FROM phase4.cross_dataset_test_runs
            WHERE run_id = %(rid)s::uuid
            ORDER BY COALESCE(completed_at_utc, started_at_utc) DESC
            LIMIT 1;
            """,
            {"rid": context.get("source_step2_run_id")},
        )
        cdr = cur.fetchone()
        if cdr:
            cdm = _parse_json_dict(cdr[0])
            measured_at = _to_utc_iso(cdr[1]) or step2_completed_at
            _set_evidence("cross_dataset_robustness", value=cdm.get("cross_dataset_robustness"), unit="ratio", source_kind="postgres_relational", source_ref="phase4.cross_dataset_test_runs.metrics_json.cross_dataset_robustness", measured_at=measured_at, priority=1)

    feedback_params: dict[str, Any] = {"mv": str(context.get("resolved_model_version") or "")}
    feedback_where = "model_version = %(mv)s"
    replay_run_id = str(context.get("replay_run_id") or "").strip()
    step3_sim_id = str(context.get("step3_v2_sim_id") or "").strip()
    if _is_uuid_like(replay_run_id):
        feedback_where += " AND replay_run_id = %(rid)s::uuid"
        feedback_params["rid"] = replay_run_id
    elif step3_sim_id:
        feedback_where += " AND replay_run_id IS NULL"
    cur.execute(
        f"""
        SELECT
            COALESCE(AVG(usefulness_score), 0)::numeric,
            COALESCE(AVG(triage_duration_ms), 0)::numeric,
            COUNT(*)::bigint,
            MAX(updated_at_utc)
        FROM phase4.step3_analyst_feedback
        WHERE {feedback_where};
        """,
        feedback_params,
    )
    fb = cur.fetchone() or (0, 0, 0, None)
    fb_count = int(fb[2] or 0)
    if fb_count > 0:
        measured_at = _to_utc_iso(fb[3]) or step3_measured_at
        _set_evidence("explanation_usefulness", value=fb[0], unit="ratio", source_kind="postgres_relational", source_ref="phase4.step3_analyst_feedback.usefulness_score", measured_at=measured_at, priority=1)
        _set_evidence("analyst_readiness_score", value=fb[0], unit="ratio", source_kind="postgres_relational", source_ref="phase4.step3_analyst_feedback.usefulness_score", measured_at=measured_at, priority=1)
        triage_seconds = (float(fb[1] or 0.0) / 1000.0) if fb[1] is not None else None
        _set_evidence("mean_triage_time_proxy", value=triage_seconds, unit="seconds", source_kind="postgres_relational", source_ref="phase4.step3_analyst_feedback.triage_duration_ms", measured_at=measured_at, priority=1)

    # Priority 2: JSON metrics.
    json_sources: dict[str, Any] = {
        "step1_metrics": step1_metrics,
        "step2_metrics": step2_metrics,
        "training_metrics": training_metrics,
        "shap_stage_metrics": shap_stage_metrics,
        "governance_traceability": governance_traceability,
        "step3_metrics": step3_metrics,
        "step3_timeline": step3_timeline,
    }
    json_path_map: dict[str, list[tuple[str, list[str], str, str]]] = {
        "precision": [
            ("step2_metrics", ["within_dataset_results", "table_4_1_rows", step2_primary_track, "precision"], "ratio", "phase4.workflow_runs.run_metrics.within_dataset_results.table_4_1_rows.<track>.precision"),
        ],
        "recall": [
            ("step2_metrics", ["within_dataset_results", "table_4_1_rows", step2_primary_track, "recall"], "ratio", "phase4.workflow_runs.run_metrics.within_dataset_results.table_4_1_rows.<track>.recall"),
        ],
        "f1_score": [
            ("step2_metrics", ["within_dataset_results", "table_4_1_rows", step2_primary_track, "f1"], "ratio", "phase4.workflow_runs.run_metrics.within_dataset_results.table_4_1_rows.<track>.f1"),
        ],
        "macro_f1": [
            ("step2_metrics", ["within_dataset_results", "table_4_1_rows", step2_primary_track, "macro_f1"], "ratio", "phase4.workflow_runs.run_metrics.within_dataset_results.table_4_1_rows.<track>.macro_f1"),
        ],
        "false_positive_rate": [
            ("step2_metrics", ["within_dataset_results", "table_4_1_rows", step2_primary_track, "fpr"], "ratio", "phase4.workflow_runs.run_metrics.within_dataset_results.table_4_1_rows.<track>.fpr"),
        ],
        "false_negative_rate": [
            ("step2_metrics", ["within_dataset_results", "table_4_1_rows", step2_primary_track, "fnr"], "ratio", "phase4.workflow_runs.run_metrics.within_dataset_results.table_4_1_rows.<track>.fnr"),
        ],
        "accuracy": [
            ("step2_metrics", ["within_dataset_results", "table_4_1_rows", step2_primary_track, "accuracy"], "ratio", "phase4.workflow_runs.run_metrics.within_dataset_results.table_4_1_rows.<track>.accuracy"),
        ],
        "cross_dataset_robustness": [
            ("step2_metrics", ["cross_dataset_robustness"], "ratio", "phase4.workflow_runs.run_metrics.cross_dataset_robustness"),
        ],
        "selected_feature_count": [
            ("training_metrics", ["feature_count"], "count", "phase4.workflow_runs.run_metrics.training_result.metrics.feature_count"),
        ],
        "feature_reduction_ratio": [
            ("training_metrics", ["feature_reduction_ratio"], "ratio", "phase4.workflow_runs.run_metrics.training_result.metrics.feature_reduction_ratio"),
        ],
        "training_time_seconds": [
            ("training_metrics", ["duration_s"], "seconds", "phase4.workflow_runs.run_metrics.training_result.metrics.duration_s"),
        ],
        "inference_latency_ms": [
            ("step2_metrics", ["inference_latency_ms"], "ms", "phase4.workflow_runs.run_metrics.inference_latency_ms"),
        ],
        "shap_generation_time_seconds": [
            ("shap_stage_metrics", ["offline_compute_duration_s"], "seconds", "phase4.workflow_runs.run_metrics.shap_stage_metrics.offline_compute_duration_s"),
        ],
        "pareto_rank": [
            ("training_metrics", ["pareto_rank"], "count", "phase4.workflow_runs.run_metrics.training_result.metrics.pareto_rank"),
        ],
        "explanation_coverage": [
            ("shap_stage_metrics", ["coverage_by_split", "test"], "ratio", "phase4.workflow_runs.run_metrics.shap_stage_metrics.coverage_by_split.test"),
        ],
        "feature_contribution_stability": [
            ("shap_stage_metrics", ["top_feature_consistency"], "ratio", "phase4.workflow_runs.run_metrics.shap_stage_metrics.top_feature_consistency"),
        ],
        "model_version_traceability": [
            ("governance_traceability", ["h1_5_traceability_ready"], "ratio", "phase4.workflow_runs.run_metrics.governance_traceability.h1_5_traceability_ready"),
        ],
        "rule_hit_rate": [
            ("step2_metrics", ["rule_validation_summary", "rule_hit_rate"], "ratio", "phase4.workflow_runs.run_metrics.rule_validation_summary.rule_hit_rate"),
        ],
        "rule_precision": [
            ("step2_metrics", ["rule_validation_summary", "rule_precision"], "ratio", "phase4.workflow_runs.run_metrics.rule_validation_summary.rule_precision"),
        ],
        "rule_scope_accuracy": [
            ("step2_metrics", ["rule_validation_summary", "rule_scope_accuracy"], "ratio", "phase4.workflow_runs.run_metrics.rule_validation_summary.rule_scope_accuracy"),
        ],
        "rule_replay_stability": [
            ("step2_metrics", ["rule_validation_summary", "rule_replay_stability"], "ratio", "phase4.workflow_runs.run_metrics.rule_validation_summary.rule_replay_stability"),
        ],
        "escalation_usefulness": [
            ("step2_metrics", ["rule_validation_summary", "escalation_usefulness"], "ratio", "phase4.workflow_runs.run_metrics.rule_validation_summary.escalation_usefulness"),
        ],
        "replay_detection_rate": [
            ("step3_metrics", ["replay_detection_rate"], "ratio", "phase4.step3_replay_metrics.metrics.replay_detection_rate"),
        ],
        "child_escalation_rate": [
            ("step3_metrics", ["child_escalation_rate"], "ratio", "phase4.step3_replay_metrics.metrics.child_escalation_rate"),
        ],
        "replay_false_positive_rate": [
            ("step3_metrics", ["replay_false_positive_rate"], "ratio", "phase4.step3_replay_metrics.metrics.replay_false_positive_rate"),
        ],
        "replay_propagation_coverage": [
            ("step3_metrics", ["replay_propagation_coverage"], "ratio", "phase4.step3_replay_metrics.metrics.replay_propagation_coverage"),
        ],
        "replay_containment_success": [
            ("step3_metrics", ["replay_containment_success"], "ratio", "phase4.step3_replay_metrics.metrics.replay_containment_success"),
        ],
        "triage_decision_confidence": [
            ("step3_metrics", ["triage_decision_confidence"], "ratio", "phase4.step3_replay_metrics.metrics.triage_decision_confidence"),
        ],
        "alert_context_density": [
            ("step3_metrics", ["alert_context_density"], "ratio", "phase4.step3_replay_metrics.metrics.alert_context_density"),
        ],
        "meta_alert_rate": [
            ("step3_metrics", ["meta_alert_rate"], "ratio", "phase4.step3_replay_metrics.metrics.meta_alert_rate"),
        ],
        "cross_child_correlation_capture": [
            ("step3_metrics", ["cross_child_correlation_capture"], "ratio", "phase4.step3_replay_metrics.metrics.cross_child_correlation_capture"),
        ],
        "temporal_escalation_usefulness": [
            ("step3_metrics", ["temporal_escalation_usefulness"], "ratio", "phase4.step3_replay_metrics.metrics.temporal_escalation_usefulness"),
        ],
        "oversight_precision_proxy": [
            ("step3_metrics", ["oversight_precision_proxy"], "ratio", "phase4.step3_replay_metrics.metrics.oversight_precision_proxy"),
        ],
        "explanation_pattern_recurrence_score": [
            ("step3_metrics", ["explanation_pattern_recurrence_score"], "ratio", "phase4.step3_replay_metrics.metrics.explanation_pattern_recurrence_score"),
        ],
    }
    for metric_name, candidates in json_path_map.items():
        for source_key, path, unit, source_ref in candidates:
            src = json_sources.get(source_key)
            value = _nested_get(src, path)
            if not _non_empty_value(value):
                continue
            measured_at = step2_completed_at or step1_completed_at or step3_measured_at
            _set_evidence(metric_name, value=value, unit=unit, source_kind="postgres_json", source_ref=source_ref, measured_at=measured_at, priority=2)
            break

    # Priority 3: artifact-backed evidence pointers.
    if _is_uuid_like(context.get("source_step2_run_id")):
        cur.execute(
            """
            SELECT artifact_type, file_path, updated_at_utc
            FROM phase4.file_artifacts
            WHERE run_id = %(rid)s::uuid
              AND artifact_type IN ('step2_metrics_json', 'step2_finalize_json', 'step4_dissertation_tables_zip')
            ORDER BY updated_at_utc DESC
            LIMIT 5;
            """,
            {"rid": context.get("source_step2_run_id")},
        )
        for a_type, fpath, updated_at in cur.fetchall() or []:
            if str(a_type or "") == "step2_metrics_json":
                _set_evidence(
                    "audit_completeness",
                    value="artifact_available",
                    unit="",
                    source_kind="artifact_file",
                    source_ref=str(fpath or ""),
                    measured_at=_to_utc_iso(updated_at),
                    priority=3,
                )
                break

    h4_row = (csv_rows.get("h4_shap_results.csv") or [{}])[0] if isinstance(csv_rows.get("h4_shap_results.csv"), list) and csv_rows.get("h4_shap_results.csv") else {}
    _set_evidence(
        "explanation_coverage",
        value=h4_row.get("explanation_coverage"),
        unit="ratio",
        source_kind="postgres_relational",
        source_ref="phase4.h1_shap_triage_results.explanation_coverage",
        measured_at=step2_completed_at or step3_measured_at,
        priority=1,
    )
    _set_evidence(
        "dissertation_h1_4_shap_triage",
        value=h4_row.get("explanation_coverage"),
        unit="ratio",
        source_kind="postgres_json",
        source_ref="h4_shap_results.csv.explanation_coverage",
        measured_at=step2_completed_at or step3_measured_at,
        priority=2,
    )
    _set_evidence(
        "step3_v2_h4_packet_label_coverage",
        value=step3_metrics.get("label_coverage_rate"),
        unit="ratio",
        source_kind="postgres_relational",
        source_ref="phase4.step3_v2_child_packets.packet_label",
        measured_at=step3_measured_at,
        priority=1,
    )

    not_applicable_metrics = {
        "response_correctness_proxy",
        "simulated_containment_success",
    }

    lineage = {
        "lineage_step1_run_id": str(context.get("source_step1_run_id") or ""),
        "lineage_step2_run_id": str(context.get("source_step2_run_id") or ""),
        "lineage_model_id": str(context.get("resolved_model_id") or ""),
        "lineage_model_version": str(context.get("resolved_model_version") or ""),
        "lineage_sim_id": str(context.get("step3_v2_sim_id") or ""),
    }

    matrix_rows: list[dict[str, Any]] = []
    for item in catalog:
        metric_name = str(item.get("metric_name") or "")
        hit = evidence.get(metric_name)
        if hit:
            status = "measured"
            value = hit.get("value")
            unit = str(hit.get("unit") or item.get("unit") or "")
            source_kind = str(hit.get("source_kind") or item.get("source_kind") or "")
            source_ref = str(hit.get("source_ref") or "")
            measured_at = str(hit.get("measured_at_utc") or "")
        elif metric_name in not_applicable_metrics and metric_name not in certainty_eligible_metrics:
            status = "not_applicable"
            value = ""
            unit = str(item.get("unit") or "")
            source_kind = str(item.get("source_kind") or "")
            source_ref = str(item.get("source_table_or_file") or "")
            measured_at = ""
        else:
            status = "not_collected"
            value = ""
            unit = str(item.get("unit") or "")
            source_kind = str(item.get("source_kind") or "")
            source_ref = str(item.get("source_table_or_file") or "")
            measured_at = ""
        if status not in METRICS_REQUIRED_STATUS_VALUES:
            status = "not_collected"
        matrix_rows.append(
            {
                "metric_name": metric_name,
                "value": _fmt_num(value) if _non_empty_value(value) and not isinstance(value, str) else str(value or ""),
                "unit": unit,
                "status": status,
                "source_kind": source_kind,
                "source_ref": source_ref,
                "lineage_step1_run_id": lineage["lineage_step1_run_id"],
                "lineage_step2_run_id": lineage["lineage_step2_run_id"],
                "lineage_model_id": lineage["lineage_model_id"],
                "lineage_model_version": lineage["lineage_model_version"],
                "lineage_sim_id": lineage["lineage_sim_id"],
                "measured_at_utc": measured_at,
            }
        )

    required_rows = [r for r, c in zip(matrix_rows, catalog) if bool(c.get("is_required_metric"))]
    summary = {
        "total_required": len(required_rows),
        "measured_count": sum(1 for r in required_rows if str(r.get("status")) == "measured"),
        "not_collected_count": sum(1 for r in required_rows if str(r.get("status")) == "not_collected"),
        "not_applicable_count": sum(1 for r in required_rows if str(r.get("status")) == "not_applicable"),
    }
    return catalog, matrix_rows, summary


def _persist_metrics_required_matrix(
    cur: Any,
    *,
    context: dict[str, Any],
    catalog: list[dict[str, Any]],
    rows: list[dict[str, Any]],
) -> int:
    _ensure_metrics_required_matrix_table(cur)
    lineage_params = {
        "mv": str(context.get("resolved_model_version") or ""),
        "mid": str(context.get("resolved_model_id") or ""),
        "s1": str(context.get("source_step1_run_id") or ""),
        "s2": str(context.get("source_step2_run_id") or ""),
        "sid": str(context.get("step3_v2_sim_id") or ""),
    }
    cur.execute(
        """
        DELETE FROM phase4.results_metrics_required_matrix
        WHERE COALESCE(lineage_model_version, '') = %(mv)s
          AND COALESCE(lineage_model_id, '') = %(mid)s
          AND COALESCE(lineage_step1_run_id, '') = %(s1)s
          AND COALESCE(lineage_step2_run_id, '') = %(s2)s
          AND COALESCE(lineage_sim_id, '') = %(sid)s;
        """,
        lineage_params,
    )
    if not rows:
        return 0
    cat_by_metric = {str(c.get("metric_name") or ""): c for c in catalog}
    ins_sql = """
        INSERT INTO phase4.results_metrics_required_matrix (
            metric_name, value, unit, status, source_kind, source_ref,
            lineage_step1_run_id, lineage_step2_run_id, lineage_model_id, lineage_model_version, lineage_sim_id,
            measured_at_utc, metric_group, status_rule
        ) VALUES (
            %(metric_name)s, %(value)s, %(unit)s, %(status)s, %(source_kind)s, %(source_ref)s,
            %(lineage_step1_run_id)s, %(lineage_step2_run_id)s, %(lineage_model_id)s, %(lineage_model_version)s, %(lineage_sim_id)s,
            CASE WHEN %(measured_at_utc)s = '' THEN NULL ELSE %(measured_at_utc)s::timestamptz END,
            %(metric_group)s, %(status_rule)s
        );
    """
    count = 0
    for row in rows:
        metric_name = str(row.get("metric_name") or "")
        if is_deprecated_metric("step1", metric_name):
            continue
        cat = cat_by_metric.get(metric_name, {})
        payload = dict(row)
        payload["metric_group"] = str(cat.get("group") or "")
        payload["status_rule"] = str(cat.get("status_rule") or "")
        cur.execute(ins_sql, payload)
        count += 1
    try:
        step4_unique_id = (
            str(context.get("step3_v2_sim_id") or "").strip()
            or str(context.get("resolved_model_id") or "").strip()
            or str(context.get("source_step2_run_id") or "").strip()
            or str(context.get("source_step1_run_id") or "").strip()
        )
        unified_rows: list[dict[str, Any]] = []
        for row in rows:
            metric_name = str(row.get("metric_name") or "")
            if is_deprecated_metric("step1", metric_name):
                continue
            unified_rows.append(
                {
                    "metric_name": metric_name,
                    "metric_value": row.get("value"),
                    "unit": row.get("unit"),
                    "calculation_status": row.get("status"),
                    "principle_status": ("collected_as_principle" if str(row.get("status") or "") == "measured" else "missing"),
                    "source_ref": row.get("source_ref"),
                    "details_json": {
                        "source_kind": row.get("source_kind"),
                        "measured_at_utc": row.get("measured_at_utc"),
                        "lineage_step1_run_id": row.get("lineage_step1_run_id"),
                        "lineage_step2_run_id": row.get("lineage_step2_run_id"),
                        "lineage_model_id": row.get("lineage_model_id"),
                        "lineage_model_version": row.get("lineage_model_version"),
                        "lineage_sim_id": row.get("lineage_sim_id"),
                    },
                }
            )
        upsert_step_metrics(
            step="step4",
            step_unique_id=step4_unique_id,
            metric_rows=unified_rows,
            include_all_principle_metrics=False,
            lineage={
                "source_step1_run_id": str(context.get("source_step1_run_id") or ""),
                "source_step2_run_id": str(context.get("source_step2_run_id") or ""),
                "resolved_model_id": str(context.get("resolved_model_id") or ""),
                "resolved_model_version": str(context.get("resolved_model_version") or ""),
                "step3_v2_sim_id": str(context.get("step3_v2_sim_id") or ""),
                "replay_run_id": str(context.get("replay_run_id") or ""),
            },
        )
    except Exception:
        pass
    return count


def _summarize_required_metric_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    measured = 0
    not_collected = 0
    not_applicable = 0
    for row in rows:
        st = str(row.get("status") or "").strip().lower()
        if st == "measured":
            measured += 1
        elif st == "not_applicable":
            not_applicable += 1
        else:
            not_collected += 1
    completion_pct = 0.0
    if total > 0:
        completion_pct = round(((measured + not_applicable) / float(total)) * 100.0, 2)
    return {
        "total_required": total,
        "measured_count": measured,
        "not_collected_count": not_collected,
        "not_applicable_count": not_applicable,
        "completion_percent": completion_pct,
        "status": "completed" if total > 0 and not_collected == 0 else "pending",
    }


def _metric_group_parts(group: str) -> dict[str, Any]:
    raw = str(group or "").strip()
    parts = [p.strip() for p in raw.split(" / ") if p.strip()]
    step_label = parts[0] if parts else "STEP ?"
    subsection_label = parts[1] if len(parts) > 1 else "uncategorized"
    step_match = re.search(r"STEP\s+(\d+)", step_label, flags=re.IGNORECASE)
    step_num = int(step_match.group(1)) if step_match else 999
    step_key = f"step{step_num}" if step_match else "step_unknown"
    subsection_match = re.match(r"^(\d+)\.(\d+)", subsection_label)
    subsection_sort = (999, 999)
    subsection_key = subsection_label.lower().replace(" ", "_")
    if subsection_match:
        subsection_sort = (int(subsection_match.group(1)), int(subsection_match.group(2)))
        subsection_key = subsection_match.group(0)
    return {
        "step_key": step_key,
        "step_label": step_label,
        "step_order": step_num,
        "subsection_key": subsection_key,
        "subsection_label": subsection_label,
        "subsection_sort": subsection_sort,
    }


def _build_metrics_required_sections(required_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    steps: dict[str, dict[str, Any]] = {}

    for row in required_rows:
        group_parts = _metric_group_parts(str(row.get("metric_group") or ""))
        step_key = group_parts["step_key"]
        subsection_key = group_parts["subsection_key"]

        step_entry = steps.get(step_key)
        if not step_entry:
            step_entry = {
                "step_key": step_key,
                "step_label": group_parts["step_label"],
                "_step_order": int(group_parts["step_order"]),
                "_subsections": {},
            }
            steps[step_key] = step_entry

        subsection_entry = step_entry["_subsections"].get(subsection_key)
        if not subsection_entry:
            subsection_entry = {
                "subsection_key": subsection_key,
                "subsection_label": group_parts["subsection_label"],
                "_sort": group_parts["subsection_sort"],
                "metrics": [],
            }
            step_entry["_subsections"][subsection_key] = subsection_entry

        subsection_entry["metrics"].append(
            {
                "metric_name": str(row.get("metric_name") or ""),
                "value": str(row.get("value") or ""),
                "unit": str(row.get("unit") or ""),
                "status": str(row.get("status") or "not_collected"),
                "source_kind": str(row.get("source_kind") or ""),
                "source_ref": str(row.get("source_ref") or ""),
                "measured_at_utc": str(row.get("measured_at_utc") or ""),
            }
        )

    sections: list[dict[str, Any]] = []
    for step_entry in sorted(steps.values(), key=lambda s: (int(s["_step_order"]), str(s["step_label"]))):
        subsection_rows: list[dict[str, Any]] = []
        for subsection_entry in sorted(
            step_entry["_subsections"].values(),
            key=lambda sub: (sub["_sort"], str(sub["subsection_label"])),
        ):
            completion = _summarize_required_metric_rows(subsection_entry["metrics"])
            subsection_rows.append(
                {
                    "subsection_key": subsection_entry["subsection_key"],
                    "subsection_label": subsection_entry["subsection_label"],
                    "completion": completion,
                    "metrics": subsection_entry["metrics"],
                }
            )
        step_completion = _summarize_required_metric_rows(
            [metric for sub in subsection_rows for metric in sub["metrics"]]
        )
        sections.append(
            {
                "step_key": step_entry["step_key"],
                "step_label": step_entry["step_label"],
                "completion": step_completion,
                "subsections": subsection_rows,
            }
        )
    return sections


def _fetch_metrics_required_matrix_view(cur: Any, context: dict[str, Any]) -> dict[str, Any]:
    _ensure_metrics_required_matrix_table(cur)
    required_catalog = [c for c in _load_metrics_required_catalog() if bool(c.get("is_required_metric"))]
    required_metric_names = {
        str(c.get("metric_name") or "")
        for c in required_catalog
        if not is_deprecated_metric("step1", str(c.get("metric_name") or ""))
    }

    params = {
        "mv": str(context.get("resolved_model_version") or ""),
        "mid": str(context.get("resolved_model_id") or ""),
        "s1": str(context.get("source_step1_run_id") or ""),
        "s2": str(context.get("source_step2_run_id") or ""),
        "sid": str(context.get("step3_v2_sim_id") or ""),
    }
    cur.execute(
        """
        SELECT
            metric_name,
            value,
            unit,
            status,
            source_kind,
            source_ref,
            lineage_step1_run_id,
            lineage_step2_run_id,
            lineage_model_id,
            lineage_model_version,
            lineage_sim_id,
            measured_at_utc,
            metric_group,
            status_rule
        FROM phase4.results_metrics_required_matrix
        WHERE COALESCE(lineage_model_version, '') = %(mv)s
          AND COALESCE(lineage_model_id, '') = %(mid)s
          AND COALESCE(lineage_step1_run_id, '') = %(s1)s
          AND COALESCE(lineage_step2_run_id, '') = %(s2)s
          AND COALESCE(lineage_sim_id, '') = %(sid)s
        ORDER BY COALESCE(measured_at_utc, to_timestamp(0)) DESC, id DESC;
        """,
        params,
    )
    persisted_rows_raw = cur.fetchall() or []
    persisted_by_metric: dict[str, dict[str, Any]] = {}
    for row in persisted_rows_raw:
        metric_name = str(row[0] or "")
        if not metric_name or metric_name in persisted_by_metric:
            continue
        if is_deprecated_metric("step1", metric_name):
            continue
        if required_metric_names and metric_name not in required_metric_names:
            continue
        status = str(row[3] or "").strip().lower()
        if status not in METRICS_REQUIRED_STATUS_VALUES:
            status = "not_collected"
        persisted_by_metric[metric_name] = {
            "metric_name": metric_name,
            "value": str(row[1] or ""),
            "unit": str(row[2] or ""),
            "status": status,
            "source_kind": str(row[4] or ""),
            "source_ref": str(row[5] or ""),
            "lineage_step1_run_id": str(row[6] or ""),
            "lineage_step2_run_id": str(row[7] or ""),
            "lineage_model_id": str(row[8] or ""),
            "lineage_model_version": str(row[9] or ""),
            "lineage_sim_id": str(row[10] or ""),
            "measured_at_utc": _to_utc_iso(row[11]),
            "metric_group": str(row[12] or ""),
            "status_rule": str(row[13] or ""),
        }

    required_rows: list[dict[str, Any]] = []
    for item in required_catalog:
        metric_name = str(item.get("metric_name") or "")
        if is_deprecated_metric("step1", metric_name):
            continue
        hit = persisted_by_metric.get(metric_name)
        if hit:
            row = dict(hit)
            if not row.get("metric_group"):
                row["metric_group"] = str(item.get("group") or "")
            if not row.get("status_rule"):
                row["status_rule"] = str(item.get("status_rule") or "")
        else:
            row = {
                "metric_name": metric_name,
                "value": "",
                "unit": str(item.get("unit") or ""),
                "status": "not_collected",
                "source_kind": str(item.get("source_kind") or ""),
                "source_ref": str(item.get("source_table_or_file") or ""),
                "lineage_step1_run_id": str(context.get("source_step1_run_id") or ""),
                "lineage_step2_run_id": str(context.get("source_step2_run_id") or ""),
                "lineage_model_id": str(context.get("resolved_model_id") or ""),
                "lineage_model_version": str(context.get("resolved_model_version") or ""),
                "lineage_sim_id": str(context.get("step3_v2_sim_id") or ""),
                "measured_at_utc": "",
                "metric_group": str(item.get("group") or ""),
                "status_rule": str(item.get("status_rule") or ""),
            }
        required_rows.append(row)

    summary = _summarize_required_metric_rows(required_rows)
    sections = _build_metrics_required_sections(required_rows)
    return {
        "row_count": len(persisted_rows_raw),
        "rows": required_rows,
        "summary": summary,
        "sections": sections,
    }


def _fetch_metrics_required_status(cur: Any, context: dict[str, Any]) -> dict[str, Any]:
    view = _fetch_metrics_required_matrix_view(cur, context)
    summary = view.get("summary") if isinstance(view.get("summary"), dict) else {}
    return {
        "row_count": int(view.get("row_count") or 0),
        "total_required": int(summary.get("total_required") or 0),
        "measured_count": int(summary.get("measured_count") or 0),
        "not_collected_count": int(summary.get("not_collected_count") or 0),
        "not_applicable_count": int(summary.get("not_applicable_count") or 0),
        "completion_percent": float(summary.get("completion_percent") or 0.0),
        "status": str(summary.get("status") or "pending"),
    }


def _collect_bundle(
    model_version: str | None = None,
    *,
    step1_run_id: str | None = None,
    step2_model_id: str | None = None,
    step2_run_id: str | None = None,
    step3_v2_sim_id: str | None = None,
) -> DissertationBundle:
    context: dict[str, Any] = {}
    step3: dict[str, Any] = {}
    csv_rows: dict[str, list[dict[str, Any]]] = {}
    metrics_catalog: list[dict[str, Any]] = []
    metrics_matrix: list[dict[str, Any]] = []
    metrics_summary: dict[str, int] = {}
    with connect() as conn:
        with conn.cursor() as cur:
            context = _resolve_step4_context(
                cur,
                requested_model_version=model_version,
                requested_step1_run_id=step1_run_id,
                requested_step2_model_id=step2_model_id,
                requested_step2_run_id=step2_run_id,
                requested_step3_v2_sim_id=step3_v2_sim_id,
            )
            step2 = context["step2"]
            step3 = context["step3"]
            rule_scopes = _query_rule_scope_stats(cur, context["resolved_model_version"])
            leakage_checks = build_leakage_checks_from_db(cur)
            csv_rows = _build_csv_rows(
                step2=step2,
                step3=step3,
                rule_scopes=rule_scopes,
                leakage_checks=leakage_checks,
                model_version=context["resolved_model_version"],
                model_id=context["resolved_model_id"],
                experiment_id=context["experiment_id"],
            )
            _augment_csv_rows_with_measured_data(
                cur,
                csv_rows,
                model_version=context["resolved_model_version"],
                model_id=context["resolved_model_id"],
                source_step1_run_id=context["source_step1_run_id"],
                source_step2_run_id=context["source_step2_run_id"],
                replay_run_id=context["replay_run_id"],
                step3_v2_sim_id=context.get("step3_v2_sim_id") or "",
            )
            metrics_catalog, metrics_matrix, metrics_summary = _build_metrics_required_matrix(
                cur,
                context=context,
                csv_rows=csv_rows,
            )

    return DissertationBundle(
        resolved_model_version=context["resolved_model_version"],
        resolved_model_id=context["resolved_model_id"],
        source_step1_run_id=context["source_step1_run_id"],
        source_step2_run_id=context["source_step2_run_id"],
        replay_status=context["replay_status"],
        experiment_id=context["experiment_id"],
        step2_run_id=context["source_step2_run_id"],
        replay_run_id=context["replay_run_id"],
        step3_v2_sim_id=context.get("step3_v2_sim_id") or "",
        replay_metrics=step3.get("metrics") if isinstance(step3.get("metrics"), dict) else {},
        csv_rows=csv_rows,
        lineage_resolution=context.get("lineage_resolution") if isinstance(context.get("lineage_resolution"), dict) else {},
        metrics_required_catalog=metrics_catalog,
        metrics_required_matrix=metrics_matrix,
        metrics_required_summary=metrics_summary,
    )


def get_dissertation_status(
    model_version: str | None = None,
    *,
    step1_run_id: str | None = None,
    step2_model_id: str | None = None,
    step2_run_id: str | None = None,
    step3_v2_sim_id: str | None = None,
) -> dict[str, Any]:
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                context = _resolve_step4_context(
                    cur,
                    requested_model_version=model_version,
                    requested_step1_run_id=step1_run_id,
                    requested_step2_model_id=step2_model_id,
                    requested_step2_run_id=step2_run_id,
                    requested_step3_v2_sim_id=step3_v2_sim_id,
                )
                hypothesis_tables = _fetch_hypothesis_tables(cur, context)
                csv_status = _fetch_csv_status(cur, context)
                metrics_required_view = _fetch_metrics_required_matrix_view(cur, context)
                metrics_required_status = {
                    "row_count": int(metrics_required_view.get("row_count") or 0),
                    **(
                        metrics_required_view.get("summary")
                        if isinstance(metrics_required_view.get("summary"), dict)
                        else {}
                    ),
                }
                metrics_required_rows = (
                    metrics_required_view.get("rows")
                    if isinstance(metrics_required_view.get("rows"), list)
                    else []
                )
                metrics_required_sections = (
                    metrics_required_view.get("sections")
                    if isinstance(metrics_required_view.get("sections"), list)
                    else []
                )
                replay_metrics = context["step3"].get("metrics") if isinstance(context["step3"].get("metrics"), dict) else {}
                has_step3_v2 = bool(str(context.get("step3_v2_sim_id") or "").strip())
                h1_4_rows = hypothesis_tables.get("h1_4") if isinstance(hypothesis_tables.get("h1_4"), list) else []
                h1_4_first = h1_4_rows[0] if h1_4_rows else {}
                h4_disambiguation = {
                    "step3_v2_h4_packet_label_coverage": replay_metrics.get("label_coverage_rate"),
                    "dissertation_h1_4_shap_triage": h1_4_first.get("explanation_coverage"),
                }
                if has_step3_v2:
                    step3_completed = str(context["replay_status"]).lower() == "completed"
                else:
                    step3_completed = bool(context["replay_run_id"]) and str(context["replay_status"]).lower() == "completed"
                total_required = int(metrics_required_status.get("total_required") or 0)
                not_collected = int(metrics_required_status.get("not_collected_count") or 0)
                step4_zip_download_ready = bool(step3_completed and total_required > 0 and not_collected == 0)
                if not step3_completed:
                    step4_zip_lock_reason = "step3_not_completed"
                elif total_required <= 0:
                    step4_zip_lock_reason = "metrics_required_catalog_empty"
                elif not_collected > 0:
                    step4_zip_lock_reason = "metrics_required_incomplete"
                else:
                    step4_zip_lock_reason = ""

                step1_present = False
                if context["source_step1_run_id"]:
                    cur.execute(
                        """
                        SELECT 1
                        FROM phase4.workflow_runs
                        WHERE step_name = 'step1' AND run_id::text = %(rid)s
                        LIMIT 1;
                        """,
                        {"rid": context["source_step1_run_id"]},
                    )
                    step1_present = bool(cur.fetchone())

                step2_present = False
                if context["source_step2_run_id"]:
                    cur.execute(
                        """
                        SELECT 1
                        FROM phase4.workflow_runs
                        WHERE step_name = 'step2' AND run_id::text = %(rid)s
                        LIMIT 1;
                        """,
                        {"rid": context["source_step2_run_id"]},
                    )
                    step2_present = bool(cur.fetchone())

                step3_present = False
                if has_step3_v2:
                    cur.execute(
                        """
                        SELECT 1
                        FROM phase4.step3_v2_simulations
                        WHERE simulation_id::text = %(sid)s
                        LIMIT 1;
                        """,
                        {"sid": context.get("step3_v2_sim_id") or ""},
                    )
                    step3_present = bool(cur.fetchone())
                elif context["replay_run_id"]:
                    cur.execute(
                        """
                        SELECT 1
                        FROM phase4.replay_runs
                        WHERE replay_run_id::text = %(rid)s
                        LIMIT 1;
                        """,
                        {"rid": context["replay_run_id"]},
                    )
                    step3_present = bool(cur.fetchone())
    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
            "requested_model_version": model_version or "",
            "requested_step1_run_id": step1_run_id or "",
            "requested_step2_model_id": step2_model_id or "",
            "requested_step2_run_id": step2_run_id or "",
            "requested_step3_v2_sim_id": step3_v2_sim_id or "",
        }

    return {
        "ok": True,
        "requested_model_version": model_version or "",
        "requested_step1_run_id": step1_run_id or "",
        "requested_step2_model_id": step2_model_id or "",
        "requested_step2_run_id": step2_run_id or "",
        "requested_step3_v2_sim_id": step3_v2_sim_id or "",
        "resolved_model_version": context["resolved_model_version"],
        "resolved_model_id": context["resolved_model_id"],
        "experiment_id": context["experiment_id"],
        "source_step1_run_id": context["source_step1_run_id"],
        "source_step2_run_id": context["source_step2_run_id"],
        "step2_run_id": context["source_step2_run_id"],
        "step3_v2_sim_id": context.get("step3_v2_sim_id") or "",
        "replay_run_id": context["replay_run_id"],
        "replay_status": context["replay_status"],
        "step3_completed": step3_completed,
        "step4_runnable": step3_completed,
        "step4_run_block_reason": "" if step3_completed else "step3_not_completed",
        "rep01_packets_total": _safe_int(replay_metrics.get("rep01_packets_total")),
        "alerts_total": _safe_int(replay_metrics.get("alerts_total")),
        "escalations_total": _safe_int(replay_metrics.get("escalations_total")),
        "csv_status": csv_status,
        "missing_files": [r["file"] for r in csv_status if not r["has_data"]],
        "completion": {
            "files_with_data": sum(1 for r in csv_status if r["has_data"]),
            "files_total": len(csv_status),
        },
        "metrics_required_coverage": metrics_required_status,
        "metrics_required_matrix_rows": metrics_required_rows,
        "metrics_required_sections": metrics_required_sections,
        "step4_zip_download_ready": step4_zip_download_ready,
        "step4_zip_lock_reason": step4_zip_lock_reason,
        "lineage_resolution": context.get("lineage_resolution") or {},
        "h4_disambiguation": h4_disambiguation,
        "audit_linkage": {
            "model_id": context["resolved_model_id"],
            "step1_run_id": context["source_step1_run_id"],
            "step2_run_id": context["source_step2_run_id"],
            "replay_run_id": context["replay_run_id"],
        },
        "source_data_availability": {
            "step1": {"run_id": context["source_step1_run_id"], "present": step1_present},
            "step2": {"run_id": context["source_step2_run_id"], "present": step2_present},
            "step3": {
                "replay_run_id": context["replay_run_id"],
                "simulation_id": context.get("step3_v2_sim_id") or "",
                "present": step3_present,
            },
        },
        "hypothesis_tables": hypothesis_tables,
        "hypothesis_table_columns": HYPOTHESIS_TABLE_COLUMNS,
    }


def refresh_dissertation_exports(
    model_version: str | None = None,
    *,
    step1_run_id: str | None = None,
    step2_model_id: str | None = None,
    step2_run_id: str | None = None,
    step3_v2_sim_id: str | None = None,
) -> dict[str, Any]:
    cleanup_counts = purge_deprecated_metrics(step="step1")
    try:
        bundle = _collect_bundle(
            model_version=model_version,
            step1_run_id=step1_run_id,
            step2_model_id=step2_model_id,
            step2_run_id=step2_run_id,
            step3_v2_sim_id=step3_v2_sim_id,
        )
    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
            "requested_model_version": model_version or "",
            "requested_step1_run_id": step1_run_id or "",
            "requested_step2_model_id": step2_model_id or "",
            "requested_step2_run_id": step2_run_id or "",
            "requested_step3_v2_sim_id": step3_v2_sim_id or "",
            "deprecated_metric_cleanup": cleanup_counts,
        }

    if str(bundle.replay_status).lower() != "completed":
        return {
            "ok": False,
            "error": "step3_not_completed",
            "requested_model_version": model_version or "",
            "requested_step1_run_id": step1_run_id or "",
            "requested_step2_model_id": step2_model_id or "",
            "requested_step2_run_id": step2_run_id or "",
            "requested_step3_v2_sim_id": step3_v2_sim_id or "",
            "resolved_model_version": bundle.resolved_model_version,
            "replay_run_id": bundle.replay_run_id,
            "replay_status": bundle.replay_status,
            "deprecated_metric_cleanup": cleanup_counts,
        }

    csv_outputs: list[dict[str, Any]] = []
    traceability_payload = {
        "model_version": bundle.resolved_model_version,
        "model_id": bundle.resolved_model_id,
        "source_step1_run_id": bundle.source_step1_run_id,
        "source_step2_run_id": bundle.source_step2_run_id,
        "replay_run_id": bundle.replay_run_id,
        "replay_status": bundle.replay_status,
        "generated_at": "",
        "trace_rows": bundle.csv_rows.get("governance_traceability.csv", []),
        "evidence_counts": {k: len(v) for k, v in bundle.csv_rows.items()},
        "metrics_required_summary": bundle.metrics_required_summary,
    }
    for out_dir in _chapter4_dirs():
        for name, fields in CSV_FIELDS.items():
            rows = bundle.csv_rows.get(name, [])
            out = out_dir / name
            _write_csv(out, fields, rows)
            csv_outputs.append({"path": str(out), "row_count": len(rows)})
        matrix_csv = out_dir / "metrics_required_matrix.csv"
        _write_csv(matrix_csv, METRICS_REQUIRED_MATRIX_FIELDS, bundle.metrics_required_matrix)
        csv_outputs.append({"path": str(matrix_csv), "row_count": len(bundle.metrics_required_matrix)})
        matrix_json = out_dir / "metrics_required_matrix.json"
        _write_json(
            matrix_json,
            {
                "metrics_required_summary": bundle.metrics_required_summary,
                "rows": bundle.metrics_required_matrix,
            },
        )
        csv_outputs.append({"path": str(matrix_json), "row_count": len(bundle.metrics_required_matrix)})
        lineage_json = out_dir / "lineage_resolution.json"
        _write_json(lineage_json, bundle.lineage_resolution)
        csv_outputs.append({"path": str(lineage_json), "row_count": 1})
        traceability_payload["generated_at"] = datetime.now(timezone.utc).isoformat()
        tpath = out_dir / "traceability_bundle.json"
        _write_json(tpath, traceability_payload)
        csv_outputs.append({"path": str(tpath), "row_count": len(traceability_payload.get("trace_rows") or [])})

    db_counts: dict[str, int] = {}
    with connect() as conn:
        with conn.cursor() as cur:
            db_counts = _persist_results_tables(
                cur,
                model_version=bundle.resolved_model_version,
                model_id=bundle.resolved_model_id,
                source_step1_run_id=bundle.source_step1_run_id,
                source_step2_run_id=bundle.source_step2_run_id,
                replay_run_id=bundle.replay_run_id,
                experiment_id=bundle.experiment_id,
                rows=bundle.csv_rows,
            )
            db_counts["phase4.results_metrics_required_matrix"] = _persist_metrics_required_matrix(
                cur,
                context={
                    "resolved_model_version": bundle.resolved_model_version,
                    "resolved_model_id": bundle.resolved_model_id,
                    "source_step1_run_id": bundle.source_step1_run_id,
                    "source_step2_run_id": bundle.source_step2_run_id,
                    "step3_v2_sim_id": bundle.step3_v2_sim_id,
                },
                catalog=bundle.metrics_required_catalog,
                rows=bundle.metrics_required_matrix,
            )
        conn.commit()

    status = get_dissertation_status(
        bundle.resolved_model_version,
        step1_run_id=step1_run_id,
        step2_model_id=step2_model_id,
        step2_run_id=step2_run_id,
        step3_v2_sim_id=step3_v2_sim_id,
    )
    status.update(
        {
            "ok": True,
            "action": "refresh_dissertation_exports",
            "csv_outputs": csv_outputs,
            "db_table_rows_written": db_counts,
            "metrics_required_summary": bundle.metrics_required_summary,
            "lineage_resolution": bundle.lineage_resolution,
            "deprecated_metric_cleanup": cleanup_counts,
        }
    )
    return status


def export_dissertation_tables_zip(
    model_version: str | None = None,
    *,
    step1_run_id: str | None = None,
    step2_model_id: str | None = None,
    step2_run_id: str | None = None,
    step3_v2_sim_id: str | None = None,
    refresh: bool = False,
) -> dict[str, Any]:
    requested_model_version = str(model_version or "").strip() or None
    if refresh:
        refreshed = refresh_dissertation_exports(
            requested_model_version,
            step1_run_id=step1_run_id,
            step2_model_id=step2_model_id,
            step2_run_id=step2_run_id,
            step3_v2_sim_id=step3_v2_sim_id,
        )
        if not refreshed.get("ok"):
            return {
                "ok": False,
                "error": str(refreshed.get("error") or "refresh_failed"),
                "requested_model_version": requested_model_version or "",
                "refresh": refreshed,
            }
        requested_model_version = str(refreshed.get("resolved_model_version") or requested_model_version or "").strip() or None

    status = get_dissertation_status(
        requested_model_version,
        step1_run_id=step1_run_id,
        step2_model_id=step2_model_id,
        step2_run_id=step2_run_id,
        step3_v2_sim_id=step3_v2_sim_id,
    )
    if not status.get("ok"):
        return {
            "ok": False,
            "error": str(status.get("error") or "status_failed"),
            "requested_model_version": requested_model_version or "",
        }
    if not bool(status.get("step4_zip_download_ready")):
        return {
            "ok": False,
            "error": "step4_zip_locked_metrics_incomplete",
            "reason": str(status.get("step4_zip_lock_reason") or "metrics_required_incomplete"),
            "requested_model_version": requested_model_version or "",
            "requested_step1_run_id": step1_run_id or "",
            "requested_step2_model_id": step2_model_id or "",
            "requested_step2_run_id": step2_run_id or "",
            "requested_step3_v2_sim_id": step3_v2_sim_id or "",
            "status": status,
        }

    resolved_model_version = str(status.get("resolved_model_version") or requested_model_version or "").strip()
    chapter_dirs = _chapter4_dirs()
    required_files = list(CSV_FIELDS.keys()) + [
        "traceability_bundle.json",
        "metrics_required_matrix.csv",
        "metrics_required_matrix.json",
        "lineage_resolution.json",
    ]
    selected_files: list[tuple[str, Path]] = []
    missing_files: list[str] = []

    for name in required_files:
        found_path = None
        for base in chapter_dirs:
            candidate = base / name
            if candidate.is_file():
                found_path = candidate
                break
        if found_path:
            selected_files.append((name, found_path))
        else:
            missing_files.append(name)

    if not selected_files:
        return {
            "ok": False,
            "error": "no_dissertation_exports_found",
            "requested_model_version": requested_model_version or "",
            "resolved_model_version": resolved_model_version,
            "required_files": required_files,
        }

    output_dir = chapter_dirs[-1]
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    zip_name = f"dissertation_tables_{_sanitize_slug(resolved_model_version)}_{ts}.zip"
    zip_path = output_dir / zip_name

    bundle_summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "requested_model_version": requested_model_version or "",
        "requested_step1_run_id": step1_run_id or "",
        "requested_step2_model_id": step2_model_id or "",
        "requested_step2_run_id": step2_run_id or "",
        "requested_step3_v2_sim_id": step3_v2_sim_id or "",
        "resolved_model_version": resolved_model_version,
        "resolved_model_id": str(status.get("resolved_model_id") or ""),
        "resolved_step1_run_id": str(status.get("source_step1_run_id") or ""),
        "resolved_step2_run_id": str(status.get("source_step2_run_id") or ""),
        "resolved_replay_run_id": str(status.get("replay_run_id") or ""),
        "resolved_step3_v2_sim_id": str(status.get("step3_v2_sim_id") or ""),
        "metrics_required_coverage": status.get("metrics_required_coverage") or {},
        "step4_zip_download_ready": bool(status.get("step4_zip_download_ready")),
        "step4_zip_lock_reason": str(status.get("step4_zip_lock_reason") or ""),
        "refresh_requested": bool(refresh),
        "snapshot_mode": not bool(refresh),
        "step4_status": status,
        "included_files": [name for name, _ in selected_files],
        "missing_files": missing_files,
    }

    with zipfile.ZipFile(zip_path, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arc_name, file_path in selected_files:
            zf.write(file_path, arcname=arc_name)
        zf.writestr("bundle_status.json", json.dumps(bundle_summary, indent=2, sort_keys=True, default=str))

    return {
        "ok": True,
        "action": "export_dissertation_tables_zip",
        "requested_model_version": requested_model_version or "",
        "requested_step1_run_id": step1_run_id or "",
        "requested_step2_model_id": step2_model_id or "",
        "requested_step2_run_id": step2_run_id or "",
        "requested_step3_v2_sim_id": step3_v2_sim_id or "",
        "resolved_model_version": resolved_model_version,
        "zip_path": str(zip_path),
        "zip_name": zip_name,
        "missing_files": missing_files,
        "included_files": [name for name, _ in selected_files],
        "artifact_count": len(selected_files),
        "snapshot_mode": not bool(refresh),
        "status": status,
    }
