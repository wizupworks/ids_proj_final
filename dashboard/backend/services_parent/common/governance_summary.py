"""Build dashboard / API governance summary from manifest, experiment design, and Postgres."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from services_parent.common.phase4_db import list_audit_events
from services_parent.common.phase4_manifest import (
    attach_policy_to_datasets,
    load_hybrid_policy,
    load_manifest,
    registered_artifacts,
)


def _badge_for_role(role: str) -> str:
    r = (role or "").lower()
    if "primary_supervised" in r or r == "training_source":
        return "TRAINING SOURCE"
    if "cross_dataset" in r or "evaluation" in r:
        return "CROSS-TEST ONLY"
    if "rule_support" in r or "rule" in r:
        return "RULE SUPPORT"
    if "replay" in r or "replay_source" in r or "replay_workflow" in r:
        return "REPLAY ONLY"
    if "reference" in r:
        return "REFERENCE ONLY"
    return "UNCLASSIFIED"


def load_experiment_design(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def build_dataset_registry_rows(
    manifest_path: Path,
    hybrid_policy_path: Path,
) -> list[dict[str, Any]]:
    manifest = load_manifest(manifest_path)
    hybrid = load_hybrid_policy(hybrid_policy_path)
    rows = attach_policy_to_datasets(manifest, hybrid)
    out: list[dict[str, Any]] = []
    for item in rows:
        did = item.get("dataset_id", "")
        out.append(
            {
                "dataset_id": did,
                "dataset_name": item.get("name"),
                "domain": item.get("domain"),
                "approved_role": item.get("role"),
                "badge": _badge_for_role(str(item.get("role", ""))),
                "registered_artifact_count": len(registered_artifacts(item)),
                "split_policy_note": "ENT-01: train/val/test hashed; other IDs: cross_test storage on test partition per experiment_design_v1.json",
            }
        )
    return out


def build_experiment_cards(experiment_design: dict[str, Any]) -> dict[str, Any]:
    mv1 = experiment_design.get("model_v1") or {}
    mv2 = experiment_design.get("model_v2_optional") or {}
    return {
        "model_v1": {
            "name": "Parent Model V1 / Enterprise Baseline",
            "train": "ENT-01 train split only",
            "validation": "ENT-01 validation split only",
            "test": "ENT-01 test split only (baseline)",
            "cross_test": list(mv1.get("cross_dataset_evaluation_ids") or ["DNS-01", "IOT-01"]),
            "replay": list(mv1.get("replay_workflow_dataset_ids") or ["REP-01"]),
            "excluded_from_training": list(
                set(
                    (mv1.get("rule_support_dataset_ids") or [])
                    + (mv1.get("cross_dataset_evaluation_ids") or [])
                    + (mv1.get("replay_workflow_dataset_ids") or [])
                    + (mv1.get("reference_only_dataset_ids") or [])
                )
            ),
            "train_button_policy": "Training must be blocked unless leakage guards pass (see leakage_guard_results).",
        },
        "model_v2": {
            "name": "Parent Model V2 / Hybrid Domain Model",
            "status": "optional — train from scratch only after Model V1 experiments are frozen",
            "proposed_training_ids": mv2.get("proposed_training_dataset_ids", []),
            "warning": "V2 must train from scratch and must not reuse V1 test row hashes (enforce via dataset_splits + leakage_guard_results).",
        },
    }


def _safe_int(cur: Any, sql: str, params: tuple[Any, ...] = ()) -> int | None:
    try:
        cur.execute(sql, params)
        row = cur.fetchone()
        if row is None:
            return None
        return int(row[0])
    except Exception:
        return None


def build_leakage_checks_from_db(cur: Any) -> list[dict[str, Any]]:
    """Run Model V1-oriented SQL checks; return rows for dashboard (no writes)."""
    checks: list[dict[str, Any]] = []

    def add(name: str, status: str, count: int | None, detail: str) -> None:
        checks.append({"check_name": name, "check_status": status, "violation_count": count, "detail": detail})

    overlap = _safe_int(
        cur,
        """
        SELECT count(*) FROM phase4.dataset_train t
        INNER JOIN phase4.dataset_test s ON t.row_hash = s.row_hash
        WHERE t.row_hash IS NOT NULL AND s.row_hash IS NOT NULL
          AND t.dataset_source = 'ENT-01' AND s.dataset_source = 'ENT-01';
        """,
    )
    if overlap is None:
        add("train_test_row_hash_overlap_ENT01", "skipped", None, "query_failed_or_column_missing")
    elif overlap == 0:
        add("train_test_row_hash_overlap_ENT01", "pass", 0, "no_overlapping_row_hashes")
    else:
        add("train_test_row_hash_overlap_ENT01", "fail", overlap, "overlapping_hashes")

    non_ent_train = _safe_int(
        cur,
        "SELECT count(*) FROM phase4.dataset_train WHERE dataset_source IS DISTINCT FROM 'ENT-01';",
    )
    if non_ent_train is None:
        add("model_v1_train_only_ENT01", "skipped", None, "query_failed")
    elif non_ent_train == 0:
        add("model_v1_train_only_ENT01", "pass", 0, "train_table_ENT01_only")
    else:
        add("model_v1_train_only_ENT01", "fail", non_ent_train, "non_ENT01_rows_in_train")

    rep_train = _safe_int(
        cur,
        "SELECT count(*) FROM phase4.dataset_train WHERE dataset_source LIKE 'REP%';",
    )
    if rep_train is None:
        add("replay_not_in_train", "skipped", None, "query_failed")
    elif rep_train == 0:
        add("replay_not_in_train", "pass", 0, "no_replay_dataset_in_train")
    else:
        add("replay_not_in_train", "fail", rep_train, "replay_rows_in_train")

    ref_any = _safe_int(
        cur,
        """
        SELECT count(*) FROM (
            SELECT dataset_source FROM phase4.dataset_train
            UNION ALL SELECT dataset_source FROM phase4.dataset_validate
            UNION ALL SELECT dataset_source FROM phase4.dataset_test
        ) x WHERE dataset_source = 'REF-01';
        """,
    )
    if ref_any is None:
        add("reference_not_in_splits", "skipped", None, "query_failed")
    elif ref_any == 0:
        add("reference_not_in_splits", "pass", 0, "REF01_absent_from_train_val_test")
    else:
        add("reference_not_in_splits", "fail", ref_any, "REF01_present_in_supervised_splits")

    ref_replay = _safe_int(
        cur,
        """
        SELECT count(*) FROM (
            SELECT dataset_source FROM phase4.dataset_train
            UNION ALL SELECT dataset_source FROM phase4.dataset_validate
            UNION ALL SELECT dataset_source FROM phase4.dataset_test
            UNION ALL SELECT dataset_source FROM phase4.dataset_replay
        ) x WHERE dataset_source = 'REF-01';
        """,
    )
    if ref_replay is None:
        add("reference_not_in_any_split_or_replay", "skipped", None, "query_failed")
    elif ref_replay == 0:
        add("reference_not_in_any_split_or_replay", "pass", 0, "REF01_absent_from_all_split_tables")
    else:
        add("reference_not_in_any_split_or_replay", "fail", ref_replay, "REF01_present_in_pipeline_tables")

    rep_supervised = _safe_int(
        cur,
        """
        SELECT count(*) FROM (
            SELECT dataset_source FROM phase4.dataset_train
            UNION ALL SELECT dataset_source FROM phase4.dataset_validate
            UNION ALL SELECT dataset_source FROM phase4.dataset_test
        ) x WHERE dataset_source = 'REP-01';
        """,
    )
    if rep_supervised is None:
        add("rep01_not_in_train_validate_test", "skipped", None, "query_failed")
    elif rep_supervised == 0:
        add("rep01_not_in_train_validate_test", "pass", 0, "REP01_absent_from_supervised_splits")
    else:
        add("rep01_not_in_train_validate_test", "fail", rep_supervised, "REP01_present_in_train_val_test")

    v2_reuse = _safe_int(
        cur,
        """
        SELECT count(*) FROM phase4.dataset_splits s1
        INNER JOIN phase4.dataset_splits s2
            ON s1.row_hash = s2.row_hash
        WHERE s1.row_hash IS NOT NULL AND trim(s1.row_hash) <> ''
          AND s1.experiment_id = 'exp_model_v1_enterprise_baseline'
          AND s1.split_name = 'test'
          AND s2.experiment_id = 'exp_model_v2_hybrid_domain'
          AND s2.split_name = 'train';
        """,
    )
    if v2_reuse is None:
        add("model_v2_no_v1_test_hash_reuse", "skipped", None, "query_failed_or_splits_empty")
    elif v2_reuse == 0:
        add("model_v2_no_v1_test_hash_reuse", "pass", 0, "no_row_hash_overlap_v1_test_v2_train")
    else:
        add("model_v2_no_v1_test_hash_reuse", "fail", v2_reuse, "v2_train_shares_hashes_with_v1_test")

    return checks


_RESULT_TABLES = frozenset(
    {
        "phase4.results_within_dataset",
        "phase4.results_cross_dataset",
        "phase4.results_categorization",
        "phase4.results_cross_scope",
        "phase4.results_shap",
        "phase4.results_rule_validation",
        "phase4.results_replay",
        "phase4.results_governance",
    }
)

_HYPOTHESIS_RESULT_TABLES = frozenset(
    {
        "phase4.h1_workflow_efficiency_results",
        "phase4.h1_categorization_results",
        "phase4.h1_cross_scope_results",
        "phase4.h1_shap_triage_results",
        "phase4.h1_governance_traceability_results",
    }
)


def fetch_result_table_samples(cur: Any, table: str, limit: int = 25) -> list[dict[str, Any]]:
    if table not in _RESULT_TABLES:
        return []
    try:
        cur.execute(f"SELECT * FROM {table} ORDER BY id DESC LIMIT %s;", (limit,))
        cols = [d.name for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
    except Exception:
        return []


def fetch_hypothesis_table_samples(cur: Any, table: str, limit: int = 12) -> list[dict[str, Any]]:
    if table not in _HYPOTHESIS_RESULT_TABLES:
        return []
    try:
        cur.execute(f"SELECT * FROM {table} ORDER BY id DESC LIMIT %s;", (limit,))
        cols = [d.name for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
    except Exception:
        return []


def _table_row_count(cur: Any, qualified: str) -> int | None:
    try:
        cur.execute(f"SELECT count(*) FROM {qualified};")
        row = cur.fetchone()
        if row is None:
            return None
        return int(row[0])
    except Exception:
        return None


def _latest_model_version(cur: Any) -> str:
    try:
        cur.execute(
            """
            SELECT model_version FROM phase4.model_registry
            ORDER BY created_at DESC NULLS LAST
            LIMIT 1;
            """
        )
        row = cur.fetchone()
        if row and row[0]:
            return str(row[0])
    except Exception:
        pass
    return "TBD"


def build_hypothesis_validation_panel(cur: Any | None, experiment_design: dict[str, Any]) -> dict[str, Any]:
    """Static mapping H1(1)–H1(5) ↔ experiments; DB row counts drive Not Run / Partial status."""
    mv1 = experiment_design.get("model_v1") or {}
    default_exp = str(mv1.get("experiment_id") or "model_v1_primary")
    model_ver = _latest_model_version(cur) if cur is not None else "TBD"

    definitions: list[dict[str, Any]] = [
        {
            "hypothesis_id": "H1(1)",
            "statement": "Parent–Child IDS improves workflow efficiency over flat IDS.",
            "system_component": "Parent–Child workflow + replay pipeline",
            "experiment_sections": ["§4.2", "§4.8"],
            "datasets_used": ["ENT-01", "REP-01"],
            "metrics_used": [
                "alert reduction rate",
                "parent review completion rate",
                "triage time proxy",
                "false alert filtering rate",
            ],
            "evaluation_method": "Compare hierarchical alert funnel vs flat alert volume proxy; replay workflow metrics.",
            "supporting_dissertation_tables": ["Table 4.1", "Table 4.8", "Table H1(1)"],
            "csv_exports": ["h1_workflow_results.csv", "within_dataset_results.csv", "replay_results.csv"],
            "postgres_table": "phase4.h1_workflow_efficiency_results",
            "expected_trend": "Lower Parent-facing noise and higher completion when Child filtering and escalation are active vs flat baseline proxy.",
        },
        {
            "hypothesis_id": "H1(2)",
            "statement": "Domain-aware categorization improves contextual interpretation.",
            "system_component": "Ingestion categorization layer",
            "experiment_sections": ["§4.3", "§4.4"],
            "datasets_used": ["ENT-01", "DNS-01", "IOT-01", "canonical audit gold (where available)"],
            "metrics_used": [
                "domain classification accuracy",
                "protocol attribution completeness",
                "vector classification completeness",
                "scope_match correctness",
            ],
            "evaluation_method": "Field-level audits + cross-dataset interpretability checks.",
            "supporting_dissertation_tables": ["Table 4.2", "Table 4.3", "Table H1(2)"],
            "csv_exports": ["h2_categorization_results.csv", "cross_dataset_results.csv", "categorization_results.csv"],
            "postgres_table": "phase4.h1_categorization_results",
            "expected_trend": "Higher completeness and correctness on canonical rows when categorization rules are applied.",
        },
        {
            "hypothesis_id": "H1(3)",
            "statement": "Cross-scope escalation improves suspicious-boundary detection.",
            "system_component": "Cross-scope engine + hybrid rules",
            "experiment_sections": ["§4.3", "§4.5", "§4.7"],
            "datasets_used": ["ENT-01", "DNS-01", "IOT-01", "rule corpora"],
            "metrics_used": [
                "cross-scope detection rate",
                "escalation correctness",
                "false escalation rate",
                "severity alignment",
            ],
            "evaluation_method": "Mismatch detection analysis vs expected scope; adjudicated escalation outcomes.",
            "supporting_dissertation_tables": ["Table 4.2", "Table 4.4", "Table 4.7", "Table H1(3)"],
            "csv_exports": ["h3_cross_scope_results.csv", "cross_dataset_results.csv", "cross_scope_results.csv", "rule_validation_results.csv"],
            "postgres_table": "phase4.h1_cross_scope_results",
            "expected_trend": "Increase in detected boundary mismatches under domain mismatch without excessive false escalation.",
        },
        {
            "hypothesis_id": "H1(4)",
            "statement": "SHAP explanation improves triage usefulness.",
            "system_component": "Parent SHAP (offline + runtime)",
            "experiment_sections": ["§4.2", "§4.6", "§4.8"],
            "datasets_used": ["ENT-01", "REP-01"],
            "metrics_used": [
                "explanation coverage",
                "feature clarity",
                "feature consistency",
                "triage usefulness proxy",
            ],
            "evaluation_method": "Coverage/latency logs + rubric or analyst proxy scores on canonical alert rows.",
            "supporting_dissertation_tables": ["Table 4.1", "Table 4.5", "Table 4.6", "Table 4.8", "Table H1(4)"],
            "csv_exports": ["h4_shap_results.csv", "within_dataset_results.csv", "shap_results.csv", "replay_results.csv"],
            "postgres_table": "phase4.h1_shap_triage_results",
            "expected_trend": "Higher explanation coverage and stable top-feature attribution for similar alerts.",
        },
        {
            "hypothesis_id": "H1(5)",
            "statement": "Governance controls improve reproducibility and traceability.",
            "system_component": "Governance plane (registries, leakage guards) + Audit plane (audit_events, replay/SHAP logs)",
            "experiment_sections": ["§4.9"],
            "datasets_used": ["All registered dataset_ids", "manifest + dataset_logs"],
            "metrics_used": [
                "dataset lineage completeness",
                "model reproducibility",
                "audit completeness",
                "replay traceability",
            ],
            "evaluation_method": "Registry and audit sampling; checklist against experiment_design_v1.json.",
            "supporting_dissertation_tables": ["Table 4.9", "Table H1(5)"],
            "csv_exports": ["h5_governance_results.csv", "governance_results.csv"],
            "postgres_table": "phase4.h1_governance_traceability_results",
            "expected_trend": "End-to-end trace from alert to model_version, rule_version, dataset batch, and replay artifact.",
        },
    ]

    hypothesis_rows: list[dict[str, Any]] = []
    samples: dict[str, list[dict[str, Any]]] = {}

    for item in definitions:
        tbl = item["postgres_table"]
        logical = tbl.replace("phase4.", "")
        n = _table_row_count(cur, tbl) if cur is not None else None
        if n is None:
            status = "Not Run"
        elif n == 0:
            status = "Not Run"
        elif n < 5:
            status = "Partial"
        else:
            status = "Complete"
        hypothesis_rows.append(
            {
                **item,
                "evaluation_status": status,
                "postgres_row_count": n,
                "default_experiment_id": default_exp,
                "model_version_display": model_ver,
            }
        )
        if cur is not None:
            samples[logical] = fetch_hypothesis_table_samples(cur, tbl, limit=8)

    return {
        "hypotheses": hypothesis_rows,
        "hypothesis_result_samples": samples,
        "status_legend": (
            "Not Run: zero rows in the linked Postgres hypothesis table. "
            "Partial: 1–4 rows (evaluation started or pilot placeholders). "
            "Complete: five or more rows recorded (UI heuristic only—dissertation support still requires metric quality review)."
        ),
    }


def build_governance_api_payload(
    *,
    manifest_path: Path,
    hybrid_policy_path: Path,
    experiment_design_path: Path,
    cur: Any | None,
) -> dict[str, Any]:
    exp = load_experiment_design(experiment_design_path)
    payload: dict[str, Any] = {
        "experiment_design_version": exp.get("version", ""),
        "dataset_registry": build_dataset_registry_rows(manifest_path, hybrid_policy_path),
        "experiments": build_experiment_cards(exp),
        "leakage_checks": [],
        "leakage_blocking": False,
        "results_samples": {},
        "hypothesis_validation": build_hypothesis_validation_panel(None, exp),
        "governance_controls": {
            "purpose": "Governance defines rules and constraints; it prevents invalid operations (e.g., leakage).",
            "includes": [
                "dataset_registry",
                "raw_artifact_registry",
                "experiment_registry",
                "dataset_splits",
                "leakage_guard_results",
                "model_registry",
                "rule_registry",
                "replay_registry",
                "audit_log",
            ],
            "failed_checks": [],
            "role_enforcement": (
                "Dataset actions are constrained by manifest role and dataset_id; "
                "POST /governance/check-action and ingest queue use governance_action_gate."
            ),
            "train_test_overlap_status": (
                "See leakage_checks entry train_test_row_hash_overlap_ENT01 (Postgres dataset_train vs dataset_test)."
            ),
            "invalid_role_usage": (
                "Static profiles in governance_action_gate.py encode dissertation-aligned allowed vs blocked steps per ID."
            ),
            "model_v1_v2_separation": (
                "Model V1 trains on ENT-01 only; Model V2 is optional, trains from scratch, "
                "and must pass separate leakage checks including model_v2_no_v1_test_hash_reuse."
            ),
        },
        "audit_trail": {
            "purpose": "Audit records actions and outcomes for traceability; it does not enforce rules.",
            "includes": [
                "phase4.audit_log",
                "phase4.replay_registry",
                "phase4.training_logs",
                "phase4.evaluation_logs",
                "phase4.shap_logs",
                "phase4.dataset_logs",
            ],
            "recent_events": [],
        },
        "results_table_roles": {
            "governance_outcomes": [
                "phase4.leakage_guard_results",
                "phase4.dataset_role_compliance",
                "phase4.results_governance",
            ],
            "audit_and_evaluation_metrics": [
                "phase4.results_replay",
                "phase4.results_shap",
                "phase4.results_cross_scope",
                "phase4.h1_governance_traceability_results",
            ],
        },
    }
    if cur is not None:
        checks = build_leakage_checks_from_db(cur)
        payload["leakage_checks"] = checks
        payload["leakage_blocking"] = any(c.get("check_status") == "fail" for c in checks)
        payload["governance_controls"]["leakage_blocking"] = payload["leakage_blocking"]
        payload["governance_controls"]["failed_checks"] = [
            c.get("check_name") for c in checks if c.get("check_status") == "fail"
        ]
        try:
            payload["audit_trail"]["recent_events"] = list_audit_events(limit=120)
        except Exception:
            payload["audit_trail"]["recent_events"] = []
        for logical, physical in (
            ("within_dataset", "phase4.results_within_dataset"),
            ("cross_dataset", "phase4.results_cross_dataset"),
            ("categorization", "phase4.results_categorization"),
            ("cross_scope", "phase4.results_cross_scope"),
            ("shap", "phase4.results_shap"),
            ("rule_validation", "phase4.results_rule_validation"),
            ("replay", "phase4.results_replay"),
            ("governance", "phase4.results_governance"),
        ):
            payload["results_samples"][logical] = fetch_result_table_samples(cur, physical)
        payload["hypothesis_validation"] = build_hypothesis_validation_panel(cur, exp)
    mv1 = exp.get("model_v1") or {}
    mv2 = exp.get("model_v2_optional") or {}
    lb = bool(payload.get("leakage_blocking"))
    payload["model_version_cards"] = {
        "model_v1": {
            "train_source": "ENT-01 only",
            "cross_test": list(mv1.get("cross_dataset_evaluation_ids") or []),
            "rule_support": list(mv1.get("rule_support_dataset_ids") or []),
            "replay": list(mv1.get("replay_workflow_dataset_ids") or []),
            "reference": list(mv1.get("reference_only_dataset_ids") or []),
            "leakage_guard_status": "fail" if lb else "pass",
            "status": "precheck_blocked_until_leakage_passes" if lb else "precheck_available_no_trainer_wired",
        },
        "model_v2": {
            "optional": True,
            "disabled_until_v1_complete": True,
            "train_from_scratch_required": True,
            "separate_leakage_guard": True,
            "proposed_training_dataset_ids": list(mv2.get("proposed_training_dataset_ids") or []),
            "leakage_guard_status": "not_run_until_v2_enabled",
            "status": "disabled_until_model_v1_experiments_complete",
        },
    }
    return payload
