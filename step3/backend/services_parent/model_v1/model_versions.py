from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from services_parent.common.phase4_db import connect, write_audit_event
from services_parent.model_v1.artifacts import write_json_artifact


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _version_now() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d.%H%M%S")
    return f"model_v1.{ts}"


def _safe_version_hint(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-")


def _artifact_root(data_root: Path, model_version: str) -> Path:
    return data_root / "outputs" / "model_v1" / "models" / model_version


def ensure_model_artifact_layout(data_root: Path, model_version: str) -> dict[str, str]:
    root = _artifact_root(data_root, model_version)
    out = {
        "artifact_root": str(root),
        "training": str(root / "training"),
        "evaluation": str(root / "evaluation"),
        "cross_dataset_tests": str(root / "cross_dataset_tests"),
        "shap": str(root / "shap"),
        "rulepacks": str(root / "rulepacks"),
        "audit": str(root / "audit"),
        "dashboard_state": str(root / "dashboard_state"),
    }
    for p in out.values():
        Path(p).mkdir(parents=True, exist_ok=True)
    return out


def _rulepack_status(cur: Any, model_version: str) -> str:
    cur.execute(
        """
        SELECT status
        FROM phase4.rulepack_registry
        WHERE model_version = %(mv)s
        ORDER BY created_at_utc DESC
        LIMIT 1;
        """,
        {"mv": model_version},
    )
    r = cur.fetchone()
    return str(r[0]) if r else "missing"


def _shap_status(cur: Any, model_version: str) -> str:
    cur.execute(
        """
        SELECT status
        FROM phase4.shap_artifacts
        WHERE model_version = %(mv)s
        ORDER BY created_at_utc DESC
        LIMIT 1;
        """,
        {"mv": model_version},
    )
    r = cur.fetchone()
    return str(r[0]) if r else "missing"


def _last_workflow_status(cur: Any, model_version: str) -> str:
    cur.execute(
        """
        SELECT w.status
        FROM phase4.workflow_runs w
        WHERE w.step_name='step2' AND (w.run_metrics->>'model_version') = %(mv)s
        ORDER BY w.started_at_utc DESC
        LIMIT 1;
        """,
        {"mv": model_version},
    )
    r = cur.fetchone()
    return str(r[0]) if r else "pending"


def _is_invalid_lineage(row: dict[str, Any]) -> bool:
    source = str(row.get("dataset_source") or "")
    split = str(row.get("training_split") or "")
    return source != "ENT-01" or split != "train"


def _model_registry_columns(cur: Any) -> set[str]:
    cur.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'phase4' AND table_name = 'model_registry';
        """
    )
    return {str(r[0]) for r in cur.fetchall()}


def list_models(*, q: str = "", status: str = "", sort: str = "created_at_desc") -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cols = _model_registry_columns(cur)
            query_cols: list[str] = []
            for c in (
                "model_id::text AS model_id",
                "model_version",
                "model_name",
                "model_type",
                "status",
                "dataset_source",
                "training_split",
                "created_at",
                "trained_at",
                "frozen_at",
                "artifact_root",
                "model_artifact_path",
                "metrics_artifact_path",
                "shap_artifact_root",
                "rulepack_root",
                "is_current",
                "is_frozen",
                "is_deprecated",
                "last_error",
                "linked_step1_lineage_hash",
                "created_by_run_id",
                "updated_at",
                "source_step1_run_id",
                "source_step1_lineage_hash",
                "dataset_readiness_snapshot",
                "selected_datasets",
                "created_from_model_id",
            ):
                raw = c.split(" AS ")[0].split("::")[0]
                if raw in cols:
                    query_cols.append(c)
            if not query_cols:
                return {"ok": True, "models": []}
            where_parts: list[str] = []
            params: dict[str, Any] = {}
            q_norm = (q or "").strip()
            status_norm = (status or "").strip().lower()
            if q_norm:
                q_predicates: list[str] = []
                if "model_version" in cols:
                    q_predicates.append("COALESCE(model_version, '') ILIKE %(q_like)s")
                if "model_name" in cols:
                    q_predicates.append("COALESCE(model_name, '') ILIKE %(q_like)s")
                if "model_id" in cols:
                    q_predicates.append("COALESCE(model_id::text, '') ILIKE %(q_like)s")
                if q_predicates:
                    where_parts.append("(" + " OR ".join(q_predicates) + ")")
                    params["q_like"] = f"%{q_norm}%"
            if status_norm and status_norm != "all":
                if "status" in cols:
                    where_parts.append("LOWER(COALESCE(status, '')) = %(status_filter)s")
                    params["status_filter"] = status_norm
            if sort == "model_version_desc":
                order_by = "model_version DESC NULLS LAST, created_at DESC NULLS LAST"
            else:
                order_by = "created_at DESC NULLS LAST, model_version DESC NULLS LAST"
            cur.execute(
                f"""
                SELECT {', '.join(query_cols)}
                FROM phase4.model_registry
                {"WHERE " + " AND ".join(where_parts) if where_parts else ""}
                ORDER BY {order_by};
                """,
                params,
            )
            colnames = [str(d.name) for d in cur.description]
            rows = []
            for r in cur.fetchall():
                m = dict(zip(colnames, r))
                row = {
                    "model_id": m.get("model_id"),
                    "model_version": m.get("model_version"),
                    "model_name": m.get("model_name"),
                    "model_type": m.get("model_type"),
                    "status": m.get("status"),
                    "dataset_source": m.get("dataset_source"),
                    "training_split": m.get("training_split"),
                    "created_at": m.get("created_at").isoformat() if m.get("created_at") else None,
                    "trained_at": m.get("trained_at").isoformat() if m.get("trained_at") else None,
                    "frozen_at": m.get("frozen_at").isoformat() if m.get("frozen_at") else None,
                    "artifact_root": m.get("artifact_root") or m.get("artifact_path"),
                    "model_artifact_path": m.get("model_artifact_path"),
                    "metrics_artifact_path": m.get("metrics_artifact_path") or m.get("metrics_path"),
                    "shap_artifact_root": m.get("shap_artifact_root") or m.get("shap_artifact_path"),
                    "rulepack_root": m.get("rulepack_root"),
                    "is_current": bool(m.get("is_current")),
                    "is_frozen": bool(m.get("is_frozen")),
                    "is_deprecated": bool(m.get("is_deprecated")),
                    "last_error": m.get("last_error"),
                    "linked_step1_lineage_hash": m.get("linked_step1_lineage_hash"),
                    "created_by_run_id": m.get("created_by_run_id"),
                    "updated_at": m.get("updated_at").isoformat() if m.get("updated_at") else None,
                    "source_step1_run_id": m.get("source_step1_run_id"),
                    "source_step1_lineage_hash": m.get("source_step1_lineage_hash"),
                    "dataset_readiness_snapshot": m.get("dataset_readiness_snapshot") or {},
                    "selected_datasets": m.get("selected_datasets") or [],
                    "created_from_model_id": m.get("created_from_model_id"),
                }
                row["invalid_lineage"] = _is_invalid_lineage(row)
                if row["invalid_lineage"] and str(row.get("status") or "") != "invalid_lineage":
                    cur.execute(
                        "UPDATE phase4.model_registry SET status='invalid_lineage', updated_at=now() WHERE model_version=%(mv)s;",
                        {"mv": row["model_version"]},
                    )
                    row["status"] = "invalid_lineage"
                row["rulepack_status"] = _rulepack_status(cur, row["model_version"])
                row["shap_status"] = _shap_status(cur, row["model_version"])
                row["last_run_status"] = _last_workflow_status(cur, row["model_version"])
                row["allowed_actions"] = next_valid_actions(row)
                rows.append(row)
    return {"ok": True, "models": rows}


def next_valid_actions(model: dict[str, Any]) -> list[str]:
    if model.get("invalid_lineage"):
        return ["view_details", "clone_as_new_version"]
    if model.get("is_deprecated"):
        return ["view_details", "clone_as_new_version"]
    status = str(model.get("status") or "pending")
    if status == "failed":
        return ["retry_failed_phase", "continue_step2", "clone_as_new_version", "view_details"]
    if status == "trained":
        return ["continue_step2", "run_evaluation_shap_rules", "view_details"]
    if status == "evaluated":
        return ["continue_step2", "freeze_or_generate_rules", "view_details"]
    if status == "frozen":
        return ["continue_step2", "publish_missing_rules", "view_details"]
    return ["continue_step2", "view_details", "clone_as_new_version", "deprecate_model"]


def get_model(model_version: str) -> dict[str, Any]:
    all_models = list_models().get("models", [])
    row = next((m for m in all_models if m["model_version"] == model_version), None)
    if not row:
        return {"ok": False, "error": "model_not_found"}
    return {"ok": True, "model": row}


def create_model(data_root: Path, payload: dict[str, Any], *, created_by_run_id: str | None = None) -> dict[str, Any]:
    requested = _safe_version_hint(str(payload.get("model_version") or "")) or _version_now()
    model_type = str(payload.get("model_type") or "anomaly_detection")
    lineage_hash = str(payload.get("linked_step1_lineage_hash") or "")
    source_step1_run_id = str(payload.get("source_step1_run_id") or "")
    source_step1_lineage_hash = str(payload.get("source_step1_lineage_hash") or lineage_hash or "")
    dataset_readiness_snapshot = payload.get("dataset_readiness_snapshot") or {}
    selected_datasets = payload.get("selected_datasets") or []
    created_from_model_id = str(payload.get("created_from_model_id") or "")
    created_model_id = ""
    model_version = requested
    paths: dict[str, str] = {}
    with connect() as conn:
        with conn.cursor() as cur:
            cols = _model_registry_columns(cur)
            # Guarantee a new row insert; do not silently no-op on version conflicts.
            for attempt in range(10):
                mv = requested if attempt == 0 else f"{requested}.{str(uuid.uuid4())[:8]}"
                maybe_paths = ensure_model_artifact_layout(data_root, mv)
                values: dict[str, Any] = {
                    "model_id": str(uuid.uuid4()),
                    "model_version": mv,
                    "model_name": str(payload.get("model_name") or mv),
                    "model_type": model_type,
                    "status": "created",
                    "dataset_source": "ENT-01",
                    "training_split": "train",
                    "linked_step1_lineage_hash": lineage_hash or None,
                    "artifact_root": maybe_paths["artifact_root"],
                    "model_artifact_path": None,
                    "metrics_artifact_path": None,
                    "shap_artifact_root": maybe_paths["shap"],
                    "rulepack_root": maybe_paths["rulepacks"],
                    "is_current": False,
                    "is_frozen": False,
                    "is_deprecated": False,
                    "training_allowed": True,
                    "created_by_run_id": created_by_run_id,
                    "source_step1_run_id": source_step1_run_id or None,
                    "source_step1_lineage_hash": source_step1_lineage_hash or None,
                    "dataset_readiness_snapshot": json.dumps(dataset_readiness_snapshot),
                    "selected_datasets": json.dumps(selected_datasets),
                    "created_from_model_id": created_from_model_id or None,
                    # Legacy governance schema columns:
                    "training_experiment_id": None,
                    "train_dataset_ids": "ENT-01",
                    "validation_dataset_ids": "ENT-01",
                    "test_dataset_ids": "ENT-01",
                    "algorithm": "anomaly_detection",
                    "feature_schema_version": "canonical_event_v1",
                    "label_map_version": "label_harmonization_v1",
                    "categorization_config_version": "categorization_config_v1",
                    "artifact_path": maybe_paths["artifact_root"],
                    "metrics_path": None,
                    "shap_artifact_path": maybe_paths["shap"],
                }
                insert_cols: list[str] = []
                insert_vals: list[str] = []
                params: dict[str, Any] = {}
                for c, v in values.items():
                    if c in cols:
                        insert_cols.append(c)
                        insert_vals.append(f"%({c})s")
                        params[c] = v
                if "model_id" in cols and "model_id" in params:
                    idx = insert_cols.index("model_id")
                    insert_vals[idx] = "%(model_id)s::uuid"
                cur.execute(
                    f"""
                    INSERT INTO phase4.model_registry ({', '.join(insert_cols)})
                    VALUES ({', '.join(insert_vals)})
                    ON CONFLICT (model_version) DO NOTHING
                    RETURNING model_id::text, model_version;
                    """,
                    params,
                )
                row = cur.fetchone()
                if row:
                    created_model_id = str(row[0])
                    model_version = str(row[1])
                    paths = maybe_paths
                    break
            if not created_model_id:
                conn.rollback()
                return {"ok": False, "error": "model_version_conflict_unresolved"}
        conn.commit()
    audit_warning: str | None = None
    try:
        write_audit_event(
            event_type="model_created",
            actor="dash-api",
            artifact_refs=[paths["artifact_root"]],
            context={
                "step": "step2",
                "model_id": created_model_id,
                "model_version": model_version,
                "dataset_source": "ENT-01",
                "training_split": "train",
                "source_step1_run_id": source_step1_run_id or None,
                "source_step1_lineage_hash": source_step1_lineage_hash or None,
                "selected_datasets": selected_datasets,
            },
            model_version=model_version,
        )
    except Exception as exc:
        # Model creation should not fail if only audit write failed.
        audit_warning = f"audit_write_failed: {exc}"
    out: dict[str, Any] = {"ok": True, "model_id": created_model_id, "model_version": model_version, "paths": paths}
    if audit_warning:
        out["warning"] = audit_warning
    return out


def set_current_model(model_version: str) -> dict[str, Any]:
    model = get_model(model_version)
    if not model.get("ok"):
        return model
    m = model["model"]
    if m.get("invalid_lineage"):
        return {"ok": False, "error": "invalid_lineage_model_cannot_be_current"}
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE phase4.model_registry SET is_current=false, updated_at=now();")
            cur.execute(
                "UPDATE phase4.model_registry SET is_current=true, updated_at=now() WHERE model_version=%(mv)s;",
                {"mv": model_version},
            )
        conn.commit()
    return {"ok": True, "model_version": model_version, "is_current": True}


def get_current_model() -> dict[str, Any]:
    """Return the currently active model (is_current=true), or fallback to latest model."""
    all_models = list_models().get("models", [])
    # First try to find the model marked as current
    row = next((m for m in all_models if m.get("is_current")), None)
    if row:
        return {"ok": True, "model": row}
    # Fallback: return latest model by created_at timestamp
    if all_models:
        return {"ok": True, "model": all_models[0]}
    return {"ok": False, "error": "no_model_found"}


def clone_model(data_root: Path, model_version: str, payload: dict[str, Any]) -> dict[str, Any]:
    src = get_model(model_version)
    if not src.get("ok"):
        return src
    suffix = _safe_version_hint(str(payload.get("suffix") or "clone"))
    new_version = f"{model_version}.{suffix}" if suffix else f"{model_version}.clone"
    return create_model(
        data_root,
        {
            "model_version": new_version,
            "model_name": f"{src['model'].get('model_name')}-clone",
            "model_type": src["model"].get("model_type"),
            "linked_step1_lineage_hash": src["model"].get("linked_step1_lineage_hash"),
            "source_step1_run_id": src["model"].get("source_step1_run_id"),
            "source_step1_lineage_hash": src["model"].get("source_step1_lineage_hash"),
            "dataset_readiness_snapshot": src["model"].get("dataset_readiness_snapshot") or {},
            "selected_datasets": src["model"].get("selected_datasets") or [],
            "created_from_model_id": src["model"].get("model_version"),
        },
        created_by_run_id=src["model"].get("created_by_run_id"),
    )


def deprecate_model(model_version: str) -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE phase4.model_registry
                SET is_deprecated=true, status='deprecated', updated_at=now(), is_current=false
                WHERE model_version=%(mv)s
                RETURNING model_version;
                """,
                {"mv": model_version},
            )
            row = cur.fetchone()
        conn.commit()
    if not row:
        return {"ok": False, "error": "model_not_found"}
    return {"ok": True, "model_version": row[0], "status": "deprecated"}


def update_model_lifecycle(
    model_version: str,
    *,
    status: str,
    model_artifact_path: str | None = None,
    metrics_artifact_path: str | None = None,
    last_error: str | None = None,
    is_frozen: bool | None = None,
    created_by_run_id: str | None = None,
) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE phase4.model_registry
                SET status=%(status)s,
                    model_artifact_path=COALESCE(%(model_artifact)s, model_artifact_path),
                    metrics_artifact_path=COALESCE(%(metrics_artifact)s, metrics_artifact_path),
                    last_error=%(last_error)s,
                    is_frozen=COALESCE(%(is_frozen)s, is_frozen),
                    trained_at=CASE WHEN %(status)s IN ('trained','evaluated','frozen') THEN COALESCE(trained_at, now()) ELSE trained_at END,
                    evaluated_at=CASE WHEN %(status)s IN ('evaluated','frozen') THEN COALESCE(evaluated_at, now()) ELSE evaluated_at END,
                    frozen_at=CASE WHEN %(status)s='frozen' THEN COALESCE(frozen_at, now()) ELSE frozen_at END,
                    created_by_run_id=COALESCE(%(run_id)s, created_by_run_id),
                    updated_at=now()
                WHERE model_version=%(mv)s;
                """,
                {
                    "mv": model_version,
                    "status": status,
                    "model_artifact": model_artifact_path,
                    "metrics_artifact": metrics_artifact_path,
                    "last_error": last_error,
                    "is_frozen": is_frozen,
                    "run_id": created_by_run_id,
                },
            )
        conn.commit()
