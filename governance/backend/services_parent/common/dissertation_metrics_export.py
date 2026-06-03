"""Write dissertation-aligned hypothesis / Chapter 4 metrics snapshots under ``docs/ref/``.

Layout and field names follow ``docs/results/CHAPTER4_RESULT_TABLES_TEMPLATE.md`` and
``docs/planning/CHAPTER4_METRIC_DICTIONARY.md``. One JSON file per model version:

    docs/ref/metrics-<sanitized_model_version>.json

Exports are best-effort: failures are logged and do not fail the training workflow.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOG = logging.getLogger(__name__)


def repo_root_from_here() -> Path:
    """``services_parent/common`` → repository root."""
    return Path(__file__).resolve().parents[2]


def sanitize_model_slug(model_version: str) -> str:
    """Filesystem-safe token from ``model_version`` (dissertation “model no.”)."""
    s = str(model_version or "").strip().lower()
    if not s:
        return "unknown"
    s = re.sub(r"[^a-z0-9._-]+", "_", s, flags=re.I)
    s = re.sub(r"_+", "_", s).strip("._-")
    return s or "unknown"


def build_dissertation_metrics_document(payload: dict[str, Any]) -> dict[str, Any]:
    """Subset of Step 2 finalize metrics in the dissertation reference shape."""
    return {
        "schema": "dissertation_metrics_ref_v1",
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "documentation": {
            "chapter4_table_mapping": "docs/results/CHAPTER4_RESULT_TABLES_TEMPLATE.md",
            "metric_definitions": "docs/planning/CHAPTER4_METRIC_DICTIONARY.md",
            "dissertation_manuscript": "docs/ref/final_detailed_dissertation_apa_full.md",
        },
        "model_id": payload.get("model_id"),
        "model_version": payload.get("model_version"),
        "run_id": payload.get("run_id"),
        "workflow_id": payload.get("workflow_id"),
        "workflow_status": payload.get("status"),
        "within_dataset_results": payload.get("within_dataset_results") or {},
        "cross_dataset_results": payload.get("cross_dataset_results") or {},
        "cross_dataset_deltas": payload.get("cross_dataset_deltas") or {},
        "cross_dataset_gate": payload.get("cross_dataset_gate"),
        "shap_stage_metrics": payload.get("shap_stage_metrics") or {},
        "rule_validation_summary": payload.get("rule_validation_summary") or {},
        "governance_traceability": payload.get("governance_traceability") or {},
        "integrity_verification": payload.get("integrity_verification"),
        "finalize": payload.get("finalize") or {},
        "metrics_artifact_path": payload.get("metrics_artifact_path"),
    }


def persist_dissertation_metrics_ref(payload: dict[str, Any]) -> Path | None:
    """Write ``docs/ref/metrics-<model>.json`` if the repo layout is writable."""
    ref_dir = repo_root_from_here() / "docs" / "ref"
    slug = sanitize_model_slug(str(payload.get("model_version") or ""))
    out = ref_dir / f"metrics-{slug}.json"
    doc = build_dissertation_metrics_document(payload)
    try:
        ref_dir.mkdir(parents=True, exist_ok=True)
        body = json.dumps(doc, indent=2, sort_keys=True).encode("utf-8")
        out.write_bytes(body + b"\n")
    except Exception as exc:
        _LOG.warning("dissertation metrics ref not written (%s): %s", out, exc)
        return None
    _LOG.info("dissertation metrics ref written: %s", out)
    return out
