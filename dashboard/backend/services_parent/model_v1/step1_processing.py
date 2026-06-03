from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from services_parent.data_pipeline.phase4_workflow import (
    build_model_v1_process_namespace,
    load_dataset_by_id,
    supervised_process_dataset,
)
from services_parent.model_v1.db import get_workflow_run


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dataset_raw_dir(raw_root: str, dataset_id: str) -> Path:
    return Path(raw_root) / dataset_id


def run_step1_dataset_task(task: dict[str, Any]) -> dict[str, Any]:
    """Model V1 dataset coordinator: one dataset, chunked CSV worker pipeline.

    Invokes ``supervised_process_dataset`` with per-dataset chunk worker sizing. ENT-01 uses strict
    file semantics (any chunk worker failure fails the dataset); other datasets may complete with
    ``readiness=partial`` while ingesting successful chunks only.
    """
    started = time.perf_counter()
    started_at = _now()
    dataset_id = str(task["dataset_id"])
    workflow_id = str(task["workflow_id"])
    run_id = str(task["run_id"])
    worker_id = f"dataset-coordinator-pid-{os.getpid()}"
    raw_root = Path(str(task["raw_root"]))
    data_root = Path(str(task["data_root"]))
    manifest = Path(str(task["manifest"]))
    hybrid_policy = Path(str(task["hybrid_policy"]))
    audit_log = data_root / "outputs" / "phase4" / "governance" / "phase4_audit_log.jsonl"
    max_file_workers = int(task.get("max_file_workers") or task.get("max_workers") or 4)
    file_executor = str(task.get("file_executor") or "process").strip().lower()
    if file_executor not in ("auto", "process", "thread"):
        file_executor = "process"

    dataset_dir = _dataset_raw_dir(str(raw_root), dataset_id)
    if not dataset_dir.exists():
        return {
            "ok": False,
            "readiness": "failed",
            "task_id": task["task_id"],
            "workflow_id": workflow_id,
            "run_id": run_id,
            "dataset_id": dataset_id,
            "worker_id": worker_id,
            "stage": "dataset_coordinator",
            "status": "failed",
            "started_at_utc": started_at,
            "completed_at_utc": _now(),
            "error": f"dataset_raw_dir_missing:{dataset_dir}",
            "file_summary": [],
            **({"training_dataset_ok": False} if dataset_id == "ENT-01" else {}),
        }
    file_count = sum(1 for p in dataset_dir.rglob("*") if p.is_file())
    if file_count == 0:
        return {
            "ok": False,
            "readiness": "failed",
            "task_id": task["task_id"],
            "workflow_id": workflow_id,
            "run_id": run_id,
            "dataset_id": dataset_id,
            "worker_id": worker_id,
            "stage": "artifact_check",
            "status": "failed",
            "started_at_utc": started_at,
            "completed_at_utc": _now(),
            "error": f"dataset_raw_files_empty:{dataset_dir}",
            "file_summary": [],
            **({"training_dataset_ok": False} if dataset_id == "ENT-01" else {}),
        }

    try:
        dataset = load_dataset_by_id(manifest, hybrid_policy, dataset_id)
    except ValueError as exc:
        return {
            "ok": False,
            "readiness": "failed",
            "task_id": task["task_id"],
            "workflow_id": workflow_id,
            "run_id": run_id,
            "dataset_id": dataset_id,
            "worker_id": worker_id,
            "stage": "manifest_resolve",
            "status": "failed",
            "started_at_utc": started_at,
            "completed_at_utc": _now(),
            "error": str(exc),
            "file_summary": [],
            **({"training_dataset_ok": False} if dataset_id == "ENT-01" else {}),
        }

    args = build_model_v1_process_namespace(
        manifest=manifest,
        hybrid_policy=hybrid_policy,
        raw_root=raw_root,
        normalized_root=data_root / "datasets_normalized",
        failed_root=data_root / "outputs" / "phase4" / "failed",
        outputs_root=data_root / "outputs" / "phase4",
        adapter_staging_root=data_root / "outputs" / "phase4" / "adapter_staging",
        audit_log=audit_log,
        max_file_workers=max_file_workers,
        file_executor=file_executor,
        dry_run=False,
        experiment_design="",
    )

    continue_on_file_failures = dataset_id != "ENT-01"
    lineage_hash = str(task.get("step1_lineage_hash") or "").strip()
    if not lineage_hash:
        run_row = get_workflow_run(run_id)
        run_metrics = run_row.get("run_metrics") if isinstance(run_row, dict) else {}
        if not isinstance(run_metrics, dict):
            run_metrics = {}
        lineage_hash = str(
            run_metrics.get("step1_ingest_lineage_hash")
            or run_metrics.get("step1_dataset_lineage_hash")
            or ""
        ).strip()
    rc, telemetry = supervised_process_dataset(
        args,
        dataset,
        continue_on_file_failures=continue_on_file_failures,
        source_step1_run_id=run_id,
        source_step1_lineage_hash=lineage_hash,
    )
    elapsed = time.perf_counter() - started
    readiness = str(telemetry.get("dataset_readiness") or "failed")
    if dataset_id == "ENT-01":
        training_ok = rc == 0 and readiness == "completed"
    else:
        training_ok = rc == 0 and readiness in ("completed", "partial")
    ok = training_ok

    out: dict[str, Any] = {
        "ok": ok,
        "readiness": readiness,
        "task_id": task["task_id"],
        "workflow_id": workflow_id,
        "run_id": run_id,
        "dataset_id": dataset_id,
        "worker_id": worker_id,
        "stage": "step1_dataset_coordinator",
        "status": "completed" if ok else "failed",
        "started_at_utc": started_at,
        "completed_at_utc": _now(),
        "duration_s": round(elapsed, 3),
        "artifact_file_count": file_count,
        "import_batch_id": telemetry.get("import_batch_id"),
        "file_summary": telemetry.get("file_summary") or [],
        "job_errors": telemetry.get("job_errors") or [],
        "split_counts": telemetry.get("split_counts") or {},
        "loaded_counts": telemetry.get("loaded_counts") or {},
        "categorization_completion": bool(telemetry.get("categorization_completion")),
        "returncode": rc,
        "run_id_context": run_id,
    }
    if dataset_id == "ENT-01":
        out["training_dataset_ok"] = training_ok
    return out
