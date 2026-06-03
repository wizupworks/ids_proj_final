from __future__ import annotations

import uuid
from typing import Any

STEP1_DATASETS = ("ENT-01", "ENT-02", "DNS-01", "IOT-01", "IOT-02")
STEP2_CROSS_DATASETS = ("DNS-01", "IOT-01", "ENT-02", "IOT-02")
STEP2_SHAP_CHUNKS_PER_SPLIT = 8
STEP2_RULE_SCOPES = ("global", "enterprise", "dns", "iot", "iiot", "cross_scope")
# Parallel testing targets after training + freeze (ENT-01 holdout + cross/support datasets).
STEP2_TESTING_TARGETS: tuple[tuple[str, str], ...] = (
    ("ent01_holdout", "ENT-01"),
    ("dns01", "DNS-01"),
    ("iot01", "IOT-01"),
    ("ent02_support", "ENT-02"),
    ("iot02_support", "IOT-02"),
)


def _task_id() -> str:
    return str(uuid.uuid4())


def plan_step1_dataset_tasks(*, workflow_id: str, run_id: str) -> list[dict[str, Any]]:
    return [
        {
            "task_id": _task_id(),
            "workflow_id": workflow_id,
            "run_id": run_id,
            "stage": "step1_dataset_pipeline",
            "dataset_id": ds,
        }
        for ds in STEP1_DATASETS
    ]


def plan_step2_cross_dataset_tasks(*, workflow_id: str, run_id: str) -> list[dict[str, Any]]:
    return [
        {
            "task_id": _task_id(),
            "workflow_id": workflow_id,
            "run_id": run_id,
            "stage": "step2_cross_dataset_test",
            "dataset_id": ds,
        }
        for ds in STEP2_CROSS_DATASETS
    ]


def plan_step2_testing_tasks(*, workflow_id: str, run_id: str) -> list[dict[str, Any]]:
    return [
        {
            "task_id": _task_id(),
            "workflow_id": workflow_id,
            "run_id": run_id,
            "stage": "step2_testing",
            "eval_target": target,
            "dataset_ref": ds,
        }
        for target, ds in STEP2_TESTING_TARGETS
    ]


def plan_step2_shap_chunk_tasks(
    *, workflow_id: str, run_id: str, chunks_per_split: int = STEP2_SHAP_CHUNKS_PER_SPLIT
) -> list[dict[str, Any]]:
    tasks: list[dict[str, Any]] = []
    for split in ("validation", "test"):
        for i in range(chunks_per_split):
            tasks.append(
                {
                    "task_id": _task_id(),
                    "workflow_id": workflow_id,
                    "run_id": run_id,
                    "stage": "step2_shap",
                    "dataset_id": "ENT-01",
                    "split_name": split,
                    "partition_id": f"{split}__chunk_{i}",
                    "chunk_index": i,
                    "chunk_count": chunks_per_split,
                }
            )
    return tasks


def plan_step2_rule_tasks(*, workflow_id: str, run_id: str) -> list[dict[str, Any]]:
    return [
        {
            "task_id": _task_id(),
            "workflow_id": workflow_id,
            "run_id": run_id,
            "stage": "step2_rule_generation",
            "scope": scope,
        }
        for scope in STEP2_RULE_SCOPES
    ]


def summarize_task_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(results)
    failed = [r for r in results if not r.get("ok")]
    return {
        "total_tasks": total,
        "failed_tasks": len(failed),
        "completed_tasks": total - len(failed),
        "failed_task_ids": [f.get("task_id") for f in failed],
    }

