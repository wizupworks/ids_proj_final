"""Central dataset role rules for REP-01 (replay-only) and REF-01 (reference-only).

Normative policy: `configs/experiment_design_v1.json` + `phase4.dataset_registry`.
"""

from __future__ import annotations

from typing import Literal

REFERENCE_ONLY_DATASET_IDS = frozenset({"REF-01"})
REPLAY_WORKFLOW_DATASET_IDS = frozenset({"REP-01"})


def is_reference_only_dataset(dataset_id: str, role: str | None = None) -> bool:
    if dataset_id in REFERENCE_ONLY_DATASET_IDS:
        return True
    r = (role or "").lower()
    return "reference_only" in r


def is_replay_workflow_dataset(dataset_id: str, role: str | None = None) -> bool:
    if dataset_id in REPLAY_WORKFLOW_DATASET_IDS or dataset_id.startswith("REP-"):
        return True
    r = (role or "").lower().replace("-", "_")
    return r in {"replay_source", "replay_workflow_only"}


def assert_csv_normalization_allowed(dataset_id: str, role: str | None = None) -> None:
    """Raise if this dataset must never produce canonical supervised split CSV rows."""
    if is_reference_only_dataset(dataset_id, role):
        raise ValueError(
            f"{dataset_id}: reference-only dataset (e.g. NSL-KDD under REF-01) must not enter "
            "normalization or split pipelines; use literature comparison only."
        )
    if is_replay_workflow_dataset(dataset_id, role):
        raise ValueError(
            f"{dataset_id}: replay-only dataset (REP-01 / CTU-13 PCAP) must not be processed through "
            "supervised CSV normalization; use replay/adapter inventory under raw_downloads/{dataset_id} only."
        )


IngestWorkflowMode = Literal["full", "replay_inventory", "forbidden"]


def ingest_workflow_mode(dataset_id: str, role: str | None = None) -> IngestWorkflowMode:
    """How dashboard / workflow may treat the dataset for the unified ingest trigger."""
    if is_reference_only_dataset(dataset_id, role):
        return "forbidden"
    if is_replay_workflow_dataset(dataset_id, role):
        return "replay_inventory"
    return "full"


def ingest_workflow_allowed(dataset_id: str, role: str | None = None) -> tuple[bool, str]:
    """Backward-compatible: full CSV pipeline allowed only for non-REF, non-REP datasets."""
    mode = ingest_workflow_mode(dataset_id, role)
    if mode == "forbidden":
        return False, "reference_only_forbidden_in_pipeline"
    if mode == "replay_inventory":
        return False, "replay_only_use_replay_inventory_stage"
    return True, "ok"


def assert_full_supervised_ingest_allowed(dataset_id: str, role: str | None = None) -> None:
    if ingest_workflow_mode(dataset_id, role) != "full":
        raise RuntimeError(
            f"ingest_workflow_blocked:{dataset_id}:expected_full_pipeline_got_{ingest_workflow_mode(dataset_id, role)}"
        )
