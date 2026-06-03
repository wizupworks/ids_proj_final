from __future__ import annotations

from typing import Any

from services_parent.common.phase4_db import write_audit_event


def emit_audit(
    *,
    event_type: str,
    actor: str,
    run_id: str,
    workflow_id: str,
    dataset_id: str | None = None,
    experiment_id: str | None = None,
    model_version: str | None = None,
    context: dict[str, Any] | None = None,
) -> None:
    payload = {"run_id": run_id, "workflow_id": workflow_id}
    if context:
        payload.update(context)
    write_audit_event(
        event_type=event_type,
        actor=actor,
        artifact_refs=[],
        context=payload,
        dataset_id=dataset_id,
        experiment_id=experiment_id,
        model_version=model_version,
    )

