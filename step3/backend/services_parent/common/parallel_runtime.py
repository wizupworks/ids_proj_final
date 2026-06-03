"""Helpers for deterministic, bounded parallel runtime configuration."""

from __future__ import annotations

from dataclasses import dataclass

from services_parent.common.project_cpu_governor import (
    build_project_cpu_governor,
    project_executor_strategy,
)


def resolve_requested_workers(cli_max_workers: int | None) -> int:
    """Resolve requested workers from CLI first, then PROJECT governor budget."""
    if cli_max_workers and cli_max_workers > 0:
        return cli_max_workers
    gov = build_project_cpu_governor()
    return max(1, int(gov.get("thread_budget_max") or 1))


@dataclass(frozen=True)
class ParallelRuntime:
    requested_workers: int
    effective_workers: int
    cpu_count: int
    strategy: str


def resolve_parallel_runtime(
    cli_max_workers: int | None,
    *,
    strategy: str = "process_pool",
) -> ParallelRuntime:
    """Compute capped worker count and preserve strategy metadata."""
    requested = resolve_requested_workers(cli_max_workers)
    gov = build_project_cpu_governor(requested_workers=requested)
    host_threads_total = max(1, int(gov.get("host_threads_total") or 1))
    effective = max(
        1,
        min(
            requested,
            host_threads_total,
            int(gov.get("thread_budget_max") or 1),
            int(gov.get("effective_thread_cap") or 1),
        ),
    )
    if strategy == "auto":
        strategy = project_executor_strategy()
    return ParallelRuntime(
        requested_workers=requested,
        effective_workers=effective,
        cpu_count=host_threads_total,
        strategy=strategy,
    )
