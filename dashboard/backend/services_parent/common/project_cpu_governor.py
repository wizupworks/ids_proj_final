"""Unified host-level CPU governor and heavy-workflow queue lock for Step 0/1/2.

This module intentionally does not govern Step 3 yet.
"""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from services_parent.common.phase4_db import connect

_HEAVY_WORKFLOW_LOCK_CLASS = 542_101
_HEAVY_WORKFLOW_LOCK_OBJ = 1
_HARD_THREAD_CAP = 20


def _detect_host_threads_total() -> tuple[int, str]:
    env_override = _int_env("PROJECT_HOST_THREADS_TOTAL", 0)
    if env_override > 0:
        return max(1, env_override), "env:PROJECT_HOST_THREADS_TOTAL"
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        try:
            processors = sum(
                1
                for line in cpuinfo.read_text(encoding="utf-8", errors="ignore").splitlines()
                if line.lower().startswith("processor")
            )
            if processors > 0:
                return processors, "/proc/cpuinfo"
        except Exception:
            pass
    return max(1, int(os.cpu_count() or 1)), "os.cpu_count"


def _int_env(name: str, default: int) -> int:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _float_env(name: str, default: float) -> float:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def project_worker_mode() -> str:
    mode = (os.getenv("PROJECT_WORKER_MODE") or "process").strip().lower()
    if mode not in {"process", "thread", "hybrid"}:
        return "process"
    return mode


def project_executor_strategy() -> str:
    strategy = (os.getenv("PROJECT_EXECUTOR_STRATEGY") or "process_pool").strip().lower()
    if strategy in {"process", "process_pool"}:
        return "process_pool"
    if strategy in {"thread", "thread_pool"}:
        return "thread_pool"
    return "process_pool"


def build_project_cpu_governor(*, requested_workers: int | None = None) -> dict[str, Any]:
    host_threads_total, host_threads_source = _detect_host_threads_total()
    reserved_threads = max(1, _int_env("PROJECT_HOST_RESERVED_THREADS", 4))
    budget_raw = _int_env("PROJECT_THREAD_BUDGET_MAX", host_threads_total - reserved_threads)
    budget_max = max(1, min(host_threads_total, _HARD_THREAD_CAP, budget_raw))
    target_utilization = max(0.10, min(0.98, _float_env("PROJECT_CPU_TARGET_UTILIZATION", 0.80)))
    derived_target = max(1, int(host_threads_total * target_utilization))
    thread_target = max(1, min(budget_max, derived_target))
    band_pct = max(0.01, min(0.30, _float_env("PROJECT_CPU_BAND_PCT", 0.06)))
    sample_interval_s = max(0.05, min(5.0, _float_env("PROJECT_CPU_SAMPLE_INTERVAL_S", 0.35)))
    adaptive_enabled = _int_env("PROJECT_CPU_ADAPTIVE_ENABLED", 1) != 0
    req = int(requested_workers or budget_max)
    effective_thread_cap = max(1, min(req, budget_max))
    return {
        "host_threads_total": host_threads_total,
        "host_threads_source": host_threads_source,
        "reserved_threads": reserved_threads,
        "thread_budget_max": budget_max,
        "thread_target": thread_target,
        "target_utilization": target_utilization,
        "adaptive_enabled": adaptive_enabled,
        "band_pct": band_pct,
        "sample_interval_s": sample_interval_s,
        "effective_thread_cap": effective_thread_cap,
        "hard_thread_cap": _HARD_THREAD_CAP,
    }


def sample_host_cpu_utilization(sample_interval_s: float) -> float | None:
    """Sample host-level CPU utilization from /proc/stat (Linux-only)."""
    stat_path = Path("/proc/stat")
    if not stat_path.is_file():
        return None

    def _read() -> tuple[int, int] | None:
        try:
            line = stat_path.read_text(encoding="utf-8", errors="ignore").splitlines()[0]
            parts = line.split()
            if len(parts) < 5 or parts[0] != "cpu":
                return None
            values = [int(x) for x in parts[1:]]
            total = sum(values)
            idle = values[3] + (values[4] if len(values) > 4 else 0)
            return total, idle
        except Exception:
            return None

    first = _read()
    if first is None:
        return None
    time.sleep(max(0.05, float(sample_interval_s or 0.35)))
    second = _read()
    if second is None:
        return None
    total_delta = second[0] - first[0]
    idle_delta = second[1] - first[1]
    if total_delta <= 0:
        return None
    util = 1.0 - (float(idle_delta) / float(total_delta))
    return max(0.0, min(1.0, util))


def plan_project_phase_parallelism(
    *,
    governor: dict[str, Any],
    phase: str,
    tasks_remaining: int,
    worker_threads: int,
    phase_max_workers: int,
    host_cpu_utilization: float | None,
) -> dict[str, Any]:
    worker_threads = max(1, int(worker_threads or 1))
    phase_max_workers = max(1, int(phase_max_workers or 1))
    base_thread_budget = min(
        int(governor["thread_target"]),
        int(governor["effective_thread_cap"]),
        int(governor["thread_budget_max"]),
    )
    thread_budget = max(1, base_thread_budget)
    action = "steady"
    reason = "within_band_or_no_sample"
    target = float(governor.get("target_utilization") or 0.80)
    band = float(governor.get("band_pct") or 0.06)
    lower = max(0.0, target - band)
    upper = min(1.0, target + band)

    if bool(governor.get("adaptive_enabled")) and host_cpu_utilization is not None:
        if host_cpu_utilization > upper:
            thread_budget = max(1, min(thread_budget, int(thread_budget * 0.80)))
            action = "backoff"
            reason = "host_cpu_above_upper_band"
        elif host_cpu_utilization < lower:
            thread_budget = min(
                int(governor["thread_budget_max"]),
                max(thread_budget, int(max(1.0, thread_budget * 1.10))),
            )
            action = "scale_up"
            reason = "host_cpu_below_lower_band"

    workers_by_budget = max(1, thread_budget // worker_threads)
    workers = max(1, min(phase_max_workers, tasks_remaining, workers_by_budget))
    allocated_threads = max(1, workers * worker_threads)
    return {
        "phase": phase,
        "workers": workers,
        "worker_threads": worker_threads,
        "allocated_threads": allocated_threads,
        "thread_budget": thread_budget,
        "action": action,
        "reason": reason,
        "host_cpu_utilization": host_cpu_utilization,
        "target_utilization": target,
        "lower_band": lower,
        "upper_band": upper,
    }


@contextmanager
def acquire_project_heavy_workflow_slot(
    *,
    run_id: str,
    workflow_id: str,
    step_name: str,
    poll_interval_s: float = 2.0,
) -> Iterator[dict[str, Any]]:
    """Acquire a global heavy-workflow slot via Postgres advisory lock.

    Lock is held for the duration of the context.
    """
    wait_started = time.monotonic()
    queued_checks = 0
    with connect() as conn:
        acquired = False
        while not acquired:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT pg_try_advisory_lock(%s, %s);",
                    (_HEAVY_WORKFLOW_LOCK_CLASS, _HEAVY_WORKFLOW_LOCK_OBJ),
                )
                row = cur.fetchone()
                acquired = bool(row and row[0])
            conn.commit()
            if acquired:
                break
            queued_checks += 1
            time.sleep(max(0.2, float(poll_interval_s)))
        info = {
            "status": "acquired",
            "step_name": step_name,
            "run_id": run_id,
            "workflow_id": workflow_id,
            "lock_class": _HEAVY_WORKFLOW_LOCK_CLASS,
            "lock_object": _HEAVY_WORKFLOW_LOCK_OBJ,
            "queued": queued_checks > 0,
            "queue_wait_s": round(max(0.0, time.monotonic() - wait_started), 3),
            "queue_checks": queued_checks,
        }
        try:
            yield info
        finally:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT pg_advisory_unlock(%s, %s);",
                    (_HEAVY_WORKFLOW_LOCK_CLASS, _HEAVY_WORKFLOW_LOCK_OBJ),
                )
            conn.commit()
