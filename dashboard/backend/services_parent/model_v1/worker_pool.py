from __future__ import annotations

import os
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from typing import Any, Callable


def run_parallel(
    *,
    mode: str,
    max_workers: int,
    fn: Callable[[dict[str, Any]], dict[str, Any]],
    tasks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not tasks:
        return []
    use_mode = (mode or "process").lower()
    workers = max(1, max_workers or (os.cpu_count() or 1))
    if use_mode == "thread":
        executor_cls = ThreadPoolExecutor
    else:
        executor_cls = ProcessPoolExecutor
    results: list[dict[str, Any]] = []
    with executor_cls(max_workers=workers) as ex:
        fut_map = {ex.submit(fn, t): t for t in tasks}
        for fut in as_completed(fut_map):
            task = fut_map[fut]
            try:
                results.append(fut.result())
            except Exception as exc:
                results.append(
                    {
                        "ok": False,
                        "task_id": task.get("task_id"),
                        "dataset_id": task.get("dataset_id"),
                        "stage": task.get("stage"),
                        "error": str(exc),
                    }
                )
    return results

