#!/usr/bin/env python3
"""ASGI runner for Step 3 V2 engine."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import uvicorn  # type: ignore[import-not-found]

from services_parent.model_v1.step3_v2_engine import app


def _env_int(name: str, default: int) -> int:
    raw = str(os.getenv(name, "")).strip()
    if not raw:
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _configure_thread_caps() -> None:
    # Keep service aligned to 16 CPU-thread target unless explicitly overridden.
    cpu_threads = max(1, min(16, _env_int("STEP3_V2_CPU_THREADS", int(os.cpu_count() or 1))))
    os.environ.setdefault("STEP3_V2_CPU_THREADS", str(cpu_threads))
    os.environ.setdefault("STEP3_V2_MAX_WORKERS", str(min(16, cpu_threads)))
    for k in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
        os.environ.setdefault(k, str(cpu_threads))


def main() -> int:
    parser = argparse.ArgumentParser(description="Step 3 V2 FastAPI engine")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8091)
    parser.add_argument("--workers", type=int, default=1)
    args = parser.parse_args()
    _configure_thread_caps()
    # Engine state is in-memory; keep ASGI process single-worker.
    uvicorn.run(app, host=args.host, port=args.port, workers=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
