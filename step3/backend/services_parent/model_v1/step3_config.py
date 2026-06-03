"""Model V1 Step 3 worker and parallelism configuration (replay simulation fabric only)."""

from __future__ import annotations

import os


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(1, int(raw))
    except ValueError:
        return default


def _mode_env(name: str, default: str) -> str:
    raw = (os.environ.get(name) or "").strip().lower()
    if raw in {"production", "simulation"}:
        return raw
    return default


def _bool_env(name: str, default: bool) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if raw in {"1", "true", "yes", "y", "on"}:
        return True
    if raw in {"0", "false", "no", "n", "off"}:
        return False
    return default


# Controlled parallelism (avoid CPU oversubscription in production).
STEP3_REPLAY_MAX_WORKERS = _int_env("STEP3_REPLAY_MAX_WORKERS", 20)
STEP3_ADAPTER_WORKERS = _int_env("STEP3_ADAPTER_WORKERS", 6)
# Tier pools: child stacks (default 10), parent review (4), factory PCAP pipeline (4).
STEP3_CHILD_STACK_THREADS = _int_env("STEP3_CHILD_STACK_THREADS", 10)
STEP3_PARENT_STACK_THREADS = _int_env("STEP3_PARENT_STACK_THREADS", 4)
STEP3_FACTORY_STACK_THREADS = _int_env("STEP3_FACTORY_STACK_THREADS", 4)
STEP3_CHILD_ROUTE_WORKERS = _int_env(
    "STEP3_CHILD_ROUTE_WORKERS", STEP3_CHILD_STACK_THREADS
)
STEP3_PARENT_REVIEW_WORKERS = _int_env(
    "STEP3_PARENT_REVIEW_WORKERS", STEP3_PARENT_STACK_THREADS
)
STEP3_SHAP_WORKERS = _int_env("STEP3_SHAP_WORKERS", 4)
STEP3_PARENT_WORKER_MODE = (os.environ.get("STEP3_PARENT_WORKER_MODE") or "thread").strip().lower()
STEP3_WORKER_MODE = (os.environ.get("STEP3_WORKER_MODE") or "process").strip().lower()
STEP3_EXECUTION_MODE = _mode_env("STEP3_EXECUTION_MODE", "simulation")
STEP3_ALERT_DEFER_TO_BUFFER = _bool_env("STEP3_ALERT_DEFER_TO_BUFFER", False)
STEP3_STRICT_ACCEPTANCE_DEFAULT = _bool_env("STEP3_STRICT_ACCEPTANCE_DEFAULT", True)
STEP3_MTLS_ENABLED = _bool_env("STEP3_MTLS_ENABLED", False)
STEP3_MTLS_REQUIRE_CLIENT_CERT = _bool_env("STEP3_MTLS_REQUIRE_CLIENT_CERT", True)
STEP3_MTLS_CERT_DIR = (os.environ.get("STEP3_MTLS_CERT_DIR") or "/data/certs/step3").strip()
STEP3_MTLS_CA_PATH = (os.environ.get("STEP3_MTLS_CA_PATH") or "").strip()

SIMULATION_NETWORK_ID = "simulation_replay_net"
PARENT_MANAGEMENT_NETWORK_ID = "parent_stack_mgmt_net"

CLIENT_PORT_BASE = 15_000
MANAGEMENT_PORT_BASE = 16_000
