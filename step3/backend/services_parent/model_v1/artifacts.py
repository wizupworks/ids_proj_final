from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def outputs_root(data_root: Path) -> Path:
    return data_root / "outputs" / "model_v1"


def ensure_layout(data_root: Path) -> dict[str, Path]:
    root = outputs_root(data_root)
    out = {
        "root": root,
        "runs": root / "runs",
        "models": root / "models",
        "metrics": root / "metrics",
        "shap": root / "shap",
        "rulepacks": root / "rulepacks",
        "audit": root / "audit",
        "dashboard_state": root / "dashboard_state",
    }
    for p in out.values():
        p.mkdir(parents=True, exist_ok=True)
    return out


def write_json_artifact(path: Path, payload: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    path.write_bytes(body + b"\n")
    return hashlib.sha256(body).hexdigest()

