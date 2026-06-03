from __future__ import annotations

import json
import os
import resource
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from services_parent.data_access.governed_data_access import (
    GovernanceDataError,
    get_cross_test_data,
    get_rule_support_data,
)
from services_parent.model_v1 import step2_config
from services_parent.model_v1.step2_config import (
    rule_subprocess_env,
    shap_subprocess_env,
    testing_subprocess_env,
    training_subprocess_env,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sample_metrics(started: float, worker_count: int) -> dict[str, Any]:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "duration_s": round(time.perf_counter() - started, 3),
        "worker_count": worker_count,
        "cpu_user_s": round(float(usage.ru_utime), 3),
        "cpu_system_s": round(float(usage.ru_stime), 3),
        "max_rss_kb": int(usage.ru_maxrss),
    }


def _parse_json_tail(stdout_text: str) -> dict[str, Any]:
    """Best-effort parse of a trailing JSON object emitted by subprocess scripts."""
    text = (stdout_text or "").strip()
    if not text:
        return {}
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for ln in reversed(lines):
        if not (ln.startswith("{") and ln.endswith("}")):
            continue
        try:
            obj = json.loads(ln)
            if isinstance(obj, dict):
                return obj
        except Exception:
            continue
    return {}


def _apply_thread_override(env: dict[str, str], env_key: str, value: Any) -> dict[str, str]:
    threads = int(value or 0)
    if threads > 0:
        env[env_key] = str(threads)
        env["OMP_NUM_THREADS"] = str(threads)
    return env


def _task_model_identity(task: dict[str, Any], script_metrics: dict[str, Any] | None = None) -> tuple[str, str]:
    sm = script_metrics if isinstance(script_metrics, dict) else {}
    task_model_id = str(task.get("model_id") or "").strip()
    task_model_version = str(task.get("model_version") or "").strip()
    script_model_id = str(sm.get("model_id") or "").strip()
    script_model_version = str(sm.get("model_version") or "").strip()
    model_id = script_model_id or task_model_id or task_model_version
    model_version = script_model_version or task_model_version or model_id
    return model_id, model_version


def run_training_task(task: dict[str, Any]) -> dict[str, Any]:
    started = time.perf_counter()
    started_at = _now()
    env = {**os.environ, **training_subprocess_env()}
    env = _apply_thread_override(env, "PROJECT_STEP2_TRAIN_THREADS", task.get("training_threads"))
    cmd = [
        "python",
        str(task["train_script"]),
        "--experiment-id",
        str(task["experiment_id"]),
        "--model-version",
        str(task["model_version"]),
        "--run-id",
        str(task["run_id"]),
        "--model-root",
        str(task["model_root"]),
    ]
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    script_metrics = _parse_json_tail(p.stdout or "")
    model_id, model_version = _task_model_identity(task, script_metrics)
    return {
        "ok": p.returncode == 0,
        "task_id": task["task_id"],
        "model_id": model_id,
        "model_version": model_version,
        "dataset_id": "ENT-01",
        "worker_id": f"pid-{os.getpid()}",
        "stage": "train_model_v1",
        "status": "completed" if p.returncode == 0 else "failed",
        "started_at_utc": started_at,
        "completed_at_utc": _now(),
        "metrics": {
            "model_id": model_id,
            "model_version": model_version,
            **_sample_metrics(started, 1),
            "training_threads_requested": int(env.get("PROJECT_STEP2_TRAIN_THREADS") or step2_config.train_threads()),
            **{k: v for k, v in script_metrics.items() if isinstance(k, str)},
        },
        "stdout_tail": "\n".join((p.stdout or "").splitlines()[-20:]),
        "stderr_tail": "\n".join((p.stderr or "").splitlines()[-20:]),
        "returncode": p.returncode,
        "enforced_train_filter": "dataset_source='ENT-01' AND split_name='train'",
    }


def run_testing_task(task: dict[str, Any]) -> dict[str, Any]:
    """Single evaluation subprocess (parallel by target in testing phase)."""
    started = time.perf_counter()
    started_at = _now()
    env = {**os.environ, **testing_subprocess_env()}
    env = _apply_thread_override(env, "PROJECT_STEP2_TEST_WORKER_THREADS", task.get("worker_threads"))
    cmd = [
        "python",
        str(task["evaluate_script"]),
        "--experiment-id",
        str(task["experiment_id"]),
        "--model-version",
        str(task["model_version"]),
        "--frozen-manifest",
        str(task["frozen_manifest"]),
        "--eval-target",
        str(task["eval_target"]),
    ]
    eval_threads = int(task.get("eval_worker_threads") or task.get("worker_threads") or 1)
    rows_per_thread = int(task.get("rows_per_thread") or 25000)
    cmd.extend(
        [
            "--eval-worker-threads",
            str(max(1, eval_threads)),
            "--rows-per-thread",
            str(max(1, rows_per_thread)),
            "--max-cpu-threads",
            "20",
        ]
    )
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    script_metrics = _parse_json_tail(p.stdout or "")
    model_id, model_version = _task_model_identity(task, script_metrics)
    return {
        "ok": p.returncode == 0,
        "task_id": task["task_id"],
        "model_id": model_id,
        "model_version": model_version,
        "dataset_id": str(task.get("dataset_ref") or ""),
        "eval_target": str(task.get("eval_target") or ""),
        "worker_id": f"pid-{os.getpid()}",
        "stage": "step2_testing",
        "status": "completed" if p.returncode == 0 else "failed",
        "started_at_utc": started_at,
        "completed_at_utc": _now(),
        "metrics": {
            "model_id": model_id,
            "model_version": model_version,
            **_sample_metrics(started, int(task.get("worker_count") or 1)),
            **{k: v for k, v in script_metrics.items() if isinstance(k, str)},
        },
        "stdout_tail": "\n".join((p.stdout or "").splitlines()[-20:]),
        "stderr_tail": "\n".join((p.stderr or "").splitlines()[-20:]),
        "returncode": p.returncode,
    }


def run_holdout_evaluation_task(task: dict[str, Any]) -> dict[str, Any]:
    """Legacy single holdout call; prefer ``run_testing_task`` with eval_target=ent01_holdout."""
    merged = {**task, "eval_target": "ent01_holdout", "dataset_ref": "ENT-01"}
    return run_testing_task(merged)


def run_cross_dataset_task(task: dict[str, Any]) -> dict[str, Any]:
    """Governance-only row count probe (no subprocess)."""
    started = time.perf_counter()
    started_at = _now()
    dataset_id = str(task["dataset_id"])
    try:
        if dataset_id in {"DNS-01", "IOT-01"}:
            rows = get_cross_test_data(dataset_id)
            mode = "cross_test"
        else:
            rows = get_rule_support_data(dataset_id)
            mode = "support_test"
        ok = True
        error = None
    except GovernanceDataError as exc:
        rows = []
        mode = "blocked"
        ok = False
        error = str(exc)
    return {
        "ok": ok,
        "task_id": task["task_id"],
        "dataset_id": dataset_id,
        "worker_id": f"pid-{os.getpid()}",
        "stage": "cross_dataset_test",
        "status": "completed" if ok else "failed",
        "started_at_utc": started_at,
        "completed_at_utc": _now(),
        "metrics": {
            **_sample_metrics(started, int(task.get("worker_count") or 1)),
            "row_count": len(rows),
            "evaluation_mode": mode,
        },
        "error": error,
    }


def run_shap_task(task: dict[str, Any]) -> dict[str, Any]:
    started = time.perf_counter()
    started_at = _now()
    env = {**os.environ, **shap_subprocess_env()}
    env = _apply_thread_override(env, "PROJECT_STEP2_SHAP_WORKER_THREADS", task.get("worker_threads"))
    if task.get("frozen_manifest"):
        env["MODEL_V1_FROZEN_MANIFEST"] = str(task["frozen_manifest"])
    cmd = [
        "python",
        str(task["shap_script"]),
        "--experiment-id",
        str(task["experiment_id"]),
        "--model-version",
        str(task["model_version"]),
        "--split",
        str(task.get("split_name") or "validation"),
        "--chunk-index",
        str(int(task.get("chunk_index", 0))),
        "--chunk-count",
        str(int(task.get("chunk_count", 1))),
        "--top-k",
        str(int(task.get("top_k", 0))),
    ]
    if task.get("frozen_manifest"):
        cmd.extend(["--frozen-manifest", str(task["frozen_manifest"])])
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    script_metrics = _parse_json_tail(p.stdout or "")
    model_id, model_version = _task_model_identity(task, script_metrics)
    return {
        "ok": p.returncode == 0,
        "task_id": task["task_id"],
        "model_id": model_id,
        "model_version": model_version,
        "dataset_id": "ENT-01",
        "split_name": script_metrics.get("split_name") or task.get("split_name"),
        "partition_id": script_metrics.get("partition_id") or task.get("partition_id"),
        "worker_id": f"pid-{os.getpid()}",
        "stage": "offline_shap",
        "status": "completed" if p.returncode == 0 else "failed",
        "started_at_utc": started_at,
        "completed_at_utc": _now(),
        "metrics": {
            "model_id": model_id,
            "model_version": model_version,
            **_sample_metrics(started, int(task.get("worker_count") or 1)),
            **{k: v for k, v in script_metrics.items() if isinstance(k, str)},
        },
        "stdout_tail": "\n".join((p.stdout or "").splitlines()[-20:]),
        "stderr_tail": "\n".join((p.stderr or "").splitlines()[-20:]),
        "returncode": p.returncode,
    }


def run_rule_task(task: dict[str, Any]) -> dict[str, Any]:
    started = time.perf_counter()
    started_at = _now()
    scope = str(task["scope"])
    detection_profile = str(task.get("detection_profile") or os.getenv("STEP2_DETECTION_PROFILE", "high_recall")).strip().lower() or "high_recall"
    alert_threshold_profile = str(task.get("alert_threshold_profile") or os.getenv("STEP2_ALERT_THRESHOLD_PROFILE", "aggressive")).strip().lower() or "aggressive"
    env = {**os.environ, **rule_subprocess_env()}
    env = _apply_thread_override(env, "PROJECT_STEP2_RULE_WORKER_THREADS", task.get("worker_threads"))
    if task.get("frozen_manifest"):
        env["MODEL_V1_FROZEN_MANIFEST"] = str(task["frozen_manifest"])
    cmd = [
        sys.executable,
        str(task["rules_script"]),
        "--experiment-id",
        str(task["experiment_id"]),
        "--model-version",
        str(task["model_version"]),
        "--run-id",
        str(task.get("run_id") or ""),
        "--workflow-id",
        str(task.get("workflow_id") or ""),
        "--metrics-artifact",
        str(task.get("metrics_artifact") or ""),
        "--scope",
        scope,
        "--detection-profile",
        detection_profile,
        "--alert-threshold-profile",
        alert_threshold_profile,
        "--skip-leakage-suite",
    ]
    timeout_s = max(60, int(os.getenv("PROJECT_STEP2_RULE_TIMEOUT_S", "900")))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout_s)
    except subprocess.TimeoutExpired as exc:
        model_id, model_version = _task_model_identity(task)
        return {
            "ok": False,
            "task_id": task["task_id"],
            "model_id": model_id,
            "model_version": model_version,
            "worker_id": f"pid-{os.getpid()}",
            "scope": scope,
            "stage": "rule_generation",
            "status": "failed",
            "started_at_utc": started_at,
            "completed_at_utc": _now(),
            "metrics": {
                "model_id": model_id,
                "model_version": model_version,
                **_sample_metrics(started, int(task.get("worker_count") or 1)),
                "timeout_s": timeout_s,
            },
            "rules": [],
            "rule_count": 0,
            "checksums": [],
            "errors": [f"subprocess_timeout:{timeout_s}", "rule_payload_missing"],
            "stdout_tail": "\n".join((exc.stdout or "").splitlines()[-20:]) if isinstance(exc.stdout, str) else "",
            "stderr_tail": "\n".join((exc.stderr or "").splitlines()[-20:]) if isinstance(exc.stderr, str) else "",
            "returncode": -9,
        }
    script_metrics = _parse_json_tail(p.stdout or "")
    rules = script_metrics.get("rules") if isinstance(script_metrics.get("rules"), list) else []
    script_ok = bool(script_metrics.get("ok")) if isinstance(script_metrics, dict) and "ok" in script_metrics else True
    parse_ok = bool(isinstance(script_metrics, dict) and script_metrics)
    effective_ok = bool(
        p.returncode == 0
        and parse_ok
        and script_ok
        and len(rules) > 0
        and int(script_metrics.get("rule_count") or len(rules)) > 0
    )
    errors: list[str] = []
    if p.returncode != 0:
        errors.append(f"subprocess_returncode:{p.returncode}")
    if not parse_ok:
        errors.append("rule_payload_missing")
    if parse_ok and not script_ok:
        errors.extend([str(x) for x in (script_metrics.get("errors") or []) if str(x).strip()])
    if parse_ok and len(rules) <= 0:
        errors.append("rule_payload_empty")
    model_id, model_version = _task_model_identity(task, script_metrics)
    return {
        "ok": effective_ok,
        "task_id": task["task_id"],
        "model_id": model_id,
        "model_version": model_version,
        "worker_id": f"pid-{os.getpid()}",
        "scope": scope,
        "stage": "rule_generation",
        "status": "completed" if p.returncode == 0 else "failed",
        "started_at_utc": started_at,
        "completed_at_utc": _now(),
        "metrics": {
            "model_id": model_id,
            "model_version": model_version,
            **_sample_metrics(started, int(task.get("worker_count") or 1)),
            **({k: v for k, v in script_metrics.items() if isinstance(k, str)} if parse_ok else {}),
        },
        "rules": rules,
        "rule_count": int(script_metrics.get("rule_count") or len(rules)) if parse_ok else 0,
        "checksums": script_metrics.get("checksums") if parse_ok else [],
        "errors": errors,
        "stdout_tail": "\n".join((p.stdout or "").splitlines()[-20:]),
        "stderr_tail": "\n".join((p.stderr or "").splitlines()[-20:]),
        "returncode": p.returncode,
    }


def freeze_model_artifact(path: Path, payload: dict[str, Any]) -> str:
    body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body + b"\n")
    return path.as_posix()


def run_integrity_verifier_task(task: dict[str, Any]) -> dict[str, Any]:
    started = time.perf_counter()
    started_at = _now()
    cmd = [
        "python",
        str(task["verify_script"]),
        "--model-id",
        str(task["model_id"]),
        "--run-id",
        str(task["run_id"]),
        "--data-root",
        str(task["data_root"]),
        "--outputs-root",
        str(task["outputs_root"]),
        "--report-out",
        str(task["report_out"]),
        "--stage",
        str(task.get("stage", "pre_freeze")),
    ]
    manifest_path = str(task.get("manifest") or "").strip()
    if manifest_path:
        cmd.extend(["--manifest", manifest_path])
    p = subprocess.run(cmd, capture_output=True, text=True, env={**os.environ})
    script_metrics = _parse_json_tail(p.stdout or "")

    verdict = None
    markdown_report = None
    json_report = None
    for line in (p.stdout or "").splitlines():
        low = line.strip()
        if low.startswith("[model-integrity] verdict="):
            verdict = low.split("=", 1)[1].strip()
        if low.startswith("[model-integrity] json_report="):
            json_report = low.split("=", 1)[1].strip()
        if low.startswith("[model-integrity] markdown_report="):
            markdown_report = low.split("=", 1)[1].strip()
    if isinstance(script_metrics, dict):
        verdict = verdict or script_metrics.get("verdict")
        rp = script_metrics.get("report_paths") or {}
        if isinstance(rp, dict):
            json_report = json_report or rp.get("json_report")
            markdown_report = markdown_report or rp.get("markdown_report")
    model_id = str(script_metrics.get("model_id") or task.get("model_id") or "")
    model_version = str(script_metrics.get("model_version") or task.get("model_version") or model_id)

    return {
        "ok": p.returncode in (0, 2),
        "task_id": task["task_id"],
        "model_id": model_id,
        "model_version": model_version,
        "worker_id": f"pid-{os.getpid()}",
        "stage": "model_integrity_verifier",
        "status": "completed" if p.returncode in (0, 2) else "failed",
        "started_at_utc": started_at,
        "completed_at_utc": _now(),
        "metrics": {
            "model_id": model_id,
            "model_version": model_version,
            **_sample_metrics(started, 1),
            "verdict": verdict or "UNKNOWN",
            "json_report": json_report,
            "markdown_report": markdown_report,
            **{k: v for k, v in script_metrics.items() if isinstance(k, str)},
        },
        "stdout_tail": "\n".join((p.stdout or "").splitlines()[-40:]),
        "stderr_tail": "\n".join((p.stderr or "").splitlines()[-40:]),
        "returncode": p.returncode,
    }
