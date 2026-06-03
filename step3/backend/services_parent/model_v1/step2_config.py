"""Model V1 Step 2 runtime configuration (PROJECT_* clean-install contract)."""

from __future__ import annotations

import os

from services_parent.common.project_cpu_governor import build_project_cpu_governor, project_worker_mode


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _float_env(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def train_threads() -> int:
    """Step 2 training thread hint (defaults to PROJECT budget cap)."""
    override = _int_env("PROJECT_STEP2_TRAIN_THREADS", 0)
    if override > 0:
        return max(1, override)
    gov = build_project_cpu_governor()
    return max(1, int(gov.get("thread_target") or 1))


def test_max_workers() -> int:
    return max(1, int(build_project_cpu_governor().get("thread_budget_max") or 1))


def test_worker_threads() -> int:
    return max(1, _int_env("PROJECT_STEP2_TEST_WORKER_THREADS", 1))


def shap_max_workers() -> int:
    return max(1, int(build_project_cpu_governor().get("thread_budget_max") or 1))


def shap_worker_threads() -> int:
    return max(1, _int_env("PROJECT_STEP2_SHAP_WORKER_THREADS", 1))


def rule_max_workers() -> int:
    cap = max(1, _int_env("PROJECT_STEP2_RULE_MAX_WORKERS", 1))
    budget = max(1, int(build_project_cpu_governor().get("thread_budget_max") or 1))
    return max(1, min(cap, budget))


def rule_worker_threads() -> int:
    return max(1, _int_env("PROJECT_STEP2_RULE_WORKER_THREADS", 1))


def worker_mode() -> str:
    return project_worker_mode()


def random_seed() -> int:
    return _int_env("PROJECT_STEP2_RANDOM_SEED", 42)


def quality_min_macro_f1() -> float:
    return max(0.0, _float_env("PROJECT_STEP2_MIN_MACRO_F1", 0.0))


def quality_min_recall_macro() -> float:
    return max(0.0, _float_env("PROJECT_STEP2_MIN_RECALL_MACRO", 0.0))


def quality_min_precision_macro() -> float:
    return max(0.0, _float_env("PROJECT_STEP2_MIN_PRECISION_MACRO", 0.0))


def quality_max_predicted_class_ratio() -> float:
    v = _float_env("PROJECT_STEP2_MAX_PREDICTED_CLASS_RATIO", 0.995)
    return min(1.0, max(0.0, v))


def quality_min_unique_pred_labels() -> int:
    return max(1, _int_env("PROJECT_STEP2_MIN_UNIQUE_PRED_LABELS", 2))


def evaluation_thresholds() -> dict[str, dict[str, float]]:
    return {
        "ent01_holdout": {
            "macro_f1_min": max(0.0, _float_env("PROJECT_STEP2_GATE_ENT01_MIN_MACRO_F1", 0.99)),
            "fnr_max": max(0.0, _float_env("PROJECT_STEP2_GATE_ENT01_MAX_FNR", 0.01)),
            "fpr_max": max(0.0, _float_env("PROJECT_STEP2_GATE_ENT01_MAX_FPR", 0.01)),
        },
        "dns01": {
            "macro_f1_min": max(0.0, _float_env("PROJECT_STEP2_GATE_DNS01_MIN_MACRO_F1", 0.99)),
            "fnr_max": max(0.0, _float_env("PROJECT_STEP2_GATE_DNS01_MAX_FNR", 0.01)),
            "fpr_max": max(0.0, _float_env("PROJECT_STEP2_GATE_DNS01_MAX_FPR", 0.01)),
        },
        "iot01": {
            "macro_f1_min": max(0.0, _float_env("PROJECT_STEP2_GATE_IOT01_MIN_MACRO_F1", 0.80)),
            "fnr_max": max(0.0, _float_env("PROJECT_STEP2_GATE_IOT01_MAX_FNR", 0.15)),
            "fpr_max": max(0.0, _float_env("PROJECT_STEP2_GATE_IOT01_MAX_FPR", 0.001)),
        },
        "ent02_support": {
            "macro_f1_min": max(0.0, _float_env("PROJECT_STEP2_GATE_ENT02_MIN_MACRO_F1", 0.75)),
            "fnr_max": max(0.0, _float_env("PROJECT_STEP2_GATE_ENT02_MAX_FNR", 0.20)),
            "fpr_max": max(0.0, _float_env("PROJECT_STEP2_GATE_ENT02_MAX_FPR", 0.15)),
        },
        "iot02_support": {
            "macro_f1_min": max(0.0, _float_env("PROJECT_STEP2_GATE_IOT02_MIN_MACRO_F1", 0.60)),
            "fnr_max": max(0.0, _float_env("PROJECT_STEP2_GATE_IOT02_MAX_FNR", 0.25)),
            "fpr_max": max(0.0, _float_env("PROJECT_STEP2_GATE_IOT02_MAX_FPR", 0.25)),
        },
    }


def training_subprocess_env() -> dict[str, str]:
    """Extra env vars merged into training subprocess (caller supplies os.environ copy)."""
    tt = train_threads()
    return {
        "PROJECT_STEP2_TRAIN_THREADS": str(tt),
        "PROJECT_STEP2_RANDOM_SEED": str(random_seed()),
        "OMP_NUM_THREADS": str(tt),
    }


def testing_subprocess_env() -> dict[str, str]:
    wt = test_worker_threads()
    return {
        "PROJECT_STEP2_TEST_WORKER_THREADS": str(wt),
        "OMP_NUM_THREADS": str(wt),
    }


def shap_subprocess_env() -> dict[str, str]:
    wt = shap_worker_threads()
    return {
        "PROJECT_STEP2_SHAP_WORKER_THREADS": str(wt),
        "OMP_NUM_THREADS": str(wt),
    }


def rule_subprocess_env() -> dict[str, str]:
    wt = rule_worker_threads()
    return {
        "PROJECT_STEP2_RULE_WORKER_THREADS": str(wt),
        "OMP_NUM_THREADS": str(wt),
    }


def config_snapshot() -> dict[str, int | float | str]:
    gov = build_project_cpu_governor()
    return {
        "PROJECT_STEP2_TRAIN_THREADS": train_threads(),
        "PROJECT_STEP2_TEST_WORKER_THREADS": test_worker_threads(),
        "PROJECT_STEP2_SHAP_WORKER_THREADS": shap_worker_threads(),
        "PROJECT_STEP2_RULE_WORKER_THREADS": rule_worker_threads(),
        "PROJECT_STEP2_RULE_MAX_WORKERS": rule_max_workers(),
        "PROJECT_STEP2_RANDOM_SEED": random_seed(),
        "PROJECT_STEP2_MIN_MACRO_F1": quality_min_macro_f1(),
        "PROJECT_STEP2_MIN_RECALL_MACRO": quality_min_recall_macro(),
        "PROJECT_STEP2_MIN_PRECISION_MACRO": quality_min_precision_macro(),
        "PROJECT_STEP2_MAX_PREDICTED_CLASS_RATIO": quality_max_predicted_class_ratio(),
        "PROJECT_STEP2_MIN_UNIQUE_PRED_LABELS": quality_min_unique_pred_labels(),
        "PROJECT_STEP2_GATE_THRESHOLDS": evaluation_thresholds(),
        "PROJECT_WORKER_MODE": worker_mode(),
        "PROJECT_CPU_TARGET_UTILIZATION": gov.get("target_utilization"),
        "PROJECT_HOST_RESERVED_THREADS": gov.get("reserved_threads"),
        "PROJECT_THREAD_BUDGET_MAX": gov.get("thread_budget_max"),
        "PROJECT_CPU_ADAPTIVE_ENABLED": int(bool(gov.get("adaptive_enabled"))),
        "PROJECT_CPU_BAND_PCT": gov.get("band_pct"),
        "PROJECT_CPU_SAMPLE_INTERVAL_S": gov.get("sample_interval_s"),
        "PROJECT_HARD_THREAD_CAP": gov.get("hard_thread_cap"),
    }
