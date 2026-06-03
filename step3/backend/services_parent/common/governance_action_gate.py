"""Governance-controlled allowed actions per dataset_id (dissertation-aligned).

Governance decides what may run; audit records outcomes. This module encodes
role-specific flows for the Phase 4 dashboard and ``POST /governance/check-action``.
"""

from __future__ import annotations

from typing import Any

from services_parent.common.dataset_role_policy import ingest_workflow_mode

# --- Canonical requested_action values (dashboard + API) ---

ACTION_REGISTER_ARTIFACT = "register_artifact"
ACTION_VALIDATE_SCHEMA = "validate_schema"
ACTION_NORMALIZE = "normalize"
ACTION_CATEGORIZE = "categorize"
ACTION_CREATE_SPLIT = "create_split"
ACTION_RUN_LEAKAGE_GUARD = "run_leakage_guard"
ACTION_TRAIN_MODEL_V1 = "train_model_v1"
ACTION_EVALUATE_WITHIN_DATASET = "evaluate_within_dataset"
ACTION_OFFLINE_SHAP = "offline_shap"
ACTION_GENERATE_RULES = "generate_rules"
ACTION_AUDIT_FREEZE = "audit_freeze"

ACTION_MARK_RULE_SUPPORT = "mark_rule_support"
ACTION_EXTRACT_STATISTICAL_PATTERNS = "extract_statistical_patterns"
ACTION_SUPPORT_ENTERPRISE_RULES = "support_enterprise_rules"
ACTION_EXTRACT_RULE_PATTERNS_REPORT = "extract_rule_patterns_report"

ACTION_MARK_CROSS_TEST = "mark_cross_test"
ACTION_RUN_CROSS_DATASET_TEST = "run_cross_dataset_test"
ACTION_RECORD_DEGRADATION = "record_degradation_metrics"

ACTION_RUN_TRANSFER_TEST = "run_transfer_test"
ACTION_RECORD_ROBUSTNESS = "record_robustness_domain_shift_metrics"

ACTION_EXTRACT_IOT_RULE_PATTERNS = "extract_iot_iot_rule_patterns"
ACTION_SUPPORT_SCOPED_RULES = "support_scoped_cross_scope_rules"

ACTION_REGISTER_PCAP = "register_pcap"
ACTION_VALIDATE_CHECKSUM = "validate_checksum"
ACTION_VALIDATE_ADAPTER = "validate_adapter"
ACTION_SELECT_REPLAY_PHASE = "select_replay_phase"
ACTION_RUN_REPLAY = "run_replay"
ACTION_CHILD_RULE_TRIGGER = "child_rule_triggering"
ACTION_PARENT_REVIEW = "parent_review"
ACTION_RUNTIME_SHAP = "runtime_shap"
ACTION_REPLAY_REPORT = "replay_report"

ACTION_REGISTER_REFERENCE = "register_reference"
ACTION_ADD_CITATION = "add_citation_link"
ACTION_MARK_REFERENCE_FROZEN = "mark_reference_frozen"
ACTION_SHOW_LITERATURE = "show_literature_context"

# Queues the existing worker pipeline (normalise → … → postgres)
ACTION_QUEUE_SUPERVISED_PIPELINE = "queue_supervised_pipeline"
ACTION_QUEUE_REPLAY_INVENTORY = "queue_replay_inventory"


def _tooltip_prefix() -> str:
    return "Blocked by governance:"


def _profile_ent01() -> dict[str, Any]:
    steps = [
        {"id": "register", "label": "Register artifact", "allowed": True},
        {"id": "validate_schema", "label": "Validate schema", "allowed": True},
        {"id": "normalize", "label": "Normalize", "allowed": True},
        {"id": "categorize", "label": "Categorize", "allowed": True},
        {"id": "split", "label": "Create train / validate / test split", "allowed": True},
        {"id": "leakage", "label": "Run leakage guard", "allowed": True},
        {"id": "train_v1", "label": "Train Model V1", "allowed": True},
        {"id": "eval_in", "label": "Evaluate within-dataset", "allowed": True},
        {"id": "shap", "label": "Run offline SHAP", "allowed": True},
        {"id": "rules", "label": "Support rule generation", "allowed": True},
        {"id": "freeze", "label": "Audit + freeze", "allowed": True},
    ]
    allowed = {
        ACTION_REGISTER_ARTIFACT,
        ACTION_VALIDATE_SCHEMA,
        ACTION_NORMALIZE,
        ACTION_CATEGORIZE,
        ACTION_CREATE_SPLIT,
        ACTION_RUN_LEAKAGE_GUARD,
        ACTION_TRAIN_MODEL_V1,
        ACTION_EVALUATE_WITHIN_DATASET,
        ACTION_OFFLINE_SHAP,
        ACTION_GENERATE_RULES,
        ACTION_AUDIT_FREEZE,
        ACTION_QUEUE_SUPERVISED_PIPELINE,
    }
    buttons = [
        {"requested_action": ACTION_REGISTER_ARTIFACT, "label": "Register"},
        {"requested_action": ACTION_VALIDATE_SCHEMA, "label": "Validate"},
        {"requested_action": ACTION_NORMALIZE, "label": "Normalize"},
        {"requested_action": ACTION_CATEGORIZE, "label": "Categorize"},
        {"requested_action": ACTION_CREATE_SPLIT, "label": "Create split"},
        {"requested_action": ACTION_RUN_LEAKAGE_GUARD, "label": "Run leakage guard"},
        {"requested_action": ACTION_TRAIN_MODEL_V1, "label": "Train Model V1"},
        {"requested_action": ACTION_EVALUATE_WITHIN_DATASET, "label": "Evaluate"},
        {"requested_action": ACTION_OFFLINE_SHAP, "label": "SHAP"},
        {"requested_action": ACTION_GENERATE_RULES, "label": "Generate rules"},
    ]
    return {
        "dataset_id": "ENT-01",
        "badge": "TRAINING SOURCE",
        "display_role": "Primary Training Source",
        "allowed_uses": [
            "Canonical supervised corpus for Model V1",
            "Within-dataset evaluation and offline SHAP",
            "Governed rule-generation support after training artifacts exist",
        ],
        "timeline_steps": steps,
        "allowed_actions": allowed,
        "action_buttons": buttons,
    }


def _profile_ent02() -> dict[str, Any]:
    blocked_train = f"{_tooltip_prefix()} ENT-02 is enterprise rule support — Model V1 trains on ENT-01 only."
    blocked_split = f"{_tooltip_prefix()} ENT-02 must not create ENT-01 Model V1 train/val/test splits."
    steps = [
        {"id": "register", "label": "Register artifact", "allowed": True},
        {"id": "validate_schema", "label": "Validate schema", "allowed": True},
        {"id": "normalize", "label": "Normalize", "allowed": True},
        {"id": "categorize", "label": "Categorize", "allowed": True},
        {"id": "mark_rs", "label": "Mark as rule_support", "allowed": True},
        {"id": "extract", "label": "Extract statistical patterns", "allowed": True},
        {"id": "support", "label": "Support enterprise / global rules", "allowed": True},
        {"id": "freeze", "label": "Audit + freeze", "allowed": True},
        {"id": "split", "label": "Create V1 train split", "allowed": False, "block_reason": blocked_split},
        {"id": "train_v1", "label": "Train Model V1", "allowed": False, "block_reason": blocked_train},
    ]
    allowed = {
        ACTION_REGISTER_ARTIFACT,
        ACTION_VALIDATE_SCHEMA,
        ACTION_NORMALIZE,
        ACTION_CATEGORIZE,
        ACTION_MARK_RULE_SUPPORT,
        ACTION_EXTRACT_STATISTICAL_PATTERNS,
        ACTION_SUPPORT_ENTERPRISE_RULES,
        ACTION_EXTRACT_RULE_PATTERNS_REPORT,
        ACTION_AUDIT_FREEZE,
        ACTION_QUEUE_SUPERVISED_PIPELINE,
    }
    buttons = [
        {"requested_action": ACTION_REGISTER_ARTIFACT, "label": "Register"},
        {"requested_action": ACTION_VALIDATE_SCHEMA, "label": "Validate"},
        {"requested_action": ACTION_NORMALIZE, "label": "Normalize"},
        {"requested_action": ACTION_CATEGORIZE, "label": "Categorize"},
        {"requested_action": ACTION_EXTRACT_STATISTICAL_PATTERNS, "label": "Extract rule patterns"},
        {"requested_action": ACTION_EXTRACT_RULE_PATTERNS_REPORT, "label": "Generate rule support report"},
    ]
    return {
        "dataset_id": "ENT-02",
        "badge": "RULE SUPPORT",
        "display_role": "Enterprise Rule Support",
        "allowed_uses": ["UNSW-NB15 flows for rule packs", "No ENT-01 train merge"],
        "timeline_steps": steps,
        "allowed_actions": allowed,
        "action_buttons": buttons,
    }


def _profile_dns01() -> dict[str, Any]:
    br = f"{_tooltip_prefix()} DNS-01 is cross-test only — no Model V1 training on this corpus."
    br2 = f"{_tooltip_prefix()} DNS-01 is cross-test only — rule support requires explicit governance approval."
    br3 = f"{_tooltip_prefix()} DNS-01 is cross-test only — replay is not in scope for this dataset role."
    steps = [
        {"id": "register", "label": "Register artifact", "allowed": True},
        {"id": "validate_schema", "label": "Validate schema", "allowed": True},
        {"id": "normalize", "label": "Normalize", "allowed": True},
        {"id": "categorize", "label": "Categorize", "allowed": True},
        {"id": "mark_xt", "label": "Mark as cross_test", "allowed": True},
        {"id": "cross_eval", "label": "Run Model V1 cross-dataset evaluation", "allowed": True},
        {"id": "deg", "label": "Record degradation metrics", "allowed": True},
        {"id": "freeze", "label": "Audit + freeze", "allowed": True},
        {"id": "train_v1", "label": "Train Model V1", "allowed": False, "block_reason": br},
        {"id": "rule", "label": "Rule support (default)", "allowed": False, "block_reason": br2},
        {"id": "replay", "label": "Replay", "allowed": False, "block_reason": br3},
    ]
    allowed = {
        ACTION_REGISTER_ARTIFACT,
        ACTION_VALIDATE_SCHEMA,
        ACTION_NORMALIZE,
        ACTION_CATEGORIZE,
        ACTION_MARK_CROSS_TEST,
        ACTION_RUN_CROSS_DATASET_TEST,
        ACTION_RECORD_DEGRADATION,
        ACTION_AUDIT_FREEZE,
        ACTION_QUEUE_SUPERVISED_PIPELINE,
    }
    buttons = [
        {"requested_action": ACTION_REGISTER_ARTIFACT, "label": "Register"},
        {"requested_action": ACTION_VALIDATE_SCHEMA, "label": "Validate"},
        {"requested_action": ACTION_NORMALIZE, "label": "Normalize"},
        {"requested_action": ACTION_CATEGORIZE, "label": "Categorize"},
        {"requested_action": ACTION_RUN_CROSS_DATASET_TEST, "label": "Run cross-dataset test"},
    ]
    return {
        "dataset_id": "DNS-01",
        "badge": "CROSS-TEST ONLY",
        "display_role": "Cross-Test Only",
        "allowed_uses": ["CIRA-CIC-DoHBrw-2020 for cross-dataset evaluation vs Model V1 trained on ENT-01"],
        "timeline_steps": steps,
        "allowed_actions": allowed,
        "action_buttons": buttons,
    }


def _profile_iot01() -> dict[str, Any]:
    br = f"{_tooltip_prefix()} IOT-01 is transfer-test only — Model V1 does not train on TON_IoT."
    br2 = f"{_tooltip_prefix()} IOT-01 is transfer-test — replay is out of scope for this role."
    steps = [
        {"id": "register", "label": "Register artifact", "allowed": True},
        {"id": "validate_schema", "label": "Validate schema", "allowed": True},
        {"id": "normalize", "label": "Normalize", "allowed": True},
        {"id": "categorize", "label": "Categorize", "allowed": True},
        {"id": "mark_xt", "label": "Mark as cross_test", "allowed": True},
        {"id": "xfer", "label": "Run Model V1 transfer evaluation", "allowed": True},
        {"id": "rob", "label": "Record robustness / domain-shift metrics", "allowed": True},
        {"id": "freeze", "label": "Audit + freeze", "allowed": True},
        {"id": "train_v1", "label": "Train Model V1", "allowed": False, "block_reason": br},
        {"id": "replay", "label": "Replay", "allowed": False, "block_reason": br2},
    ]
    allowed = {
        ACTION_REGISTER_ARTIFACT,
        ACTION_VALIDATE_SCHEMA,
        ACTION_NORMALIZE,
        ACTION_CATEGORIZE,
        ACTION_MARK_CROSS_TEST,
        ACTION_RUN_TRANSFER_TEST,
        ACTION_RECORD_ROBUSTNESS,
        ACTION_AUDIT_FREEZE,
        ACTION_QUEUE_SUPERVISED_PIPELINE,
    }
    buttons = [
        {"requested_action": ACTION_REGISTER_ARTIFACT, "label": "Register"},
        {"requested_action": ACTION_VALIDATE_SCHEMA, "label": "Validate"},
        {"requested_action": ACTION_NORMALIZE, "label": "Normalize"},
        {"requested_action": ACTION_CATEGORIZE, "label": "Categorize"},
        {"requested_action": ACTION_RUN_TRANSFER_TEST, "label": "Run transfer test"},
    ]
    return {
        "dataset_id": "IOT-01",
        "badge": "CROSS-TEST ONLY",
        "display_role": "IoT/IIoT Transfer Test",
        "allowed_uses": ["TON_IoT for transfer and robustness metrics against ENT-01-trained Model V1"],
        "timeline_steps": steps,
        "allowed_actions": allowed,
        "action_buttons": buttons,
    }


def _profile_iot02() -> dict[str, Any]:
    br = f"{_tooltip_prefix()} IOT-02 is IoT/IIoT rule support — Model V1 trains on ENT-01 only."
    br2 = f"{_tooltip_prefix()} IOT-02 — cross-test requires explicit governance approval."
    steps = [
        {"id": "register", "label": "Register artifact", "allowed": True},
        {"id": "validate_schema", "label": "Validate schema", "allowed": True},
        {"id": "normalize", "label": "Normalize", "allowed": True},
        {"id": "categorize", "label": "Categorize", "allowed": True},
        {"id": "mark_rs", "label": "Mark as rule_support", "allowed": True},
        {"id": "extract", "label": "Extract IoT/IIoT patterns", "allowed": True},
        {"id": "scoped", "label": "Support scoped and cross-scope rules", "allowed": True},
        {"id": "freeze", "label": "Audit + freeze", "allowed": True},
        {"id": "train_v1", "label": "Train Model V1", "allowed": False, "block_reason": br},
        {"id": "cross", "label": "Cross-test (default)", "allowed": False, "block_reason": br2},
    ]
    allowed = {
        ACTION_REGISTER_ARTIFACT,
        ACTION_VALIDATE_SCHEMA,
        ACTION_NORMALIZE,
        ACTION_CATEGORIZE,
        ACTION_MARK_RULE_SUPPORT,
        ACTION_EXTRACT_IOT_RULE_PATTERNS,
        ACTION_SUPPORT_SCOPED_RULES,
        ACTION_AUDIT_FREEZE,
        ACTION_QUEUE_SUPERVISED_PIPELINE,
    }
    buttons = [
        {"requested_action": ACTION_REGISTER_ARTIFACT, "label": "Register"},
        {"requested_action": ACTION_VALIDATE_SCHEMA, "label": "Validate"},
        {"requested_action": ACTION_NORMALIZE, "label": "Normalize"},
        {"requested_action": ACTION_CATEGORIZE, "label": "Categorize"},
        {"requested_action": ACTION_EXTRACT_IOT_RULE_PATTERNS, "label": "Extract IoT/IIoT rule patterns"},
    ]
    return {
        "dataset_id": "IOT-02",
        "badge": "RULE SUPPORT",
        "display_role": "IoT/IIoT Rule Support",
        "allowed_uses": ["BoT-IoT patterns for scoped / cross-scope Child rules without ENT-01 train merge"],
        "timeline_steps": steps,
        "allowed_actions": allowed,
        "action_buttons": buttons,
    }


def _profile_rep01() -> dict[str, Any]:
    br = f"{_tooltip_prefix()} REP-01 is replay-only — must not normalize into supervised training corpus."
    br2 = f"{_tooltip_prefix()} REP-01 cannot create train/validate/test splits for supervised benchmarks."
    br3 = f"{_tooltip_prefix()} REP-01 cannot train classification models on PCAP-derived tensors for supervised accuracy claims."
    steps = [
        {"id": "reg_pcap", "label": "Register PCAP artifact", "allowed": True},
        {"id": "chk", "label": "Validate file / checksum", "allowed": True},
        {"id": "adapt", "label": "Adapter validation", "allowed": True},
        {"id": "mark_rep", "label": "Mark as replay_only", "allowed": True},
        {"id": "phase", "label": "Select replay phase", "allowed": True},
        {"id": "run", "label": "Run replay", "allowed": True},
        {"id": "child", "label": "Child rule triggering", "allowed": True},
        {"id": "parent", "label": "Parent review", "allowed": True},
        {"id": "shap_rt", "label": "Runtime SHAP (where applicable)", "allowed": True},
        {"id": "report", "label": "Replay report", "allowed": True},
        {"id": "freeze", "label": "Audit + freeze", "allowed": True},
        {"id": "norm_train", "label": "Normalize into training corpus", "allowed": False, "block_reason": br},
        {"id": "split", "label": "Create train/validate/test split", "allowed": False, "block_reason": br2},
        {"id": "train", "label": "Train model (supervised)", "allowed": False, "block_reason": br3},
    ]
    allowed = {
        ACTION_REGISTER_PCAP,
        ACTION_VALIDATE_CHECKSUM,
        ACTION_VALIDATE_ADAPTER,
        ACTION_SELECT_REPLAY_PHASE,
        ACTION_RUN_REPLAY,
        ACTION_CHILD_RULE_TRIGGER,
        ACTION_PARENT_REVIEW,
        ACTION_RUNTIME_SHAP,
        ACTION_REPLAY_REPORT,
        ACTION_AUDIT_FREEZE,
        ACTION_QUEUE_REPLAY_INVENTORY,
    }
    buttons = [
        {"requested_action": ACTION_REGISTER_PCAP, "label": "Register PCAP"},
        {"requested_action": ACTION_VALIDATE_CHECKSUM, "label": "Validate checksum"},
        {"requested_action": ACTION_VALIDATE_ADAPTER, "label": "Validate adapter"},
        {"requested_action": ACTION_SELECT_REPLAY_PHASE, "label": "Select replay phase"},
        {"requested_action": ACTION_RUN_REPLAY, "label": "Run replay"},
        {"requested_action": ACTION_REPLAY_REPORT, "label": "View replay report"},
    ]
    return {
        "dataset_id": "REP-01",
        "badge": "REPLAY ONLY",
        "display_role": "Replay Only",
        "allowed_uses": ["CTU-13 PCAP replay, adapter validation, behavioural metrics — not supervised train accuracy"],
        "timeline_steps": steps,
        "allowed_actions": allowed,
        "action_buttons": buttons,
    }


def _profile_ref01() -> dict[str, Any]:
    br = f"{_tooltip_prefix()} REF-01 is reference-only — no experiment pipeline uploads or processing."
    steps = [
        {"id": "reg_ref", "label": "Register reference", "allowed": True},
        {"id": "cite", "label": "Store citation / source link", "allowed": True},
        {"id": "mark", "label": "Mark as reference_only", "allowed": True},
        {"id": "lit", "label": "Show literature-context status", "allowed": True},
        {"id": "freeze", "label": "Audit + freeze", "allowed": True},
        {"id": "pipe", "label": "Upload into experiment pipeline", "allowed": False, "block_reason": br},
        {"id": "norm", "label": "Normalize", "allowed": False, "block_reason": br},
        {"id": "split", "label": "Split", "allowed": False, "block_reason": br},
        {"id": "train", "label": "Train", "allowed": False, "block_reason": br},
        {"id": "xt", "label": "Cross-test", "allowed": False, "block_reason": br},
        {"id": "rep", "label": "Replay", "allowed": False, "block_reason": br},
        {"id": "rules", "label": "Rule generation", "allowed": False, "block_reason": br},
    ]
    allowed = {
        ACTION_REGISTER_REFERENCE,
        ACTION_ADD_CITATION,
        ACTION_MARK_REFERENCE_FROZEN,
        ACTION_SHOW_LITERATURE,
        ACTION_AUDIT_FREEZE,
    }
    buttons = [
        {"requested_action": ACTION_REGISTER_REFERENCE, "label": "Register reference"},
        {"requested_action": ACTION_ADD_CITATION, "label": "Add citation link"},
        {"requested_action": ACTION_MARK_REFERENCE_FROZEN, "label": "Mark reference frozen"},
    ]
    return {
        "dataset_id": "REF-01",
        "badge": "REFERENCE ONLY",
        "display_role": "Reference Only",
        "allowed_uses": ["NSL-KDD citation and literature comparison only"],
        "timeline_steps": steps,
        "allowed_actions": allowed,
        "action_buttons": buttons,
    }


_PROFILES: dict[str, dict[str, Any]] = {
    "ENT-01": _profile_ent01(),
    "ENT-02": _profile_ent02(),
    "DNS-01": _profile_dns01(),
    "IOT-01": _profile_iot01(),
    "IOT-02": _profile_iot02(),
    "REP-01": _profile_rep01(),
    "REF-01": _profile_ref01(),
}


def governance_profile_for(dataset_id: str, role: str | None = None) -> dict[str, Any]:
    """Return a copy of the static profile for known IDs; else infer from role."""
    if dataset_id in _PROFILES:
        return dict(_PROFILES[dataset_id])
    r = (role or "").lower()
    if "reference" in r:
        return dict(_profile_ref01())
    if "replay" in r or dataset_id.startswith("REP-"):
        return dict(_profile_rep01())
    if "rule_support" in r or "rule" in r:
        if "iot" in r or dataset_id.startswith("IOT-"):
            return dict(_profile_iot02())
        return dict(_profile_ent02())
    if "cross_dataset" in r or "evaluation" in r:
        return dict(_profile_dns01())
    return dict(
        {
            "dataset_id": dataset_id,
            "badge": "UNCLASSIFIED",
            "display_role": role or "unknown",
            "allowed_uses": ["Define role in manifest to enable governed actions."],
            "timeline_steps": [],
            "allowed_actions": {ACTION_AUDIT_FREEZE},
            "action_buttons": [{"requested_action": ACTION_REGISTER_ARTIFACT, "label": "Register"}],
        }
    )


def blocked_steps_list(profile: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for step in profile.get("timeline_steps") or []:
        if not step.get("allowed", True):
            out.append(
                {
                    "step_id": str(step.get("id", "")),
                    "label": str(step.get("label", "")),
                    "reason": str(step.get("block_reason", "blocked")),
                }
            )
    return out


def allowed_next_step_labels(profile: dict[str, Any]) -> list[str]:
    return [str(s.get("label", "")) for s in (profile.get("timeline_steps") or []) if s.get("allowed", True)]


def evaluate_governance_action(
    *,
    dataset_id: str,
    role: str | None,
    requested_action: str,
    experiment_id: str | None,
    model_version: str | None,
    cur: Any | None,
    leakage_checks_failed: bool,
    step0_ready: bool | None = None,
) -> dict[str, Any]:
    """Return allowed, reason, allowed_next_steps, blocked_steps for API and dashboard.

    When ``step0_ready`` is false and ingest mode is ``full``, ``queue_supervised_pipeline`` is denied.
    Pass ``None`` to skip the Step-0 check (callers that do not compute Step-0).
    """
    profile = governance_profile_for(dataset_id, role)
    allowed_set: set[str] = set(profile.get("allowed_actions") or [])
    blocked = blocked_steps_list(profile)
    next_labels = allowed_next_step_labels(profile)

    if not requested_action:
        return {
            "allowed": False,
            "reason": "requested_action is required",
            "allowed_next_steps": next_labels,
            "blocked_steps": blocked,
            "governance_profile": _public_profile_slice(profile),
        }

    if requested_action == ACTION_QUEUE_SUPERVISED_PIPELINE:
        mode = ingest_workflow_mode(dataset_id, role)
        if mode == "forbidden":
            return {
                "allowed": False,
                "reason": f"{_tooltip_prefix()} {dataset_id} is reference-only and cannot enter the supervised pipeline.",
                "allowed_next_steps": next_labels,
                "blocked_steps": blocked,
                "governance_profile": _public_profile_slice(profile),
            }
        if mode == "replay_inventory":
            return {
                "allowed": False,
                "reason": f"{_tooltip_prefix()} {dataset_id} is replay-only — use queue_replay_inventory instead of the supervised CSV pipeline.",
                "allowed_next_steps": next_labels,
                "blocked_steps": blocked,
                "governance_profile": _public_profile_slice(profile),
            }
        if step0_ready is False and mode == "full":
            return {
                "allowed": False,
                "reason": f"{_tooltip_prefix()} Step-0 failed — all manifest `process_csv_paths` files must exist under the dataset raw folder (see /status `step0` for paths). In Docker, ensure the host scratch tree is bound to /data/raw_downloads.",
                "allowed_next_steps": next_labels,
                "blocked_steps": blocked,
                "governance_profile": _public_profile_slice(profile),
            }

    if requested_action == ACTION_QUEUE_REPLAY_INVENTORY:
        mode = ingest_workflow_mode(dataset_id, role)
        if mode != "replay_inventory":
            return {
                "allowed": False,
                "reason": f"{_tooltip_prefix()} queue_replay_inventory applies only to replay-only datasets (e.g. REP-01).",
                "allowed_next_steps": next_labels,
                "blocked_steps": blocked,
                "governance_profile": _public_profile_slice(profile),
            }

    if requested_action not in allowed_set:
        return {
            "allowed": False,
            "reason": f"{_tooltip_prefix()} action '{requested_action}' is not approved for {dataset_id} ({profile.get('display_role')}).",
            "allowed_next_steps": next_labels,
            "blocked_steps": blocked,
            "governance_profile": _public_profile_slice(profile),
        }

    if requested_action == ACTION_TRAIN_MODEL_V1:
        if dataset_id != "ENT-01":
            return {
                "allowed": False,
                "reason": f"{_tooltip_prefix()} Model V1 trains on ENT-01 only; {dataset_id} cannot run train_model_v1.",
                "allowed_next_steps": next_labels,
                "blocked_steps": blocked,
                "governance_profile": _public_profile_slice(profile),
            }
        if leakage_checks_failed:
            return {
                "allowed": False,
                "reason": f"{_tooltip_prefix()} leakage guard checks failed — resolve phase4.leakage_guard_results / SQL checks before training.",
                "allowed_next_steps": next_labels,
                "blocked_steps": blocked,
                "governance_profile": _public_profile_slice(profile),
            }
        if cur is None:
            return {
                "allowed": False,
                "reason": "Database connection required to verify Model V1 training governance (leakage SQL).",
                "allowed_next_steps": next_labels,
                "blocked_steps": blocked,
                "governance_profile": _public_profile_slice(profile),
            }
        try:
            from services_parent.common.training_governance_gate import (
                TrainingGovernanceError,
                assert_training_governance_allows,
            )

            assert_training_governance_allows(cur)
        except Exception as exc:
            return {
                "allowed": False,
                "reason": f"{_tooltip_prefix()} {exc}",
                "allowed_next_steps": next_labels,
                "blocked_steps": blocked,
                "governance_profile": _public_profile_slice(profile),
            }

    return {
        "allowed": True,
        "reason": "approved",
        "allowed_next_steps": next_labels,
        "blocked_steps": blocked,
        "governance_profile": _public_profile_slice(profile),
        "experiment_id": experiment_id,
        "model_version": model_version,
    }


def _public_profile_slice(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "dataset_id": profile.get("dataset_id"),
        "badge": profile.get("badge"),
        "display_role": profile.get("display_role"),
        "allowed_uses": profile.get("allowed_uses"),
    }


def build_governance_ui_row(
    *,
    dataset_id: str,
    role: str | None,
    dashboard_state: dict[str, Any],
    step0_ready: bool,
    leakage_blocking: bool,
    latest_audit: dict[str, Any] | None,
) -> dict[str, Any]:
    """Per-dataset card fields for /status uploads[].governance_ui."""
    profile = governance_profile_for(dataset_id, role)
    phase = str((dashboard_state or {}).get("phase") or "download")
    stages = (dashboard_state or {}).get("stages") or []
    stage_summary = ", ".join(f"{s.get('id')}:{s.get('status')}" for s in stages[:5])

    if not step0_ready and ingest_workflow_mode(dataset_id, role) == "full":
        next_action = "Resolve Step-0 (manifest CSV filenames present under dataset folder)"
    elif phase in {"download", ""}:
        next_action = "Use an allowed action button (governance check) then queue worker stages where implemented"
    else:
        next_action = f"Worker phase: {phase} — {stage_summary or 'see Background worker'}"

    audit_status = "No audit rows for this dataset_id yet"
    if latest_audit:
        audit_status = f"Latest: {latest_audit.get('event_type')} @ {latest_audit.get('timestamp_utc')}"

    leakage_status = "unknown"
    if dataset_id == "ENT-01":
        leakage_status = "fail" if leakage_blocking else "pass"
    else:
        leakage_status = "n/a (Model V1 train not on this ID)"

    return {
        "badge": profile.get("badge"),
        "display_role": profile.get("display_role"),
        "allowed_uses": profile.get("allowed_uses"),
        "current_stage": phase,
        "worker_stages_summary": stage_summary,
        "next_allowed_action": next_action,
        "blocked_actions": blocked_steps_list(profile),
        "leakage_guard_status": leakage_status,
        "audit_status": audit_status,
        "timeline_steps": profile.get("timeline_steps"),
        "action_buttons": profile.get("action_buttons"),
    }


def latest_audit_by_dataset(audit_events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """First occurrence per dataset_id (events are newest-first from list_audit_events)."""
    out: dict[str, dict[str, Any]] = {}
    for ev in audit_events:
        did = ev.get("dataset_id")
        if did and did not in out:
            out[str(did)] = ev
    return out
