"""Canonical audit event_type strings for Phase 4 (AUDIT = evidence only).

These values are written to ``phase4.audit_log`` (and optional domain logs).
They must never implement policy; governance checks live elsewhere.
"""

# Ingestion / splits
DATASET_INGESTED = "dataset_ingested"
SPLIT_CREATED = "split_created"

# Training lifecycle
TRAINING_STARTED = "training_started"
TRAINING_COMPLETED = "training_completed"
TRAINING_BLOCKED = "training_blocked"

# Explainability / rules / replay
SHAP_GENERATED = "shap_generated"
RULE_GENERATED = "rule_generated"
REPLAY_STARTED = "replay_started"
REPLAY_COMPLETED = "replay_completed"

# Runtime
ALERT_GENERATED = "alert_generated"
CROSS_SCOPE_TRIGGERED = "cross_scope_triggered"

# Governance gate (audit evidence when dashboard denies an action)
GOVERNANCE_BLOCKED_ACTION = "governance_blocked_action"

# Model V1 workflow (coordinator; audit evidence only)
MODEL_V1_STEP1_COMPLETED = "model_v1_step1_completed"
MODEL_V1_STEP1_FAILED = "model_v1_step1_failed"
MODEL_V1_STEP2_COMPLETED = "model_v1_step2_completed"
MODEL_V1_STEP2_FAILED = "model_v1_step2_failed"
MODEL_V1_STEP2_DENIED = "model_v1_step2_denied"
MODEL_V1_STEP3_STARTED = "model_v1_step3_started"
MODEL_V1_STEP3_COMPLETED = "model_v1_step3_completed"
MODEL_V1_STEP3_FAILED = "model_v1_step3_failed"

# Dataset lifecycle (writers emit when jobs exist; dashboard may reserve names)
DATASET_REGISTERED = "dataset_registered"
ARTIFACT_VALIDATED = "artifact_validated"
NORMALIZED = "normalized"
CATEGORIZED = "categorized"
LEAKAGE_GUARD_PASSED = "leakage_guard_passed"
LEAKAGE_GUARD_FAILED = "leakage_guard_failed"
EVALUATION_COMPLETED = "evaluation_completed"
RULE_SUPPORT_MARKED = "rule_support_marked"
CROSS_TEST_MARKED = "cross_test_marked"
