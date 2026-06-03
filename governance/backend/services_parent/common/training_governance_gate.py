"""Governance gate for training: leakage checks must pass before any training job runs.

Governance = prevention (blocks invalid operations). This module does not log audit
evidence; callers should log ``training_blocked`` or ``training_started`` after checks.
"""

from __future__ import annotations

from typing import Any

from services_parent.common.governance_summary import build_leakage_checks_from_db


class TrainingGovernanceError(RuntimeError):
    """Raised when Postgres-backed leakage governance checks fail."""


def evaluate_training_governance(cur: Any) -> tuple[list[dict[str, Any]], bool]:
    """Return (checks, blocking) where blocking is True if any check_status == 'fail'."""
    checks = build_leakage_checks_from_db(cur)
    blocking = any(c.get("check_status") == "fail" for c in checks)
    return checks, blocking


def assert_training_governance_allows(cur: Any) -> list[dict[str, Any]]:
    """Run governance checks; raise TrainingGovernanceError if training must be blocked."""
    checks, blocking = evaluate_training_governance(cur)
    if blocking:
        failed = [c.get("check_name") for c in checks if c.get("check_status") == "fail"]
        raise TrainingGovernanceError(
            "Training blocked: leakage governance checks failed: " + ", ".join(str(x) for x in failed if x)
        )
    return checks
