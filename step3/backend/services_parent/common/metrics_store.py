from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from services_parent.common.phase4_db import connect

_METRIC_NAME_RE = re.compile(r"[a-z][a-z0-9_]*")
_VALID_STEPS = {"step1", "step2", "step3", "step4"}
_DEPRECATED_METRICS_BY_STEP: dict[str, set[str]] = {
    "step1": {
        "mismatch_escalation_correctness",
        "vector_mapping_accuracy",
        "failed_input_archive_coverage",
    },
    "step2": {
        "pareto_rank",
    },
}


@dataclass(frozen=True)
class MetricPrinciple:
    step: str
    metric_name: str
    calculation_method: str
    principle_status: str


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _principle_doc_path() -> Path:
    return _repo_root() / "docs" / "final_dissertation_docs" / "metrics_principle_review.md"


def _split_md_row(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def load_metric_principles() -> dict[str, dict[str, MetricPrinciple]]:
    out: dict[str, dict[str, MetricPrinciple]] = {"step1": {}, "step2": {}, "step3": {}, "step4": {}}
    path = _principle_doc_path()
    if not path.is_file():
        return out

    lines = path.read_text(encoding="utf-8").splitlines()
    current_step = ""
    in_table = False
    for raw in lines:
        line = raw.strip()
        if line.startswith("## Step 1"):
            current_step = "step1"
            in_table = False
            continue
        if line.startswith("## Step 2"):
            current_step = "step2"
            in_table = False
            continue
        if line.startswith("## Step 3"):
            current_step = "step3"
            in_table = False
            continue
        if line.startswith("## Step 4"):
            current_step = "step4"
            in_table = False
            continue
        if line.startswith("## "):
            in_table = False
            continue

        if not current_step:
            continue
        if line.startswith("| Metric | Principle expectation | Status |"):
            in_table = True
            continue
        if in_table and line.startswith("|---"):
            continue
        if not in_table or not line.startswith("|"):
            continue

        cols = _split_md_row(line)
        if len(cols) < 3:
            continue
        metric_name = str(cols[0] or "").strip().strip("`")
        if not _METRIC_NAME_RE.fullmatch(metric_name):
            continue
        if is_deprecated_metric(current_step, metric_name):
            continue
        out[current_step][metric_name] = MetricPrinciple(
            step=current_step,
            metric_name=metric_name,
            calculation_method=str(cols[1] or "").strip(),
            principle_status=str(cols[2] or "").strip() or "missing",
        )
    return out


def _to_numeric_or_none(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return round(float(value), 6)
    except Exception:
        return None


def _infer_status_from_row(metric_name: str, row: dict[str, Any], principle_status: str) -> tuple[str, str]:
    calc_status = str(row.get("calculation_status") or row.get("status") or "").strip().lower()
    if calc_status in {"measured", "not_collected", "not_applicable", "failed"}:
        pass
    else:
        calc_status = "measured" if _to_numeric_or_none(row.get("metric_value")) is not None else "not_collected"
    status = str(row.get("principle_status") or row.get("status_in_review") or principle_status or "").strip()
    if not status:
        status = "missing"
    if calc_status == "failed" and status == "collected_as_principle":
        status = "incorrect_principle"
    _ = metric_name
    return status, calc_status


def deprecated_metrics_for_step(step: str) -> set[str]:
    return set(_DEPRECATED_METRICS_BY_STEP.get(str(step or "").strip().lower(), set()))


def is_deprecated_metric(step: str, metric_name: str) -> bool:
    return str(metric_name or "").strip() in deprecated_metrics_for_step(step)


def purge_deprecated_metrics(*, step: str | None = None) -> dict[str, int]:
    step_key = str(step or "").strip().lower()
    metrics: set[str] = set()
    if step_key:
        metrics = deprecated_metrics_for_step(step_key)
    else:
        for vals in _DEPRECATED_METRICS_BY_STEP.values():
            metrics.update(vals)
    if not metrics:
        return {"phase4.metrics": 0, "phase4.results_metrics_required_matrix": 0}

    deleted_metrics = 0
    deleted_matrix = 0
    with connect() as conn:
        with conn.cursor() as cur:
            if step_key:
                cur.execute(
                    """
                    DELETE FROM phase4.metrics
                    WHERE step = %(step)s
                      AND metric = ANY(%(metrics)s);
                    """,
                    {"step": step_key, "metrics": sorted(metrics)},
                )
            else:
                cur.execute(
                    """
                    DELETE FROM phase4.metrics
                    WHERE metric = ANY(%(metrics)s);
                    """,
                    {"metrics": sorted(metrics)},
                )
            deleted_metrics = int(cur.rowcount or 0)

            cur.execute(
                """
                SELECT to_regclass('phase4.results_metrics_required_matrix')::text;
                """
            )
            has_matrix = bool((cur.fetchone() or [""])[0])
            if has_matrix:
                cur.execute(
                    """
                    DELETE FROM phase4.results_metrics_required_matrix
                    WHERE metric_name = ANY(%(metrics)s);
                    """,
                    {"metrics": sorted(metrics)},
                )
                deleted_matrix = int(cur.rowcount or 0)
        conn.commit()
    return {
        "phase4.metrics": deleted_metrics,
        "phase4.results_metrics_required_matrix": deleted_matrix,
    }


def upsert_step_metrics(
    *,
    step: str,
    step_unique_id: str,
    metric_rows: dict[str, dict[str, Any]] | list[dict[str, Any]],
    include_all_principle_metrics: bool = True,
    lineage: dict[str, Any] | None = None,
) -> None:
    step_key = str(step or "").strip().lower()
    sid = str(step_unique_id or "").strip()
    if step_key not in _VALID_STEPS or not sid:
        return

    principles = load_metric_principles().get(step_key, {})
    deprecated = deprecated_metrics_for_step(step_key)
    provided: dict[str, dict[str, Any]] = {}
    if isinstance(metric_rows, dict):
        for metric_name, row in metric_rows.items():
            mname = str(metric_name or "").strip()
            if not _METRIC_NAME_RE.fullmatch(mname) or not isinstance(row, dict):
                continue
            if mname in deprecated:
                continue
            payload = dict(row)
            if "metric_name" not in payload:
                payload["metric_name"] = mname
            provided[mname] = payload
    elif isinstance(metric_rows, list):
        for row in metric_rows:
            if not isinstance(row, dict):
                continue
            mname = str(row.get("metric_name") or "").strip()
            if not _METRIC_NAME_RE.fullmatch(mname):
                continue
            if mname in deprecated:
                continue
            provided[mname] = dict(row)

    metric_names: set[str] = set(provided.keys())
    if include_all_principle_metrics and principles:
        metric_names.update(principles.keys())
    metric_names = {m for m in metric_names if m not in deprecated}
    if not metric_names:
        if deprecated:
            purge_deprecated_metrics(step=step_key)
        return

    with connect() as conn:
        with conn.cursor() as cur:
            for metric_name in sorted(metric_names):
                principle = principles.get(metric_name)
                row = dict(provided.get(metric_name) or {})
                metric_value = _to_numeric_or_none(row.get("metric_value"))
                numerator = _to_numeric_or_none(row.get("numerator"))
                denominator = _to_numeric_or_none(row.get("denominator"))
                status, calculation_status = _infer_status_from_row(
                    metric_name,
                    row=row,
                    principle_status=(principle.principle_status if principle else "missing"),
                )
                details = row.get("details_json")
                if not isinstance(details, dict):
                    details = {}
                if lineage:
                    for key, value in lineage.items():
                        if key not in details:
                            details[key] = value
                source_ref = str(row.get("source_ref") or "").strip()
                if source_ref:
                    details.setdefault("source_ref", source_ref)
                unit = str(row.get("unit") or "").strip()
                if unit:
                    details.setdefault("unit", unit)

                cur.execute(
                    """
                    INSERT INTO phase4.metrics (
                        createdat,
                        updatedat,
                        step,
                        step_unique_id,
                        metric,
                        calculation_method,
                        numerator,
                        denominator,
                        metric_value,
                        status,
                        calculation_status,
                        details_json
                    )
                    VALUES (
                        now(),
                        now(),
                        %(step)s,
                        %(step_unique_id)s,
                        %(metric)s,
                        %(calculation_method)s,
                        %(numerator)s,
                        %(denominator)s,
                        %(metric_value)s,
                        %(status)s,
                        %(calculation_status)s,
                        %(details_json)s::jsonb
                    )
                    ON CONFLICT (step, step_unique_id, metric)
                    DO UPDATE
                    SET
                        updatedat = now(),
                        calculation_method = EXCLUDED.calculation_method,
                        numerator = EXCLUDED.numerator,
                        denominator = EXCLUDED.denominator,
                        metric_value = EXCLUDED.metric_value,
                        status = EXCLUDED.status,
                        calculation_status = EXCLUDED.calculation_status,
                        details_json = EXCLUDED.details_json;
                    """,
                    {
                        "step": step_key,
                        "step_unique_id": sid,
                        "metric": metric_name,
                        "calculation_method": (
                            str(row.get("calculation_method") or "").strip()
                            or (principle.calculation_method if principle else None)
                        ),
                        "numerator": numerator,
                        "denominator": denominator,
                        "metric_value": metric_value,
                        "status": status,
                        "calculation_status": calculation_status,
                        "details_json": json.dumps(details),
                    },
                )
        conn.commit()
