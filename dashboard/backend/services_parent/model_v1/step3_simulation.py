from __future__ import annotations

import json
import os
import random
import re
import shutil
import subprocess
import time
import uuid
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from services_parent.common.audit_event_types import REPLAY_COMPLETED, REPLAY_STARTED
from services_parent.common.phase4_db import (
    connect,
    count_step3_pcap_catalog,
    get_latest_step3_preparation_run,
    get_step3_replay_metrics,
    register_step3_pcap_catalog,
    upsert_step3_preparation_run,
    upsert_step3_replay_metrics,
    upsert_step3_model_preparation,
    write_audit_event,
)
from services_parent.common.step_metrics_jobs import generate_step3_metrics
from services_parent.model_v1.artifacts import write_json_artifact
from services_parent.model_v1.db import insert_shap_log
from services_parent.model_v1.step3_child_runtime import (
    new_event_id,
    push_udp_to_child,
    register_remote_runtime,
    runtime_set_rules,
    simulation_process_state,
    simulation_set_running,
    start_child_runtime,
    stop_child_runtime,
    runtime_stats,
    unregister_remote_runtime,
)
from services_parent.model_v1.step3_config import (
    CLIENT_PORT_BASE,
    MANAGEMENT_PORT_BASE,
    PARENT_MANAGEMENT_NETWORK_ID,
    SIMULATION_NETWORK_ID,
    STEP3_ADAPTER_WORKERS,
    STEP3_ALERT_DEFER_TO_BUFFER,
    STEP3_CHILD_ROUTE_WORKERS,
    STEP3_CHILD_STACK_THREADS,
    STEP3_FACTORY_STACK_THREADS,
    STEP3_PARENT_REVIEW_WORKERS,
    STEP3_PARENT_STACK_THREADS,
    STEP3_PARENT_WORKER_MODE,
    STEP3_REPLAY_MAX_WORKERS,
    STEP3_SHAP_WORKERS,
    STEP3_WORKER_MODE,
    STEP3_EXECUTION_MODE,
    STEP3_STRICT_ACCEPTANCE_DEFAULT,
    STEP3_MTLS_ENABLED,
    STEP3_MTLS_REQUIRE_CLIENT_CERT,
    STEP3_MTLS_CERT_DIR,
    STEP3_MTLS_CA_PATH,
)
from services_parent.model_v1.step3_pcap_adapter import (
    REPLAY_PHASES,
    chunk_to_udp_payload,
    resolve_rep01_packet_inventory,
    resolve_rep01_pcap_paths,
    segment_pcap_into_chunks,
)

DEFAULT_CHILD_TEMPLATES: list[dict[str, Any]] = [
    {
        "template_id": "enterprise",
        "child_type": "enterprise",
        "assigned_scope": "enterprise",
        "description": "Enterprise Child Template",
        "defaults": {"cross_scope_detection": True},
    },
    {
        "template_id": "dns",
        "child_type": "dns",
        "assigned_scope": "dns",
        "description": "DNS Child Template",
        "defaults": {"cross_scope_detection": True},
    },
    {
        "template_id": "iot",
        "child_type": "iot",
        "assigned_scope": "iot",
        "description": "IoT Child Template",
        "defaults": {"cross_scope_detection": True},
    },
    {
        "template_id": "iiot",
        "child_type": "iiot",
        "assigned_scope": "iiot",
        "description": "IIoT Child Template",
        "defaults": {"cross_scope_detection": True, "high_priority_enterprise_recon": True},
    },
]

DEFAULT_CHILD_STACKS: list[dict[str, str]] = [
    {"child_id": "child-enterprise-01", "child_type": "enterprise", "assigned_scope": "enterprise"},
    {"child_id": "child-enterprise-02", "child_type": "enterprise", "assigned_scope": "enterprise"},
    {"child_id": "child-dns-01", "child_type": "dns", "assigned_scope": "dns"},
    {"child_id": "child-dns-02", "child_type": "dns", "assigned_scope": "dns"},
    {"child_id": "child-iot-01", "child_type": "iot", "assigned_scope": "iot"},
    {"child_id": "child-iot-02", "child_type": "iot", "assigned_scope": "iot"},
    {"child_id": "child-iot-03", "child_type": "iot", "assigned_scope": "iot"},
    {"child_id": "child-iiot-01", "child_type": "iiot", "assigned_scope": "iiot"},
    {"child_id": "child-iiot-02", "child_type": "iiot", "assigned_scope": "iiot"},
    {"child_id": "child-iiot-03", "child_type": "iiot", "assigned_scope": "iiot"},
]

_RUNTIME_SHAP_CACHE: dict[str, dict[str, Any]] = {}
_STEP3_DOCKER_REPLAY_STATE: dict[str, Any] = {
    "running": False,
    "factory_container": None,
    "replay_run_id": None,
    "started_at": None,
    "last_error": None,
    "last_result": None,
}
_IST_TZ = ZoneInfo("Asia/Kolkata")


def _env_float(name: str, default: float) -> float:
    try:
        raw = str(os.getenv(name, str(default))).strip()
        val = float(raw)
        if val <= 0:
            return float(default)
        return val
    except Exception:
        return float(default)


STEP3_DOCKER_CMD_TIMEOUT_S = _env_float("STEP3_DOCKER_CMD_TIMEOUT_S", 60.0)
STEP3_DOCKER_START_TIMEOUT_S = _env_float("STEP3_DOCKER_START_TIMEOUT_S", 90.0)
STEP3_DOCKER_PROBE_TIMEOUT_S = _env_float("STEP3_DOCKER_PROBE_TIMEOUT_S", 30.0)
STEP3_PREPARE_LOCK_TIMEOUT_MS = int(max(1000, _env_float("STEP3_PREPARE_LOCK_TIMEOUT_MS", 7000.0)))


def _execution_mode(payload: dict[str, Any] | None = None) -> str:
    raw = str((payload or {}).get("execution_mode") or STEP3_EXECUTION_MODE).strip().lower()
    return raw if raw in {"production", "simulation"} else "simulation"


def _is_simulation_mode(payload: dict[str, Any] | None = None) -> bool:
    return _execution_mode(payload) == "simulation"


def _metric_provenance(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    mode = _execution_mode(payload)
    return {
        "execution_mode": mode,
        "is_simulated": mode == "simulation",
        "metric_source": "simulated_runtime" if mode == "simulation" else "observed_runtime",
        "observation_confidence": "high" if mode == "simulation" else "measured_or_unknown",
    }


def _shap_evidence_status(payload: dict[str, Any] | None = None) -> str:
    p = payload if isinstance(payload, dict) else {}
    status = str(p.get("status") or "").strip().lower()
    if bool(p.get("ok")) and status in {"runtime_shap_completed", "runtime_model_scored"}:
        return "measured"
    if status in {"runtime_shap_not_available", "runtime_bundle_unavailable"}:
        return "not_available"
    if status in {"runtime_shap_dependency_missing", "feature_integrity_failed"}:
        return "failed"
    if not status:
        return "not_available"
    return "failed"


def _to_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "f", "no", "n", "off", ""}:
        return False
    return bool(default)


def _uuid_or_none(value: Any) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return str(uuid.UUID(raw))
    except Exception:
        return None


def _preparation_replay_id(payload: dict[str, Any] | None = None) -> str | None:
    p = payload or {}
    return _uuid_or_none(
        p.get("preparation_replay_id")
        or p.get("replay_id")
        or p.get("prepare_replay_id")
    )


def _audit_replay_id(*, preparation_replay_id: str | None, replay_run_id: str | None) -> str | None:
    return _uuid_or_none(preparation_replay_id) or _uuid_or_none(replay_run_id)


def _dissertation_metrics_summary(
    *,
    replay_run_id: str,
    model_id: str | None,
    model_version: str | None,
    preparation_replay_id: str | None,
    simulation_session_id: str | None,
    execution_mode: str,
    child_sent: dict[str, Any] | None = None,
    child_dropped: dict[str, Any] | None = None,
    rep01_inventory: dict[str, Any] | None = None,
    rep01_file_stats: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    sent_map = child_sent or {}
    drop_map = child_dropped or {}
    total_sent = sum(int(v or 0) for v in sent_map.values()) if sent_map else 0
    total_dropped = sum(int(v or 0) for v in drop_map.values()) if drop_map else 0
    guardrail_error: str | None = None
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    COALESCE(SUM(packets_sent), 0)::bigint,
                    COALESCE(SUM(packets_received), 0)::bigint,
                    COALESCE(SUM(alerts_generated), 0)::bigint,
                    COALESCE(SUM(escalations_generated), 0)::bigint,
                    COALESCE(AVG(latency_ms), 0)::numeric
                FROM phase4.replay_streams
                WHERE replay_run_id = %(rid)s::uuid;
                """,
                {"rid": replay_run_id},
            )
            row = cur.fetchone() or (0, 0, 0, 0, 0)
            cur.execute(
                """
                SELECT COUNT(*)::bigint, COUNT(*) FILTER (WHERE status = 'completed')::bigint
                FROM phase4.child_stacks;
                """
            )
            c_row = cur.fetchone() or (0, 0)
            cur.execute(
                """
                SELECT child_id, COALESCE(alert_count, 0), COALESCE(escalation_count, 0)
                FROM phase4.step3_stack_alerts
                WHERE replay_run_id = %(rid)s::uuid;
                """,
                {"rid": replay_run_id},
            )
            stack_alert_rows = cur.fetchall() or []
            cur.execute(
                """
                SELECT metadata
                FROM phase4.replay_streams
                WHERE replay_run_id = %(rid)s::uuid;
                """,
                {"rid": replay_run_id},
            )
            replay_stream_meta_rows = cur.fetchall() or []
    packets_sent_db = int(row[0] or 0)
    packets_received_db = int(row[1] or 0)
    alerts_total = int(row[2] or 0)
    escalations_total = int(row[3] or 0)
    mean_latency_ms = float(row[4] or 0.0)
    child_nodes_total = int(c_row[0] or 0)
    child_nodes_ready = int(c_row[1] or 0)
    packets_sent = packets_sent_db if packets_sent_db > 0 else total_sent
    packets_dropped = total_dropped
    delivery_ratio = float((packets_received_db / packets_sent) if packets_sent > 0 else 0.0)
    rep01 = rep01_inventory or {}
    rep01_stats = rep01_file_stats or []
    alerts_by_child: dict[str, int] = {}
    escalations_by_child: dict[str, int] = {}
    for row_child in stack_alert_rows:
        child_id = str(row_child[0] or "").strip()
        if not child_id:
            continue
        alerts_by_child[child_id] = int(alerts_by_child.get(child_id) or 0) + int(row_child[1] or 0)
        escalations_by_child[child_id] = int(escalations_by_child.get(child_id) or 0) + int(row_child[2] or 0)
    rule_hits_by_family: dict[str, int] = {}
    for row_meta in replay_stream_meta_rows:
        meta = row_meta[0] if row_meta else {}
        if not isinstance(meta, dict):
            continue
        fam = meta.get("rule_hits_by_family")
        if not isinstance(fam, dict):
            continue
        for key, value in fam.items():
            k = str(key or "").strip() or "unknown"
            rule_hits_by_family[k] = int(rule_hits_by_family.get(k) or 0) + int(value or 0)
    per_file_alert_density: list[dict[str, Any]] = []
    rep01_transmission_by_file: list[dict[str, Any]] = []
    for row_fs in rep01_stats:
        if not isinstance(row_fs, dict):
            continue
        row = dict(row_fs)
        total_file = int(row.get("packets_total_in_file") or 0)
        alerts_est = int(row.get("rule_matches") or 0)
        density = float(alerts_est / total_file) if total_file > 0 else 0.0
        per_file_alert_density.append(
            {
                "file_path": str(row.get("file_path") or ""),
                "packets_total_in_file": total_file,
                "alerts_estimated": alerts_est,
                "alert_density": round(density, 9),
            }
        )
        rep01_transmission_by_file.append(row)
    rule_hits_by_scope: dict[str, int] = {}
    for key, value in rule_hits_by_family.items():
        k = str(key or "").strip().lower()
        if "dns" in k:
            scope = "dns"
        elif "iiot" in k:
            scope = "iiot"
        elif "iot" in k:
            scope = "iot"
        elif "enterprise" in k:
            scope = "enterprise"
        elif "cross" in k:
            scope = "cross_scope"
        else:
            scope = "global"
        rule_hits_by_scope[scope] = int(rule_hits_by_scope.get(scope) or 0) + int(value or 0)
    child_breakdown = _step3_replay_child_breakdown(replay_run_id)
    packets_by_child: dict[str, dict[str, int]] = {}
    for row_child in child_breakdown:
        cid = str(row_child.get("child_id") or "").strip()
        if not cid:
            continue
        packets_by_child[cid] = {
            "packets_sent": int(row_child.get("packets_sent") or 0),
            "packets_received": int(row_child.get("packets_received") or 0),
            "packets_dropped": int(row_child.get("packets_dropped") or 0),
        }
    metrics = {
        "replay_run_id": replay_run_id,
        "preparation_replay_id": preparation_replay_id,
        "simulation_session_id": simulation_session_id,
        "model_id": model_id,
        "model_version": model_version,
        "execution_mode": execution_mode,
        "is_simulated": execution_mode == "simulation",
        "child_nodes_total": child_nodes_total,
        "child_nodes_ready": child_nodes_ready,
        "packets_sent_total": packets_sent,
        "packets_received_total": packets_received_db,
        "packets_dropped_total": packets_dropped,
        "delivery_ratio": delivery_ratio,
        "alerts_total": alerts_total,
        "escalations_total": escalations_total,
        "mean_latency_ms": mean_latency_ms,
        "rep01_files_count": int(rep01.get("files_count") or 0),
        "rep01_packets_total": int(rep01.get("packets_total") or 0),
        "rep01_packets_by_file": list(rep01.get("files") or []),
        "rep01_transmission_by_file": rep01_transmission_by_file,
        "rule_hits_by_scope": rule_hits_by_scope,
        "rule_hits_by_family": rule_hits_by_family,
        "packets_by_child": packets_by_child,
        "alerts_by_child": alerts_by_child,
        "escalations_by_child": escalations_by_child,
        "escalations_by_rule_family": dict(rule_hits_by_family),
        "per_file_alert_density": per_file_alert_density,
        "generated_at": _now(),
    }
    upsert_step3_replay_metrics(
        replay_run_id=replay_run_id,
        model_id=model_id,
        model_version=model_version,
        preparation_replay_id=preparation_replay_id,
        simulation_session_id=simulation_session_id,
        metrics=metrics,
    )
    return metrics


def _normalize_rule_family(value: Any) -> str:
    family = str(value or "").strip().lower()
    return family if family else "unknown"


def _step3_replay_child_breakdown(replay_run_id: str | None) -> list[dict[str, Any]]:
    rid = str(replay_run_id or "").strip()
    if not rid:
        return []
    traffic_by_child: dict[str, dict[str, int]] = {}
    alerts_by_child: dict[str, dict[str, int]] = {}
    stream_rule_hits_by_child: dict[str, dict[str, int]] = {}
    match_rule_hits_by_child: dict[str, dict[str, int]] = {}
    rule_state_by_child: dict[str, dict[str, Any]] = {}
    replay_model_version = ""
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT model_version
                    FROM phase4.replay_runs
                    WHERE replay_run_id = %(rid)s::uuid
                    LIMIT 1;
                    """,
                    {"rid": rid},
                )
                row = cur.fetchone()
                replay_model_version = str((row[0] if row else "") or "").strip()
                cur.execute(
                    """
                    SELECT child_id,
                           COALESCE(SUM(packets_sent), 0)::bigint,
                           COALESCE(SUM(packets_received), 0)::bigint,
                           COALESCE(SUM(packets_dropped), 0)::bigint
                    FROM phase4.step3_stack_traffic
                    WHERE replay_run_id = %(rid)s::uuid
                    GROUP BY child_id;
                    """,
                    {"rid": rid},
                )
                for child_id, sent, received, dropped in cur.fetchall():
                    cid = str(child_id or "").strip()
                    if not cid:
                        continue
                    traffic_by_child[cid] = {
                        "packets_sent": int(sent or 0),
                        "packets_received": int(received or 0),
                        "packets_dropped": int(dropped or 0),
                    }
                cur.execute(
                    """
                    SELECT child_id,
                           COALESCE(SUM(alert_count), 0)::bigint,
                           COALESCE(SUM(escalation_count), 0)::bigint
                    FROM phase4.step3_stack_alerts
                    WHERE replay_run_id = %(rid)s::uuid
                    GROUP BY child_id;
                    """,
                    {"rid": rid},
                )
                for child_id, alerts, escalations in cur.fetchall():
                    cid = str(child_id or "").strip()
                    if not cid:
                        continue
                    alerts_by_child[cid] = {
                        "alerts": int(alerts or 0),
                        "escalations": int(escalations or 0),
                    }
                cur.execute(
                    """
                    SELECT child_id, metadata
                    FROM phase4.replay_streams
                    WHERE replay_run_id = %(rid)s::uuid;
                    """,
                    {"rid": rid},
                )
                for child_id, metadata in cur.fetchall():
                    cid = str(child_id or "").strip()
                    if not cid or not isinstance(metadata, dict):
                        continue
                    fam = metadata.get("rule_hits_by_family")
                    if not isinstance(fam, dict):
                        continue
                    merged = stream_rule_hits_by_child.setdefault(cid, {})
                    for key, value in fam.items():
                        k = _normalize_rule_family(key)
                        merged[k] = int(merged.get(k) or 0) + int(value or 0)
                cur.execute(
                    """
                    SELECT child_id,
                           COALESCE(payload->>'rule_scope', 'unknown') AS rule_family,
                           COUNT(*)::bigint
                    FROM phase4.step3_child_rule_matches
                    WHERE replay_id = %(rid)s::uuid
                    GROUP BY child_id, COALESCE(payload->>'rule_scope', 'unknown');
                    """,
                    {"rid": rid},
                )
                for child_id, family, count in cur.fetchall():
                    cid = str(child_id or "").strip()
                    if not cid:
                        continue
                    merged = match_rule_hits_by_child.setdefault(cid, {})
                    k = _normalize_rule_family(family)
                    merged[k] = int(merged.get(k) or 0) + int(count or 0)
                cur.execute(
                    """
                    SELECT child_id, rulepack_version, rule_count
                    FROM (
                        SELECT child_id, rulepack_version, rule_count,
                               ROW_NUMBER() OVER (PARTITION BY child_id ORDER BY created_at_utc DESC) AS rn
                        FROM phase4.step3_stack_rules
                    ) x
                    WHERE rn = 1;
                    """
                )
                for child_id, rulepack_version, rule_count in cur.fetchall():
                    cid = str(child_id or "").strip()
                    if not cid:
                        continue
                    rule_state_by_child[cid] = {
                        "rulepack_version": str(rulepack_version or "").strip() or None,
                        "active_rule_count": int(rule_count or 0),
                    }
    except Exception:
        return []

    all_child_ids = set(traffic_by_child) | set(alerts_by_child) | set(stream_rule_hits_by_child) | set(match_rule_hits_by_child) | set(rule_state_by_child)
    out: list[dict[str, Any]] = []
    for cid in sorted(all_child_ids):
        rt = runtime_stats(cid)
        rulepack_version = None
        active_rule_count = 0
        if rt is not None:
            rulepack_version = str(getattr(rt, "rulepack_version", "") or "").strip() or None
            active_rule_count = int(getattr(rt, "active_rule_count", 0) or 0)
        fallback_state = rule_state_by_child.get(cid) or {}
        if not rulepack_version:
            rulepack_version = fallback_state.get("rulepack_version")
        if active_rule_count <= 0:
            active_rule_count = int(fallback_state.get("active_rule_count") or 0)
        packets = traffic_by_child.get(cid) or {"packets_sent": 0, "packets_received": 0, "packets_dropped": 0}
        alerts = alerts_by_child.get(cid) or {"alerts": 0, "escalations": 0}
        family_map: dict[str, int] = {}
        for src in (stream_rule_hits_by_child.get(cid) or {}, match_rule_hits_by_child.get(cid) or {}):
            for key, value in src.items():
                k = _normalize_rule_family(key)
                family_map[k] = int(family_map.get(k) or 0) + int(value or 0)
        out.append(
            {
                "child_id": cid,
                "model_version": replay_model_version or None,
                "rulepack_version": rulepack_version,
                "active_rule_count": int(active_rule_count),
                "packets_sent": int(packets.get("packets_sent") or 0),
                "packets_received": int(packets.get("packets_received") or 0),
                "packets_dropped": int(packets.get("packets_dropped") or 0),
                "alerts": int(alerts.get("alerts") or 0),
                "escalations": int(alerts.get("escalations") or 0),
                "rule_hits_by_family": family_map,
            }
        )
    return out


def _step3_event_sample_rows(
    *,
    replay_run_id: str | None,
    target_rows: int = 100,
) -> dict[str, Any]:
    rid = str(replay_run_id or "").strip()
    target = max(1, min(int(target_rows or 100), 500))
    if not rid:
        return {"rows": [], "target_rows": target, "actual_rows": 0, "warnings": ["replay_run_id_missing"]}
    sample_rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT m.child_id,
                           NULLIF(m.rule_id, '') AS rule_id,
                           COALESCE(NULLIF(m.payload->>'rule_scope', ''), 'unknown') AS rule_family,
                           COALESCE(
                               NULLIF(m.payload->'context'->>'flow_id', ''),
                               NULLIF(m.payload->'context'->>'packet_id', ''),
                               NULLIF(m.payload->'context'->>'checksum', ''),
                               m.match_id::text
                           ) AS packet_or_flow_id,
                           m.created_at_utc
                    FROM phase4.step3_child_rule_matches m
                    WHERE m.replay_id = %(rid)s::uuid
                    ORDER BY m.created_at_utc DESC
                    LIMIT %(lim)s;
                    """,
                    {"rid": rid, "lim": target},
                )
                for child_id, rule_id, family, packet_or_flow_id, created in cur.fetchall():
                    sample_rows.append(
                        {
                            "child_id": str(child_id or ""),
                            "rule_id": str(rule_id or "") or None,
                            "rule_family": _normalize_rule_family(family),
                            "packet_or_flow_id": str(packet_or_flow_id or ""),
                            "timestamp": created.isoformat() if created else None,
                        }
                    )
                if len(sample_rows) < target:
                    rem = target - len(sample_rows)
                    cur.execute(
                        """
                        SELECT a.child_id,
                               NULLIF(rm.elem->>'rule_id', '') AS rule_id,
                               COALESCE(
                                   NULLIF(rm.elem->>'rule_scope', ''),
                                   NULLIF(rm.elem->>'family', ''),
                                   'unknown'
                               ) AS rule_family,
                               COALESCE(
                                   NULLIF(rm.elem->'context'->>'flow_id', ''),
                                   NULLIF(rm.elem->'context'->>'packet_id', ''),
                                   NULLIF(rm.elem->'context'->>'checksum', ''),
                                   a.alert_id::text
                               ) AS packet_or_flow_id,
                               a.created_at_utc
                        FROM phase4.step3_alerts a
                        LEFT JOIN LATERAL (
                            SELECT elem
                            FROM jsonb_array_elements(COALESCE(a.payload->'rule_matches', '[]'::jsonb)) elem
                            LIMIT 1
                        ) rm ON TRUE
                        WHERE a.replay_run_id = %(rid)s::uuid
                        ORDER BY a.created_at_utc DESC
                        LIMIT %(lim)s;
                        """,
                        {"rid": rid, "lim": rem},
                    )
                    for child_id, rule_id, family, packet_or_flow_id, created in cur.fetchall():
                        sample_rows.append(
                            {
                                "child_id": str(child_id or ""),
                                "rule_id": str(rule_id or "") or None,
                                "rule_family": _normalize_rule_family(family),
                                "packet_or_flow_id": str(packet_or_flow_id or ""),
                                "timestamp": created.isoformat() if created else None,
                            }
                        )
                if len(sample_rows) < target:
                    rem = target - len(sample_rows)
                    cur.execute(
                        """
                        SELECT f.child_id,
                               NULL::text AS rule_id,
                               CASE
                                   WHEN f.event_kind = 'escalation' THEN 'escalation'
                                   WHEN f.event_kind = 'child_alert' THEN 'alert'
                                   ELSE 'unknown'
                               END AS rule_family,
                               f.flow_event_id::text AS packet_or_flow_id,
                               f.created_at_utc
                        FROM phase4.step3_replay_flow_events f
                        WHERE f.replay_run_id = %(rid)s::uuid
                          AND f.event_kind IN ('child_alert', 'escalation')
                        ORDER BY f.created_at_utc DESC
                        LIMIT %(lim)s;
                        """,
                        {"rid": rid, "lim": rem},
                    )
                    for child_id, rule_id, family, packet_or_flow_id, created in cur.fetchall():
                        sample_rows.append(
                            {
                                "child_id": str(child_id or ""),
                                "rule_id": str(rule_id or "") or None,
                                "rule_family": _normalize_rule_family(family),
                                "packet_or_flow_id": str(packet_or_flow_id or ""),
                                "timestamp": created.isoformat() if created else None,
                            }
                        )
    except Exception as exc:
        warnings.append(f"event_sample_query_failed:{exc}")
        sample_rows = []
    unique_rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in sample_rows:
        key = (
            str(row.get("child_id") or ""),
            str(row.get("rule_id") or ""),
            str(row.get("packet_or_flow_id") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        unique_rows.append(row)
    if len(unique_rows) < target:
        warnings.append(f"event_sample_rows_below_target:actual={len(unique_rows)} target={target}")
    return {
        "rows": unique_rows[:target],
        "target_rows": target,
        "actual_rows": len(unique_rows[:target]),
        "warnings": warnings,
    }


def _step3_parent_review_artifact(*, replay_run_id: str | None) -> dict[str, Any]:
    rid = str(replay_run_id or "").strip()
    if not rid:
        return {"rows_total": 0, "status_counts": {}, "recent_rows": [], "warnings": ["replay_run_id_missing"]}
    status_counts: dict[str, int] = {}
    recent_rows: list[dict[str, Any]] = []
    total = 0
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM phase4.parent_actions
                    WHERE replay_run_id = %(rid)s::uuid;
                    """,
                    {"rid": rid},
                )
                row = cur.fetchone()
                total = int((row[0] if row else 0) or 0)
                cur.execute(
                    """
                    SELECT COALESCE(status, 'unknown') AS status, COUNT(*)::bigint
                    FROM phase4.parent_actions
                    WHERE replay_run_id = %(rid)s::uuid
                    GROUP BY COALESCE(status, 'unknown');
                    """,
                    {"rid": rid},
                )
                for status, count in cur.fetchall():
                    status_counts[str(status or "unknown")] = int(count or 0)
                cur.execute(
                    """
                    SELECT parent_action_id::text, child_id, status, action_type, recommendation, created_at_utc
                    FROM phase4.parent_actions
                    WHERE replay_run_id = %(rid)s::uuid
                    ORDER BY created_at_utc DESC
                    LIMIT 25;
                    """,
                    {"rid": rid},
                )
                for aid, child_id, status, action_type, recommendation, created in cur.fetchall():
                    recent_rows.append(
                        {
                            "parent_action_id": aid,
                            "child_id": str(child_id or ""),
                            "status": str(status or ""),
                            "action_type": str(action_type or ""),
                            "recommendation": str(recommendation or ""),
                            "timestamp": created.isoformat() if created else None,
                        }
                    )
    except Exception as exc:
        return {"rows_total": 0, "status_counts": {}, "recent_rows": [], "warnings": [f"parent_review_query_failed:{exc}"]}
    return {"rows_total": total, "status_counts": status_counts, "recent_rows": recent_rows, "warnings": []}


def _step3_runtime_shap_artifact(*, replay_run_id: str | None) -> dict[str, Any]:
    rid = str(replay_run_id or "").strip()
    if not rid:
        return {"rows_total": 0, "status_counts": {}, "recent_rows": [], "warnings": ["replay_run_id_missing"]}
    total = 0
    status_counts: dict[str, int] = {}
    recent_rows: list[dict[str, Any]] = []
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM phase4.shap_logs
                    WHERE replay_id = %(rid)s
                      AND shap_stage = 'runtime';
                    """,
                    {"rid": rid},
                )
                row = cur.fetchone()
                total = int((row[0] if row else 0) or 0)
                cur.execute(
                    """
                    SELECT COALESCE(top_features_json->>'status', 'unknown') AS status, COUNT(*)::bigint
                    FROM phase4.shap_logs
                    WHERE replay_id = %(rid)s
                      AND shap_stage = 'runtime'
                    GROUP BY COALESCE(top_features_json->>'status', 'unknown');
                    """,
                    {"rid": rid},
                )
                for status, count in cur.fetchall():
                    status_counts[str(status or "unknown")] = int(count or 0)
                cur.execute(
                    """
                    SELECT id, event_details_json, top_features_json, created_at
                    FROM phase4.shap_logs
                    WHERE replay_id = %(rid)s
                      AND shap_stage = 'runtime'
                    ORDER BY created_at DESC
                    LIMIT 25;
                    """,
                    {"rid": rid},
                )
                for sid, details, topf, created in cur.fetchall():
                    d = details if isinstance(details, dict) else {}
                    t = topf if isinstance(topf, dict) else {}
                    recent_rows.append(
                        {
                            "shap_log_id": int(sid),
                            "child_id": str(d.get("child_id") or ""),
                            "status": str(d.get("status") or t.get("status") or ""),
                            "evidence_status": str(d.get("evidence_status") or t.get("evidence_status") or ""),
                            "alert_id": str(d.get("alert_id") or "") or None,
                            "rule_id": str(d.get("rule_id") or "") or None,
                            "rule_family": str(d.get("rule_family") or "") or None,
                            "packet_or_flow_id": str(d.get("packet_or_flow_id") or "") or None,
                            "prediction": d.get("prediction") if isinstance(d.get("prediction"), dict) else {},
                            "timestamp": created.isoformat() if created else None,
                        }
                    )
    except Exception as exc:
        return {"rows_total": 0, "status_counts": {}, "recent_rows": [], "warnings": [f"runtime_shap_query_failed:{exc}"]}
    return {"rows_total": total, "status_counts": status_counts, "recent_rows": recent_rows, "warnings": []}


def _step3_correlation_summary(event_rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(event_rows or [])
    unique_event_keys: set[tuple[str, str, str]] = set()
    family_by_child: dict[str, int] = {}
    for row in event_rows or []:
        child_id = str(row.get("child_id") or "")
        rule_id = str(row.get("rule_id") or "")
        packet_or_flow_id = str(row.get("packet_or_flow_id") or "")
        unique_event_keys.add((child_id, rule_id, packet_or_flow_id))
        fam = _normalize_rule_family(row.get("rule_family"))
        family_key = f"{child_id}:{fam}"
        family_by_child[family_key] = int(family_by_child.get(family_key) or 0) + 1
    deduplicated = len(unique_event_keys)
    duplicate_rows = max(0, total - deduplicated)
    top = sorted(
        (
            {"correlation_key": key, "count": value}
            for key, value in family_by_child.items()
        ),
        key=lambda item: (-int(item["count"]), item["correlation_key"]),
    )[:25]
    return {
        "total_event_rows": total,
        "deduplicated_event_rows": deduplicated,
        "duplicate_rows": duplicate_rows,
        "top_correlations": top,
    }


def _step3_detailed_metrics_artifact(
    *,
    replay_run_id: str,
    model_id: str | None,
    model_version: str | None,
    preparation_replay_id: str | None,
    simulation_session_id: str | None,
    execution_mode: str,
    dissertation_metrics: dict[str, Any] | None,
    data_root: Path,
) -> dict[str, Any]:
    child_breakdown = _step3_replay_child_breakdown(replay_run_id)
    event_sample = _step3_event_sample_rows(replay_run_id=replay_run_id, target_rows=100)
    parent_review = _step3_parent_review_artifact(replay_run_id=replay_run_id)
    runtime_shap = _step3_runtime_shap_artifact(replay_run_id=replay_run_id)
    correlation = _step3_correlation_summary(event_sample.get("rows") if isinstance(event_sample, dict) else [])
    warnings: list[str] = []
    warnings.extend(list(event_sample.get("warnings") or []))
    warnings.extend(list(parent_review.get("warnings") or []))
    warnings.extend(list(runtime_shap.get("warnings") or []))

    measured_rule_rows = len([r for r in (event_sample.get("rows") or []) if str(r.get("rule_id") or "").strip()])  # type: ignore[union-attr]
    measured_packets = any(int(row.get("packets_received") or 0) > 0 for row in child_breakdown)
    if measured_packets and measured_rule_rows > 0:
        evidence_quality = "measured"
        quality_reasons = ["per_child_packet_counts_present", "rule_level_event_rows_present"]
    elif measured_packets or len(event_sample.get("rows") or []) > 0:  # type: ignore[union-attr]
        evidence_quality = "partial_measured"
        quality_reasons = ["some_measured_signals_present", "rule_level_lineage_incomplete"]
    else:
        evidence_quality = "not_measured"
        quality_reasons = ["no_packet_or_rule_level_events_observed"]
    if evidence_quality != "measured":
        warnings.append("rule_level_lineage_incomplete_for_some_paths")

    detailed_payload = {
        "replay_metadata": {
            "replay_run_id": replay_run_id,
            "preparation_replay_id": preparation_replay_id,
            "simulation_session_id": simulation_session_id,
            "model_id": model_id,
            "model_version": model_version,
            "execution_mode": execution_mode,
            "generated_at": _now(),
        },
        "summary_metrics": dissertation_metrics or {},
        "alert_evidence_totals": {
            "event_sample_target_rows": int(event_sample.get("target_rows") or 100),  # type: ignore[union-attr]
            "event_sample_actual_rows": int(event_sample.get("actual_rows") or 0),  # type: ignore[union-attr]
            "parent_review_rows_total": int(parent_review.get("rows_total") or 0),
            "runtime_shap_rows_total": int(runtime_shap.get("rows_total") or 0),
        },
        "per_child_packet_counts": child_breakdown,
        "event_sample": {
            "target_rows": int(event_sample.get("target_rows") or 100),  # type: ignore[union-attr]
            "actual_rows": int(event_sample.get("actual_rows") or 0),  # type: ignore[union-attr]
            "rows": list(event_sample.get("rows") or []),  # type: ignore[union-attr]
        },
        "parent_review_artifact": parent_review,
        "runtime_shap_artifact": runtime_shap,
        "dedup_correlation_summary": correlation,
        "evidence_quality": evidence_quality,
        "evidence_quality_detail": {
            "status": evidence_quality,
            "reasons": quality_reasons,
            "available_statuses": ["measured", "partial_measured", "not_measured"],
        },
        "warnings": warnings,
    }

    replay_dir = _storage_root(data_root) / "replay_runs"
    replay_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = replay_dir / f"step3_detailed_metrics__{replay_run_id}.json"
    checksum = write_json_artifact(artifact_path, detailed_payload)
    return {
        "ok": True,
        "artifact_path": str(artifact_path),
        "checksum_sha256": checksum,
        "evidence_quality": evidence_quality,
        "warnings": warnings,
        "rows": int(event_sample.get("actual_rows") or 0),  # type: ignore[union-attr]
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _coerce_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    raw = str(value).strip()
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _to_utc_iso(value: Any) -> str | None:
    dt = _coerce_dt(value)
    return dt.astimezone(timezone.utc).isoformat() if dt else None


def _to_ist_iso(value: Any) -> str | None:
    dt = _coerce_dt(value)
    return dt.astimezone(_IST_TZ).isoformat() if dt else None


def _step3_audit_log_path(payload: dict[str, Any] | None = None) -> str | None:
    if not isinstance(payload, dict):
        return None
    raw = str(payload.get("step3_audit_log_path") or "").strip()
    return raw or None


def _step3_audit_log_append(log_path: str | None, *, event: str, payload: dict[str, Any] | None = None) -> None:
    target = str(log_path or "").strip()
    details = payload if isinstance(payload, dict) else {}
    simulation_id = str(
        details.get("simulation_id")
        or details.get("sim_id")
        or details.get("simulation_session_id")
        or ""
    ).strip()
    replay_run_id = str(details.get("replay_run_id") or details.get("preparation_replay_id") or details.get("replay_id") or "").strip()
    step_unique_id = simulation_id or replay_run_id or None
    try:
        write_audit_event(
            event_type=f"step3_{str(event or 'unknown')}",
            actor="step3_simulation",
            artifact_refs=[],
            context={
                "step": "step3",
                "step_unique_id": step_unique_id,
                "legacy_log_path": target,
                "payload": details,
                "ts_utc": _now(),
            },
            dataset_id=str(details.get("dataset_id") or "REP-01").strip() or "REP-01",
            model_version=str(details.get("model_version") or "").strip() or None,
            replay_id=str(details.get("replay_id") or details.get("preparation_replay_id") or "").strip() or None,
            step="step3",
            step_unique_id=step_unique_id,
        )
    except Exception:
        return


def _child_index(child_id: str) -> int:
    for i, row in enumerate(DEFAULT_CHILD_STACKS):
        if row["child_id"] == child_id:
            return i
    return 0


def _client_listener_port(child_id: str) -> int:
    return CLIENT_PORT_BASE + _child_index(child_id)


def _management_port(child_id: str) -> int:
    return MANAGEMENT_PORT_BASE + _child_index(child_id)


def _client_network_id(child_id: str) -> str:
    return f"{child_id}-client-net"


def _management_network_id(child_id: str) -> str:
    return f"{child_id}-mgmt-net"


def _ports_for_child_id(child_id: str) -> tuple[int, int]:
    if any(x["child_id"] == child_id for x in DEFAULT_CHILD_STACKS):
        return _client_listener_port(child_id), _management_port(child_id)
    h = abs(hash(child_id)) % 800
    return 17_500 + h, 18_500 + h


def _network_name(child_id: str) -> str:
    """Legacy single-network id (client replay plane). Prefer client_network_id."""
    return _client_network_id(child_id)


def _listener_endpoint(child_id: str) -> str:
    return f"udp://127.0.0.1:{_client_listener_port(child_id)}/replay"


def _packet_endpoint(child_id: str) -> str:
    return f"http://127.0.0.1:{_management_port(child_id)}/management"


def _step3_docker_enabled() -> bool:
    return str(os.getenv("STEP3_DOCKER_ORCHESTRATION", "1")).strip().lower() in {"1", "true", "yes", "on"}


def _step3_docker_project_prefix() -> str:
    return str(os.getenv("STEP3_DOCKER_PROJECT_PREFIX", "ids-project")).strip() or "ids-project"


def _step3_docker_image() -> str:
    return str(os.getenv("STEP3_DOCKER_IMAGE", "ids-project-phase4-python:local")).strip() or "ids-project-phase4-python:local"


def _step3_host_data_root() -> str:
    return str(os.getenv("STEP3_DOCKER_DATA_ROOT_HOST", "/data")).strip() or "/data"


def _step3_host_raw_downloads_root() -> str:
    return str(os.getenv("STEP3_DOCKER_RAW_DOWNLOADS_HOST", "/srv/scratch/ids_final_amity/raw_downloads")).strip() or "/srv/scratch/ids_final_amity/raw_downloads"


def _child_stack_slug(child_id: str) -> str:
    slug = re.sub(r"[^a-z0-9-]+", "-", str(child_id or "").strip().lower())
    slug = re.sub(r"-{2,}", "-", slug).strip("-")
    return slug or "child"


def _child_container_name(child_id: str) -> str:
    return f"ids-step3-child-{_child_stack_slug(child_id)}"


def _factory_container_name(replay_run_id: str) -> str:
    return f"ids-step3-factory-{str(replay_run_id).replace('_', '-').replace('.', '-')[:40]}"


def _postgres_container_name() -> str:
    return str(
        os.getenv(
            "STEP3_DOCKER_POSTGRES_CONTAINER",
            f"{_step3_docker_project_prefix()}-phase4-postgres-1",
        )
    ).strip()


def _parent_container_name() -> str:
    return str(
        os.getenv(
            "STEP3_DOCKER_PARENT_CONTAINER",
            f"{_step3_docker_project_prefix()}-parent-api-1",
        )
    ).strip()


def _dash_api_container_name() -> str:
    return str(
        os.getenv(
            "STEP3_DOCKER_DASH_API_CONTAINER",
            f"{_step3_docker_project_prefix()}-phase4-dash-api-1",
        )
    ).strip()


def _child_db_network_id(child_id: str) -> str:
    return f"{child_id}-db-net"


def _child_rules_file(child_id: str) -> str:
    return f"/data/outputs/model_v1/step3/child_rules/{child_id}.json"


def _run_docker(args: list[str], *, timeout_s: float | None = None) -> tuple[bool, str, str]:
    cmd = list(args or [])
    if cmd and cmd[0] == "docker":
        docker_bin = _resolve_docker_bin()
        if not docker_bin:
            return False, "", "docker_cli_not_found"
        cmd[0] = docker_bin
    eff_timeout_s = float(timeout_s) if timeout_s is not None else float(STEP3_DOCKER_CMD_TIMEOUT_S)
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=eff_timeout_s,
        )
        return proc.returncode == 0, (proc.stdout or "").strip(), (proc.stderr or "").strip()
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - docker boundary
        out = (exc.stdout or "").strip() if isinstance(exc.stdout, str) else ""
        err = (exc.stderr or "").strip() if isinstance(exc.stderr, str) else ""
        detail = f"timeout_after_{eff_timeout_s}s"
        if err:
            detail = f"{detail}:{err}"
        return False, out, detail
    except Exception as exc:  # pragma: no cover - docker boundary
        return False, "", str(exc)


def _docker_cli_available() -> bool:
    return _resolve_docker_bin() is not None


def _resolve_docker_bin() -> str | None:
    requested = str(os.getenv("STEP3_DOCKER_BIN", "docker")).strip() or "docker"
    for candidate in (requested, "docker", "docker.io"):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def _docker_network_connect(network_name: str, container_name: str) -> tuple[bool, str | None]:
    ok, _out, err = _run_docker(["docker", "network", "connect", network_name, container_name])
    if ok:
        return True, None
    # Ignore "already exists" class errors for idempotency.
    if "already exists" in (err or "").lower() or "already connected" in (err or "").lower():
        return True, None
    return False, err or "docker_network_connect_failed"


def _docker_container_running(container_name: str) -> tuple[bool, str]:
    ok, out, err = _run_docker(["docker", "inspect", "-f", "{{.State.Running}}", container_name])
    if not ok:
        return False, err or "inspect_failed"
    val = str(out or "").strip().lower()
    if val == "true":
        return True, "running"
    if not val:
        return False, "unknown_state"
    return False, val


def _docker_container_exists(container_name: str) -> bool:
    if not str(container_name or "").strip():
        return False
    ok, _out, _err = _run_docker(["docker", "inspect", container_name])
    return bool(ok)


def _docker_remove_container(container_name: str) -> tuple[bool, str | None]:
    name = str(container_name or "").strip()
    if not name:
        return True, None
    ok, _out, err = _run_docker(["docker", "rm", "-f", name])
    if ok:
        return True, None
    low = str(err or "").lower()
    if "no such container" in low:
        return True, None
    return False, err or "docker_rm_failed"


def _docker_containers_with_prefixes(prefixes: tuple[str, ...]) -> list[str]:
    ok, out, _err = _run_docker(["docker", "ps", "-a", "--format", "{{.Names}}"])
    if not ok:
        return []
    pref = tuple(str(p or "").strip() for p in prefixes if str(p or "").strip())
    names = [str(x or "").strip() for x in str(out or "").splitlines() if str(x or "").strip()]
    if not pref:
        return names
    return [name for name in names if any(name.startswith(p) for p in pref)]


def _docker_image_exists(image_name: str) -> bool:
    ok, _out, _err = _run_docker(["docker", "image", "inspect", image_name])
    return bool(ok)


def _docker_network_exists(name: str) -> bool:
    ok, _out, _err = _run_docker(["docker", "network", "inspect", name])
    return bool(ok)


def _storage_root(data_root: Path) -> Path:
    return data_root / "outputs" / "model_v1" / "step3"


def _ensure_step3_sim_file_summaries_table() -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS phase4.step3_sim_file_summaries (
                    summary_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                    replay_id uuid NOT NULL,
                    replay_run_id uuid,
                    run_id uuid,
                    model_id uuid,
                    model_version text,
                    file_path text NOT NULL,
                    file_name text,
                    status text NOT NULL DEFAULT 'prepared',
                    packets_total_in_file bigint NOT NULL DEFAULT 0,
                    packets_attack_in_file bigint NOT NULL DEFAULT 0,
                    packets_benign_in_file bigint NOT NULL DEFAULT 0,
                    packets_transmitted bigint NOT NULL DEFAULT 0,
                    packets_failed bigint NOT NULL DEFAULT 0,
                    packets_received bigint NOT NULL DEFAULT 0,
                    packets_lost bigint NOT NULL DEFAULT 0,
                    alerts_triggered bigint NOT NULL DEFAULT 0,
                    alert_ratio numeric NOT NULL DEFAULT 0,
                    file_run_started_at_utc timestamptz,
                    file_run_finished_at_utc timestamptz,
                    stats jsonb NOT NULL DEFAULT '{}'::jsonb,
                    created_at_utc timestamptz NOT NULL DEFAULT now(),
                    updated_at_utc timestamptz NOT NULL DEFAULT now(),
                    CONSTRAINT uq_step3_sim_file_summaries_replay_file UNIQUE (replay_id, file_path)
                );
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_step3_sim_file_summaries_replay
                    ON phase4.step3_sim_file_summaries(replay_id, updated_at_utc DESC);
                """
            )
        conn.commit()


def _upsert_step3_sim_file_summary(
    *,
    replay_id: str,
    replay_run_id: str | None,
    run_id: str | None,
    model_id: str | None,
    model_version: str | None,
    file_path: str,
    file_name: str | None,
    status: str,
    packets_total_in_file: int,
    packets_attack_in_file: int,
    packets_benign_in_file: int,
    packets_transmitted: int,
    packets_failed: int,
    packets_received: int,
    packets_lost: int,
    alerts_triggered: int,
    alert_ratio: float,
    file_run_started_at_utc: str | None,
    file_run_finished_at_utc: str | None,
    stats: dict[str, Any] | None = None,
) -> None:
    if not _uuid_or_none(replay_id) or not str(file_path or "").strip():
        return
    _ensure_step3_sim_file_summaries_table()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.step3_sim_file_summaries (
                    replay_id, replay_run_id, run_id, model_id, model_version,
                    file_path, file_name, status,
                    packets_total_in_file, packets_attack_in_file, packets_benign_in_file,
                    packets_transmitted, packets_failed, packets_received, packets_lost,
                    alerts_triggered, alert_ratio,
                    file_run_started_at_utc, file_run_finished_at_utc, stats, created_at_utc, updated_at_utc
                )
                VALUES (
                    %(replay_id)s::uuid,
                    CASE WHEN %(replay_run_id)s = '' THEN NULL ELSE %(replay_run_id)s::uuid END,
                    CASE WHEN %(run_id)s = '' THEN NULL ELSE %(run_id)s::uuid END,
                    CASE WHEN %(model_id)s = '' THEN NULL ELSE %(model_id)s::uuid END,
                    %(model_version)s,
                    %(file_path)s, %(file_name)s, %(status)s,
                    %(packets_total_in_file)s, %(packets_attack_in_file)s, %(packets_benign_in_file)s,
                    %(packets_transmitted)s, %(packets_failed)s, %(packets_received)s, %(packets_lost)s,
                    %(alerts_triggered)s, %(alert_ratio)s,
                    CASE WHEN %(file_run_started_at_utc)s = '' THEN NULL ELSE %(file_run_started_at_utc)s::timestamptz END,
                    CASE WHEN %(file_run_finished_at_utc)s = '' THEN NULL ELSE %(file_run_finished_at_utc)s::timestamptz END,
                    %(stats)s::jsonb, now(), now()
                )
                ON CONFLICT (replay_id, file_path)
                DO UPDATE SET
                    replay_run_id = COALESCE(EXCLUDED.replay_run_id, phase4.step3_sim_file_summaries.replay_run_id),
                    run_id = COALESCE(EXCLUDED.run_id, phase4.step3_sim_file_summaries.run_id),
                    model_id = COALESCE(EXCLUDED.model_id, phase4.step3_sim_file_summaries.model_id),
                    model_version = COALESCE(EXCLUDED.model_version, phase4.step3_sim_file_summaries.model_version),
                    file_name = COALESCE(EXCLUDED.file_name, phase4.step3_sim_file_summaries.file_name),
                    status = EXCLUDED.status,
                    packets_total_in_file = GREATEST(phase4.step3_sim_file_summaries.packets_total_in_file, EXCLUDED.packets_total_in_file),
                    packets_attack_in_file = GREATEST(phase4.step3_sim_file_summaries.packets_attack_in_file, EXCLUDED.packets_attack_in_file),
                    packets_benign_in_file = GREATEST(phase4.step3_sim_file_summaries.packets_benign_in_file, EXCLUDED.packets_benign_in_file),
                    packets_transmitted = GREATEST(phase4.step3_sim_file_summaries.packets_transmitted, EXCLUDED.packets_transmitted),
                    packets_failed = GREATEST(phase4.step3_sim_file_summaries.packets_failed, EXCLUDED.packets_failed),
                    packets_received = GREATEST(phase4.step3_sim_file_summaries.packets_received, EXCLUDED.packets_received),
                    packets_lost = GREATEST(phase4.step3_sim_file_summaries.packets_lost, EXCLUDED.packets_lost),
                    alerts_triggered = GREATEST(phase4.step3_sim_file_summaries.alerts_triggered, EXCLUDED.alerts_triggered),
                    alert_ratio = GREATEST(phase4.step3_sim_file_summaries.alert_ratio, EXCLUDED.alert_ratio),
                    file_run_started_at_utc = COALESCE(phase4.step3_sim_file_summaries.file_run_started_at_utc, EXCLUDED.file_run_started_at_utc),
                    file_run_finished_at_utc = COALESCE(EXCLUDED.file_run_finished_at_utc, phase4.step3_sim_file_summaries.file_run_finished_at_utc),
                    stats = COALESCE(phase4.step3_sim_file_summaries.stats, '{}'::jsonb) || EXCLUDED.stats,
                    updated_at_utc = now();
                """,
                {
                    "replay_id": _uuid_or_none(replay_id),
                    "replay_run_id": _uuid_or_none(replay_run_id) or "",
                    "run_id": _uuid_or_none(run_id) or "",
                    "model_id": _uuid_or_none(model_id) or "",
                    "model_version": str(model_version or "").strip() or None,
                    "file_path": str(file_path or "").strip(),
                    "file_name": str(file_name or "").strip() or None,
                    "status": str(status or "prepared").strip().lower() or "prepared",
                    "packets_total_in_file": int(packets_total_in_file or 0),
                    "packets_attack_in_file": int(packets_attack_in_file or 0),
                    "packets_benign_in_file": int(packets_benign_in_file or 0),
                    "packets_transmitted": int(packets_transmitted or 0),
                    "packets_failed": int(packets_failed or 0),
                    "packets_received": int(packets_received or 0),
                    "packets_lost": int(packets_lost or 0),
                    "alerts_triggered": int(alerts_triggered or 0),
                    "alert_ratio": float(alert_ratio or 0.0),
                    "file_run_started_at_utc": str(file_run_started_at_utc or "").strip(),
                    "file_run_finished_at_utc": str(file_run_finished_at_utc or "").strip(),
                    "stats": json.dumps(stats or {}),
                },
            )
        conn.commit()


def _prime_step3_sim_file_summaries_from_inventory(
    *,
    replay_id: str,
    run_id: str | None,
    model_id: str | None,
    model_version: str | None,
    rep01_inventory: dict[str, Any],
) -> None:
    files = list(rep01_inventory.get("files") or []) if isinstance(rep01_inventory, dict) else []
    for row in files:
        if not isinstance(row, dict):
            continue
        file_path = str(row.get("path") or "").strip()
        if not file_path:
            continue
        packets_total = int(row.get("packets") or 0)
        _upsert_step3_sim_file_summary(
            replay_id=replay_id,
            replay_run_id=None,
            run_id=run_id,
            model_id=model_id,
            model_version=model_version,
            file_path=file_path,
            file_name=Path(file_path).name,
            status="prepared",
            packets_total_in_file=packets_total,
            packets_attack_in_file=0,
            packets_benign_in_file=0,
            packets_transmitted=0,
            packets_failed=0,
            packets_received=0,
            packets_lost=0,
            alerts_triggered=0,
            alert_ratio=0.0,
            file_run_started_at_utc=None,
            file_run_finished_at_utc=None,
            stats={
                "source": "prepare_inventory",
                "size_bytes": int(row.get("size_bytes") or 0),
                "packets_total_in_file": packets_total,
            },
        )


def _read_factory_progress_rows(progress_path: Path, start_offset: int) -> tuple[list[dict[str, Any]], int]:
    if not progress_path.exists() or not progress_path.is_file():
        return [], start_offset
    raw = progress_path.read_text(encoding="utf-8")
    if start_offset >= len(raw):
        return [], len(raw)
    chunk = raw[start_offset:]
    rows: list[dict[str, Any]] = []
    for line in chunk.splitlines():
        line = str(line or "").strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except Exception:
            continue
        if isinstance(parsed, dict):
            rows.append(parsed)
    return rows, len(raw)


def _rule_status(status: str | None) -> str:
    s = str(status or "").lower()
    if s in {"no_rulepack", "pending_sync", "syncing", "ready", "failed", "stale"}:
        return s
    return "no_rulepack"


def _severity_rank(severity: str) -> int:
    m = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return m.get(str(severity or "").strip().lower(), 1)


def _normalize_urgency(severity: str, confidence: float | None, cross_scope: bool) -> str:
    base = str(severity or "low").strip().lower()
    if base not in {"critical", "high", "medium", "low"}:
        base = "low"
    conf = float(confidence) if confidence is not None else 0.0
    if cross_scope and _severity_rank(base) < 3:
        return "high"
    if conf >= 0.95 and _severity_rank(base) < 4:
        return "high" if base == "medium" else base
    if conf >= 0.99:
        return "critical"
    return base


def _mtls_paths_for_child(child_id: str) -> dict[str, Any]:
    cert_dir = Path(STEP3_MTLS_CERT_DIR)
    cert = cert_dir / f"{child_id}.crt"
    key = cert_dir / f"{child_id}.key"
    ca = Path(STEP3_MTLS_CA_PATH) if STEP3_MTLS_CA_PATH else cert_dir / "ca.crt"
    return {
        "enabled": bool(STEP3_MTLS_ENABLED),
        "require_client_cert": bool(STEP3_MTLS_REQUIRE_CLIENT_CERT),
        "cert_path": str(cert),
        "key_path": str(key),
        "ca_path": str(ca),
        "cert_exists": cert.exists(),
        "key_exists": key.exists(),
        "ca_exists": ca.exists(),
    }


def _rule_scope_for_child(child_type: str, assigned_scope: str | None) -> str:
    scope = str(assigned_scope or "").strip().lower()
    if scope:
        return scope
    ct = str(child_type or "").strip().lower()
    if ct in {"enterprise", "dns", "iot", "iiot"}:
        return ct
    return "global"


def _load_published_rules_for_child(
    *,
    child_id: str,
    child_type: str,
    assigned_scope: str | None,
    model_version: str | None = None,
) -> dict[str, Any]:
    scope = _rule_scope_for_child(child_type, assigned_scope)
    mv = str(model_version or "").strip() or None
    rp = _latest_rulepack_for_scope(scope, model_version=mv) or _latest_rulepack_for_scope("global", model_version=mv)
    if not rp:
        return {
            "ok": False,
            "child_id": child_id,
            "rule_scope": scope,
            "error": "no_published_rulepack_for_scope",
            "rules": [],
            "rulepack_version": None,
            "run_id": None,
        }
    run_id = str(rp.get("run_id") or "")
    rules: list[dict[str, Any]] = []
    with connect() as conn:
        with conn.cursor() as cur:
            if run_id:
                cur.execute(
                    """
                    SELECT rule_id::text, rule_scope, rule_type, condition_json, severity, action, evidence_sources, status
                    FROM phase4.rulepack_rules
                    WHERE run_id = %(run_id)s::uuid
                      AND (rule_scope = %(scope)s OR rule_scope = 'global' OR rule_scope = 'cross_scope')
                    ORDER BY created_at_utc ASC;
                    """,
                    {"run_id": run_id, "scope": scope},
                )
            else:
                cur.execute(
                    """
                    SELECT rule_id::text, rule_scope, rule_type, condition_json, severity, action, evidence_sources, status
                    FROM phase4.rulepack_rules
                    WHERE model_version = %(mv)s
                      AND (rule_scope = %(scope)s OR rule_scope = 'global' OR rule_scope = 'cross_scope')
                    ORDER BY created_at_utc ASC
                    LIMIT 500;
                    """,
                    {"mv": str(rp.get("model_version") or ""), "scope": scope},
                )
            for rid, rscope, rtype, cond, sev, action, evid, status in cur.fetchall():
                rules.append(
                    {
                        "rule_id": rid,
                        "rule_scope": rscope,
                        "rule_type": rtype,
                        "condition": cond or {},
                        "severity": str(sev or "low"),
                        "action": str(action or "monitor"),
                        "evidence_sources": evid or [],
                        "status": str(status or ""),
                    }
                )
    return {
        "ok": len(rules) > 0,
        "child_id": child_id,
        "rule_scope": scope,
        "rulepack_version": rp.get("rulepack_version"),
        "run_id": run_id or None,
        "rules": rules,
        "error": None if rules else "rulepack_rules_empty",
    }


def _evaluate_rule_condition(condition: dict[str, Any], context: dict[str, Any]) -> bool:
    if not isinstance(condition, dict) or not condition:
        return False
    if "all" in condition and isinstance(condition["all"], list):
        return all(_evaluate_rule_condition(x if isinstance(x, dict) else {}, context) for x in condition["all"])
    if "any" in condition and isinstance(condition["any"], list):
        return any(_evaluate_rule_condition(x if isinstance(x, dict) else {}, context) for x in condition["any"])
    feature = str(condition.get("feature") or condition.get("field") or "").strip()
    op = str(condition.get("op") or condition.get("operator") or "eq").strip().lower()
    expected = condition.get("value")
    if not feature:
        # deterministic fallback on replay phase when condition schema is absent
        replay_phase = str(context.get("replay_phase") or "")
        return replay_phase in {"attack_burst", "domain_shift"}
    actual = context.get(feature)
    if op in {"eq", "=="}:
        if isinstance(actual, (list, tuple, set)):
            return expected in actual
        return actual == expected
    if op in {"neq", "!="}:
        if isinstance(actual, (list, tuple, set)):
            return expected not in actual
        return actual != expected
    if op in {"gt", ">"}:
        try:
            return float(actual) > float(expected)
        except Exception:
            return False
    if op in {"gte", ">="}:
        try:
            return float(actual) >= float(expected)
        except Exception:
            return False
    if op in {"lt", "<"}:
        try:
            return float(actual) < float(expected)
        except Exception:
            return False
    if op in {"lte", "<="}:
        try:
            return float(actual) <= float(expected)
        except Exception:
            return False
    if op in {"contains"}:
        if isinstance(actual, (list, tuple, set)):
            return expected in actual or str(expected) in [str(x) for x in actual]
        return str(expected) in str(actual)
    if op in {"in"} and isinstance(expected, list):
        if isinstance(actual, (list, tuple, set)):
            return any(x in expected for x in actual)
        return actual in expected
    return False


def _evaluate_child_rules(
    *,
    rules: list[dict[str, Any]],
    context: dict[str, Any],
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for row in rules:
        condition = row.get("condition") if isinstance(row.get("condition"), dict) else {}
        if _evaluate_rule_condition(condition, context):
            matches.append(
                {
                    "rule_id": str(row.get("rule_id") or ""),
                    "rule_scope": str(row.get("rule_scope") or ""),
                    "rule_type": str(row.get("rule_type") or ""),
                    "severity": str(row.get("severity") or "low").lower(),
                    "action": str(row.get("action") or "monitor"),
                    "condition": condition,
                }
            )
    matches.sort(key=lambda r: _severity_rank(r.get("severity", "low")), reverse=True)
    return matches


def _parent_decision_from_evidence(
    *,
    prediction_label: str | None,
    prediction_confidence: float | None,
    top_rule_severity: str,
    cross_scope: bool,
) -> dict[str, Any]:
    sev = top_rule_severity.lower() if top_rule_severity else "low"
    urgency = _normalize_urgency(sev, prediction_confidence, cross_scope)
    label = str(prediction_label or "").lower()
    conf = float(prediction_confidence) if prediction_confidence is not None else 0.0
    if urgency == "critical":
        recommendation = "escalate_to_soc_and_isolate_segment"
        action_status = "completed"
    elif urgency == "high":
        recommendation = "escalate_to_parent"
        action_status = "completed"
    elif label in {"data_exfiltration", "reconnaissance"} and conf >= 0.85:
        recommendation = "triage_with_priority"
        action_status = "completed"
    elif conf < 0.50:
        recommendation = "operator_review_required"
        action_status = "pending_review"
    else:
        recommendation = "monitor_and_triage"
        action_status = "completed"
    return {
        "urgency": urgency,
        "recommendation": recommendation,
        "action_status": action_status,
    }

def _safe_json_dict(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            out = json.loads(raw)
            if isinstance(out, dict):
                return out
        except Exception:
            return {}
    return {}


def _runtime_track_model_id(model_id: str | None, model_version: str) -> str:
    return str(model_id or model_version)


def _resolve_step2_runtime_bundle(model_version: str) -> dict[str, Any]:
    try:
        import joblib  # type: ignore[import-not-found]
    except Exception:
        return {"ok": False, "error": "runtime_shap_dependency_missing:joblib"}
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT run_id::text, run_metrics
                FROM phase4.workflow_runs
                WHERE step_name='step2' AND (run_metrics->>'model_version') = %(mv)s
                ORDER BY started_at_utc DESC
                LIMIT 1;
                """,
                {"mv": model_version},
            )
            row = cur.fetchone()
    if not row:
        return {"ok": False, "error": "step2_run_not_found_for_model_version"}
    run_id = str(row[0])
    run_metrics = _safe_json_dict(row[1] or {})
    frozen_manifest_path = str(run_metrics.get("frozen_manifest_path") or "").strip()
    manifest: dict[str, Any] = {}
    if frozen_manifest_path:
        p = Path(frozen_manifest_path)
        if p.exists():
            manifest = _safe_json_dict(p.read_text(encoding="utf-8", errors="ignore"))
    primary_track = str(
        manifest.get("primary_supervised_model")
        or run_metrics.get("primary_supervised_model")
        or "random_forest"
    )
    model_tracks = manifest.get("model_tracks") or run_metrics.get("model_tracks") or {}
    if not isinstance(model_tracks, dict) or not model_tracks:
        return {"ok": False, "error": "step2_model_tracks_unavailable", "run_id": run_id}
    track_payload = model_tracks.get(primary_track) or model_tracks.get("random_forest") or next(
        (v for v in model_tracks.values() if isinstance(v, dict)),
        {},
    )
    if not isinstance(track_payload, dict) or not track_payload:
        return {"ok": False, "error": "step2_primary_track_unavailable", "run_id": run_id}
    model_artifact_path = str(track_payload.get("model_artifact_path") or "").strip()
    preprocess_artifact_path = str(track_payload.get("preprocessing_artifact_path") or "").strip()
    feature_list_path = str(track_payload.get("feature_list_path") or "").strip()
    label_encoder_path = str(track_payload.get("label_encoder_path") or "").strip()
    if not model_artifact_path or not preprocess_artifact_path or not feature_list_path:
        return {"ok": False, "error": "step2_track_paths_missing", "run_id": run_id}
    mp = Path(model_artifact_path)
    pp = Path(preprocess_artifact_path)
    fp = Path(feature_list_path)
    if not (mp.exists() and pp.exists() and fp.exists()):
        return {"ok": False, "error": "step2_track_paths_unreadable", "run_id": run_id}
    try:
        feature_list = json.loads(fp.read_text(encoding="utf-8"))
    except Exception:
        feature_list = []
    if not isinstance(feature_list, list) or not feature_list:
        return {"ok": False, "error": "step2_feature_list_invalid", "run_id": run_id}
    model_obj = joblib.load(mp)
    preprocess_obj = joblib.load(pp)
    label_encoder_obj = None
    if label_encoder_path and Path(label_encoder_path).exists():
        try:
            label_encoder_obj = joblib.load(label_encoder_path)
        except Exception:
            label_encoder_obj = None
    numeric_cols: set[str] = set()
    categorical_cols: set[str] = set()
    try:
        for t_name, _transformer, cols in getattr(preprocess_obj, "transformers_", []):
            if t_name == "remainder":
                continue
            if not isinstance(cols, (list, tuple)):
                continue
            cset = {str(c) for c in cols}
            if t_name == "num":
                numeric_cols.update(cset)
            else:
                categorical_cols.update(cset)
    except Exception:
        pass
    return {
        "ok": True,
        "step2_run_id": run_id,
        "frozen_manifest_path": frozen_manifest_path or None,
        "primary_track": primary_track,
        "model_tracks": model_tracks,
        "track_payload": track_payload,
        "model": model_obj,
        "preprocess": preprocess_obj,
        "label_encoder": label_encoder_obj,
        "feature_list": [str(x) for x in feature_list],
        "numeric_cols": numeric_cols,
        "categorical_cols": categorical_cols,
    }


def _runtime_bundle_for_model(model_version: str) -> dict[str, Any]:
    cached = _RUNTIME_SHAP_CACHE.get(model_version)
    if cached:
        return cached
    bundle = _resolve_step2_runtime_bundle(model_version)
    if bundle.get("ok"):
        _RUNTIME_SHAP_CACHE[model_version] = bundle
    return bundle


def _seed_runtime_features(context: dict[str, Any]) -> dict[str, Any]:
    child_id = str(context.get("child_id") or "child-unknown")
    child_type = str(context.get("child_type") or "enterprise").lower()
    seed = abs(hash(child_id)) % 240
    recv = int(context.get("packets_received") or 0)
    sent = int(context.get("packets_sent") or 0)
    payload_bytes = int(context.get("payload_bytes") or 256)
    latency_ms = float(context.get("latency_ms") or 0.0)
    replay_phase = str(context.get("replay_phase") or "mixed_recovery")
    source_domain = (
        "dns"
        if child_type == "dns"
        else ("iot" if child_type == "iot" else ("iiot" if child_type == "iiot" else "enterprise"))
    )
    expected_environment = str(context.get("expected_environment") or source_domain).strip().lower() or source_domain
    observed_environment = str(context.get("observed_environment") or source_domain).strip().lower() or source_domain
    cross_scope = observed_environment != expected_environment
    return {
        "timestamp_utc": float(time.time()),
        "source_ip": f"10.20.{seed // 16}.{(seed % 16) + 10}",
        "destination_ip": f"172.16.{seed // 16}.{(seed % 16) + 20}",
        "source_port": 5300 if child_type == "dns" else 40000 + (seed % 1024),
        "destination_port": 53 if child_type == "dns" else 443,
        "protocol": "udp" if child_type == "dns" else "tcp",
        "protocol_family": "dns" if child_type == "dns" else "transport_tcp_udp",
        "source_domain": source_domain,
        "source_zone": "dns_zone" if child_type == "dns" else ("iot_vlan" if child_type in {"iot", "iiot"} else "corp_lan"),
        "vector_class": "data_exfiltration" if replay_phase in {"attack_burst", "domain_shift"} else "unknown_suspicious",
        "scope_match": "cross_scope" if cross_scope else "in_scope",
        "expected_environment": expected_environment,
        "observed_environment": observed_environment,
        "cross_scope_flag": cross_scope,
        "escalation_reason": (
            f"environment_mismatch:{observed_environment}_vs_{expected_environment}" if cross_scope else "none"
        ),
        "categorization_confidence": 0.7 if replay_phase in {"attack_burst", "domain_shift"} else 0.55,
        "bytes_in": float(max(0, recv) * max(1, payload_bytes)),
        "bytes_out": float(max(0, sent) * max(1, payload_bytes)),
        "duration_ms": max(0.0, latency_ms),
    }


def _default_value_for_feature(
    feature: str,
    *,
    numeric_cols: set[str],
    categorical_cols: set[str],
    source_domain: str,
) -> Any:
    f = feature.lower()
    if feature in numeric_cols:
        return 0.0
    if "timestamp" in f or f.endswith("_ts") or f.endswith("_time"):
        return float(time.time())
    if "port" in f:
        return 0
    if "bytes" in f or "count" in f or "duration" in f or f.endswith("_ms") or f.endswith("_sec"):
        return 0.0
    if "confidence" in f:
        return 0.0
    if "ip" in f:
        return "0.0.0.0"
    if "protocol" in f:
        return "unknown"
    if "domain" in f:
        return source_domain
    if "zone" in f:
        return "unknown"
    if "vector" in f or "class" in f:
        return "unknown_suspicious"
    if "scope" in f:
        return "unknown"
    if feature in categorical_cols:
        return "unknown"
    return 0.0


def _build_runtime_feature_row(bundle: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    feature_list = [str(x) for x in (bundle.get("feature_list") or [])]
    if not feature_list:
        return {"ok": False, "error": "empty_feature_list"}
    numeric_cols = set(str(x) for x in (bundle.get("numeric_cols") or set()))
    categorical_cols = set(str(x) for x in (bundle.get("categorical_cols") or set()))
    source_domain = "enterprise"
    seed = _seed_runtime_features(context)
    if isinstance(seed.get("source_domain"), str):
        source_domain = str(seed.get("source_domain"))
    row: dict[str, Any] = {}
    defaulted_features: list[str] = []
    for feature in feature_list:
        if feature in seed:
            row[feature] = seed[feature]
            continue
        row[feature] = _default_value_for_feature(
            feature,
            numeric_cols=numeric_cols,
            categorical_cols=categorical_cols,
            source_domain=source_domain,
        )
        defaulted_features.append(feature)
    missing = [f for f in feature_list if f not in row]
    if missing:
        return {
            "ok": False,
            "error": "feature_integrity_missing",
            "missing_features": missing,
            "defaulted_feature_count": len(defaulted_features),
        }
    return {
        "ok": True,
        "feature_row": row,
        "defaulted_feature_count": len(defaulted_features),
        "defaulted_features": defaulted_features,
    }


def _predict_and_explain_runtime_event(
    *,
    bundle: dict[str, Any],
    model_id: str,
    model_version: str,
    replay_run_id: str,
    child_id: str,
    child_type: str,
    interaction_id: str,
    parent_action_id: str,
    context: dict[str, Any],
) -> dict[str, Any]:
    try:
        import numpy as np  # type: ignore[import-not-found]
        import pandas as pd  # type: ignore[import-not-found]
        from scipy import sparse  # type: ignore[import-not-found]
    except Exception as exc:
        return {
            "ok": False,
            "status": "runtime_shap_dependency_missing",
            "evidence_status": "failed",
            "error": f"runtime_ml_import_failed:{exc}",
            "details": {"missing_dependency": "numpy|pandas|scipy"},
        }
    row_payload = _build_runtime_feature_row(bundle, context)
    if not row_payload.get("ok"):
        return {
            "ok": False,
            "status": "feature_integrity_failed",
            "evidence_status": "failed",
            "error": str(row_payload.get("error") or "feature_integrity_failed"),
            "details": row_payload,
        }
    feature_list = [str(x) for x in (bundle.get("feature_list") or [])]
    row = row_payload["feature_row"]
    df = pd.DataFrame([row], columns=feature_list)
    model = bundle["model"]
    pre = bundle["preprocess"]
    label_encoder = bundle.get("label_encoder")
    transformed = pre.transform(df)
    if sparse.issparse(transformed):
        x_t = transformed
        x_dense = transformed.toarray()
    else:
        x_dense = np.asarray(transformed)
        x_t = sparse.csr_matrix(x_dense)
    pred_raw = model.predict(x_t)
    pred_value = pred_raw[0] if hasattr(pred_raw, "__len__") else pred_raw
    pred_label = str(pred_value)
    pred_index = 0
    if label_encoder is not None:
        try:
            pred_idx_arr = np.asarray(pred_raw).astype(int)
            pred_index = int(pred_idx_arr[0]) if pred_idx_arr.size > 0 else 0
            pred_label = str(label_encoder.inverse_transform(pred_idx_arr)[0])
        except Exception:
            pred_label = str(pred_value)
    confidence = None
    if hasattr(model, "predict_proba"):
        try:
            probs = model.predict_proba(x_t)
            if isinstance(probs, np.ndarray) and probs.ndim >= 2 and probs.shape[0] > 0:
                confidence = float(np.max(probs[0]))
        except Exception:
            confidence = None
    try:
        import shap  # type: ignore[import-not-found]
    except Exception as exc:
        return {
            "ok": False,
            "status": "runtime_shap_dependency_missing",
            "evidence_status": "failed",
            "error": f"shap_import_failed:{exc}",
            "details": {
                "defaulted_feature_count": row_payload.get("defaulted_feature_count", 0),
                "feature_count": len(feature_list),
            },
        }
    transformed_feature_names = []
    try:
        transformed_feature_names = [str(x) for x in pre.get_feature_names_out()]
    except Exception:
        transformed_feature_names = [f"f_{i}" for i in range(x_dense.shape[1])]
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(x_dense)
    if isinstance(shap_values, list):
        class_idx = min(max(0, int(pred_index)), len(shap_values) - 1)
        values = np.asarray(shap_values[class_idx])[0]
    else:
        arr = np.asarray(shap_values)
        if arr.ndim == 3:
            if arr.shape[-1] > 1:
                class_idx = min(max(0, int(pred_index)), arr.shape[-1] - 1)
                values = arr[0, :, class_idx]
            else:
                values = arr[0, :, 0]
        elif arr.ndim == 2:
            values = arr[0]
        else:
            values = arr.reshape(-1)
    abs_values = np.abs(values)
    top_k = min(10, len(transformed_feature_names))
    order = np.argsort(-abs_values)[:top_k]
    top_features = []
    for rank, idx in enumerate(order.tolist(), start=1):
        top_features.append(
            {
                "rank": rank,
                "feature": transformed_feature_names[idx] if idx < len(transformed_feature_names) else f"f_{idx}",
                "shap_value": float(values[idx]),
                "abs_shap": float(abs_values[idx]),
            }
        )
    return {
        "ok": True,
        "status": "runtime_shap_completed",
        "evidence_status": "measured",
        "prediction": {"label": pred_label, "confidence": confidence},
        "metrics": {
            "model_id": model_id,
            "model_version": model_version,
            "replay_run_id": replay_run_id,
            "child_id": child_id,
            "child_type": child_type,
            "interaction_id": interaction_id,
            "parent_action_id": parent_action_id,
            "defaulted_feature_count": int(row_payload.get("defaulted_feature_count") or 0),
            "feature_count": len(feature_list),
            "transformed_feature_count": int(len(transformed_feature_names)),
            "mean_abs_shap_total": float(abs_values.mean()) if abs_values.size > 0 else 0.0,
            "top_features": top_features,
        },
    }


def _ensure_templates() -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            for t in DEFAULT_CHILD_TEMPLATES:
                cur.execute(
                    """
                    INSERT INTO phase4.child_stack_templates (
                        template_id, child_type, assigned_scope, description, defaults_json, created_at_utc, updated_at_utc
                    )
                    VALUES (
                        %(template_id)s, %(child_type)s, %(assigned_scope)s, %(description)s, %(defaults)s::jsonb, now(), now()
                    )
                    ON CONFLICT (template_id) DO UPDATE
                    SET child_type = EXCLUDED.child_type,
                        assigned_scope = EXCLUDED.assigned_scope,
                        description = EXCLUDED.description,
                        defaults_json = EXCLUDED.defaults_json,
                        updated_at_utc = now();
                    """,
                    {
                        "template_id": t["template_id"],
                        "child_type": t["child_type"],
                        "assigned_scope": t["assigned_scope"],
                        "description": t["description"],
                        "defaults": json.dumps(t["defaults"]),
                    },
                )
        conn.commit()


def _latest_step2_ready() -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT run_id::text, run_metrics
                FROM phase4.workflow_runs
                WHERE step_name = 'step2' AND status = 'completed'
                ORDER BY started_at_utc DESC
                LIMIT 1;
                """
            )
            row = cur.fetchone()
            if not row:
                return {"ok": False, "error": "step2_not_completed"}
            run_id, run_metrics = row
            metrics = run_metrics or {}
            if isinstance(metrics, str):
                try:
                    metrics = json.loads(metrics)
                except Exception:
                    metrics = {}
            mstatus = metrics.get("model_v1_status") or {}
            if not bool(mstatus.get("frozen")):
                return {"ok": False, "error": "model_not_frozen"}
            if not bool(mstatus.get("rules_published")):
                return {"ok": False, "error": "rules_not_published"}
            return {"ok": True, "step2_run_id": run_id, "metrics": metrics}


def _json_ts(value: Any) -> str | None:
    """Format DB timestamps for JSON; drivers may return datetime or text."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            return iso()
        except Exception:
            return str(value)
    return str(value)


def _step3_registry_state_allows_gate(*, model_status: str, is_frozen: bool) -> bool:
    status_norm = str(model_status or "").strip().lower()
    if bool(is_frozen):
        return True
    return status_norm in {"frozen", "ready_for_step3", "ready_for_step3_scaffold"}


def _resolve_model_identity(model_id: str | None, model_version: str | None) -> dict[str, Any]:
    mid = str(model_id or "").strip()
    mv = str(model_version or "").strip()
    if not mid and not mv:
        return {"ok": False, "error": "model_selection_required"}
    with connect() as conn:
        with conn.cursor() as cur:
            if mid:
                cur.execute(
                    """
                    SELECT model_id::text, model_version
                    FROM phase4.model_registry
                    WHERE model_id::text = %(mid)s
                    LIMIT 1;
                    """,
                    {"mid": mid},
                )
                row = cur.fetchone()
                if not row:
                    return {"ok": False, "error": "model_id_not_found"}
                return {"ok": True, "model_id": row[0], "model_version": row[1]}
            cur.execute(
                """
                SELECT model_id::text, model_version
                FROM phase4.model_registry
                WHERE model_version = %(mv)s
                LIMIT 1;
                """,
                {"mv": mv},
            )
            row = cur.fetchone()
            if not row:
                return {"ok": False, "error": "model_version_not_found"}
            return {"ok": True, "model_id": row[0], "model_version": row[1]}


def step3_model_readiness(model_id: str | None = None, model_version: str | None = None) -> dict[str, Any]:
    identity = _resolve_model_identity(model_id, model_version)
    if not identity.get("ok"):
        return {"ok": False, "is_ready": False, "completion_percent": 0, "missing_requirements": [identity.get("error")]}
    mid = identity["model_id"]
    mv = identity["model_version"]
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT model_id::text, model_version, status, is_frozen, source_step1_run_id, artifact_root
                FROM phase4.model_registry
                WHERE model_version = %(mv)s
                LIMIT 1;
                """,
                {"mv": mv},
            )
            mrow = cur.fetchone()
            if not mrow:
                return {"ok": False, "is_ready": False, "completion_percent": 0, "missing_requirements": ["model_not_found"]}
            cur.execute(
                """
                SELECT workflow_id
                FROM phase4.workflow_runs
                WHERE step_name='step2' AND (run_metrics->>'model_version') = %(mv)s
                ORDER BY started_at_utc DESC
                LIMIT 1;
                """,
                {"mv": mv},
            )
            wf = cur.fetchone()
            source_step2_workflow_id = wf[0] if wf else None
            cur.execute("SELECT 1 FROM phase4.model_training_runs WHERE model_version=%(mv)s LIMIT 1;", {"mv": mv})
            training_ok = cur.fetchone() is not None
            cur.execute("SELECT 1 FROM phase4.model_evaluation_runs WHERE model_version=%(mv)s LIMIT 1;", {"mv": mv})
            eval_ok = cur.fetchone() is not None
            cur.execute(
                """
                SELECT status
                FROM phase4.cross_dataset_test_runs
                WHERE model_version=%(mv)s
                ORDER BY COALESCE(completed_at_utc, started_at_utc) DESC
                LIMIT 1;
                """,
                {"mv": mv},
            )
            cd = cur.fetchone()
            cd_status = str(cd[0] or "").lower() if cd else ""
            cross_ok = cd_status in {"completed", "accepted_partial"}
            cur.execute(
                """
                SELECT status, artifact_path
                FROM phase4.shap_artifacts
                WHERE model_version=%(mv)s
                ORDER BY created_at_utc DESC
                LIMIT 1;
                """,
                {"mv": mv},
            )
            shap_row = cur.fetchone()
            shap_ok = bool(shap_row and str(shap_row[0]).lower() in {"completed", "ready", "ok"})
            cur.execute(
                """
                SELECT rulepack_version, status, artifact_path
                FROM phase4.rulepack_registry
                WHERE model_version=%(mv)s
                ORDER BY created_at_utc DESC
                LIMIT 1;
                """,
                {"mv": mv},
            )
            rp_row = cur.fetchone()
            rule_generated = rp_row is not None
            rule_published = bool(rp_row and str(rp_row[1]).lower() == "published")
            cur.execute(
                """
                SELECT audit_id::text, event_type, created_at
                FROM phase4.audit_log
                WHERE model_version=%(mv)s
                ORDER BY created_at DESC
                LIMIT 1;
                """,
                {"mv": mv},
            )
            audit = cur.fetchone()
    model_status = str(mrow[2] or "")
    is_frozen = bool(mrow[3])
    source_step1_run_id = mrow[4]
    artifact_root = mrow[5]
    invalid_lineage = model_status == "invalid_lineage"
    registry_gate_ok = _step3_registry_state_allows_gate(model_status=model_status, is_frozen=is_frozen)
    checks = [
        (
            "step2_completion_100",
            training_ok and eval_ok and cross_ok and shap_ok and rule_generated and rule_published and registry_gate_ok,
        ),
        ("status_frozen_or_ready_for_step3", registry_gate_ok),
        ("training_completed", training_ok),
        ("evaluation_completed", eval_ok),
        ("cross_dataset_testing_completed_or_accepted_partial", cross_ok),
        ("shap_completed", shap_ok),
        ("rulepacks_generated", rule_generated),
        ("rulepacks_published", rule_published),
        ("no_invalid_lineage", not invalid_lineage),
        ("source_step1_run_id_linked", bool(source_step1_run_id)),
        ("audit_trail_present", audit is not None),
    ]
    passed = sum(1 for _, ok in checks if ok)
    missing = [name for name, ok in checks if not ok]
    completion_percent = int(round((passed / len(checks)) * 100)) if checks else 0
    return {
        "ok": True,
        "is_ready": len(missing) == 0 and completion_percent == 100,
        "completion_percent": completion_percent,
        "missing_requirements": missing,
        "model_id": mid,
        "model_version": mv,
        "registry_status": model_status,
        "source_step1_run_id": source_step1_run_id,
        "source_step2_workflow_id": source_step2_workflow_id,
        "frozen_status": is_frozen,
        "active_rulepack_version": rp_row[0] if rp_row else None,
        "artifact_root": artifact_root,
        "latest_audit_event": (
            {"event_id": audit[0], "event_type": audit[1], "timestamp": _json_ts(audit[2])}
            if audit
            else None
        ),
        "model_artifacts": {"artifact_root": artifact_root},
        "rulepacks": (
            {"rulepack_version": rp_row[0], "status": rp_row[1], "artifact_path": rp_row[2]}
            if rp_row
            else {}
        ),
        "shap_artifacts": (
            {"status": shap_row[0], "artifact_path": shap_row[1]}
            if shap_row
            else {}
        ),
        "audit_status": {"present": audit is not None},
    }


def step3_eligible_models(*, ready_only: bool = False) -> dict[str, Any]:
    """List Step-3 candidate model versions from model registry and split ready vs incomplete rows."""
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT model_id::text, model_version
                FROM phase4.model_registry
                WHERE
                    COALESCE(is_frozen, false) = true
                    OR LOWER(TRIM(COALESCE(status, ''))) IN ('frozen', 'ready_for_step3', 'ready_for_step3_scaffold')
                ORDER BY created_at DESC;
                """
            )
            rows = cur.fetchall()
    eligible: list[dict[str, Any]] = []
    incomplete: list[dict[str, Any]] = []
    for row in rows:
        rd = step3_model_readiness(model_id=row[0], model_version=row[1])
        if not rd.get("ok"):
            continue
        item = {
            "model_id": rd.get("model_id"),
            "model_version": rd.get("model_version"),
            "registry_status": rd.get("registry_status"),
            "completion_percent": rd.get("completion_percent", 0),
            "is_ready": rd.get("is_ready", False),
            "missing_requirements": rd.get("missing_requirements") or [],
            "source_step1_run_id": rd.get("source_step1_run_id"),
            "source_step2_workflow_id": rd.get("source_step2_workflow_id"),
            "active_rulepack_version": rd.get("active_rulepack_version"),
        }
        if item["is_ready"]:
            eligible.append(item)
        else:
            incomplete.append(item)
    out: dict[str, Any] = {
        "ok": True,
        "eligible_models": eligible,
        "incomplete_models": [] if ready_only else incomplete,
        "total_models": len(rows),
        "ready_only": bool(ready_only),
    }
    return out


def _preparation_row(model_version: str) -> dict[str, Any] | None:
    mv = str(model_version or "").strip()
    if not mv:
        return None
    prep_run = get_latest_step3_preparation_run(model_version=mv)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT model_version, model_id::text, verified_ok, checks, verified_at_utc
                FROM phase4.step3_model_preparation
                WHERE model_version = %(mv)s
                LIMIT 1;
                """,
                {"mv": mv},
            )
            row = cur.fetchone()
    if not row:
        if prep_run:
            return {
                "model_version": str(prep_run.get("model_version") or mv),
                "model_id": prep_run.get("model_id"),
                "verified_ok": bool(prep_run.get("verified_ok")),
                "checks": prep_run.get("checks") or [],
                "verified_at": prep_run.get("updated_at"),
                "preparation_replay_id": prep_run.get("replay_id"),
                "prepare_status": prep_run.get("status"),
                "prepare_created_at": prep_run.get("created_at"),
                "prepare_updated_at": prep_run.get("updated_at"),
                "prepare_payload": prep_run.get("prepare_payload") or {},
                "prepare_result": prep_run.get("prepare_result") or {},
                "verify_result": prep_run.get("verify_result") or {},
                "run_checks": prep_run.get("checks") or [],
            }
        return None
    chk = row[3]
    if isinstance(chk, dict):
        chk = [chk]
    elif not isinstance(chk, list):
        chk = []
    out = {
        "model_version": row[0],
        "model_id": row[1],
        "verified_ok": bool(row[2]),
        "checks": chk,
        "verified_at": row[4].isoformat() if row[4] else None,
    }
    if prep_run:
        out["preparation_replay_id"] = prep_run.get("replay_id")
        out["prepare_status"] = prep_run.get("status")
        out["prepare_created_at"] = prep_run.get("created_at")
        out["prepare_updated_at"] = prep_run.get("updated_at")
        out["prepare_payload"] = prep_run.get("prepare_payload") or {}
        out["prepare_result"] = prep_run.get("prepare_result") or {}
        out["verify_result"] = prep_run.get("verify_result") or {}
        out["run_checks"] = prep_run.get("checks") or []
    return out


def _preparation_verified(model_version: str) -> bool:
    row = _preparation_row(model_version)
    return bool(row and row.get("verified_ok"))


def _latest_preparation_replay_id(model_version: str) -> str | None:
    mv = str(model_version or "").strip()
    if not mv:
        return None
    row = get_latest_step3_preparation_run(model_version=mv)
    if not row:
        return None
    return _uuid_or_none(row.get("replay_id"))


def step3_preparation_verify(payload: dict[str, Any], data_root: Path) -> dict[str, Any]:
    """Run Preparation-phase checks and persist result for replay gating."""
    payload = payload or {}
    skip_prepare = _to_bool(payload.get("skip_prepare"), default=False)
    prep: dict[str, Any] | None = None
    prepared_hint = payload.get("_prepared_result")
    if isinstance(prepared_hint, dict):
        prep = dict(prepared_hint)
    if prep is None:
        if skip_prepare:
            hinted_mv = str(payload.get("model_version") or "").strip()
            hinted_mid = str(payload.get("model_id") or "").strip()
            row = _preparation_row(hinted_mv) if hinted_mv else None
            prepare_result = row.get("prepare_result") if isinstance(row, dict) and isinstance(row.get("prepare_result"), dict) else {}
            if prepare_result:
                prep = dict(prepare_result)
            else:
                prep = {
                    "ok": False,
                    "error": "preparation_state_missing_for_verify",
                    "missing_requirements": ["run_step3_prepare_first"],
                    "model_version": hinted_mv or (row.get("model_version") if isinstance(row, dict) else ""),
                    "model_id": hinted_mid or (row.get("model_id") if isinstance(row, dict) else ""),
                    "phase1_substages": [],
                }
                if isinstance(row, dict):
                    rid = _uuid_or_none(row.get("preparation_replay_id"))
                    if rid:
                        prep["preparation_replay_id"] = rid
        else:
            prep = step3_prepare(payload)
    checks: list[dict[str, Any]] = []
    all_ok = True
    model_version = ""
    model_id: str | None = None
    prep_replay_id = (
        _uuid_or_none(prep.get("preparation_replay_id"))
        or _preparation_replay_id(payload)
        or str(uuid.uuid4())
    )
    phase1_substages = list(prep.get("phase1_substages") or [])
    if not prep.get("ok"):
        all_ok = False
        checks.append({"name": "model_prepare", "ok": False, "detail": prep.get("missing_requirements") or []})
    else:
        model_version = str(prep.get("model_version") or "")
        model_id = str(prep.get("model_id") or "") or None
        if not _docker_cli_available():
            checks.append({"name": "docker_cli_available", "ok": False, "detail": ["docker binary is missing in phase4-dash-api container"]})
            all_ok = False
        else:
            checks.append({"name": "docker_cli_available", "ok": True, "detail": []})
        if not _step3_docker_enabled():
            checks.append({"name": "docker_orchestration_enabled", "ok": False, "detail": ["STEP3_DOCKER_ORCHESTRATION must be 1"]})
            all_ok = False
        else:
            checks.append({"name": "docker_orchestration_enabled", "ok": True, "detail": []})
        gate = step3_model_readiness(model_id=model_id, model_version=model_version)
        mr_ok = bool(gate.get("is_ready"))
        checks.append(
            {
                "name": "step2_model_readiness_100",
                "ok": mr_ok,
                "detail": gate.get("missing_requirements") or [],
            }
        )
        if not mr_ok:
            all_ok = False
        missing_set = {str(x).strip() for x in (gate.get("missing_requirements") or [])}
        audit_ok = "audit_trail_present" not in missing_set
        checks.append({"name": "audit_trail_present", "ok": audit_ok, "detail": [] if audit_ok else ["audit_trail_present"]})
        if not audit_ok:
            all_ok = False
        lineage_ok = "no_invalid_lineage" not in missing_set
        checks.append({"name": "governance_lineage_valid", "ok": lineage_ok, "detail": [] if lineage_ok else ["no_invalid_lineage"]})
        if not lineage_ok:
            all_ok = False
        rulepack_ok = "rulepacks_published" not in missing_set
        checks.append({"name": "governance_rulepack_published", "ok": rulepack_ok, "detail": [] if rulepack_ok else ["rulepacks_published"]})
        if not rulepack_ok:
            all_ok = False
        stack = _step3_readiness(model_id=model_id, model_version=model_version)
        sr_ok = bool(stack.get("ok"))
        checks.append({"name": "child_stack_readiness", "ok": sr_ok, "detail": stack.get("missing") or []})
        if not sr_ok:
            all_ok = False
        # Explicit non-stub checks: child containers + factory image/network readiness.
        children = list_child_stacks().get("children", [])
        child_checks: list[dict[str, Any]] = []
        for c in children:
            cid = str(c.get("child_id") or "")
            if not cid:
                continue
            cname = _child_container_name(cid)
            ok_run, state = _docker_container_running(cname)
            child_checks.append({"child_id": cid, "container_name": cname, "running": ok_run, "state": state})
        child_runtime_ok = len(child_checks) > 0 and all(bool(x.get("running")) for x in child_checks)
        checks.append({"name": "child_containers_running", "ok": child_runtime_ok, "detail": child_checks})
        if not child_runtime_ok:
            all_ok = False
        rule_sync_checks: list[dict[str, Any]] = []
        for c in children:
            cid = str(c.get("child_id") or "")
            if not cid:
                continue
            rs = runtime_stats(cid)
            rule_sync_checks.append(
                {
                    "child_id": cid,
                    "rule_sync_status": str(getattr(rs, "rule_sync_status", "unreachable")) if rs else "unreachable",
                    "active_rule_count": int(getattr(rs, "active_rule_count", 0) or 0) if rs else 0,
                    "rulepack_version": str(getattr(rs, "rulepack_version", "") or "") if rs else None,
                    "runtime_reachable": bool(rs),
                }
            )
        rules_tx_ok = len(rule_sync_checks) > 0 and all(
            bool(x.get("runtime_reachable"))
            and str(x.get("rule_sync_status") or "").lower() == "ready"
            and int(x.get("active_rule_count") or 0) > 0
            for x in rule_sync_checks
        )
        checks.append({"name": "rules_transmitted_to_children", "ok": rules_tx_ok, "detail": rule_sync_checks})
        if not rules_tx_ok:
            all_ok = False
        packet_feature_checks: list[dict[str, Any]] = []
        window_agg_checks: list[dict[str, Any]] = []
        eval_pipeline_checks: list[dict[str, Any]] = []
        for c in children:
            cid = str(c.get("child_id") or "")
            if not cid:
                continue
            rs = runtime_stats(cid)
            packet_feature_checks.append(
                {
                    "child_id": cid,
                    "runtime_reachable": bool(rs),
                    "packet_feature_extraction_active": bool(getattr(rs, "packet_feature_extraction_active", False)),
                }
            )
            window_agg_checks.append(
                {
                    "child_id": cid,
                    "runtime_reachable": bool(rs),
                    "window_aggregator_active": bool(getattr(rs, "window_aggregator_active", False)),
                    "window_sizes_s": list(getattr(rs, "configured_window_sizes_s", [1, 5, 30])),
                }
            )
            eval_pipeline_checks.append(
                {
                    "child_id": cid,
                    "runtime_reachable": bool(rs),
                    "rule_evaluation_pipeline_active": bool(getattr(rs, "rule_evaluation_pipeline_active", False)),
                    "active_rule_count": int(getattr(rs, "active_rule_count", 0) or 0),
                }
            )
        packet_feature_ok = len(packet_feature_checks) > 0 and all(
            bool(x.get("runtime_reachable")) and bool(x.get("packet_feature_extraction_active")) for x in packet_feature_checks
        )
        checks.append({"name": "packet_feature_extraction_active", "ok": packet_feature_ok, "detail": packet_feature_checks})
        if not packet_feature_ok:
            all_ok = False
        window_agg_ok = len(window_agg_checks) > 0 and all(
            bool(x.get("runtime_reachable")) and bool(x.get("window_aggregator_active")) for x in window_agg_checks
        )
        checks.append({"name": "window_aggregator_active", "ok": window_agg_ok, "detail": window_agg_checks})
        if not window_agg_ok:
            all_ok = False
        eval_pipeline_ok = len(eval_pipeline_checks) > 0 and all(
            bool(x.get("runtime_reachable"))
            and bool(x.get("rule_evaluation_pipeline_active"))
            and int(x.get("active_rule_count") or 0) > 0
            for x in eval_pipeline_checks
        )
        checks.append({"name": "rule_evaluation_pipeline_active", "ok": eval_pipeline_ok, "detail": eval_pipeline_checks})
        if not eval_pipeline_ok:
            all_ok = False
        factory_image = _step3_docker_image()
        factory_ready = _docker_image_exists(factory_image) and _docker_network_exists(SIMULATION_NETWORK_ID)
        checks.append(
            {
                "name": "factory_stack_ready",
                "ok": factory_ready,
                "detail": {
                    "image": factory_image,
                    "image_exists": _docker_image_exists(factory_image),
                    "simulation_network_exists": _docker_network_exists(SIMULATION_NETWORK_ID),
                },
            }
        )
        if not factory_ready:
            all_ok = False
        paths = resolve_rep01_pcap_paths(data_root)
        pcap_ok = bool(paths) or count_step3_pcap_catalog() > 0
        pcap_register_errors: list[str] = []
        try:
            if paths:
                tp = str(payload.get("traffic_profile") or "mixed").strip() or "mixed"
                for p in paths:
                    try:
                        sz = int(p.stat().st_size) if p.exists() else None
                        register_step3_pcap_catalog(
                            file_path=str(p),
                            byte_size=sz,
                            traffic_profile=tp,
                            metadata={
                                "source": "preparation_verify",
                                "replay_id": prep_replay_id,
                                "preparation_replay_id": prep_replay_id,
                                "model_version": model_version,
                            },
                        )
                    except Exception as perr:
                        pcap_register_errors.append(f"{p}:{perr}")
                pcap_ok = len(paths) > 0 and len(pcap_register_errors) == 0
        except Exception as exc:
            checks.append({"name": "pcap_catalog_register", "ok": False, "detail": str(exc)})
            all_ok = False
        if pcap_register_errors:
            checks.append({"name": "pcap_catalog_register", "ok": False, "detail": pcap_register_errors})
            all_ok = False
        else:
            checks.append(
                {
                    "name": "pcap_catalog",
                    "ok": pcap_ok,
                    "detail": {
                        "resolved_paths": [str(x) for x in paths],
                        "catalog_rows": count_step3_pcap_catalog(),
                    },
                }
            )
            if not pcap_ok:
                all_ok = False
        if phase1_substages:
            replaced = False
            for idx, row in enumerate(phase1_substages):
                if str(row.get("name") or "") == "verify_all_stages_completed":
                    phase1_substages[idx] = {
                        "name": "verify_all_stages_completed",
                        "ok": bool(all_ok),
                        "status": "completed" if bool(all_ok) else "failed",
                        "detail": {"checks_passed": len([c for c in checks if bool(c.get("ok"))]), "checks_total": len(checks)},
                        "updated_at": _now(),
                    }
                    replaced = True
                    break
            if not replaced:
                phase1_substages.append(
                    {
                        "name": "verify_all_stages_completed",
                        "ok": bool(all_ok),
                        "status": "completed" if bool(all_ok) else "failed",
                        "detail": {"checks_passed": len([c for c in checks if bool(c.get("ok"))]), "checks_total": len(checks)},
                        "updated_at": _now(),
                    }
                )
    if model_version:
        upsert_step3_model_preparation(
            model_version=model_version,
            model_id=model_id,
            replay_id=prep_replay_id,
            verified_ok=all_ok,
            checks=checks,
        )
        verify_result = {
            "ok": True,
            "verified_ok": all_ok,
            "checks": checks,
            "model_version": model_version,
            "model_id": model_id,
            "preparation_replay_id": prep_replay_id,
        }
        if phase1_substages:
            verify_result["phase1_substages"] = phase1_substages
        upsert_step3_preparation_run(
            replay_id=prep_replay_id,
            model_id=model_id,
            model_version=model_version,
            status="verified" if all_ok else "verification_failed",
            verified_ok=all_ok,
            verify_result=verify_result,
            checks=checks,
        )
    return {
        "ok": True,
        "verified_ok": all_ok,
        "checks": checks,
        "model_version": model_version or None,
        "model_id": model_id,
        "preparation_replay_id": prep_replay_id,
        "phase1_substages": phase1_substages,
    }


def step3_preparation_status(*, model_version: str) -> dict[str, Any]:
    mv = str(model_version or "").strip()
    if not mv:
        # Default to current model
        try:
            from services_parent.model_v1.model_versions import get_current_model
            current = get_current_model()
            if current.get("ok"):
                mv = current["model"].get("model_version", "")
        except Exception:
            pass
    if not mv:
        return {"ok": True, "verified_ok": False, "record": None, "missing": ["model_version"]}
    row = _preparation_row(mv)
    if not row:
        return {"ok": True, "verified_ok": False, "record": None}
    return {"ok": True, "verified_ok": bool(row.get("verified_ok")), "record": row}


def _prepare_step3_docker_stacks(*, model_id: str, model_version: str) -> dict[str, Any]:
    def _stage_row(name: str, ok: bool, *, detail: Any = None, metrics: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "name": name,
            "ok": bool(ok),
            "status": "completed" if ok else "failed",
            "detail": detail,
            "metrics": metrics or {},
            "updated_at": _now(),
        }

    def _network_isolation_report(children_rows: list[dict[str, Any]]) -> dict[str, Any]:
        client_nets: list[str] = []
        mgmt_nets: list[str] = []
        db_nets: list[str] = []
        missing: list[str] = []
        for c in children_rows:
            cid = str(c.get("child_id") or "").strip()
            if not cid:
                continue
            cn = str(c.get("client_network_id") or _client_network_id(cid)).strip()
            mn = str(c.get("management_network_id") or _management_network_id(cid)).strip()
            dn = _child_db_network_id(cid)
            if not cn:
                missing.append(f"{cid}:client_network_missing")
            if not mn:
                missing.append(f"{cid}:management_network_missing")
            if not dn:
                missing.append(f"{cid}:db_network_missing")
            if cn:
                client_nets.append(cn)
            if mn:
                mgmt_nets.append(mn)
            if dn:
                db_nets.append(dn)
        dup_client = sorted({n for n in client_nets if client_nets.count(n) > 1})
        dup_mgmt = sorted({n for n in mgmt_nets if mgmt_nets.count(n) > 1})
        overlap_client_mgmt = sorted(set(client_nets).intersection(set(mgmt_nets)))
        network_missing_runtime: list[str] = []
        for net_name in sorted(set(client_nets + mgmt_nets + db_nets)):
            if not _docker_network_exists(net_name):
                network_missing_runtime.append(net_name)
        ok = len(missing) == 0 and len(dup_client) == 0 and len(dup_mgmt) == 0 and len(overlap_client_mgmt) == 0 and len(network_missing_runtime) == 0
        detail = {
            "missing": missing,
            "duplicate_client_networks": dup_client,
            "duplicate_management_networks": dup_mgmt,
            "overlap_client_management_networks": overlap_client_mgmt,
            "missing_runtime_networks": network_missing_runtime,
            "client_networks": sorted(set(client_nets)),
            "management_networks": sorted(set(mgmt_nets)),
            "db_networks": sorted(set(db_nets)),
            "expected_policy": "child client/mgmt networks isolated; no client↔mgmt overlap; per-child db network present",
        }
        return {"ok": ok, "detail": detail}

    def _factory_probe() -> dict[str, Any]:
        probe_id = str(uuid.uuid4())
        probe_name = f"ids-step3-factory-probe-{probe_id[:12]}"
        ok_net, net_err = _ensure_docker_network(SIMULATION_NETWORK_ID, internal=True)
        if not ok_net:
            return {"ok": False, "error": f"simulation_network_missing:{net_err}"}
        _remove_container_if_exists(probe_name)
        cmd = [
            "docker",
            "run",
            "--name",
            probe_name,
            "--network",
            SIMULATION_NETWORK_ID,
            "--rm",
            "-v",
            f"{_step3_host_data_root()}:/data",
            "-v",
            f"{_step3_host_raw_downloads_root()}:/data/raw_downloads:ro",
            _step3_docker_image(),
            "python",
            "-c",
            "from pathlib import Path; p=Path('/data/raw_downloads/REP-01'); print('factory_probe_ok', p.exists())",
        ]
        ok, out, err = _run_docker(cmd, timeout_s=STEP3_DOCKER_PROBE_TIMEOUT_S)
        return {"ok": ok, "stdout": out, "stderr": err}

    children = list_child_stacks().get("children", [])
    started: list[str] = []
    failed: list[dict[str, Any]] = []
    for child in children:
        cid = str(child.get("child_id") or "")
        status = str(child.get("status") or "").lower()
        if not cid:
            continue
        if status == "running":
            # Child can be marked running in DB while container is gone (daemon restart/manual cleanup).
            # In that case, self-heal by recreating it instead of failing later with "no such object".
            cname = _child_container_name(cid)
            is_running, _state = _docker_container_running(cname)
            if is_running:
                ok, err = _ensure_stack_network_memberships(
                    cid,
                    client_net=str(child.get("client_network_id") or _client_network_id(cid)),
                    mgmt_net=str(child.get("management_network_id") or _management_network_id(cid)),
                    db_net=str(child.get("db_network_id") or _child_db_network_id(cid)),
                )
                if not ok:
                    failed.append({"child_id": cid, "error": err})
                    continue
                register_remote_runtime(
                    cid,
                    int(child.get("management_port") or _management_port(cid)),
                    host=cname,
                )
                continue
        out = _child_stack_lifecycle_docker(cid, "start", child)
        if out.get("ok"):
            started.append(cid)
        else:
            failed.append({"child_id": cid, "error": out.get("error")})
    deploy = deploy_rules({})
    deploy_results = list(deploy.get("results") or [])
    deploy_failures = [r for r in deploy_results if not bool(r.get("ok"))]
    # Hard proof child nodes are real docker containers and currently running.
    running_checks: list[dict[str, Any]] = []
    for child in list_child_stacks().get("children", []):
        cid = str(child.get("child_id") or "")
        if not cid:
            continue
        cname = _child_container_name(cid)
        ok_run, state = _docker_container_running(cname)
        running_checks.append({"child_id": cid, "container_name": cname, "running": ok_run, "state": state})
    running_failures = [x for x in running_checks if not x.get("running")]
    # Factory stack readiness check: image present + simulation network available.
    factory_image = _step3_docker_image()
    factory_image_ok = _docker_image_exists(factory_image)
    sim_net_ok = _docker_network_exists(SIMULATION_NETWORK_ID)
    factory_probe = _factory_probe() if factory_image_ok else {"ok": False, "error": "factory_image_missing"}
    isolation = _network_isolation_report(list_child_stacks().get("children", []))
    networks = network_status()
    topology = network_topology()
    stage_rows = [
        _stage_row(
            "create_and_start_child_stacks",
            len(failed) == 0 and len(running_failures) == 0,
            detail={"failed_children": failed, "running_failures": running_failures},
            metrics={"started": len(started), "total": len(children)},
        ),
        _stage_row(
            "create_and_start_factory_stack",
            bool(factory_image_ok and sim_net_ok and factory_probe.get("ok")),
            detail={
                "factory_image": factory_image,
                "factory_image_exists": factory_image_ok,
                "simulation_network_exists": sim_net_ok,
                "factory_probe": factory_probe,
            },
            metrics={"simulation_network": SIMULATION_NETWORK_ID},
        ),
        _stage_row(
            "sync_parent_rules_to_child_stacks",
            bool(deploy.get("ok")) and len(deploy_failures) == 0,
            detail={"deploy_failures": deploy_failures},
            metrics={"success": len(deploy_results) - len(deploy_failures), "total": len(deploy_results)},
        ),
        _stage_row(
            "confirm_network_isolation",
            bool(isolation.get("ok")),
            detail=isolation.get("detail"),
            metrics={"children": len(children)},
        ),
    ]
    boot_errors: list[str] = []
    if failed:
        boot_errors.append(
            "child_start_failed:"
            + ",".join(f"{str(x.get('child_id') or '')}:{str(x.get('error') or 'unknown')}" for x in failed)
        )
    if running_failures:
        boot_errors.append(
            "child_not_running:"
            + ",".join(f"{str(x.get('child_id') or '')}:{str(x.get('state') or 'unknown')}" for x in running_failures)
        )
    if deploy_failures:
        boot_errors.append(
            "rules_deploy_failed:"
            + ",".join(f"{str(x.get('child_id') or '')}:{str(x.get('error') or x.get('status') or 'unknown')}" for x in deploy_failures)
        )
    if not factory_image_ok:
        boot_errors.append("factory_image_missing")
    if not sim_net_ok:
        boot_errors.append("simulation_network_missing")
    if not bool(factory_probe.get("ok")):
        boot_errors.append(f"factory_probe_failed:{str(factory_probe.get('error') or factory_probe.get('stderr') or 'unknown')}")
    if not bool(isolation.get("ok")):
        boot_errors.append("network_isolation_failed")
    return {
        "ok": len(failed) == 0 and bool(deploy.get("ok")) and len(deploy_failures) == 0 and len(running_failures) == 0 and factory_image_ok and sim_net_ok and bool(factory_probe.get("ok")) and bool(isolation.get("ok")),
        "error": (";".join(boot_errors) if boot_errors else None),
        "model_id": model_id or None,
        "model_version": model_version or None,
        "started_children": started,
        "failed_children": failed,
        "rules_deploy": deploy,
        "rules_deploy_failures": deploy_failures,
        "child_container_checks": running_checks,
        "child_container_failures": running_failures,
        "network_status": networks,
        "network_topology": topology,
        "network_isolation": isolation,
        "factory_probe": factory_probe,
        "phase1_substages": stage_rows,
        "factory_stack": {
            "network": SIMULATION_NETWORK_ID,
            "orchestration": "docker_factory",
            "image": factory_image,
            "image_exists": factory_image_ok,
            "simulation_network_exists": sim_net_ok,
        },
    }


def step3_prepare(payload: dict[str, Any]) -> dict[str, Any]:
    payload = payload or {}
    model_id = payload.get("model_id")
    model_version = str(payload.get("model_version") or "").strip()
    if not model_version and not model_id:
        # Default to current model
        try:
            from services_parent.model_v1.model_versions import get_current_model
            current = get_current_model()
            if current.get("ok"):
                model_version = current["model"].get("model_version", "")
                model_id = current["model"].get("model_id")
        except Exception:
            pass
    rd = step3_model_readiness(model_id, model_version)
    if not rd.get("ok"):
        return rd
    prep_replay_id = _preparation_replay_id(payload) or str(uuid.uuid4())
    stage_rows: list[dict[str, Any]] = [
        {
            "name": "create_replay_id",
            "ok": True,
            "status": "completed",
            "detail": {"preparation_replay_id": prep_replay_id},
            "updated_at": _now(),
        },
        {
            "name": "link_replay_id_to_model_and_readiness",
            "ok": bool(rd.get("is_ready")),
            "status": "completed" if bool(rd.get("is_ready")) else "failed",
            "detail": {
                "model_id": rd.get("model_id"),
                "model_version": rd.get("model_version"),
                "completion_percent": rd.get("completion_percent"),
                "missing_requirements": rd.get("missing_requirements") or [],
            },
            "updated_at": _now(),
        },
    ]
    resolved_mid = str(rd.get("model_id") or "")
    resolved_mv = str(rd.get("model_version") or "")
    step1_run_id = _uuid_or_none(rd.get("source_step1_run_id"))
    rep01_inventory = resolve_rep01_packet_inventory(Path("/data"))
    if int(rep01_inventory.get("files_count") or 0) <= 0:
        rep01_inventory = resolve_rep01_packet_inventory(Path(__file__).resolve().parents[2] / "data")
    rd["sim_id"] = prep_replay_id
    rd["run_id"] = step1_run_id
    rd["rep01_packet_inventory"] = rep01_inventory
    upsert_step3_preparation_run(
        replay_id=prep_replay_id,
        model_id=resolved_mid or None,
        model_version=resolved_mv,
        status="prepare_started",
        prepare_payload=payload,
    )
    if not _step3_docker_enabled():
        missing = list(rd.get("missing_requirements") or [])
        missing.append("docker_orchestration_required")
        rd["is_ready"] = False
        rd["missing_requirements"] = sorted(set(missing))
        rd["stack_prepare"] = {
            "ok": False,
            "error": "docker_orchestration_disabled",
            "required_env": "STEP3_DOCKER_ORCHESTRATION=1",
        }
        stage_rows.append(
            {
                "name": "docker_orchestration_enabled",
                "ok": False,
                "status": "failed",
                "detail": rd["stack_prepare"],
                "updated_at": _now(),
            }
        )
        rd["phase1_substages"] = stage_rows
        rd["preparation_replay_id"] = prep_replay_id
        upsert_step3_preparation_run(
            replay_id=prep_replay_id,
            model_id=resolved_mid or None,
            model_version=resolved_mv,
            status="prepare_failed",
            verified_ok=False,
            prepare_result=rd,
        )
        return rd
    if not _docker_cli_available():
        missing = list(rd.get("missing_requirements") or [])
        missing.append("docker_cli_missing")
        rd["is_ready"] = False
        rd["missing_requirements"] = sorted(set(missing))
        rd["stack_prepare"] = {
            "ok": False,
            "error": "docker_cli_not_available",
            "detail": "Install docker CLI in phase4-dash-api image and keep /var/run/docker.sock mounted.",
        }
        stage_rows.append(
            {
                "name": "docker_cli_available",
                "ok": False,
                "status": "failed",
                "detail": rd["stack_prepare"],
                "updated_at": _now(),
            }
        )
        rd["phase1_substages"] = stage_rows
        rd["preparation_replay_id"] = prep_replay_id
        upsert_step3_preparation_run(
            replay_id=prep_replay_id,
            model_id=resolved_mid or None,
            model_version=resolved_mv,
            status="prepare_failed",
            verified_ok=False,
            prepare_result=rd,
        )
        return rd
    _ensure_templates()
    _ensure_default_child_stacks()
    if _step3_docker_enabled():
        boot = _prepare_step3_docker_stacks(
            model_id=str(rd.get("model_id") or ""),
            model_version=str(rd.get("model_version") or ""),
        )
        rd["stack_prepare"] = boot
        stage_rows.extend(list(boot.get("phase1_substages") or []))
        if not boot.get("ok"):
            rd["is_ready"] = False
            missing = list(rd.get("missing_requirements") or [])
            missing.append("docker_stack_prepare_failed")
            rd["missing_requirements"] = sorted(set(missing))
    stage_rows.append(
        {
            "name": "verify_all_stages_completed",
            "ok": False,
            "status": "pending",
            "detail": "Run /model-v1/step3/preparation/verify to complete phase-1 governance verification.",
            "updated_at": _now(),
        }
    )
    stage_rows.append(
        {
            "name": "persist_phase1_stage_state_to_postgres",
            "ok": True,
            "status": "completed",
            "detail": {"store": "phase4.step3_preparation_runs", "key": prep_replay_id},
            "updated_at": _now(),
        }
    )
    if _uuid_or_none(prep_replay_id) and int(rep01_inventory.get("files_count") or 0) > 0:
        try:
            _prime_step3_sim_file_summaries_from_inventory(
                replay_id=prep_replay_id,
                run_id=step1_run_id,
                model_id=resolved_mid or None,
                model_version=resolved_mv,
                rep01_inventory=rep01_inventory,
            )
            stage_rows.append(
                {
                    "name": "prime_per_pcap_summary_rows",
                    "ok": True,
                    "status": "completed",
                    "detail": {
                        "sim_id": prep_replay_id,
                        "files_count": int(rep01_inventory.get("files_count") or 0),
                    },
                    "updated_at": _now(),
                }
            )
        except Exception as exc:
            stage_rows.append(
                {
                    "name": "prime_per_pcap_summary_rows",
                    "ok": False,
                    "status": "failed",
                    "detail": {"error": str(exc)},
                    "updated_at": _now(),
                }
            )
    rd["phase1_substages"] = stage_rows
    rd["preparation_replay_id"] = prep_replay_id
    upsert_step3_preparation_run(
        replay_id=prep_replay_id,
        model_id=resolved_mid or None,
        model_version=resolved_mv,
        status="prepared" if bool(rd.get("is_ready")) else "prepare_failed",
        verified_ok=bool(rd.get("is_ready")),
        prepare_result=rd,
    )
    return rd


def _latest_rulepack_for_scope(scope: str, *, model_version: str | None = None) -> dict[str, Any] | None:
    with connect() as conn:
        with conn.cursor() as cur:
            if model_version:
                cur.execute(
                    """
                    SELECT rulepack_version, checksum_sha256, artifact_path, model_version, run_id::text
                    FROM phase4.rulepack_registry
                    WHERE scope = %(scope)s
                      AND model_version = %(model_version)s
                      AND status = 'published'
                    ORDER BY created_at_utc DESC
                    LIMIT 1;
                    """,
                    {"scope": scope, "model_version": model_version},
                )
            else:
                cur.execute(
                    """
                    SELECT rulepack_version, checksum_sha256, artifact_path, model_version, run_id::text
                    FROM phase4.rulepack_registry
                    WHERE scope = %(scope)s AND status = 'published'
                    ORDER BY created_at_utc DESC
                    LIMIT 1;
                    """,
                    {"scope": scope},
                )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "rulepack_version": row[0],
                "checksum_sha256": row[1],
                "artifact_path": row[2],
                "model_version": row[3],
                "run_id": row[4],
            }


def list_child_templates() -> dict[str, Any]:
    _ensure_templates()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT template_id, child_type, assigned_scope, description, defaults_json, created_at_utc, updated_at_utc
                FROM phase4.child_stack_templates
                ORDER BY template_id;
                """
            )
            rows = []
            for r in cur.fetchall():
                rows.append(
                    {
                        "template_id": r[0],
                        "child_type": r[1],
                        "assigned_scope": r[2],
                        "description": r[3],
                        "defaults": r[4] or {},
                        "created_at": r[5].isoformat() if r[5] else None,
                        "updated_at": r[6].isoformat() if r[6] else None,
                    }
                )
    return {"ok": True, "templates": rows}


def _ensure_default_child_stacks() -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            # Serialize bootstrap writes to avoid deadlocks when status polling and replay APIs race.
            cur.execute(f"SET LOCAL lock_timeout = '{int(STEP3_PREPARE_LOCK_TIMEOUT_MS)}ms';")
            try:
                cur.execute("SELECT pg_advisory_xact_lock(hashtext('phase4_step3_default_child_stacks'));")
            except Exception as exc:
                raise RuntimeError(
                    f"default_child_stack_lock_timeout:{int(STEP3_PREPARE_LOCK_TIMEOUT_MS)}ms:{exc}"
                ) from exc
            for c in DEFAULT_CHILD_STACKS:
                cid = c["child_id"]
                client_net = _client_network_id(cid)
                mgmt_net = _management_network_id(cid)
                db_net = _child_db_network_id(cid)
                cl_port = _client_listener_port(cid)
                mg_port = _management_port(cid)
                region = str(c.get("assigned_scope") or c.get("child_type") or "global")
                cur.execute(
                    """
                    INSERT INTO phase4.child_stacks (
                        child_id, child_type, assigned_scope, network_id, listener_endpoint, packet_endpoint,
                        client_listener_port, management_port, client_network_id, management_network_id, region,
                        model_version, status, health_status, parent_connection_status, replay_status,
                        created_at_utc, updated_at_utc
                    )
                    VALUES (
                        %(child_id)s, %(child_type)s, %(assigned_scope)s, %(network_id)s, %(listener)s, %(packet)s,
                        %(client_listener_port)s, %(management_port)s, %(client_network_id)s, %(management_network_id)s, %(region)s,
                        'v1', 'created', 'unknown', 'disconnected', 'idle', now(), now()
                    )
                    ON CONFLICT (child_id) DO UPDATE SET
                        client_listener_port = COALESCE(EXCLUDED.client_listener_port, phase4.child_stacks.client_listener_port),
                        management_port = COALESCE(EXCLUDED.management_port, phase4.child_stacks.management_port),
                        client_network_id = COALESCE(EXCLUDED.client_network_id, phase4.child_stacks.client_network_id),
                        management_network_id = COALESCE(EXCLUDED.management_network_id, phase4.child_stacks.management_network_id),
                        region = COALESCE(EXCLUDED.region, phase4.child_stacks.region),
                        listener_endpoint = EXCLUDED.listener_endpoint,
                        packet_endpoint = EXCLUDED.packet_endpoint,
                        network_id = EXCLUDED.network_id,
                        updated_at_utc = now();
                    """,
                    {
                        "child_id": cid,
                        "child_type": c["child_type"],
                        "assigned_scope": c["assigned_scope"],
                        "network_id": client_net,
                        "listener": _listener_endpoint(cid),
                        "packet": _packet_endpoint(cid),
                        "client_listener_port": cl_port,
                        "management_port": mg_port,
                        "client_network_id": client_net,
                        "management_network_id": mgmt_net,
                        "region": region,
                    },
                )
                for net_id, role in ((client_net, "client_listener"), (mgmt_net, "management"), (db_net, "postgres_data")):
                    cur.execute(
                        """
                        INSERT INTO phase4.replay_networks (
                            network_id, workflow_id, child_id, child_type, status, docker_network_name, isolated, metadata, created_at_utc, updated_at_utc
                        )
                        VALUES (%(network_id)s, 'model_v1_step3_replay_simulation', %(child_id)s, %(child_type)s, 'created', %(docker)s, true, %(metadata)s::jsonb, now(), now())
                        ON CONFLICT (network_id) DO UPDATE SET metadata = EXCLUDED.metadata, updated_at_utc = now();
                        """,
                        {
                            "network_id": net_id,
                            "child_id": cid,
                            "child_type": c["child_type"],
                            "docker": net_id,
                            "metadata": json.dumps({"network_role": role, "isolation": "regional_per_child", "db_isolation": role == "postgres_data"}),
                        },
                    )
                    cur.execute(
                        """
                        INSERT INTO phase4.step3_child_networks (
                            child_id, network_role, network_id, docker_network_name, isolated, metadata, created_at_utc, updated_at_utc
                        )
                        VALUES (%(child_id)s, %(role)s, %(network_id)s, %(docker)s, true, %(metadata)s::jsonb, now(), now())
                        ON CONFLICT (child_id, network_role) DO UPDATE SET
                            network_id = EXCLUDED.network_id,
                            docker_network_name = EXCLUDED.docker_network_name,
                            metadata = EXCLUDED.metadata,
                            updated_at_utc = now();
                        """,
                        {
                            "child_id": cid,
                            "role": role,
                            "network_id": net_id,
                            "docker": net_id,
                            "metadata": json.dumps({"stack": "db" if role == "postgres_data" else ("child" if role == "management" else "client")}),
                        },
                    )
                for port_role, port in (("client_listener", cl_port), ("management", mg_port)):
                    cur.execute(
                        """
                        INSERT INTO phase4.step3_child_ports (child_id, port_role, port, metadata, created_at_utc)
                        VALUES (%(child_id)s, %(port_role)s, %(port)s, %(metadata)s::jsonb, now())
                        ON CONFLICT (child_id, port_role) DO UPDATE SET port = EXCLUDED.port, metadata = EXCLUDED.metadata;
                        """,
                        {
                            "child_id": cid,
                            "port_role": port_role,
                            "port": port,
                            "metadata": json.dumps({"simulation_plane": port_role == "client_listener"}),
                        },
                    )
        conn.commit()
    _ensure_docker_network(SIMULATION_NETWORK_ID)


def create_child_stack(payload: dict[str, Any]) -> dict[str, Any]:
    child_id = str(payload.get("child_id") or "").strip()
    template_id = str(payload.get("template_id") or "").strip().lower()
    assigned_scope = str(payload.get("assigned_scope") or "").strip().lower()
    if not child_id:
        return {"ok": False, "error": "child_id_required"}
    tpl = next((x for x in DEFAULT_CHILD_TEMPLATES if x["template_id"] == template_id), None)
    if not tpl:
        return {"ok": False, "error": "invalid_template_id"}
    child_type = tpl["child_type"]
    scope = assigned_scope or tpl["assigned_scope"]
    client_net = str(payload.get("client_network_id") or _client_network_id(child_id))
    mgmt_net = str(payload.get("management_network_id") or _management_network_id(child_id))
    db_net = str(payload.get("db_network_id") or _child_db_network_id(child_id))
    cl_port, mg_port = _ports_for_child_id(child_id)
    cl_port = int(payload.get("client_listener_port") or cl_port)
    mg_port = int(payload.get("management_port") or mg_port)
    region = str(payload.get("region") or scope)
    listener = str(payload.get("listener_endpoint") or _listener_endpoint(child_id))
    packet = str(payload.get("packet_endpoint") or _packet_endpoint(child_id))
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.child_stacks (
                    child_id, workflow_id, child_type, assigned_scope, network_id, listener_endpoint, packet_endpoint,
                    client_listener_port, management_port, client_network_id, management_network_id, region,
                    model_version, status, health_status, parent_connection_status, replay_status, metadata, created_at_utc, updated_at_utc
                )
                VALUES (
                    %(child_id)s, 'model_v1_step3_replay_simulation', %(child_type)s, %(assigned_scope)s, %(network_id)s, %(listener)s, %(packet)s,
                    %(client_listener_port)s, %(management_port)s, %(client_network_id)s, %(management_network_id)s, %(region)s,
                    'v1', 'created', 'unknown', 'disconnected', 'idle', %(metadata)s::jsonb, now(), now()
                )
                ON CONFLICT (child_id) DO UPDATE
                SET child_type = EXCLUDED.child_type,
                    assigned_scope = EXCLUDED.assigned_scope,
                    network_id = EXCLUDED.network_id,
                    listener_endpoint = EXCLUDED.listener_endpoint,
                    packet_endpoint = EXCLUDED.packet_endpoint,
                    client_listener_port = COALESCE(EXCLUDED.client_listener_port, phase4.child_stacks.client_listener_port),
                    management_port = COALESCE(EXCLUDED.management_port, phase4.child_stacks.management_port),
                    client_network_id = COALESCE(EXCLUDED.client_network_id, phase4.child_stacks.client_network_id),
                    management_network_id = COALESCE(EXCLUDED.management_network_id, phase4.child_stacks.management_network_id),
                    region = COALESCE(EXCLUDED.region, phase4.child_stacks.region),
                    metadata = COALESCE(phase4.child_stacks.metadata, '{}'::jsonb) || EXCLUDED.metadata,
                    updated_at_utc = now();
                """,
                {
                    "child_id": child_id,
                    "child_type": child_type,
                    "assigned_scope": scope,
                    "network_id": client_net,
                    "listener": listener,
                    "packet": packet,
                    "client_listener_port": cl_port,
                    "management_port": mg_port,
                    "client_network_id": client_net,
                    "management_network_id": mgmt_net,
                    "region": region,
                    "metadata": json.dumps({"template_id": template_id}),
                },
            )
            for net_id, role in ((client_net, "client_listener"), (mgmt_net, "management"), (db_net, "postgres_data")):
                cur.execute(
                    """
                    INSERT INTO phase4.replay_networks (
                        network_id, workflow_id, child_id, child_type, status, docker_network_name, isolated, metadata, created_at_utc, updated_at_utc
                    )
                    VALUES (%(network_id)s, 'model_v1_step3_replay_simulation', %(child_id)s, %(child_type)s, 'created', %(docker)s, true, %(metadata)s::jsonb, now(), now())
                    ON CONFLICT (network_id) DO UPDATE SET metadata = EXCLUDED.metadata, updated_at_utc = now();
                    """,
                    {
                        "network_id": net_id,
                        "child_id": child_id,
                        "child_type": child_type,
                        "docker": net_id,
                        "metadata": json.dumps({"network_role": role, "db_isolation": role == "postgres_data"}),
                    },
                )
                cur.execute(
                    """
                    INSERT INTO phase4.step3_child_networks (
                        child_id, network_role, network_id, docker_network_name, isolated, metadata, created_at_utc, updated_at_utc
                    )
                    VALUES (%(child_id)s, %(role)s, %(network_id)s, %(docker)s, true, %(metadata)s::jsonb, now(), now())
                    ON CONFLICT (child_id, network_role) DO UPDATE SET
                        network_id = EXCLUDED.network_id,
                        docker_network_name = EXCLUDED.docker_network_name,
                        metadata = EXCLUDED.metadata,
                        updated_at_utc = now();
                    """,
                    {
                        "child_id": child_id,
                        "role": role,
                        "network_id": net_id,
                        "docker": net_id,
                        "metadata": json.dumps({"stack": "db" if role == "postgres_data" else ("child" if role == "management" else "client")}),
                    },
                )
        conn.commit()
    return {"ok": True, "child_id": child_id}


def _row_to_child(r: tuple[Any, ...]) -> dict[str, Any]:
    base = {
        "child_id": r[0],
        "child_type": r[1],
        "assigned_scope": r[2],
        "network_id": r[3],
        "listener_endpoint": r[4],
        "packet_endpoint": r[5],
        "rulepack_version": r[6],
        "status": r[7],
        "health_status": r[8],
        "last_heartbeat": r[9].isoformat() if r[9] else None,
        "last_rule_sync": r[10].isoformat() if r[10] else None,
        "parent_connection_status": r[11],
        "replay_status": r[12],
        "captured_event_count": int(r[13] or 0),
        "escalated_event_count": int(r[14] or 0),
        "started_at": r[15].isoformat() if r[15] else None,
        "finished_at": r[16].isoformat() if r[16] else None,
        "error_message": r[17],
        "metadata": r[18] or {},
        "created_at": r[19].isoformat() if r[19] else None,
        "updated_at": r[20].isoformat() if r[20] else None,
    }
    if len(r) > 21:
        base.update(
            {
                "client_listener_port": r[21],
                "management_port": r[22],
                "client_network_id": r[23],
                "management_network_id": r[24],
                "region": r[25],
                "replay_receive_count": int(r[26] or 0),
                "alert_count": int(r[27] or 0),
                "escalation_count": int(r[28] or 0),
                "rule_ready_status": r[29] or "no_rulepack",
            }
        )
        rs = runtime_stats(str(r[0]))
        if rs:
            base["listener_runtime_received"] = rs.received_packets
            base["listener_runtime_rule_matches"] = rs.rule_match_count
            base["mtls_enabled"] = bool(rs.mtls_enabled)
            base["mtls_ready"] = bool(rs.mtls_ready)
            base["mtls_error"] = rs.mtls_error
            base["rule_sync_status"] = rs.rule_sync_status
            base["active_rule_count"] = int(rs.active_rule_count)
    else:
        base.setdefault("client_listener_port", _client_listener_port(str(r[0])))
        base.setdefault("management_port", _management_port(str(r[0])))
        base.setdefault("client_network_id", _client_network_id(str(r[0])))
        base.setdefault("management_network_id", _management_network_id(str(r[0])))
        base.setdefault("region", str(r[2] or ""))
        base.setdefault("replay_receive_count", 0)
        base.setdefault("alert_count", 0)
        base.setdefault("escalation_count", 0)
        base.setdefault("rule_ready_status", "no_rulepack")
    return base


def list_child_stacks() -> dict[str, Any]:
    # Read-only listing path: avoid write-side upserts here to reduce deadlock risk under polling.
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT child_id, child_type, assigned_scope, network_id, listener_endpoint, packet_endpoint,
                       rulepack_version, status, health_status, last_heartbeat_utc, last_rule_sync_utc,
                       parent_connection_status, replay_status, captured_event_count, escalated_event_count,
                       started_at_utc, finished_at_utc, error_message, metadata, created_at_utc, updated_at_utc,
                       client_listener_port, management_port, client_network_id, management_network_id, region,
                       replay_receive_count, alert_count, escalation_count, rule_ready_status
                FROM phase4.child_stacks
                ORDER BY child_id;
                """
            )
            rows = [_row_to_child(r) for r in cur.fetchall()]
    return {"ok": True, "children": rows, "minimum_required": 10}


def get_child_stack(child_id: str) -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT child_id, child_type, assigned_scope, network_id, listener_endpoint, packet_endpoint,
                       rulepack_version, status, health_status, last_heartbeat_utc, last_rule_sync_utc,
                       parent_connection_status, replay_status, captured_event_count, escalated_event_count,
                       started_at_utc, finished_at_utc, error_message, metadata, created_at_utc, updated_at_utc,
                       client_listener_port, management_port, client_network_id, management_network_id, region,
                       replay_receive_count, alert_count, escalation_count, rule_ready_status
                FROM phase4.child_stacks
                WHERE child_id = %(child_id)s;
                """,
                {"child_id": child_id},
            )
            r = cur.fetchone()
            if not r:
                return {"ok": False, "error": "child_not_found"}
            return {"ok": True, "child": _row_to_child(r)}


def _ensure_docker_network(name: str, *, internal: bool = True) -> tuple[bool, str | None]:
    try:
        ok_inspect, _out, _err = _run_docker(["docker", "network", "inspect", name])
        if ok_inspect:
            return True, None
        cmd = ["docker", "network", "create", "--driver", "bridge"]
        if internal:
            cmd.append("--internal")
        cmd.append(name)
        ok_create, _out, err_create = _run_docker(cmd)
        if ok_create:
            return True, None
        return False, err_create or "docker_network_create_failed"
    except Exception as exc:
        return False, str(exc)


def _remove_container_if_exists(container_name: str) -> tuple[bool, str | None]:
    ok, _out, err = _run_docker(["docker", "rm", "-f", container_name])
    if ok:
        return True, None
    low = (err or "").lower()
    if "no such container" in low:
        return True, None
    return False, err or "docker_rm_failed"


def _ensure_stack_network_memberships(child_id: str, *, client_net: str, mgmt_net: str, db_net: str) -> tuple[bool, str | None]:
    # Each child stack has isolated client/mgmt/db networks.
    for net in (client_net, mgmt_net, db_net):
        ok, err = _ensure_docker_network(net, internal=True)
        if not ok:
            return False, f"network_setup_failed:{net}:{err}"
    # Simulation factory reaches child listeners on client nets only.
    ok, err = _ensure_docker_network(SIMULATION_NETWORK_ID, internal=True)
    if not ok:
        return False, f"network_setup_failed:{SIMULATION_NETWORK_ID}:{err}"
    # Parent controls child only on management net.
    parent = _parent_container_name()
    if parent and _docker_container_exists(parent):
        ok, err = _docker_network_connect(mgmt_net, parent)
        if not ok:
            return False, f"parent_network_connect_failed:{mgmt_net}:{err}"
    dash_api = _dash_api_container_name()
    if dash_api and _docker_container_exists(dash_api):
        ok, err = _docker_network_connect(mgmt_net, dash_api)
        if not ok:
            return False, f"dash_api_network_connect_failed:{mgmt_net}:{err}"
    # Postgres isolated per stack on dedicated DB net.
    postgres = _postgres_container_name()
    if postgres and _docker_container_exists(postgres):
        ok, err = _docker_network_connect(db_net, postgres)
        if not ok:
            return False, f"postgres_network_connect_failed:{db_net}:{err}"
    return True, None


def _launch_child_container(
    *,
    child_id: str,
    child_type: str,
    assigned_scope: str,
    client_listener_port: int,
    management_port: int,
    client_net: str,
    mgmt_net: str,
    db_net: str,
    execution_mode: str,
) -> tuple[bool, str | None]:
    container_name = _child_container_name(child_id)
    ok, err = _remove_container_if_exists(container_name)
    if not ok:
        return False, err
    rules_file = _child_rules_file(child_id)
    host_data = _step3_host_data_root()
    cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        container_name,
        "--network",
        client_net,
        "--network-alias",
        child_id,
        "--restart",
        "unless-stopped",
        "-p",
        f"{client_listener_port}:{client_listener_port}/udp",
        "-p",
        f"{management_port}:{management_port}",
        "-v",
        f"{host_data}:/data",
        "-e",
        f"PHASE4_POSTGRES_HOST={_postgres_container_name()}",
        "-e",
        f"PHASE4_POSTGRES_DB={os.getenv('PHASE4_POSTGRES_DB', 'ids_phase4')}",
        "-e",
        f"PHASE4_POSTGRES_USER={os.getenv('PHASE4_POSTGRES_USER', 'ids_phase4')}",
        "-e",
        f"PHASE4_POSTGRES_PASSWORD={os.getenv('PHASE4_POSTGRES_PASSWORD', 'ids_phase4_local_change_me')}",
        _step3_docker_image(),
        "python",
        "/workspace/services_child/step3_child_node.py",
        "--child-id",
        child_id,
        "--child-type",
        child_type,
        "--assigned-scope",
        assigned_scope,
        "--udp-port",
        str(client_listener_port),
        "--mgmt-port",
        str(management_port),
        "--rules-file",
        rules_file,
        "--execution-mode",
        execution_mode,
    ]
    ok, _out, err = _run_docker(cmd, timeout_s=STEP3_DOCKER_START_TIMEOUT_S)
    if not ok:
        return False, err or "docker_child_launch_failed"
    for net in (mgmt_net, db_net):
        ok, err = _docker_network_connect(net, container_name)
        if not ok:
            return False, f"child_network_connect_failed:{net}:{err}"
    running, state = _docker_container_running(container_name)
    if not running:
        return False, f"child_container_not_running:{state}"
    return True, None


def _child_stack_lifecycle_docker(child_id: str, action: str, child: dict[str, Any]) -> dict[str, Any]:
    client_net = str(child.get("client_network_id") or _client_network_id(child_id))
    mgmt_net = str(child.get("management_network_id") or _management_network_id(child_id))
    db_net = _child_db_network_id(child_id)
    cl_port = int(child.get("client_listener_port") or _client_listener_port(child_id))
    mg_port = int(child.get("management_port") or _management_port(child_id))
    child_type = str(child.get("child_type") or "enterprise")
    assigned_scope = str(child.get("assigned_scope") or child_type)
    container_name = _child_container_name(child_id)
    exec_mode = _execution_mode()
    rule_sync: dict[str, Any] = {"ok": True, "rulepack_version": child.get("rulepack_version"), "rules": []}

    if action in {"start", "restart"}:
        ok, err = _ensure_stack_network_memberships(
            child_id,
            client_net=client_net,
            mgmt_net=mgmt_net,
            db_net=db_net,
        )
        if not ok:
            return {"ok": False, "error": err}
        rule_sync = _load_published_rules_for_child(
            child_id=child_id,
            child_type=child_type,
            assigned_scope=assigned_scope,
            model_version=str(child.get("model_version") or "") or None,
        )
        if not rule_sync.get("ok"):
            return {"ok": False, "error": f"rule_sync_failed:{rule_sync.get('error')}"}
        ok, err = _launch_child_container(
            child_id=child_id,
            child_type=child_type,
            assigned_scope=assigned_scope,
            client_listener_port=cl_port,
            management_port=mg_port,
            client_net=client_net,
            mgmt_net=mgmt_net,
            db_net=db_net,
            execution_mode=exec_mode,
        )
        if not ok:
            return {"ok": False, "error": err or "docker_launch_failed"}
        register_remote_runtime(child_id, mg_port, host=container_name)
        sync_ok = runtime_set_rules(
            child_id,
            list(rule_sync.get("rules") or []),
            rulepack_version=str(rule_sync.get("rulepack_version") or ""),
        )
        if not sync_ok:
            return {"ok": False, "error": f"runtime_rule_sync_failed:{child_id}"}
    elif action == "stop":
        _run_docker(["docker", "stop", container_name])
        unregister_remote_runtime(child_id)
    else:
        return {"ok": False, "error": "unsupported_action"}

    with connect() as conn:
        with conn.cursor() as cur:
            if action in {"start", "restart"}:
                cur.execute(
                    """
                    UPDATE phase4.child_stacks
                    SET status='running', health_status='healthy', parent_connection_status='connected',
                        replay_status='idle',
                        rulepack_version = %(rulepack_version)s, rule_ready_status='ready',
                        started_at_utc=COALESCE(started_at_utc, now()),
                        last_heartbeat_utc=now(), updated_at_utc=now(), error_message=NULL,
                        metadata = COALESCE(metadata, '{}'::jsonb) || %(meta)s::jsonb
                    WHERE child_id = %(child_id)s;
                    """,
                    {
                        "child_id": child_id,
                        "rulepack_version": rule_sync.get("rulepack_version"),
                        "meta": json.dumps(
                            {
                                "orchestration": "docker",
                                "container_name": container_name,
                                "db_network_id": db_net,
                                "execution_mode": exec_mode,
                            }
                        ),
                    },
                )
            else:
                cur.execute(
                    """
                    UPDATE phase4.child_stacks
                    SET status='stopped', replay_status='idle', health_status='stopped',
                        finished_at_utc=now(), updated_at_utc=now(),
                        metadata = COALESCE(metadata, '{}'::jsonb) || %(meta)s::jsonb
                    WHERE child_id = %(child_id)s;
                    """,
                    {
                        "child_id": child_id,
                        "meta": json.dumps({"orchestration": "docker", "container_name": container_name}),
                    },
                )
            cur.execute(
                """
                INSERT INTO phase4.child_stack_health (
                    health_id, child_id, workflow_id, child_type, network_id, status, checks_json, heartbeat_at_utc, created_at_utc, updated_at_utc
                )
                VALUES (
                    %(id)s::uuid, %(child_id)s, 'model_v1_step3_replay_simulation', %(child_type)s, %(network_id)s, %(status)s,
                    %(checks)s::jsonb, now(), now(), now()
                );
                """,
                {
                    "id": str(uuid.uuid4()),
                    "child_id": child_id,
                    "child_type": child_type,
                    "network_id": client_net,
                    "status": "healthy" if action in {"start", "restart"} else "stopped",
                    "checks": json.dumps(
                        {
                            "action": action,
                            "orchestration": "docker",
                            "container_name": container_name,
                            "client_network": client_net,
                            "management_network": mgmt_net,
                            "postgres_network": db_net,
                            "client_listener_port": cl_port,
                            "management_port": mg_port,
                            "rulepack_version": rule_sync.get("rulepack_version"),
                            "rule_count": len(rule_sync.get("rules") or []),
                        }
                    ),
                },
            )
        conn.commit()
    return {"ok": True, "child_id": child_id, "action": action, "orchestration": "docker"}


def child_stack_lifecycle(child_id: str, action: str) -> dict[str, Any]:
    child = get_child_stack(child_id)
    if not child.get("ok"):
        return child
    c = child["child"]
    if _step3_docker_enabled():
        return _child_stack_lifecycle_docker(child_id, action, c)
    client_net = str(c.get("client_network_id") or _client_network_id(child_id))
    mgmt_net = str(c.get("management_network_id") or _management_network_id(child_id))
    cl_port = int(c.get("client_listener_port") or _client_listener_port(child_id))
    mg_port = int(c.get("management_port") or _management_port(child_id))
    network_id = str(c.get("network_id") or client_net)
    if action in {"start", "restart"}:
        rule_sync = _load_published_rules_for_child(
            child_id=child_id,
            child_type=str(c.get("child_type") or "enterprise"),
            assigned_scope=str(c.get("assigned_scope") or ""),
            model_version=str(c.get("model_version") or "") or None,
        )
        if not rule_sync.get("ok"):
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE phase4.child_stacks
                        SET rule_ready_status='failed', updated_at_utc=now(), error_message=%(err)s
                        WHERE child_id = %(child_id)s;
                        """,
                        {"child_id": child_id, "err": str(rule_sync.get("error") or "rule_sync_failed")},
                    )
                conn.commit()
            write_audit_event(
                event_type="step3_rule_sync_failed",
                actor="model-v1-step3-child-lifecycle",
                artifact_refs=[],
                context={"child_id": child_id, "error": rule_sync.get("error")},
                dataset_id="REP-01",
                model_version=str(c.get("model_version") or "v1"),
            )
            return {"ok": False, "error": f"rule_sync_failed:{rule_sync.get('error')}"}
        mtls = _mtls_paths_for_child(child_id)
        if mtls.get("enabled") and not (mtls.get("cert_exists") and mtls.get("key_exists") and mtls.get("ca_exists")):
            write_audit_event(
                event_type="step3_mtls_material_missing",
                actor="model-v1-step3-child-lifecycle",
                artifact_refs=[],
                context={"child_id": child_id, "mtls": mtls},
                dataset_id="REP-01",
                model_version=str(c.get("model_version") or "v1"),
            )
            return {
                "ok": False,
                "error": "mtls_material_missing",
                "details": mtls,
            }
        for net in (client_net, mgmt_net, SIMULATION_NETWORK_ID):
            ok_net, err = _ensure_docker_network(net)
            if not ok_net:
                return {"ok": False, "error": f"network_setup_failed:{net}:{err}"}
        rt = start_child_runtime(
            child_id,
            child_type=str(c.get("child_type") or "enterprise"),
            client_listener_port=cl_port,
            management_port=mg_port,
            execution_mode=_execution_mode(),
            tls_certfile=str(mtls.get("cert_path")) if mtls.get("enabled") else None,
            tls_keyfile=str(mtls.get("key_path")) if mtls.get("enabled") else None,
            tls_ca_file=str(mtls.get("ca_path")) if mtls.get("enabled") else None,
            tls_require_client_cert=bool(mtls.get("require_client_cert")),
        )
        if not rt.get("ok"):
            return {"ok": False, "error": f"child_runtime_failed:{rt.get('error')}"}
        sync_ok = runtime_set_rules(
            child_id,
            list(rule_sync.get("rules") or []),
            rulepack_version=str(rule_sync.get("rulepack_version") or ""),
        )
        if not sync_ok:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE phase4.child_stacks
                        SET rule_ready_status='failed', updated_at_utc=now(), error_message=%(err)s
                        WHERE child_id = %(child_id)s;
                        """,
                        {"child_id": child_id, "err": "runtime_rule_sync_failed"},
                    )
                conn.commit()
            return {"ok": False, "error": f"runtime_rule_sync_failed:{child_id}"}
        write_audit_event(
            event_type="step3_rule_sync_completed",
            actor="model-v1-step3-child-lifecycle",
            artifact_refs=[],
            context={
                "child_id": child_id,
                "rulepack_version": rule_sync.get("rulepack_version"),
                "rule_count": len(rule_sync.get("rules") or []),
                "mtls_enabled": bool(mtls.get("enabled")),
            },
            dataset_id="REP-01",
            model_version=str(c.get("model_version") or "v1"),
        )
    if action == "stop":
        stop_child_runtime(child_id)
    with connect() as conn:
        with conn.cursor() as cur:
            if action == "start":
                cur.execute(
                    """
                    UPDATE phase4.child_stacks
                    SET status='running', health_status='healthy', parent_connection_status='connected',
                        rulepack_version = %(rulepack_version)s, rule_ready_status='ready',
                        started_at_utc=COALESCE(started_at_utc, now()), last_heartbeat_utc=now(), updated_at_utc=now(), error_message=NULL
                    WHERE child_id = %(child_id)s;
                    """,
                    {"child_id": child_id, "rulepack_version": rule_sync.get("rulepack_version")},
                )
            elif action == "stop":
                cur.execute(
                    """
                    UPDATE phase4.child_stacks
                    SET status='stopped', replay_status='idle', finished_at_utc=now(), updated_at_utc=now()
                    WHERE child_id = %(child_id)s;
                    """,
                    {"child_id": child_id},
                )
            elif action == "restart":
                cur.execute(
                    """
                    UPDATE phase4.child_stacks
                    SET status='running', health_status='healthy', parent_connection_status='connected',
                        rulepack_version = %(rulepack_version)s, rule_ready_status='ready',
                        last_heartbeat_utc=now(), updated_at_utc=now(), error_message=NULL
                    WHERE child_id = %(child_id)s;
                    """,
                    {"child_id": child_id, "rulepack_version": rule_sync.get("rulepack_version")},
                )
            cur.execute(
                """
                INSERT INTO phase4.child_stack_health (
                    health_id, child_id, workflow_id, child_type, network_id, status, checks_json, heartbeat_at_utc, created_at_utc, updated_at_utc
                )
                VALUES (
                    %(id)s::uuid, %(child_id)s, 'model_v1_step3_replay_simulation', %(child_type)s, %(network_id)s, %(status)s,
                    %(checks)s::jsonb, now(), now(), now()
                );
                """,
                {
                    "id": str(uuid.uuid4()),
                    "child_id": child_id,
                    "child_type": c["child_type"],
                    "network_id": network_id,
                    "status": "healthy" if action != "stop" else "stopped",
                    "checks": json.dumps(
                        {
                            "action": action,
                            "client_network": client_net,
                            "management_network": mgmt_net,
                            "simulation_network": SIMULATION_NETWORK_ID,
                            "client_listener_port": cl_port,
                            "management_port": mg_port,
                            "rulepack_version": rule_sync.get("rulepack_version") if action in {"start", "restart"} else None,
                            "rule_count": len(rule_sync.get("rules") or []) if action in {"start", "restart"} else 0,
                            "mtls": mtls if action in {"start", "restart"} else {},
                        }
                    ),
                },
            )
        conn.commit()
    return {"ok": True, "child_id": child_id, "action": action}


def child_health(child_id: str) -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT health_id::text, status, checks_json, heartbeat_at_utc, error_message, created_at_utc
                FROM phase4.child_stack_health
                WHERE child_id = %(child_id)s
                ORDER BY created_at_utc DESC
                LIMIT 1;
                """,
                {"child_id": child_id},
            )
            row = cur.fetchone()
            if not row:
                return {"ok": False, "error": "health_not_found"}
            return {
                "ok": True,
                "health": {
                    "health_id": row[0],
                    "status": row[1],
                    "checks": row[2] or {},
                    "heartbeat_at": row[3].isoformat() if row[3] else None,
                    "error_message": row[4],
                    "created_at": row[5].isoformat() if row[5] else None,
                },
            }


def remove_child_stack(child_id: str) -> dict[str, Any]:
    child = get_child_stack(child_id)
    if not child.get("ok"):
        return child
    container_name = _child_container_name(child_id)
    _run_docker(["docker", "stop", container_name])
    _remove_container_if_exists(container_name)
    unregister_remote_runtime(child_id)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM phase4.child_stacks WHERE child_id = %(child_id)s;", {"child_id": child_id})
            cur.execute(
                "DELETE FROM phase4.replay_networks WHERE child_id = %(child_id)s;",
                {"child_id": child_id},
            )
            cur.execute(
                "DELETE FROM phase4.step3_child_networks WHERE child_id = %(child_id)s;",
                {"child_id": child_id},
            )
            cur.execute(
                "DELETE FROM phase4.step3_child_ports WHERE child_id = %(child_id)s;",
                {"child_id": child_id},
            )
        conn.commit()
    return {"ok": True, "child_id": child_id, "action": "remove", "orchestration": "docker"}


def deploy_rules(payload: dict[str, Any]) -> dict[str, Any]:
    _ensure_default_child_stacks()
    _ensure_templates()
    children = list_child_stacks().get("children", [])
    target_ids = payload.get("child_ids") or [c["child_id"] for c in children]
    explicit_replay_id = _preparation_replay_id(payload) or _uuid_or_none(payload.get("replay_id"))
    results: list[dict[str, Any]] = []
    with connect() as conn:
        with conn.cursor() as cur:
            for cid in target_ids:
                child = next((c for c in children if c["child_id"] == cid), None)
                if not child:
                    results.append({"child_id": cid, "ok": False, "status": "failed", "error": "child_not_found"})
                    continue
                scope = str(child.get("assigned_scope") or child.get("child_type") or "global")
                child_model_version = str(child.get("model_version") or "").strip() or None
                rp = _latest_rulepack_for_scope(scope, model_version=child_model_version) or _latest_rulepack_for_scope(
                    "global",
                    model_version=child_model_version,
                )
                if not rp:
                    cur.execute(
                        """
                        INSERT INTO phase4.child_rule_deployments (
                            deployment_id, child_id, child_type, model_version, status, validation_result, created_at_utc, updated_at_utc
                        ) VALUES (%(id)s::uuid, %(child_id)s, %(child_type)s, 'v1', 'no_rulepack', 'missing', now(), now());
                        """,
                        {"id": str(uuid.uuid4()), "child_id": cid, "child_type": child["child_type"]},
                    )
                    cur.execute(
                        """
                        UPDATE phase4.child_stacks
                        SET rule_ready_status = 'failed', updated_at_utc = now()
                        WHERE child_id = %(child_id)s;
                        """,
                        {"child_id": cid},
                    )
                    results.append({"child_id": cid, "ok": False, "status": "no_rulepack"})
                    continue
                rule_sync = _load_published_rules_for_child(
                    child_id=cid,
                    child_type=str(child.get("child_type") or "enterprise"),
                    assigned_scope=str(child.get("assigned_scope") or ""),
                    model_version=child_model_version,
                )
                rules_payload = list(rule_sync.get("rules") or [])
                if not rules_payload:
                    results.append({"child_id": cid, "ok": False, "status": "failed", "error": "rules_empty"})
                    continue
                rf = Path(_child_rules_file(cid))
                rf.parent.mkdir(parents=True, exist_ok=True)
                rf.write_text(
                    json.dumps(
                        {
                            "child_id": cid,
                            "rulepack_version": rp.get("rulepack_version"),
                            "rules": rules_payload,
                            "updated_at_utc": _now(),
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                sync_ok = runtime_set_rules(
                    cid,
                    rules_payload,
                    rulepack_version=str(rp.get("rulepack_version") or ""),
                )
                runtime_sync_status = "ok" if sync_ok else "failed"
                checksum = str(rp.get("checksum_sha256") or "")
                val = "ok" if checksum else "missing_checksum"
                if runtime_sync_status != "ok":
                    val = "runtime_sync_failed"
                status = "ready" if val == "ok" else "failed"
                cur.execute(
                    """
                    INSERT INTO phase4.child_rule_deployments (
                        deployment_id, workflow_id, child_id, child_type, model_version, rulepack_version,
                        checksum_sha256, validation_result, status, deployed_at_utc, last_sync_utc, metadata, created_at_utc, updated_at_utc
                    ) VALUES (
                        %(id)s::uuid, 'model_v1_step3_replay_simulation', %(child_id)s, %(child_type)s, %(model_version)s, %(rulepack_version)s,
                        %(checksum)s, %(validation)s, %(status)s, now(), now(), %(metadata)s::jsonb, now(), now()
                    );
                    """,
                    {
                        "id": str(uuid.uuid4()),
                        "child_id": cid,
                        "child_type": child["child_type"],
                        "model_version": rp.get("model_version") or "v1",
                        "rulepack_version": rp.get("rulepack_version"),
                        "checksum": checksum,
                        "validation": val,
                        "status": status,
                        "metadata": json.dumps(
                            {
                                "artifact_path": rp.get("artifact_path"),
                                "source_step2_run_id": rp.get("run_id"),
                                "runtime_sync_status": runtime_sync_status,
                            }
                        ),
                    },
                )
                cur.execute(
                    """
                    INSERT INTO phase4.step3_stack_rules (
                        stack_rule_id, replay_id, child_id, model_id, model_version, rulepack_version, rule_count, status, payload, created_at_utc
                    ) VALUES (
                        %(id)s::uuid, CASE WHEN %(replay_id)s = '' THEN NULL ELSE %(replay_id)s::uuid END, %(child_id)s, CASE WHEN %(model_id)s = '' THEN NULL ELSE %(model_id)s::uuid END, %(model_version)s,
                        %(rulepack_version)s, %(rule_count)s, %(status)s, %(payload)s::jsonb, now()
                    );
                    """,
                    {
                        "id": str(uuid.uuid4()),
                        "replay_id": explicit_replay_id or _latest_preparation_replay_id(str(rp.get("model_version") or child_model_version or "")) or "",
                        "child_id": cid,
                        "model_id": str(child.get("model_id") or ""),
                        "model_version": str(rp.get("model_version") or "v1"),
                        "rulepack_version": rp.get("rulepack_version"),
                        "rule_count": len(rules_payload),
                        "status": status,
                        "payload": json.dumps(
                            {
                                "assigned_scope": child.get("assigned_scope"),
                                "checksum_sha256": checksum,
                                "validation_result": val,
                                "runtime_sync_status": runtime_sync_status,
                                "replay_id": explicit_replay_id or _latest_preparation_replay_id(str(rp.get("model_version") or child_model_version or "")),
                            }
                        ),
                    },
                )
                cur.execute(
                    """
                    UPDATE phase4.child_stacks
                    SET rulepack_version = %(rulepack_version)s,
                        last_rule_sync_utc = now(),
                        rule_ready_status = %(rule_ready)s,
                        updated_at_utc = now()
                    WHERE child_id = %(child_id)s;
                    """,
                    {
                        "child_id": cid,
                        "rulepack_version": rp.get("rulepack_version"),
                        "rule_ready": "ready" if status == "ready" else "failed",
                    },
                )
                results.append(
                    {
                        "child_id": cid,
                        "ok": status == "ready",
                        "status": status,
                        "rulepack_version": rp.get("rulepack_version"),
                        "rule_count": len(rules_payload),
                        "checksum": checksum,
                        "validation_result": val,
                        "runtime_sync_status": runtime_sync_status,
                    }
                )
        conn.commit()
    return {"ok": True, "results": results}


def rules_status() -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT d.child_id, s.child_type, s.assigned_scope, d.rulepack_version, d.checksum_sha256,
                       d.status, d.validation_result, d.last_sync_utc, d.deployed_at_utc
                FROM phase4.child_rule_deployments d
                JOIN phase4.child_stacks s ON s.child_id = d.child_id
                WHERE d.created_at_utc = (
                    SELECT max(d2.created_at_utc) FROM phase4.child_rule_deployments d2 WHERE d2.child_id = d.child_id
                )
                ORDER BY d.child_id;
                """
            )
            rows = []
            for r in cur.fetchall():
                rows.append(
                    {
                        "child_id": r[0],
                        "child_type": r[1],
                        "assigned_scope": r[2],
                        "rulepack_version": r[3],
                        "checksum": r[4],
                        "status": _rule_status(r[5]),
                        "validation_result": r[6],
                        "last_sync": r[7].isoformat() if r[7] else None,
                        "last_deployed": r[8].isoformat() if r[8] else None,
                        "ready": _rule_status(r[5]) == "ready",
                    }
                )
    return {"ok": True, "rules": rows}


def _step3_readiness(model_id: str | None = None, model_version: str | None = None) -> dict[str, Any]:
    model_gate = step3_model_readiness(model_id=model_id, model_version=model_version)
    if not model_gate.get("ok"):
        return {"ok": False, "missing": model_gate.get("missing_requirements") or ["model_selection_required"]}
    if not model_gate.get("is_ready"):
        return {"ok": False, "missing": model_gate.get("missing_requirements") or ["model_not_ready"]}
    children = list_child_stacks().get("children", [])
    missing: list[str] = []
    if len(children) < 10:
        missing.append("minimum_10_child_stacks_required")
    no_port = [c["child_id"] for c in children if c.get("client_listener_port") in (None, 0) or c.get("management_port") in (None, 0)]
    if no_port:
        missing.append(f"child_ports_not_configured:{','.join(no_port)}")
    unhealthy = [c["child_id"] for c in children if c.get("health_status") not in {"healthy"}]
    if unhealthy:
        missing.append(f"unhealthy_children:{','.join(unhealthy)}")
    not_running = [c["child_id"] for c in children if str(c.get("status") or "") != "running"]
    if not_running:
        missing.append(f"child_listeners_not_running:{','.join(not_running)}")
    rs = rules_status().get("rules", [])
    not_ready = [r["child_id"] for r in rs if not r.get("ready")]
    if not_ready:
        missing.append(f"child_rules_not_ready:{','.join(not_ready)}")
    stale_rule = [c["child_id"] for c in children if str(c.get("rule_ready_status") or "") != "ready"]
    if stale_rule:
        missing.append(f"child_rule_ready_status_not_ready:{','.join(stale_rule)}")
    if not _docker_network_exists(SIMULATION_NETWORK_ID):
        missing.append("simulation_replay_net_missing")
    return {
        "ok": len(missing) == 0,
        "missing": missing,
        "model_id": model_gate.get("model_id"),
        "model_version": model_gate.get("model_version"),
        "source_step1_run_id": model_gate.get("source_step1_run_id"),
        "source_step2_workflow_id": model_gate.get("source_step2_workflow_id"),
        "active_rulepack_version": model_gate.get("active_rulepack_version"),
    }


def _db_timeline_row(
    cur: Any,
    replay_run_id: str,
    stage: str,
    child_id: str | None,
    payload: dict[str, Any],
    *,
    replay_id: str | None = None,
    simulation_session_id: str | None = None,
) -> None:
    merged = dict(payload or {})
    if simulation_session_id:
        merged["simulation_session_id"] = simulation_session_id
    cur.execute(
        """
        INSERT INTO phase4.step3_timeline_events (timeline_event_id, replay_run_id, replay_id, stage, child_id, payload, created_at_utc)
        VALUES (%(eid)s::uuid, %(rid)s::uuid, CASE WHEN %(replay_id)s = '' THEN NULL ELSE %(replay_id)s::uuid END, %(stage)s, %(cid)s, %(payload)s::jsonb, now());
        """,
        {
            "eid": str(uuid.uuid4()),
            "rid": replay_run_id,
            "replay_id": _audit_replay_id(preparation_replay_id=replay_id, replay_run_id=replay_run_id) or "",
            "stage": stage,
            "cid": child_id,
            "payload": json.dumps(merged),
        },
    )


def _db_adapter_log_row(
    cur: Any,
    replay_run_id: str | None,
    level: str,
    message: str,
    ctx: dict[str, Any],
    *,
    replay_id: str | None = None,
    simulation_session_id: str | None = None,
) -> None:
    merged = dict(ctx or {})
    if simulation_session_id:
        merged["simulation_session_id"] = simulation_session_id
    cur.execute(
        """
        INSERT INTO phase4.step3_adapter_logs (log_id, replay_run_id, replay_id, level, message, context, created_at_utc)
        VALUES (%(lid)s::uuid, %(rid)s::uuid, CASE WHEN %(replay_id)s = '' THEN NULL ELSE %(replay_id)s::uuid END, %(level)s, %(msg)s, %(ctx)s::jsonb, now());
        """,
        {
            "lid": str(uuid.uuid4()),
            "rid": replay_run_id,
            "replay_id": _audit_replay_id(preparation_replay_id=replay_id, replay_run_id=replay_run_id) or "",
            "level": level,
            "msg": message[:4000],
            "ctx": json.dumps(merged),
        },
    )


def _append_runtime_shap_log(
    *,
    model_version: str,
    replay_run_id: str,
    child_id: str,
    child_type: str,
    interaction_id: str | None,
    parent_action_id: str | None,
    payload: dict[str, Any],
    rule_version: str | None = None,
    simulation_session_id: str | None = None,
) -> int | None:
    status = str(payload.get("status") or "")
    evidence_status = _shap_evidence_status(payload)
    top_features = payload.get("metrics", {}).get("top_features") if isinstance(payload.get("metrics"), dict) else []
    details_obj = payload.get("details") if isinstance(payload.get("details"), dict) else {}
    context_obj = payload.get("context") if isinstance(payload.get("context"), dict) else {}
    try:
        return insert_shap_log(
            event_type="step3_runtime_shap",
            actor="model-v1-step3-runtime-shap",
            dataset_id="REP-01",
            experiment_id="exp_model_v1_step3_runtime_shap",
            model_version=model_version,
            rule_version=rule_version,
            replay_id=replay_run_id,
            shap_stage="runtime",
            top_features_json={
                "status": status,
                "evidence_status": evidence_status,
                "top_features": top_features if isinstance(top_features, list) else [],
            },
            shap_artifact_path=None,
            event_details_json={
                "model_id": payload.get("metrics", {}).get("model_id"),
                "model_version": model_version,
                "replay_run_id": replay_run_id,
                "simulation_session_id": simulation_session_id,
                "child_id": child_id,
                "child_type": child_type,
                "interaction_id": interaction_id,
                "parent_action_id": parent_action_id,
                "status": status,
                "evidence_status": evidence_status,
                "ok": bool(payload.get("ok")),
                "prediction": payload.get("prediction") if isinstance(payload.get("prediction"), dict) else {},
                "metrics": payload.get("metrics") if isinstance(payload.get("metrics"), dict) else {},
                "error": payload.get("error"),
                "details": details_obj,
                "context": context_obj,
                "alert_id": str(details_obj.get("alert_id") or ""),
                "rule_id": str(details_obj.get("rule_id") or ""),
                "rule_family": str(details_obj.get("rule_family") or ""),
                "packet_or_flow_id": str(details_obj.get("packet_or_flow_id") or ""),
            },
        )
    except Exception:
        # Runtime SHAP logging is best-effort for replay continuity.
        return None


def _insert_step3_alert(
    *,
    replay_run_id: str,
    replay_id: str | None = None,
    run_id: str | None,
    model_id: str,
    model_version: str,
    child_id: str,
    child_type: str,
    rulepack_version: str | None,
    rule_version: str | None,
    pcap_artifact_id: str | None,
    interaction_id: str | None,
    parent_action_id: str | None,
    parent_decision_id: str | None,
    rule_matches: list[dict[str, Any]],
    decision: dict[str, Any],
    shap_payload: dict[str, Any],
    shap_evidence_id: int | None,
    context: dict[str, Any],
    db_cursor: Any | None = None,
    defer_buffer: bool = False,
    alert_id_override: str | None = None,
) -> dict[str, Any]:
    alert_id = str(alert_id_override or uuid.uuid4())
    urgency = str(decision.get("urgency") or "low").lower()
    recommendation = str(decision.get("recommendation") or "monitor_and_triage")
    severity = str((rule_matches[0].get("severity") if rule_matches else urgency) or "low").lower()
    top_features = []
    if isinstance(shap_payload.get("metrics"), dict):
        tf = shap_payload["metrics"].get("top_features")
        if isinstance(tf, list):
            top_features = tf[:10]
    payload = {
        "alert_id": alert_id,
        "replay_id": _audit_replay_id(preparation_replay_id=replay_id, replay_run_id=replay_run_id),
        "model_id": model_id,
        "model_version": model_version,
        "run_id": run_id,
        "replay_run_id": replay_run_id,
        "child_id": child_id,
        "child_type": child_type,
        "rulepack_version": rulepack_version,
        "rule_version": rule_version,
        "pcap_artifact_id": pcap_artifact_id,
        "severity": severity,
        "urgency": urgency,
        "status": "open",
        "recommendation": recommendation,
        "interaction_id": interaction_id,
        "parent_action_id": parent_action_id,
        "parent_decision_id": parent_decision_id or parent_action_id,
        "rule_matches": rule_matches,
        "prediction": shap_payload.get("prediction") if isinstance(shap_payload.get("prediction"), dict) else {},
        "top_shap_features": top_features,
        "shap_evidence_status": _shap_evidence_status(shap_payload),
        "shap_evidence_id": shap_evidence_id,
        "expected_environment": context.get("expected_environment"),
        "observed_environment": context.get("observed_environment"),
        "cross_scope_flag": bool(context.get("cross_scope_flag")),
        "escalation_reason": context.get("escalation_reason"),
        "context": context,
        "parent_shap": shap_payload,
    }
    sql = """
                INSERT INTO phase4.step3_alerts (
                    alert_id, replay_run_id, replay_id, run_id, model_id, model_version, child_id, child_type, rulepack_version,
                    rule_version, pcap_artifact_id, interaction_id, parent_action_id, parent_decision_id,
                    severity, urgency, status, recommendation, expected_environment, observed_environment,
                    cross_scope_flag, escalation_reason, shap_evidence_status, shap_evidence_id, payload, created_at_utc, updated_at_utc
                )
                VALUES (
                    %(alert_id)s::uuid, %(replay_run_id)s::uuid, CASE WHEN %(replay_id)s = '' THEN NULL ELSE %(replay_id)s::uuid END,
                    CASE WHEN %(run_id)s = '' THEN NULL ELSE %(run_id)s::uuid END,
                    CASE WHEN %(model_id)s = '' THEN NULL ELSE %(model_id)s::uuid END,
                    %(model_version)s, %(child_id)s, %(child_type)s, %(rulepack_version)s,
                    %(rule_version)s, CASE WHEN %(pcap_artifact_id)s='' THEN NULL ELSE %(pcap_artifact_id)s::uuid END,
                    %(interaction_id)s::uuid, %(parent_action_id)s::uuid, %(parent_decision_id)s::uuid,
                    %(severity)s, %(urgency)s, 'open', %(recommendation)s, %(expected_environment)s, %(observed_environment)s,
                    %(cross_scope_flag)s, %(escalation_reason)s, %(shap_evidence_status)s,
                    CASE WHEN %(shap_evidence_id)s <= 0 THEN NULL ELSE %(shap_evidence_id)s END, %(payload)s::jsonb, now(), now()
                );
                """
    params = {
        "alert_id": alert_id,
        "replay_run_id": replay_run_id,
        "replay_id": _audit_replay_id(preparation_replay_id=replay_id, replay_run_id=replay_run_id) or "",
        "run_id": run_id,
        "model_id": _uuid_or_none(model_id) or "",
        "model_version": model_version,
        "child_id": child_id,
        "child_type": child_type,
        "rulepack_version": rulepack_version,
        "rule_version": rule_version,
        "pcap_artifact_id": str(pcap_artifact_id or ""),
        "interaction_id": interaction_id,
        "parent_action_id": parent_action_id,
        "parent_decision_id": parent_decision_id or parent_action_id,
        "severity": severity,
        "urgency": urgency,
        "recommendation": recommendation,
        "expected_environment": str(context.get("expected_environment") or "unknown"),
        "observed_environment": str(context.get("observed_environment") or "unknown"),
        "cross_scope_flag": bool(context.get("cross_scope_flag")),
        "escalation_reason": str(context.get("escalation_reason") or "none"),
        "shap_evidence_status": _shap_evidence_status(shap_payload),
        "shap_evidence_id": int(shap_evidence_id or 0),
        "payload": json.dumps(payload),
    }
    if defer_buffer and db_cursor is not None:
        _buffer_step3_alert(
            db_cursor,
            replay_run_id=replay_run_id,
            replay_id=_audit_replay_id(preparation_replay_id=replay_id, replay_run_id=replay_run_id),
            child_id=child_id,
            alert_payload=payload,
        )
        return payload
    if db_cursor is not None:
        db_cursor.execute(sql, params)
        return payload
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
        conn.commit()
    return payload


def _buffer_step3_alert(
    cur: Any,
    *,
    replay_run_id: str,
    replay_id: str | None = None,
    child_id: str,
    alert_payload: dict[str, Any],
) -> None:
    cur.execute(
        """
        INSERT INTO phase4.step3_child_alert_buffer (
            buffer_id, session_id, replay_run_id, replay_id, child_id, payload, created_at_utc
        ) VALUES (
            gen_random_uuid(), NULL, %(rid)s::uuid, CASE WHEN %(replay_id)s = '' THEN NULL ELSE %(replay_id)s::uuid END, %(cid)s, %(payload)s::jsonb, now()
        );
        """,
        {
            "rid": replay_run_id,
            "replay_id": _audit_replay_id(preparation_replay_id=replay_id, replay_run_id=replay_run_id) or "",
            "cid": child_id,
            "payload": json.dumps(alert_payload),
        },
    )


def _flush_step3_alert_buffer(cur: Any, replay_run_id: str) -> int:
    cur.execute(
        """
        SELECT buffer_id::text, child_id, payload
        FROM phase4.step3_child_alert_buffer
        WHERE replay_run_id = %(rid)s::uuid AND flushed_at_utc IS NULL
        ORDER BY created_at_utc;
        """,
        {"rid": replay_run_id},
    )
    rows = cur.fetchall()
    n = 0
    for buf_id, cid, pl in rows:
        if not isinstance(pl, dict):
            try:
                pl = json.loads(pl) if isinstance(pl, str) else {}
            except Exception:
                pl = {}
        aid = str(pl.get("alert_id") or uuid.uuid4())
        ins = """
            INSERT INTO phase4.step3_alerts (
                alert_id, replay_run_id, replay_id, run_id, model_id, model_version, child_id, child_type, rulepack_version,
                rule_version, pcap_artifact_id, interaction_id, parent_action_id, parent_decision_id,
                severity, urgency, status, recommendation, expected_environment, observed_environment,
                cross_scope_flag, escalation_reason, shap_evidence_status, shap_evidence_id, payload, created_at_utc, updated_at_utc
            )
            VALUES (
                %(aid)s::uuid, %(rid)s::uuid, CASE WHEN %(replay_id)s = '' THEN NULL ELSE %(replay_id)s::uuid END,
                CASE WHEN %(run_id)s = '' THEN NULL ELSE %(run_id)s::uuid END,
                CASE WHEN %(model_id)s = '' THEN NULL ELSE %(model_id)s::uuid END,
                %(model_version)s, %(child_id)s, %(child_type)s, %(rulepack_version)s,
                %(rule_version)s, CASE WHEN %(pcap_artifact_id)s='' THEN NULL ELSE %(pcap_artifact_id)s::uuid END,
                CASE WHEN %(iid)s = '' THEN NULL ELSE %(iid)s::uuid END,
                CASE WHEN %(paid)s = '' THEN NULL ELSE %(paid)s::uuid END,
                CASE WHEN %(parent_decision_id)s = '' THEN NULL ELSE %(parent_decision_id)s::uuid END,
                %(severity)s, %(urgency)s, 'open', %(recommendation)s, %(expected_environment)s, %(observed_environment)s,
                %(cross_scope_flag)s, %(escalation_reason)s, %(shap_evidence_status)s,
                CASE WHEN %(shap_evidence_id)s <= 0 THEN NULL ELSE %(shap_evidence_id)s END, %(payload)s::jsonb, now(), now()
            )
            ON CONFLICT (alert_id) DO NOTHING;
            """
        cur.execute(
            ins,
            {
                "aid": aid,
                "rid": replay_run_id,
                "replay_id": _audit_replay_id(
                    preparation_replay_id=pl.get("replay_id"),
                    replay_run_id=replay_run_id,
                )
                or "",
                "run_id": str(pl.get("run_id") or "") or "",
                "model_id": str(pl.get("model_id") or "") or "",
                "model_version": str(pl.get("model_version") or ""),
                "child_id": str(pl.get("child_id") or cid),
                "child_type": str(pl.get("child_type") or ""),
                "rulepack_version": str(pl.get("rulepack_version") or "") or None,
                "rule_version": str(pl.get("rule_version") or "") or None,
                "pcap_artifact_id": str(pl.get("pcap_artifact_id") or "") or "",
                "iid": str(pl.get("interaction_id") or "") or "",
                "paid": str(pl.get("parent_action_id") or "") or "",
                "parent_decision_id": str(pl.get("parent_decision_id") or pl.get("parent_action_id") or "") or "",
                "severity": str(pl.get("severity") or "low"),
                "urgency": str(pl.get("urgency") or "low"),
                "recommendation": str(pl.get("recommendation") or "monitor_and_triage"),
                "expected_environment": str(pl.get("expected_environment") or "unknown"),
                "observed_environment": str(pl.get("observed_environment") or "unknown"),
                "cross_scope_flag": bool(pl.get("cross_scope_flag")),
                "escalation_reason": str(pl.get("escalation_reason") or "none"),
                "shap_evidence_status": str(pl.get("shap_evidence_status") or "not_available"),
                "shap_evidence_id": int(pl.get("shap_evidence_id") or 0),
                "payload": json.dumps(pl),
            },
        )
        if cur.rowcount:
            n += 1
        cur.execute(
            "UPDATE phase4.step3_child_alert_buffer SET flushed_at_utc = now() WHERE buffer_id = %(bid)s::uuid;",
            {"bid": buf_id},
        )
    return n


def _run_replay_docker(payload: dict[str, Any], data_root: Path) -> dict[str, Any]:
    audit_log_path = _step3_audit_log_path(payload)
    exec_mode = _execution_mode(payload)
    detection_profile = str(payload.get("detection_profile") or "high_recall").strip().lower() or "high_recall"
    alert_threshold_profile = str(payload.get("alert_threshold_profile") or "aggressive").strip().lower() or "aggressive"
    window_sizes_raw = payload.get("window_sizes_s")
    if not isinstance(window_sizes_raw, list):
        window_sizes_raw = [1, 5, 30]
    window_sizes_s = [int(x) for x in window_sizes_raw if isinstance(x, (int, float, str)) and str(x).strip().isdigit()]
    if not window_sizes_s:
        window_sizes_s = [1, 5, 30]
    _step3_audit_log_append(
        audit_log_path,
        event="run_replay_docker_started",
        payload={
            "execution_mode": exec_mode,
            "model_id": payload.get("model_id"),
            "model_version": payload.get("model_version"),
            "detection_profile": detection_profile,
            "alert_threshold_profile": alert_threshold_profile,
            "window_sizes_s": window_sizes_s,
        },
    )
    _step3_audit_log_append(audit_log_path, event="step3_prepare_started", payload={})
    try:
        prep = step3_prepare(payload)
    except Exception as exc:
        out = {"ok": False, "error": f"step3_prepare_exception:{exc}"}
        _step3_audit_log_append(audit_log_path, event="run_replay_docker_failed", payload=out)
        return out
    _step3_audit_log_append(audit_log_path, event="step3_prepare_result", payload=prep if isinstance(prep, dict) else {"ok": False})
    if not prep.get("ok"):
        out = {"ok": False, "error": "invalid_model_selection", "missing": prep.get("missing_requirements") or []}
        _step3_audit_log_append(audit_log_path, event="run_replay_docker_failed", payload=out)
        return out
    _step3_audit_log_append(audit_log_path, event="step3_preparation_verify_started", payload={})
    try:
        verify = step3_preparation_verify(
            {
                **dict(payload or {}),
                "model_id": prep.get("model_id"),
                "model_version": prep.get("model_version"),
                "preparation_replay_id": prep.get("preparation_replay_id") or _preparation_replay_id(payload),
                "skip_prepare": True,
                "_prepared_result": prep,
            },
            data_root,
        )
    except Exception as exc:
        out = {"ok": False, "error": f"step3_preparation_verify_exception:{exc}"}
        _step3_audit_log_append(audit_log_path, event="run_replay_docker_failed", payload=out)
        return out
    _step3_audit_log_append(
        audit_log_path,
        event="step3_preparation_verify_result",
        payload=verify if isinstance(verify, dict) else {"ok": False},
    )
    if not bool(verify.get("ok")) or not bool(verify.get("verified_ok")):
        out = {
            "ok": False,
            "error": str(verify.get("error") or "preparation_verify_failed"),
            "verification_checks": verify.get("checks") or [],
            "missing": verify.get("missing") or [],
        }
        _step3_audit_log_append(audit_log_path, event="run_replay_docker_failed", payload=out)
        return out
    readiness = _step3_readiness(model_id=prep.get("model_id"), model_version=prep.get("model_version"))
    if not readiness.get("ok"):
        out = {"ok": False, "error": "step3_not_ready", "missing": readiness.get("missing") or []}
        _step3_audit_log_append(audit_log_path, event="run_replay_docker_failed", payload=out)
        return out
    model_version = str(prep.get("model_version") or "v1")
    model_id = str(prep.get("model_id") or "")
    active_rulepack_version = str(prep.get("active_rulepack_version") or "")
    runtime_bundle = _runtime_bundle_for_model(model_version)
    runtime_bundle_ok = bool(runtime_bundle.get("ok"))
    runtime_bundle_error = str(runtime_bundle.get("error") or "")
    runtime_bundle_model_id = _runtime_track_model_id(
        str(model_id) if model_id else None,
        model_version,
    )
    prep_replay_id = (
        _uuid_or_none(verify.get("preparation_replay_id"))
        or _uuid_or_none(prep.get("preparation_replay_id"))
        or _preparation_replay_id(payload)
        or _latest_preparation_replay_id(model_version)
    )
    source_step1_run_id = _uuid_or_none(prep.get("source_step1_run_id"))
    strict_default = STEP3_STRICT_ACCEPTANCE_DEFAULT if exec_mode == "production" else False
    strict_acceptance = _to_bool(payload.get("strict_acceptance"), default=strict_default)
    pcap_path = None
    pcap_paths = resolve_rep01_pcap_paths(data_root)
    rep01_inventory = resolve_rep01_packet_inventory(data_root)
    if int(rep01_inventory.get("files_count") or 0) <= 0:
        out = {"ok": False, "error": "rep01_pcap_files_missing"}
        _step3_audit_log_append(audit_log_path, event="run_replay_docker_failed", payload=out)
        return out
    if int(rep01_inventory.get("packets_total") or 0) <= 0:
        out = {"ok": False, "error": "rep01_pcap_packets_zero"}
        _step3_audit_log_append(audit_log_path, event="run_replay_docker_failed", payload=out)
        return out
    if _uuid_or_none(prep_replay_id):
        _prime_step3_sim_file_summaries_from_inventory(
            replay_id=prep_replay_id,
            run_id=source_step1_run_id,
            model_id=model_id or None,
            model_version=model_version,
            rep01_inventory=rep01_inventory,
        )
    catalog_errors: list[str] = []
    pcap_catalog_by_path: dict[str, str] = {}
    for f in list(rep01_inventory.get("files") or []):
        if not isinstance(f, dict):
            continue
        fp = str(f.get("path") or "").strip()
        if not fp:
            continue
        try:
            cat = register_step3_pcap_catalog(
                file_path=fp,
                byte_size=int(f.get("size_bytes") or 0) or None,
                traffic_profile=str(payload.get("traffic_profile") or "mixed").strip() or "mixed",
                metadata={
                    "source": "step3_replay_run",
                    "replay_id": prep_replay_id,
                    "preparation_replay_id": prep_replay_id,
                    "replay_profile": str(payload.get("replay_profile") or "default"),
                    "model_version": model_version,
                },
            )
            if isinstance(cat, dict) and str(cat.get("catalog_id") or "").strip():
                pcap_catalog_by_path[fp] = str(cat.get("catalog_id") or "").strip()
        except Exception as exc:
            catalog_errors.append(f"{fp}:{exc}")
    if catalog_errors:
        out = {"ok": False, "error": "pcap_catalog_register_failed", "detail": catalog_errors}
        _step3_audit_log_append(audit_log_path, event="run_replay_docker_failed", payload=out)
        return out
    if pcap_paths:
        pcap_path = pcap_paths[0]
    chunks, seg_stats = segment_pcap_into_chunks(pcap_path, execution_mode=exec_mode)
    strict_errors: list[str] = []
    if strict_acceptance:
        if exec_mode != "production":
            strict_errors.append("strict_acceptance_requires_production_execution_mode")
        if not pcap_path:
            strict_errors.append("strict_acceptance_requires_rep01_pcap")
        if bool((seg_stats or {}).get("synthetic")):
            strict_errors.append("strict_acceptance_disallows_synthetic_replay")
        if int((seg_stats or {}).get("total_packets_sampled") or 0) <= 0:
            strict_errors.append("strict_acceptance_requires_nonzero_packet_sample")
    if strict_errors:
        write_audit_event(
            event_type="step3_replay_strict_preflight_failed",
            actor="model-v1-step3-factory",
            artifact_refs=[],
            context={
                "model_id": model_id or None,
                "model_version": model_version,
                "strict_errors": strict_errors,
                "execution_mode": exec_mode,
                "orchestration": "docker_factory",
            },
            dataset_id="REP-01",
            experiment_id="exp_model_v1_step3_replay",
            model_version=model_version,
        )
        out = {
            "ok": False,
            "error": "strict_acceptance_failed_preflight",
            "strict_acceptance": strict_acceptance,
            "strict_errors": strict_errors,
            "execution_mode": exec_mode,
            "is_simulated": exec_mode == "simulation",
            "metric_provenance": _metric_provenance(payload),
        }
        _step3_audit_log_append(audit_log_path, event="run_replay_docker_failed", payload=out)
        return out
    if not payload.get("bypass_preparation_gate") and not _preparation_verified(model_version):
        out = {
            "ok": False,
            "error": "preparation_not_verified",
            "missing": ["call_post_model_v1_step3_preparation_verify"],
            "model_version": model_version,
        }
        _step3_audit_log_append(audit_log_path, event="run_replay_docker_failed", payload=out)
        return out
    children = list_child_stacks().get("children", [])
    target_ids = payload.get("child_ids") or [c["child_id"] for c in children if str(c.get("status") or "").lower() == "running"]
    target_set = set(target_ids)
    targets = [c for c in children if c.get("child_id") in target_set]
    if not targets:
        out = {"ok": False, "error": "no_running_child_targets"}
        _step3_audit_log_append(audit_log_path, event="run_replay_docker_failed", payload=out)
        return out
    reset_child_stacks = _to_bool(
        payload.get("reset_child_stacks"),
        default=_to_bool(os.getenv("STEP3_RESET_CHILD_STACKS_ON_REPLAY"), default=False),
    )
    if reset_child_stacks:
        restart_failures: list[dict[str, Any]] = []
        for cid in target_ids:
            out = child_stack_lifecycle(str(cid), "restart")
            if not out.get("ok"):
                restart_failures.append({"child_id": cid, "error": out.get("error")})
        if restart_failures:
            out = {"ok": False, "error": "child_stack_restart_failed", "detail": restart_failures}
            _step3_audit_log_append(audit_log_path, event="run_replay_docker_failed", payload=out)
            return out
        children = list_child_stacks().get("children", [])
        targets = [c for c in children if c.get("child_id") in target_set]
        if not targets:
            out = {"ok": False, "error": "no_running_child_targets_after_restart"}
            _step3_audit_log_append(audit_log_path, event="run_replay_docker_failed", payload=out)
            return out
    runtime_baseline: dict[str, dict[str, Any]] = {}
    for c in targets:
        cid = str(c.get("child_id") or "")
        if not cid:
            continue
        rs0 = runtime_stats(cid)
        baseline_files = dict(getattr(rs0, "file_received_counts", {}) or {}) if rs0 else {}
        baseline_file_rule_matches = dict(getattr(rs0, "file_rule_match_counts", {}) or {}) if rs0 else {}
        baseline_file_attack_packets = dict(getattr(rs0, "file_attack_packet_counts", {}) or {}) if rs0 else {}
        baseline_file_benign_packets = dict(getattr(rs0, "file_benign_packet_counts", {}) or {}) if rs0 else {}
        baseline_rule_hits_by_family = dict(getattr(rs0, "rule_hits_by_family", {}) or {}) if rs0 else {}
        runtime_baseline[cid] = {
            "received_packets": int(getattr(rs0, "received_packets", 0) or 0),
            "rule_match_count": int(getattr(rs0, "rule_match_count", 0) or 0),
            "alert_count": int(getattr(rs0, "alert_count", 0) or 0),
            "escalation_count": int(getattr(rs0, "escalation_count", 0) or 0),
            "file_received_counts": {str(k): int(v or 0) for k, v in baseline_files.items()},
            "file_rule_match_counts": {str(k): int(v or 0) for k, v in baseline_file_rule_matches.items()},
            "file_attack_packet_counts": {str(k): int(v or 0) for k, v in baseline_file_attack_packets.items()},
            "file_benign_packet_counts": {str(k): int(v or 0) for k, v in baseline_file_benign_packets.items()},
            "rule_hits_by_family": {str(k): int(v or 0) for k, v in baseline_rule_hits_by_family.items()},
        }

    replay_run_id = str(uuid.uuid4())
    simulation_session_id = str(uuid.uuid4())
    profile = str(payload.get("replay_profile") or "default")
    factory_name = _factory_container_name(replay_run_id)
    model_step3_root = _storage_root(data_root)
    manifest_dir = model_step3_root / "factory"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / f"factory_manifest__{replay_run_id}.json"
    result_path = manifest_dir / f"factory_result__{replay_run_id}.json"
    progress_path = manifest_dir / f"factory_progress__{replay_run_id}.jsonl"
    progress_path.write_text("", encoding="utf-8")

    def _mark_replay_failed(reason: str) -> None:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE phase4.replay_runs
                        SET status='failed', active_streams=0, finished_at_utc=now(), updated_at_utc=now(), error_message=%(err)s
                        WHERE replay_run_id = %(rid)s::uuid;
                        """,
                        {"rid": replay_run_id, "err": reason},
                    )
                    cur.execute(
                        """
                        UPDATE phase4.step3_simulation_sessions
                        SET status='failed', stopped_at_utc=now(), updated_at_utc=now(), active_replay_run_id=%(rid)s::uuid
                        WHERE session_id = %(sid)s::uuid;
                        """,
                        {"sid": simulation_session_id, "rid": replay_run_id},
                    )
                conn.commit()
        except Exception:
            pass
        try:
            if prep_replay_id:
                upsert_step3_preparation_run(
                    replay_id=prep_replay_id,
                    model_id=model_id or None,
                    model_version=model_version,
                    status="simulation_failed",
                    verified_ok=False,
                    verify_result={"replay_run_id": replay_run_id, "error": reason},
                )
        except Exception:
            pass

    try:
        requested_send_workers = int(payload.get("send_workers") or os.getenv("STEP3_FACTORY_SEND_WORKERS", "4"))
    except Exception:
        requested_send_workers = 4
    send_workers = max(1, min(requested_send_workers, 4))
    target_mode = "random_single"
    manifest_payload = {
        "replay_run_id": replay_run_id,
        "replay_profile": profile,
        "model_id": model_id or None,
        "model_version": model_version,
        "random_seed": int(payload.get("sequencer_seed") or 0),
        "sleep_ms": int(payload.get("sleep_ms") or 0),
        "requested_send_workers": requested_send_workers,
        "send_workers": send_workers,
        "effective_send_workers": send_workers,
        "target_mode": target_mode,
        "detection_profile": detection_profile,
        "alert_threshold_profile": alert_threshold_profile,
        "window_sizes_s": window_sizes_s,
        "result_path": str(result_path),
        "progress_path": str(progress_path),
        "targets": [
            {
                "child_id": str(c.get("child_id")),
                # Factory runs in container namespace; child network alias must be used, not loopback.
                "host": str(c.get("child_id") or _child_container_name(str(c.get("child_id") or ""))),
                "port": int(c.get("client_listener_port") or _client_listener_port(str(c.get("child_id")))),
                "client_network_id": str(c.get("client_network_id") or _client_network_id(str(c.get("child_id")))),
            }
            for c in targets
        ],
        "rep01_packet_inventory": rep01_inventory,
        "pcap_files": list(rep01_inventory.get("files") or []),
    }
    manifest_path.write_text(json.dumps(manifest_payload, indent=2), encoding="utf-8")

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.step3_simulation_sessions (
                    session_id, status, metadata, started_at_utc, current_phase, model_id, model_version, replay_id, run_kind, replay_profile, updated_at_utc
                ) VALUES (
                    %(sid)s::uuid, 'running', %(meta)s::jsonb, now(), 'replay', CASE WHEN %(mid)s='' THEN NULL ELSE %(mid)s::uuid END, %(mv)s, CASE WHEN %(replay_id)s='' THEN NULL ELSE %(replay_id)s::uuid END, 'replay', %(profile)s, now()
                );
                """,
                {
                    "sid": simulation_session_id,
                    "meta": json.dumps(
                        {
                            "sim_id": prep_replay_id,
                            "run_id": source_step1_run_id,
                            "step3_audit_log_path": audit_log_path,
                            "factory_container": factory_name,
                            "target_ids": target_ids,
                            "execution_mode": exec_mode,
                            "preparation_replay_id": prep_replay_id,
                            "model_id": model_id or None,
                            "model_version": model_version,
                        }
                    ),
                    "mid": model_id,
                    "mv": model_version,
                    "replay_id": _audit_replay_id(preparation_replay_id=prep_replay_id, replay_run_id=replay_run_id) or "",
                    "profile": profile,
                },
            )
            cur.execute(
                """
                INSERT INTO phase4.replay_runs (
                    replay_run_id, run_id, workflow_id, model_id, model_version, replay_profile, status, active_streams, started_at_utc, created_at_utc, updated_at_utc, metadata, simulation_session_id, preparation_replay_id, replay_id
                ) VALUES (
                    %(rid)s::uuid, CASE WHEN %(run_id)s='' THEN NULL ELSE %(run_id)s::uuid END, 'model_v1_step3_replay_simulation', CASE WHEN %(mid)s='' THEN NULL ELSE %(mid)s::uuid END, %(mv)s, %(profile)s, 'running', %(active)s, now(), now(), now(), %(meta)s::jsonb, %(sid)s::uuid, CASE WHEN %(prid)s='' THEN NULL ELSE %(prid)s::uuid END, CASE WHEN %(replay_id)s='' THEN NULL ELSE %(replay_id)s::uuid END
                );
                """,
                {
                    "rid": replay_run_id,
                    "run_id": source_step1_run_id or "",
                    "mid": model_id,
                    "mv": model_version,
                    "profile": profile,
                    "active": len(targets),
                    "sid": simulation_session_id,
                    "prid": prep_replay_id or "",
                    "replay_id": _audit_replay_id(preparation_replay_id=prep_replay_id, replay_run_id=replay_run_id) or "",
                    "meta": json.dumps(
                        {
                            "orchestration": "docker_factory",
                            "sim_id": prep_replay_id,
                            "run_id": source_step1_run_id,
                            "step3_audit_log_path": audit_log_path,
                            "factory_container": factory_name,
                            "execution_mode": exec_mode,
                            "is_simulated": exec_mode == "simulation",
                            "strict_acceptance": strict_acceptance,
                            "detection_profile": detection_profile,
                            "alert_threshold_profile": alert_threshold_profile,
                            "window_sizes_s": window_sizes_s,
                            "requested_send_workers": requested_send_workers,
                            "send_workers": send_workers,
                            "effective_send_workers": send_workers,
                            "target_mode": target_mode,
                            "factory_manifest_path": str(manifest_path),
                            "factory_result_path": str(result_path),
                            "factory_progress_path": str(progress_path),
                            "metric_provenance": _metric_provenance(payload),
                            "preparation_replay_id": prep_replay_id,
                            "rep01_packet_inventory": rep01_inventory,
                        }
                    ),
                },
            )
        conn.commit()
    if prep_replay_id:
        upsert_step3_preparation_run(
            replay_id=prep_replay_id,
            model_id=model_id or None,
            model_version=model_version,
            status="simulation_running",
            verified_ok=True,
            verify_result={
                "replay_run_id": replay_run_id,
                "simulation_session_id": simulation_session_id,
                "execution_mode": exec_mode,
            },
        )

    ok, err = _ensure_docker_network(SIMULATION_NETWORK_ID, internal=True)
    if not ok:
        reason = f"simulation_network_missing:{err}"
        _step3_audit_log_append(
            audit_log_path,
            event="run_replay_docker_failed",
            payload={"error": reason, "replay_run_id": replay_run_id},
        )
        _mark_replay_failed(reason)
        return {"ok": False, "error": reason}
    _remove_container_if_exists(factory_name)
    cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        factory_name,
        "--network",
        SIMULATION_NETWORK_ID,
        "--restart",
        "no",
        "-v",
        f"{_step3_host_data_root()}:/data",
        "-v",
        f"{_step3_host_raw_downloads_root()}:/data/raw_downloads:ro",
        _step3_docker_image(),
        "python",
        "/workspace/services_child/step3_factory_replay.py",
        "--manifest",
        str(manifest_path),
    ]
    ok, _out, err = _run_docker(cmd)
    if not ok:
        reason = f"factory_launch_failed:{err}"
        _step3_audit_log_append(
            audit_log_path,
            event="run_replay_docker_failed",
            payload={"error": reason, "replay_run_id": replay_run_id, "factory_container": factory_name},
        )
        _mark_replay_failed(reason)
        return {"ok": False, "error": reason}
    factory_running, factory_state = _docker_container_running(factory_name)
    if not factory_running:
        _run_docker(["docker", "rm", "-f", factory_name])
        reason = f"factory_container_not_running:{factory_state}"
        _step3_audit_log_append(
            audit_log_path,
            event="run_replay_docker_failed",
            payload={"error": reason, "replay_run_id": replay_run_id, "factory_container": factory_name},
        )
        _mark_replay_failed(reason)
        return {"ok": False, "error": reason}
    for c in targets:
        cn = str(c.get("client_network_id") or _client_network_id(str(c.get("child_id"))))
        ok_conn, err_conn = _docker_network_connect(cn, factory_name)
        if not ok_conn:
            _run_docker(["docker", "rm", "-f", factory_name])
            reason = f"factory_child_network_connect_failed:{cn}:{err_conn}"
            _step3_audit_log_append(
                audit_log_path,
                event="run_replay_docker_failed",
                payload={"error": reason, "replay_run_id": replay_run_id, "factory_container": factory_name},
            )
            _mark_replay_failed(reason)
            return {"ok": False, "error": reason}
    _STEP3_DOCKER_REPLAY_STATE.update(
        {
            "running": True,
            "factory_container": factory_name,
            "replay_run_id": replay_run_id,
            "started_at": _now(),
            "last_error": None,
            "last_result": None,
        }
    )
    _step3_audit_log_append(
        audit_log_path,
        event="factory_container_started",
        payload={
            "replay_run_id": replay_run_id,
            "simulation_session_id": simulation_session_id,
            "factory_container": factory_name,
            "send_workers": send_workers,
            "sim_id": prep_replay_id,
            "run_id": source_step1_run_id,
            "target_children": [str(c.get("child_id") or "") for c in targets],
        },
    )
    try:
        wait_timeout_s = max(30.0, float(os.getenv("STEP3_FACTORY_WAIT_TIMEOUT_S", "900")))
    except Exception:
        wait_timeout_s = 900.0
    wait_ok = True
    wait_out = ""
    wait_err = ""
    progress_offset = 0
    progress_events_seen = 0
    completed_file_events_emitted: set[str] = set()
    monitor_started_at = time.time()
    while True:
        progress_rows, progress_offset = _read_factory_progress_rows(progress_path, progress_offset)
        file_completion_events: list[dict[str, Any]] = []
        if progress_rows:
            progress_events_seen += len(progress_rows)
            for prow in progress_rows:
                if str(prow.get("type") or "").strip() != "file_progress":
                    continue
                fs = prow.get("file_stat") if isinstance(prow.get("file_stat"), dict) else {}
                fp = str(fs.get("file_path") or "").strip()
                if not fp:
                    continue
                packets_total = int(fs.get("packets_total_in_file") or 0)
                transmitted = int(fs.get("packets_transmitted") or 0)
                failed = int(fs.get("packets_failed") or 0)
                received = int(fs.get("packets_received") or fs.get("packets_received_estimated") or transmitted)
                lost = int(fs.get("packets_lost") or fs.get("packets_lost_estimated") or max(0, transmitted - received))
                alerts = int(fs.get("alerts_triggered") or fs.get("rule_matches") or 0)
                ratio = float(fs.get("alert_ratio") or (float(alerts) / float(packets_total) if packets_total > 0 else 0.0))
                file_started_at = str(fs.get("file_run_started_at_utc") or "").strip() or None
                file_finished_at = str(fs.get("file_run_finished_at_utc") or "").strip() or None
                row_status = "finalized" if file_finished_at else "running"
                _upsert_step3_sim_file_summary(
                    replay_id=prep_replay_id or replay_run_id,
                    replay_run_id=replay_run_id,
                    run_id=source_step1_run_id,
                    model_id=model_id or None,
                    model_version=model_version,
                    file_path=fp,
                    file_name=str(fs.get("file_name") or Path(fp).name),
                    status=row_status,
                    packets_total_in_file=packets_total,
                    packets_attack_in_file=int(fs.get("packets_attack_in_file") or 0),
                    packets_benign_in_file=int(fs.get("packets_benign_in_file") or 0),
                    packets_transmitted=transmitted,
                    packets_failed=failed,
                    packets_received=received,
                    packets_lost=lost,
                    alerts_triggered=alerts,
                    alert_ratio=ratio,
                    file_run_started_at_utc=file_started_at,
                    file_run_finished_at_utc=file_finished_at,
                    stats={**fs, "progress_event_at_utc": str(prow.get("event_at_utc") or _now())},
                )
                if file_finished_at and fp not in completed_file_events_emitted:
                    completed_file_events_emitted.add(fp)
                    file_completion_events.append(
                        {
                            "file_path": fp,
                            "file_name": str(fs.get("file_name") or Path(fp).name),
                            "packets_total_in_file": packets_total,
                            "packets_transmitted": transmitted,
                            "packets_received": received,
                            "packets_lost": lost,
                            "alerts_triggered": alerts,
                            "alert_ratio": ratio,
                            "file_run_started_at_utc": file_started_at,
                            "file_run_finished_at_utc": file_finished_at,
                            "worker_id": str(fs.get("worker_id") or ""),
                            "cpu_core_id": fs.get("cpu_core_id"),
                        }
                    )

        child_runtime_heartbeat: dict[str, Any] = {}
        for c in targets:
            cid = str(c.get("child_id") or "").strip()
            if not cid:
                continue
            rs = runtime_stats(cid)
            if rs is None:
                child_runtime_heartbeat[cid] = {"status": "unavailable"}
                continue
            child_runtime_heartbeat[cid] = {
                "status": "ok",
                "received_packets": int(getattr(rs, "received_packets", 0) or 0),
                "rule_match_count": int(getattr(rs, "rule_match_count", 0) or 0),
                "alert_count": int(getattr(rs, "alert_count", 0) or 0),
                "escalation_count": int(getattr(rs, "escalation_count", 0) or 0),
                "rule_hits_by_family": dict(getattr(rs, "rule_hits_by_family", {}) or {}),
                "active_rule_count": int(getattr(rs, "active_rule_count", 0) or 0),
                "rulepack_version": str(getattr(rs, "rulepack_version", "") or ""),
                "metric_source": str(getattr(rs, "metric_source", "") or "runtime"),
            }
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    for cid, hb in child_runtime_heartbeat.items():
                        if not isinstance(hb, dict):
                            continue
                        cur.execute(
                            """
                            UPDATE phase4.child_stacks
                            SET replay_status = 'running',
                                replay_receive_count = GREATEST(COALESCE(replay_receive_count, 0), %(recv)s),
                                alert_count = GREATEST(COALESCE(alert_count, 0), %(alerts)s),
                                escalation_count = GREATEST(COALESCE(escalation_count, 0), %(esc)s),
                                captured_event_count = GREATEST(COALESCE(captured_event_count, 0), %(alerts)s),
                                escalated_event_count = GREATEST(COALESCE(escalated_event_count, 0), %(esc)s),
                                health_status = CASE WHEN %(hb_status)s = 'ok' THEN 'healthy' ELSE health_status END,
                                last_heartbeat_utc = now(),
                                updated_at_utc = now(),
                                metadata = COALESCE(metadata, '{}'::jsonb) || %(meta_patch)s::jsonb
                            WHERE child_id = %(cid)s;
                            """,
                            {
                                "cid": cid,
                                "recv": int(hb.get("received_packets") or 0),
                                "alerts": int(hb.get("alert_count") or 0),
                                "esc": int(hb.get("escalation_count") or 0),
                                "hb_status": str(hb.get("status") or ""),
                                "meta_patch": json.dumps(
                                    {
                                        "realtime_sync": {
                                            "updated_at_utc": _now(),
                                            "rule_match_count": int(hb.get("rule_match_count") or 0),
                                            "active_rule_count": int(hb.get("active_rule_count") or 0),
                                            "rulepack_version": str(hb.get("rulepack_version") or ""),
                                            "rule_hits_by_family": hb.get("rule_hits_by_family") or {},
                                        }
                                    }
                                ),
                            },
                        )
                    for completed_row in file_completion_events:
                        _db_timeline_row(
                            cur,
                            replay_run_id,
                            "file_run_completed",
                            None,
                            completed_row,
                            replay_id=prep_replay_id,
                            simulation_session_id=simulation_session_id,
                        )
                    cur.execute(
                        """
                        UPDATE phase4.replay_runs
                        SET metadata = COALESCE(metadata, '{}'::jsonb) || %(meta)s::jsonb,
                            updated_at_utc = now()
                        WHERE replay_run_id = %(rid)s::uuid;
                        """,
                        {
                            "rid": replay_run_id,
                            "meta": json.dumps(
                                {
                                    "sim_id": prep_replay_id,
                                    "run_id": source_step1_run_id,
                                    "realtime_sync": {
                                        "status": "running",
                                        "updated_at_utc": _now(),
                                        "factory_container": factory_name,
                                        "progress_events_seen": progress_events_seen,
                                        "child_runtime": child_runtime_heartbeat,
                                    },
                                }
                            ),
                        },
                    )
                    cur.execute(
                        """
                        UPDATE phase4.step3_simulation_sessions
                        SET metadata = COALESCE(metadata, '{}'::jsonb) || %(meta)s::jsonb,
                            updated_at_utc = now()
                        WHERE session_id = %(sid)s::uuid;
                        """,
                        {
                            "sid": simulation_session_id,
                            "meta": json.dumps(
                                {
                                    "sim_id": prep_replay_id,
                                    "run_id": source_step1_run_id,
                                    "realtime_sync": {
                                        "status": "running",
                                        "updated_at_utc": _now(),
                                        "factory_container": factory_name,
                                        "progress_events_seen": progress_events_seen,
                                        "child_runtime_children": len(child_runtime_heartbeat),
                                    },
                                }
                            ),
                        },
                    )
                conn.commit()
        except Exception:
            pass

        factory_running, factory_state = _docker_container_running(factory_name)
        if not factory_running:
            break
        if (time.time() - monitor_started_at) > wait_timeout_s:
            wait_ok = False
            wait_err = f"timeout_after_{wait_timeout_s:.1f}s"
            _run_docker(["docker", "stop", factory_name])
            break
        time.sleep(1.0)
    exit_ok, exit_out, exit_err = _run_docker(["docker", "inspect", "-f", "{{.State.ExitCode}}", factory_name])
    if exit_ok:
        wait_out = str(exit_out or "").strip()
    else:
        wait_ok = False
        wait_err = str(wait_err or exit_err or "factory_exit_code_unavailable")
    logs_ok, logs_out, logs_err = _run_docker(["docker", "logs", factory_name])
    _run_docker(["docker", "rm", "-f", factory_name])
    result: dict[str, Any] = {}
    if result_path.is_file():
        try:
            parsed = json.loads(result_path.read_text(encoding="utf-8"))
            if isinstance(parsed, dict):
                result = parsed
        except Exception:
            result = {}
    if not result and logs_ok:
        for line in reversed((logs_out or "").splitlines()):
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    result = parsed
                    break
            except Exception:
                continue
    if bool(result):
        result_replay_id = str(result.get("replay_run_id") or "").strip()
        if result_replay_id and result_replay_id != replay_run_id:
            reason = f"factory_result_replay_id_mismatch:expected={replay_run_id}:actual={result_replay_id}"
            _step3_audit_log_append(
                audit_log_path,
                event="run_replay_docker_failed",
                payload={"error": reason, "replay_run_id": replay_run_id, "factory_result_replay_id": result_replay_id},
            )
            _mark_replay_failed(reason)
            _STEP3_DOCKER_REPLAY_STATE.update(
                {
                    "running": False,
                    "factory_container": None,
                    "replay_run_id": replay_run_id,
                    "last_error": reason,
                    "last_result": result or None,
                }
            )
            return {"ok": False, "error": reason, "replay_run_id": replay_run_id}
    if not bool(result.get("ok")):
        reason = str(result.get("error") or "factory_result_invalid")
        if reason == "factory_result_invalid":
            wait_code = str(wait_out or "").strip()
            logs_tail = ""
            if logs_out:
                logs_tail = " | ".join([ln.strip() for ln in str(logs_out).splitlines()[-8:] if ln.strip()])[:1200]
            elif logs_err:
                logs_tail = str(logs_err).strip()[:1200]
            elif wait_err:
                logs_tail = str(wait_err).strip()[:1200]
            detail_parts = []
            if wait_code:
                detail_parts.append(f"exit_code={wait_code}")
            if wait_err:
                detail_parts.append(f"wait_error={str(wait_err).strip()[:300]}")
            if logs_tail:
                detail_parts.append(f"logs_tail={logs_tail}")
            detail_parts.append(f"result_path={str(result_path)}")
            reason = "factory_result_invalid:" + ";".join(detail_parts)
        _step3_audit_log_append(
            audit_log_path,
            event="run_replay_docker_failed",
            payload={
                "error": reason,
                "replay_run_id": replay_run_id,
                "factory_exit_code": str(wait_out or ""),
                "factory_wait_error": str(wait_err or ""),
                "factory_logs_tail": str((logs_out or logs_err or "")[-2000:]),
                "factory_result_path": str(result_path),
            },
        )
        _mark_replay_failed(reason)
        _STEP3_DOCKER_REPLAY_STATE.update(
            {
                "running": False,
                "factory_container": None,
                "replay_run_id": replay_run_id,
                "last_error": reason,
                "last_result": result or None,
            }
        )
        return {"ok": False, "error": reason, "replay_run_id": replay_run_id}

    child_sent = result.get("child_sent") if isinstance(result.get("child_sent"), dict) else {}
    child_drop = result.get("child_dropped") if isinstance(result.get("child_dropped"), dict) else {}
    file_stats_raw = result.get("file_stats") if isinstance(result.get("file_stats"), list) else []
    child_runtime_delta: dict[str, dict[str, Any]] = {}
    file_received_totals: dict[str, int] = {}
    file_rule_match_totals: dict[str, int] = {}
    file_attack_packet_totals: dict[str, int] = {}
    file_benign_packet_totals: dict[str, int] = {}
    runtime_stats_missing_children: list[str] = []
    zero_rule_pipeline_children: list[str] = []
    for c in targets:
        cid = str(c.get("child_id") or "")
        if not cid:
            continue
        rs = runtime_stats(cid)
        sent_for_child = int(child_sent.get(cid) or 0)
        if rs is None and sent_for_child > 0:
            runtime_stats_missing_children.append(cid)
        if rs is not None and sent_for_child > 0 and int(getattr(rs, "active_rule_count", 0) or 0) <= 0:
            zero_rule_pipeline_children.append(cid)
        base = runtime_baseline.get(cid, {})
        recv_now = int(getattr(rs, "received_packets", 0) or 0) if rs else int(child_sent.get(cid) or 0)
        rule_match_now = int(getattr(rs, "rule_match_count", 0) or 0) if rs else 0
        alerts_now = int(getattr(rs, "alert_count", 0) or 0) if rs else 0
        escalations_now = int(getattr(rs, "escalation_count", 0) or 0) if rs else 0
        recv_delta = max(0, recv_now - int(base.get("received_packets") or 0))
        rule_match_delta = max(0, rule_match_now - int(base.get("rule_match_count") or 0))
        alert_delta = max(0, alerts_now - int(base.get("alert_count") or 0))
        escalation_delta = max(0, escalations_now - int(base.get("escalation_count") or 0))
        now_file_counts = dict(getattr(rs, "file_received_counts", {}) or {}) if rs else {}
        now_file_rule_match_counts = dict(getattr(rs, "file_rule_match_counts", {}) or {}) if rs else {}
        now_file_attack_packet_counts = dict(getattr(rs, "file_attack_packet_counts", {}) or {}) if rs else {}
        now_file_benign_packet_counts = dict(getattr(rs, "file_benign_packet_counts", {}) or {}) if rs else {}
        now_rule_hits_by_family = dict(getattr(rs, "rule_hits_by_family", {}) or {}) if rs else {}
        raw_recent_rule_matches = list(getattr(rs, "recent_rule_matches", []) or []) if rs else []
        recent_rule_matches: list[dict[str, Any]] = []
        for row in raw_recent_rule_matches:
            if not isinstance(row, dict):
                continue
            row_replay = str(row.get("replay_run_id") or "").strip()
            if row_replay and row_replay != replay_run_id:
                continue
            recent_rule_matches.append(
                {
                    "rule_id": str(row.get("rule_id") or "").strip(),
                    "rule_family": _normalize_rule_family(row.get("rule_family") or row.get("rule_scope")),
                    "rule_scope": _normalize_rule_family(row.get("rule_scope") or row.get("rule_family")),
                    "severity": str(row.get("severity") or "medium"),
                    "action": str(row.get("action") or "alert"),
                    "packet_or_flow_id": str(row.get("packet_or_flow_id") or "").strip(),
                    "source_file_path": str(row.get("source_file_path") or "").strip(),
                    "timestamp": str(row.get("timestamp") or "").strip() or _now(),
                }
            )
        base_file_counts = dict(base.get("file_received_counts") or {})
        base_file_rule_match_counts = dict(base.get("file_rule_match_counts") or {})
        base_file_attack_packet_counts = dict(base.get("file_attack_packet_counts") or {})
        base_file_benign_packet_counts = dict(base.get("file_benign_packet_counts") or {})
        base_rule_hits_by_family = dict(base.get("rule_hits_by_family") or {})
        file_delta: dict[str, int] = {}
        file_rule_match_delta: dict[str, int] = {}
        file_attack_packet_delta: dict[str, int] = {}
        file_benign_packet_delta: dict[str, int] = {}
        rule_hits_by_family_delta: dict[str, int] = {}
        for fp, now_cnt in now_file_counts.items():
            fpath = str(fp or "").strip()
            if not fpath:
                continue
            delta = max(0, int(now_cnt or 0) - int(base_file_counts.get(fpath) or 0))
            if delta <= 0:
                continue
            file_delta[fpath] = delta
            file_received_totals[fpath] = int(file_received_totals.get(fpath) or 0) + delta
        for fp, now_cnt in now_file_rule_match_counts.items():
            fpath = str(fp or "").strip()
            if not fpath:
                continue
            delta = max(0, int(now_cnt or 0) - int(base_file_rule_match_counts.get(fpath) or 0))
            if delta <= 0:
                continue
            file_rule_match_delta[fpath] = delta
            file_rule_match_totals[fpath] = int(file_rule_match_totals.get(fpath) or 0) + delta
        for fp, now_cnt in now_file_attack_packet_counts.items():
            fpath = str(fp or "").strip()
            if not fpath:
                continue
            delta = max(0, int(now_cnt or 0) - int(base_file_attack_packet_counts.get(fpath) or 0))
            if delta <= 0:
                continue
            file_attack_packet_delta[fpath] = delta
            file_attack_packet_totals[fpath] = int(file_attack_packet_totals.get(fpath) or 0) + delta
        for fp, now_cnt in now_file_benign_packet_counts.items():
            fpath = str(fp or "").strip()
            if not fpath:
                continue
            delta = max(0, int(now_cnt or 0) - int(base_file_benign_packet_counts.get(fpath) or 0))
            if delta <= 0:
                continue
            file_benign_packet_delta[fpath] = delta
            file_benign_packet_totals[fpath] = int(file_benign_packet_totals.get(fpath) or 0) + delta
        for fam, now_cnt in now_rule_hits_by_family.items():
            key = str(fam or "").strip()
            if not key:
                continue
            delta = max(0, int(now_cnt or 0) - int(base_rule_hits_by_family.get(key) or 0))
            if delta <= 0:
                continue
            rule_hits_by_family_delta[key] = delta
        child_runtime_delta[cid] = {
            "received_packets": recv_delta,
            "rule_match_count": rule_match_delta,
            "alert_count": alert_delta,
            "escalation_count": escalation_delta,
            "file_received_counts": file_delta,
            "file_rule_match_counts": file_rule_match_delta,
            "file_attack_packet_counts": file_attack_packet_delta,
            "file_benign_packet_counts": file_benign_packet_delta,
            "rule_hits_by_family": rule_hits_by_family_delta,
            "recent_rule_matches": recent_rule_matches[-500:],
        }
    if runtime_stats_missing_children:
        reason = "child_runtime_stats_unavailable:" + ",".join(sorted(runtime_stats_missing_children))
        _mark_replay_failed(reason)
        _STEP3_DOCKER_REPLAY_STATE.update(
            {
                "running": False,
                "factory_container": None,
                "replay_run_id": replay_run_id,
                "last_error": reason,
                "last_result": result or None,
            }
        )
        return {"ok": False, "error": reason, "replay_run_id": replay_run_id}
    if zero_rule_pipeline_children:
        reason = "child_rules_not_loaded:" + ",".join(sorted(zero_rule_pipeline_children))
        _mark_replay_failed(reason)
        _STEP3_DOCKER_REPLAY_STATE.update(
            {
                "running": False,
                "factory_container": None,
                "replay_run_id": replay_run_id,
                "last_error": reason,
                "last_result": result or None,
            }
        )
        return {"ok": False, "error": reason, "replay_run_id": replay_run_id}

    file_stats: list[dict[str, Any]] = []
    for fs in file_stats_raw:
        if not isinstance(fs, dict):
            continue
        fp = str(fs.get("file_path") or "").strip()
        if not fp:
            continue
        total_file = int(fs.get("packets_total_in_file") or 0)
        tx = int(fs.get("packets_transmitted") or 0)
        recv = int(file_received_totals.get(fp) or fs.get("packets_received_estimated") or tx)
        rule_matches = int(file_rule_match_totals.get(fp) or 0)
        lost = max(0, tx - recv)
        # Attack/benign labeling is based on child rule-trigger outcomes (hits > 0), not filenames/phases.
        attack_count = int(file_attack_packet_totals.get(fp) or 0)
        benign_count = int(file_benign_packet_totals.get(fp) or 0)
        if attack_count <= 0 and benign_count <= 0:
            # Backward-compat fallback when older child runtimes do not expose packet-level attack/benign counters.
            attack_count = min(recv, max(0, int(rule_matches)))
            benign_count = max(0, recv - attack_count)
        enriched = dict(fs)
        enriched["file_name"] = str(Path(fp).name)
        enriched["packets_received"] = recv
        enriched["packets_lost"] = lost
        enriched["rule_matches"] = rule_matches
        enriched["alerts_triggered"] = rule_matches
        enriched["alert_ratio"] = round(float(rule_matches) / float(total_file), 9) if total_file > 0 else 0.0
        enriched["packets_attack_in_file"] = attack_count
        enriched["packets_benign_in_file"] = benign_count
        enriched["packet_label_source"] = "child_rule_trigger"
        file_stats.append(enriched)
    if int(rep01_inventory.get("files_count") or 0) > 0 and not file_stats:
        reason = "factory_replay_missing_file_stats"
        _mark_replay_failed(reason)
        _STEP3_DOCKER_REPLAY_STATE.update(
            {
                "running": False,
                "factory_container": None,
                "replay_run_id": replay_run_id,
                "last_error": reason,
                "last_result": result or None,
            }
        )
        return {"ok": False, "error": reason, "replay_run_id": replay_run_id}
    child_file_stats: dict[str, list[dict[str, Any]]] = {}
    for fs in file_stats:
        if not isinstance(fs, dict):
            continue
        child_sent_map = fs.get("child_sent") if isinstance(fs.get("child_sent"), dict) else {}
        child_fail_map = fs.get("child_failed") if isinstance(fs.get("child_failed"), dict) else {}
        child_recv_map: dict[str, int] = {}
        child_rule_match_map: dict[str, int] = {}
        child_attack_packet_map: dict[str, int] = {}
        child_benign_packet_map: dict[str, int] = {}
        fp = str(fs.get("file_path") or "").strip()
        for cid, rdelta in child_runtime_delta.items():
            fr = rdelta.get("file_received_counts") if isinstance(rdelta, dict) else {}
            if isinstance(fr, dict) and fp:
                child_recv_map[cid] = int(fr.get(fp) or 0)
            frm = rdelta.get("file_rule_match_counts") if isinstance(rdelta, dict) else {}
            if isinstance(frm, dict) and fp:
                child_rule_match_map[cid] = int(frm.get(fp) or 0)
            fap = rdelta.get("file_attack_packet_counts") if isinstance(rdelta, dict) else {}
            if isinstance(fap, dict) and fp:
                child_attack_packet_map[cid] = int(fap.get(fp) or 0)
            fbp = rdelta.get("file_benign_packet_counts") if isinstance(rdelta, dict) else {}
            if isinstance(fbp, dict) and fp:
                child_benign_packet_map[cid] = int(fbp.get(fp) or 0)
        for cid, sval in child_sent_map.items():
            c = str(cid or "").strip()
            if not c:
                continue
            recv_c = int(child_recv_map.get(c) or 0)
            attack_c = int(child_attack_packet_map.get(c) or 0)
            benign_c = int(child_benign_packet_map.get(c) or 0)
            if attack_c <= 0 and benign_c <= 0:
                attack_c = min(recv_c, max(0, int(child_rule_match_map.get(c) or 0)))
                benign_c = max(0, recv_c - attack_c)
            row = {
                "file_path": str(fs.get("file_path") or ""),
                "packets_total_in_file": int(fs.get("packets_total_in_file") or 0),
                "packets_transmitted": int(sval or 0),
                "packets_failed": int(child_fail_map.get(c) or 0),
                "packets_received": recv_c,
                "packets_lost": max(0, int(sval or 0) - recv_c),
                "rule_matches": int(child_rule_match_map.get(c) or 0),
                "packets_attack_in_file": attack_c,
                "packets_benign_in_file": benign_c,
                "packet_label_source": "child_rule_trigger",
            }
            child_file_stats.setdefault(c, []).append(row)
    inserted_alerts = 0
    runtime_shap_rows_generated = 0
    runtime_shap_scored_total = 0
    runtime_shap_failed_total = 0
    alert_lineage_missing_rows = 0
    with connect() as conn:
        with conn.cursor() as cur:
            for fs in file_stats:
                if not isinstance(fs, dict):
                    continue
                fp = str(fs.get("file_path") or "").strip()
                if not fp:
                    continue
                total_file = int(fs.get("packets_total_in_file") or 0)
                tx = int(fs.get("packets_transmitted") or 0)
                fail = int(fs.get("packets_failed") or 0)
                recv = int(fs.get("packets_received") or fs.get("packets_received_estimated") or tx)
                lost = int(fs.get("packets_lost") or fs.get("packets_lost_estimated") or max(0, tx - recv))
                attack_count = max(0, int(fs.get("packets_attack_in_file") or 0))
                benign_count = max(0, int(fs.get("packets_benign_in_file") or 0))
                cur.execute(
                    """
                    INSERT INTO phase4.step3_replay_file_stats (
                        replay_run_id, replay_id, model_id, model_version, preparation_replay_id, file_path,
                        packets_total_in_file, packets_attack_in_file, packets_benign_in_file,
                        packets_transmitted, packets_failed, packets_received, packets_lost, stats, created_at_utc
                    ) VALUES (
                        %(rid)s::uuid,
                        CASE WHEN %(replay_id)s='' THEN NULL ELSE %(replay_id)s::uuid END,
                        CASE WHEN %(mid)s='' THEN NULL ELSE %(mid)s::uuid END,
                        %(mv)s,
                        CASE WHEN %(prid)s='' THEN NULL ELSE %(prid)s::uuid END,
                        %(fp)s,
                        %(total)s, %(attack)s, %(benign)s, %(tx)s, %(fail)s, %(recv)s, %(lost)s,
                        %(stats)s::jsonb,
                        now()
                    );
                    """,
                    {
                        "rid": replay_run_id,
                        "replay_id": _audit_replay_id(preparation_replay_id=prep_replay_id, replay_run_id=replay_run_id) or "",
                        "mid": model_id,
                        "mv": model_version,
                        "prid": prep_replay_id or "",
                        "fp": fp,
                        "total": total_file,
                        "attack": attack_count,
                        "benign": benign_count,
                        "tx": tx,
                        "fail": fail,
                        "recv": recv,
                        "lost": lost,
                        "stats": json.dumps(fs),
                    },
                )
                cur.execute(
                    """
                    INSERT INTO phase4.step3_sim_file_summaries (
                        replay_id, replay_run_id, run_id, model_id, model_version,
                        file_path, file_name, status,
                        packets_total_in_file, packets_attack_in_file, packets_benign_in_file,
                        packets_transmitted, packets_failed, packets_received, packets_lost,
                        alerts_triggered, alert_ratio,
                        file_run_started_at_utc, file_run_finished_at_utc, stats, created_at_utc, updated_at_utc
                    ) VALUES (
                        CASE WHEN %(replay_id)s='' THEN NULL ELSE %(replay_id)s::uuid END,
                        %(rid)s::uuid,
                        CASE WHEN %(run_id)s='' THEN NULL ELSE %(run_id)s::uuid END,
                        CASE WHEN %(mid)s='' THEN NULL ELSE %(mid)s::uuid END,
                        %(mv)s,
                        %(fp)s, %(file_name)s, 'finalized',
                        %(total)s, %(attack)s, %(benign)s, %(tx)s, %(fail)s, %(recv)s, %(lost)s,
                        %(alerts)s, %(ratio)s,
                        CASE WHEN %(started)s='' THEN NULL ELSE %(started)s::timestamptz END,
                        CASE WHEN %(finished)s='' THEN NULL ELSE %(finished)s::timestamptz END,
                        %(stats)s::jsonb, now(), now()
                    )
                    ON CONFLICT (replay_id, file_path)
                    DO UPDATE SET
                        replay_run_id = EXCLUDED.replay_run_id,
                        run_id = COALESCE(EXCLUDED.run_id, phase4.step3_sim_file_summaries.run_id),
                        model_id = COALESCE(EXCLUDED.model_id, phase4.step3_sim_file_summaries.model_id),
                        model_version = COALESCE(EXCLUDED.model_version, phase4.step3_sim_file_summaries.model_version),
                        file_name = COALESCE(EXCLUDED.file_name, phase4.step3_sim_file_summaries.file_name),
                        status = 'finalized',
                        packets_total_in_file = GREATEST(phase4.step3_sim_file_summaries.packets_total_in_file, EXCLUDED.packets_total_in_file),
                        packets_attack_in_file = GREATEST(phase4.step3_sim_file_summaries.packets_attack_in_file, EXCLUDED.packets_attack_in_file),
                        packets_benign_in_file = GREATEST(phase4.step3_sim_file_summaries.packets_benign_in_file, EXCLUDED.packets_benign_in_file),
                        packets_transmitted = GREATEST(phase4.step3_sim_file_summaries.packets_transmitted, EXCLUDED.packets_transmitted),
                        packets_failed = GREATEST(phase4.step3_sim_file_summaries.packets_failed, EXCLUDED.packets_failed),
                        packets_received = GREATEST(phase4.step3_sim_file_summaries.packets_received, EXCLUDED.packets_received),
                        packets_lost = GREATEST(phase4.step3_sim_file_summaries.packets_lost, EXCLUDED.packets_lost),
                        alerts_triggered = GREATEST(phase4.step3_sim_file_summaries.alerts_triggered, EXCLUDED.alerts_triggered),
                        alert_ratio = GREATEST(phase4.step3_sim_file_summaries.alert_ratio, EXCLUDED.alert_ratio),
                        file_run_started_at_utc = COALESCE(phase4.step3_sim_file_summaries.file_run_started_at_utc, EXCLUDED.file_run_started_at_utc),
                        file_run_finished_at_utc = COALESCE(EXCLUDED.file_run_finished_at_utc, phase4.step3_sim_file_summaries.file_run_finished_at_utc),
                        stats = COALESCE(phase4.step3_sim_file_summaries.stats, '{}'::jsonb) || EXCLUDED.stats,
                        updated_at_utc = now();
                    """,
                    {
                        "replay_id": _audit_replay_id(preparation_replay_id=prep_replay_id, replay_run_id=replay_run_id) or "",
                        "rid": replay_run_id,
                        "run_id": source_step1_run_id or "",
                        "mid": model_id,
                        "mv": model_version,
                        "fp": fp,
                        "file_name": str(fs.get("file_name") or Path(fp).name),
                        "total": total_file,
                        "attack": attack_count,
                        "benign": benign_count,
                        "tx": tx,
                        "fail": fail,
                        "recv": recv,
                        "lost": lost,
                        "alerts": int(fs.get("alerts_triggered") or fs.get("rule_matches") or 0),
                        "ratio": float(fs.get("alert_ratio") or 0.0),
                        "started": str(fs.get("file_run_started_at_utc") or "").strip(),
                        "finished": str(fs.get("file_run_finished_at_utc") or "").strip(),
                        "stats": json.dumps(fs),
                    },
                )
                _db_timeline_row(
                    cur,
                    replay_run_id,
                    "file_run_completed",
                    None,
                    {
                        "file_name": str(fs.get("file_name") or Path(fp).name),
                        "file_path": fp,
                        "packets_total_in_file": total_file,
                        "packets_transmitted": tx,
                        "packets_received": recv,
                        "packets_failed": fail,
                        "packets_lost": lost,
                        "packets_attack_in_file": attack_count,
                        "packets_benign_in_file": benign_count,
                        "alerts_triggered": int(fs.get("alerts_triggered") or fs.get("rule_matches") or 0),
                        "alert_ratio": float(fs.get("alert_ratio") or 0.0),
                        "file_run_started_at_utc": fs.get("file_run_started_at_utc"),
                        "file_run_finished_at_utc": fs.get("file_run_finished_at_utc"),
                    },
                    replay_id=prep_replay_id,
                    simulation_session_id=simulation_session_id,
                )
            for c in targets:
                cid = str(c.get("child_id"))
                ctype = str(c.get("child_type") or "enterprise")
                sent = int(child_sent.get(cid) or 0)
                dropped = int(child_drop.get(cid) or 0)
                delta = child_runtime_delta.get(cid, {})
                recv = int(delta.get("received_packets") or sent)
                alerts = int(delta.get("alert_count") or 0)
                escalations = int(delta.get("escalation_count") or 0)
                rule_matches = int(delta.get("rule_match_count") or 0)
                sid = str(uuid.uuid4())
                child_fs = child_file_stats.get(cid, [])
                cur.execute(
                    """
                    INSERT INTO phase4.replay_streams (
                        replay_stream_id, replay_run_id, workflow_id, child_id, child_type, network_id, dataset_id, stream_name,
                        replay_phase, status, packets_sent, packets_received, alerts_generated, escalations_generated, latency_ms,
                        started_at_utc, finished_at_utc, created_at_utc, updated_at_utc, model_id, model_version, metadata
                    ) VALUES (
                        %(sid)s::uuid, %(rid)s::uuid, 'model_v1_step3_replay_simulation', %(cid)s, %(ctype)s, %(nid)s, 'REP-01', %(sname)s,
                        'mixed_recovery', 'completed', %(sent)s, %(recv)s, %(alerts)s, %(esc)s, 0, now(), now(), now(), now(),
                        CASE WHEN %(mid)s='' THEN NULL ELSE %(mid)s::uuid END, %(mv)s, %(meta)s::jsonb
                    );
                    """,
                    {
                        "sid": sid,
                        "rid": replay_run_id,
                        "cid": cid,
                        "ctype": ctype,
                        "nid": str(c.get("client_network_id") or _client_network_id(cid)),
                        "sname": f"{cid}-stream",
                        "sent": sent,
                        "recv": recv,
                        "alerts": alerts,
                        "esc": escalations,
                        "mid": model_id,
                        "mv": model_version,
                        "meta": json.dumps(
                            {
                                "orchestration": "docker_factory",
                                "dropped": dropped,
                                "rule_match_count": rule_matches,
                                "rule_hits_by_family": delta.get("rule_hits_by_family") or {},
                                "detection_profile": detection_profile,
                                "alert_threshold_profile": alert_threshold_profile,
                                "window_sizes_s": window_sizes_s,
                            }
                        ),
                    },
                )
                cur.execute(
                    """
                    INSERT INTO phase4.step3_replay_flow_events (
                        flow_event_id, replay_run_id, replay_stream_id, child_id, phase_id, event_kind, payload, created_at_utc
                    ) VALUES (
                        %(id)s::uuid, %(rid)s::uuid, %(sid)s::uuid, %(cid)s, NULL, 'packet_transit', %(payload)s::jsonb, now()
                    );
                    """,
                    {
                        "id": str(uuid.uuid4()),
                        "rid": replay_run_id,
                        "sid": sid,
                        "cid": cid,
                        "payload": json.dumps(
                            {
                                "packets_sent": sent,
                                "packets_received": recv,
                                "packets_failed": dropped,
                                "file_stats": child_fs,
                                "model_id": model_id or None,
                                "model_version": model_version,
                                "replay_run_id": replay_run_id,
                                "simulation_session_id": simulation_session_id,
                            }
                        ),
                    },
                )
                cur.execute(
                    """
                    INSERT INTO phase4.step3_replay_flow_events (
                        flow_event_id, replay_run_id, replay_stream_id, child_id, phase_id, event_kind, payload, created_at_utc
                    ) VALUES (
                        %(id)s::uuid, %(rid)s::uuid, %(sid)s::uuid, %(cid)s, NULL, 'replay_summary', %(payload)s::jsonb, now()
                    );
                    """,
                    {
                        "id": str(uuid.uuid4()),
                        "rid": replay_run_id,
                        "sid": sid,
                        "cid": cid,
                        "payload": json.dumps({"received": recv, "sent": sent, "alerts": alerts, "escalations": escalations}),
                    },
                )
                cur.execute(
                    """
                    UPDATE phase4.child_stacks
                    SET replay_status='completed',
                        model_id = CASE WHEN %(mid)s='' THEN model_id ELSE %(mid)s::uuid END,
                        model_version = %(mv)s,
                        replay_receive_count = COALESCE(replay_receive_count, 0) + %(recv)s,
                        alert_count = COALESCE(alert_count, 0) + %(alerts)s,
                        escalation_count = COALESCE(escalation_count, 0) + %(esc)s,
                        captured_event_count = COALESCE(captured_event_count, 0) + %(alerts)s,
                        escalated_event_count = COALESCE(escalated_event_count, 0) + %(esc)s,
                        last_heartbeat_utc = now(),
                        updated_at_utc = now()
                    WHERE child_id = %(cid)s;
                    """,
                    {"cid": cid, "mid": model_id, "mv": model_version, "recv": recv, "alerts": alerts, "esc": escalations},
                )
                cur.execute(
                    """
                    INSERT INTO phase4.step3_stack_traffic (
                        traffic_id, replay_run_id, replay_id, model_id, model_version, child_id, child_type, packets_sent, packets_dropped, packets_received, metadata, created_at_utc
                    ) VALUES (
                        %(tid)s::uuid, %(rid)s::uuid, CASE WHEN %(replay_id)s='' THEN NULL ELSE %(replay_id)s::uuid END, CASE WHEN %(mid)s='' THEN NULL ELSE %(mid)s::uuid END, %(mv)s, %(cid)s, %(ctype)s,
                        %(sent)s, %(drop)s, %(recv)s, %(meta)s::jsonb, now()
                    );
                    """,
                    {
                        "tid": str(uuid.uuid4()),
                        "rid": replay_run_id,
                        "replay_id": _audit_replay_id(preparation_replay_id=prep_replay_id, replay_run_id=replay_run_id) or "",
                        "mid": model_id,
                        "mv": model_version,
                        "cid": cid,
                        "ctype": ctype,
                        "sent": sent,
                        "drop": dropped,
                        "recv": recv,
                        "meta": json.dumps({"orchestration": "docker_factory"}),
                    },
                )
                recent_rule_matches = delta.get("recent_rule_matches") if isinstance(delta.get("recent_rule_matches"), list) else []
                for rm in recent_rule_matches:
                    if not isinstance(rm, dict):
                        continue
                    cur.execute(
                        """
                        INSERT INTO phase4.step3_child_rule_matches (
                            match_id, replay_id, capture_event_id, child_id, rule_id, payload, created_at_utc
                        ) VALUES (
                            %(match_id)s::uuid,
                            CASE WHEN %(replay_id)s = '' THEN NULL ELSE %(replay_id)s::uuid END,
                            NULL,
                            %(child_id)s,
                            %(rule_id)s,
                            %(payload)s::jsonb,
                            now()
                        );
                        """,
                        {
                            "match_id": str(uuid.uuid4()),
                            "replay_id": _audit_replay_id(preparation_replay_id=prep_replay_id, replay_run_id=replay_run_id) or "",
                            "child_id": cid,
                            "rule_id": str(rm.get("rule_id") or ""),
                            "payload": json.dumps(
                                {
                                    "rule_scope": _normalize_rule_family(rm.get("rule_scope") or rm.get("rule_family")),
                                    "severity": str(rm.get("severity") or "medium"),
                                    "action": str(rm.get("action") or "alert"),
                                    "context": {
                                        "packet_or_flow_id": str(rm.get("packet_or_flow_id") or ""),
                                        "source_file_path": str(rm.get("source_file_path") or ""),
                                        "timestamp": str(rm.get("timestamp") or _now()),
                                        "model_id": model_id or None,
                                        "model_version": model_version,
                                        "replay_run_id": replay_run_id,
                                    },
                                }
                            ),
                        },
                    )
                if alerts > 0:
                    recent_rule_matches = delta.get("recent_rule_matches") if isinstance(delta, dict) else []
                    if not isinstance(recent_rule_matches, list):
                        recent_rule_matches = []
                    measured_rows = [rm for rm in recent_rule_matches if isinstance(rm, dict)]
                    if not measured_rows:
                        alert_lineage_missing_rows += int(alerts)
                    elif len(measured_rows) < int(alerts):
                        alert_lineage_missing_rows += int(alerts) - len(measured_rows)

                    for rm in measured_rows:
                        interaction_id = str(uuid.uuid4())
                        parent_action_id = str(uuid.uuid4())
                        packet_or_flow_id = str(rm.get("packet_or_flow_id") or "").strip() or f"{cid}:{uuid.uuid4()}"
                        rule_family = _normalize_rule_family(rm.get("rule_scope") or rm.get("rule_family"))
                        rule_id = str(rm.get("rule_id") or "").strip()
                        severity = str(rm.get("severity") or "medium").strip().lower() or "medium"
                        escalation_for_alert = 1 if severity in {"high", "critical"} else 0
                        urgency = "high" if escalation_for_alert > 0 else "medium"
                        rule_match_rows = [
                            {
                                "rule_id": rule_id,
                                "rule_scope": rule_family,
                                "rule_family": rule_family,
                                "severity": severity,
                                "action": str(rm.get("action") or "alert"),
                                "context": {
                                    "packet_or_flow_id": packet_or_flow_id,
                                    "source_file_path": str(rm.get("source_file_path") or ""),
                                    "timestamp": str(rm.get("timestamp") or _now()),
                                },
                            }
                        ]
                        interaction_payload = {
                            "alerts": 1,
                            "escalations": escalation_for_alert,
                            "source": "docker_child_runtime",
                            "rule_id": rule_id or None,
                            "rule_family": rule_family,
                            "packet_or_flow_id": packet_or_flow_id,
                        }
                        cur.execute(
                            """
                            INSERT INTO phase4.parent_child_interactions (
                                interaction_id, replay_run_id, replay_stream_id, workflow_id, child_id, child_type, network_id,
                                model_id, model_version, status, latency_ms, interaction_payload, started_at_utc, finished_at_utc, created_at_utc, updated_at_utc
                            ) VALUES (
                                %(iid)s::uuid, %(rid)s::uuid, %(sid)s::uuid, 'model_v1_step3_replay_simulation', %(cid)s, %(ctype)s, %(nid)s,
                                CASE WHEN %(mid)s='' THEN NULL ELSE %(mid)s::uuid END, %(mv)s, 'parent_reviewed', 0,
                                %(payload)s::jsonb, now(), now(), now(), now()
                            );
                            """,
                            {
                                "iid": interaction_id,
                                "rid": replay_run_id,
                                "sid": sid,
                                "cid": cid,
                                "ctype": ctype,
                                "nid": str(c.get("management_network_id") or c.get("network_id") or ""),
                                "mid": model_id,
                                "mv": model_version,
                                "payload": json.dumps(interaction_payload),
                            },
                        )
                        cur.execute(
                            """
                            INSERT INTO phase4.parent_actions (
                                parent_action_id, interaction_id, replay_run_id, workflow_id, child_id, child_type, network_id, model_version,
                                model_id, status, action_type, recommendation, action_payload, started_at_utc, finished_at_utc, created_at_utc, updated_at_utc
                            ) VALUES (
                                %(aid)s::uuid, %(iid)s::uuid, %(rid)s::uuid, 'model_v1_step3_replay_simulation', %(cid)s, %(ctype)s, %(nid)s, %(mv)s,
                                CASE WHEN %(mid)s='' THEN NULL ELSE %(mid)s::uuid END, 'completed', 'recommendation', 'review_and_triage', %(payload)s::jsonb, now(), now(), now(), now()
                            );
                            """,
                            {
                                "aid": parent_action_id,
                                "iid": interaction_id,
                                "rid": replay_run_id,
                                "cid": cid,
                                "ctype": ctype,
                                "nid": str(c.get("management_network_id") or c.get("network_id") or ""),
                                "mv": model_version,
                                "mid": model_id,
                                "payload": json.dumps(interaction_payload),
                            },
                        )

                        runtime_context = {
                            "child_id": cid,
                            "child_type": ctype,
                            "packets_received": recv,
                            "packets_sent": sent,
                            "payload_bytes": 256,
                            "latency_ms": float(delta.get("latency_ms") or 0.0),
                            "replay_phase": "attack_burst",
                            "expected_environment": str(c.get("assigned_scope") or ctype or "unknown"),
                            "observed_environment": str(c.get("assigned_scope") or ctype or "unknown"),
                            "cross_scope_flag": False,
                            "escalation_reason": "none",
                            "rule_id": rule_id or None,
                            "rule_family": rule_family,
                            "packet_or_flow_id": packet_or_flow_id,
                            "source_file_path": str(rm.get("source_file_path") or ""),
                        }
                        if runtime_bundle_ok:
                            runtime_shap_payload = _predict_and_explain_runtime_event(
                                bundle=runtime_bundle,
                                model_id=runtime_bundle_model_id,
                                model_version=model_version,
                                replay_run_id=replay_run_id,
                                child_id=cid,
                                child_type=ctype,
                                interaction_id=interaction_id,
                                parent_action_id=parent_action_id,
                                context=runtime_context,
                            )
                        else:
                            runtime_shap_payload = {
                                "ok": False,
                                "status": "runtime_shap_not_available",
                                "evidence_status": "not_available",
                                "error": runtime_bundle_error or "runtime_bundle_unavailable",
                                "details": {
                                    "model_id": runtime_bundle_model_id,
                                    "model_version": model_version,
                                    "replay_run_id": replay_run_id,
                                    "child_id": cid,
                                    "child_type": ctype,
                                    "context": runtime_context,
                                },
                            }
                        alert_event_id = str(uuid.uuid4())
                        runtime_shap_payload["context"] = runtime_context
                        runtime_shap_payload.setdefault("details", {})
                        if isinstance(runtime_shap_payload.get("details"), dict):
                            runtime_shap_payload["details"].update(
                                {
                                    "alert_id": alert_event_id,
                                    "rule_id": rule_id,
                                    "rule_family": rule_family,
                                    "packet_or_flow_id": packet_or_flow_id,
                                }
                            )
                        shap_log_id = _append_runtime_shap_log(
                            model_version=model_version,
                            replay_run_id=replay_run_id,
                            child_id=cid,
                            child_type=ctype,
                            interaction_id=interaction_id,
                            parent_action_id=parent_action_id,
                            payload=runtime_shap_payload,
                            rule_version=active_rulepack_version,
                            simulation_session_id=simulation_session_id,
                        )
                        runtime_shap_rows_generated += 1
                        if bool(runtime_shap_payload.get("ok")) and str(runtime_shap_payload.get("status") or "") == "runtime_shap_completed":
                            runtime_shap_scored_total += 1
                        else:
                            runtime_shap_failed_total += 1
                        _insert_step3_alert(
                            replay_run_id=replay_run_id,
                            replay_id=prep_replay_id,
                            run_id=source_step1_run_id,
                            model_id=_uuid_or_none(model_id) or "",
                            model_version=model_version,
                            child_id=cid,
                            child_type=ctype,
                            rulepack_version=active_rulepack_version,
                            rule_version=active_rulepack_version,
                            pcap_artifact_id=str(pcap_catalog_by_path.get(str(pcap_path or "")) or ""),
                            interaction_id=interaction_id,
                            parent_action_id=parent_action_id,
                            parent_decision_id=parent_action_id,
                            rule_matches=rule_match_rows,
                            decision={"urgency": urgency, "recommendation": "review_and_triage"},
                            shap_payload=runtime_shap_payload,
                            shap_evidence_id=shap_log_id,
                            context=runtime_context,
                            db_cursor=cur,
                            defer_buffer=False,
                            alert_id_override=alert_event_id,
                        )
                        cur.execute(
                            """
                            INSERT INTO phase4.step3_replay_flow_events (
                                flow_event_id, replay_run_id, replay_stream_id, child_id, phase_id, event_kind, payload, created_at_utc
                            ) VALUES (
                                %(id)s::uuid, %(rid)s::uuid, %(sid)s::uuid, %(cid)s, NULL, 'child_alert', %(payload)s::jsonb, now()
                            );
                            """,
                            {
                                "id": str(uuid.uuid4()),
                                "rid": replay_run_id,
                                "sid": sid,
                                "cid": cid,
                                "payload": json.dumps(
                                    {
                                        "alerts": 1,
                                        "severity": severity,
                                        "urgency": urgency,
                                        "rule_id": rule_id or None,
                                        "rule_family": rule_family,
                                        "packet_or_flow_id": packet_or_flow_id,
                                    }
                                ),
                            },
                        )
                        if escalation_for_alert > 0:
                            cur.execute(
                                """
                                INSERT INTO phase4.step3_replay_flow_events (
                                    flow_event_id, replay_run_id, replay_stream_id, child_id, phase_id, event_kind, payload, created_at_utc
                                ) VALUES (
                                    %(id)s::uuid, %(rid)s::uuid, %(sid)s::uuid, %(cid)s, NULL, 'escalation', %(payload)s::jsonb, now()
                                );
                                """,
                                {
                                    "id": str(uuid.uuid4()),
                                    "rid": replay_run_id,
                                    "sid": sid,
                                    "cid": cid,
                                    "payload": json.dumps(
                                        {
                                            "escalations": 1,
                                            "severity": "high",
                                            "urgency": "high",
                                            "rule_id": rule_id or None,
                                            "rule_family": rule_family,
                                            "packet_or_flow_id": packet_or_flow_id,
                                        }
                                    ),
                                },
                            )
                        inserted_alerts += 1

                    summary_payload = {
                        "source": "docker_child_runtime",
                        "replay_run_id": replay_run_id,
                        "child_id": cid,
                        "alert_count": alerts,
                        "escalation_count": escalations,
                        "measured_alert_rows": len(measured_rows),
                        "lineage_missing_rows": max(0, int(alerts) - len(measured_rows)),
                    }
                    cur.execute(
                        """
                        INSERT INTO phase4.step3_stack_alerts (
                            stack_alert_id, replay_run_id, replay_id, model_id, model_version, child_id, child_type, alert_count, escalation_count, payload, created_at_utc
                        ) VALUES (
                            %(id)s::uuid, %(rid)s::uuid, CASE WHEN %(replay_id)s='' THEN NULL ELSE %(replay_id)s::uuid END, CASE WHEN %(mid)s='' THEN NULL ELSE %(mid)s::uuid END, %(mv)s, %(cid)s, %(ctype)s, %(alerts)s, %(esc)s, %(payload)s::jsonb, now()
                        );
                        """,
                        {
                            "id": str(uuid.uuid4()),
                            "rid": replay_run_id,
                            "replay_id": _audit_replay_id(preparation_replay_id=prep_replay_id, replay_run_id=replay_run_id) or "",
                            "mid": model_id,
                            "mv": model_version,
                            "cid": cid,
                            "ctype": ctype,
                            "alerts": alerts,
                            "esc": escalations,
                            "payload": json.dumps(summary_payload),
                        },
                    )
            if exec_mode == "production" and alert_lineage_missing_rows > 0:
                guardrail_error = f"production_guardrail_alert_lineage_missing:{alert_lineage_missing_rows}"
                cur.execute(
                    """
                    UPDATE phase4.replay_runs
                    SET status='failed', active_streams=0, finished_at_utc=now(), updated_at_utc=now(),
                        metadata = COALESCE(metadata, '{}'::jsonb) || %(meta)s::jsonb
                    WHERE replay_run_id = %(rid)s::uuid;
                    """,
                    {
                        "rid": replay_run_id,
                        "meta": json.dumps(
                            {
                                "factory_result": result,
                                "preparation_replay_id": prep_replay_id,
                                "execution_mode": exec_mode,
                                "is_simulated": False,
                                "strict_acceptance": strict_acceptance,
                                "strict_acceptance_status": "failed",
                                "strict_acceptance_errors": [guardrail_error],
                                "detection_profile": detection_profile,
                                "alert_threshold_profile": alert_threshold_profile,
                                "window_sizes_s": window_sizes_s,
                                "metric_provenance": _metric_provenance(payload),
                                "rep01_packet_inventory": rep01_inventory,
                                "rep01_file_stats": file_stats,
                                "runtime_shap_rows": runtime_shap_rows_generated,
                                "runtime_shap_scored_total": runtime_shap_scored_total,
                                "runtime_shap_failed_total": runtime_shap_failed_total,
                                "user_alert_rows": inserted_alerts,
                                "user_alert_count_total": inserted_alerts + alert_lineage_missing_rows,
                                "alert_lineage_missing_rows": alert_lineage_missing_rows,
                                "evidence_quality": "not_measured",
                            }
                        ),
                    },
                )
                cur.execute(
                    """
                    UPDATE phase4.step3_simulation_sessions
                    SET status='failed', stopped_at_utc=now(), updated_at_utc=now(), active_replay_run_id=%(rid)s::uuid
                    WHERE session_id = %(sid)s::uuid;
                    """,
                    {"sid": simulation_session_id, "rid": replay_run_id},
                )
            else:
                cur.execute(
                    """
                    UPDATE phase4.replay_runs
                    SET status='completed', active_streams=0, finished_at_utc=now(), updated_at_utc=now(),
                        metadata = COALESCE(metadata, '{}'::jsonb) || %(meta)s::jsonb
                    WHERE replay_run_id = %(rid)s::uuid;
                    """,
                    {
                        "rid": replay_run_id,
                        "meta": json.dumps(
                            {
                                "factory_result": result,
                                "preparation_replay_id": prep_replay_id,
                                "execution_mode": exec_mode,
                                "is_simulated": exec_mode == "simulation",
                                "strict_acceptance": strict_acceptance,
                                "strict_acceptance_status": "passed",
                                "strict_acceptance_errors": [],
                                "detection_profile": detection_profile,
                                "alert_threshold_profile": alert_threshold_profile,
                                "window_sizes_s": window_sizes_s,
                                "metric_provenance": _metric_provenance(payload),
                                "rep01_packet_inventory": rep01_inventory,
                                "rep01_file_stats": file_stats,
                                "runtime_shap_rows": runtime_shap_rows_generated,
                                "runtime_shap_scored_total": runtime_shap_scored_total,
                                "runtime_shap_failed_total": runtime_shap_failed_total,
                                "user_alert_rows": inserted_alerts,
                                "user_alert_count_total": inserted_alerts + alert_lineage_missing_rows,
                                "alert_lineage_missing_rows": alert_lineage_missing_rows,
                            }
                        ),
                    },
                )
                cur.execute(
                    """
                    UPDATE phase4.step3_simulation_sessions
                    SET status='completed', stopped_at_utc=now(), updated_at_utc=now(), active_replay_run_id=%(rid)s::uuid
                    WHERE session_id = %(sid)s::uuid;
                    """,
                    {"sid": simulation_session_id, "rid": replay_run_id},
                )
        conn.commit()

    if guardrail_error:
        _mark_replay_failed(guardrail_error)
        _STEP3_DOCKER_REPLAY_STATE.update(
            {
                "running": False,
                "factory_container": None,
                "replay_run_id": replay_run_id,
                "last_error": guardrail_error,
                "last_result": {
                    "factory_result": result,
                    "preparation_replay_id": prep_replay_id,
                    "runtime_shap_rows": runtime_shap_rows_generated,
                    "runtime_shap_scored_total": runtime_shap_scored_total,
                    "runtime_shap_failed_total": runtime_shap_failed_total,
                    "user_alert_rows": inserted_alerts,
                    "user_alert_count_total": inserted_alerts + alert_lineage_missing_rows,
                    "alert_lineage_missing_rows": alert_lineage_missing_rows,
                },
            }
        )
        return {
            "ok": False,
            "error": guardrail_error,
            "replay_run_id": replay_run_id,
            "simulation_session_id": simulation_session_id,
            "user_alert_rows": inserted_alerts,
            "alert_lineage_missing_rows": alert_lineage_missing_rows,
        }

    dissertation_metrics: dict[str, Any] = {}
    metrics_error: str | None = None
    detailed_metrics_artifact: dict[str, Any] = {}
    postgres_validation_report: dict[str, Any] = {}
    validation_status = "ok"
    try:
        dissertation_metrics = _dissertation_metrics_summary(
            replay_run_id=replay_run_id,
            model_id=model_id or None,
            model_version=model_version,
            preparation_replay_id=prep_replay_id,
            simulation_session_id=simulation_session_id,
            execution_mode=exec_mode,
            child_sent=child_sent,
            child_dropped=child_drop,
            rep01_inventory=rep01_inventory,
            rep01_file_stats=file_stats,
        )
        detailed_metrics_artifact = _step3_detailed_metrics_artifact(
            replay_run_id=replay_run_id,
            model_id=model_id or None,
            model_version=model_version,
            preparation_replay_id=prep_replay_id,
            simulation_session_id=simulation_session_id,
            execution_mode=exec_mode,
            dissertation_metrics=dissertation_metrics,
            data_root=data_root,
        )
        if detailed_metrics_artifact.get("ok"):
            dissertation_metrics["detailed_metrics_artifact"] = {
                "path": detailed_metrics_artifact.get("artifact_path"),
                "checksum_sha256": detailed_metrics_artifact.get("checksum_sha256"),
                "evidence_quality": detailed_metrics_artifact.get("evidence_quality"),
                "warnings": list(detailed_metrics_artifact.get("warnings") or []),
                "event_rows": int(detailed_metrics_artifact.get("rows") or 0),
            }
            upsert_step3_replay_metrics(
                replay_run_id=replay_run_id,
                model_id=model_id or None,
                model_version=model_version,
                preparation_replay_id=prep_replay_id,
                simulation_session_id=simulation_session_id,
                metrics=dissertation_metrics,
            )
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE phase4.replay_runs
                    SET metadata = COALESCE(metadata, '{}'::jsonb) || %(meta)s::jsonb,
                        updated_at_utc = now()
                    WHERE replay_run_id = %(rid)s::uuid;
                    """,
                    {
                        "rid": replay_run_id,
                        "meta": json.dumps(
                            {
                                "dissertation_metrics": dissertation_metrics,
                                "step3_detailed_metrics_artifact": (
                                    dissertation_metrics.get("detailed_metrics_artifact")
                                    if isinstance(dissertation_metrics, dict)
                                    else {}
                                ),
                            }
                        ),
                    },
                )
            conn.commit()
    except Exception as exc:  # pragma: no cover - db/runtime boundary
        metrics_error = str(exc)

    try:
        postgres_validation_report = _step3_postgres_validation_report(
            replay_run_id=replay_run_id,
            expected_files_count=int(rep01_inventory.get("files_count") or len(file_stats)),
            expected_packets_sent_total=int(sum(int(fs.get("packets_transmitted") or 0) for fs in file_stats)),
        )
        validation_status = str(postgres_validation_report.get("status") or "ok")
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE phase4.replay_runs
                    SET metadata = COALESCE(metadata, '{}'::jsonb) || %(meta)s::jsonb,
                        updated_at_utc = now()
                    WHERE replay_run_id = %(rid)s::uuid;
                    """,
                    {
                        "rid": replay_run_id,
                        "meta": json.dumps(
                            {
                                "postgres_validation_report": postgres_validation_report,
                                "validation_status": validation_status,
                            }
                        ),
                    },
                )
            conn.commit()
    except Exception as exc:
        postgres_validation_report = {
            "status": "error_non_gating",
            "warnings": [],
            "errors": [f"postgres_validation_update_failed:{exc}"],
            "summary": {},
            "generated_at_utc": _now(),
            "gating": False,
        }
        validation_status = "error_non_gating"

    if prep_replay_id:
        upsert_step3_preparation_run(
            replay_id=prep_replay_id,
            model_id=model_id or None,
            model_version=model_version,
            status="simulation_completed",
            verified_ok=True,
            verify_result={
                "replay_run_id": replay_run_id,
                "simulation_session_id": simulation_session_id,
                "execution_mode": exec_mode,
                "dissertation_metrics_available": bool(dissertation_metrics),
                "metrics_error": metrics_error,
                "postgres_validation_report": postgres_validation_report,
                "validation_status": validation_status,
            },
        )

    _STEP3_DOCKER_REPLAY_STATE.update(
        {
            "running": False,
            "factory_container": None,
            "replay_run_id": replay_run_id,
            "started_at": _STEP3_DOCKER_REPLAY_STATE.get("started_at"),
            "last_error": None,
            "last_result": {
                "factory_result": result,
                "dissertation_metrics": dissertation_metrics,
                "step3_detailed_metrics_artifact": detailed_metrics_artifact,
                "metrics_error": metrics_error,
                "postgres_validation_report": postgres_validation_report,
                "validation_status": validation_status,
                "preparation_replay_id": prep_replay_id,
                "sim_id": prep_replay_id,
                "run_id": source_step1_run_id,
                "rep01_packet_inventory": rep01_inventory,
            },
        }
    )
    write_audit_event(
        event_type=REPLAY_STARTED,
        actor="model-v1-step3-factory",
        artifact_refs=[str(manifest_path)],
        context={
            "replay_run_id": replay_run_id,
            "simulation_session_id": simulation_session_id,
            "orchestration": "docker_factory",
            "model_id": model_id or None,
            "model_version": model_version,
            "preparation_replay_id": prep_replay_id,
        },
        experiment_id="exp_model_v1_step3_replay",
        model_version=model_version,
        replay_id=replay_run_id,
    )
    write_audit_event(
        event_type=REPLAY_COMPLETED,
        actor="model-v1-step3-factory",
        artifact_refs=[str(result_path)],
        context={
            "replay_run_id": replay_run_id,
            "alerts_summary_rows": inserted_alerts,
            "user_alert_rows": inserted_alerts,
            "user_alert_count_total": inserted_alerts + alert_lineage_missing_rows,
            "runtime_shap_rows": runtime_shap_rows_generated,
            "runtime_shap_scored_total": runtime_shap_scored_total,
            "runtime_shap_failed_total": runtime_shap_failed_total,
            "alert_lineage_missing_rows": alert_lineage_missing_rows,
            "orchestration": "docker_factory",
            "preparation_replay_id": prep_replay_id,
            "dissertation_metrics_available": bool(dissertation_metrics),
            "step3_detailed_metrics_artifact": detailed_metrics_artifact if detailed_metrics_artifact else None,
            "metrics_error": metrics_error,
            "postgres_validation_report": postgres_validation_report,
            "validation_status": validation_status,
        },
        experiment_id="exp_model_v1_step3_replay",
        model_version=model_version,
        replay_id=replay_run_id,
    )
    out = {
        "ok": True,
        "status": "completed",
        "replay_run_id": replay_run_id,
        "sim_id": prep_replay_id,
        "run_id": source_step1_run_id,
        "simulation_session_id": simulation_session_id,
        "model_id": model_id or None,
        "model_version": model_version,
        "preparation_replay_id": prep_replay_id,
        "orchestration": "docker_factory",
        "factory_manifest_path": str(manifest_path),
        "factory_result_path": str(result_path),
        "result": result,
        "execution_mode": exec_mode,
        "is_simulated": exec_mode == "simulation",
        "strict_acceptance": strict_acceptance,
        "strict_acceptance_status": "passed",
        "strict_acceptance_errors": [],
        "detection_profile": detection_profile,
        "alert_threshold_profile": alert_threshold_profile,
        "window_sizes_s": window_sizes_s,
        "metric_provenance": _metric_provenance(payload),
        "rep01_packet_inventory": rep01_inventory,
        "rep01_file_stats": file_stats,
        "dissertation_metrics": dissertation_metrics,
        "step3_detailed_metrics_artifact": detailed_metrics_artifact,
        "dissertation_metrics_error": metrics_error,
        "postgres_validation_report": postgres_validation_report,
        "validation_status": validation_status,
    }
    try:
        metric_job = generate_step3_metrics(
            sim_id=prep_replay_id or simulation_session_id,
            replay_run_id=replay_run_id,
        )
        out["step3_metrics_generation"] = metric_job
        if bool(metric_job.get("warning")):
            out["warning"] = True
            out["status"] = "completed_with_warning"
            out["missing_requirements"] = metric_job.get("missing_requirements") or []
    except Exception as exc:
        out["step3_metrics_generation"] = {
            "ok": False,
            "error": f"step3_metrics_generation_failed:{exc}",
            "replay_run_id": replay_run_id,
        }
        out["warning"] = True
        out["status"] = "completed_with_warning"
        out["missing_requirements"] = ["step3_metric_generation_failed_manual_review_required"]
    _step3_audit_log_append(
        audit_log_path,
        event="run_replay_docker_completed",
        payload={
            "ok": True,
            "status": "completed",
            "replay_run_id": replay_run_id,
            "sim_id": prep_replay_id,
            "run_id": source_step1_run_id,
            "simulation_session_id": simulation_session_id,
            "model_id": model_id or None,
            "model_version": model_version,
            "alerts_total": (dissertation_metrics or {}).get("alerts_total"),
            "packets_sent_total": (dissertation_metrics or {}).get("packets_sent_total"),
            "packets_received_total": (dissertation_metrics or {}).get("packets_received_total"),
            "packets_dropped_total": (dissertation_metrics or {}).get("packets_dropped_total"),
            "validation_status": validation_status,
            "factory_result_path": str(result_path),
        },
    )
    return out


def run_replay(payload: dict[str, Any], data_root: Path) -> dict[str, Any]:
    audit_log_path = _step3_audit_log_path(payload)
    if _step3_docker_enabled():
        if not _docker_cli_available():
            out = {
                "ok": False,
                "error": "docker_cli_not_available",
                "detail": "Install docker CLI in phase4-dash-api image and keep /var/run/docker.sock mounted.",
            }
            _step3_audit_log_append(audit_log_path, event="run_replay_failed", payload=out)
            return out
        return _run_replay_docker(payload, data_root)
    out = {
        "ok": False,
        "error": "docker_orchestration_required",
        "detail": "STEP3_DOCKER_ORCHESTRATION must be enabled; in-process replay path is disabled.",
    }
    _step3_audit_log_append(audit_log_path, event="run_replay_failed", payload=out)
    return out
    exec_mode = _execution_mode(payload)
    is_simulated = exec_mode == "simulation"
    strict_default = STEP3_STRICT_ACCEPTANCE_DEFAULT if exec_mode == "production" else False
    strict_acceptance = _to_bool(payload.get("strict_acceptance"), default=strict_default)
    prep = step3_prepare(payload)
    if not prep.get("ok"):
        return {"ok": False, "error": "invalid_model_selection", "missing": prep.get("missing_requirements") or []}
    readiness = _step3_readiness(model_id=prep.get("model_id"), model_version=prep.get("model_version"))
    if not readiness.get("ok"):
        return {"ok": False, "error": "step3_not_ready", "missing": readiness.get("missing") or []}
    children = list_child_stacks().get("children", [])
    target_ids = payload.get("child_ids") or [c["child_id"] for c in children]
    profile = str(payload.get("replay_profile") or "default")
    replay_run_id = str(uuid.uuid4())
    simulation_session_id = str(uuid.uuid4())
    workflow_id = "model_v1_step3_replay_simulation"
    model_id = prep.get("model_id")
    model_version = str(prep.get("model_version") or "v1")
    source_step1_run_id = prep.get("source_step1_run_id")
    source_step2_workflow_id = prep.get("source_step2_workflow_id")
    active_rulepack_version = prep.get("active_rulepack_version")
    runtime_bundle = _runtime_bundle_for_model(model_version)
    runtime_bundle_ok = bool(runtime_bundle.get("ok"))
    runtime_bundle_error = str(runtime_bundle.get("error") or "")
    runtime_bundle_model_id = _runtime_track_model_id(
        str(model_id) if model_id else None,
        model_version,
    )
    datasets_by_type = {
        "enterprise": "ENT-01",
        "dns": "DNS-01",
        "iot": "IOT-01",
        "iiot": "REP-01",
    }
    paths = resolve_rep01_pcap_paths(data_root)
    pcap_path = paths[0] if paths else None
    all_chunks, seg_stats = segment_pcap_into_chunks(pcap_path, execution_mode=exec_mode)
    strict_errors: list[str] = []
    if strict_acceptance:
        if exec_mode != "production":
            strict_errors.append("strict_acceptance_requires_production_execution_mode")
        if not pcap_path:
            strict_errors.append("strict_acceptance_requires_rep01_pcap")
        if bool(seg_stats.get("synthetic")):
            strict_errors.append("strict_acceptance_disallows_synthetic_replay")
        if int(seg_stats.get("total_packets_sampled") or 0) <= 0:
            strict_errors.append("strict_acceptance_requires_nonzero_packet_sample")
    if not all_chunks and str(seg_stats.get("error") or ""):
        return {
            "ok": False,
            "error": str(seg_stats.get("error")),
            "execution_mode": exec_mode,
            "is_simulated": is_simulated,
            "metric_provenance": _metric_provenance(payload),
        }
    if strict_errors:
        write_audit_event(
            event_type="step3_replay_strict_preflight_failed",
            actor="model-v1-step3-replay-worker",
            artifact_refs=[],
            context={
                "model_id": model_id,
                "model_version": model_version,
                "strict_errors": strict_errors,
                "execution_mode": exec_mode,
            },
            dataset_id="REP-01",
            experiment_id="exp_model_v1_step3_replay",
            model_version=model_version,
        )
        return {
            "ok": False,
            "error": "strict_acceptance_failed_preflight",
            "strict_acceptance": strict_acceptance,
            "strict_errors": strict_errors,
            "execution_mode": exec_mode,
            "is_simulated": is_simulated,
            "metric_provenance": _metric_provenance(payload),
        }
    if not payload.get("bypass_preparation_gate") and not _preparation_verified(model_version):
        return {
            "ok": False,
            "error": "preparation_not_verified",
            "missing": ["call_post_model_v1_step3_preparation_verify"],
            "model_version": model_version,
            "metric_provenance": _metric_provenance(payload),
        }

    def _route_task(args: tuple[str, Any, str, str, str, int, str]) -> tuple[str, bool]:
        cid, chunk, rid, sid, phase_id, port, sim_sid = args
        pl = chunk_to_udp_payload(
            chunk,
            replay_run_id=rid,
            phase_id=phase_id,
            stream_id=sid,
            child_id=cid,
            event_id=new_event_id(),
            simulation_session_id=sim_sid,
        )
        ok = push_udp_to_child("127.0.0.1", port, pl)
        return cid, ok

    sent_by_child: dict[str, int] = {cid: 0 for cid in target_ids}
    dropped_by_child: dict[str, int] = {cid: 0 for cid in target_ids}
    strict_runtime_errors: list[str] = []
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO phase4.step3_simulation_sessions (
                        session_id, status, metadata, started_at_utc,
                        current_phase, model_id, model_version, replay_id, run_kind, replay_profile, updated_at_utc
                    ) VALUES (
                        %(sid)s::uuid, 'running', %(sess_meta)s::jsonb, now(),
                        'replay',
                        CASE WHEN %(mid)s = '' THEN NULL ELSE %(mid)s::uuid END,
                        %(mv)s, CASE WHEN %(replay_id)s = '' THEN NULL ELSE %(replay_id)s::uuid END, 'replay', %(profile)s, now()
                    );
                    """,
                    {
                        "sid": simulation_session_id,
                        "sess_meta": json.dumps(
                            {
                                "targets": target_ids,
                                "execution_mode": exec_mode,
                                "metric_provenance": _metric_provenance(payload),
                                "replay_run_id": replay_run_id,
                            }
                        ),
                        "mid": str(model_id or ""),
                        "mv": model_version,
                        "replay_id": _audit_replay_id(preparation_replay_id=prep_replay_id, replay_run_id=replay_run_id) or "",
                        "profile": profile,
                    },
                )
                cur.execute(
                    """
                    INSERT INTO phase4.replay_runs (
                        replay_run_id, workflow_id, model_id, model_version, source_step1_run_id, source_step2_workflow_id,
                        active_rulepack_version, replay_profile, status, active_streams, started_at_utc, created_at_utc, updated_at_utc, metadata,
                        simulation_session_id, preparation_replay_id, replay_id
                    ) VALUES (
                        %(rid)s::uuid, %(workflow_id)s, %(model_id)s::uuid, %(model_version)s, %(source_step1_run_id)s, %(source_step2_workflow_id)s,
                        %(active_rulepack_version)s, %(profile)s, 'running', %(active)s, now(), now(), now(), %(meta)s::jsonb,
                        %(sid)s::uuid, CASE WHEN %(prid)s='' THEN NULL ELSE %(prid)s::uuid END, CASE WHEN %(replay_id)s='' THEN NULL ELSE %(replay_id)s::uuid END
                    );
                    """,
                    {
                        "rid": replay_run_id,
                        "sid": simulation_session_id,
                        "workflow_id": workflow_id,
                        "model_id": model_id,
                        "model_version": model_version,
                        "source_step1_run_id": source_step1_run_id,
                        "source_step2_workflow_id": source_step2_workflow_id,
                        "active_rulepack_version": active_rulepack_version,
                        "profile": profile,
                        "active": len(target_ids),
                        "prid": prep_replay_id or "",
                        "replay_id": _audit_replay_id(preparation_replay_id=prep_replay_id, replay_run_id=replay_run_id) or "",
                        "meta": json.dumps(
                            {
                                "simulation_session_id": simulation_session_id,
                                "pcap_adapter": seg_stats,
                                "simulation_network": SIMULATION_NETWORK_ID,
                                "parent_mgmt_network": PARENT_MANAGEMENT_NETWORK_ID,
                                "blocked_path": "simulation_stack_to_parent_management",
                                "execution_mode": exec_mode,
                                "is_simulated": is_simulated,
                                "strict_acceptance": strict_acceptance,
                                "strict_acceptance_status": "pending",
                                "metric_provenance": _metric_provenance(payload),
                            }
                        ),
                    },
                )
                cur.execute(
                    """
                    UPDATE phase4.step3_simulation_sessions
                    SET active_replay_run_id = %(rid)s::uuid, updated_at_utc = now()
                    WHERE session_id = %(sid)s::uuid;
                    """,
                    {"rid": replay_run_id, "sid": simulation_session_id},
                )
                simulation_set_running(
                    True,
                    simulation_session_id=simulation_session_id,
                    replay_run_id=replay_run_id,
                )
                _db_adapter_log_row(
                    cur,
                    replay_run_id,
                    "info",
                    "replay_run_started",
                    {"targets": target_ids},
                    simulation_session_id=simulation_session_id,
                )
                _db_timeline_row(
                    cur,
                    replay_run_id,
                    "replay_run_started",
                    None,
                    {"profile": profile},
                    simulation_session_id=simulation_session_id,
                )

                phase_order = 0
                if profile == "random_single_chunk":
                    seed = int(payload.get("sequencer_seed") or 0)
                    rng = random.Random(seed)
                    phase_id = str(uuid.uuid4())
                    cur.execute(
                        """
                        INSERT INTO phase4.step3_replay_phases (
                            phase_id, replay_run_id, pcap_artifact_id, phase_name, phase_order, packets_sent, packets_dropped, error_count, metadata, started_at_utc, created_at_utc
                        ) VALUES (
                            %(pid)s::uuid, %(rid)s::uuid, CASE WHEN %(pcap_artifact_id)s='' THEN NULL ELSE %(pcap_artifact_id)s::uuid END, %(name)s, %(ord)s, 0, 0, 0, %(meta)s::jsonb, now(), now()
                        );
                        """,
                        {
                            "pid": phase_id,
                            "rid": replay_run_id,
                            "pcap_artifact_id": str(pcap_catalog_by_path.get(str(pcap_path or "")) or ""),
                            "name": "random_single_chunk",
                            "ord": phase_order,
                            "meta": json.dumps(
                                {"source": "pcap_adapter", "sequencer": "random_single_chunk", "sequencer_seed": seed}
                            ),
                        },
                    )
                    phase_order += 1
                    flat_tasks: list[tuple[str, Any, str, str, str, int, str]] = []
                    for ch in list(all_chunks):
                        for cid in target_ids:
                            c = next((x for x in children if x["child_id"] == cid), None)
                            if not c:
                                continue
                            port = int(c.get("client_listener_port") or _client_listener_port(cid))
                            sid = str(uuid.uuid4())
                            flat_tasks.append((cid, ch, replay_run_id, sid, phase_id, port, simulation_session_id))
                    rng.shuffle(flat_tasks)
                    sent = 0
                    dropped = 0
                    tw = 1
                    if flat_tasks:
                        with ThreadPoolExecutor(max_workers=tw) as ex:
                            futs = [ex.submit(_route_task, t) for t in flat_tasks]
                            for fut in as_completed(futs):
                                _cid, ok = fut.result()
                                if ok:
                                    sent += 1
                                    sent_by_child[_cid] = int(sent_by_child.get(_cid) or 0) + 1
                                else:
                                    dropped += 1
                                    dropped_by_child[_cid] = int(dropped_by_child.get(_cid) or 0) + 1
                    cur.execute(
                        """
                        UPDATE phase4.step3_replay_phases
                        SET packets_sent=%(sent)s, packets_dropped=%(drop)s, finished_at_utc=now()
                        WHERE phase_id=%(pid)s::uuid;
                        """,
                        {"sent": sent, "drop": dropped, "pid": phase_id},
                    )
                    _db_timeline_row(
                        cur,
                        replay_run_id,
                        "adapter_phase_complete",
                        None,
                        {"phase": "random_single_chunk", "sent": sent, "dropped": dropped},
                        simulation_session_id=simulation_session_id,
                    )
                    _db_adapter_log_row(
                        cur,
                        replay_run_id,
                        "info",
                        "phase_random_single_chunk_complete",
                        {"sent": sent, "dropped": dropped},
                        simulation_session_id=simulation_session_id,
                    )
                else:
                    for phase in REPLAY_PHASES:
                        phase_id = str(uuid.uuid4())
                        pchunks = [ch for ch in all_chunks if ch.phase == phase]
                        if not pchunks:
                            continue
                        cur.execute(
                            """
                            INSERT INTO phase4.step3_replay_phases (
                                phase_id, replay_run_id, pcap_artifact_id, phase_name, phase_order, packets_sent, packets_dropped, error_count, metadata, started_at_utc, created_at_utc
                            ) VALUES (
                                %(pid)s::uuid, %(rid)s::uuid, CASE WHEN %(pcap_artifact_id)s='' THEN NULL ELSE %(pcap_artifact_id)s::uuid END, %(name)s, %(ord)s, 0, 0, 0, %(meta)s::jsonb, now(), now()
                            );
                            """,
                            {
                                "pid": phase_id,
                                "rid": replay_run_id,
                                "pcap_artifact_id": str(pcap_catalog_by_path.get(str(pcap_path or "")) or ""),
                                "name": phase,
                                "ord": phase_order,
                                "meta": json.dumps({"source": "pcap_adapter"}),
                            },
                        )
                        phase_order += 1
                        sent = 0
                        dropped = 0
                        tasks: list[tuple[str, Any, str, str, str, int, str]] = []
                        for cid in target_ids:
                            c = next((x for x in children if x["child_id"] == cid), None)
                            if not c:
                                continue
                            port = int(c.get("client_listener_port") or _client_listener_port(cid))
                            sid = str(uuid.uuid4())
                            for ch in pchunks:
                                tasks.append((cid, ch, replay_run_id, sid, phase_id, port, simulation_session_id))
                        tw = min(STEP3_CHILD_STACK_THREADS, max(1, len(tasks))) if tasks else 1
                        if tasks:
                            with ThreadPoolExecutor(max_workers=tw) as ex:
                                futs = [ex.submit(_route_task, t) for t in tasks]
                                for fut in as_completed(futs):
                                    _cid, ok = fut.result()
                                    if ok:
                                        sent += 1
                                        sent_by_child[_cid] = int(sent_by_child.get(_cid) or 0) + 1
                                    else:
                                        dropped += 1
                                        dropped_by_child[_cid] = int(dropped_by_child.get(_cid) or 0) + 1
                        cur.execute(
                            """
                            UPDATE phase4.step3_replay_phases
                            SET packets_sent=%(sent)s, packets_dropped=%(drop)s, finished_at_utc=now()
                            WHERE phase_id=%(pid)s::uuid;
                            """,
                            {"sent": sent, "drop": dropped, "pid": phase_id},
                        )
                        _db_timeline_row(
                            cur,
                            replay_run_id,
                            "adapter_phase_complete",
                            None,
                            {"phase": phase, "sent": sent, "dropped": dropped},
                            simulation_session_id=simulation_session_id,
                        )
                        _db_adapter_log_row(
                            cur,
                            replay_run_id,
                            "info",
                            f"phase_{phase}_complete",
                            {"sent": sent, "dropped": dropped},
                            simulation_session_id=simulation_session_id,
                        )

                for cid in target_ids:
                    c = next((x for x in children if x["child_id"] == cid), None)
                    if not c:
                        continue
                    sid = str(uuid.uuid4())
                    ctype = str(c.get("child_type") or "enterprise")
                    dataset_id = datasets_by_type.get(ctype, "REP-01")
                    rule_sync = _load_published_rules_for_child(
                        child_id=cid,
                        child_type=ctype,
                        assigned_scope=str(c.get("assigned_scope") or ""),
                        model_version=model_version,
                    )
                    child_rules = list(rule_sync.get("rules") or [])
                    if strict_acceptance and not rule_sync.get("ok"):
                        strict_runtime_errors.append(f"{cid}:rule_sync_failed:{rule_sync.get('error')}")
                    rs = runtime_stats(cid)
                    packets_received = int(rs.received_packets) if rs else 0
                    rule_matches = int(rs.rule_match_count) if rs else 0
                    alerts = int(rs.alert_count) if rs else 0
                    escalations = int(rs.escalation_count) if rs else 0
                    packets_sent = int(sent_by_child.get(cid) or 0)
                    latency = 42.0 if ctype == "iiot" else 28.0
                    replay_phase = "attack_burst" if packets_received > 0 and ctype in {"iiot", "iot", "dns", "enterprise"} else "mixed_recovery"
                    seeded = _seed_runtime_features(
                        {
                            "child_id": cid,
                            "child_type": ctype,
                            "packets_received": packets_received,
                            "packets_sent": packets_sent,
                            "payload_bytes": 256,
                            "latency_ms": latency,
                            "replay_phase": replay_phase,
                        }
                    )
                    expected_environment = str(c.get("assigned_scope") or ctype or "unknown").strip().lower() or "unknown"
                    observed_environment = expected_environment
                    if replay_phase == "domain_shift":
                        observed_environment = "enterprise" if expected_environment != "enterprise" else "iiot"
                    cross_scope_flag = observed_environment != expected_environment
                    scope_match_value = "cross_scope" if cross_scope_flag else "in_scope"
                    scope_match_aliases = [scope_match_value, expected_environment, "global"]
                    if cross_scope_flag:
                        scope_match_aliases.append("cross_scope")
                    else:
                        scope_match_aliases.append("in_scope")
                    scope_match_aliases = [str(x).strip().lower() for x in scope_match_aliases if str(x).strip()]
                    scope_match_aliases = list(dict.fromkeys(scope_match_aliases))
                    prediction_confidence = float(seeded.get("categorization_confidence") or 0.0)
                    rule_eval_context = {
                        "child_id": cid,
                        "child_type": ctype,
                        "dataset_id": dataset_id,
                        "replay_phase": replay_phase,
                        "packets_received": packets_received,
                        "packets_sent": packets_sent,
                        "payload_bytes": 256,
                        "latency_ms": latency,
                        "scope_match": scope_match_aliases,
                        "scope_match_state": scope_match_value,
                        "source_domain": observed_environment,
                        "expected_environment": expected_environment,
                        "observed_environment": observed_environment,
                        "cross_scope_flag": cross_scope_flag,
                        "escalation_reason": (
                            f"environment_mismatch:{observed_environment}_vs_{expected_environment}"
                            if cross_scope_flag
                            else "none"
                        ),
                        "vector_class": seeded.get("vector_class"),
                        "categorization_confidence": float(seeded.get("categorization_confidence") or 0.0),
                        "prediction_confidence": prediction_confidence,
                    }
                    deterministic_matches = _evaluate_child_rules(rules=child_rules, context=rule_eval_context)
                    top_rule = deterministic_matches[0] if deterministic_matches else {}
                    alerts_to_store = len(deterministic_matches)
                    escalations_to_store = sum(
                        1 for m in deterministic_matches if str(m.get("action") or "").lower() in {"escalate", "escalate_to_parent", "escalation"}
                    )
                    if is_simulated and not strict_acceptance and alerts_to_store == 0:
                        alerts_to_store = max(alerts, 1)
                    if is_simulated and not strict_acceptance and escalations_to_store == 0:
                        escalations_to_store = max(escalations, 0)
                    if strict_acceptance:
                        if packets_received <= 0:
                            strict_runtime_errors.append(f"{cid}:no_packets_received")
                        if len(deterministic_matches) <= 0:
                            strict_runtime_errors.append(f"{cid}:no_rule_match")
                    cur.execute(
                        """
                        INSERT INTO phase4.replay_streams (
                            replay_stream_id, replay_run_id, workflow_id, model_id, model_version, source_step1_run_id, source_step2_workflow_id,
                            child_id, child_type, network_id, dataset_id, stream_name,
                            replay_phase, status, packets_sent, packets_received, alerts_generated, escalations_generated, latency_ms,
                            started_at_utc, finished_at_utc, created_at_utc, updated_at_utc, metadata
                        ) VALUES (
                            %(sid)s::uuid, %(rid)s::uuid, %(workflow_id)s, %(model_id)s::uuid, %(model_version)s, %(source_step1_run_id)s, %(source_step2_workflow_id)s,
                            %(child_id)s, %(child_type)s, %(network_id)s, %(dataset_id)s, %(stream_name)s,
                            'mixed_recovery', 'completed', %(sent)s, %(recv)s, %(alerts)s, %(escalations)s, %(latency)s, now(), now(), now(), now(),
                            %(meta)s::jsonb
                        );
                        """,
                        {
                            "sid": sid,
                            "rid": replay_run_id,
                            "workflow_id": workflow_id,
                            "model_id": model_id,
                            "model_version": model_version,
                            "source_step1_run_id": source_step1_run_id,
                            "source_step2_workflow_id": source_step2_workflow_id,
                            "child_id": cid,
                            "child_type": ctype,
                            "network_id": c.get("client_network_id") or c.get("network_id"),
                            "dataset_id": dataset_id,
                            "stream_name": f"{cid}-stream",
                            "sent": packets_sent,
                            "recv": packets_received,
                            "alerts": alerts_to_store,
                            "escalations": escalations_to_store,
                            "latency": latency,
                            "meta": json.dumps(
                                {
                                    "listener": "udp_client_port",
                                    "management_path_separate": True,
                                    "pcap_segmentation": seg_stats,
                                    "rule_matches_runtime": int(len(deterministic_matches)),
                                    "rulepack_sync_ok": bool(rule_sync.get("ok")),
                                    "rulepack_sync_error": rule_sync.get("error"),
                                    "rulepack_version": rule_sync.get("rulepack_version"),
                                    "execution_mode": exec_mode,
                                    "is_simulated": is_simulated,
                                    "strict_acceptance": strict_acceptance,
                                    "metric_provenance": _metric_provenance(payload),
                                }
                            ),
                        },
                    )
                    cur.execute(
                        """
                        INSERT INTO phase4.step3_replay_flow_events (
                            flow_event_id, replay_run_id, replay_stream_id, child_id, phase_id, event_kind, payload, created_at_utc
                        ) VALUES (%(fid)s::uuid, %(rid)s::uuid, %(sid)s::uuid, %(cid)s, NULL, 'replay_summary',
                            %(payload)s::jsonb, now());
                        """,
                        {
                            "fid": str(uuid.uuid4()),
                            "rid": replay_run_id,
                            "sid": sid,
                            "cid": cid,
                            "payload": json.dumps({"received": packets_received, "sent": packets_sent}),
                        },
                    )
                    cur.execute(
                        """
                        INSERT INTO phase4.step3_replay_flow_events (
                            flow_event_id, replay_run_id, replay_stream_id, child_id, phase_id, event_kind, payload, created_at_utc
                        ) VALUES (%(fid)s::uuid, %(rid)s::uuid, %(sid)s::uuid, %(cid)s, NULL, 'packet_transit',
                            %(payload)s::jsonb, now());
                        """,
                        {
                            "fid": str(uuid.uuid4()),
                            "rid": replay_run_id,
                            "sid": sid,
                            "cid": cid,
                            "payload": json.dumps(
                                {
                                    "packets_sent": packets_sent,
                                    "packets_received": packets_received,
                                    "listener_port": c.get("client_listener_port"),
                                    "management_port": c.get("management_port"),
                                    "model_id": runtime_bundle_model_id,
                                    "model_version": model_version,
                                    "replay_run_id": replay_run_id,
                                    "simulation_session_id": simulation_session_id,
                                    "child_id": cid,
                                    "event_time": _now(),
                                }
                            ),
                        },
                    )
                    _db_timeline_row(
                        cur,
                        replay_run_id,
                        "child_received",
                        cid,
                        {"stream": sid},
                        simulation_session_id=simulation_session_id,
                    )
                    statuses = ["captured"]
                    if deterministic_matches:
                        statuses.append("rule_matched")
                    if escalations_to_store > 0:
                        statuses.extend(["escalated_to_parent", "parent_received"])
                    if packets_received > 0:
                        statuses.append("parent_reviewed")
                    inserted_interaction_ids: list[str] = []
                    parent_review_interaction_id: str | None = None
                    for st in statuses:
                        iid = str(uuid.uuid4())
                        cur.execute(
                            """
                            INSERT INTO phase4.parent_child_interactions (
                                interaction_id, replay_run_id, replay_stream_id, workflow_id, child_id, child_type, network_id,
                                model_id, model_version, source_step1_run_id, source_step2_workflow_id,
                                rulepack_version, status, latency_ms, interaction_payload, started_at_utc, finished_at_utc, created_at_utc, updated_at_utc
                            ) VALUES (
                                %(iid)s::uuid, %(rid)s::uuid, %(sid)s::uuid, %(workflow_id)s, %(child_id)s, %(child_type)s, %(network_id)s,
                                %(model_id)s::uuid, %(model_version)s, %(source_step1_run_id)s, %(source_step2_workflow_id)s,
                                %(rulepack_version)s, %(status)s, %(latency)s, %(payload)s::jsonb, now(), now(), now(), now()
                            );
                            """,
                            {
                                "iid": iid,
                                "rid": replay_run_id,
                                "sid": sid,
                                "workflow_id": workflow_id,
                                "child_id": cid,
                                "child_type": ctype,
                                "network_id": c.get("management_network_id") or c.get("network_id"),
                                "model_id": model_id,
                                "model_version": model_version,
                                "source_step1_run_id": source_step1_run_id,
                                "source_step2_workflow_id": source_step2_workflow_id,
                                "rulepack_version": c.get("rulepack_version"),
                                "status": st,
                                "latency": latency,
                                "payload": json.dumps(
                                    {
                                        "phase": profile,
                                        "dataset_id": dataset_id,
                                        "path": "child_management_to_parent_api",
                                        "execution_mode": exec_mode,
                                        "is_simulated": is_simulated,
                                        "metric_provenance": _metric_provenance(payload),
                                    }
                                ),
                            },
                        )
                        inserted_interaction_ids.append(iid)
                        if parent_review_interaction_id is None and st in {"parent_reviewed", "parent_actioned", "observed"}:
                            parent_review_interaction_id = iid
                    if deterministic_matches:
                        for rm in deterministic_matches:
                            cur.execute(
                                """
                                INSERT INTO phase4.step3_child_rule_matches (
                                    match_id, replay_id, capture_event_id, child_id, rule_id, payload, created_at_utc
                                ) VALUES (
                                    %(id)s::uuid, CASE WHEN %(replay_id)s = '' THEN NULL ELSE %(replay_id)s::uuid END, NULL, %(child_id)s, %(rule_id)s, %(payload)s::jsonb, now()
                                );
                                """,
                                {
                                    "id": str(uuid.uuid4()),
                                    "replay_id": _audit_replay_id(preparation_replay_id=prep_replay_id, replay_run_id=replay_run_id) or "",
                                    "child_id": cid,
                                    "rule_id": rm.get("rule_id"),
                                    "payload": json.dumps(
                                        {
                                            "model_id": runtime_bundle_model_id,
                                            "model_version": model_version,
                                            "replay_run_id": replay_run_id,
                                            "rulepack_version": rule_sync.get("rulepack_version"),
                                            "rule_scope": rm.get("rule_scope"),
                                            "severity": rm.get("severity"),
                                            "action": rm.get("action"),
                                            "context": rule_eval_context,
                                        }
                                    ),
                                },
                            )
                        write_audit_event(
                            event_type="step3_rule_match_detected",
                            actor="model-v1-step3-replay-worker",
                            artifact_refs=[],
                            context={
                                "child_id": cid,
                                "replay_run_id": replay_run_id,
                                "rulepack_version": rule_sync.get("rulepack_version"),
                                "match_count": len(deterministic_matches),
                                "top_severity": top_rule.get("severity"),
                            },
                            dataset_id="REP-01",
                            experiment_id="exp_model_v1_step3_replay",
                            model_version=model_version,
                            replay_id=replay_run_id,
                        )
                    if deterministic_matches or (is_simulated and not strict_acceptance):
                        parent_action_id = str(uuid.uuid4())
                        prelim_decision = _parent_decision_from_evidence(
                            prediction_label=None,
                            prediction_confidence=None,
                            top_rule_severity=str(top_rule.get("severity") or "low"),
                            cross_scope=bool(rule_eval_context.get("cross_scope_flag")),
                        )
                        cur.execute(
                            """
                            INSERT INTO phase4.parent_actions (
                                parent_action_id, replay_run_id, workflow_id, child_id, child_type, network_id, model_version, rulepack_version,
                                model_id, source_step1_run_id, source_step2_workflow_id,
                                status, action_type, recommendation, action_payload, started_at_utc, finished_at_utc, created_at_utc, updated_at_utc
                            ) VALUES (
                                %(id)s::uuid, %(rid)s::uuid, %(workflow_id)s, %(child_id)s, %(child_type)s, %(network_id)s, %(model_version)s, %(rulepack_version)s,
                                %(model_id)s::uuid, %(source_step1_run_id)s, %(source_step2_workflow_id)s,
                                %(status)s, 'recommendation', %(recommendation)s, %(payload)s::jsonb, now(), now(), now(), now()
                            );
                            """,
                            {
                                "id": parent_action_id,
                                "rid": replay_run_id,
                                "workflow_id": workflow_id,
                                "child_id": cid,
                                "child_type": ctype,
                                "network_id": c.get("management_network_id") or c.get("network_id"),
                                "model_version": model_version,
                                "model_id": model_id,
                                "source_step1_run_id": source_step1_run_id,
                                "source_step2_workflow_id": source_step2_workflow_id,
                                "rulepack_version": c.get("rulepack_version"),
                                "status": str(prelim_decision.get("action_status") or ("completed" if is_simulated else "pending_review")),
                                "recommendation": str(prelim_decision.get("recommendation") or "operator_review_required"),
                                "payload": json.dumps(
                                    {
                                        "latency_ms": latency,
                                        "shap_worker_budget": STEP3_SHAP_WORKERS,
                                        "review_workers": STEP3_PARENT_REVIEW_WORKERS,
                                        "execution_mode": exec_mode,
                                        "is_simulated": is_simulated,
                                        "strict_acceptance": strict_acceptance,
                                        "urgency": prelim_decision.get("urgency"),
                                        "rule_match_count": len(deterministic_matches),
                                        "metric_provenance": _metric_provenance(payload),
                                    }
                                ),
                            },
                        )
                    else:
                        parent_action_id = None
                    if alerts_to_store > 0:
                        cur.execute(
                            """
                            INSERT INTO phase4.step3_replay_flow_events (
                                flow_event_id, replay_run_id, replay_stream_id, child_id, phase_id, event_kind, payload, created_at_utc
                            ) VALUES (%(fid)s::uuid, %(rid)s::uuid, %(sid)s::uuid, %(cid)s, NULL, 'child_alert',
                                %(payload)s::jsonb, now());
                            """,
                            {
                                "fid": str(uuid.uuid4()),
                                "rid": replay_run_id,
                                "sid": sid,
                                "cid": cid,
                                "payload": json.dumps(
                                    {
                                        "alert_count": alerts_to_store,
                                        "rule_matches": len(deterministic_matches),
                                        "model_id": runtime_bundle_model_id,
                                        "model_version": model_version,
                                        "replay_run_id": replay_run_id,
                                        "child_id": cid,
                                        "event_time": _now(),
                                    }
                                ),
                            },
                        )
                    if escalations_to_store > 0 or parent_action_id:
                        cur.execute(
                            """
                            INSERT INTO phase4.step3_replay_flow_events (
                                flow_event_id, replay_run_id, replay_stream_id, child_id, phase_id, event_kind, payload, created_at_utc
                            ) VALUES (%(fid)s::uuid, %(rid)s::uuid, %(sid)s::uuid, %(cid)s, NULL, 'escalation',
                                %(payload)s::jsonb, now());
                            """,
                            {
                                "fid": str(uuid.uuid4()),
                                "rid": replay_run_id,
                                "sid": sid,
                                "cid": cid,
                                "payload": json.dumps(
                                    {
                                        "escalation_count": escalations_to_store,
                                        "parent_action_id": parent_action_id,
                                        "model_id": runtime_bundle_model_id,
                                        "model_version": model_version,
                                        "replay_run_id": replay_run_id,
                                        "child_id": cid,
                                        "event_time": _now(),
                                    }
                                ),
                            },
                        )
                    runtime_context = {
                        "child_id": cid,
                        "child_type": ctype,
                        "packets_sent": packets_sent,
                        "packets_received": packets_received,
                        "payload_bytes": 256,
                        "latency_ms": latency,
                        "replay_phase": "attack_burst" if alerts_to_store > 0 else "mixed_recovery",
                        "expected_environment": rule_eval_context.get("expected_environment"),
                        "observed_environment": rule_eval_context.get("observed_environment"),
                        "cross_scope_flag": bool(rule_eval_context.get("cross_scope_flag")),
                        "escalation_reason": rule_eval_context.get("escalation_reason"),
                    }
                    if runtime_bundle_ok:
                        runtime_shap_payload = _predict_and_explain_runtime_event(
                            bundle=runtime_bundle,
                            model_id=runtime_bundle_model_id,
                            model_version=model_version,
                            replay_run_id=replay_run_id,
                            child_id=cid,
                            child_type=ctype,
                            interaction_id=parent_review_interaction_id or (inserted_interaction_ids[0] if inserted_interaction_ids else ""),
                            parent_action_id=parent_action_id or "",
                            context=runtime_context,
                        )
                    else:
                        runtime_shap_payload = {
                            "ok": False,
                            "status": "runtime_shap_not_available",
                            "evidence_status": "not_available",
                            "error": runtime_bundle_error or "runtime_bundle_unavailable",
                            "details": {
                                "model_id": runtime_bundle_model_id,
                                "model_version": model_version,
                                "replay_run_id": replay_run_id,
                                "child_id": cid,
                                "child_type": ctype,
                                "context": runtime_context,
                            },
                        }
                    shap_log_id = _append_runtime_shap_log(
                        model_version=model_version,
                        replay_run_id=replay_run_id,
                        child_id=cid,
                        child_type=ctype,
                        interaction_id=parent_review_interaction_id or (inserted_interaction_ids[0] if inserted_interaction_ids else None),
                        parent_action_id=parent_action_id,
                        payload=runtime_shap_payload,
                        rule_version=str(rule_sync.get("rulepack_version") or c.get("rulepack_version") or ""),
                        simulation_session_id=simulation_session_id,
                    )
                    pred = runtime_shap_payload.get("prediction") if isinstance(runtime_shap_payload.get("prediction"), dict) else {}
                    final_decision = _parent_decision_from_evidence(
                        prediction_label=str(pred.get("label") or ""),
                        prediction_confidence=float(pred.get("confidence")) if pred.get("confidence") is not None else None,
                        top_rule_severity=str(top_rule.get("severity") or "low"),
                        cross_scope=bool(rule_eval_context.get("cross_scope_flag")),
                    )
                    write_audit_event(
                        event_type="step3_parent_decision_made",
                        actor="model-v1-step3-replay-worker",
                        artifact_refs=[],
                        context={
                            "child_id": cid,
                            "replay_run_id": replay_run_id,
                            "simulation_session_id": simulation_session_id,
                            "decision": final_decision,
                            "prediction": pred,
                            "rule_match_count": len(deterministic_matches),
                        },
                        dataset_id="REP-01",
                        experiment_id="exp_model_v1_step3_replay",
                        model_version=model_version,
                        replay_id=replay_run_id,
                    )
                    if deterministic_matches:
                        alert_payload = _insert_step3_alert(
                            replay_run_id=replay_run_id,
                            replay_id=prep_replay_id,
                            run_id=None,
                            model_id=runtime_bundle_model_id,
                            model_version=model_version,
                            child_id=cid,
                            child_type=ctype,
                            rulepack_version=str(rule_sync.get("rulepack_version") or c.get("rulepack_version") or ""),
                            rule_version=str(rule_sync.get("rulepack_version") or c.get("rulepack_version") or ""),
                            pcap_artifact_id=str(pcap_catalog_by_path.get(str(pcap_path or "")) or ""),
                            interaction_id=parent_review_interaction_id or (inserted_interaction_ids[0] if inserted_interaction_ids else None),
                            parent_action_id=parent_action_id,
                            parent_decision_id=parent_action_id,
                            rule_matches=deterministic_matches,
                            decision=final_decision,
                            shap_payload=runtime_shap_payload,
                            shap_evidence_id=shap_log_id,
                            context=rule_eval_context,
                            db_cursor=cur,
                            defer_buffer=STEP3_ALERT_DEFER_TO_BUFFER,
                        )
                        _db_timeline_row(
                            cur,
                            replay_run_id,
                            "alert_published",
                            cid,
                            {
                                "alert_id": alert_payload.get("alert_id"),
                                "urgency": alert_payload.get("urgency"),
                                "severity": alert_payload.get("severity"),
                                "recommendation": alert_payload.get("recommendation"),
                                "model_id": runtime_bundle_model_id,
                                "model_version": model_version,
                            },
                            simulation_session_id=simulation_session_id,
                        )
                        write_audit_event(
                            event_type="step3_alert_published",
                            actor="model-v1-step3-replay-worker",
                            artifact_refs=[],
                            context={
                                "alert_id": alert_payload.get("alert_id"),
                                "urgency": alert_payload.get("urgency"),
                                "child_id": cid,
                                "replay_run_id": replay_run_id,
                                "simulation_session_id": simulation_session_id,
                                "parent_action_id": parent_action_id,
                            },
                            dataset_id="REP-01",
                            experiment_id="exp_model_v1_step3_replay",
                            model_version=model_version,
                            replay_id=replay_run_id,
                        )
                    cur.execute(
                        """
                        UPDATE phase4.child_stacks
                        SET replay_status='completed',
                            model_id = %(model_id)s::uuid,
                            model_version = %(model_version)s,
                            replay_receive_count = COALESCE(replay_receive_count, 0) + %(recv)s,
                            alert_count = COALESCE(alert_count, 0) + %(alerts)s,
                            escalation_count = COALESCE(escalation_count, 0) + %(escalations)s,
                            captured_event_count = captured_event_count + %(alerts)s,
                            escalated_event_count = escalated_event_count + %(escalations)s,
                            rule_ready_status = %(rule_ready_status)s,
                            last_heartbeat_utc = now(),
                            updated_at_utc = now()
                        WHERE child_id = %(child_id)s;
                        """,
                        {
                            "child_id": cid,
                            "model_id": model_id,
                            "model_version": model_version,
                            "recv": packets_received,
                            "alerts": alerts_to_store,
                            "escalations": escalations_to_store,
                            "rule_ready_status": "ready" if rule_sync.get("ok") else "failed",
                        },
                    )
                    _db_timeline_row(
                        cur,
                        replay_run_id,
                        "dashboard_audit_updated",
                        cid,
                        {"replay_stream_id": sid},
                        simulation_session_id=simulation_session_id,
                    )
                if STEP3_ALERT_DEFER_TO_BUFFER:
                    _flush_step3_alert_buffer(cur, replay_run_id)
                cur.execute(
                    """
                    UPDATE phase4.replay_runs
                    SET status=%(status)s, active_streams=0, finished_at_utc=now(), updated_at_utc=now(),
                        error_message=%(error_message)s,
                        metadata = COALESCE(metadata, '{}'::jsonb) || %(meta_patch)s::jsonb
                    WHERE replay_run_id = %(rid)s::uuid;
                    """,
                    {
                        "rid": replay_run_id,
                        "status": "failed" if strict_runtime_errors else "completed",
                        "error_message": "strict_acceptance_runtime_failed" if strict_runtime_errors else None,
                        "meta_patch": json.dumps(
                            {
                                "strict_acceptance_status": "failed" if strict_runtime_errors else "passed",
                                "strict_acceptance_errors": strict_runtime_errors,
                            }
                        ),
                    },
                )
                cur.execute(
                    """
                    UPDATE phase4.step3_simulation_sessions
                    SET status=%(ss)s, stopped_at_utc=now(), updated_at_utc=now(),
                        metadata = COALESCE(metadata, '{}'::jsonb) || %(sm)s::jsonb
                    WHERE session_id = %(sid)s::uuid;
                    """,
                    {
                        "sid": simulation_session_id,
                        "ss": "failed" if strict_runtime_errors else "completed",
                        "sm": json.dumps(
                            {
                                "replay_terminal": "failed" if strict_runtime_errors else "completed",
                                "strict_acceptance_errors": strict_runtime_errors,
                            }
                        ),
                    },
                )
            conn.commit()
    finally:
        simulation_set_running(False)

    step3_root = _storage_root(data_root)
    for sub in (
        "child_stacks",
        "replay_runs",
        "replay_streams",
        "parent_child_interactions",
        "parent_actions",
        "network_logs",
        "audit",
    ):
        (step3_root / sub).mkdir(parents=True, exist_ok=True)
    artifact = step3_root / "replay_runs" / f"replay_run__{replay_run_id}.json"
    artifact_payload = {
        "replay_run_id": replay_run_id,
        "simulation_session_id": simulation_session_id,
        "status": "failed" if strict_runtime_errors else "completed",
        "replay_profile": profile,
        "child_count": len(target_ids),
        "execution_mode": exec_mode,
        "is_simulated": is_simulated,
        "strict_acceptance": strict_acceptance,
        "strict_acceptance_status": "failed" if strict_runtime_errors else "passed",
        "strict_acceptance_errors": strict_runtime_errors,
        "metric_provenance": _metric_provenance(payload),
        "generated_at_utc": _now(),
    }
    checksum = write_json_artifact(artifact, artifact_payload)
    write_audit_event(
        event_type=REPLAY_STARTED,
        actor="model-v1-step3-replay-worker",
        artifact_refs=[str(artifact)],
        context={
            "replay_run_id": replay_run_id,
            "simulation_session_id": simulation_session_id,
            "profile": profile,
            "targets": target_ids,
        },
        experiment_id="exp_model_v1_step3_replay",
        model_version=model_version,
        replay_id=replay_run_id,
    )
    write_audit_event(
        event_type=REPLAY_COMPLETED if not strict_runtime_errors else "step3_replay_strict_failed",
        actor="model-v1-step3-replay-worker",
        artifact_refs=[str(artifact)],
        context={
            "replay_run_id": replay_run_id,
            "simulation_session_id": simulation_session_id,
            "checksum_sha256": checksum,
            "strict_acceptance": strict_acceptance,
            "strict_acceptance_errors": strict_runtime_errors,
        },
        experiment_id="exp_model_v1_step3_replay",
        model_version=model_version,
        replay_id=replay_run_id,
    )
    return {
        "ok": not strict_runtime_errors,
        "replay_run_id": replay_run_id,
        "simulation_session_id": simulation_session_id,
        "artifact_path": str(artifact),
        "checksum_sha256": checksum,
        "execution_mode": exec_mode,
        "is_simulated": is_simulated,
        "strict_acceptance": strict_acceptance,
        "strict_acceptance_status": "failed" if strict_runtime_errors else "passed",
        "strict_acceptance_errors": strict_runtime_errors,
        "metric_provenance": _metric_provenance(payload),
        "deprecated_fields": ["legacy_derived_status_chain"],
    }


def replay_status() -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT replay_run_id::text, workflow_id, model_id::text, model_version, replay_profile, status, active_streams,
                       started_at_utc, finished_at_utc, error_message, metadata,
                       simulation_session_id::text, preparation_replay_id::text,
                       run_id::text, replay_id::text, created_at_utc
                FROM phase4.replay_runs
                ORDER BY created_at_utc DESC
                LIMIT 1;
                """
            )
            row = cur.fetchone()
            if not row:
                return {
                    "ok": True,
                    "status": "running" if _STEP3_DOCKER_REPLAY_STATE.get("running") else "idle",
                    "message": "No replay run",
                    "sim_id": None,
                    "run_id": None,
                    "created_at_utc": None,
                    "created_at_ist": None,
                    "started_at": None,
                    "started_at_ist": None,
                    "finished_at": None,
                    "finished_at_ist": None,
                    "orchestration": "docker_factory" if _step3_docker_enabled() else "in_process",
                    "factory_container": _STEP3_DOCKER_REPLAY_STATE.get("factory_container"),
                    "inflight_replay_run_id": _STEP3_DOCKER_REPLAY_STATE.get("replay_run_id"),
                    "execution_mode": _execution_mode(),
                    "is_simulated": _is_simulation_mode(),
                    "detection_profile": "high_recall",
                    "alert_threshold_profile": "aggressive",
                    "window_sizes_s": [1, 5, 30],
                    "metric_provenance": _metric_provenance(None),
                }
            meta = row[10] or {}
            status = str(row[5] or "").strip().lower()
            orchestration = str(meta.get("orchestration") or "docker_factory").strip().lower()
            started_at = row[7]
            started_age_s = 0.0
            if started_at is not None:
                try:
                    started_age_s = max(0.0, (datetime.now(timezone.utc) - started_at).total_seconds())
                except Exception:
                    started_age_s = 0.0
            # Reconcile stale "running" state if DB still says running but container/process is gone.
            if status == "running" and orchestration == "docker_factory":
                inflight_id = str(_STEP3_DOCKER_REPLAY_STATE.get("replay_run_id") or "").strip()
                inmem_running = bool(_STEP3_DOCKER_REPLAY_STATE.get("running")) and inflight_id == str(row[0]).strip()
                container_hint = str(_STEP3_DOCKER_REPLAY_STATE.get("factory_container") or meta.get("factory_container") or "").strip()
                container_running = False
                container_state = "container_unknown"
                if container_hint:
                    container_running, container_state = _docker_container_running(container_hint)
                stale_container_state = (
                    container_state in {"false", "exited", "dead", "created", "unknown_state"}
                    or "no such object" in container_state.lower()
                    or "not found" in container_state.lower()
                )
                stale_running = (
                    (started_age_s >= 45.0)
                    and ((not container_hint) or (not container_running and stale_container_state))
                    and (
                        (not inmem_running)
                        or stale_container_state
                    )
                )
                if stale_running:
                    artifact_promoted = False
                    result_path = str(meta.get("factory_result_path") or "").strip()
                    if result_path:
                        rp = Path(result_path)
                        if rp.exists() and rp.is_file():
                            try:
                                parsed = json.loads(rp.read_text(encoding="utf-8"))
                            except Exception:
                                parsed = {}
                            if isinstance(parsed, dict) and bool(parsed.get("ok")):
                                artifact_promoted = True
                                cur.execute(
                                    """
                                    UPDATE phase4.replay_runs
                                    SET status='completed', active_streams=0, finished_at_utc=now(), updated_at_utc=now(),
                                        metadata = COALESCE(metadata, '{}'::jsonb) || %(meta)s::jsonb
                                    WHERE replay_run_id = %(rid)s::uuid
                                      AND status = 'running'
                                    RETURNING replay_run_id::text, workflow_id, model_id::text, model_version, replay_profile, status, active_streams,
                                              started_at_utc, finished_at_utc, error_message, metadata,
                                              simulation_session_id::text, preparation_replay_id::text,
                                              run_id::text, replay_id::text;
                                    """,
                                    {
                                        "rid": str(row[0]),
                                        "meta": json.dumps({"factory_result": parsed, "artifact_reconcile": "auto_completed_from_result_path"}),
                                    },
                                )
                    if not artifact_promoted:
                        reason = f"stale_replay_status:{container_state}"
                        cur.execute(
                            """
                            UPDATE phase4.replay_runs
                            SET status='failed', active_streams=0, finished_at_utc=now(), updated_at_utc=now(),
                                error_message = CASE
                                    WHEN COALESCE(NULLIF(error_message, ''), '') <> '' THEN error_message
                                    ELSE %(err)s
                                END
                            WHERE replay_run_id = %(rid)s::uuid
                              AND status = 'running'
                            RETURNING replay_run_id::text, workflow_id, model_id::text, model_version, replay_profile, status, active_streams,
                                      started_at_utc, finished_at_utc, error_message, metadata,
                                      simulation_session_id::text, preparation_replay_id::text,
                                      run_id::text, replay_id::text;
                            """,
                            {"rid": str(row[0]), "err": reason},
                        )
                    patched = cur.fetchone()
                    sid = str(row[11] or "").strip() if len(row) > 11 else ""
                    if sid:
                        cur.execute(
                            """
                            UPDATE phase4.step3_simulation_sessions
                            SET status=%(status)s, stopped_at_utc=now(), updated_at_utc=now(), active_replay_run_id=%(rid)s::uuid
                            WHERE session_id = %(sid)s::uuid
                              AND status = 'running';
                            """,
                            {"sid": sid, "rid": str(row[0]), "status": "completed" if artifact_promoted else "failed"},
                        )
                    if patched:
                        row = patched
                        meta = row[10] or {}
                    conn.commit()
            metrics_row = get_step3_replay_metrics(replay_run_id=str(row[0]))
            return {
                "ok": True,
                "replay_run_id": row[0],
                "workflow_id": row[1],
                "model_id": row[2],
                "model_version": row[3],
                "replay_profile": row[4],
                "status": row[5],
                "active_streams": int(row[6] or 0),
                "started_at": row[7].isoformat() if row[7] else None,
                "started_at_ist": _to_ist_iso(row[7]),
                "finished_at": row[8].isoformat() if row[8] else None,
                "finished_at_ist": _to_ist_iso(row[8]),
                "created_at_utc": _to_utc_iso(row[15] if len(row) > 15 else None),
                "created_at_ist": _to_ist_iso(row[15] if len(row) > 15 else None),
                "error_message": row[9],
                "metadata": meta,
                "simulation_session_id": row[11] if len(row) > 11 else None,
                "preparation_replay_id": row[12] if len(row) > 12 else None,
                "run_id": row[13] if len(row) > 13 else None,
                "sim_id": row[14] if len(row) > 14 else (row[12] if len(row) > 12 else None),
                "orchestration": "docker_factory" if _step3_docker_enabled() else "in_process",
                "factory_container": _STEP3_DOCKER_REPLAY_STATE.get("factory_container"),
                "execution_mode": str(meta.get("execution_mode") or _execution_mode()),
                "is_simulated": bool(meta.get("is_simulated", _is_simulation_mode())),
                "strict_acceptance": _to_bool(
                    meta.get("strict_acceptance"),
                    default=(STEP3_STRICT_ACCEPTANCE_DEFAULT if str(meta.get("execution_mode") or _execution_mode()) == "production" else False),
                ),
                "strict_acceptance_status": meta.get("strict_acceptance_status"),
                "strict_acceptance_errors": meta.get("strict_acceptance_errors") or [],
                "detection_profile": str(meta.get("detection_profile") or "high_recall"),
                "alert_threshold_profile": str(meta.get("alert_threshold_profile") or "aggressive"),
                "window_sizes_s": list(meta.get("window_sizes_s") or [1, 5, 30]),
                "metric_provenance": meta.get("metric_provenance") or _metric_provenance(None),
                "dissertation_metrics": (metrics_row or {}).get("metrics") or meta.get("dissertation_metrics") or {},
                "dissertation_metrics_updated_at": (metrics_row or {}).get("updated_at"),
            }


def replay_runs() -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT replay_run_id::text, workflow_id, model_id::text, model_version, replay_profile, status, active_streams,
                       started_at_utc, finished_at_utc, error_message, metadata,
                       simulation_session_id::text, preparation_replay_id::text,
                       run_id::text, replay_id::text, created_at_utc
                FROM phase4.replay_runs
                ORDER BY created_at_utc DESC
                LIMIT 100;
                """
            )
            rows = []
            for r in cur.fetchall():
                meta = r[10] or {}
                metrics_row = get_step3_replay_metrics(replay_run_id=str(r[0]))
                rows.append(
                    {
                        "replay_run_id": r[0],
                        "workflow_id": r[1],
                        "model_id": r[2],
                        "model_version": r[3],
                        "replay_profile": r[4],
                        "status": r[5],
                        "active_streams": int(r[6] or 0),
                        "started_at": r[7].isoformat() if r[7] else None,
                        "started_at_ist": _to_ist_iso(r[7]),
                        "finished_at": r[8].isoformat() if r[8] else None,
                        "finished_at_ist": _to_ist_iso(r[8]),
                        "created_at_utc": _to_utc_iso(r[15] if len(r) > 15 else None),
                        "created_at_ist": _to_ist_iso(r[15] if len(r) > 15 else None),
                        "error_message": r[9],
                        "metadata": meta,
                        "simulation_session_id": r[11] if len(r) > 11 else None,
                        "preparation_replay_id": r[12] if len(r) > 12 else None,
                        "run_id": r[13] if len(r) > 13 else None,
                        "sim_id": r[14] if len(r) > 14 else (r[12] if len(r) > 12 else None),
                        "execution_mode": str(meta.get("execution_mode") or _execution_mode()),
                        "is_simulated": bool(meta.get("is_simulated", _is_simulation_mode())),
                        "strict_acceptance": _to_bool(
                            meta.get("strict_acceptance"),
                            default=(STEP3_STRICT_ACCEPTANCE_DEFAULT if str(meta.get("execution_mode") or _execution_mode()) == "production" else False),
                        ),
                        "strict_acceptance_status": meta.get("strict_acceptance_status"),
                        "strict_acceptance_errors": meta.get("strict_acceptance_errors") or [],
                        "detection_profile": str(meta.get("detection_profile") or "high_recall"),
                        "alert_threshold_profile": str(meta.get("alert_threshold_profile") or "aggressive"),
                        "window_sizes_s": list(meta.get("window_sizes_s") or [1, 5, 30]),
                        "metric_provenance": meta.get("metric_provenance") or _metric_provenance(None),
                        "dissertation_metrics": (metrics_row or {}).get("metrics") or meta.get("dissertation_metrics") or {},
                        "dissertation_metrics_updated_at": (metrics_row or {}).get("updated_at"),
                    }
                )
    return {"ok": True, "runs": rows}


def replay_stop() -> dict[str, Any]:
    factory = str(_STEP3_DOCKER_REPLAY_STATE.get("factory_container") or "")
    if factory:
        _run_docker(["docker", "stop", factory])
        _run_docker(["docker", "rm", "-f", factory])
    _STEP3_DOCKER_REPLAY_STATE["running"] = False
    _STEP3_DOCKER_REPLAY_STATE["factory_container"] = None
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE phase4.replay_runs
                SET status='failed', active_streams=0, finished_at_utc=now(), error_message='stopped_by_operator', updated_at_utc=now()
                WHERE replay_run_id = (
                    SELECT replay_run_id FROM phase4.replay_runs
                    WHERE status = 'running'
                    ORDER BY created_at_utc DESC
                    LIMIT 1
                )
                RETURNING replay_run_id::text, simulation_session_id::text;
                """
            )
            row = cur.fetchone()
            if row and row[1]:
                cur.execute(
                    """
                    UPDATE phase4.step3_simulation_sessions
                    SET status='stopped', stopped_at_utc=now(), updated_at_utc=now()
                    WHERE session_id = %(sid)s::uuid;
                    """,
                    {"sid": row[1]},
                )
        conn.commit()
    return {"ok": True, "stopped_run_id": row[0] if row else None}


def replay_fail_active(reason: str, *, replay_run_id: str | None = None) -> dict[str, Any]:
    rid = str(replay_run_id or "").strip()
    err = str(reason or "replay_failed").strip() or "replay_failed"
    row: tuple[str | None, str | None] | None = None
    with connect() as conn:
        with conn.cursor() as cur:
            if rid:
                cur.execute(
                    """
                    UPDATE phase4.replay_runs
                    SET status='failed',
                        active_streams=0,
                        finished_at_utc=now(),
                        updated_at_utc=now(),
                        error_message = %(err)s
                    WHERE replay_run_id = %(rid)s::uuid
                    RETURNING replay_run_id::text, simulation_session_id::text;
                    """,
                    {"rid": rid, "err": err},
                )
                row = cur.fetchone()
            if not row:
                cur.execute(
                    """
                    UPDATE phase4.replay_runs
                    SET status='failed',
                        active_streams=0,
                        finished_at_utc=now(),
                        updated_at_utc=now(),
                        error_message = %(err)s
                    WHERE replay_run_id = (
                        SELECT replay_run_id
                        FROM phase4.replay_runs
                        WHERE status = 'running'
                        ORDER BY created_at_utc DESC
                        LIMIT 1
                    )
                    RETURNING replay_run_id::text, simulation_session_id::text;
                    """,
                    {"err": err},
                )
                row = cur.fetchone()
            if row and row[1]:
                cur.execute(
                    """
                    UPDATE phase4.step3_simulation_sessions
                    SET status='failed', stopped_at_utc=now(), updated_at_utc=now()
                    WHERE session_id = %(sid)s::uuid;
                    """,
                    {"sid": row[1]},
                )
        conn.commit()
    stopped_id = str(row[0]) if row and row[0] else None
    if stopped_id:
        try:
            write_audit_event(
                event_type="step3_replay_forced_failed",
                actor="model-v1-step3-replay-watchdog",
                artifact_refs=[],
                context={"reason": err, "replay_run_id": stopped_id},
                dataset_id="REP-01",
                experiment_id="exp_model_v1_step3_replay",
                replay_id=stopped_id,
            )
        except Exception:
            pass
        if str(_STEP3_DOCKER_REPLAY_STATE.get("replay_run_id") or "").strip() == stopped_id:
            _STEP3_DOCKER_REPLAY_STATE.update(
                {
                    "running": False,
                    "factory_container": None,
                    "replay_run_id": stopped_id,
                    "last_error": err,
                }
            )
    return {"ok": True, "failed_run_id": stopped_id, "error_message": err}


def interactions(limit: int = 300) -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT interaction_id::text, replay_run_id::text, replay_stream_id::text, child_id, child_type, network_id, status, latency_ms,
                       interaction_payload, created_at_utc
                FROM phase4.parent_child_interactions
                ORDER BY created_at_utc DESC
                LIMIT %(limit)s;
                """,
                {"limit": limit},
            )
            rows = []
            for r in cur.fetchall():
                rows.append(
                    {
                        "interaction_id": r[0],
                        "replay_run_id": r[1],
                        "replay_stream_id": r[2],
                        "child_id": r[3],
                        "child_type": r[4],
                        "network_id": r[5],
                        "status": r[6],
                        "latency_ms": float(r[7]) if r[7] is not None else None,
                        "payload": r[8] or {},
                        "created_at": r[9].isoformat() if r[9] else None,
                    }
                )
    return {"ok": True, "interactions": rows}


def parent_actions(limit: int = 300) -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT parent_action_id::text, interaction_id::text, replay_run_id::text, child_id, child_type, network_id,
                       status, action_type, recommendation, action_payload, created_at_utc
                FROM phase4.parent_actions
                ORDER BY created_at_utc DESC
                LIMIT %(limit)s;
                """,
                {"limit": limit},
            )
            rows = []
            for r in cur.fetchall():
                rows.append(
                    {
                        "parent_action_id": r[0],
                        "interaction_id": r[1],
                        "replay_run_id": r[2],
                        "child_id": r[3],
                        "child_type": r[4],
                        "network_id": r[5],
                        "status": r[6],
                        "action_type": r[7],
                        "recommendation": r[8],
                        "payload": r[9] or {},
                        "created_at": r[10].isoformat() if r[10] else None,
                    }
                )
    return {"ok": True, "actions": rows}


def step3_alerts(
    *,
    model_id: str | None = None,
    model_version: str | None = None,
    replay_run_id: str | None = None,
    child_id: str | None = None,
    urgency: str | None = None,
    status: str | None = None,
    limit: int = 300,
) -> dict[str, Any]:
    lim = max(1, min(int(limit or 300), 2000))
    where = ["1=1"]
    params: dict[str, Any] = {"lim": lim}
    if model_id:
        where.append("model_id = %(model_id)s::uuid")
        params["model_id"] = model_id
    if model_version:
        where.append("model_version = %(model_version)s")
        params["model_version"] = model_version
    if replay_run_id:
        where.append("replay_run_id = %(replay_run_id)s::uuid")
        params["replay_run_id"] = replay_run_id
    if child_id:
        where.append("child_id = %(child_id)s")
        params["child_id"] = child_id
    if urgency:
        where.append("urgency = %(urgency)s")
        params["urgency"] = urgency
    if status:
        where.append("status = %(status)s")
        params["status"] = status
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT alert_id::text, replay_run_id::text, run_id::text, model_id::text, model_version, child_id, child_type,
                       rulepack_version, rule_version, pcap_artifact_id::text, interaction_id::text, parent_action_id::text, parent_decision_id::text,
                       severity, urgency, status, recommendation, expected_environment, observed_environment, cross_scope_flag, escalation_reason,
                       shap_evidence_status, shap_evidence_id, payload, created_at_utc, updated_at_utc
                FROM phase4.step3_alerts
                WHERE {' AND '.join(where)}
                ORDER BY created_at_utc DESC
                LIMIT %(lim)s;
                """,
                params,
            )
            rows = []
            for r in cur.fetchall():
                pl = r[23] or {}
                if isinstance(pl, str):
                    try:
                        pl = json.loads(pl)
                    except Exception:
                        pl = {}
                rows.append(
                    {
                        "alert_id": r[0],
                        "replay_run_id": r[1],
                        "run_id": r[2],
                        "model_id": r[3],
                        "model_version": r[4],
                        "child_id": r[5],
                        "child_type": r[6],
                        "rulepack_version": r[7],
                        "rule_version": r[8],
                        "pcap_artifact_id": r[9],
                        "interaction_id": r[10],
                        "parent_action_id": r[11],
                        "parent_decision_id": r[12],
                        "severity": r[13],
                        "urgency": r[14],
                        "status": r[15],
                        "recommendation": r[16],
                        "expected_environment": r[17],
                        "observed_environment": r[18],
                        "cross_scope_flag": bool(r[19]),
                        "escalation_reason": r[20],
                        "shap_evidence_status": r[21],
                        "shap_evidence_id": int(r[22]) if r[22] is not None else None,
                        "payload": pl if isinstance(pl, dict) else {},
                        "parent_shap": pl.get("parent_shap") if isinstance(pl, dict) else {},
                        "created_at": r[24].isoformat() if r[24] else None,
                        "updated_at": r[25].isoformat() if r[25] else None,
                    }
                )
    return {"ok": True, "alerts": rows}


def submit_analyst_feedback(payload: dict[str, Any]) -> dict[str, Any]:
    alert_id = str(payload.get("alert_id") or "").strip()
    analyst_label = str(payload.get("analyst_label") or "").strip().lower()
    alert_verdict = str(payload.get("alert_verdict") or "unknown").strip().lower()
    if not alert_id:
        return {"ok": False, "error": "alert_id_required"}
    if not analyst_label:
        return {"ok": False, "error": "analyst_label_required"}
    if alert_verdict not in {"true_positive", "false_positive", "benign", "unknown"}:
        return {"ok": False, "error": "invalid_alert_verdict"}
    try:
        usefulness_score = int(payload.get("usefulness_score"))
    except Exception:
        return {"ok": False, "error": "usefulness_score_required"}
    if usefulness_score < 1 or usefulness_score > 5:
        return {"ok": False, "error": "usefulness_score_out_of_range"}
    shap_helped = _to_bool(payload.get("shap_helped"), default=False)
    triage_comment = str(payload.get("triage_comment") or "").strip() or None
    triage_duration_ms = None
    if payload.get("triage_duration_ms") is not None and str(payload.get("triage_duration_ms")).strip() != "":
        try:
            triage_duration_ms = max(0, int(payload.get("triage_duration_ms")))
        except Exception:
            return {"ok": False, "error": "invalid_triage_duration_ms"}
    replay_id = _uuid_or_none(payload.get("replay_id"))
    replay_run_id = _uuid_or_none(payload.get("replay_run_id"))
    model_id = _uuid_or_none(payload.get("model_id"))
    model_version = str(payload.get("model_version") or "").strip() or None
    rulepack_version = str(payload.get("rulepack_version") or "").strip() or None
    child_id = str(payload.get("child_id") or "").strip() or None

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT replay_id::text, replay_run_id::text, model_id::text, model_version, rulepack_version, child_id
                FROM phase4.step3_alerts
                WHERE alert_id = %(alert_id)s::uuid
                LIMIT 1;
                """,
                {"alert_id": alert_id},
            )
            alert_row = cur.fetchone()
            if not alert_row:
                return {"ok": False, "error": "alert_not_found"}
            replay_id = replay_id or _uuid_or_none(alert_row[0])
            replay_run_id = replay_run_id or _uuid_or_none(alert_row[1])
            model_id = model_id or _uuid_or_none(alert_row[2])
            model_version = model_version or (str(alert_row[3] or "").strip() or None)
            rulepack_version = rulepack_version or (str(alert_row[4] or "").strip() or None)
            child_id = child_id or (str(alert_row[5] or "").strip() or None)
            feedback_id = str(uuid.uuid4())
            cur.execute(
                """
                INSERT INTO phase4.step3_analyst_feedback (
                    feedback_id, alert_id, replay_id, replay_run_id, model_id, model_version, rulepack_version, child_id,
                    analyst_label, usefulness_score, shap_helped, alert_verdict, triage_comment, triage_duration_ms, feedback_payload,
                    created_at_utc, updated_at_utc
                ) VALUES (
                    %(feedback_id)s::uuid, %(alert_id)s::uuid,
                    CASE WHEN %(replay_id)s='' THEN NULL ELSE %(replay_id)s::uuid END,
                    CASE WHEN %(replay_run_id)s='' THEN NULL ELSE %(replay_run_id)s::uuid END,
                    CASE WHEN %(model_id)s='' THEN NULL ELSE %(model_id)s::uuid END,
                    %(model_version)s, %(rulepack_version)s, %(child_id)s,
                    %(analyst_label)s, %(usefulness_score)s, %(shap_helped)s, %(alert_verdict)s, %(triage_comment)s, %(triage_duration_ms)s,
                    %(feedback_payload)s::jsonb, now(), now()
                );
                """,
                {
                    "feedback_id": feedback_id,
                    "alert_id": alert_id,
                    "replay_id": replay_id or "",
                    "replay_run_id": replay_run_id or "",
                    "model_id": model_id or "",
                    "model_version": model_version,
                    "rulepack_version": rulepack_version,
                    "child_id": child_id,
                    "analyst_label": analyst_label,
                    "usefulness_score": usefulness_score,
                    "shap_helped": shap_helped,
                    "alert_verdict": alert_verdict,
                    "triage_comment": triage_comment,
                    "triage_duration_ms": triage_duration_ms,
                    "feedback_payload": json.dumps(
                        {
                            "source": "dashboard_api",
                            "submitted_at": _now(),
                        }
                    ),
                },
            )
        conn.commit()
    return {
        "ok": True,
        "feedback_id": feedback_id,
        "alert_id": alert_id,
        "replay_id": replay_id,
        "replay_run_id": replay_run_id,
        "model_id": model_id,
        "model_version": model_version,
    }


def analyst_feedback(
    *,
    alert_id: str | None = None,
    replay_id: str | None = None,
    replay_run_id: str | None = None,
    model_version: str | None = None,
    limit: int = 300,
) -> dict[str, Any]:
    lim = max(1, min(int(limit or 300), 2000))
    where = ["1=1"]
    params: dict[str, Any] = {"lim": lim}
    if alert_id:
        where.append("f.alert_id = %(alert_id)s::uuid")
        params["alert_id"] = alert_id
    if replay_id:
        where.append("f.replay_id = %(replay_id)s::uuid")
        params["replay_id"] = replay_id
    if replay_run_id:
        where.append("f.replay_run_id = %(replay_run_id)s::uuid")
        params["replay_run_id"] = replay_run_id
    if model_version:
        where.append("f.model_version = %(model_version)s")
        params["model_version"] = model_version
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT f.feedback_id::text, f.alert_id::text, f.replay_id::text, f.replay_run_id::text, f.model_id::text, f.model_version,
                       f.rulepack_version, f.child_id, f.analyst_label, f.usefulness_score, f.shap_helped, f.alert_verdict,
                       f.triage_comment, f.triage_duration_ms, f.feedback_payload, f.created_at_utc, f.updated_at_utc
                FROM phase4.step3_analyst_feedback f
                WHERE {' AND '.join(where)}
                ORDER BY f.created_at_utc DESC
                LIMIT %(lim)s;
                """,
                params,
            )
            rows = []
            for r in cur.fetchall():
                pl = r[14] or {}
                if isinstance(pl, str):
                    try:
                        pl = json.loads(pl)
                    except Exception:
                        pl = {}
                rows.append(
                    {
                        "feedback_id": r[0],
                        "alert_id": r[1],
                        "replay_id": r[2],
                        "replay_run_id": r[3],
                        "model_id": r[4],
                        "model_version": r[5],
                        "rulepack_version": r[6],
                        "child_id": r[7],
                        "analyst_label": r[8],
                        "usefulness_score": int(r[9]) if r[9] is not None else None,
                        "shap_helped": bool(r[10]),
                        "alert_verdict": r[11],
                        "triage_comment": r[12],
                        "triage_duration_ms": int(r[13]) if r[13] is not None else None,
                        "feedback_payload": pl if isinstance(pl, dict) else {},
                        "created_at": r[15].isoformat() if r[15] else None,
                        "updated_at": r[16].isoformat() if r[16] else None,
                    }
                )
    return {"ok": True, "feedback": rows}


def network_status() -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT network_id, child_id, child_type, status, docker_network_name, isolated, started_at_utc, finished_at_utc, error_message, metadata
                FROM phase4.replay_networks
                ORDER BY child_id;
                """
            )
            rows = []
            for r in cur.fetchall():
                rows.append(
                    {
                        "network_id": r[0],
                        "child_id": r[1],
                        "child_type": r[2],
                        "status": r[3],
                        "docker_network_name": r[4],
                        "isolated": bool(r[5]),
                        "started_at": r[6].isoformat() if r[6] else None,
                        "finished_at": r[7].isoformat() if r[7] else None,
                        "error_message": r[8],
                        "metadata": r[9] or {},
                    }
                )
    rows.append(
        {
            "network_id": SIMULATION_NETWORK_ID,
            "child_id": None,
            "child_type": "simulation",
            "status": "defined",
            "docker_network_name": SIMULATION_NETWORK_ID,
            "isolated": True,
            "started_at": None,
            "finished_at": None,
            "error_message": None,
            "metadata": {"network_role": "simulation_replay", "no_parent_attachment": True},
        }
    )
    rows.append(
        {
            "network_id": PARENT_MANAGEMENT_NETWORK_ID,
            "child_id": None,
            "child_type": "parent",
            "status": "defined",
            "docker_network_name": PARENT_MANAGEMENT_NETWORK_ID,
            "isolated": True,
            "started_at": None,
            "finished_at": None,
            "error_message": None,
            "metadata": {"network_role": "parent_management", "simulation_may_not_attach": True},
        }
    )
    return {"ok": True, "networks": rows}


_ADAPTER_SURFACE: dict[str, Any] = {
    "running": False,
    "pcap_loaded": False,
    "replay_phase": None,
    "active_workers": 0,
    "sent": 0,
    "dropped": 0,
    "errors": 0,
    "last_error": None,
    "recent_logs": [],
    "execution_mode": STEP3_EXECUTION_MODE,
    "is_simulated": STEP3_EXECUTION_MODE == "simulation",
    "metric_provenance": _metric_provenance(None),
}


def network_topology() -> dict[str, Any]:
    _ensure_templates()
    _ensure_default_child_stacks()
    children = list_child_stacks().get("children", [])
    nodes: list[dict[str, Any]] = [
        {
            "id": "simulation_stack",
            "label": "Simulation Stack",
            "stack_group": "simulation",
            "networks": [SIMULATION_NETWORK_ID],
            "policies": ["push_replay_to_child_client_listener_only"],
        },
        {
            "id": "parent_stack",
            "label": "Parent Stack",
            "stack_group": "parent",
            "networks": [PARENT_MANAGEMENT_NETWORK_ID],
            "policies": ["child_management_only", "model_v1_review"],
        },
    ]
    for c in children:
        cid = c["child_id"]
        nodes.append(
            {
                "id": f"child:{cid}",
                "label": cid,
                "stack_group": "child",
                "child_id": cid,
                "child_type": c.get("child_type"),
                "region": c.get("region") or c.get("assigned_scope"),
                "client_listener_port": c.get("client_listener_port"),
                "management_port": c.get("management_port"),
                "client_network_id": c.get("client_network_id"),
                "management_network_id": c.get("management_network_id"),
                "db_network_id": _child_db_network_id(cid),
                "health_status": c.get("health_status"),
                "rule_ready_status": c.get("rule_ready_status"),
            }
        )
    edges: list[dict[str, Any]] = [
        {
            "from": "simulation_stack",
            "to": "child:*:client_listener",
            "kind": "replay_traffic",
            "blocked": False,
            "description": "PCAP adapter → UDP/TCP client listener ports",
        },
        {
            "from": "child:*:management",
            "to": "parent_stack",
            "kind": "management",
            "blocked": False,
            "description": "Health, rulepack sync, escalations, Parent actions",
        },
        {
            "from": "child:*:db",
            "to": "phase4-postgres",
            "kind": "data_plane",
            "blocked": False,
            "description": "Per-stack isolated Postgres data network",
        },
        {
            "from": "simulation_stack",
            "to": "parent_stack",
            "kind": "management_or_api",
            "blocked": True,
            "description": "No direct Simulation → Parent path (enforced in compose + routing policy)",
        },
    ]
    return {"ok": True, "nodes": nodes, "edges": edges, "children": children}


def simulation_start(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    session_id = str(uuid.uuid4())
    prep = step3_prepare(payload)
    if not bool(prep.get("ok")):
        return {
            "ok": False,
            "error": str(prep.get("error") or "step3_prepare_failed"),
            "detail": prep,
        }
    mv = str(prep.get("model_version") or payload.get("model_version") or "").strip()
    mid = str(prep.get("model_id") or payload.get("model_id") or "").strip()
    prep_replay_id = (
        _uuid_or_none(prep.get("preparation_replay_id"))
        or _preparation_replay_id(payload)
        or _latest_preparation_replay_id(mv)
    )
    phase = str(payload.get("current_phase") or "preparation").strip() or "preparation"
    meta = dict(payload)
    meta["prepared_ok"] = bool(prep.get("ok"))
    if prep_replay_id:
        meta["preparation_replay_id"] = prep_replay_id
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.step3_simulation_sessions (
                    session_id, status, metadata, started_at_utc,
                    current_phase, model_id, model_version, replay_id, run_kind, updated_at_utc
                )
                VALUES (
                    %(sid)s::uuid, 'running', %(meta)s::jsonb, now(),
                    %(phase)s,
                    CASE WHEN %(mid)s = '' THEN NULL ELSE %(mid)s::uuid END,
                    CASE WHEN %(mv)s = '' THEN NULL ELSE %(mv)s END,
                    CASE WHEN %(replay_id)s = '' THEN NULL ELSE %(replay_id)s::uuid END,
                    'stack', now()
                );
                """,
                {
                    "sid": session_id,
                    "meta": json.dumps(meta),
                    "phase": phase,
                    "mid": mid,
                    "mv": mv,
                    "replay_id": _audit_replay_id(preparation_replay_id=prep_replay_id, replay_run_id=None) or "",
                },
            )
        conn.commit()
    simulation_set_running(True, simulation_session_id=session_id)
    _ensure_docker_network(SIMULATION_NETWORK_ID)
    return {
        "ok": True,
        "session_id": session_id,
        "status": "running",
        "current_phase": phase,
        "model_version": mv or None,
        "model_id": mid or None,
        "preparation_replay_id": prep_replay_id,
        "orchestration": "docker_factory" if _step3_docker_enabled() else "in_process",
    }


def simulation_stop() -> dict[str, Any]:
    simulation_set_running(False)
    children_rows = list(list_child_stacks().get("children") or [])
    child_ids = [str(c.get("child_id") or "").strip() for c in children_rows if str(c.get("child_id") or "").strip()]
    removed_child_containers: list[str] = []
    removed_factory_containers: list[str] = []
    removal_errors: list[dict[str, Any]] = []
    for child_id in child_ids:
        unregister_remote_runtime(child_id)
        if not _step3_docker_enabled():
            stop_child_runtime(child_id)
            continue
        cname = _child_container_name(child_id)
        ok_rm, err_rm = _docker_remove_container(cname)
        if ok_rm:
            removed_child_containers.append(cname)
        else:
            removal_errors.append({"container": cname, "error": err_rm or "docker_rm_failed"})
    if _step3_docker_enabled():
        known_removed = set(removed_child_containers)
        discovered = _docker_containers_with_prefixes(
            ("ids-step3-child-", "ids-step3-factory-", "ids-step3-factory-probe-")
        )
        for cname in discovered:
            if cname in known_removed:
                continue
            ok_rm, err_rm = _docker_remove_container(cname)
            if ok_rm:
                if cname.startswith("ids-step3-child-"):
                    removed_child_containers.append(cname)
                else:
                    removed_factory_containers.append(cname)
            else:
                removal_errors.append({"container": cname, "error": err_rm or "docker_rm_failed"})
    _STEP3_DOCKER_REPLAY_STATE.update(
        {
            "running": False,
            "factory_container": None,
            "replay_run_id": None,
            "last_error": "stopped_by_operator",
        }
    )
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE phase4.replay_runs
                SET status='failed',
                    active_streams=0,
                    finished_at_utc=COALESCE(finished_at_utc, now()),
                    updated_at_utc=now(),
                    error_message=COALESCE(error_message, 'stopped_by_operator')
                WHERE status='running'
                RETURNING replay_run_id::text;
                """
            )
            stopped_replay_rows = cur.fetchall() or []
            cur.execute(
                """
                UPDATE phase4.step3_simulation_sessions
                SET status='stopped', stopped_at_utc=now(), updated_at_utc=now()
                WHERE status='running'
                RETURNING session_id::text;
                """
            )
            stopped_session_rows = cur.fetchall() or []
            if child_ids:
                cur.execute(
                    """
                    UPDATE phase4.child_stacks
                    SET status='removed',
                        health_status='stopped',
                        parent_connection_status='disconnected',
                        replay_status='halted',
                        finished_at_utc=now(),
                        updated_at_utc=now(),
                        metadata = COALESCE(metadata, '{}'::jsonb) || %(meta)s::jsonb,
                        error_message=NULL
                    WHERE child_id = ANY(%(child_ids)s);
                    """,
                    {
                        "child_ids": child_ids,
                        "meta": json.dumps(
                            {
                                "teardown": {
                                    "trigger": "simulation_stop",
                                    "container_action": "removed",
                                    "at_utc": _now(),
                                }
                            }
                        ),
                    },
                )
                cur.execute(
                    """
                    UPDATE phase4.replay_networks
                    SET status='removed',
                        finished_at_utc=now(),
                        updated_at_utc=now(),
                        error_message=COALESCE(error_message, 'stopped_by_operator'),
                        metadata = COALESCE(metadata, '{}'::jsonb) || %(meta)s::jsonb
                    WHERE child_id = ANY(%(child_ids)s);
                    """,
                    {
                        "child_ids": child_ids,
                        "meta": json.dumps({"teardown": {"trigger": "simulation_stop", "at_utc": _now()}}),
                    },
                )
                for child in children_rows:
                    cid = str(child.get("child_id") or "").strip()
                    if not cid:
                        continue
                    cur.execute(
                        """
                        INSERT INTO phase4.child_stack_health (
                            health_id, child_id, workflow_id, child_type, network_id, status, checks_json, heartbeat_at_utc, created_at_utc, updated_at_utc
                        )
                        VALUES (
                            %(id)s::uuid, %(child_id)s, 'model_v1_step3_replay_simulation', %(child_type)s, %(network_id)s, 'removed',
                            %(checks)s::jsonb, now(), now(), now()
                        );
                        """,
                        {
                            "id": str(uuid.uuid4()),
                            "child_id": cid,
                            "child_type": str(child.get("child_type") or "unknown"),
                            "network_id": str(child.get("client_network_id") or child.get("network_id") or ""),
                            "checks": json.dumps(
                                {
                                    "action": "simulation_stop",
                                    "container_removed": True,
                                    "replay_status": "halted",
                                }
                            ),
                        },
                    )
        conn.commit()
    stopped_replay_ids = [str(r[0]) for r in stopped_replay_rows if r and r[0]]
    stopped_session_ids = [str(r[0]) for r in stopped_session_rows if r and r[0]]
    try:
        write_audit_event(
            event_type="step3_simulation_stopped_by_operator",
            actor="model-v1-step3-simulation-stop",
            artifact_refs=[],
            context={
                "stopped_replay_ids": stopped_replay_ids,
                "stopped_session_ids": stopped_session_ids,
                "removed_child_containers": removed_child_containers,
                "removed_factory_containers": removed_factory_containers,
                "errors": removal_errors,
            },
            experiment_id="exp_model_v1_step3_replay",
            replay_id=(stopped_replay_ids[0] if stopped_replay_ids else None),
        )
    except Exception:
        pass
    return {
        "ok": len(removal_errors) == 0,
        "stopped_session_ids": stopped_session_ids,
        "stopped_replay_ids": stopped_replay_ids,
        "removed_child_containers": sorted(set(removed_child_containers)),
        "removed_factory_containers": sorted(set(removed_factory_containers)),
        "errors": removal_errors,
    }


def simulation_status() -> dict[str, Any]:
    st = simulation_process_state()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT session_id::text, status, started_at_utc, stopped_at_utc, metadata,
                       current_phase, model_version, model_id::text, preparation_verified_at,
                       active_replay_run_id::text
                FROM phase4.step3_simulation_sessions
                ORDER BY started_at_utc DESC
                LIMIT 1;
                """
            )
            row = cur.fetchone()
    return {
        "ok": True,
        "process": st,
        "execution_mode": _execution_mode(),
        "is_simulated": _is_simulation_mode(),
        "orchestration": "docker_factory" if _step3_docker_enabled() else "in_process",
        "docker_replay_state": dict(_STEP3_DOCKER_REPLAY_STATE),
        "metric_provenance": _metric_provenance(None),
        "last_session": (
            {
                "session_id": row[0],
                "status": row[1],
                "started_at": row[2].isoformat() if row[2] else None,
                "started_at_ist": _to_ist_iso(row[2]),
                "stopped_at": row[3].isoformat() if row[3] else None,
                "stopped_at_ist": _to_ist_iso(row[3]),
                "metadata": row[4] or {},
                "current_phase": row[5] if len(row) > 5 else None,
                "model_version": row[6] if len(row) > 6 else None,
                "model_id": row[7] if len(row) > 7 else None,
                "preparation_verified_at": row[8].isoformat() if len(row) > 8 and row[8] else None,
                "preparation_verified_at_ist": _to_ist_iso(row[8] if len(row) > 8 else None),
                "active_replay_run_id": row[9] if len(row) > 9 else None,
            }
            if row
            else None
        ),
    }


def adapter_run(payload: dict[str, Any], data_root: Path) -> dict[str, Any]:
    global _ADAPTER_SURFACE  # noqa: PLW0603
    exec_mode = _execution_mode(payload)
    is_simulated = exec_mode == "simulation"
    paths = resolve_rep01_pcap_paths(data_root)
    pcap_path = paths[0] if paths else None
    chunks, seg = segment_pcap_into_chunks(pcap_path, execution_mode=exec_mode)
    if not chunks and str(seg.get("error") or ""):
        return {
            "ok": False,
            "error": str(seg.get("error")),
            "execution_mode": exec_mode,
            "is_simulated": is_simulated,
            "metric_provenance": _metric_provenance(payload),
        }
    _ADAPTER_SURFACE = {
        "running": True,
        "pcap_loaded": bool(pcap_path),
        "replay_phase": REPLAY_PHASES[0],
        "active_workers": min(STEP3_ADAPTER_WORKERS, STEP3_FACTORY_STACK_THREADS, len(chunks) or 1),
        "sent": 0,
        "dropped": 0,
        "errors": 0,
        "last_error": None,
        "recent_logs": list(_ADAPTER_SURFACE.get("recent_logs") or [])[-50:],
        "segmentation": seg,
        "execution_mode": exec_mode,
        "is_simulated": is_simulated,
        "metric_provenance": _metric_provenance(payload),
    }
    children = list_child_stacks().get("children", [])
    rid = str(uuid.uuid4())
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                _db_adapter_log_row(cur, None, "info", "adapter_run_started", {"replay_probe_id": rid, "chunks": len(chunks)})
            conn.commit()
        sample = chunks[: min(len(chunks), 8)]
        for ch in sample:
            for c in children[:3]:
                port = int(c.get("client_listener_port") or _client_listener_port(str(c["child_id"])))
                pl = chunk_to_udp_payload(
                    ch,
                    replay_run_id=rid,
                    phase_id=str(uuid.uuid4()),
                    stream_id=str(uuid.uuid4()),
                    child_id=str(c["child_id"]),
                    event_id=new_event_id(),
                )
                if push_udp_to_child("127.0.0.1", port, pl):
                    _ADAPTER_SURFACE["sent"] += 1
                else:
                    _ADAPTER_SURFACE["dropped"] += 1
        _ADAPTER_SURFACE["running"] = False
        _ADAPTER_SURFACE["replay_phase"] = "idle"
        return {
            "ok": True,
            "probe_id": rid,
            "adapter": _ADAPTER_SURFACE,
            "execution_mode": exec_mode,
            "is_simulated": is_simulated,
            "metric_provenance": _metric_provenance(payload),
        }
    except Exception as exc:
        _ADAPTER_SURFACE["running"] = False
        _ADAPTER_SURFACE["errors"] = int(_ADAPTER_SURFACE.get("errors") or 0) + 1
        _ADAPTER_SURFACE["last_error"] = str(exc)
        return {
            "ok": False,
            "error": str(exc),
            "adapter": _ADAPTER_SURFACE,
            "execution_mode": exec_mode,
            "is_simulated": is_simulated,
            "metric_provenance": _metric_provenance(payload),
        }


def adapter_status() -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT count(*)::bigint, coalesce(sum(packets_sent),0)::bigint, coalesce(sum(packets_dropped),0)::bigint, coalesce(sum(error_count),0)::bigint
                FROM phase4.step3_replay_phases;
                """
            )
            agg = cur.fetchone()
    return {
        "ok": True,
        "surface": _ADAPTER_SURFACE,
        "db_totals": {
            "phase_rows": int(agg[0] or 0) if agg else 0,
            "packets_sent": int(agg[1] or 0) if agg else 0,
            "packets_dropped": int(agg[2] or 0) if agg else 0,
            "errors": int(agg[3] or 0) if agg else 0,
        },
    }


def adapter_logs(limit: int = 200) -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT log_id::text, replay_run_id::text, level, message, context, created_at_utc
                FROM phase4.step3_adapter_logs
                ORDER BY created_at_utc DESC
                LIMIT %(lim)s;
                """,
                {"lim": limit},
            )
            rows = []
            for r in cur.fetchall():
                rows.append(
                    {
                        "log_id": r[0],
                        "replay_run_id": r[1],
                        "level": r[2],
                        "message": r[3],
                        "context": r[4] or {},
                        "created_at": r[5].isoformat() if r[5] else None,
                    }
                )
    return {"ok": True, "logs": rows}


def child_listener_status(child_id: str) -> dict[str, Any]:
    ch = get_child_stack(child_id)
    if not ch.get("ok"):
        return ch
    c = ch["child"]
    rs = runtime_stats(child_id)
    return {
        "ok": True,
        "child_id": child_id,
        "client_listener_port": c.get("client_listener_port"),
        "client_network_id": c.get("client_network_id"),
        "runtime": (
            {
                "received_packets": rs.received_packets,
                "rule_match_count": rs.rule_match_count,
                "alert_count": rs.alert_count,
                "escalation_count": rs.escalation_count,
                "metric_source": rs.metric_source,
                "measurement_type": rs.measurement_type,
                "rule_sync_status": rs.rule_sync_status,
                "active_rule_count": rs.active_rule_count,
            }
            if rs
            else None
        ),
        "db": {
            "replay_receive_count": c.get("replay_receive_count"),
            "health_status": c.get("health_status"),
            "status": c.get("status"),
        },
        "execution_mode": _execution_mode(),
        "is_simulated": _is_simulation_mode(),
        "metric_provenance": _metric_provenance(None),
    }


def child_management_status(child_id: str) -> dict[str, Any]:
    ch = get_child_stack(child_id)
    if not ch.get("ok"):
        return ch
    c = ch["child"]
    rs = runtime_stats(child_id)
    return {
        "ok": True,
        "child_id": child_id,
        "management_port": c.get("management_port"),
        "management_network_id": c.get("management_network_id"),
        "parent_connection_status": c.get("parent_connection_status"),
        "runtime": {"parent_ack_pending": rs.parent_ack_pending, "health": rs.health} if rs else None,
        "mtls": (
            {
                "enabled": bool(rs.mtls_enabled),
                "ready": bool(rs.mtls_ready),
                "error": rs.mtls_error,
            }
            if rs
            else {"enabled": bool(STEP3_MTLS_ENABLED), "ready": False, "error": None}
        ),
        "execution_mode": _execution_mode(),
        "is_simulated": _is_simulation_mode(),
        "metric_provenance": _metric_provenance(None),
    }


def replay_timeline(replay_run_id: str | None = None, limit: int = 500) -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            if replay_run_id:
                cur.execute(
                    """
                    SELECT timeline_event_id::text, replay_run_id::text, stage, child_id, payload, created_at_utc
                    FROM phase4.step3_timeline_events
                    WHERE replay_run_id = %(rid)s::uuid
                    ORDER BY created_at_utc ASC
                    LIMIT %(lim)s;
                    """,
                    {"rid": replay_run_id, "lim": limit},
                )
            else:
                cur.execute(
                    """
                    SELECT timeline_event_id::text, replay_run_id::text, stage, child_id, payload, created_at_utc
                    FROM phase4.step3_timeline_events
                    ORDER BY created_at_utc DESC
                    LIMIT %(lim)s;
                    """,
                    {"lim": limit},
                )
            rows = []
            for r in cur.fetchall():
                rows.append(
                    {
                        "timeline_event_id": r[0],
                        "replay_run_id": r[1],
                        "stage": r[2],
                        "child_id": r[3],
                        "payload": r[4] or {},
                        "created_at": r[5].isoformat() if r[5] else None,
                    }
                )
    return {"ok": True, "events": rows}


def step3_visual_feed(
    *,
    model_id: str | None = None,
    model_version: str | None = None,
    replay_run_id: str | None = None,
    since_ts: str | None = None,
    since_event_id: str | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    lim = max(10, min(int(limit or 200), 1000))
    replay_filter = _uuid_or_none(replay_run_id)
    since_cutoff = str(since_ts or "").strip() or None
    mid = _uuid_or_none(model_id)
    mv = str(model_version or "").strip() or None
    if replay_filter is None:
        rs = replay_status()
        replay_filter = str(rs.get("replay_run_id") or "").strip() or None
    event_cursor_id = _uuid_or_none(since_event_id)
    if event_cursor_id and not since_cutoff:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT created_at_utc
                    FROM phase4.step3_timeline_events
                    WHERE timeline_event_id = %(eid)s::uuid
                    LIMIT 1;
                    """,
                    {"eid": event_cursor_id},
                )
                r = cur.fetchone()
                if r and r[0] is not None:
                    since_cutoff = r[0].isoformat()

    def _matches_model(payload_obj: dict[str, Any], row_model_version: str | None, row_model_id: str | None) -> bool:
        if mv and str(row_model_version or "") != mv:
            return False
        if mid and str(row_model_id or "") != mid:
            return False
        return True

    timeline_events: list[dict[str, Any]] = []
    packet_flow_events: list[dict[str, Any]] = []
    child_alert_events: list[dict[str, Any]] = []
    alert_events: list[dict[str, Any]] = []
    parent_review_events: list[dict[str, Any]] = []
    runtime_shap_events: list[dict[str, Any]] = []
    with connect() as conn:
        with conn.cursor() as cur:
            if replay_filter:
                if since_cutoff:
                    cur.execute(
                        """
                        SELECT t.timeline_event_id::text, t.replay_run_id::text, t.stage, t.child_id, t.payload, t.created_at_utc,
                               rr.run_id::text, rr.model_version, rr.model_id::text
                        FROM phase4.step3_timeline_events t
                        LEFT JOIN phase4.replay_runs rr ON rr.replay_run_id = t.replay_run_id
                        WHERE t.replay_run_id = %(rid)s::uuid
                          AND t.created_at_utc > %(since)s::timestamptz
                        ORDER BY t.created_at_utc ASC
                        LIMIT %(lim)s;
                        """,
                        {"rid": replay_filter, "since": since_cutoff, "lim": lim},
                    )
                else:
                    cur.execute(
                        """
                        SELECT t.timeline_event_id::text, t.replay_run_id::text, t.stage, t.child_id, t.payload, t.created_at_utc,
                               rr.run_id::text, rr.model_version, rr.model_id::text
                        FROM phase4.step3_timeline_events t
                        LEFT JOIN phase4.replay_runs rr ON rr.replay_run_id = t.replay_run_id
                        WHERE t.replay_run_id = %(rid)s::uuid
                        ORDER BY t.created_at_utc DESC
                        LIMIT %(lim)s;
                        """,
                        {"rid": replay_filter, "lim": lim},
                    )
            else:
                if since_cutoff:
                    cur.execute(
                        """
                        SELECT t.timeline_event_id::text, t.replay_run_id::text, t.stage, t.child_id, t.payload, t.created_at_utc,
                               rr.run_id::text, rr.model_version, rr.model_id::text
                        FROM phase4.step3_timeline_events t
                        LEFT JOIN phase4.replay_runs rr ON rr.replay_run_id = t.replay_run_id
                        WHERE t.created_at_utc > %(since)s::timestamptz
                        ORDER BY t.created_at_utc ASC
                        LIMIT %(lim)s;
                        """,
                        {"since": since_cutoff, "lim": lim},
                    )
                else:
                    cur.execute(
                        """
                        SELECT t.timeline_event_id::text, t.replay_run_id::text, t.stage, t.child_id, t.payload, t.created_at_utc,
                               rr.run_id::text, rr.model_version, rr.model_id::text
                        FROM phase4.step3_timeline_events t
                        LEFT JOIN phase4.replay_runs rr ON rr.replay_run_id = t.replay_run_id
                        ORDER BY t.created_at_utc DESC
                        LIMIT %(lim)s;
                        """,
                        {"lim": lim},
                    )
            timeline_rows = cur.fetchall()
            for eid, rid, stage, child_id_row, payload_row, created, run_id_row, row_mv, row_mid in timeline_rows:
                payload_obj = payload_row or {}
                rv = str(payload_obj.get("model_version") or row_mv or mv or "")
                rm = str(payload_obj.get("model_id") or row_mid or mid or "")
                if not _matches_model(payload_obj, rv or None, rm or None):
                    continue
                timeline_events.append(
                    {
                        "event_id": eid,
                        "event_time": created.isoformat() if created else None,
                        "event_type": str(stage or ""),
                        "model_id": rm or None,
                        "model_version": rv or None,
                        "run_id": run_id_row,
                        "replay_run_id": rid,
                        "child_id": child_id_row,
                        "payload": payload_obj,
                    }
                )

            flow_query_where = ["1=1"]
            flow_params: dict[str, Any] = {"lim": lim}
            if replay_filter:
                flow_query_where.append("f.replay_run_id = %(rid)s::uuid")
                flow_params["rid"] = replay_filter
            if since_cutoff:
                flow_query_where.append("f.created_at_utc > %(since)s::timestamptz")
                flow_params["since"] = since_cutoff
            cur.execute(
                f"""
                SELECT f.flow_event_id::text, f.replay_run_id::text, f.child_id, f.event_kind, f.payload, f.created_at_utc,
                       rr.model_version, rr.model_id::text, rr.run_id::text
                FROM phase4.step3_replay_flow_events f
                LEFT JOIN phase4.replay_runs rr ON rr.replay_run_id = f.replay_run_id
                WHERE {' AND '.join(flow_query_where)}
                ORDER BY f.created_at_utc ASC
                LIMIT %(lim)s;
                """,
                flow_params,
            )
            for eid, rid, cid, kind, payload_row, created, row_mv, row_mid, row_run_id in cur.fetchall():
                payload_obj = payload_row or {}
                if not _matches_model(payload_obj, row_mv, row_mid):
                    continue
                event = {
                    "event_id": eid,
                    "event_time": created.isoformat() if created else None,
                    "event_type": str(kind or ""),
                    "model_id": str(row_mid or payload_obj.get("model_id") or "") or None,
                    "model_version": str(row_mv or payload_obj.get("model_version") or "") or None,
                    "run_id": row_run_id,
                    "replay_run_id": rid,
                    "child_id": cid,
                    "payload": payload_obj,
                }
                if str(kind or "") in {"packet_transit", "replay_summary"}:
                    packet_flow_events.append(event)
                if str(kind or "") in {"child_alert", "escalation"}:
                    child_alert_events.append(event)

            pci_where = ["1=1"]
            pci_params: dict[str, Any] = {"lim": lim}
            if replay_filter:
                pci_where.append("i.replay_run_id = %(rid)s::uuid")
                pci_params["rid"] = replay_filter
            if since_cutoff:
                pci_where.append("i.created_at_utc > %(since)s::timestamptz")
                pci_params["since"] = since_cutoff
            cur.execute(
                f"""
                SELECT i.interaction_id::text, i.replay_run_id::text, i.run_id::text, i.child_id, i.status, i.interaction_payload, i.created_at_utc,
                       i.model_version, i.model_id::text
                FROM phase4.parent_child_interactions i
                WHERE {' AND '.join(pci_where)}
                ORDER BY i.created_at_utc ASC
                LIMIT %(lim)s;
                """,
                pci_params,
            )
            for iid, rid, row_run_id, cid, status, payload_row, created, row_mv, row_mid in cur.fetchall():
                payload_obj = payload_row or {}
                if not _matches_model(payload_obj, row_mv, row_mid):
                    continue
                parent_review_events.append(
                    {
                        "event_id": iid,
                        "event_time": created.isoformat() if created else None,
                        "event_type": str(status or ""),
                        "model_id": str(row_mid or payload_obj.get("model_id") or "") or None,
                        "model_version": str(row_mv or payload_obj.get("model_version") or "") or None,
                        "run_id": row_run_id,
                        "replay_run_id": rid,
                        "child_id": cid,
                        "payload": payload_obj,
                    }
                )

            pa_where = ["1=1"]
            pa_params: dict[str, Any] = {"lim": lim}
            if replay_filter:
                pa_where.append("a.replay_run_id = %(rid)s::uuid")
                pa_params["rid"] = replay_filter
            if since_cutoff:
                pa_where.append("a.created_at_utc > %(since)s::timestamptz")
                pa_params["since"] = since_cutoff
            cur.execute(
                f"""
                SELECT a.parent_action_id::text, a.replay_run_id::text, a.run_id::text, a.child_id, a.status, a.action_type, a.recommendation,
                       a.action_payload, a.created_at_utc, a.model_version, a.model_id::text
                FROM phase4.parent_actions a
                WHERE {' AND '.join(pa_where)}
                ORDER BY a.created_at_utc ASC
                LIMIT %(lim)s;
                """,
                pa_params,
            )
            for aid, rid, row_run_id, cid, status, action_type, rec, payload_row, created, row_mv, row_mid in cur.fetchall():
                payload_obj = payload_row or {}
                if not _matches_model(payload_obj, row_mv, row_mid):
                    continue
                parent_review_events.append(
                    {
                        "event_id": aid,
                        "event_time": created.isoformat() if created else None,
                        "event_type": str(status or ""),
                        "action_type": action_type,
                        "recommendation": rec,
                        "model_id": str(row_mid or payload_obj.get("model_id") or "") or None,
                        "model_version": str(row_mv or payload_obj.get("model_version") or "") or None,
                        "run_id": row_run_id,
                        "replay_run_id": rid,
                        "child_id": cid,
                        "payload": payload_obj,
                    }
                )

            shap_where = ["l.shap_stage = 'runtime'"]
            shap_params: dict[str, Any] = {"lim": lim}
            if replay_filter:
                shap_where.append("l.replay_id = %(rid)s")
                shap_params["rid"] = replay_filter
            if since_cutoff:
                shap_where.append("l.created_at > %(since)s::timestamptz")
                shap_params["since"] = since_cutoff
            if mv:
                shap_where.append("l.model_version = %(mv)s")
                shap_params["mv"] = mv
            cur.execute(
                f"""
                SELECT l.id, l.replay_id, l.model_version, l.top_features_json, l.event_details_json, l.created_at
                FROM phase4.shap_logs l
                WHERE {' AND '.join(shap_where)}
                ORDER BY l.created_at ASC
                LIMIT %(lim)s;
                """,
                shap_params,
            )
            for sid, rid, row_mv, top_features_json, details, created in cur.fetchall():
                details_obj = details or {}
                row_mid = str(details_obj.get("model_id") or "")
                if mid and row_mid != mid:
                    continue
                runtime_shap_events.append(
                    {
                        "event_id": str(sid),
                        "event_time": created.isoformat() if created else None,
                        "event_type": "runtime_shap",
                        "status": str((details_obj.get("status") or (top_features_json or {}).get("status") or "")),
                        "alert_id": str(details_obj.get("alert_id") or "") or None,
                        "rule_id": str(details_obj.get("rule_id") or "") or None,
                        "rule_family": str(details_obj.get("rule_family") or "") or None,
                        "packet_or_flow_id": str(details_obj.get("packet_or_flow_id") or "") or None,
                        "model_id": row_mid or None,
                        "model_version": str(row_mv or details_obj.get("model_version") or "") or None,
                        "run_id": None,
                        "replay_run_id": str(rid or details_obj.get("replay_run_id") or ""),
                        "child_id": details_obj.get("child_id"),
                        "payload": {
                            "top_features": (top_features_json or {}).get("top_features") or [],
                            "prediction": details_obj.get("prediction") or {},
                            "error": details_obj.get("error"),
                            "details": details_obj.get("details") or {},
                            "metrics": details_obj.get("metrics") or {},
                            "interaction_id": details_obj.get("interaction_id"),
                            "parent_action_id": details_obj.get("parent_action_id"),
                        },
                    }
                )
            alert_where = ["1=1"]
            alert_params: dict[str, Any] = {"lim": lim}
            if replay_filter:
                alert_where.append("a.replay_run_id = %(rid)s::uuid")
                alert_params["rid"] = replay_filter
            if since_cutoff:
                alert_where.append("a.created_at_utc > %(since)s::timestamptz")
                alert_params["since"] = since_cutoff
            if mv:
                alert_where.append("a.model_version = %(mv)s")
                alert_params["mv"] = mv
            if mid:
                alert_where.append("a.model_id = %(mid)s::uuid")
                alert_params["mid"] = mid
            cur.execute(
                f"""
                SELECT a.alert_id::text, a.replay_run_id::text, a.run_id::text, a.model_id::text, a.model_version, a.child_id,
                       a.severity, a.urgency, a.status, a.recommendation, a.payload, a.created_at_utc
                FROM phase4.step3_alerts a
                WHERE {' AND '.join(alert_where)}
                ORDER BY a.created_at_utc ASC
                LIMIT %(lim)s;
                """,
                alert_params,
            )
            for aid, rid, run_id_row, row_mid, row_mv, cid, sev, urg, ast, rec, payload_row, created in cur.fetchall():
                pl = payload_row or {}
                if isinstance(pl, str):
                    try:
                        pl = json.loads(pl)
                    except Exception:
                        pl = {}
                alert_events.append(
                    {
                        "event_id": aid,
                        "event_time": created.isoformat() if created else None,
                        "event_type": "incident_alert",
                        "model_id": row_mid,
                        "model_version": row_mv,
                        "run_id": run_id_row,
                        "replay_run_id": rid,
                        "child_id": cid,
                        "severity": sev,
                        "urgency": urg,
                        "status": ast,
                        "recommendation": rec,
                        "payload": pl if isinstance(pl, dict) else {},
                        "parent_shap": pl.get("parent_shap") if isinstance(pl, dict) else {},
                    }
                )

    timeline_events.sort(key=lambda x: str(x.get("event_time") or ""))
    packet_flow_events.sort(key=lambda x: str(x.get("event_time") or ""))
    child_alert_events.sort(key=lambda x: str(x.get("event_time") or ""))
    alert_events.sort(key=lambda x: str(x.get("event_time") or ""))
    parent_review_events.sort(key=lambda x: str(x.get("event_time") or ""))
    runtime_shap_events.sort(key=lambda x: str(x.get("event_time") or ""))
    all_times = [
        *(e.get("event_time") for e in timeline_events),
        *(e.get("event_time") for e in packet_flow_events),
        *(e.get("event_time") for e in child_alert_events),
        *(e.get("event_time") for e in alert_events),
        *(e.get("event_time") for e in parent_review_events),
        *(e.get("event_time") for e in runtime_shap_events),
    ]
    cursor_ts = max((t for t in all_times if t), default=since_cutoff)
    cursor_event_id = (timeline_events[-1].get("event_id") if timeline_events else None) or (
        packet_flow_events[-1].get("event_id") if packet_flow_events else None
    )
    counters = {
        "timeline_events": len(timeline_events),
        "packet_flow_events": len(packet_flow_events),
        "child_alert_events": len(child_alert_events),
        "alert_events": len(alert_events),
        "parent_review_events": len(parent_review_events),
        "runtime_shap_events": len(runtime_shap_events),
    }
    urgency_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for row in alert_events:
        u = str(row.get("urgency") or "").lower()
        if u in urgency_counts:
            urgency_counts[u] += 1
    counters["urgency_counts"] = urgency_counts
    child_snapshots_all = list_child_stacks().get("children", [])
    child_filter = {str(e.get("child_id") or "") for e in packet_flow_events + child_alert_events + parent_review_events if e.get("child_id")}
    child_status_snapshots = []
    for c in child_snapshots_all:
        cid = str(c.get("child_id") or "")
        if child_filter and cid not in child_filter:
            continue
        child_status_snapshots.append(
            {
                "child_id": cid,
                "child_type": c.get("child_type"),
                "listener_port": c.get("client_listener_port"),
                "management_port": c.get("management_port"),
                "health_status": c.get("health_status"),
                "parent_connection_status": c.get("parent_connection_status"),
                "rule_ready_status": c.get("rule_ready_status"),
                "replay_status": c.get("replay_status"),
                "replay_receive_count": c.get("replay_receive_count"),
                "alert_count": c.get("alert_count"),
                "escalation_count": c.get("escalation_count"),
                "model_id": c.get("model_id"),
                "model_version": c.get("model_version"),
                "run_id": None,
                "event_time": c.get("updated_at"),
                "mgmt_link_state": {
                    "mtls_enabled": bool(STEP3_MTLS_ENABLED),
                    "mtls_material_expected": bool(STEP3_MTLS_ENABLED),
                },
            }
        )
        rs = runtime_stats(cid)
        if rs:
            child_status_snapshots[-1]["mgmt_link_state"] = {
                "mtls_enabled": bool(rs.mtls_enabled),
                "mtls_ready": bool(rs.mtls_ready),
                "mtls_error": rs.mtls_error,
                "rule_sync_status": rs.rule_sync_status,
                "active_rule_count": int(rs.active_rule_count),
            }
    return {
        "ok": True,
        "model_id": mid,
        "model_version": mv,
        "replay_run_id": replay_filter,
        "timeline_events": timeline_events,
        "packet_flow_events": packet_flow_events,
        "child_alert_events": child_alert_events,
        "alert_events": alert_events,
        "child_status_snapshots": child_status_snapshots,
        "parent_review_events": parent_review_events,
        "runtime_shap_events": runtime_shap_events,
        "counters": counters,
        "cursor": {"since_ts": cursor_ts, "since_event_id": cursor_event_id},
    }


def parent_child_interactions(limit: int = 300) -> dict[str, Any]:
    return interactions(limit=limit)


def step3_audit_events(limit: int = 200) -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT event_id, event_type, actor, context, artifact_refs, created_at_utc
                FROM phase4.step3_audit_events
                ORDER BY created_at_utc DESC NULLS LAST
                LIMIT %(lim)s;
                """,
                {"lim": limit},
            )
            rows = []
            for r in cur.fetchall():
                rows.append(
                    {
                        "event_id": r[0],
                        "event_type": r[1],
                        "actor": r[2],
                        "context": r[3] or {},
                        "artifact_refs": r[4] or [],
                        "created_at": r[5].isoformat() if r[5] else None,
                    }
                )
    return {"ok": True, "audit_events": rows}


def current_model_header() -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT run_id::text, status, run_metrics, started_at_utc
                FROM phase4.workflow_runs
                WHERE step_name = 'step2'
                ORDER BY started_at_utc DESC
                LIMIT 1;
                """
            )
            row = cur.fetchone()
            if not row:
                return {
                    "ok": True,
                    "current_model_version": None,
                    "model_status": "not_ready",
                    "frozen": False,
                    "trained_at": None,
                    "active_rulepack_version": None,
                    "step2_completion_status": "pending",
                    "step3_readiness_status": "blocked",
                    "banner": "Current Model: Not Ready — Complete Step 2",
                }
            run_id, run_status, run_metrics, started_at = row
            metrics = run_metrics or {}
            if isinstance(metrics, str):
                try:
                    metrics = json.loads(metrics)
                except Exception:
                    metrics = {}
            mstatus = metrics.get("model_v1_status") or {}
            cur.execute(
                """
                SELECT rulepack_version
                FROM phase4.rulepack_registry
                WHERE run_id = %(run_id)s::uuid AND status='published'
                ORDER BY created_at_utc DESC
                LIMIT 1;
                """,
                {"run_id": run_id},
            )
            rp = cur.fetchone()
            rulepack_version = rp[0] if rp else None
    step3 = _step3_readiness()
    ready = bool(step3.get("ok"))
    return {
        "ok": True,
        "current_model_version": "Model V1",
        "model_status": run_status,
        "frozen": bool(mstatus.get("frozen")),
        "trained_at": started_at.isoformat() if started_at else None,
        "active_rulepack_version": rulepack_version,
        "step2_completion_status": "completed" if run_status == "completed" else run_status,
        "step3_readiness_status": "ready" if ready else "blocked",
        "banner": (
            "Current Model: Model V1 | Frozen | Rules Published | Ready for Replay"
            if ready
            else "Current Model: Model V1 | Frozen | Rules Published | Step 3 Blocked"
        ),
    }


def step3_status() -> dict[str, Any]:
    stacks = list_child_stacks().get("children", [])
    rules = rules_status().get("rules", [])
    replay = replay_status()
    readiness = _step3_readiness()
    ready_children = [c["child_id"] for c in stacks if c.get("health_status") == "healthy"]
    ready_rules = [r["child_id"] for r in rules if r.get("ready")]
    return {
        "ok": True,
        "step": "step3",
        "status": "ready" if readiness.get("ok") else "blocked",
        "minimum_children_required": 10,
        "child_count": len(stacks),
        "healthy_children": len(ready_children),
        "rule_ready_children": len(ready_rules),
        "missing_requirements": readiness.get("missing") or [],
        "replay": replay,
        "simulation": simulation_process_state(),
        "adapter_surface": dict(_ADAPTER_SURFACE),
        "execution_mode": _execution_mode(),
        "is_simulated": _is_simulation_mode(),
        "metric_provenance": _metric_provenance(None),
        "deprecated_fields": ["legacy_derived_status_chain"],
        "worker_limits": {
            "STEP3_REPLAY_MAX_WORKERS": STEP3_REPLAY_MAX_WORKERS,
            "STEP3_ADAPTER_WORKERS": STEP3_ADAPTER_WORKERS,
            "STEP3_CHILD_STACK_THREADS": STEP3_CHILD_STACK_THREADS,
            "STEP3_PARENT_STACK_THREADS": STEP3_PARENT_STACK_THREADS,
            "STEP3_FACTORY_STACK_THREADS": STEP3_FACTORY_STACK_THREADS,
            "STEP3_CHILD_ROUTE_WORKERS": STEP3_CHILD_ROUTE_WORKERS,
            "STEP3_PARENT_REVIEW_WORKERS": STEP3_PARENT_REVIEW_WORKERS,
            "STEP3_SHAP_WORKERS": STEP3_SHAP_WORKERS,
            "STEP3_PARENT_WORKER_MODE": STEP3_PARENT_WORKER_MODE,
            "STEP3_WORKER_MODE": STEP3_WORKER_MODE,
            "STEP3_STRICT_ACCEPTANCE_DEFAULT": STEP3_STRICT_ACCEPTANCE_DEFAULT,
            "STEP3_MTLS_ENABLED": STEP3_MTLS_ENABLED,
            "STEP3_ALERT_DEFER_TO_BUFFER": STEP3_ALERT_DEFER_TO_BUFFER,
        },
        "step3_cpu_governance": {
            "status": "measured_or_not_applicable",
            "reason": "simulation_runtime_operational_telemetry",
        },
        "message": "Step 3 replay simulation ready" if readiness.get("ok") else "Step 3 readiness requirements missing",
    }


def _step3_file_run_summaries(*, replay_run_id: str | None = None, sim_id: str | None = None) -> list[dict[str, Any]]:
    rid = str(replay_run_id or "").strip()
    sid = _uuid_or_none(sim_id)
    if not rid and not sid:
        return []
    rows_out: list[dict[str, Any]] = []
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                _ensure_step3_sim_file_summaries_table()
                if sid:
                    cur.execute(
                        """
                        SELECT file_path,
                               packets_total_in_file,
                               packets_attack_in_file,
                               packets_benign_in_file,
                               packets_transmitted,
                               packets_received,
                               packets_failed,
                               packets_lost,
                               alerts_triggered,
                               alert_ratio,
                               file_run_started_at_utc,
                               file_run_finished_at_utc,
                               stats,
                               updated_at_utc
                        FROM phase4.step3_sim_file_summaries
                        WHERE replay_id = %(sid)s::uuid
                        ORDER BY updated_at_utc ASC, file_path ASC;
                        """,
                        {"sid": sid},
                    )
                elif rid:
                    cur.execute(
                        """
                        SELECT file_path,
                               packets_total_in_file,
                               packets_attack_in_file,
                               packets_benign_in_file,
                               packets_transmitted,
                               packets_received,
                               packets_failed,
                               packets_lost,
                               0::bigint AS alerts_triggered,
                               0::numeric AS alert_ratio,
                               NULL::timestamptz AS file_run_started_at_utc,
                               NULL::timestamptz AS file_run_finished_at_utc,
                               stats,
                               created_at_utc
                        FROM phase4.step3_replay_file_stats
                        WHERE replay_run_id = %(rid)s::uuid
                        ORDER BY created_at_utc ASC, file_path ASC;
                        """,
                        {"rid": rid},
                    )
                for (
                    file_path,
                    total,
                    attack,
                    benign,
                    tx,
                    recv,
                    failed,
                    lost,
                    alerts_triggered,
                    alert_ratio,
                    file_run_started_at_utc,
                    file_run_finished_at_utc,
                    stats,
                    updated_at_utc,
                ) in cur.fetchall():
                    st = stats if isinstance(stats, dict) else {}
                    alerts = int(
                        alerts_triggered
                        or st.get("alerts_triggered")
                        or st.get("rule_matches")
                        or 0
                    )
                    packets_total = int(total or 0)
                    ratio_value = (
                        float(alert_ratio)
                        if alert_ratio is not None
                        else (
                            float(st.get("alert_ratio"))
                            if st.get("alert_ratio") is not None
                            else (float(alerts) / float(packets_total) if packets_total > 0 else 0.0)
                        )
                    )
                    started_at_val = (
                        file_run_started_at_utc.isoformat()
                        if hasattr(file_run_started_at_utc, "isoformat") and file_run_started_at_utc
                        else (str(file_run_started_at_utc) if file_run_started_at_utc else st.get("file_run_started_at_utc"))
                    )
                    finished_at_val = (
                        file_run_finished_at_utc.isoformat()
                        if hasattr(file_run_finished_at_utc, "isoformat") and file_run_finished_at_utc
                        else (
                            str(file_run_finished_at_utc)
                            if file_run_finished_at_utc
                            else (
                                updated_at_utc.isoformat()
                                if hasattr(updated_at_utc, "isoformat") and updated_at_utc
                                else (str(updated_at_utc) if updated_at_utc else st.get("file_run_finished_at_utc"))
                            )
                        )
                    )
                    rows_out.append(
                        {
                            "file_name": str(st.get("file_name") or Path(str(file_path or "")).name),
                            "file_path": str(file_path or ""),
                            "status": str(st.get("status") or ("finalized" if finished_at_val else ("running" if started_at_val else "prepared"))),
                            "packets_total_in_file": packets_total,
                            "packets_attack_in_file": int(attack or 0),
                            "packets_benign_in_file": int(benign or 0),
                            "packets_transmitted": int(tx or 0),
                            "packets_received": int(recv or 0),
                            "packets_failed": int(failed or 0),
                            "packets_lost": int(lost or 0),
                            "alerts_triggered": int(alerts or 0),
                            "alerts_sent_from_child": int(st.get("alerts_sent_from_child") or alerts or 0),
                            "alerts_received_at_parent": int(st.get("alerts_received_at_parent") or st.get("parent_alerts_received") or alerts or 0),
                            "alert_ratio": ratio_value,
                            "file_run_started_at_utc": _to_utc_iso(started_at_val) or started_at_val,
                            "file_run_started_at_ist": _to_ist_iso(started_at_val),
                            "file_run_finished_at_utc": _to_utc_iso(finished_at_val) or finished_at_val,
                            "file_run_finished_at_ist": _to_ist_iso(finished_at_val),
                        }
                    )
    except Exception:
        return []
    return rows_out


def _step3_postgres_validation_report(
    *,
    replay_run_id: str,
    expected_files_count: int,
    expected_packets_sent_total: int,
) -> dict[str, Any]:
    warnings: list[str] = []
    errors: list[str] = []
    summary: dict[str, Any] = {}
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*)::bigint,
                           COALESCE(SUM(packets_total_in_file), 0)::bigint,
                           COALESCE(SUM(packets_transmitted), 0)::bigint,
                           COALESCE(SUM(packets_received), 0)::bigint,
                           COALESCE(SUM(packets_lost), 0)::bigint
                    FROM phase4.step3_replay_file_stats
                    WHERE replay_run_id = %(rid)s::uuid;
                    """,
                    {"rid": replay_run_id},
                )
                row = cur.fetchone() or (0, 0, 0, 0, 0)
                file_rows = int(row[0] or 0)
                file_packets_total = int(row[1] or 0)
                file_packets_transmitted = int(row[2] or 0)
                file_packets_received = int(row[3] or 0)
                file_packets_lost = int(row[4] or 0)

                cur.execute(
                    """
                    SELECT COALESCE(SUM(packets_sent), 0)::bigint,
                           COALESCE(SUM(packets_received), 0)::bigint,
                           COALESCE(SUM(packets_dropped), 0)::bigint
                    FROM phase4.step3_stack_traffic
                    WHERE replay_run_id = %(rid)s::uuid;
                    """,
                    {"rid": replay_run_id},
                )
                traffic = cur.fetchone() or (0, 0, 0)
                traffic_sent = int(traffic[0] or 0)
                traffic_received = int(traffic[1] or 0)
                traffic_dropped = int(traffic[2] or 0)

                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM phase4.step3_alerts
                    WHERE replay_run_id = %(rid)s::uuid;
                    """,
                    {"rid": replay_run_id},
                )
                alert_rows = int((cur.fetchone() or [0])[0] or 0)

                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM phase4.shap_logs
                    WHERE replay_id = %(rid)s
                      AND shap_stage = 'runtime';
                    """,
                    {"rid": replay_run_id},
                )
                shap_rows = int((cur.fetchone() or [0])[0] or 0)

        if file_rows != int(expected_files_count or 0):
            warnings.append(f"file_rows_mismatch:expected={int(expected_files_count or 0)} actual={file_rows}")
        if expected_packets_sent_total > 0 and file_packets_transmitted != int(expected_packets_sent_total):
            warnings.append(
                f"file_packets_transmitted_mismatch:expected={int(expected_packets_sent_total)} actual={file_packets_transmitted}"
            )
        if traffic_sent > 0 and file_packets_transmitted > 0 and traffic_sent != file_packets_transmitted:
            warnings.append(f"traffic_vs_file_transmitted_mismatch:traffic={traffic_sent} files={file_packets_transmitted}")
        if traffic_received > 0 and file_packets_received > 0 and traffic_received != file_packets_received:
            warnings.append(f"traffic_vs_file_received_mismatch:traffic={traffic_received} files={file_packets_received}")
        if alert_rows <= 0:
            warnings.append("no_alert_rows_recorded")
        if shap_rows <= 0:
            warnings.append("no_runtime_shap_rows_recorded")
        summary = {
            "expected_files_count": int(expected_files_count or 0),
            "actual_file_rows": file_rows,
            "file_packets_total": file_packets_total,
            "file_packets_transmitted": file_packets_transmitted,
            "file_packets_received": file_packets_received,
            "file_packets_lost": file_packets_lost,
            "traffic_packets_sent": traffic_sent,
            "traffic_packets_received": traffic_received,
            "traffic_packets_dropped": traffic_dropped,
            "alert_rows": alert_rows,
            "runtime_shap_rows": shap_rows,
        }
    except Exception as exc:
        errors.append(f"postgres_validation_query_failed:{exc}")
    status = "ok"
    if errors:
        status = "error_non_gating"
    elif warnings:
        status = "warning"
    return {
        "status": status,
        "warnings": warnings,
        "errors": errors,
        "summary": summary,
        "generated_at_utc": _now(),
        "gating": False,
    }


def _step3_realtime_signal_counts(*, replay_run_id: str | None) -> dict[str, Any]:
    rid = str(replay_run_id or "").strip()
    base = {
        "replay_run_id": rid or None,
        "runtime_shap_events": 0,
        "runtime_shap_rows": 0,
        "runtime_shap_scored_total": 0,
        "runtime_shap_failed_total": 0,
        "user_alert_events": 0,
        "user_alert_rows": 0,
        "user_alert_count_total": 0,
        "child_alert_events": 0,
        "escalation_events": 0,
        "parent_review_events": 0,
        "alert_to_shap_coverage_ratio": 0.0,
        "evidence_quality": "not_measured",
        "children": [],
    }
    if not rid:
        return base
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        COUNT(*)::bigint AS shap_rows,
                        COUNT(*) FILTER (
                            WHERE COALESCE(top_features_json->>'status', '') = 'runtime_shap_completed'
                        )::bigint AS shap_scored_rows
                    FROM phase4.shap_logs
                    WHERE replay_id = %(rid)s
                      AND shap_stage = 'runtime';
                    """,
                    {"rid": rid},
                )
                row = cur.fetchone()
                shap_rows = int((row[0] if row else 0) or 0)
                shap_scored_rows = int((row[1] if row else 0) or 0)
                base["runtime_shap_events"] = shap_rows
                base["runtime_shap_rows"] = shap_rows
                base["runtime_shap_scored_total"] = shap_scored_rows
                base["runtime_shap_failed_total"] = max(0, shap_rows - shap_scored_rows)
                cur.execute(
                    """
                    SELECT
                        COUNT(*)::bigint AS alert_rows,
                        COALESCE(SUM(CASE
                            WHEN (payload->>'alert_count') ~ '^[0-9]+$' THEN (payload->>'alert_count')::bigint
                            ELSE 1
                        END), 0)::bigint AS alert_total
                    FROM phase4.step3_alerts
                    WHERE replay_run_id = %(rid)s::uuid;
                    """,
                    {"rid": rid},
                )
                row = cur.fetchone()
                alert_rows = int((row[0] if row else 0) or 0)
                alert_total = int((row[1] if row else 0) or 0)
                base["user_alert_events"] = alert_rows
                base["user_alert_rows"] = alert_rows
                base["user_alert_count_total"] = alert_total
                cur.execute(
                    """
                    SELECT
                        count(*) FILTER (WHERE event_kind = 'child_alert') AS child_alerts,
                        count(*) FILTER (WHERE event_kind = 'escalation') AS escalations
                    FROM phase4.step3_replay_flow_events
                    WHERE replay_run_id = %(rid)s::uuid;
                    """,
                    {"rid": rid},
                )
                row = cur.fetchone()
                base["child_alert_events"] = int((row[0] if row else 0) or 0)
                base["escalation_events"] = int((row[1] if row else 0) or 0)
                cur.execute(
                    """
                    SELECT count(*)
                    FROM phase4.parent_actions
                    WHERE replay_run_id = %(rid)s::uuid;
                    """,
                    {"rid": rid},
                )
                row = cur.fetchone()
                base["parent_review_events"] = int((row[0] if row else 0) or 0)
        base["children"] = _step3_replay_child_breakdown(rid)
        total_alerts = int(base.get("user_alert_count_total") or 0)
        scored = int(base.get("runtime_shap_scored_total") or 0)
        ratio = float(scored / total_alerts) if total_alerts > 0 else 0.0
        base["alert_to_shap_coverage_ratio"] = ratio
        if total_alerts <= 0 and int(base.get("runtime_shap_rows") or 0) <= 0:
            base["evidence_quality"] = "not_measured"
        elif scored >= total_alerts:
            base["evidence_quality"] = "measured"
        elif scored > 0:
            base["evidence_quality"] = "partial_measured"
        else:
            base["evidence_quality"] = "not_measured"
    except Exception as exc:
        base["error"] = str(exc)
    return base


def _phase2_step_progress_events(replay_run_id: str | None, *, limit: int = 20) -> list[dict[str, Any]]:
    rid = str(replay_run_id or "").strip()
    if not rid:
        return []
    lim = max(1, min(int(limit), 200))
    out: list[dict[str, Any]] = []
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT timeline_event_id::text, payload, created_at_utc
                    FROM phase4.step3_timeline_events
                    WHERE replay_run_id = %(rid)s::uuid
                      AND stage = 'phase2_step_progress'
                    ORDER BY created_at_utc DESC
                    LIMIT %(lim)s;
                    """,
                    {"rid": rid, "lim": lim},
                )
                for eid, payload, created in cur.fetchall():
                    pl = payload if isinstance(payload, dict) else {}
                    out.append(
                        {
                            "event_id": str(eid),
                            "sim_id": str(pl.get("sim_id") or ""),
                            "run_id": str(pl.get("run_id") or ""),
                            "replay_run_id": str(pl.get("replay_run_id") or rid),
                            "phase2_state": str(pl.get("phase2_state") or ""),
                            "replay_status": str(pl.get("replay_status") or ""),
                            "steps": list(pl.get("steps") or []),
                            "errors": list(pl.get("errors") or []),
                            "realtime_signals": pl.get("realtime_signals") if isinstance(pl.get("realtime_signals"), dict) else {},
                            "file_run_summaries": list(pl.get("file_run_summaries") or []),
                            "postgres_validation_report": pl.get("postgres_validation_report") if isinstance(pl.get("postgres_validation_report"), dict) else {},
                            "validation_status": str(pl.get("validation_status") or ""),
                            "created_at": created.isoformat() if created else None,
                            "created_at_ist": _to_ist_iso(created),
                        }
                    )
    except Exception:
        return []
    return out


def _persist_phase2_step_progress(
    *,
    replay_run_id: str | None,
    preparation_replay_id: str | None,
    simulation_session_id: str | None,
    run_id: str | None,
    model_id: str | None,
    model_version: str | None,
    phase2_state: str,
    replay_state: str,
    phase2_steps: list[dict[str, Any]],
    phase2_errors: list[str],
    realtime_signals: dict[str, Any],
    file_run_summaries: list[dict[str, Any]] | None = None,
    postgres_validation_report: dict[str, Any] | None = None,
    validation_status: str | None = None,
) -> dict[str, Any]:
    rid = str(replay_run_id or "").strip()
    if not rid:
        return {"ok": True, "persisted": False, "reason": "replay_run_id_missing"}
    normalized_steps: list[dict[str, Any]] = []
    for row in phase2_steps or []:
        if not isinstance(row, dict):
            continue
        normalized_steps.append(
            {
                "name": str(row.get("name") or ""),
                "status": str(row.get("status") or ""),
                "ok": bool(row.get("ok")),
                "detail": row.get("detail") if isinstance(row.get("detail"), dict) else (row.get("detail") or None),
            }
        )
    snapshot = {
        "phase2_state": str(phase2_state or ""),
        "replay_status": str(replay_state or ""),
        "replay_run_id": rid,
        "sim_id": str(preparation_replay_id or "").strip() or None,
        "run_id": str(run_id or "").strip() or None,
        "steps": normalized_steps,
        "errors": [str(e) for e in (phase2_errors or []) if str(e).strip()],
        "realtime_signals": realtime_signals if isinstance(realtime_signals, dict) else {},
        "file_run_summaries": list(file_run_summaries or []),
        "postgres_validation_report": postgres_validation_report if isinstance(postgres_validation_report, dict) else {},
        "validation_status": str(validation_status or ""),
        "simulation_session_id": str(simulation_session_id or "").strip() or None,
        "model_id": str(model_id or "").strip() or None,
        "model_version": str(model_version or "").strip() or None,
    }
    digest = hashlib.sha256(json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    has_failed_step = any(str(s.get("status") or "").strip().lower() == "failed" for s in normalized_steps)
    terminal = str(phase2_state or "").strip().lower() in {"failed", "completed"} or str(replay_state or "").strip().lower() in {
        "failed",
        "completed",
        "error",
        "stopped",
    }
    event_payload = {"fingerprint": digest, **snapshot}
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT payload
                    FROM phase4.step3_timeline_events
                    WHERE replay_run_id = %(rid)s::uuid
                      AND stage = 'phase2_step_progress'
                    ORDER BY created_at_utc DESC
                    LIMIT 1;
                    """,
                    {"rid": rid},
                )
                prev = cur.fetchone()
                prev_payload = (prev[0] if prev else {}) or {}
                prev_fp = str(prev_payload.get("fingerprint") or "").strip() if isinstance(prev_payload, dict) else ""
                if prev_fp == digest:
                    return {"ok": True, "persisted": False, "reason": "unchanged"}
                if not terminal and not has_failed_step and bool(prev):
                    return {"ok": True, "persisted": False, "reason": "non_terminal_delta_suppressed"}
                _db_timeline_row(
                    cur,
                    rid,
                    "phase2_step_progress",
                    None,
                    event_payload,
                    replay_id=preparation_replay_id,
                    simulation_session_id=simulation_session_id,
                )
            conn.commit()
    except Exception as exc:
        return {"ok": False, "persisted": False, "error": str(exc)}
    try:
        write_audit_event(
            event_type="step3_phase2_step_progress",
            actor="model-v1-step3-process-status",
            artifact_refs=[],
            context=event_payload,
            dataset_id="REP-01",
            experiment_id="exp_model_v1_step3_replay",
            model_version=str(model_version or "").strip() or None,
            replay_id=rid,
        )
    except Exception:
        pass
    return {"ok": True, "persisted": True}


def step3_process_status(*, model_version: str | None = None, model_id: str | None = None) -> dict[str, Any]:
    """Two-phase Step 3 progress view for dashboard polling."""
    mv = str(model_version or "").strip()
    mid = str(model_id or "").strip()
    replay = replay_status()
    simulation = simulation_status()
    if not mv:
        mv = str(replay.get("model_version") or "").strip()
    prep = step3_preparation_status(model_version=mv) if mv else {"ok": True, "verified_ok": False, "record": None}
    prep_record = prep.get("record") or {}
    if not mid:
        mid = str(prep_record.get("model_id") or replay.get("model_id") or "").strip()

    checks = list(prep_record.get("checks") or [])
    prep_result = prep_record.get("prepare_result") if isinstance(prep_record.get("prepare_result"), dict) else {}
    verify_result = prep_record.get("verify_result") if isinstance(prep_record.get("verify_result"), dict) else {}
    phase1_substages = []
    if isinstance(verify_result.get("phase1_substages"), list) and verify_result.get("phase1_substages"):
        phase1_substages = list(verify_result.get("phase1_substages") or [])
    elif isinstance(prep_result.get("phase1_substages"), list) and prep_result.get("phase1_substages"):
        phase1_substages = list(prep_result.get("phase1_substages") or [])
    if bool(prep.get("verified_ok")) and phase1_substages:
        found_verify_stage = False
        for idx, stage in enumerate(phase1_substages):
            if str(stage.get("name") or "") != "verify_all_stages_completed":
                continue
            found_verify_stage = True
            if bool(stage.get("ok")) and str(stage.get("status") or "").lower() == "completed":
                break
            phase1_substages[idx] = {
                **stage,
                "ok": True,
                "status": "completed",
                "detail": {
                    "checks_passed": len([c for c in checks if bool(c.get("ok"))]),
                    "checks_total": len(checks),
                    "source": "verified_ok_normalization",
                },
                "updated_at": _now(),
            }
            break
        if not found_verify_stage:
            phase1_substages.append(
                {
                    "name": "verify_all_stages_completed",
                    "ok": True,
                    "status": "completed",
                    "detail": {
                        "checks_passed": len([c for c in checks if bool(c.get("ok"))]),
                        "checks_total": len(checks),
                        "source": "verified_ok_normalization_missing_stage",
                    },
                    "updated_at": _now(),
                }
            )
    checks_total = len(checks)
    checks_ok = len([c for c in checks if bool(c.get("ok"))])
    prep_status = str(prep_record.get("prepare_status") or "").strip().lower()
    phase1_errors: list[str] = []
    for chk in checks:
        if bool(chk.get("ok")):
            continue
        name = str(chk.get("name") or "check_failed")
        detail = chk.get("detail")
        if detail:
            phase1_errors.append(f"{name}:{detail}")
        else:
            phase1_errors.append(name)
    for st in phase1_substages:
        if bool(st.get("ok")):
            continue
        sname = str(st.get("name") or "substage_failed")
        sdetail = st.get("detail")
        if sdetail:
            phase1_errors.append(f"{sname}:{sdetail}")
        else:
            phase1_errors.append(sname)

    if bool(prep.get("verified_ok")):
        phase1_state = "completed"
    elif prep_status in {"prepare_started", "preparing", "verifying"}:
        phase1_state = "running"
    elif prep_status in {"prepare_failed", "verification_failed"} or phase1_errors:
        phase1_state = "failed"
    else:
        phase1_state = "pending"

    replay_state = str(replay.get("status") or "idle").strip().lower()
    if replay_state in {"running", "starting"}:
        phase2_state = "running"
    elif replay_state == "completed":
        phase2_state = "completed"
    elif replay_state in {"failed", "error", "stopped"}:
        phase2_state = "failed"
    else:
        phase2_state = "pending"
    if phase1_state != "completed" and phase2_state == "pending":
        phase2_state = "blocked"

    strict_errors = list(replay.get("strict_acceptance_errors") or [])
    replay_error = str(replay.get("error_message") or "").strip()
    phase2_errors: list[str] = []
    if replay_error:
        phase2_errors.append(replay_error)
    for se in strict_errors:
        phase2_errors.append(str(se))
    if not phase2_errors and replay_state == "failed":
        phase2_errors.append("replay_failed")

    dm = replay.get("dissertation_metrics") if isinstance(replay.get("dissertation_metrics"), dict) else {}
    metrics_persisted = bool(dm)
    replay_run_id = str(replay.get("replay_run_id") or "").strip() or None
    realtime_signals = _step3_realtime_signal_counts(replay_run_id=replay_run_id)
    replay_meta = replay.get("metadata") if isinstance(replay.get("metadata"), dict) else {}
    postgres_validation_report = replay_meta.get("postgres_validation_report") if isinstance(replay_meta.get("postgres_validation_report"), dict) else {}
    validation_status = str(replay_meta.get("validation_status") or postgres_validation_report.get("status") or "ok")
    preparation_replay_id = str(
        replay.get("preparation_replay_id")
        or prep_record.get("preparation_replay_id")
        or ""
    ).strip() or None
    sim_id = str(
        replay.get("sim_id")
        or replay.get("preparation_replay_id")
        or prep_record.get("preparation_replay_id")
        or replay.get("replay_id")
        or ""
    ).strip() or None
    step1_run_id = str(
        replay.get("run_id")
        or prep_record.get("source_step1_run_id")
        or replay_meta.get("run_id")
        or ""
    ).strip() or None
    file_run_summaries = _step3_file_run_summaries(
        replay_run_id=replay_run_id,
        sim_id=sim_id,
    )

    sim_session = simulation.get("last_session") if isinstance(simulation.get("last_session"), dict) else {}
    simulation_session_id = str(sim_session.get("session_id") or replay.get("simulation_session_id") or "").strip() or None
    sim_link_ok = bool(sim_id and (mv or replay.get("model_version")))
    phase2_steps = [
        {
            "name": "create_sim_id_and_link_replay_id_model_id",
            "status": (
                "completed"
                if sim_link_ok
                else ("running" if replay_state in {"running", "starting"} else ("blocked" if phase2_state == "blocked" else "pending"))
            ),
            "ok": sim_link_ok,
            "detail": {
                "sim_id": sim_id,
                "run_id": step1_run_id,
                "simulation_session_id": simulation_session_id,
                "replay_run_id": replay_run_id,
                "model_version": mv or replay.get("model_version"),
            },
        },
        {
            "name": "start_rep01_unpack_randomized_multicore_send",
            "status": "running" if replay_state in {"running", "starting"} else ("completed" if replay_state == "completed" else ("failed" if replay_state in {"failed", "error"} else "pending")),
            "ok": replay_state == "completed",
            "detail": {
                "replay_status": replay_state,
                "target_mode": (replay.get("metadata") or {}).get("factory_result", {}).get("target_mode")
                or (replay.get("metadata") or {}).get("target_mode"),
                "requested_send_workers": (replay.get("metadata") or {}).get("factory_result", {}).get("requested_send_workers")
                or (replay.get("metadata") or {}).get("requested_send_workers"),
                "send_workers": (replay.get("metadata") or {}).get("factory_result", {}).get("send_workers")
                or (replay.get("metadata") or {}).get("send_workers"),
                "effective_send_workers": (replay.get("metadata") or {}).get("factory_result", {}).get("effective_send_workers")
                or (replay.get("metadata") or {}).get("effective_send_workers")
                or (replay.get("metadata") or {}).get("factory_result", {}).get("send_workers")
                or (replay.get("metadata") or {}).get("send_workers"),
                "detection_profile": replay.get("detection_profile") or (replay.get("metadata") or {}).get("detection_profile"),
                "alert_threshold_profile": replay.get("alert_threshold_profile") or (replay.get("metadata") or {}).get("alert_threshold_profile"),
                "window_sizes_s": replay.get("window_sizes_s") or (replay.get("metadata") or {}).get("window_sizes_s"),
            },
        },
        {
            "name": "realtime_shap_alert_and_parent_review_tracking",
            "status": "completed" if metrics_persisted else ("failed" if replay_state == "completed" else "pending"),
            "ok": metrics_persisted,
            "detail": {"metrics_persisted": metrics_persisted},
        },
        {
            "name": "realtime_shap_and_user_alert_status",
            "status": (
                "running"
                if replay_state in {"running", "starting"}
                else ("completed" if replay_state == "completed" else ("failed" if replay_state in {"failed", "error"} else "pending"))
            ),
            "ok": replay_state in {"running", "starting", "completed"},
            "detail": realtime_signals,
        },
        {
            "name": "visual_feed_ready",
            "status": "completed" if replay_run_id else ("blocked" if phase2_state == "blocked" else "pending"),
            "ok": bool(replay_run_id),
        },
    ]
    phase2_ok_count = len([s for s in phase2_steps if bool(s.get("ok"))])
    phase2_total = len(phase2_steps)
    phase2_audit_write = _persist_phase2_step_progress(
        replay_run_id=replay_run_id,
        preparation_replay_id=sim_id,
        simulation_session_id=simulation_session_id,
        run_id=step1_run_id,
        model_id=mid or replay.get("model_id"),
        model_version=mv or replay.get("model_version"),
        phase2_state=phase2_state,
        replay_state=replay_state,
        phase2_steps=phase2_steps,
        phase2_errors=phase2_errors,
        realtime_signals=realtime_signals,
        file_run_summaries=file_run_summaries,
        postgres_validation_report=postgres_validation_report,
        validation_status=validation_status,
    )
    phase2_audit_events = _phase2_step_progress_events(replay_run_id, limit=20)
    phase2_audit_ref = (
        f"/dash_api/model-v1/step3/replay/timeline?replay_run_id={replay_run_id}"
        if replay_run_id
        else None
    )
    phase1_total = len(phase1_substages) if phase1_substages else checks_total
    phase1_ok = len([s for s in phase1_substages if bool(s.get("ok"))]) if phase1_substages else checks_ok
    phase1_progress = int(round((phase1_ok / phase1_total) * 100)) if phase1_total > 0 else 0

    return {
        "ok": True,
        "model_id": mid or None,
        "model_version": mv or None,
        "sim_id": sim_id,
        "run_id": step1_run_id,
        "replay_run_id": replay_run_id,
        "preparation_replay_id": preparation_replay_id,
        "phase1": {
            "name": "Choose Model and Prepare to Start Simulation",
            "status": phase1_state,
            "verified_ok": bool(prep.get("verified_ok")),
            "prepare_status": prep_status or None,
            "checks_passed": checks_ok,
            "checks_total": checks_total,
            "steps_passed": phase1_ok,
            "steps_total": phase1_total,
            "progress_percent": phase1_progress,
            "errors": phase1_errors,
            "substages": phase1_substages,
        },
        "phase2": {
            "name": "Start Simulation",
            "status": phase2_state,
            "replay_status": replay_state,
            "sim_id": sim_id,
            "run_id": step1_run_id,
            "simulation_session_id": simulation_session_id,
            "sim_created_at_utc": replay.get("created_at_utc") or replay.get("started_at"),
            "sim_created_at_ist": replay.get("created_at_ist") or replay.get("started_at_ist"),
            "sim_started_at_utc": replay.get("started_at"),
            "sim_started_at_ist": replay.get("started_at_ist"),
            "sim_ended_at_utc": replay.get("finished_at"),
            "sim_ended_at_ist": replay.get("finished_at_ist"),
            "sim_completed_at_utc": replay.get("finished_at"),
            "sim_completed_at_ist": replay.get("finished_at_ist"),
            "session_started_at_utc": sim_session.get("started_at") if isinstance(sim_session, dict) else None,
            "session_started_at_ist": sim_session.get("started_at_ist") if isinstance(sim_session, dict) else None,
            "session_stopped_at_utc": sim_session.get("stopped_at") if isinstance(sim_session, dict) else None,
            "session_stopped_at_ist": sim_session.get("stopped_at_ist") if isinstance(sim_session, dict) else None,
            "active_streams": int(replay.get("active_streams") or 0),
            "steps_passed": phase2_ok_count,
            "steps_total": phase2_total,
            "progress_percent": int(round((phase2_ok_count / phase2_total) * 100)) if phase2_total > 0 else 0,
            "errors": phase2_errors,
            "steps": phase2_steps,
            "realtime_signals": realtime_signals,
            "audit_log_ref": phase2_audit_ref,
            "step3_audit_log_path": str((replay.get("metadata") or {}).get("step3_audit_log_path") or ""),
            "audit_step_progress_events": phase2_audit_events,
            "audit_step_progress_persist": phase2_audit_write,
            "dissertation_metrics": dm,
            "high_recall_metrics": {
                "rule_hits_by_scope": dm.get("rule_hits_by_scope") if isinstance(dm, dict) else {},
                "rule_hits_by_family": dm.get("rule_hits_by_family") if isinstance(dm, dict) else {},
                "alerts_by_child": dm.get("alerts_by_child") if isinstance(dm, dict) else {},
                "packets_by_child": dm.get("packets_by_child") if isinstance(dm, dict) else {},
                "escalations_by_rule_family": dm.get("escalations_by_rule_family") if isinstance(dm, dict) else {},
                "per_file_alert_density": dm.get("per_file_alert_density") if isinstance(dm, dict) else [],
                "rep01_transmission_by_file": dm.get("rep01_transmission_by_file") if isinstance(dm, dict) else [],
            },
            "file_run_summaries": file_run_summaries,
            "postgres_validation_report": postgres_validation_report,
            "validation_status": validation_status,
            "detailed_metrics_artifact": (
                dm.get("detailed_metrics_artifact")
                if isinstance(dm, dict)
                else {}
            ),
            "visual_dashboard_url": (
                f"./step3_visual.html?model_version={mv}&replay_run_id={replay_run_id}"
                if mv and replay_run_id
                else None
            ),
        },
        "replay": replay,
        "simulation": simulation,
    }
