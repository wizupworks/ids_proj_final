#!/usr/bin/env python3
"""Dashboard-only API for Phase 4 orchestration state."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from services_parent.common.audit_event_types import GOVERNANCE_BLOCKED_ACTION, TRAINING_BLOCKED
from services_parent.common.dataset_role_policy import ingest_workflow_mode
from services_parent.common.governance_summary import build_governance_api_payload, build_leakage_checks_from_db
from services_parent.common.dissertation_completion import (
    export_dissertation_tables_zip,
    get_dissertation_status,
)
from services_parent.common.step_metrics_jobs import (
    generate_step1_metrics,
    generate_step2_metrics,
    generate_step3_metrics,
    generate_step4_metrics,
)
from services_parent.common.metrics_store import load_metric_principles
from services_parent.common.phase4_db import (
    connect,
    create_workflow_request,
    list_dataset_logs,
    register_file_artifact,
    resolve_file_artifact,
    upsert_workflow_runtime_state,
    write_audit_event,
)
from services_parent.common.training_governance_gate import (
    TrainingGovernanceError,
    assert_training_governance_allows,
)
from services_parent.common.governance_action_gate import (
    ACTION_QUEUE_REPLAY_INVENTORY,
    ACTION_QUEUE_SUPERVISED_PIPELINE,
    build_governance_ui_row,
    evaluate_governance_action,
    latest_audit_by_dataset,
)
from services_parent.common.phase4_manifest import (
    attach_policy_to_datasets,
    load_hybrid_policy,
    load_manifest,
    process_csv_readiness,
    registered_artifacts,
    resolve_dataset_raw_dir_with_source,
)
from services_parent.model_v1 import step2_config
from services_parent.model_v1.workflow_coordinator import (
    STEP1_DATASETS,
    reconcile_orphaned_workflow_runs,
    start_step1_async,
    start_step2_async,
    step1_dataset_lineage_hash,
    status_for_run,
)
from services_parent.model_v1.step3_simulation import (
    analyst_feedback as step3_analyst_feedback,
    adapter_logs as step3_adapter_logs,
    adapter_run as step3_adapter_run,
    adapter_status as step3_adapter_status,
    child_health,
    child_listener_status as step3_child_listener_status,
    child_management_status as step3_child_management_status,
    child_stack_lifecycle,
    create_child_stack,
    deploy_rules,
    get_child_stack,
    interactions as step3_interactions,
    list_child_stacks,
    list_child_templates,
    network_status as step3_network_status,
    network_topology as step3_network_topology,
    parent_actions as step3_parent_actions,
    parent_child_interactions as step3_parent_child_interactions,
    step3_alerts as step3_alerts_list,
    submit_analyst_feedback as step3_submit_analyst_feedback,
    replay_runs as step3_replay_runs,
    replay_fail_active as step3_replay_fail_active,
    replay_status as step3_replay_status,
    replay_stop as step3_replay_stop,
    replay_timeline as step3_replay_timeline,
    remove_child_stack,
    rules_status as step3_rules_status,
    run_replay as step3_run_replay,
    simulation_status as step3_simulation_status,
    simulation_stop as step3_simulation_stop,
    step3_audit_events,
    step3_eligible_models,
    step3_model_readiness,
    step3_process_status,
    step3_preparation_status,
    step3_visual_feed,
    step3_status,
)
from services_parent.model_v1.model_versions import (
    clone_model,
    create_model,
    deprecate_model,
    get_model,
    list_models,
    set_current_model,
)


def _parse_metrics(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            x = json.loads(value)
            return x if isinstance(x, dict) else {}
        except Exception:
            return {}
    return {}


IGNORED_UPLOAD_NAMES = {".DS_Store", ".gitkeep"}
_STEP3_REPLAY_BG_LOCK = threading.Lock()
_STEP3_REPLAY_BG_STATE: dict[str, Any] = {
    "running": False,
    "launch_token": None,
    "started_at": None,
    "finished_at": None,
    "last_error": None,
    "last_result": None,
    "audit_log_path": None,
}
_STEP3_REPLAY_BG_THREAD: threading.Thread | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _step3_audit_log_dir(data_root: Path) -> Path:
    root = str(os.getenv("STEP3_AUDIT_LOG_DIR", "")).strip()
    if root:
        return Path(root)
    return data_root / "outputs" / "model_v1" / "step3" / "audit"


def _step3_new_audit_log_path(data_root: Path, *, model_version: str | None = None) -> Path:
    _ = model_version
    return _step3_audit_log_dir(data_root) / "step3_audit_step3_all.jsonl"


def _append_step3_audit_log(log_path: str | Path | None, *, event: str, payload: dict[str, Any] | None = None) -> None:
    raw = str(log_path or "").strip()
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
            event_type=f"step3_dashboard_{str(event or 'unknown')}",
            actor="phase4_dash_api",
            artifact_refs=[],
            context={
                "step": "step3",
                "step_unique_id": step_unique_id,
                "legacy_log_path": raw,
                "payload": details,
                "ts_utc": utc_now(),
            },
            dataset_id=str(details.get("dataset_id") or "REP-01").strip() or "REP-01",
            model_version=str(details.get("model_version") or "").strip() or None,
            replay_id=str(details.get("replay_id") or details.get("preparation_replay_id") or "").strip() or None,
            step="step3",
            step_unique_id=step_unique_id,
        )
    except Exception:
        return


def _read_step3_audit_log(log_path: str | Path | None, *, max_lines: int = 500) -> list[dict[str, Any]]:
    raw = str(log_path or "").strip()
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT audit_id::text, event_type, actor, event_details_json, created_at
                    FROM phase4.audit_log
                    WHERE step = 'step3'
                      AND (%(legacy_log_path)s = '' OR COALESCE(event_details_json->>'legacy_log_path','') = %(legacy_log_path)s)
                    ORDER BY created_at DESC
                    LIMIT %(limit)s;
                    """,
                    {
                        "legacy_log_path": raw,
                        "limit": max(1, int(max_lines)),
                    },
                )
                rows = cur.fetchall() or []
        out: list[dict[str, Any]] = []
        for row in rows:
            details = row[3] if isinstance(row[3], dict) else {}
            out.append(
                {
                    "audit_id": str(row[0]),
                    "event": str(row[1] or ""),
                    "actor": str(row[2] or ""),
                    "ts_utc": str(row[4]) if row[4] else None,
                    "payload": details.get("payload") if isinstance(details.get("payload"), dict) else details,
                }
            )
        return out
    except Exception:
        return []


def load_json(path: Path, default: dict) -> dict:
    if not path.is_file():
        return default
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def read_manifest(path: Path, hybrid_policy_path: Path) -> list[dict]:
    manifest = load_manifest(path)
    hybrid_policy = load_hybrid_policy(hybrid_policy_path)
    return attach_policy_to_datasets(manifest, hybrid_policy)


def required_dataset_ids(datasets: list[dict], override: str) -> set[str]:
    """Optional env override only; no static required-dataset gate."""
    if override.strip():
        return {item.strip() for item in override.split(",") if item.strip()}
    return set()


def has_uploads(path: Path) -> bool:
    if not path.exists():
        return False
    return any(p.is_file() and p.name not in IGNORED_UPLOAD_NAMES for p in path.rglob("*"))


def default_state() -> dict:
    return {
        "phase": "download",
        "download_phase_visible": True,
        "ingestion_request_id": None,
        "ingestion_started_at_utc": None,
        "ingestion_completed_at_utc": None,
        "last_error": None,
        "updated_at_utc": utc_now(),
        "stages": [
            {"id": "normalise", "label": "Normalise", "status": "pending"},
            {"id": "categorise", "label": "Categorise", "status": "pending"},
            {"id": "split", "label": "Train / Validate / Test split", "status": "pending"},
            {"id": "ingest", "label": "Ingest", "status": "pending"},
            {"id": "postgres", "label": "Postgres tables", "status": "pending"},
        ],
    }


def merge_state(state_path: Path) -> dict:
    state = default_state()
    persisted = load_json(state_path, {})
    persisted_stages = {
        item.get("id"): item
        for item in persisted.get("stages", [])
        if isinstance(item, dict) and item.get("id")
    }
    state.update({key: value for key, value in persisted.items() if key != "stages"})
    state["stages"] = [
        {**stage, "status": persisted_stages.get(stage["id"], {}).get("status", stage["status"])}
        for stage in state["stages"]
    ]
    return state


class DashHandler(BaseHTTPRequestHandler):
    server_version = "Phase4DashAPI/1.0"

    @property
    def manifest_path(self) -> Path:
        return self.server.manifest_path  # type: ignore[attr-defined]

    @property
    def hybrid_policy_path(self) -> Path:
        return self.server.hybrid_policy_path  # type: ignore[attr-defined]

    @property
    def data_root(self) -> Path:
        return self.server.data_root  # type: ignore[attr-defined]

    @property
    def state_path(self) -> Path:
        return self.server.state_path  # type: ignore[attr-defined]

    @property
    def control_dir(self) -> Path:
        return self.server.control_dir  # type: ignore[attr-defined]

    @property
    def required_override(self) -> str:
        return self.server.required_override  # type: ignore[attr-defined]

    @property
    def experiment_design_path(self) -> Path:
        return self.server.experiment_design_path  # type: ignore[attr-defined]

    def step0_readiness(self, item: dict) -> dict:
        """Manifest Step-0 check (process_csv_paths on disk) for a dataset row from the manifest."""
        resolved = resolve_dataset_raw_dir_with_source(self.data_root, item)
        return process_csv_readiness(self.data_root, item, precomputed_raw=resolved)

    def log_message(self, fmt: str, *args: object) -> None:
        print("[dash-api] " + fmt % args)

    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    @staticmethod
    def _norm_http_path(raw_path: str) -> str:
        """Match routes whether the client called /status, /api/status, or /dash_api/... (with or without nginx strip)."""
        p = (raw_path.split("?", 1)[0].rstrip("/") or "/")
        # Strip /api and /dash_api segment-by-segment; str.removeprefix("/dash_api") on
        # "/dash_api/model-v1/models" yields "model-v1/models" (no leading "/") and breaks routing.
        while True:
            if p.startswith("/dash_api/"):
                p = "/" + p[len("/dash_api/") :].lstrip("/")
            elif p == "/dash_api":
                p = "/"
            elif p.startswith("/api/"):
                p = "/" + p[len("/api/") :].lstrip("/")
            elif p == "/api":
                p = "/"
            else:
                break
            if p == "":
                p = "/"
                break
        if not p.startswith("/"):
            p = "/" + p
        return p or "/"

    def _content_type_for_artifact(self, content_type: str | None, file_path: str) -> str:
        if content_type:
            return content_type
        suffix = Path(file_path).suffix.lower()
        if suffix in {".json", ".jsonl"}:
            return "application/json"
        if suffix in {".log", ".txt", ".md", ".csv"}:
            return "text/plain; charset=utf-8"
        return "application/octet-stream"

    def _artifact_url_from_path(
        self,
        *,
        file_path: str | None,
        artifact_type: str,
        run_id: str | None = None,
        model_id: str | None = None,
        model_version: str | None = None,
        step_name: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str | None:
        if not file_path:
            return None
        try:
            row = register_file_artifact(
                file_path=file_path,
                artifact_type=artifact_type,
                run_id=run_id,
                model_id=model_id,
                model_version=model_version,
                step_name=step_name,
                metadata=metadata or {},
            )
        except Exception:
            return None
        if not row:
            return None
        return f"/dash_api/artifacts/view?artifact_id={row['artifact_id']}"

    def _serve_artifact_by_id(self, artifact_id: str) -> None:
        row = resolve_file_artifact(artifact_id)
        if not row:
            self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "artifact_not_found"})
            return
        file_path = str(row.get("file_path") or "")
        path = Path(file_path)
        if not path.is_file():
            self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "artifact_file_missing", "file_path": file_path})
            return
        data = path.read_bytes()
        content_type = self._content_type_for_artifact(row.get("content_type"), file_path)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_bytes(
        self,
        status: HTTPStatus,
        payload: bytes,
        *,
        content_type: str = "application/octet-stream",
        filename: str | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(payload)

    def send_json(self, status: HTTPStatus, payload: dict) -> None:
        # DB-backed fields often include datetime/Decimal/uuid; default=str avoids 500 on json.dumps.
        try:
            raw = json.dumps(payload, indent=2, sort_keys=True, default=str)
        except (TypeError, ValueError) as exc:
            raw = json.dumps(
                {"ok": False, "error": "json_serialization_failed", "detail": str(exc)},
                indent=2,
                sort_keys=True,
                default=str,
            )
        body = raw.encode("utf-8", errors="replace")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _step3_v2_upstream_bases() -> list[str]:
        # When requests reach phase4-dash-api directly (without nginx location split),
        # proxy Step3 V2 endpoints to the dedicated engine service.
        raw_candidates = [
            str(os.getenv("STEP3_V2_ENGINE_BASE_URL", "")).strip(),
            "http://step3-v2-engine:8091",
            "http://127.0.0.1:8091",
        ]
        out: list[str] = []
        for raw in raw_candidates:
            base = str(raw or "").strip().rstrip("/")
            if not base or base in out:
                continue
            out.append(base)
        return out

    def _proxy_step3_v2(
        self,
        *,
        method: str,
        path: str,
        query: str = "",
        payload: dict[str, Any] | None = None,
        stream: bool = False,
    ) -> None:
        body = None
        headers: dict[str, str] = {"Accept": str(self.headers.get("Accept") or "application/json")}
        last_event_id = str(self.headers.get("Last-Event-ID") or "").strip()
        if last_event_id:
            headers["Last-Event-ID"] = last_event_id
        if payload is not None:
            body = json.dumps(payload, default=str).encode("utf-8")
            headers["Content-Type"] = "application/json"
        suffix = f"{path}?{query}" if query else path
        last_error: str | None = None
        for base in self._step3_v2_upstream_bases():
            target = f"{base}{suffix}"
            req = Request(url=target, data=body, method=method.upper(), headers=headers)
            try:
                with urlopen(req, timeout=65 if stream else 25) as resp:
                    status_code = int(getattr(resp, "status", HTTPStatus.OK))
                    content_type = str(resp.headers.get("Content-Type") or "application/json")
                    cache_control = str(resp.headers.get("Cache-Control") or "")
                    if stream:
                        self.send_response(status_code)
                        self.send_header("Content-Type", content_type)
                        if cache_control:
                            self.send_header("Cache-Control", cache_control)
                        self.end_headers()
                        try:
                            while True:
                                chunk = resp.read(4096)
                                if not chunk:
                                    break
                                self.wfile.write(chunk)
                                self.wfile.flush()
                        except BrokenPipeError:
                            return
                        return
                    body_bytes = resp.read() or b"{}"
                    self.send_response(status_code)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(body_bytes)))
                    if cache_control:
                        self.send_header("Cache-Control", cache_control)
                    self.end_headers()
                    self.wfile.write(body_bytes)
                    return
            except HTTPError as http_err:
                err_body = http_err.read() or b"{}"
                err_content_type = str(http_err.headers.get("Content-Type") or "application/json")
                self.send_response(int(http_err.code))
                self.send_header("Content-Type", err_content_type)
                self.send_header("Content-Length", str(len(err_body)))
                self.end_headers()
                self.wfile.write(err_body)
                return
            except URLError as net_err:
                last_error = str(net_err.reason or net_err)
                continue
            except Exception as exc:
                last_error = str(exc)
                continue
        self.send_json(
            HTTPStatus.SERVICE_UNAVAILABLE,
            {
                "ok": False,
                "error": "step3_v2_upstream_unavailable",
                "detail": str(last_error or "no_step3_v2_upstream_reachable"),
                "path": path,
            },
        )

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()

    def do_GET(self) -> None:
        path = DashHandler._norm_http_path(urlparse(self.path).path)
        if path.startswith("/model-v1/step3/v2/"):
            parsed = urlparse(self.path)
            self._proxy_step3_v2(method="GET", path=path, query=parsed.query, stream=(path == "/model-v1/step3/v2/stream"))
            return
        if path == "/health":
            self.send_json(HTTPStatus.OK, {"ok": True, "service": "phase4-dash-api"})
            return
        if path == "/status":
            self.send_json(HTTPStatus.OK, self.status_payload())
            return
        if path == "/artifacts/view":
            params = parse_qs(urlparse(self.path).query, keep_blank_values=False)
            artifact_id = str((params.get("artifact_id") or [""])[0]).strip()
            if not artifact_id:
                self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "artifact_id_required"})
                return
            self._serve_artifact_by_id(artifact_id)
            return
        if path == "/governance/summary":
            self.send_json(HTTPStatus.OK, self.governance_payload())
            return
        if path in {"/dissertation/status", "/step4/status"}:
            qs = parse_qs(urlparse(self.path).query or "")
            mv = str((qs.get("model_version") or [""])[0]).strip() or None
            step1_run_id = str((qs.get("step1_run_id") or [""])[0]).strip() or None
            step2_model_id = str((qs.get("step2_model_id") or [""])[0]).strip() or None
            step2_run_id = str((qs.get("step2_run_id") or [""])[0]).strip() or None
            step3_v2_sim_id = str((qs.get("step3_v2_sim_id") or qs.get("sim_id") or [""])[0]).strip() or None
            self.send_json(
                HTTPStatus.OK,
                get_dissertation_status(
                    mv,
                    step1_run_id=step1_run_id,
                    step2_model_id=step2_model_id,
                    step2_run_id=step2_run_id,
                    step3_v2_sim_id=step3_v2_sim_id,
                ),
            )
            return
        if path in {"/dissertation/export.zip", "/step4/export.zip"}:
            qs = parse_qs(urlparse(self.path).query or "")
            mv = str((qs.get("model_version") or [""])[0]).strip() or None
            step1_run_id = str((qs.get("step1_run_id") or [""])[0]).strip() or None
            step2_model_id = str((qs.get("step2_model_id") or [""])[0]).strip() or None
            step2_run_id = str((qs.get("step2_run_id") or [""])[0]).strip() or None
            step3_v2_sim_id = str((qs.get("step3_v2_sim_id") or qs.get("sim_id") or [""])[0]).strip() or None
            refresh_raw = str((qs.get("refresh") or ["0"])[0]).strip().lower()
            refresh = refresh_raw in {"1", "true", "yes", "y", "on"}
            export_payload = export_dissertation_tables_zip(
                mv,
                step1_run_id=step1_run_id,
                step2_model_id=step2_model_id,
                step2_run_id=step2_run_id,
                step3_v2_sim_id=step3_v2_sim_id,
                refresh=refresh,
            )
            if not export_payload.get("ok"):
                self.send_json(HTTPStatus.BAD_REQUEST, export_payload)
                return
            zip_path = Path(str(export_payload.get("zip_path") or ""))
            if not zip_path.is_file():
                self.send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {
                        "ok": False,
                        "error": "zip_file_not_found_after_export",
                        "zip_path": str(zip_path),
                    },
                )
                return
            resolved_mv = str(export_payload.get("resolved_model_version") or "")
            register_file_artifact(
                file_path=str(zip_path),
                artifact_type="step4_dissertation_tables_zip",
                model_version=resolved_mv,
                step_name="step4",
                metadata={
                    "requested_model_version": str(export_payload.get("requested_model_version") or ""),
                    "requested_step1_run_id": str(export_payload.get("requested_step1_run_id") or ""),
                    "requested_step2_model_id": str(export_payload.get("requested_step2_model_id") or ""),
                    "requested_step2_run_id": str(export_payload.get("requested_step2_run_id") or ""),
                    "requested_step3_v2_sim_id": str(export_payload.get("requested_step3_v2_sim_id") or ""),
                    "resolved_model_version": resolved_mv,
                    "refresh": refresh,
                    "snapshot_mode": bool(export_payload.get("snapshot_mode")),
                    "artifact_count": int(export_payload.get("artifact_count") or 0),
                    "missing_files": export_payload.get("missing_files") or [],
                    "metrics_required_coverage": ((export_payload.get("status") or {}).get("metrics_required_coverage") or {}),
                },
            )
            self.send_bytes(
                HTTPStatus.OK,
                zip_path.read_bytes(),
                content_type="application/zip",
                filename=str(export_payload.get("zip_name") or zip_path.name),
            )
            return
        if path == "/step3/status":
            self.send_json(HTTPStatus.OK, step3_status())
            return
        if path == "/model-v1/status":
            self.send_json(HTTPStatus.OK, self.current_model_header_payload())
            return
        if path == "/model-v1/current-model-header":
            self.send_json(HTTPStatus.OK, self.current_model_header_payload())
            return
        if path == "/model-v1/step1/runs":
            self.send_json(HTTPStatus.OK, self.list_step1_runs_payload())
            return
        if path.startswith("/model-v1/step1/runs/"):
            rid = path.removeprefix("/model-v1/step1/runs/")
            self.send_json(HTTPStatus.OK, self.step1_run_detail_payload(rid))
            return
        if path == "/model-v1/models":
            params = parse_qs(urlparse(self.path).query, keep_blank_values=False)
            q = str((params.get("q") or [""])[0]).strip()
            status = str((params.get("status") or [""])[0]).strip()
            sort = str((params.get("sort") or ["created_at_desc"])[0]).strip() or "created_at_desc"
            self.send_json(HTTPStatus.OK, list_models(q=q, status=status, sort=sort))
            return
        if path.startswith("/model-v1/models/") and path.endswith("/artifacts"):
            mv = path.removeprefix("/model-v1/models/").removesuffix("/artifacts")
            model = get_model(mv)
            if not model.get("ok"):
                self.send_json(HTTPStatus.NOT_FOUND, model)
                return
            self.send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "model_version": mv,
                    "artifacts": {
                        "artifact_root": model["model"].get("artifact_root"),
                        "model_artifact_path": model["model"].get("model_artifact_path"),
                        "metrics_artifact_path": model["model"].get("metrics_artifact_path"),
                        "shap_artifact_root": model["model"].get("shap_artifact_root"),
                        "rulepack_root": model["model"].get("rulepack_root"),
                    },
                },
            )
            return
        if path.startswith("/model-v1/models/") and path.endswith("/metrics"):
            mv = path.removeprefix("/model-v1/models/").removesuffix("/metrics")
            self.send_json(HTTPStatus.OK, {"ok": True, "model_version": mv, **self.metrics_payload()})
            return
        if path.startswith("/model-v1/models/") and path.endswith("/audit"):
            mv = path.removeprefix("/model-v1/models/").removesuffix("/audit")
            gov = self.governance_payload()
            audit_rows = ((gov.get("audit_trail") or {}).get("recent_events") or [])
            self.send_json(
                HTTPStatus.OK,
                {"ok": True, "model_version": mv, "audit": [x for x in audit_rows if str(x.get("model_version") or "") == mv]},
            )
            return
        if path.startswith("/model-v1/models/"):
            mv = path.removeprefix("/model-v1/models/")
            self.send_json(HTTPStatus.OK, get_model(mv))
            return
        if path == "/model-v1/step2/readiness":
            qs = parse_qs(urlparse(self.path).query or "")
            mv = str((qs.get("model_version") or [""])[0]).strip()
            if not mv:
                self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "model_version_required"})
                return
            rid = str((qs.get("source_step1_run_id") or [""])[0]).strip()
            payload = self.step2_readiness_payload(mv)
            if rid:
                detail = self.step1_run_detail_payload(rid)
                payload["selected_step1_run"] = detail.get("run")
                if not detail.get("ok"):
                    payload["ready"] = False
                    payload.setdefault("issues", []).append("selected_step1_run_not_found")
                elif str((detail.get("run") or {}).get("readiness_status")) != "ready":
                    payload["ready"] = False
                    payload.setdefault("issues", []).append("selected_step1_run_not_ready")
            self.send_json(HTTPStatus.OK, payload)
            return
        if path == "/model-v1/step3/child-templates":
            self.send_json(HTTPStatus.OK, list_child_templates())
            return
        if path == "/model-v1/step3/eligible-models":
            qs = parse_qs(urlparse(self.path).query or "")
            ro = str((qs.get("ready_only") or ["0"])[0]).strip().lower() in {"1", "true", "yes", "y", "on"}
            self.send_json(HTTPStatus.OK, step3_eligible_models(ready_only=ro))
            return
        if path == "/model-v1/step3/preparation/status":
            qs = parse_qs(urlparse(self.path).query or "")
            mv = str((qs.get("model_version") or [""])[0]).strip()
            # Don't error here - let step3_preparation_status handle default
            self.send_json(HTTPStatus.OK, step3_preparation_status(model_version=mv))
            return
        if path == "/model-v1/step3/process/status":
            qs = parse_qs(urlparse(self.path).query or "")
            self.send_json(
                HTTPStatus.OK,
                step3_process_status(
                    model_id=str((qs.get("model_id") or [""])[0]).strip() or None,
                    model_version=str((qs.get("model_version") or [""])[0]).strip() or None,
                ),
            )
            return
        if path == "/model-v1/step3/readiness":
            qs = parse_qs(urlparse(self.path).query or "")
            model_id = str((qs.get("model_id") or [""])[0]).strip()
            model_version = str((qs.get("model_version") or [""])[0]).strip()
            if not model_id and not model_version:
                self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "model_id_or_model_version_required"})
                return
            self.send_json(HTTPStatus.OK, step3_model_readiness(model_id=model_id or None, model_version=model_version or None))
            return
        if path == "/model-v1/step3/network-topology":
            self.send_json(HTTPStatus.OK, step3_network_topology())
            return
        if path == "/model-v1/step3/network-status":
            self.send_json(HTTPStatus.OK, step3_network_status())
            return
        if path == "/model-v1/step3/simulation/status":
            self.send_json(HTTPStatus.OK, step3_simulation_status())
            return
        if path == "/model-v1/step3/adapter/status":
            self.send_json(HTTPStatus.OK, step3_adapter_status())
            return
        if path == "/model-v1/step3/adapter/logs":
            self.send_json(HTTPStatus.OK, step3_adapter_logs())
            return
        if path == "/model-v1/step3/replay/timeline":
            qs = parse_qs(urlparse(self.path).query or "")
            rid = (qs.get("replay_run_id") or [None])[0]
            self.send_json(HTTPStatus.OK, step3_replay_timeline(str(rid) if rid else None))
            return
        if path == "/model-v1/step3/visual-feed":
            qs = parse_qs(urlparse(self.path).query or "")
            try:
                lim = int(str((qs.get("limit") or ["200"])[0]).strip() or "200")
            except ValueError:
                lim = 200
            try:
                self.send_json(
                    HTTPStatus.OK,
                    step3_visual_feed(
                        model_id=str((qs.get("model_id") or [""])[0]).strip() or None,
                        model_version=str((qs.get("model_version") or [""])[0]).strip() or None,
                        replay_run_id=str((qs.get("replay_run_id") or [""])[0]).strip() or None,
                        since_ts=str((qs.get("since_ts") or [""])[0]).strip() or None,
                        since_event_id=str((qs.get("since_event_id") or [""])[0]).strip() or None,
                        limit=lim,
                    ),
                )
            except Exception as exc:
                print(f"[dash-api] step3 visual-feed failed: {exc}", flush=True)
                self.send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"ok": False, "error": "visual_feed_failed", "detail": str(exc)})
            return
        if path == "/model-v1/step3/parent-child-interactions":
            self.send_json(HTTPStatus.OK, step3_parent_child_interactions())
            return
        if path == "/model-v1/step3/child-stacks":
            self.send_json(HTTPStatus.OK, list_child_stacks())
            return
        if path.startswith("/model-v1/step3/child-stacks/") and path.endswith("/listener-status"):
            child_id = path.removeprefix("/model-v1/step3/child-stacks/").removesuffix("/listener-status")
            self.send_json(HTTPStatus.OK, step3_child_listener_status(child_id))
            return
        if path.startswith("/model-v1/step3/child-stacks/") and path.endswith("/management-status"):
            child_id = path.removeprefix("/model-v1/step3/child-stacks/").removesuffix("/management-status")
            self.send_json(HTTPStatus.OK, step3_child_management_status(child_id))
            return
        if path.startswith("/model-v1/step3/child-stacks/") and path.endswith("/health"):
            child_id = path.removeprefix("/model-v1/step3/child-stacks/").removesuffix("/health")
            self.send_json(HTTPStatus.OK, child_health(child_id))
            return
        if path.startswith("/model-v1/step3/child-stacks/"):
            child_id = path.removeprefix("/model-v1/step3/child-stacks/")
            self.send_json(HTTPStatus.OK, get_child_stack(child_id))
            return
        if path == "/model-v1/step3/rules/status":
            self.send_json(HTTPStatus.OK, step3_rules_status())
            return
        if path == "/model-v1/step3/replay/status":
            self.send_json(HTTPStatus.OK, step3_replay_status())
            return
        if path == "/model-v1/step3/replay/runs":
            self.send_json(HTTPStatus.OK, step3_replay_runs())
            return
        if path == "/model-v1/step3/interactions":
            self.send_json(HTTPStatus.OK, step3_interactions())
            return
        if path == "/model-v1/step3/parent-actions":
            self.send_json(HTTPStatus.OK, step3_parent_actions())
            return
        if path == "/model-v1/step3/alerts":
            qs = parse_qs(urlparse(self.path).query or "")
            try:
                lim = int(str((qs.get("limit") or ["300"])[0]).strip() or "300")
            except ValueError:
                lim = 300
            self.send_json(
                HTTPStatus.OK,
                step3_alerts_list(
                    model_id=str((qs.get("model_id") or [""])[0]).strip() or None,
                    model_version=str((qs.get("model_version") or [""])[0]).strip() or None,
                    replay_run_id=str((qs.get("replay_run_id") or [""])[0]).strip() or None,
                    child_id=str((qs.get("child_id") or [""])[0]).strip() or None,
                    urgency=str((qs.get("urgency") or [""])[0]).strip() or None,
                    status=str((qs.get("status") or [""])[0]).strip() or None,
                    limit=lim,
                ),
            )
            return
        if path == "/model-v1/step3/analyst-feedback":
            qs = parse_qs(urlparse(self.path).query or "")
            try:
                lim = int(str((qs.get("limit") or ["300"])[0]).strip() or "300")
            except ValueError:
                lim = 300
            self.send_json(
                HTTPStatus.OK,
                step3_analyst_feedback(
                    alert_id=str((qs.get("alert_id") or [""])[0]).strip() or None,
                    replay_id=str((qs.get("replay_id") or [""])[0]).strip() or None,
                    replay_run_id=str((qs.get("replay_run_id") or [""])[0]).strip() or None,
                    model_version=str((qs.get("model_version") or [""])[0]).strip() or None,
                    limit=lim,
                ),
            )
            return
        if path == "/model-v1/step3/audit-events":
            self.send_json(HTTPStatus.OK, step3_audit_events())
            return
        if path == "/model-v1/step3/audit-log":
            qs = parse_qs(urlparse(self.path).query or "")
            try:
                max_lines = int(str((qs.get("max_lines") or ["500"])[0]).strip() or "500")
            except Exception:
                max_lines = 500
            log_path = _step3_new_audit_log_path(self.data_root)
            self.send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "path": "phase4.audit_log",
                    "legacy_path_filter": str(log_path),
                    "max_lines": max_lines,
                    "rows": _read_step3_audit_log(log_path, max_lines=max_lines),
                },
            )
            return
        if path == "/step1/status":
            self.step_status("step1")
            return
        if path == "/step1/split-summary":
            params = parse_qs(urlparse(self.path).query, keep_blank_values=False)
            rid = str((params.get("run_id") or [""])[0]).strip()
            self.send_json(HTTPStatus.OK, self.step1_split_summary_payload(rid or None))
            return
        if path == "/step2/status":
            self.step_status("step2")
            return
        if path == "/model-v1/step2/status":
            self.model_v1_step2_status_get()
            return
        if path.startswith("/model-v1/step2/"):
            self.model_v1_step2_resource_get(path)
            return
        if path == "/model-v1/step3/metrics":
            qs = parse_qs(urlparse(self.path).query, keep_blank_values=False)
            sim_id = str((qs.get("sim_id") or qs.get("step3_sim_id") or qs.get("simulation_id") or [""])[0]).strip()
            self.send_json(HTTPStatus.OK if sim_id else HTTPStatus.BAD_REQUEST, self.step3_metrics_payload(sim_id=sim_id))
            return
        if path == "/model-v1/metrics":
            self.send_json(HTTPStatus.OK, self.metrics_payload())
            return
        if path == "/model-v1/shap/summary":
            self.send_json(HTTPStatus.OK, self.shap_summary_payload())
            return
        if path == "/model-v1/rules/summary":
            self.send_json(HTTPStatus.OK, self.rules_summary_payload())
            return
        if path == "/model-v1/rulepacks":
            self.send_json(HTTPStatus.OK, self.rulepacks_payload())
            return
        if path == "/model-v1/audit-events":
            gov = self.governance_payload()
            self.send_json(
                HTTPStatus.OK,
                {"ok": True, "audit": ((gov.get("audit_trail") or {}).get("recent_events") or [])},
            )
            return
        if path == "/datasets":
            self.send_json(HTTPStatus.OK, {"ok": True, "datasets": self.upload_status()[0]})
            return
        if path == "/logs":
            params = parse_qs(urlparse(self.path).query, keep_blank_values=False)
            rid = str((params.get("run_id") or [""])[0]).strip()
            logs = self.status_payload().get("dataset_logs", [])
            if rid:
                logs = [row for row in logs if str((row.get("metadata") or {}).get("run_id") or "") == rid]
            self.send_json(HTTPStatus.OK, {"ok": True, "logs": logs})
            return
        if path == "/audit":
            gov = self.governance_payload()
            self.send_json(
                HTTPStatus.OK,
                {"ok": True, "audit": ((gov.get("audit_trail") or {}).get("recent_events") or [])},
            )
            return
        if path == "/artifacts":
            self.send_json(HTTPStatus.OK, self.artifacts_payload())
            return
        if path == "/metrics":
            self.send_json(HTTPStatus.OK, self.metrics_payload())
            return
        if path == "/metrics/source":
            qs = parse_qs(urlparse(self.path).query, keep_blank_values=False)
            doc = str((qs.get("doc") or [""])[0]).strip().lower()
            source_map = {
                "metrics": REPO_ROOT / "docs" / "final_dissertation_docs" / "metrics.md",
                "metrics_principle_review": REPO_ROOT / "docs" / "final_dissertation_docs" / "metrics_principle_review.md",
            }
            source_path = source_map.get(doc)
            if source_path is None:
                self.send_json(
                    HTTPStatus.BAD_REQUEST,
                    {
                        "ok": False,
                        "error": "invalid_metrics_source_doc",
                        "allowed_docs": sorted(source_map.keys()),
                    },
                )
                return
            if not source_path.is_file():
                self.send_json(
                    HTTPStatus.NOT_FOUND,
                    {
                        "ok": False,
                        "error": "metrics_source_not_found",
                        "doc": doc,
                        "path": str(source_path),
                    },
                )
                return
            try:
                content = source_path.read_text(encoding="utf-8")
            except Exception as exc:
                self.send_json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {
                        "ok": False,
                        "error": "metrics_source_read_failed",
                        "doc": doc,
                        "path": str(source_path),
                        "detail": str(exc),
                    },
                )
                return
            self.send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "doc": doc,
                    "path": str(source_path),
                    "content": content,
                },
            )
            return
        if path == "/rulepacks":
            self.send_json(HTTPStatus.OK, self.rulepacks_payload())
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Unknown endpoint."})

    def _fmt_ts(self, value: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            return value
        try:
            return value.isoformat()
        except Exception:
            return str(value)

    def _duration_seconds(self, started: str | None, finished: str | None) -> float | None:
        if not started or not finished:
            return None
        try:
            s = datetime.fromisoformat(started.replace("Z", "+00:00"))
            f = datetime.fromisoformat(finished.replace("Z", "+00:00"))
            return round(max(0.0, (f - s).total_seconds()), 3)
        except Exception:
            return None

    def _normalize_status(self, raw: Any) -> str:
        s = str(raw or "").strip().lower()
        if s in {"pending", "queued", "running", "completed", "failed", "skipped", "partial"}:
            return s
        if s in {"success", "done", "ok", "published"}:
            return "completed"
        if s in {"error"}:
            return "failed"
        return "pending"

    def _derive_parent_status(self, children: list[dict[str, Any]], required_ids: set[str]) -> str:
        if not children:
            return "pending"
        by_id = {str(c.get("id")): self._normalize_status(c.get("status")) for c in children}
        required = [by_id.get(cid, "pending") for cid in required_ids] if required_ids else list(by_id.values())
        all_status = list(by_id.values())
        if any(s == "running" for s in all_status):
            return "running"
        if any(s == "failed" for s in required):
            return "failed"
        if all(s in {"completed", "skipped"} for s in required) and required:
            if any(s in {"failed", "partial"} for s in all_status if s not in required):
                return "partial"
            return "completed"
        if any(s in {"completed", "partial", "failed", "queued", "running"} for s in all_status):
            return "partial"
        return "pending"

    def _build_step2_hierarchy(self, run_id: str, base: dict[str, Any]) -> dict[str, Any]:
        live = base.get("live") or {}
        db = base.get("db") or {}
        metrics = db.get("run_metrics") or {}
        if isinstance(metrics, str):
            try:
                metrics = json.loads(metrics)
            except Exception:
                metrics = {}
        metrics_testing_results = metrics.get("testing_results") if isinstance(metrics.get("testing_results"), list) else []
        metrics_shap_results = metrics.get("shap_results") if isinstance(metrics.get("shap_results"), list) else []
        metrics_rule_results = metrics.get("rule_results") if isinstance(metrics.get("rule_results"), list) else []
        metrics_training_result = metrics.get("training_result") if isinstance(metrics.get("training_result"), dict) else {}
        metrics_training_payload = (
            metrics_training_result.get("metrics") if isinstance(metrics_training_result.get("metrics"), dict) else {}
        )
        step2_metric_results_rows: list[dict[str, Any]] = []
        step2_missing_requirements: list[dict[str, Any]] = []
        step2_metric_rows_error = ""
        step2_metrics_excluded = {
            "cross_scope_detection_rate",
            "explanation_usefulness",
            "rule_version_traceability",
            "analyst_readiness_score",
            "rule_precision",
            "rule_scope_accuracy",
            "rule_replay_stability",
            "escalation_usefulness",
            "pareto_rank",
        }

        training_row: dict[str, Any] | None = None
        holdout_row: dict[str, Any] | None = None
        cross_rows: dict[str, dict[str, Any]] = {}
        shap_rows: list[dict[str, Any]] = []
        rule_rows: dict[str, dict[str, Any]] = {}
        rule_rule_count: dict[str, int] = {}
        latest_audits: list[dict[str, Any]] = []
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT status, worker_count, started_at_utc, completed_at_utc, metrics_json
                        FROM phase4.model_training_runs
                        WHERE run_id = %(rid)s::uuid
                        ORDER BY started_at_utc DESC
                        LIMIT 1;
                        """,
                        {"rid": run_id},
                    )
                    row = cur.fetchone()
                    if row:
                        training_row = {
                            "status": row[0],
                            "worker_count": row[1],
                            "started_at": self._fmt_ts(row[2]),
                            "finished_at": self._fmt_ts(row[3]),
                            "metrics": row[4] or {},
                        }
                    cur.execute(
                        """
                        SELECT status, started_at_utc, completed_at_utc, metrics_json
                        FROM phase4.model_evaluation_runs
                        WHERE run_id = %(rid)s::uuid AND dataset_id = 'ENT-01' AND split_name = 'test'
                        ORDER BY started_at_utc DESC
                        LIMIT 1;
                        """,
                        {"rid": run_id},
                    )
                    row = cur.fetchone()
                    if row:
                        holdout_row = {
                            "status": row[0],
                            "started_at": self._fmt_ts(row[1]),
                            "finished_at": self._fmt_ts(row[2]),
                            "metrics": row[3] or {},
                        }
                    cur.execute(
                        """
                        SELECT dataset_id, status, started_at_utc, completed_at_utc, metrics_json
                        FROM phase4.cross_dataset_test_runs
                        WHERE run_id = %(rid)s::uuid
                        ORDER BY started_at_utc DESC;
                        """,
                        {"rid": run_id},
                    )
                    for ds, st, sa, fa, mj in cur.fetchall():
                        if ds in cross_rows:
                            continue
                        cross_rows[ds] = {
                            "status": st,
                            "started_at": self._fmt_ts(sa),
                            "finished_at": self._fmt_ts(fa),
                            "metrics": mj or {},
                        }
                    cur.execute(
                        """
                        SELECT split_name, partition_id, artifact_path, status, created_at_utc, metadata
                        FROM phase4.shap_artifacts
                        WHERE run_id = %(rid)s::uuid
                        ORDER BY created_at_utc DESC;
                        """,
                        {"rid": run_id},
                    )
                    for split, partition_id, artifact_path, st, created_at, md in cur.fetchall():
                        shap_rows.append(
                            {
                                "split_name": split,
                                "partition_id": partition_id,
                                "artifact_path": artifact_path,
                                "status": st,
                                "created_at": self._fmt_ts(created_at),
                                "metadata": md or {},
                            }
                        )
                    rulepack_rows: list[tuple[Any, ...]] = []
                    cur.execute(
                        """
                        SELECT EXISTS (
                            SELECT 1
                            FROM information_schema.columns
                            WHERE table_schema = 'phase4'
                              AND table_name = 'rulepack_registry'
                              AND column_name = 'published_at_utc'
                        );
                        """
                    )
                    has_published_at_col = bool(cur.fetchone()[0])
                    if has_published_at_col:
                        cur.execute(
                            """
                            SELECT scope, status, artifact_path, checksum_sha256, created_at_utc, published_at_utc, metadata
                            FROM phase4.rulepack_registry
                            WHERE run_id = %(rid)s::uuid
                            ORDER BY created_at_utc DESC;
                            """,
                            {"rid": run_id},
                        )
                        rulepack_rows = cur.fetchall()
                    else:
                        cur.execute(
                            """
                            SELECT scope, status, artifact_path, checksum_sha256, created_at_utc, metadata
                            FROM phase4.rulepack_registry
                            WHERE run_id = %(rid)s::uuid
                            ORDER BY created_at_utc DESC;
                            """,
                            {"rid": run_id},
                        )
                        rulepack_rows = [
                            (row[0], row[1], row[2], row[3], row[4], None, row[5])
                            for row in cur.fetchall()
                        ]
                    for scope, st, artifact_path, checksum, created_at, published_at, md in rulepack_rows:
                        if scope in rule_rows:
                            continue
                        rule_rows[scope] = {
                            "status": st,
                            "artifact_path": artifact_path,
                            "checksum": checksum,
                            "created_at": self._fmt_ts(created_at),
                            "published_at": self._fmt_ts(published_at),
                            "metadata": md or {},
                        }
                    cur.execute(
                        """
                        SELECT rule_scope, count(*)::int
                        FROM phase4.rulepack_rules
                        WHERE run_id = %(rid)s::uuid
                        GROUP BY rule_scope;
                        """,
                        {"rid": run_id},
                    )
                    for scope, cnt in cur.fetchall():
                        rule_rule_count[str(scope)] = int(cnt)
                    cur.execute(
                        """
                        SELECT
                            event_type,
                            created_at,
                            COALESCE(event_details_json->'context', '{}'::jsonb) AS context
                        FROM phase4.audit_log
                        WHERE COALESCE(event_details_json->'context'->>'run_id', '') = %(rid)s
                        ORDER BY created_at DESC
                        LIMIT 80;
                        """,
                        {"rid": run_id},
                    )
                    for et, ts, ctx in cur.fetchall():
                        latest_audits.append(
                            {"event_type": et, "timestamp_utc": self._fmt_ts(ts), "context": ctx or {}}
                        )
                    try:
                        step2_model_id = str(
                            (metrics.get("model_id") if isinstance(metrics, dict) else "")
                            or ""
                        ).strip()
                        cur.execute(
                            """
                            SELECT DISTINCT ON (metric)
                                metric,
                                metric_value,
                                calculation_method,
                                details_json,
                                status,
                                calculation_status,
                                numerator,
                                denominator,
                                updatedat
                            FROM phase4.metrics
                            WHERE step = 'step2'
                              AND (
                                  COALESCE(details_json->>'run_id', '') = %(rid)s
                                  OR step_unique_id = %(rid)s
                                  OR (%(mid)s <> '' AND step_unique_id = %(mid)s)
                                  OR (%(mid)s <> '' AND COALESCE(details_json->>'model_id', '') = %(mid)s)
                              )
                              AND metric NOT IN (
                                  'cross_scope_detection_rate',
                                  'explanation_usefulness',
                                  'rule_version_traceability',
                                  'analyst_readiness_score',
                                  'rule_precision',
                                  'rule_scope_accuracy',
                                  'rule_replay_stability',
                                  'escalation_usefulness',
                                  'pareto_rank'
                              )
                            ORDER BY metric, updatedat DESC;
                            """,
                            {"rid": run_id, "mid": step2_model_id},
                        )
                        for metric_name, metric_value, calculation_method, details_json, principle_st, calc_st, numerator, denominator, extracted_at_utc in cur.fetchall():
                            details = details_json if isinstance(details_json, dict) else {}
                            metric_name_s = str(metric_name or "")
                            numerator_f = float(numerator) if numerator is not None else None
                            denominator_f = float(denominator) if denominator is not None else None
                            metric_value_f = float(metric_value) if metric_value is not None else None
                            if (
                                metric_value_f is None
                                and metric_name_s in {"accuracy", "false_positive_rate", "false_negative_rate"}
                                and numerator_f is not None
                                and denominator_f is not None
                                and denominator_f > 0.0
                            ):
                                metric_value_f = float(numerator_f / denominator_f)
                            if (
                                metric_name_s in {"accuracy", "false_positive_rate", "false_negative_rate"}
                                and metric_value_f is not None
                                and (denominator_f is None or denominator_f <= 0.0)
                            ):
                                denominator_f = 1.0
                                if numerator_f is None:
                                    numerator_f = float(metric_value_f)
                            status_val = str(calc_st or "").strip() or "not_collected"
                            recovered_from_components = (
                                metric_name_s in {"accuracy", "false_positive_rate", "false_negative_rate"}
                                and metric_value_f is not None
                                and numerator_f is not None
                                and denominator_f is not None
                                and denominator_f > 0.0
                            )
                            if status_val != "measured" and recovered_from_components:
                                status_val = "measured"
                            if status_val == "measured":
                                status_val = str(principle_st or "collected_as_principle")
                            else:
                                step2_missing_requirements.append(
                                    {
                                        "metric_name": str(metric_name or ""),
                                        "required_calculation_method": str(calculation_method or ""),
                                        "principle_status_in_review": str(principle_st or ""),
                                        "required_data_note": "Need additional source data aligned to metrics_principle_review.md.",
                                    }
                                )
                            step2_metric_results_rows.append(
                                {
                                    "metric_name": metric_name_s,
                                    "metric_value": metric_value_f,
                                    "unit": str(details.get("unit") or ""),
                                    "status": status_val,
                                    "source_ref": str(details.get("source_ref") or ""),
                                    "numerator": numerator_f,
                                    "denominator": denominator_f,
                                    "extracted_at_utc": self._fmt_ts(extracted_at_utc),
                                }
                            )
                    except Exception as exc:
                        step2_metric_rows_error = str(exc)
                        step2_metric_results_rows = []
        except Exception:
            pass

        # Step 2 metrics are authoritative only from phase4.metrics (step='step2').
        # Always surface metric names from principles so the dashboard never renders a blank list.
        step2_principles = load_metric_principles().get("step2") or {}
        existing_metric_names = {
            str(r.get("metric_name") or "").strip()
            for r in step2_metric_results_rows
            if isinstance(r, dict)
        }
        for metric_name, principle in sorted(step2_principles.items()):
            metric_key = str(metric_name or "").strip()
            if not metric_key or metric_key in step2_metrics_excluded or metric_key in existing_metric_names:
                continue
            principle_status = str(getattr(principle, "principle_status", "") or "missing")
            calc_method = str(getattr(principle, "calculation_method", "") or "")
            step2_metric_results_rows.append(
                {
                    "metric_name": metric_key,
                    "metric_value": None,
                    "unit": "",
                    "status": "not_collected",
                    "source_ref": "step2_metrics_principles_fallback",
                    "numerator": None,
                    "denominator": None,
                    "extracted_at_utc": None,
                }
            )
            step2_missing_requirements.append(
                {
                    "metric_name": metric_key,
                    "required_calculation_method": calc_method,
                    "principle_status_in_review": principle_status,
                    "required_data_note": "Need additional source data aligned to metrics_principle_review.md.",
                }
            )

        # Remove duplicate missing requirements (prefer first entry per metric name).
        dedup_missing: list[dict[str, Any]] = []
        seen_missing: set[str] = set()
        for row in step2_missing_requirements:
            metric_name = str((row or {}).get("metric_name") or "").strip()
            if not metric_name or metric_name in seen_missing:
                continue
            seen_missing.add(metric_name)
            dedup_missing.append(row)
        step2_missing_requirements = dedup_missing
        step2_metric_results_rows = sorted(
            step2_metric_results_rows,
            key=lambda r: str((r or {}).get("metric_name") or ""),
        )

        if training_row is None and metrics_training_result:
            training_row = {
                "status": metrics_training_result.get("status"),
                "worker_count": metrics_training_payload.get("worker_count"),
                "started_at": self._fmt_ts(metrics_training_result.get("started_at_utc")),
                "finished_at": self._fmt_ts(metrics_training_result.get("completed_at_utc")),
                "metrics": metrics_training_payload,
                "ok": bool(metrics_training_result.get("ok", True)),
            }

        # Fallback to workflow_runs.run_metrics (single-source DB truth) when legacy/aux tables are sparse.
        if not holdout_row:
            for row in metrics_testing_results:
                if str(row.get("eval_target") or "") == "ent01_holdout":
                    holdout_row = {
                        "status": row.get("status") or ("completed" if row.get("ok") else "failed"),
                        "started_at": row.get("started_at_utc"),
                        "finished_at": row.get("completed_at_utc"),
                        "metrics": row.get("metrics") or {},
                    }
                    break
        if not cross_rows:
            cross_map = {
                "dns01": "DNS-01",
                "iot01": "IOT-01",
                "ent02_support": "ENT-02",
                "iot02_support": "IOT-02",
            }
            for row in metrics_testing_results:
                et = str(row.get("eval_target") or "")
                ds = cross_map.get(et)
                if not ds or ds in cross_rows:
                    continue
                cross_rows[ds] = {
                    "status": row.get("status") or ("completed" if row.get("ok") else "failed"),
                    "started_at": row.get("started_at_utc"),
                    "finished_at": row.get("completed_at_utc"),
                    "metrics": row.get("metrics") or {},
                }
        if not shap_rows:
            for row in metrics_shap_results:
                shap_rows.append(
                    {
                        "split_name": str(row.get("split_name") or ""),
                        "partition_id": str(row.get("partition_id") or ""),
                        "artifact_path": None,
                        "status": row.get("status") or ("completed" if row.get("ok") else "failed"),
                        "created_at": row.get("completed_at_utc") or row.get("started_at_utc"),
                        "metadata": row.get("metrics") or {},
                    }
                )
        if not rule_rows:
            for row in metrics_rule_results:
                scope = str(row.get("scope") or "")
                if not scope or scope in rule_rows:
                    continue
                base_status = row.get("status") or ("completed" if row.get("ok") else "failed")
                # If workflow is already completed, publish phase has finished by contract.
                if self._normalize_status((db or {}).get("status")) == "completed" and self._normalize_status(base_status) == "completed":
                    base_status = "published"
                rule_rows[scope] = {
                    "status": base_status,
                    "artifact_path": None,
                    "checksum": None,
                    "created_at": row.get("completed_at_utc") or row.get("started_at_utc"),
                    "published_at": row.get("completed_at_utc") if str(base_status).lower() == "published" else None,
                    "metadata": row.get("metrics") or {},
                }
        if not latest_audits and self._normalize_status((db or {}).get("status")) == "completed":
            latest_audits.append(
                {
                    "event_type": "model_v1_step2_completed",
                    "timestamp_utc": self._fmt_ts(db.get("completed_at_utc")),
                    "context": {"run_id": run_id, "source": "workflow_runs_status_fallback"},
                }
            )

        phase = str(metrics.get("current_phase") or live.get("current_phase") or "")
        workflow_completed = self._normalize_status((db or {}).get("status")) == "completed"
        run_started = self._fmt_ts(db.get("started_at_utc")) or self._fmt_ts(live.get("started_at_utc"))
        run_finished = self._fmt_ts(db.get("completed_at_utc")) or self._fmt_ts(live.get("completed_at_utc"))
        metrics_artifact = str(metrics.get("metrics_artifact_path") or live.get("metrics_artifact_path") or "")
        degradation_artifact = str(metrics.get("degradation_report_path") or "")
        confusion_artifact = str(metrics.get("confusion_metrics_path") or "")
        model_artifact = str(
            metrics.get("model_artifact_path")
            or metrics_training_payload.get("model_artifact_path")
            or live.get("model_artifact_path")
            or ""
        )
        finalize_payload = metrics.get("model_v1_status") or {}
        integrity_verification = metrics.get("integrity_verification") or live.get("integrity_verification") or {}
        cpu_governor = metrics.get("cpu_governor") or live.get("host_cpu_governor") or {}
        cpu_telemetry = metrics.get("cpu_telemetry") or {}

        testing_targets = [
            ("ent01_holdout", "ENT-01 holdout evaluation", holdout_row),
            ("dns01", "DNS-01 cross-dataset test", cross_rows.get("DNS-01")),
            ("iot01", "IOT-01 cross-dataset test", cross_rows.get("IOT-01")),
            ("ent02_support", "ENT-02 support/test evaluation", cross_rows.get("ENT-02")),
            ("iot02_support", "IOT-02 support/test evaluation", cross_rows.get("IOT-02")),
        ]

        shap_total = max(1, len(shap_rows))
        shap_done = sum(1 for r in shap_rows if self._normalize_status(r.get("status")) == "completed")
        rule_scopes = ["global", "enterprise", "dns", "iot", "iiot", "cross_scope"]

        stages: list[dict[str, Any]] = []

        train_metrics = (training_row or {}).get("metrics") or metrics_training_payload or {}
        train_rows = int(train_metrics.get("row_count") or 0)
        train_features = int(train_metrics.get("feature_count") or 0)
        train_duration_s = float(train_metrics.get("duration_s") or 0.0)
        train_fit_executed = bool(train_metrics.get("fit_executed", training_row is not None))
        train_metrics_path = str(train_metrics.get("training_metrics_path") or "")
        artifact_exists = bool(model_artifact and Path(model_artifact).exists())
        artifact_size = Path(model_artifact).stat().st_size if artifact_exists else 0
        artifact_recorded = bool(model_artifact)
        training_row_completed = bool(
            training_row and self._normalize_status((training_row or {}).get("status")) == "completed"
        )
        training_row_ok = bool((training_row or {}).get("ok", training_row is not None))
        # Prefer DB truth when training itself completed with fit execution, even if the dashboard
        # process cannot stat files due to runtime/container path context differences.
        artifact_truth = bool(
            (artifact_exists and artifact_size > 0)
            or (workflow_completed and artifact_recorded)
            or (training_row_completed and training_row_ok and train_fit_executed and artifact_recorded)
        )
        training_verified = bool(
            training_row
            and self._normalize_status(training_row.get("status")) == "completed"
            and train_rows > 0
            and train_features > 0
            and train_duration_s > 0
            and train_fit_executed
            and artifact_truth
            and train_metrics_path
        )
        training_children = [
            {"id": "load_ent01_train", "label": "load ENT-01 train partition", "status": "completed" if train_rows > 0 else ("running" if phase == "training" else "failed"), "row_count": train_rows},
            {"id": "feature_prep", "label": "feature preparation", "status": "completed" if train_features > 0 else ("running" if phase == "training" else "failed"), "feature_count": train_features},
            {"id": "train_model_v1", "label": "train Model V1", "status": "completed" if training_verified else self._normalize_status(training_row.get("status") if training_row else ("running" if phase == "training" else "pending")), "duration_s": train_duration_s},
            {
                "id": "save_model_artifact",
                "label": "save model artifact",
                "status": "completed" if artifact_truth else ("running" if phase in {"freeze", "training"} else "failed"),
                "artifact_path": model_artifact or None,
                "verification": (
                    "filesystem"
                    if artifact_exists and artifact_size > 0
                    else (
                        "workflow_completed_db"
                        if workflow_completed and artifact_recorded
                        else (
                            "training_contract_db"
                            if training_row_completed and training_row_ok and train_fit_executed and artifact_recorded
                            else "missing"
                        )
                    )
                ),
            },
            {"id": "save_training_metrics", "label": "save training metrics", "status": "completed" if train_metrics_path else ("running" if phase == "training" else "failed"), "artifact_path": train_metrics_path or None},
        ]
        stages.append(
            {
                "id": "training_phase",
                "label": "Training Phase",
                "required_substages": [c["id"] for c in training_children],
                "substages": training_children,
                "worker_count": (training_row or {}).get("worker_count") or 1,
                "started_at": (training_row or {}).get("started_at") or run_started,
                "finished_at": (training_row or {}).get("finished_at"),
            }
        )

        testing_children: list[dict[str, Any]] = []
        for tid, label, rec in testing_targets:
            st = self._normalize_status(rec.get("status") if rec else ("running" if phase == "testing" else "pending"))
            note = None
            if tid in {"ent02_support", "iot02_support"}:
                note = "testing/support only"
            rec_metrics = (rec or {}).get("metrics") or {}
            task_error = (
                rec_metrics.get("task_error")
                or rec_metrics.get("error")
                or (rec or {}).get("error_message")
            )
            testing_children.append(
                {
                    "id": tid,
                    "label": label,
                    "status": st,
                    "started_at": rec.get("started_at") if rec else None,
                    "finished_at": rec.get("finished_at") if rec else None,
                    "note": note,
                    "row_count": int(rec_metrics.get("row_count") or 0),
                    "source_row_count": int(rec_metrics.get("source_row_count") or rec_metrics.get("row_count") or 0),
                    "sampling_applied": bool(rec_metrics.get("sampling_applied")),
                    "prediction_count": int(rec_metrics.get("prediction_count") or 0),
                    "error": str(task_error) if task_error else None,
                    "audit_ref": f"/dash_api/model-v1/audit-events?run_id={run_id}",
                }
            )
        testing_children.extend(
            [
                {
                    "id": "degradation_report",
                    "label": "degradation report",
                    "status": "completed" if any(c.get("status") in {"completed", "partial"} for c in testing_children) else ("running" if phase == "testing" else "pending"),
                    "artifact_path": degradation_artifact or metrics_artifact or None,
                },
                {
                    "id": "confusion_metrics",
                    "label": "confusion metrics",
                    "status": "completed" if holdout_row else ("running" if phase == "testing" else "pending"),
                    "artifact_path": confusion_artifact or metrics_artifact or None,
                },
            ]
        )
        stages.append(
            {
                "id": "testing_phase",
                "label": "Evaluation / Testing Phase",
                "required_substages": [c["id"] for c in testing_children],
                "substages": testing_children,
                "worker_count": live.get("max_workers_phase") if phase == "testing" else None,
            }
        )

        shap_children = [
            {"id": "prep_validation", "label": "prepare ENT-01 validation matrix", "status": "completed" if any(r.get("split_name") == "validation" for r in shap_rows) else ("running" if phase == "shap" else "pending")},
            {"id": "prep_test", "label": "prepare ENT-01 test matrix", "status": "completed" if any(r.get("split_name") == "test" for r in shap_rows) else ("running" if phase == "shap" else "pending")},
            {
                "id": "shap_chunks",
                "label": "SHAP chunk processing",
                "status": "completed" if shap_done == shap_total and shap_rows else ("running" if phase == "shap" else ("partial" if shap_done > 0 else "pending")),
                "progress_percent": round((shap_done / shap_total) * 100.0, 1) if shap_rows else 0.0,
                "worker_count": live.get("max_workers_phase") if phase == "shap" else None,
                "artifact_path": next((r.get("artifact_path") for r in shap_rows if r.get("artifact_path")), None),
            },
            {"id": "shap_aggregate", "label": "SHAP aggregation", "status": "completed" if shap_rows else ("running" if phase == "shap" else "pending")},
            {"id": "rule_hint_artifact", "label": "rule-hint artifact generation", "status": "completed" if shap_rows else ("running" if phase == "shap" else "pending"), "artifact_path": next((r.get("artifact_path") for r in shap_rows if r.get("artifact_path")), None)},
        ]
        stages.append(
            {
                "id": "shap_phase",
                "label": "SHAP Phase",
                "required_substages": [c["id"] for c in shap_children],
                "substages": shap_children,
            }
        )

        freeze_children = [
            {"id": "freeze_model", "label": "freeze Model V1", "status": "completed" if model_artifact else ("running" if phase == "freeze" else "pending")},
            {"id": "immutable_artifact", "label": "save immutable artifact", "status": "completed" if model_artifact else ("running" if phase == "freeze" else "pending"), "artifact_path": model_artifact or None},
            {"id": "freeze_checksum", "label": "save checksum", "status": "completed" if model_artifact else ("running" if phase == "freeze" else "pending")},
            {"id": "model_registry_update", "label": "update model_registry status", "status": "completed" if model_artifact else ("running" if phase == "freeze" else "pending")},
        ]
        stages.append(
            {
                "id": "freeze_phase",
                "label": "Model Freeze Phase",
                "required_substages": [c["id"] for c in freeze_children],
                "substages": freeze_children,
            }
        )

        verifier_children = [
            {
                "id": "run_pre_freeze_integrity_verifier",
                "label": "run pre-freeze integrity verifier",
                "status": self._normalize_status(
                    "completed"
                    if integrity_verification
                    else ("running" if phase == "verifier" else "pending")
                ),
                "started_at": run_started if integrity_verification else None,
                "finished_at": run_finished if integrity_verification else None,
                "verdict": str(integrity_verification.get("verdict") or ""),
                "gate_action": str(integrity_verification.get("gate_action") or ""),
            },
            {
                "id": "publish_integrity_reports",
                "label": "publish integrity reports",
                "status": self._normalize_status(
                    "completed"
                    if integrity_verification and (
                        integrity_verification.get("json_report") or integrity_verification.get("markdown_report")
                    )
                    else ("running" if phase == "verifier" else "pending")
                ),
                "artifact_path": integrity_verification.get("json_report") or integrity_verification.get("markdown_report"),
            },
        ]
        stages.append(
            {
                "id": "verifier_phase",
                "label": "Integrity Verifier Phase",
                "required_substages": [c["id"] for c in verifier_children],
                "substages": verifier_children,
                "model_id": integrity_verification.get("model_id"),
                "model_version": integrity_verification.get("model_version"),
                "verdict": integrity_verification.get("verdict"),
            }
        )

        has_rule_truth = bool(rule_rows) or bool(metrics_rule_results)
        rule_children: list[dict[str, Any]] = [
            {"id": "corpus_stats", "label": "corpus statistics", "status": "completed" if has_rule_truth else ("running" if phase == "rule_generation" else "pending")}
        ]
        for scope in rule_scopes:
            rec = rule_rows.get(scope)
            st = self._normalize_status(rec.get("status") if rec else ("running" if phase == "rule_generation" else "pending"))
            rule_children.append(
                {
                    "id": f"rules_{scope}",
                    "label": f"{scope.replace('_', '-')} rules",
                    "status": st,
                    "artifact_path": rec.get("artifact_path") if rec else None,
                    "progress_percent": 100.0 if rule_rule_count.get(scope, 0) > 0 and st == "completed" else None,
                }
            )
        stages.append(
            {
                "id": "rule_generation_phase",
                "label": "Rule Generation Phase",
                "required_substages": [c["id"] for c in rule_children],
                "substages": rule_children,
                "worker_count": live.get("max_workers_phase") if phase == "rule_generation" else None,
            }
        )

        publish_done_by_workflow = self._normalize_status((db or {}).get("status")) == "completed" and bool(metrics_rule_results)
        publishing_children = [
            {"id": "validate_rules", "label": "validate generated rules", "status": "completed" if (rule_rows or publish_done_by_workflow) else ("running" if phase == "publishing" else "pending")},
            {"id": "semantic_versions", "label": "create semantic rulepack versions", "status": "completed" if (rule_rows or publish_done_by_workflow) else ("running" if phase == "publishing" else "pending")},
            {
                "id": "rulepack_checksums",
                "label": "save rulepack checksums",
                "status": "completed"
                if (
                    any((r.get("checksum") for r in rule_rows.values()))
                    or publish_done_by_workflow
                )
                else ("running" if phase == "publishing" else "pending"),
            },
            {"id": "publish_rulepacks", "label": "publish rulepacks", "status": "completed" if ((all((self._normalize_status(r.get("status")) == "completed" for r in rule_rows.values())) and rule_rows) or publish_done_by_workflow) else ("running" if phase == "publishing" else "pending")},
            {"id": "publish_audit", "label": "write audit event", "status": "completed" if (any(a.get("event_type") in {"model_v1_step2_completed", "model_v1_step2_failed"} for a in latest_audits) or publish_done_by_workflow) else ("running" if phase == "publishing" else "pending"), "audit_ref": f"/dash_api/model-v1/audit-events?run_id={run_id}"},
        ]
        stages.append(
            {
                "id": "rule_publishing_phase",
                "label": "Rule Publishing Phase",
                "required_substages": [c["id"] for c in publishing_children],
                "substages": publishing_children,
            }
        )

        final_children = [
            {"id": "verify_artifacts", "label": "verify required artifacts", "status": "completed" if metrics_artifact and model_artifact else ("running" if phase == "finalized" else "pending")},
            {"id": "verify_audits", "label": "verify logs/audit events", "status": "completed" if (latest_audits or self._normalize_status((db or {}).get("status")) == "completed") else ("running" if phase == "finalized" else "pending"), "audit_ref": f"/dash_api/model-v1/audit-events?run_id={run_id}"},
            {"id": "mark_step2_complete", "label": "mark Step 2 complete", "status": self._normalize_status(db.get("status")) if db else "pending"},
            {"id": "mark_model_v1_ready", "label": "mark Model V1 ready for Step 3 scaffold", "status": "completed" if bool(finalize_payload.get("ready_for_step3_scaffold")) else ("partial" if db and db.get("status") == "completed" else "pending")},
        ]
        stages.append(
            {
                "id": "finalization_phase",
                "label": "Finalization Phase",
                "required_substages": [c["id"] for c in final_children],
                "substages": final_children,
                "artifact_path": metrics_artifact or None,
            }
        )

        desired_stage_order = {
            "training_phase": 10,
            "freeze_phase": 20,
            "verifier_phase": 30,
            "testing_phase": 40,
            "shap_phase": 50,
            "rule_generation_phase": 60,
            "rule_publishing_phase": 70,
            "finalization_phase": 80,
        }
        stages.sort(key=lambda s: desired_stage_order.get(str(s.get("id") or ""), 999))

        total_nodes = 0
        completed_nodes = 0
        stage_resource_map = {
            "training_phase": "/dash_api/model-v1/step2/training",
            "freeze_phase": "/dash_api/model-v1/step2/status",
            "verifier_phase": "/dash_api/model-v1/step2/status",
            "testing_phase": "/dash_api/model-v1/step2/testing",
            "shap_phase": "/dash_api/model-v1/step2/shap",
            "rule_generation_phase": "/dash_api/model-v1/step2/rules",
            "rule_publishing_phase": "/dash_api/model-v1/step2/rules",
            "finalization_phase": "/dash_api/model-v1/step2/status",
        }
        for stage in stages:
            stage["required"] = True
            stage["stage_log_ref"] = f"{stage_resource_map.get(stage['id'], '/dash_api/model-v1/step2/status')}?run_id={run_id}"
            for child in stage.get("substages") or []:
                child["required"] = True
                child_status = self._normalize_status(child.get("status"))
                child["status"] = child_status
                st = child.get("started_at")
                ft = child.get("finished_at")
                child["duration_s"] = self._duration_seconds(st, ft)
                total_nodes += 1
                if child_status == "completed":
                    completed_nodes += 1
            stage["status"] = self._derive_parent_status(stage.get("substages") or [], set(stage.get("required_substages") or []))
            stage["started_at"] = stage.get("started_at") or run_started
            stage["finished_at"] = stage.get("finished_at")
            stage["duration_s"] = self._duration_seconds(stage.get("started_at"), stage.get("finished_at"))
            stage["progress_percent"] = round(
                100.0
                * (
                    sum(1 for c in (stage.get("substages") or []) if c.get("status") == "completed")
                    / max(1, len(stage.get("substages") or []))
                ),
                1,
            )
        overall_status = self._derive_parent_status(stages, {s["id"] for s in stages})
        overall_progress = round((completed_nodes / max(1, total_nodes)) * 100.0, 1)
        model_id_for_artifacts = str(integrity_verification.get("model_id") or metrics.get("model_id") or "")
        model_version_for_artifacts = str(
            integrity_verification.get("model_version") or metrics.get("model_version") or db.get("model_version") or ""
        )
        for stage in stages:
            stage_artifact_path = stage.get("artifact_path")
            if stage_artifact_path:
                stage["artifact_url"] = self._artifact_url_from_path(
                    file_path=str(stage_artifact_path),
                    artifact_type=f"step2_{stage.get('id', 'stage')}_artifact",
                    run_id=run_id,
                    model_id=model_id_for_artifacts or None,
                    model_version=model_version_for_artifacts or None,
                    step_name="step2",
                    metadata={"stage_id": stage.get("id"), "label": stage.get("label")},
                )
            for sub in stage.get("substages") or []:
                sub_artifact_path = sub.get("artifact_path")
                if sub_artifact_path:
                    sub["artifact_url"] = self._artifact_url_from_path(
                        file_path=str(sub_artifact_path),
                        artifact_type=f"step2_{sub.get('id', 'substage')}_artifact",
                        run_id=run_id,
                        model_id=model_id_for_artifacts or None,
                        model_version=model_version_for_artifacts or None,
                        step_name="step2",
                        metadata={"stage_id": stage.get("id"), "substage_id": sub.get("id")},
                    )

        metrics_url = self._artifact_url_from_path(
            file_path=metrics_artifact or None,
            artifact_type="step2_metrics",
            run_id=run_id,
            model_id=model_id_for_artifacts or None,
            model_version=model_version_for_artifacts or None,
            step_name="step2",
        )
        degradation_url = self._artifact_url_from_path(
            file_path=degradation_artifact or None,
            artifact_type="step2_degradation_report",
            run_id=run_id,
            model_id=model_id_for_artifacts or None,
            model_version=model_version_for_artifacts or None,
            step_name="step2",
        )
        confusion_url = self._artifact_url_from_path(
            file_path=confusion_artifact or None,
            artifact_type="step2_confusion_metrics",
            run_id=run_id,
            model_id=model_id_for_artifacts or None,
            model_version=model_version_for_artifacts or None,
            step_name="step2",
        )
        model_url = self._artifact_url_from_path(
            file_path=model_artifact or None,
            artifact_type="step2_model_manifest",
            run_id=run_id,
            model_id=model_id_for_artifacts or None,
            model_version=model_version_for_artifacts or None,
            step_name="step2",
        )
        finalize_path = metrics.get("finalize_path")
        finalize_url = self._artifact_url_from_path(
            file_path=finalize_path or None,
            artifact_type="step2_finalize",
            run_id=run_id,
            model_id=model_id_for_artifacts or None,
            model_version=model_version_for_artifacts or None,
            step_name="step2",
        )
        if integrity_verification:
            iv_json = integrity_verification.get("json_report")
            iv_md = integrity_verification.get("markdown_report")
            integrity_verification["json_report_url"] = self._artifact_url_from_path(
                file_path=iv_json or None,
                artifact_type="step2_integrity_json_report",
                run_id=run_id,
                model_id=model_id_for_artifacts or None,
                model_version=model_version_for_artifacts or None,
                step_name="step2",
            )
            integrity_verification["markdown_report_url"] = self._artifact_url_from_path(
                file_path=iv_md or None,
                artifact_type="step2_integrity_markdown_report",
                run_id=run_id,
                model_id=model_id_for_artifacts or None,
                model_version=model_version_for_artifacts or None,
                step_name="step2",
            )
        step2_metrics_generation = (
            metrics.get("step2_metrics_generation")
            if isinstance(metrics.get("step2_metrics_generation"), dict)
            else {}
        )
        step2_metrics_warning = bool(
            step2_missing_requirements
            or bool(step2_metrics_generation.get("warning"))
            or bool(step2_metrics_generation.get("errors"))
        )

        return {
            "run_id": run_id,
            "workflow_id": db.get("workflow_id") or live.get("workflow_id"),
            "current_phase": metrics.get("current_phase") or live.get("current_phase"),
            "overall_status": overall_status,
            "overall_progress_percent": overall_progress,
            "active_workers": live.get("active_workers"),
            "max_workers": live.get("max_workers_phase"),
            "queued_tasks": live.get("queued_tasks"),
            "completed_tasks": live.get("completed_tasks"),
            "failed_tasks": live.get("failed_tasks"),
            "retryable_tasks": live.get("failed_tasks") or 0,
            "stages": stages,
            "artifact_paths": {
                "metrics": metrics_artifact or None,
                "model": model_artifact or None,
                "finalize": finalize_path,
                "degradation_report": degradation_artifact or None,
                "confusion_metrics": confusion_artifact or None,
                "metrics_url": metrics_url,
                "degradation_report_url": degradation_url,
                "confusion_metrics_url": confusion_url,
                "model_url": model_url,
                "finalize_url": finalize_url,
            },
            "audit_refs": {
                "events": f"/dash_api/model-v1/audit-events?run_id={run_id}",
                "logs": f"/dash_api/logs?run_id={run_id}",
            },
            "latest_audit_events": latest_audits[:20],
            "model_v1_ready": bool(finalize_payload.get("ready_for_step3_scaffold")),
            "training_source_lock": "Training source: ENT-01 train only",
            "integrity_verification": integrity_verification,
            "cpu_governor": cpu_governor,
            "cpu_telemetry": cpu_telemetry,
            "queue_state": metrics.get("queue_state") or live.get("queue_state"),
            "effective_parallelism": metrics.get("effective_parallelism") or live.get("effective_parallelism"),
            "step2_metric_results": step2_metric_results_rows,
            "step2_metric_results_summary": {
                "total": len(step2_metric_results_rows),
                "collected": sum(1 for r in step2_metric_results_rows if str(r.get("status") or "") == "collected_as_principle"),
                "proxy": sum(1 for r in step2_metric_results_rows if str(r.get("status") or "") == "proxy"),
                "missing": sum(
                    1
                    for r in step2_metric_results_rows
                    if str(r.get("status") or "") in {"not_collected", "missing"}
                ),
            },
            "step2_missing_requirements": step2_missing_requirements,
            "step2_metrics_warning": step2_metrics_warning,
            "step2_metrics_generation": step2_metrics_generation,
            "step2_metric_results_error": step2_metric_rows_error or None,
            "step3_cpu_governance": metrics.get("step3_cpu_governance")
            or {"status": "deferred", "reason": "excluded_from_current_rollout"},
        }

    def model_v1_step2_status_get(self) -> None:
        params = parse_qs(urlparse(self.path).query, keep_blank_values=False)
        run_id = (params.get("run_id") or [""])[0].strip()
        if not run_id:
            try:
                with connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT run_id::text
                            FROM phase4.workflow_runs
                            WHERE step_name = 'step2'
                            ORDER BY started_at_utc DESC, run_id DESC
                            LIMIT 1;
                            """
                        )
                        row = cur.fetchone()
                        run_id = str(row[0]) if row else ""
            except Exception:
                run_id = ""
        if not run_id:
            self.send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "run_id": "",
                    "overall_status": "pending",
                    "overall_progress_percent": 0.0,
                    "stages": [],
                    "training_source_lock": "Training source: ENT-01 train only",
                },
            )
            return
        base = status_for_run(run_id)
        hierarchy = self._build_step2_hierarchy(run_id, base)
        metric_rows = hierarchy.get("step2_metric_results") if isinstance(hierarchy.get("step2_metric_results"), list) else []
        if not metric_rows:
            db = base.get("db") if isinstance(base.get("db"), dict) else {}
            db_status = str((db or {}).get("status") or "").strip().lower()
            # Safety net: if terminal Step 2 run has no metric rows visible, try one direct generation pass.
            if db_status in {"completed", "failed", "blocked"}:
                try:
                    regen = generate_step2_metrics(run_id=run_id)
                    if regen.get("ok"):
                        self._persist_metrics_generation_result(step_name="step2", run_id=run_id, result=regen)
                    base = status_for_run(run_id)
                    hierarchy = self._build_step2_hierarchy(run_id, base)
                except Exception:
                    pass
        try:
            upsert_workflow_runtime_state(
                step_name="step2",
                workflow_id=str(hierarchy.get("workflow_id") or "model_v1_step2_train_rules"),
                run_id=run_id,
                current_phase=str(hierarchy.get("current_phase") or ""),
                phase_status=str(hierarchy.get("overall_status") or ""),
                status=str(hierarchy.get("overall_status") or ""),
                source="dashboard_api",
                state_payload=hierarchy,
            )
        except Exception:
            pass
        self.send_json(HTTPStatus.OK, {"ok": True, **base, **hierarchy})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = DashHandler._norm_http_path(parsed.path)
        if path.startswith("/model-v1/step3/v2/"):
            self._proxy_step3_v2(method="POST", path=path, query=parsed.query, payload=self._read_json_body())
            return
        if path == "/ingestion/start":
            self.send_json(
                HTTPStatus.GONE,
                {
                    "ok": False,
                    "error": "The single-step ingestion endpoint was replaced by /workflow/ingest.",
                },
            )
            return
        if path == "/workflow/ingest":
            self.request_stage("ingest", parsed.query)
            return
        if path == "/governance/training-precheck":
            self.training_precheck()
            return
        if path == "/governance/check-action":
            self.governance_check_action()
            return
        if path in {"/dissertation/refresh", "/step4/refresh"}:
            data = self._read_json_body()
            mv = str(data.get("model_version") or "").strip() or None
            step1_run_id = str(data.get("step1_run_id") or "").strip() or None
            step2_model_id = str(data.get("step2_model_id") or "").strip() or None
            step2_run_id = str(data.get("step2_run_id") or "").strip() or None
            step3_v2_sim_id = str(data.get("step3_v2_sim_id") or data.get("sim_id") or "").strip() or None
            self.send_json(
                HTTPStatus.OK,
                generate_step4_metrics(
                    mv,
                    step1_run_id=step1_run_id,
                    step2_model_id=step2_model_id,
                    step2_run_id=step2_run_id,
                    step3_v2_sim_id=step3_v2_sim_id,
                ),
            )
            return
        if path == "/step1/run":
            self.run_step1()
            return
        if path == "/step1/metrics/regenerate":
            self.regenerate_step1_metrics()
            return
        if path == "/step2/run":
            self.run_step2()
            return
        if path == "/step2/metrics/regenerate":
            self.regenerate_step2_metrics()
            return
        if path == "/model-v1/step2/run":
            self.run_step2()
            return
        if path == "/model-v1/step2/metrics/regenerate":
            self.regenerate_step2_metrics()
            return
        if path == "/model-v1/step3/metrics/regenerate":
            self.regenerate_step3_metrics()
            return
        if path == "/model-v1/models":
            data = self._read_json_body()
            source_step1_run_id = str(data.get("source_step1_run_id") or "").strip()
            if source_step1_run_id:
                detail = self.step1_run_detail_payload(source_step1_run_id)
                if not detail.get("ok"):
                    self.send_json(HTTPStatus.CONFLICT, {"ok": False, "error": "invalid_step1_run_id"})
                    return
                run_row = detail.get("run") or {}
                if str(run_row.get("readiness_status")) != "ready":
                    self.send_json(
                        HTTPStatus.CONFLICT,
                        {"ok": False, "error": "step1_run_not_ready", "run": run_row},
                    )
                    return
                data.setdefault("source_step1_lineage_hash", run_row.get("lineage_hash"))
                data.setdefault("linked_step1_lineage_hash", run_row.get("lineage_hash"))
                data.setdefault("dataset_readiness_snapshot", run_row.get("dataset_readiness_snapshot") or {})
                data.setdefault("selected_datasets", run_row.get("processed_datasets") or [])
            self.send_json(HTTPStatus.OK, create_model(self.data_root, data))
            return
        if path.startswith("/model-v1/models/") and path.endswith("/set-current"):
            mv = path.removeprefix("/model-v1/models/").removesuffix("/set-current")
            self.send_json(HTTPStatus.OK, set_current_model(mv))
            return
        if path.startswith("/model-v1/models/") and path.endswith("/clone"):
            mv = path.removeprefix("/model-v1/models/").removesuffix("/clone")
            self.send_json(HTTPStatus.OK, clone_model(self.data_root, mv, self._read_json_body()))
            return
        if path.startswith("/model-v1/models/") and path.endswith("/deprecate"):
            mv = path.removeprefix("/model-v1/models/").removesuffix("/deprecate")
            self.send_json(HTTPStatus.OK, deprecate_model(mv))
            return
        if path == "/model-v1/step2/prepare":
            try:
                data = self._read_json_body()
                source_step1_run_id = str(data.get("source_step1_run_id") or "").strip()
                mode = str(data.get("model_execution_mode") or "continue_existing").strip()
                model_id = str(data.get("model_id") or "").strip()
                new_model_name = str(data.get("new_model_name") or "").strip()
                if not source_step1_run_id:
                    self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "source_step1_run_id_required"})
                    return
                run_detail = self.step1_run_detail_payload(source_step1_run_id)
                if not run_detail.get("ok"):
                    self.send_json(HTTPStatus.CONFLICT, {"ok": False, "error": "invalid_step1_run_id"})
                    return
                run_row = run_detail["run"]
                if str(run_row.get("readiness_status")) != "ready":
                    self.send_json(HTTPStatus.CONFLICT, {"ok": False, "error": "step1_run_not_ready", "run": run_row})
                    return
                selected_model_version = model_id
                if mode == "create_new":
                    created = create_model(
                        self.data_root,
                        {
                            "model_name": new_model_name or None,
                            "source_step1_run_id": source_step1_run_id,
                            "source_step1_lineage_hash": run_row.get("lineage_hash"),
                            "linked_step1_lineage_hash": run_row.get("lineage_hash"),
                            "dataset_readiness_snapshot": run_row.get("dataset_readiness_snapshot") or {},
                            "selected_datasets": run_row.get("processed_datasets") or [],
                        },
                    )
                    if not created.get("ok"):
                        self.send_json(
                            HTTPStatus.CONFLICT,
                            {"ok": False, "error": "create_model_failed", "detail": created},
                        )
                        return
                    selected_model_version = str(created.get("model_version") or "")
                elif mode == "clone_and_train":
                    if not model_id:
                        self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "model_id_required_for_clone"})
                        return
                    cloned = clone_model(
                        self.data_root,
                        model_id,
                        {
                            "source_step1_run_id": source_step1_run_id,
                            "source_step1_lineage_hash": run_row.get("lineage_hash"),
                            "linked_step1_lineage_hash": run_row.get("lineage_hash"),
                            "dataset_readiness_snapshot": run_row.get("dataset_readiness_snapshot") or {},
                            "selected_datasets": run_row.get("processed_datasets") or [],
                        },
                    )
                    if not cloned.get("ok"):
                        self.send_json(
                            HTTPStatus.CONFLICT,
                            {"ok": False, "error": "clone_model_failed", "detail": cloned},
                        )
                        return
                    selected_model_version = str(cloned.get("model_version") or "")
                elif not model_id:
                    self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "model_id_required"})
                    return
                readiness = self.step2_readiness_payload(selected_model_version)
                self.send_json(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "source_step1_run_id": source_step1_run_id,
                        "model_id": (get_model(selected_model_version).get("model") or {}).get("model_id"),
                        "model_version": selected_model_version,
                        "model_execution_mode": mode,
                        "step2_ready": bool(readiness.get("ready")),
                        "readiness": readiness,
                        "step1_run": run_row,
                    },
                )
                return
            except Exception as exc:
                self.send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"ok": False, "error": "step2_prepare_failed", "detail": str(exc)})
                return
        if path == "/model-v1/step3/child-stacks":
            self.send_json(HTTPStatus.OK, create_child_stack(self._read_json_body()))
            return
        if path == "/model-v1/step3/simulation/start":
            data = self._read_json_body()
            qs = parse_qs(parsed.query or "")
            async_requested = _parse_bool(
                (qs.get("async") or [data.get("async")])[0],
                default=True,
            )
            replay_payload = json.loads(json.dumps(data))
            replay_payload["target_mode"] = "random_single"
            replay_payload["execution_mode"] = "simulation"
            if replay_payload.get("strict_acceptance") is None:
                replay_payload["strict_acceptance"] = False
            try:
                replay_payload["send_workers"] = max(1, min(int(replay_payload.get("send_workers") or 4), 4))
            except Exception:
                replay_payload["send_workers"] = 4
            audit_path = _step3_new_audit_log_path(
                self.data_root,
                model_version=str(replay_payload.get("model_version") or "").strip() or None,
            )
            replay_payload["step3_audit_log_path"] = str(audit_path)
            _append_step3_audit_log(
                audit_path,
                event="step3_simulation_start_requested",
                payload={
                    "model_id": replay_payload.get("model_id"),
                    "model_version": replay_payload.get("model_version"),
                    "send_workers": replay_payload.get("send_workers"),
                    "target_mode": replay_payload.get("target_mode"),
                    "execution_mode": replay_payload.get("execution_mode"),
                    "strict_acceptance": replay_payload.get("strict_acceptance"),
                },
            )
            if not async_requested:
                try:
                    self.send_json(HTTPStatus.OK, step3_run_replay(replay_payload, self.data_root))
                except Exception as exc:
                    print(f"[dash-api] step3 simulation start failed: {exc}", flush=True)
                    self.send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"ok": False, "error": "step3_simulation_start_failed", "detail": str(exc)})
                return
            live: dict[str, Any] = {}
            try:
                live = step3_replay_status()
                if str(live.get("status") or "").lower() == "running":
                    self.send_json(
                        HTTPStatus.CONFLICT,
                        {
                            "ok": False,
                            "error": "replay_already_running",
                            "replay_run_id": live.get("replay_run_id"),
                            "sim_id": live.get("sim_id"),
                            "run_id": live.get("run_id"),
                            "phase2_state": "running",
                        },
                    )
                    return
            except Exception:
                pass
            with _STEP3_REPLAY_BG_LOCK:
                global _STEP3_REPLAY_BG_THREAD
                bg_running = bool(_STEP3_REPLAY_BG_STATE.get("running"))
                bg_started_at_raw = str(_STEP3_REPLAY_BG_STATE.get("started_at") or "").strip()
                bg_thread_alive = bool(_STEP3_REPLAY_BG_THREAD and _STEP3_REPLAY_BG_THREAD.is_alive())
                live_running = str((live or {}).get("status") or "").lower() == "running"
                stale_bg_state = False
                bg_age_s = 0.0
                if bg_running and bg_started_at_raw:
                    try:
                        bg_started_dt = datetime.fromisoformat(bg_started_at_raw.replace("Z", "+00:00"))
                        bg_age_s = max(0.0, (datetime.now(timezone.utc) - bg_started_dt).total_seconds())
                    except Exception:
                        bg_age_s = 0.0
                if bg_running and not bg_thread_alive and not live_running:
                    stale_bg_state = True
                if bg_running and not stale_bg_state and not live_running and bg_age_s >= 45.0:
                    stale_bg_state = True
                if stale_bg_state:
                    _STEP3_REPLAY_BG_STATE.update(
                        {
                            "running": False,
                            "launch_token": None,
                            "finished_at": utc_now(),
                            "last_error": "cleared_stale_replay_launch_state",
                        }
                    )
                    if _STEP3_REPLAY_BG_THREAD and not _STEP3_REPLAY_BG_THREAD.is_alive():
                        _STEP3_REPLAY_BG_THREAD = None
                if bool(_STEP3_REPLAY_BG_STATE.get("running")) and bool(_STEP3_REPLAY_BG_STATE.get("launch_token")):
                    self.send_json(
                        HTTPStatus.CONFLICT,
                        {
                            "ok": False,
                            "error": "replay_launch_in_progress",
                            "started_at": _STEP3_REPLAY_BG_STATE.get("started_at"),
                            "launch_token": _STEP3_REPLAY_BG_STATE.get("launch_token"),
                            "audit_log_path": _STEP3_REPLAY_BG_STATE.get("audit_log_path"),
                            "sim_id": live.get("sim_id"),
                            "replay_run_id": live.get("replay_run_id"),
                            "run_id": live.get("run_id"),
                            "phase2_state": "starting",
                        },
                    )
                    return
                launch_token = str(uuid.uuid4())
                _STEP3_REPLAY_BG_STATE.update(
                    {
                        "running": True,
                        "launch_token": launch_token,
                        "started_at": utc_now(),
                        "finished_at": None,
                        "last_error": None,
                        "last_result": None,
                        "audit_log_path": str(audit_path),
                    }
                )

            def _run_step3_replay_bg() -> None:
                _append_step3_audit_log(
                    audit_path,
                    event="step3_replay_background_started",
                    payload={
                        "launch_token": launch_token,
                        "model_id": replay_payload.get("model_id"),
                        "model_version": replay_payload.get("model_version"),
                    },
                )
                try:
                    result = step3_run_replay(replay_payload, self.data_root)
                    _append_step3_audit_log(
                        audit_path,
                        event="step3_replay_background_result",
                        payload=result if isinstance(result, dict) else {"result": result},
                    )
                    with _STEP3_REPLAY_BG_LOCK:
                        if _STEP3_REPLAY_BG_STATE.get("launch_token") == launch_token:
                            _STEP3_REPLAY_BG_STATE.update(
                                {
                                    "running": False,
                                    "launch_token": None,
                                    "finished_at": utc_now(),
                                    "last_error": None if bool(result.get("ok")) else str(result.get("error") or "replay_failed"),
                                    "last_result": result,
                                    "audit_log_path": str(audit_path),
                                }
                            )
                except Exception as exc:
                    print(f"[dash-api] step3 simulation start failed: {exc}", flush=True)
                    _append_step3_audit_log(
                        audit_path,
                        event="step3_replay_background_exception",
                        payload={"error": str(exc)},
                    )
                    replay_id_hint = str(
                        ((_STEP3_REPLAY_BG_STATE.get("last_result") or {}).get("replay_run_id"))
                        or ((step3_replay_status() or {}).get("replay_run_id"))
                        or ""
                    ).strip()
                    fail_reason = f"step3_replay_bg_exception:{exc}"
                    try:
                        step3_replay_fail_active(fail_reason, replay_run_id=replay_id_hint or None)
                    except Exception as fail_exc:
                        print(f"[dash-api] step3 replay fail-close failed: {fail_exc}", flush=True)
                    with _STEP3_REPLAY_BG_LOCK:
                        if _STEP3_REPLAY_BG_STATE.get("launch_token") == launch_token:
                            _STEP3_REPLAY_BG_STATE.update(
                                {
                                    "running": False,
                                    "launch_token": None,
                                    "finished_at": utc_now(),
                                    "last_error": fail_reason,
                                    "last_result": {
                                        "ok": False,
                                        "error": "step3_replay_run_failed",
                                        "detail": str(exc),
                                        "replay_run_id": replay_id_hint or None,
                                    },
                                    "audit_log_path": str(audit_path),
                                }
                            )

            _STEP3_REPLAY_BG_THREAD = threading.Thread(target=_run_step3_replay_bg, name="step3-replay-bg", daemon=True)
            _STEP3_REPLAY_BG_THREAD.start()
            self.send_json(
                HTTPStatus.ACCEPTED,
                {
                    "ok": True,
                    "status": "accepted",
                    "message": "Step 3 simulation accepted and running asynchronously",
                    "requested_at": utc_now(),
                    "model_id": replay_payload.get("model_id"),
                    "model_version": replay_payload.get("model_version"),
                    "send_workers": replay_payload.get("send_workers"),
                    "target_mode": replay_payload.get("target_mode"),
                    "step3_audit_log_path": str(audit_path),
                },
            )
            return
        if path == "/model-v1/step3/simulation/stop":
            self.send_json(HTTPStatus.OK, step3_simulation_stop())
            return
        if path == "/model-v1/step3/adapter/run":
            self.send_json(HTTPStatus.OK, step3_adapter_run(self._read_json_body(), self.data_root))
            return
        if path == "/model-v1/step3/rules/deploy":
            self.send_json(HTTPStatus.OK, deploy_rules(self._read_json_body()))
            return
        if path == "/model-v1/step3/prepare":
            self.send_json(
                HTTPStatus.CONFLICT,
                {
                    "ok": False,
                    "error": "step3_legacy_endpoint_disabled",
                    "endpoint": "/model-v1/step3/prepare",
                    "recommended_endpoint": "/model-v1/step3/simulation/start",
                },
            )
            return
        if path == "/model-v1/step3/preparation/verify":
            self.send_json(
                HTTPStatus.CONFLICT,
                {
                    "ok": False,
                    "error": "step3_legacy_endpoint_disabled",
                    "endpoint": "/model-v1/step3/preparation/verify",
                    "recommended_endpoint": "/model-v1/step3/simulation/start",
                },
            )
            return
        if path == "/model-v1/step3/replay/run":
            self.send_json(
                HTTPStatus.CONFLICT,
                {
                    "ok": False,
                    "error": "step3_legacy_endpoint_disabled",
                    "endpoint": "/model-v1/step3/replay/run",
                    "recommended_endpoint": "/model-v1/step3/simulation/start",
                },
            )
            return
        if path == "/model-v1/step3/replay/stop":
            resp = step3_replay_stop()
            with _STEP3_REPLAY_BG_LOCK:
                _STEP3_REPLAY_BG_STATE.update(
                    {
                        "running": False,
                        "launch_token": None,
                        "finished_at": utc_now(),
                        "last_error": str((resp or {}).get("error") or "stopped_by_operator"),
                    }
                )
            self.send_json(HTTPStatus.OK, resp)
            return
        if path == "/model-v1/step3/analyst-feedback":
            self.send_json(HTTPStatus.OK, step3_submit_analyst_feedback(self._read_json_body()))
            return
        if path.startswith("/model-v1/step3/child-stacks/") and path.endswith("/start"):
            child_id = path.removeprefix("/model-v1/step3/child-stacks/").removesuffix("/start")
            self.send_json(HTTPStatus.OK, child_stack_lifecycle(child_id, "start"))
            return
        if path.startswith("/model-v1/step3/child-stacks/") and path.endswith("/stop"):
            child_id = path.removeprefix("/model-v1/step3/child-stacks/").removesuffix("/stop")
            self.send_json(HTTPStatus.OK, child_stack_lifecycle(child_id, "stop"))
            return
        if path.startswith("/model-v1/step3/child-stacks/") and path.endswith("/remove"):
            child_id = path.removeprefix("/model-v1/step3/child-stacks/").removesuffix("/remove")
            self.send_json(HTTPStatus.OK, remove_child_stack(child_id))
            return
        if path.startswith("/model-v1/step3/child-stacks/") and path.endswith("/restart"):
            child_id = path.removeprefix("/model-v1/step3/child-stacks/").removesuffix("/restart")
            self.send_json(HTTPStatus.OK, child_stack_lifecycle(child_id, "restart"))
            return
        if path.startswith("/model-v1/step3/child-stacks/") and path.endswith("/rules/sync"):
            child_id = path.removeprefix("/model-v1/step3/child-stacks/").removesuffix("/rules/sync")
            self.send_json(HTTPStatus.OK, deploy_rules({"child_ids": [child_id]}))
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Unknown endpoint."})

    def upload_status(self) -> tuple[list[dict], bool]:
        datasets = read_manifest(self.manifest_path, self.hybrid_policy_path)
        required = required_dataset_ids(datasets, self.required_override)
        rows = []
        for item in datasets:
            dataset_id = item["dataset_id"]
            resolved_raw = resolve_dataset_raw_dir_with_source(self.data_root, item)
            dataset_raw = resolved_raw[0]
            step0 = process_csv_readiness(self.data_root, item, precomputed_raw=resolved_raw)
            uploaded_any = has_uploads(dataset_raw)
            rows.append(
                {
                    "dataset_id": dataset_id,
                    "name": item.get("name"),
                    "role": item.get("role"),
                    "required": dataset_id in required,
                    "uploaded": uploaded_any,
                    "uploaded_replay": uploaded_any,
                    "target_dir": str(dataset_raw),
                    "ingest_target_dir": str(dataset_raw),
                    "replay_target_dir": str(dataset_raw),
                    "dataset_raw_dir": str(dataset_raw),
                    "step0": step0,
                    "step0_ready": step0["step0_ready"],
                    "registered_artifacts": registered_artifacts(item),
                    "ingest_workflow_mode": ingest_workflow_mode(dataset_id, str(item.get("role") or "")),
                }
            )
        return rows, True

    def training_precheck(self) -> None:
        """Governance gate before training: leakage checks must pass (no training job is started here)."""
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    assert_training_governance_allows(cur)
        except TrainingGovernanceError as exc:
            try:
                write_audit_event(
                    event_type=TRAINING_BLOCKED,
                    actor="phase4-dash-api",
                    artifact_refs=[],
                    context={"reason": "governance_precheck_failed", "detail": str(exc)},
                    dataset_id=None,
                    experiment_id="exp_model_v1_enterprise_baseline",
                    model_version="v1",
                )
            except Exception:
                pass
            self.send_json(
                HTTPStatus.FORBIDDEN,
                {"ok": False, "error": str(exc), "governance": "training_blocked"},
            )
            return
        except Exception as exc:
            self.send_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"ok": False, "error": f"governance_precheck_unavailable: {exc}"},
            )
            return
        self.send_json(
            HTTPStatus.OK,
            {
                "ok": True,
                "governance": "training_allowed",
                "message": "Leakage governance checks passed; training service may proceed when wired.",
            },
        )

    def governance_payload(self) -> dict:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    gov = build_governance_api_payload(
                        manifest_path=self.manifest_path,
                        hybrid_policy_path=self.hybrid_policy_path,
                        experiment_design_path=self.experiment_design_path,
                        cur=cur,
                    )
            return {"ok": True, **gov, "db_status": "ok"}
        except Exception as exc:
            gov = build_governance_api_payload(
                manifest_path=self.manifest_path,
                hybrid_policy_path=self.hybrid_policy_path,
                experiment_design_path=self.experiment_design_path,
                cur=None,
            )
            return {"ok": True, **gov, "db_status": f"unavailable: {exc}"}

    def _latest_workflow_statuses(self) -> tuple[dict[str, dict[str, Any]], str]:
        latest: dict[str, dict[str, Any]] = {}
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        WITH ranked AS (
                            SELECT
                                step_name,
                                run_id::text AS run_id,
                                status,
                                started_at_utc,
                                completed_at_utc,
                                ROW_NUMBER() OVER (PARTITION BY step_name ORDER BY started_at_utc DESC, run_id DESC) AS rn
                            FROM phase4.workflow_runs
                            WHERE step_name IN ('step1', 'step2')
                        )
                        SELECT step_name, run_id, status, started_at_utc, completed_at_utc
                        FROM ranked
                        WHERE rn = 1;
                        """
                    )
                    for step_name, run_id, status, started_at, completed_at in cur.fetchall():
                        latest[str(step_name)] = {
                            "run_id": str(run_id or ""),
                            "status": str(status or ""),
                            "started_at_utc": started_at.isoformat() if started_at else None,
                            "completed_at_utc": completed_at.isoformat() if completed_at else None,
                        }
            return latest, "ok"
        except Exception as exc:
            return latest, f"unavailable: {exc}"

    def _latest_runtime_state(self, step_name: str) -> dict[str, Any] | None:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT step_name, workflow_id, run_id::text, current_phase, phase_status, status, state_payload, updated_at_utc
                        FROM phase4.workflow_runtime_state
                        WHERE step_name = %(step_name)s
                        ORDER BY updated_at_utc DESC
                        LIMIT 1;
                        """,
                        {"step_name": step_name},
                    )
                    row = cur.fetchone()
                    if not row:
                        return None
                    return {
                        "step_name": row[0],
                        "workflow_id": row[1],
                        "run_id": row[2],
                        "current_phase": row[3],
                        "phase_status": row[4],
                        "status": row[5],
                        "state_payload": row[6] or {},
                        "updated_at_utc": self._fmt_ts(row[7]),
                    }
        except Exception:
            return None

    def _open_requests(self, step_name: str) -> list[dict[str, Any]]:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT request_id::text, step_name, stage_name, workflow_id, run_id::text, dataset_id,
                               requested_by, status, request_payload, requested_at_utc, updated_at_utc, completed_at_utc
                        FROM phase4.workflow_requests
                        WHERE step_name = %(step_name)s
                        ORDER BY requested_at_utc DESC
                        LIMIT 50;
                        """,
                        {"step_name": step_name},
                    )
                    out: list[dict[str, Any]] = []
                    for row in cur.fetchall():
                        out.append(
                            {
                                "request_id": row[0],
                                "step_name": row[1],
                                "stage_name": row[2],
                                "workflow_id": row[3],
                                "run_id": row[4],
                                "dataset_id": row[5],
                                "requested_by": row[6],
                                "status": row[7],
                                "request_payload": row[8] or {},
                                "requested_at_utc": self._fmt_ts(row[9]),
                                "updated_at_utc": self._fmt_ts(row[10]),
                                "completed_at_utc": self._fmt_ts(row[11]),
                            }
                        )
                    return out
        except Exception:
            return []

    def _reconcile_dashboard_state_with_db(
        self,
        state: dict[str, Any],
        workflow_status: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        out = dict(state or {})
        stages = out.get("stages")
        if not isinstance(stages, list):
            stages = []
        stage_map = {
            str(stage.get("id")): stage
            for stage in stages
            if isinstance(stage, dict) and stage.get("id")
        }
        step1 = workflow_status.get("step1") or {}
        step1_status = self._normalize_status(step1.get("status"))
        if step1_status == "completed":
            phase = str(out.get("phase") or "")
            if phase.endswith("_running") or phase.endswith("_requested") or phase == "ingestion":
                out["phase"] = "ingestion_complete"
            for sid in ("normalise", "categorise", "split", "ingest", "postgres"):
                stage = stage_map.get(sid)
                if stage and self._normalize_status(stage.get("status")) in {"pending", "running"}:
                    stage["status"] = "complete"
        elif step1_status == "failed":
            phase = str(out.get("phase") or "")
            if phase.endswith("_running") or phase.endswith("_requested") or phase == "ingestion":
                out["phase"] = "ingestion_failed"
            for sid in ("normalise", "categorise", "split", "ingest", "postgres"):
                stage = stage_map.get(sid)
                if stage and self._normalize_status(stage.get("status")) in {"pending", "running"}:
                    stage["status"] = "failed"
        elif step1_status in {"queued", "running"}:
            out["phase"] = "ingestion_running"
        out["stages"] = stages
        out["workflow_status"] = workflow_status
        out["status_source"] = "postgres_authoritative"
        return out

    def status_payload(self) -> dict:
        rows, all_required_uploaded = self.upload_status()
        workflow_status, workflow_db_status = self._latest_workflow_statuses()
        runtime_state = self._latest_runtime_state("step1")
        state = default_state()
        if runtime_state and isinstance(runtime_state.get("state_payload"), dict):
            payload_state = runtime_state.get("state_payload") or {}
            if isinstance(payload_state, dict):
                state.update({k: v for k, v in payload_state.items() if k != "stages"})
                if isinstance(payload_state.get("stages"), list):
                    state["stages"] = payload_state["stages"]
        state = self._reconcile_dashboard_state_with_db(state, workflow_status)
        state["runtime_state"] = runtime_state or {}
        state["recent_requests"] = self._open_requests("step1")
        try:
            dataset_logs = list_dataset_logs(limit=300)
            db_status = "ok"
        except Exception as exc:
            dataset_logs = []
            db_status = f"unavailable: {exc}"
        governance = self.governance_payload()
        leakage_blocking = governance.get("leakage_blocking", False)
        audits = (governance.get("audit_trail") or {}).get("recent_events") or []
        by_ds = latest_audit_by_dataset(audits)
        for row in rows:
            row["governance_ui"] = build_governance_ui_row(
                dataset_id=row["dataset_id"],
                role=row.get("role"),
                dashboard_state=state,
                step0_ready=bool(row.get("step0_ready")),
                leakage_blocking=bool(leakage_blocking),
                latest_audit=by_ds.get(row["dataset_id"]),
            )
        return {
            "ok": True,
            "state": state,
            "uploads": rows,
            "dataset_logs": dataset_logs,
            "db_status": db_status,
            "workflow_db_status": workflow_db_status,
            "all_required_uploaded": all_required_uploaded,
            "can_start_ingestion": False,
            "governance": governance,
            "training_blocked": leakage_blocking,
            "training_block_reason": "leakage_guard_failure" if leakage_blocking else None,
        }

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def current_model_header_payload(self) -> dict[str, Any]:
        """Registry row with ``is_current`` drives the header; else newest non-deprecated row as preview."""
        models = list_models().get("models", [])
        n = len(models)
        current = next((m for m in models if m.get("is_current")), None)
        header_source = "registry_current"
        preview = current
        if not preview:
            for m in models:
                if not m.get("is_deprecated"):
                    preview = m
                    header_source = "registry_fallback"
                    break
            if not preview and models:
                preview = models[0]
                header_source = "registry_fallback_deprecated_only"

        if not preview:
            return {
                "ok": True,
                "header_source": "empty",
                "registry_model_count": n,
                "current_model_version": None,
                "model_status": "not_selected",
                "frozen": False,
                "trained_at": None,
                "active_rulepack_version": None,
                "step2_completion_status": "pending",
                "step3_readiness_status": "not_applicable",
                "last_run_status": None,
                "banner": (
                    "Current Model: Not selected — no rows in phase4.model_registry yet "
                    "(create a model from Step 2)."
                    if n == 0
                    else "Current Model: Not selected — choose or create a model version"
                ),
            }

        banner = (
            f"Current Model: {preview.get('model_version')} | status={preview.get('status')} | "
            f"frozen={bool(preview.get('is_frozen'))}"
        )
        if header_source != "registry_current":
            banner = (
                f"Preview (no is_current in DB): {preview.get('model_version')} | "
                f"status={preview.get('status')} — use Step 2 model actions and Set Current on the row you want as active."
            )

        out: dict[str, Any] = {
            "ok": True,
            "header_source": header_source,
            "registry_model_count": n,
            "current_model_version": preview.get("model_version"),
            "model_status": preview.get("status"),
            "frozen": bool(preview.get("is_frozen")),
            "trained_at": preview.get("trained_at"),
            "active_rulepack_version": preview.get("rulepack_status"),
            "step2_completion_status": preview.get("status"),
            "step3_readiness_status": "not_applicable",
            "last_run_status": preview.get("last_run_status"),
            "banner": banner,
            "model": preview,
        }
        if header_source != "registry_current":
            out["is_current_flag"] = False
        else:
            out["is_current_flag"] = True
        return out

    def step2_readiness_payload(self, model_version: str) -> dict[str, Any]:
        model = get_model(model_version)
        if not model.get("ok"):
            return {"ok": False, "error": "model_not_found", "ready": False}
        m = model["model"]
        issues: list[str] = []
        if m.get("invalid_lineage"):
            issues.append("invalid_lineage_model_cannot_run")
        if m.get("is_deprecated"):
            issues.append("deprecated_model_read_only")
        if str(m.get("dataset_source") or "") != "ENT-01":
            issues.append("dataset_source_must_be_ent01")
        if str(m.get("training_split") or "") != "train":
            issues.append("training_split_must_be_train")
        # Reuse governance precheck semantics for leakage enforcement.
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    assert_training_governance_allows(cur)
        except Exception as exc:
            issues.append(f"leakage_guard_failed:{exc}")
        latest_step1 = None
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT run_id::text, status, run_metrics
                        FROM phase4.workflow_runs
                        WHERE step_name='step1'
                        ORDER BY started_at_utc DESC
                        LIMIT 1;
                        """
                    )
                    latest_step1 = cur.fetchone()
        except Exception:
            latest_step1 = None
        step1_ready = bool(latest_step1 and latest_step1[1] == "completed")
        if not step1_ready:
            issues.append("step1_not_ready")
        status = str(m.get("status") or "created")
        allowed_modes = {
            "created": ["create_new", "continue_existing"],
            "pending": ["continue_existing"],
            "training": ["continue_existing"],
            "trained": ["continue_existing"],
            "evaluated": ["continue_existing"],
            "frozen": ["continue_existing"],
            "failed": ["retry_failed_phase", "clone_and_train"],
            "deprecated": ["clone_and_train"],
            "invalid_lineage": ["clone_and_train"],
        }.get(status, ["continue_existing"])
        return {
            "ok": True,
            "ready": len(issues) == 0,
            "model_version": model_version,
            "model_status": status,
            "issues": issues,
            "allowed_execution_modes": allowed_modes,
            "step1_ready": step1_ready,
            "leakage_guard_ok": not any(x.startswith("leakage_guard_failed") for x in issues),
        }

    def list_step1_runs_payload(self) -> dict[str, Any]:
        out: list[dict[str, Any]] = []
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT run_id::text, workflow_id, status, started_at_utc, completed_at_utc, run_metrics
                        FROM phase4.workflow_runs
                        WHERE step_name='step1'
                        ORDER BY started_at_utc DESC, run_id DESC
                        LIMIT 200;
                        """
                    )
                    for run_id, workflow_id, status, started, completed, run_metrics in cur.fetchall():
                        run_id_txt = str(run_id or "")
                        base = status_for_run(run_id_txt) if run_id_txt else {}
                        base_db = (base.get("db") or {}) if isinstance(base, dict) else {}
                        m = _parse_metrics(base_db.get("run_metrics") if base_db else run_metrics)
                        status = str(base_db.get("status") or status)
                        ds = m.get("dataset_summary") or {}
                        if not isinstance(ds, dict):
                            ds = {}
                        dataset_rows = {
                            k: {
                                "ok": bool((v or {}).get("ok")),
                                "readiness": (v or {}).get("readiness"),
                                "rows": (v or {}).get("normalized_rows"),
                                "failed_rows": (v or {}).get("failed_rows"),
                            }
                            for k, v in ds.items()
                        }
                        selected_datasets = [k for k, v in dataset_rows.items() if bool(v.get("ok"))]
                        readiness = all(
                            bool((dataset_rows.get(dsid) or {}).get("ok"))
                            and str((dataset_rows.get(dsid) or {}).get("readiness") or "") == "completed"
                            for dsid in STEP1_DATASETS
                        )
                        out.append(
                            {
                                "run_id": run_id_txt,
                                "run_label": str(m.get("run_label") or ""),
                                "workflow_id": workflow_id,
                                "status": status,
                                "started_at": started.isoformat() if started else None,
                                "started_at_utc": started.isoformat() if started else None,
                                "completed_at": completed.isoformat() if completed else None,
                                "completed_at_utc": completed.isoformat() if completed else None,
                                "processed_datasets": selected_datasets,
                                "dataset_row_counts": {k: dataset_rows[k].get("rows") for k in dataset_rows.keys()},
                                "dataset_readiness_snapshot": dataset_rows,
                                "readiness_status": "ready" if readiness else "blocked",
                                "lineage_hash": step1_dataset_lineage_hash(ds) if ds else None,
                            }
                        )
        except Exception as exc:
            return {"ok": False, "error": str(exc), "runs": []}
        return {
            "ok": True,
            "sort": {"primary": "started_at_utc_desc", "fallback": "run_id_desc"},
            "runs": out,
        }

    def step1_run_detail_payload(self, run_id: str) -> dict[str, Any]:
        rows = self.list_step1_runs_payload().get("runs", [])
        row = next((r for r in rows if r["run_id"] == run_id), None)
        if not row:
            return {"ok": False, "error": "step1_run_not_found"}
        return {"ok": True, "run": row}

    def step1_split_summary_payload(self, run_id: str | None = None) -> dict[str, Any]:
        try:
            rid = str(run_id or "").strip()
            with connect() as conn:
                with conn.cursor() as cur:
                    if not rid:
                        cur.execute(
                            """
                            SELECT run_id::text
                            FROM phase4.workflow_runs
                            WHERE step_name='step1'
                            ORDER BY started_at_utc DESC, run_id DESC
                            LIMIT 1;
                            """
                        )
                        row = cur.fetchone()
                        rid = str(row[0]) if row else ""
                    if not rid:
                        return {"ok": True, "run_id": "", "rows": []}
                    cur.execute(
                        """
                        SELECT
                            ds.dataset_id,
                            COALESCE(NULLIF(LOWER(ds.source_domain), ''), NULLIF(LOWER(dr.domain), ''), 'unknown') AS domain,
                            COALESCE(NULLIF(ds.source_role, ''), NULLIF(dr.approved_role, ''), 'unknown') AS role,
                            COALESCE(NULLIF(ds.vector_class, ''), 'unknown') AS vector,
                            COALESCE(NULLIF(ds.split_name, ''), 'unknown') AS split_label,
                            COUNT(*)::bigint AS total_rows
                        FROM phase4.dataset_splits ds
                        LEFT JOIN phase4.dataset_registry dr
                          ON dr.dataset_id = ds.dataset_id
                        WHERE ds.source_step1_run_id = %(rid)s::uuid
                        GROUP BY
                            ds.dataset_id,
                            COALESCE(NULLIF(LOWER(ds.source_domain), ''), NULLIF(LOWER(dr.domain), ''), 'unknown'),
                            COALESCE(NULLIF(ds.source_role, ''), NULLIF(dr.approved_role, ''), 'unknown'),
                            COALESCE(NULLIF(ds.vector_class, ''), 'unknown'),
                            COALESCE(NULLIF(ds.split_name, ''), 'unknown')
                        ORDER BY ds.dataset_id, domain, role, vector, split_label;
                        """,
                        {"rid": rid},
                    )
                    rows = [
                        {
                            "dataset_id": str(dataset_id or ""),
                            "domain": str(domain or "unknown"),
                            "role": str(role or "unknown"),
                            "vector": str(vector or "unknown"),
                            "split_label": str(split_label or "unknown"),
                            "total_rows": int(total_rows or 0),
                        }
                        for dataset_id, domain, role, vector, split_label, total_rows in cur.fetchall()
                    ]
            return {"ok": True, "run_id": rid, "rows": rows}
        except Exception as exc:
            return {"ok": False, "error": str(exc), "run_id": str(run_id or ""), "rows": []}

    def run_step1(self) -> None:
        data = self._read_json_body()
        worker_mode = str(data.get("worker_mode") or os.getenv("PROJECT_WORKER_MODE", "process")).strip().lower()
        max_workers = data.get("max_workers")
        max_workers_int = int(max_workers) if isinstance(max_workers, int) or (isinstance(max_workers, str) and max_workers.isdigit()) else None
        result = start_step1_async(
            data_root=self.data_root,
            workflow_script=REPO_ROOT / "services_parent" / "data_pipeline" / "phase4_workflow.py",
            manifest=self.manifest_path,
            hybrid_policy=self.hybrid_policy_path,
            requested_by="dashboard",
            worker_mode=worker_mode if worker_mode in {"process", "thread", "hybrid"} else "process",
            max_workers=max_workers_int,
        )
        status = HTTPStatus.ACCEPTED if result.get("ok") else HTTPStatus.CONFLICT
        self.send_json(status, result)

    @staticmethod
    def _metrics_generation_key(step_name: str) -> str:
        return "step1_metrics_generation" if step_name == "step1" else "step2_metrics_generation"

    @staticmethod
    def _latest_workflow_run_id(step_name: str) -> str:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT run_id::text
                    FROM phase4.workflow_runs
                    WHERE step_name = %(step_name)s
                    ORDER BY started_at_utc DESC, run_id DESC
                    LIMIT 1;
                    """,
                    {"step_name": step_name},
                )
                row = cur.fetchone()
                return str((row or [""])[0] or "").strip()

    @staticmethod
    def _latest_step3_replay_run_id() -> str:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT replay_run_id::text
                    FROM phase4.replay_runs
                    ORDER BY created_at_utc DESC, replay_run_id DESC
                    LIMIT 1;
                    """
                )
                row = cur.fetchone()
                return str((row or [""])[0] or "").strip()

    @staticmethod
    def _latest_step3_sim_id() -> str:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT simulation_id::text
                    FROM phase4.step3_v2_simulations
                    ORDER BY created_at_utc DESC, simulation_id DESC
                    LIMIT 1;
                    """
                )
                row = cur.fetchone()
                sim_id = str((row or [""])[0] or "").strip()
                if sim_id:
                    return sim_id
                cur.execute(
                    """
                    SELECT COALESCE(replay_id::text, preparation_replay_id::text, simulation_session_id::text, '') AS sim_id
                    FROM phase4.replay_runs
                    WHERE replay_id IS NOT NULL
                       OR preparation_replay_id IS NOT NULL
                       OR simulation_session_id IS NOT NULL
                    ORDER BY created_at_utc DESC, replay_run_id DESC
                    LIMIT 1;
                    """
                )
                row = cur.fetchone()
                return str((row or [""])[0] or "").strip()

    @staticmethod
    def _persist_metrics_generation_result(*, step_name: str, run_id: str, result: dict[str, Any]) -> None:
        if not str(run_id or "").strip():
            return
        key = DashHandler._metrics_generation_key(step_name)
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE phase4.workflow_runs
                    SET run_metrics = COALESCE(run_metrics, '{}'::jsonb) || jsonb_build_object(%(key)s, %(payload)s::jsonb)
                    WHERE run_id = %(run_id)s::uuid
                      AND step_name = %(step_name)s;
                    """,
                    {
                        "key": key,
                        "payload": json.dumps(result),
                        "run_id": run_id,
                        "step_name": step_name,
                    },
                )
            conn.commit()

    def regenerate_step1_metrics(self) -> None:
        data = self._read_json_body()
        requested_run_id = str(data.get("run_id") or data.get("step1_run_id") or "").strip()
        run_id = requested_run_id or self._latest_workflow_run_id("step1")
        if not run_id:
            self.send_json(HTTPStatus.CONFLICT, {"ok": False, "error": "step1_run_not_found", "run_id": ""})
            return
        result = generate_step1_metrics(run_id=run_id)
        if result.get("ok"):
            try:
                self._persist_metrics_generation_result(step_name="step1", run_id=run_id, result=result)
            except Exception as exc:
                result = dict(result)
                errs = result.get("errors") if isinstance(result.get("errors"), list) else []
                errs = list(errs)
                errs.append(f"persist_step1_metrics_generation:{exc}")
                result["errors"] = errs
                result["warning"] = True
                result["status"] = "completed_with_warning"
        self.send_json(HTTPStatus.OK if result.get("ok") else HTTPStatus.CONFLICT, result)

    def model_v1_step2_resource_get(self, path: str) -> None:
        """GET /model-v1/step2/{training|testing|shap|rules} — slice live + DB status for Step 2."""
        params = parse_qs(urlparse(self.path).query, keep_blank_values=False)
        run_id = (params.get("run_id") or [""])[0].strip()
        tail = path.split("/model-v1/step2/", 1)[-1]
        if not run_id:
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "run_id query parameter required"})
            return
        base = status_for_run(run_id)
        live = base.get("live") or {}
        db = base.get("db") or {}
        metrics = db.get("run_metrics") or {}
        if isinstance(metrics, str):
            try:
                metrics = json.loads(metrics)
            except Exception:
                metrics = {}
        payload: dict[str, Any] = {
            "ok": True,
            "run_id": run_id,
            "resource": tail,
            "live": live,
            "step2_config": step2_config.config_snapshot(),
            "cpu_governor": metrics.get("cpu_governor") or live.get("host_cpu_governor") or {},
            "cpu_telemetry": metrics.get("cpu_telemetry") or {},
            "queue_state": metrics.get("queue_state") or live.get("queue_state"),
            "effective_parallelism": metrics.get("effective_parallelism") or live.get("effective_parallelism"),
            "step3_cpu_governance": metrics.get("step3_cpu_governance")
            or {"status": "deferred", "reason": "excluded_from_current_rollout"},
        }
        if tail == "training":
            payload["training"] = metrics.get("training_result") or live.get("training_result")
        elif tail == "testing":
            payload["testing"] = metrics.get("testing_results")
        elif tail == "shap":
            payload["shap"] = metrics.get("shap_results")
        elif tail == "rules":
            rules_rows = metrics.get("rule_results")
            if not isinstance(rules_rows, list):
                rules_rows = []
            payload["rules"] = rules_rows
            rules_total = 0
            rules_by_scope: dict[str, int] = {}
            rules_by_family: dict[str, int] = {}
            detection_profile = "high_recall"
            for row in rules_rows:
                if not isinstance(row, dict):
                    continue
                scope = str(row.get("scope") or row.get("rule_scope") or "unknown").strip() or "unknown"
                rule_list = row.get("rules") if isinstance(row.get("rules"), list) else []
                if rule_list:
                    rules_total += len(rule_list)
                    rules_by_scope[scope] = int(rules_by_scope.get(scope) or 0) + len(rule_list)
                    for rr in rule_list:
                        if not isinstance(rr, dict):
                            continue
                        fam = str(rr.get("rule_type") or "unspecified").strip() or "unspecified"
                        rules_by_family[fam] = int(rules_by_family.get(fam) or 0) + 1
                        dp = str(rr.get("detection_profile") or "").strip().lower()
                        if dp:
                            detection_profile = dp
                else:
                    rule_count = int(row.get("rule_count") or 0)
                    if rule_count > 0:
                        rules_total += rule_count
                        rules_by_scope[scope] = int(rules_by_scope.get(scope) or 0) + rule_count
            payload["rules_total"] = int(rules_total)
            payload["rules_by_scope"] = rules_by_scope
            payload["rules_by_family"] = rules_by_family
            payload["detection_profile"] = detection_profile
        else:
            self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": f"Unknown model-v1 step2 resource: {tail}"})
            return
        self.send_json(HTTPStatus.OK, payload)

    def run_step2(self) -> None:
        data = self._read_json_body()
        source_step1_run_id = str(data.get("source_step1_run_id") or data.get("prerequisite_step1_run_id") or data.get("step1_run_id") or "").strip()
        if not source_step1_run_id:
            self.send_json(
                HTTPStatus.BAD_REQUEST,
                {"ok": False, "error": "source_step1_run_id_required_before_step2", "run_enabled": False},
            )
            return
        run_detail = self.step1_run_detail_payload(source_step1_run_id)
        if not run_detail.get("ok"):
            self.send_json(HTTPStatus.CONFLICT, {"ok": False, "error": "invalid_step1_run_id"})
            return
        if str((run_detail.get("run") or {}).get("readiness_status")) != "ready":
            self.send_json(
                HTTPStatus.CONFLICT,
                {"ok": False, "error": "selected_step1_run_not_ready", "selected_step1_run": run_detail.get("run")},
            )
            return
        model_version = str(data.get("model_version") or "").strip()
        execution_mode = str(data.get("execution_mode") or "").strip() or "continue_existing"
        if not model_version:
            self.send_json(
                HTTPStatus.BAD_REQUEST,
                {"ok": False, "error": "model_version_required_before_step2", "run_enabled": False},
            )
            return
        if execution_mode == "create_new":
            existing = get_model(model_version)
            if not existing.get("ok"):
                step1_row = run_detail.get("run") or {}
                created = create_model(
                    self.data_root,
                    {
                        "model_version": model_version,
                        "source_step1_run_id": source_step1_run_id,
                        "source_step1_lineage_hash": step1_row.get("lineage_hash"),
                        "linked_step1_lineage_hash": step1_row.get("lineage_hash"),
                        "dataset_readiness_snapshot": step1_row.get("dataset_readiness_snapshot") or {},
                        "selected_datasets": step1_row.get("processed_datasets") or [],
                    },
                )
                if not created.get("ok"):
                    self.send_json(HTTPStatus.CONFLICT, {"ok": False, "error": "failed_to_create_model_version"})
                    return
        readiness = self.step2_readiness_payload(model_version)
        readiness["selected_step1_run"] = run_detail.get("run")
        if str((run_detail.get("run") or {}).get("readiness_status")) != "ready":
            readiness["ready"] = False
            readiness.setdefault("issues", []).append("selected_step1_run_not_ready")
        if not readiness.get("ok") or not readiness.get("ready"):
            self.send_json(
                HTTPStatus.CONFLICT,
                {
                    "ok": False,
                    "error": "step2_not_ready_for_selected_model",
                    "model_version": model_version,
                    "readiness": readiness,
                    "run_enabled": False,
                },
            )
            return
        if execution_mode not in set(readiness.get("allowed_execution_modes") or []):
            self.send_json(
                HTTPStatus.CONFLICT,
                {
                    "ok": False,
                    "error": "execution_mode_not_allowed_for_model_status",
                    "model_version": model_version,
                    "execution_mode": execution_mode,
                    "allowed_execution_modes": readiness.get("allowed_execution_modes") or [],
                },
            )
            return
        # Ensure selected model is current before launching run.
        set_current_model(model_version)
        write_audit_event(
            event_type="step2_training_filter_enforced",
            actor="phase4-dash-api",
            artifact_refs=[],
            context={
                "model_version": model_version,
                "dataset_source": "ENT-01",
                "split_name": "train",
                "filter_sql": "dataset_source='ENT-01' AND split_name='train'",
                "execution_mode": execution_mode,
            },
            model_version=model_version,
            experiment_id="exp_model_v1_enterprise_baseline",
        )
        worker_mode = str(data.get("worker_mode") or os.getenv("PROJECT_WORKER_MODE", "process")).strip().lower()
        max_workers = data.get("max_workers")
        max_workers_int = int(max_workers) if isinstance(max_workers, int) or (isinstance(max_workers, str) and max_workers.isdigit()) else None
        prereq = source_step1_run_id
        result = start_step2_async(
            data_root=self.data_root,
            train_script=REPO_ROOT / "scripts" / "train_model_v1.py",
            evaluate_script=REPO_ROOT / "scripts" / "evaluate_model_v1.py",
            shap_script=REPO_ROOT / "scripts" / "shap_offline.py",
            rules_script=REPO_ROOT / "scripts" / "generate_rules.py",
            requested_by="dashboard",
            worker_mode=worker_mode if worker_mode in {"process", "thread", "hybrid"} else "process",
            max_workers=max_workers_int,
            prerequisite_step1_run_id=prereq or None,
            model_version=model_version,
            execution_mode=execution_mode,
        )
        status = HTTPStatus.ACCEPTED if result.get("ok") else HTTPStatus.CONFLICT
        self.send_json(status, result)

    def regenerate_step2_metrics(self) -> None:
        data = self._read_json_body()
        requested_run_id = str(data.get("run_id") or data.get("step2_run_id") or "").strip()
        run_id = requested_run_id or self._latest_workflow_run_id("step2")
        if not run_id:
            self.send_json(HTTPStatus.CONFLICT, {"ok": False, "error": "step2_run_not_found", "run_id": ""})
            return
        result = generate_step2_metrics(run_id=run_id)
        if result.get("ok"):
            try:
                self._persist_metrics_generation_result(step_name="step2", run_id=run_id, result=result)
            except Exception as exc:
                result = dict(result)
                errs = result.get("errors") if isinstance(result.get("errors"), list) else []
                errs = list(errs)
                errs.append(f"persist_step2_metrics_generation:{exc}")
                result["errors"] = errs
                result["warning"] = True
                result["status"] = "completed_with_warning"
        self.send_json(HTTPStatus.OK if result.get("ok") else HTTPStatus.CONFLICT, result)

    def step3_metrics_payload(self, *, sim_id: str) -> dict[str, Any]:
        sid = str(sim_id or "").strip()
        if not sid:
            return {"ok": False, "error": "sim_id_required", "sim_id": "", "metrics": []}
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT simulation_id::text, model_id::text, model_version, status, started_at_utc, finished_at_utc
                        FROM phase4.step3_v2_simulations
                        WHERE simulation_id::text = %(sid)s
                        LIMIT 1;
                        """,
                        {"sid": sid},
                    )
                    sim = cur.fetchone()
                    cur.execute(
                        """
                        SELECT metric, metric_value, numerator, denominator, status, calculation_status,
                               calculation_method, details_json, createdat, updatedat
                        FROM phase4.metrics
                        WHERE step = 'step3'
                          AND step_unique_id = %(sid)s
                        ORDER BY metric ASC;
                        """,
                        {"sid": sid},
                    )
                    rows = cur.fetchall() or []
            metrics: list[dict[str, Any]] = []
            measured = 0
            not_collected = 0
            for metric, metric_value, numerator, denominator, principle_status, calculation_status, method, details_json, created_at, updated_at in rows:
                details = details_json if isinstance(details_json, dict) else {}
                calc_status = str(calculation_status or "not_collected")
                if calc_status == "measured":
                    measured += 1
                elif calc_status == "not_collected":
                    not_collected += 1
                metrics.append(
                    {
                        "metric_name": str(metric or ""),
                        "metric_value": float(metric_value) if metric_value is not None else None,
                        "numerator": float(numerator) if numerator is not None else None,
                        "denominator": float(denominator) if denominator is not None else None,
                        "principle_status": str(principle_status or ""),
                        "calculation_status": calc_status,
                        "calculation_method": str(method or ""),
                        "source_ref": str(details.get("source_ref") or "phase4.metrics"),
                        "details_json": details,
                        "created_at_utc": self._fmt_ts(created_at),
                        "updated_at_utc": self._fmt_ts(updated_at),
                    }
                )
            sim_payload = None
            if sim:
                sim_payload = {
                    "simulation_id": str(sim[0] or ""),
                    "model_id": str(sim[1] or "") if sim[1] else None,
                    "model_version": str(sim[2] or ""),
                    "status": str(sim[3] or ""),
                    "started_at_utc": self._fmt_ts(sim[4]),
                    "finished_at_utc": self._fmt_ts(sim[5]),
                }
            return {
                "ok": True,
                "sim_id": sid,
                "simulation": sim_payload,
                "metrics": metrics,
                "summary": {
                    "total": len(metrics),
                    "measured": measured,
                    "not_collected": not_collected,
                    "other": max(0, len(metrics) - measured - not_collected),
                },
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc), "sim_id": sid, "metrics": []}

    def regenerate_step3_metrics(self) -> None:
        data = self._read_json_body()
        requested_sim_id = str(
            data.get("sim_id")
            or data.get("step3_sim_id")
            or data.get("replay_id")
            or data.get("preparation_replay_id")
            or ""
        ).strip()
        requested_simulation_id = str(
            data.get("simulation_id")
            or data.get("step3_simulation_id")
            or data.get("simulation_session_id")
            or ""
        ).strip()
        requested_replay_run_id = str(data.get("replay_run_id") or data.get("step3_replay_run_id") or "").strip()
        sim_id = requested_sim_id or requested_simulation_id or self._latest_step3_sim_id()
        replay_run_id = requested_replay_run_id or ("" if sim_id else self._latest_step3_replay_run_id())
        if not sim_id and not replay_run_id:
            self.send_json(
                HTTPStatus.CONFLICT,
                {"ok": False, "error": "step3_sim_id_not_found", "sim_id": "", "replay_run_id": ""},
            )
            return
        result = generate_step3_metrics(
            sim_id=sim_id or None,
            replay_run_id=replay_run_id or None,
        )
        self.send_json(HTTPStatus.OK if result.get("ok") else HTTPStatus.CONFLICT, result)

    def step_status(self, step_name: str) -> None:
        params = parse_qs(urlparse(self.path).query, keep_blank_values=False)
        run_id = (params.get("run_id") or [""])[0].strip()
        if run_id:
            self.send_json(HTTPStatus.OK, status_for_run(run_id))
            return
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT run_id::text, workflow_id, step_name, status, requested_by, worker_mode,
                               requested_workers, effective_workers, started_at_utc, completed_at_utc,
                               run_metrics, error_message
                        FROM phase4.workflow_runs
                        WHERE step_name = %(step)s
                        ORDER BY started_at_utc DESC
                        LIMIT 10;
                        """,
                        {"step": step_name},
                    )
                    cols = [d.name for d in cur.description]
                    rows = [dict(zip(cols, row)) for row in cur.fetchall()]
            for row in rows:
                for key in ("started_at_utc", "completed_at_utc"):
                    if row.get(key) is not None:
                        row[key] = row[key].isoformat()
                m = _parse_metrics(row.get("run_metrics"))
                if step_name == "step1":
                    rid = str(row.get("run_id") or "")
                    if rid:
                        base = status_for_run(rid)
                        base_db = (base.get("db") or {}) if isinstance(base, dict) else {}
                        m = _parse_metrics(base_db.get("run_metrics") if base_db else row.get("run_metrics"))
                        row["status"] = str(base_db.get("status") or row.get("status") or "")
                        row["error_message"] = base_db.get("error_message") or row.get("error_message")
                        row["run_metrics"] = m
                row["run_label"] = str(m.get("run_label") or "")
            self.send_json(HTTPStatus.OK, {"ok": True, "step": step_name, "runs": rows})
        except Exception as exc:
            self.send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"ok": False, "error": str(exc)})

    def artifacts_payload(self) -> dict[str, Any]:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT shap_artifact_id::text AS id, run_id::text, model_version, dataset_id,
                               split_name, partition_id, artifact_path, status, created_at_utc, metadata
                        FROM phase4.shap_artifacts
                        ORDER BY created_at_utc DESC
                        LIMIT 100;
                        """
                    )
                    shap_cols = [d.name for d in cur.description]
                    shap = [dict(zip(shap_cols, r)) for r in cur.fetchall()]
            for row in shap:
                if row.get("created_at_utc") is not None:
                    row["created_at_utc"] = row["created_at_utc"].isoformat()
            return {"ok": True, "shap_artifacts": shap}
        except Exception as exc:
            return {"ok": False, "error": str(exc), "shap_artifacts": []}

    def metrics_payload(self) -> dict[str, Any]:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT training_run_id::text AS id, run_id::text, model_version, experiment_id, status,
                               train_dataset_filter, worker_mode, worker_count, metrics_json, started_at_utc, completed_at_utc
                        FROM phase4.model_training_runs
                        ORDER BY started_at_utc DESC
                        LIMIT 20;
                        """
                    )
                    t_cols = [d.name for d in cur.description]
                    training = [dict(zip(t_cols, r)) for r in cur.fetchall()]
                    cur.execute(
                        """
                        SELECT cross_test_run_id::text AS id, run_id::text, model_version, experiment_id, dataset_id,
                               evaluation_mode, status, metrics_json, started_at_utc, completed_at_utc
                        FROM phase4.cross_dataset_test_runs
                        ORDER BY started_at_utc DESC
                        LIMIT 80;
                        """
                    )
                    c_cols = [d.name for d in cur.description]
                    cross = [dict(zip(c_cols, r)) for r in cur.fetchall()]
            for collection in (training, cross):
                for row in collection:
                    for key in ("started_at_utc", "completed_at_utc"):
                        if row.get(key) is not None:
                            row[key] = row[key].isoformat()
            return {"ok": True, "training_runs": training, "cross_dataset_test_runs": cross}
        except Exception as exc:
            return {"ok": False, "error": str(exc), "training_runs": [], "cross_dataset_test_runs": []}

    def rulepacks_payload(self) -> dict[str, Any]:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT rulepack_id::text AS id, run_id::text, model_version, rulepack_version, scope,
                               status, artifact_path, checksum_sha256, created_at_utc, metadata
                        FROM phase4.rulepack_registry
                        ORDER BY created_at_utc DESC
                        LIMIT 100;
                        """
                    )
                    cols = [d.name for d in cur.description]
                    rows = [dict(zip(cols, r)) for r in cur.fetchall()]
            for row in rows:
                if row.get("created_at_utc") is not None:
                    row["created_at_utc"] = row["created_at_utc"].isoformat()
            return {"ok": True, "rulepacks": rows}
        except Exception as exc:
            return {"ok": False, "error": str(exc), "rulepacks": []}

    def shap_summary_payload(self) -> dict[str, Any]:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, event_type, actor, dataset_id, experiment_id, model_version, rule_version,
                               replay_id, shap_stage, top_features_json, event_details_json, created_at
                        FROM phase4.shap_logs
                        ORDER BY created_at DESC
                        LIMIT 400;
                        """
                    )
                    cols = [d.name for d in cur.description]
                    logs = [dict(zip(cols, r)) for r in cur.fetchall()]
                    cur.execute(
                        """
                        SELECT split_name, status, artifact_path, metadata, created_at_utc
                        FROM phase4.shap_artifacts
                        ORDER BY created_at_utc DESC
                        LIMIT 200;
                        """
                    )
                    a_cols = [d.name for d in cur.description]
                    artifacts = [dict(zip(a_cols, r)) for r in cur.fetchall()]
            for row in logs:
                if row.get("created_at") is not None:
                    row["created_at"] = row["created_at"].isoformat()
            for row in artifacts:
                if row.get("created_at_utc") is not None:
                    row["created_at_utc"] = row["created_at_utc"].isoformat()
            return {"ok": True, "shap_logs": logs, "shap_artifacts": artifacts}
        except Exception as exc:
            return {"ok": False, "error": str(exc), "shap_logs": [], "shap_artifacts": []}

    def rules_summary_payload(self) -> dict[str, Any]:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT rulepack_version, model_version, scope, status, checksum_sha256, artifact_path, created_at_utc
                        FROM phase4.rulepack_registry
                        ORDER BY created_at_utc DESC
                        LIMIT 200;
                        """
                    )
                    rp_cols = [d.name for d in cur.description]
                    rulepacks = [dict(zip(rp_cols, r)) for r in cur.fetchall()]
                    cur.execute(
                        """
                        SELECT rule_id::text, run_id::text, model_id, model_version, rule_scope, rule_type,
                               severity, action, status, created_at_utc
                        FROM phase4.rulepack_rules
                        ORDER BY created_at_utc DESC
                        LIMIT 600;
                        """
                    )
                    rr_cols = [d.name for d in cur.description]
                    rules = [dict(zip(rr_cols, r)) for r in cur.fetchall()]
            for row in rulepacks:
                if row.get("created_at_utc") is not None:
                    row["created_at_utc"] = row["created_at_utc"].isoformat()
            for row in rules:
                if row.get("created_at_utc") is not None:
                    row["created_at_utc"] = row["created_at_utc"].isoformat()
            return {"ok": True, "rulepacks": rulepacks, "rules": rules}
        except Exception as exc:
            return {"ok": False, "error": str(exc), "rulepacks": [], "rules": []}

    def governance_check_action(self) -> None:
        """POST /governance/check-action — role + leakage governance (no job execution)."""
        data = self._read_json_body()
        dataset_id = str(data.get("dataset_id") or "").strip()
        requested_action = str(data.get("requested_action") or "").strip()
        experiment_id = str(data.get("experiment_id") or "").strip() or None
        model_version = str(data.get("model_version") or "").strip() or None
        if not dataset_id:
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "dataset_id is required."})
            return
        if not self.dataset_exists(dataset_id):
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": f"Unknown dataset_id: {dataset_id}"})
            return
        row = next(
            (r for r in read_manifest(self.manifest_path, self.hybrid_policy_path) if r.get("dataset_id") == dataset_id),
            None,
        )
        role = str(row.get("role") or "") if row else ""
        s0 = self.step0_readiness(row) if row else {"step0_ready": True}
        result: dict[str, Any]
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    checks = build_leakage_checks_from_db(cur)
                    leak_fail = any(c.get("check_status") == "fail" for c in checks)
                    result = evaluate_governance_action(
                        dataset_id=dataset_id,
                        role=role,
                        requested_action=requested_action,
                        experiment_id=experiment_id,
                        model_version=model_version,
                        cur=cur,
                        leakage_checks_failed=leak_fail,
                        step0_ready=bool(s0.get("step0_ready")),
                    )
        except Exception as exc:
            self.send_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"ok": False, "error": f"governance_check_unavailable:{exc}", "allowed": False},
            )
            return
        if not result.get("allowed"):
            try:
                write_audit_event(
                    event_type=GOVERNANCE_BLOCKED_ACTION,
                    actor="phase4-dash-api",
                    artifact_refs=[],
                    context={
                        "requested_action": requested_action,
                        "reason": result.get("reason"),
                        "source": "governance_check_action",
                    },
                    dataset_id=dataset_id,
                    experiment_id=experiment_id,
                    model_version=model_version,
                )
            except Exception:
                pass
        self.send_json(HTTPStatus.OK, {"ok": True, **result})

    def dataset_exists(self, dataset_id: str) -> bool:
        return any(item.get("dataset_id") == dataset_id for item in read_manifest(self.manifest_path, self.hybrid_policy_path))

    def request_stage(self, stage: str, query: str) -> None:
        params = parse_qs(query, keep_blank_values=False)
        dataset_id = params.get("dataset_id", [""])[0]
        if not dataset_id:
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "dataset_id is required."})
            return
        if not self.dataset_exists(dataset_id):
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": f"Unknown dataset_id: {dataset_id}"})
            return

        row = next(
            (r for r in read_manifest(self.manifest_path, self.hybrid_policy_path) if r.get("dataset_id") == dataset_id),
            None,
        )
        role = str(row.get("role") or "") if row else ""
        s0_ingest = self.step0_readiness(row) if row else {"step0_ready": True}

        if stage == "ingest":
            mode = ingest_workflow_mode(dataset_id, role)
            if mode == "forbidden":
                self.send_json(
                    HTTPStatus.FORBIDDEN,
                    {
                        "ok": False,
                        "error": "REF-01 (NSL-KDD) is reference-only: it must not enter normalization, splits, or replay pipelines.",
                        "ingest_workflow_mode": mode,
                    },
                )
                return
            requested = (
                ACTION_QUEUE_REPLAY_INVENTORY if mode == "replay_inventory" else ACTION_QUEUE_SUPERVISED_PIPELINE
            )
            try:
                with connect() as conn:
                    with conn.cursor() as cur:
                        checks = build_leakage_checks_from_db(cur)
                        leak_fail = any(c.get("check_status") == "fail" for c in checks)
                        result = evaluate_governance_action(
                            dataset_id=dataset_id,
                            role=role,
                            requested_action=requested,
                            experiment_id="exp_dashboard",
                            model_version=None,
                            cur=cur,
                            leakage_checks_failed=leak_fail,
                            step0_ready=bool(s0_ingest.get("step0_ready")),
                        )
            except Exception as exc:
                self.send_json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"ok": False, "error": f"governance_gate_unavailable:{exc}"},
                )
                return
            if not result.get("allowed"):
                try:
                    write_audit_event(
                        event_type=GOVERNANCE_BLOCKED_ACTION,
                        actor="phase4-dash-api",
                        artifact_refs=[],
                        context={
                            "requested_action": requested,
                            "reason": result.get("reason"),
                            "source": "workflow_ingest",
                        },
                        dataset_id=dataset_id,
                        experiment_id="exp_dashboard",
                    )
                except Exception:
                    pass
                self.send_json(
                    HTTPStatus.FORBIDDEN,
                    {"ok": False, "error": result.get("reason"), "governance": result},
                )
                return

        runtime_state = self._latest_runtime_state("step1")
        state = default_state()
        if runtime_state and isinstance(runtime_state.get("state_payload"), dict):
            payload_state = runtime_state.get("state_payload") or {}
            state.update({k: v for k, v in payload_state.items() if k != "stages"})
            if isinstance(payload_state.get("stages"), list):
                state["stages"] = payload_state["stages"]
        request_id = str(uuid.uuid4())
        request = {
            "request_id": request_id,
            "stage": stage,
            "dataset_id": dataset_id,
            "requested_at_utc": utc_now(),
            "requested_by": "dashboard",
        }
        try:
            create_workflow_request(
                request_id=request_id,
                step_name="step1",
                stage_name=stage,
                workflow_id="model_v1_step1_dataset_processing",
                dataset_id=dataset_id,
                requested_by="dashboard",
                status="queued",
                request_payload=request,
            )
        except Exception:
            pass
        atomic_write_json(self.control_dir / f"{stage}_requested__{dataset_id}.json", request)

        for item in state["stages"]:
            if item["id"] == stage:
                item["status"] = "queued"
            if stage == "ingest" and item["id"] in {"normalise", "categorise", "split", "postgres"}:
                item["status"] = "queued"
        state.update(
            {
                "phase": f"{stage}_requested",
                "active_dataset_id": dataset_id,
                "updated_at_utc": utc_now(),
                f"{stage}_request_id": request_id,
            }
        )
        try:
            upsert_workflow_runtime_state(
                step_name="step1",
                workflow_id="model_v1_step1_dataset_processing",
                current_phase=f"{stage}_requested",
                phase_status="queued",
                status="queued",
                source="dashboard_api",
                state_payload=state,
            )
        except Exception:
            pass
        atomic_write_json(self.state_path, state)
        self.send_json(HTTPStatus.ACCEPTED, {"ok": True, "state": state, "request": request})

    def start_ingestion(self) -> None:
        payload = self.status_payload()
        state = payload["state"]
        if state.get("phase") != "download":
            self.send_json(HTTPStatus.CONFLICT, {"ok": False, "error": "Ingestion already requested or started."})
            return

        request_id = str(uuid.uuid4())
        request = {
            "request_id": request_id,
            "requested_at_utc": utc_now(),
            "requested_by": "dashboard",
            "required_uploads": [row for row in payload["uploads"] if row["required"]],
        }
        try:
            create_workflow_request(
                request_id=request_id,
                step_name="step1",
                stage_name="ingestion",
                workflow_id="model_v1_step1_dataset_processing",
                requested_by="dashboard",
                status="queued",
                request_payload=request,
            )
        except Exception:
            pass
        atomic_write_json(self.control_dir / "ingestion_requested.json", request)

        for stage in state["stages"]:
            if stage["id"] == "download":
                stage["status"] = "complete"
            elif stage["id"] == "ingestion":
                stage["status"] = "queued"

        state.update(
            {
                "phase": "ingestion_requested",
                "download_phase_visible": False,
                "ingestion_request_id": request_id,
                "ingestion_started_at_utc": utc_now(),
                "updated_at_utc": utc_now(),
            }
        )
        try:
            upsert_workflow_runtime_state(
                step_name="step1",
                workflow_id="model_v1_step1_dataset_processing",
                current_phase="ingestion_requested",
                phase_status="queued",
                status="queued",
                source="dashboard_api",
                state_payload=state,
            )
        except Exception:
            pass
        atomic_write_json(self.state_path, state)
        self.send_json(HTTPStatus.ACCEPTED, {"ok": True, "state": state})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Phase 4 dashboard API")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--hybrid-policy", type=Path, required=True)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--state-path", type=Path, required=True)
    parser.add_argument("--control-dir", type=Path, required=True)
    parser.add_argument("--required-datasets", default=os.getenv("DASH_REQUIRED_DATASETS", ""))
    parser.add_argument(
        "--experiment-design",
        type=Path,
        default=None,
        help="Path to experiment_design_v1.json (defaults to <repo>/configs/experiment_design_v1.json).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.control_dir.mkdir(parents=True, exist_ok=True)
    args.state_path.parent.mkdir(parents=True, exist_ok=True)
    reconcile_on_start = str(os.getenv("PROJECT_WORKFLOW_RECONCILE_ON_START", "1")).strip().lower() not in {
        "0",
        "false",
        "no",
    }
    if reconcile_on_start:
        try:
            reconciliation = reconcile_orphaned_workflow_runs(
                reason="dash_api_startup_reconcile",
                limit=int(os.getenv("PROJECT_WORKFLOW_RECONCILE_LIMIT", "200")),
            )
            print(f"[dash-api] workflow run reconciliation: {json.dumps(reconciliation)}", flush=True)
        except Exception as exc:
            print(f"[dash-api] workflow run reconciliation skipped: {exc}", flush=True)
    experiment_design_path = args.experiment_design
    if experiment_design_path is None:
        experiment_design_path = REPO_ROOT / "configs" / "experiment_design_v1.json"

    server = ThreadingHTTPServer((args.host, args.port), DashHandler)
    server.manifest_path = args.manifest  # type: ignore[attr-defined]
    server.hybrid_policy_path = args.hybrid_policy  # type: ignore[attr-defined]
    server.data_root = args.data_root  # type: ignore[attr-defined]
    server.state_path = args.state_path  # type: ignore[attr-defined]
    server.control_dir = args.control_dir  # type: ignore[attr-defined]
    server.required_override = args.required_datasets  # type: ignore[attr-defined]
    server.experiment_design_path = experiment_design_path  # type: ignore[attr-defined]

    print(f"[dash-api] listening on {args.host}:{args.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
