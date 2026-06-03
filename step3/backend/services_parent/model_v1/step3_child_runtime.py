"""In-process Child listener (UDP client port) and management (HTTP) servers for Step 3 simulation.

Traffic enters only via the client listener port. Parent-facing health and status are exposed
only on the management port. This mirrors the two-port design used in Docker network isolation.
"""

from __future__ import annotations

import json
import os
import socket
import socketserver
import ssl
import threading
import uuid
from urllib.error import URLError
from urllib.request import Request, urlopen
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import BaseRequestHandler, UDPServer
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _recent_rule_match_export_limit() -> int:
    raw = str(os.getenv("STEP3_RECENT_RULE_MATCH_EXPORT_LIMIT", "20000")).strip()
    try:
        return max(100, min(int(raw), 200000))
    except Exception:
        return 20000


@dataclass
class ChildRuntimeStats:
    child_id: str
    client_listener_port: int
    management_port: int
    received_packets: int = 0
    rule_match_count: int = 0
    alert_count: int = 0
    escalation_count: int = 0
    file_received_counts: dict[str, int] = field(default_factory=dict)
    file_rule_match_counts: dict[str, int] = field(default_factory=dict)
    file_attack_packet_counts: dict[str, int] = field(default_factory=dict)
    file_benign_packet_counts: dict[str, int] = field(default_factory=dict)
    file_alert_counts: dict[str, int] = field(default_factory=dict)
    file_escalation_counts: dict[str, int] = field(default_factory=dict)
    rule_hits_by_family: dict[str, int] = field(default_factory=dict)
    recent_rule_matches: list[dict[str, Any]] = field(default_factory=list)
    last_event: dict[str, Any] = field(default_factory=dict)
    health: str = "unknown"
    parent_ack_pending: int = 0
    metric_source: str = "in_process_runtime"
    measurement_type: str = "simulated"
    mtls_enabled: bool = False
    mtls_ready: bool = False
    mtls_error: str | None = None
    rule_sync_status: str = "unsynced"
    active_rule_count: int = 0
    packet_feature_extraction_active: bool = False
    window_aggregator_active: bool = False
    rule_evaluation_pipeline_active: bool = False
    configured_window_sizes_s: list[int] = field(default_factory=lambda: [1, 5, 30])
    rulepack_version: str | None = None


class ThreadingUDPServer(socketserver.ThreadingMixIn, UDPServer):
    daemon_threads = True
    allow_reuse_address = True


class _ChildUDPHandler(BaseRequestHandler):
    def handle(self) -> None:
        data, _sock = self.request
        server = self.server
        rt = getattr(server, "child_runtime", None)
        if rt is not None:
            rt._handle_udp(data)


@dataclass
class ChildRuntime:
    child_id: str
    child_type: str
    client_listener_port: int
    management_port: int
    stats: ChildRuntimeStats = field(init=False)
    _udp: ThreadingUDPServer | None = field(default=None, repr=False)
    _udp_thread: threading.Thread | None = field(default=None, repr=False)
    _http: ThreadingHTTPServer | None = field(default=None, repr=False)
    _http_thread: threading.Thread | None = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    execution_mode: str = "simulation"
    assigned_rules: list[dict[str, Any]] = field(default_factory=list, repr=False)
    tls_certfile: str | None = None
    tls_keyfile: str | None = None
    tls_ca_file: str | None = None
    tls_require_client_cert: bool = False

    def __post_init__(self) -> None:
        self.stats = ChildRuntimeStats(
            child_id=self.child_id,
            client_listener_port=self.client_listener_port,
            management_port=int(self.management_port),
        )

    def _handle_udp(self, data: bytes) -> None:
        try:
            payload = json.loads(data.decode("utf-8"))
        except Exception:
            payload = {"raw_len": len(data)}
        hits = 0
        if isinstance(payload, dict):
            for row in self.assigned_rules:
                if not isinstance(row, dict):
                    continue
                cond = row.get("condition")
                if not isinstance(cond, dict):
                    cond = row.get("condition_json")
                if not isinstance(cond, dict):
                    continue
                if self._rule_condition_matches(cond, payload):
                    hits += 1
        with self._lock:
            self.stats.received_packets += 1
            self.stats.last_event = payload
            self.stats.rule_match_count += int(hits)
            if hits > 0:
                self.stats.alert_count += 1
            if hits > 1:
                self.stats.escalation_count += 1
            self.stats.health = "healthy"
            if self.stats.escalation_count > 0 and self.stats.received_packets % 5 == 0:
                self.stats.parent_ack_pending += 1

    def _rule_condition_matches(self, condition: dict[str, Any], event: dict[str, Any]) -> bool:
        if not isinstance(condition, dict) or not condition:
            return False
        all_conditions = condition.get("all")
        if isinstance(all_conditions, list):
            return all(self._rule_condition_matches(c, event) for c in all_conditions if isinstance(c, dict))
        any_conditions = condition.get("any")
        if isinstance(any_conditions, list):
            return any(self._rule_condition_matches(c, event) for c in any_conditions if isinstance(c, dict))
        feature = str(condition.get("feature") or condition.get("field") or "").strip()
        op = str(condition.get("op") or condition.get("operator") or "eq").strip().lower()
        expected = condition.get("value", condition.get("equals"))
        if not feature:
            return False
        actual = event.get(feature)
        if op in {"eq", "=="}:
            return actual == expected
        if op in {"neq", "!="}:
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
        if op == "contains":
            return str(expected) in str(actual)
        if op == "in" and isinstance(expected, list):
            return actual in expected
        return False

    def update_rules(self, rules: list[dict[str, Any]], *, rulepack_version: str | None = None) -> None:
        with self._lock:
            self.assigned_rules = list(rules)
            self.stats.active_rule_count = len(self.assigned_rules)
            self.stats.rule_sync_status = "ready" if self.assigned_rules else "no_rules"
            self.stats.rulepack_version = str(rulepack_version or "").strip() or None

    def start(self) -> tuple[bool, str | None]:
        if self._udp is not None:
            return True, None
        try:
            class _H(BaseHTTPRequestHandler):
                outer_local: ChildRuntime

                def log_message(self, fmt: str, *args: Any) -> None:  # noqa: ARG002
                    return

                def _send_json(self, code: int, body: dict[str, Any]) -> None:
                    raw = json.dumps(body).encode("utf-8")
                    self.send_response(code)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)

                def do_GET(self) -> None:  # noqa: N802
                    c = self.outer_local
                    if self.path.startswith("/health"):
                        self._send_json(
                            200,
                            {
                                "ok": True,
                                "child_id": c.child_id,
                                "health": c.stats.health,
                                "client_listener_port": c.client_listener_port,
                                "management_port": c.stats.management_port,
                            },
                        )
                        return
                    if self.path.startswith("/listener-status"):
                        self._send_json(
                            200,
                            {
                                "ok": True,
                                "child_id": c.child_id,
                                "listener_port": c.client_listener_port,
                                "received_packets": c.stats.received_packets,
                                "rule_match_count": c.stats.rule_match_count,
                                "alert_count": c.stats.alert_count,
                                "escalation_count": c.stats.escalation_count,
                            },
                        )
                        return
                    if self.path.startswith("/management-status"):
                        self._send_json(
                            200,
                            {
                                "ok": True,
                                "child_id": c.child_id,
                                "management_port": c.stats.management_port,
                                "parent_ack_pending": c.stats.parent_ack_pending,
                                "health": c.stats.health,
                                "mtls_enabled": c.stats.mtls_enabled,
                                "mtls_ready": c.stats.mtls_ready,
                                "mtls_error": c.stats.mtls_error,
                                "rule_sync_status": c.stats.rule_sync_status,
                                "active_rule_count": c.stats.active_rule_count,
                                "rulepack_version": c.stats.rulepack_version,
                            },
                        )
                        return
                    self._send_json(404, {"ok": False, "error": "not_found"})

            class Handler(_H):
                outer_local = self

            self._udp = ThreadingUDPServer(("0.0.0.0", self.client_listener_port), _ChildUDPHandler)
            setattr(self._udp, "child_runtime", self)
            self._udp_thread = threading.Thread(target=self._udp.serve_forever, name=f"udp-{self.child_id}", daemon=True)
            self._udp_thread.start()

            self._http = ThreadingHTTPServer(("0.0.0.0", int(self.management_port)), Handler)
            if self.tls_certfile and self.tls_keyfile:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(certfile=self.tls_certfile, keyfile=self.tls_keyfile)
                if self.tls_require_client_cert:
                    if self.tls_ca_file:
                        ctx.load_verify_locations(cafile=self.tls_ca_file)
                    ctx.verify_mode = ssl.CERT_REQUIRED
                else:
                    ctx.verify_mode = ssl.CERT_NONE
                self._http.socket = ctx.wrap_socket(self._http.socket, server_side=True)
                self.stats.mtls_enabled = True
                self.stats.mtls_ready = True
                self.stats.mtls_error = None
            else:
                self.stats.mtls_enabled = False
                self.stats.mtls_ready = False
                self.stats.mtls_error = None
            self._http_thread = threading.Thread(target=self._http.serve_forever, name=f"mgmt-{self.child_id}", daemon=True)
            self._http_thread.start()
            self.stats.health = "healthy"
            return True, None
        except ssl.SSLError as exc:
            self.stats.mtls_enabled = True
            self.stats.mtls_ready = False
            self.stats.mtls_error = str(exc)
            return False, f"mtls_ssl_error:{exc}"
        except OSError as exc:
            return False, str(exc)
        except Exception as exc:
            return False, str(exc)

    def stop(self) -> None:
        if self._udp:
            try:
                self._udp.shutdown()
            except Exception:
                pass
            try:
                self._udp.server_close()
            except Exception:
                pass
        self._udp = None
        self._udp_thread = None
        if self._http:
            try:
                self._http.shutdown()
            except Exception:
                pass
            try:
                self._http.server_close()
            except Exception:
                pass
        self._http = None
        self._http_thread = None
        self.stats.health = "stopped"


# Global registry (one dashboard API process).
_LOCK = threading.Lock()
_RUNTIMES: dict[str, ChildRuntime] = {}
_REMOTE_MGMT_ENDPOINTS: dict[str, dict[str, Any]] = {}


def _http_json(url: str, *, method: str = "GET", payload: dict[str, Any] | None = None, timeout: float = 2.5) -> dict[str, Any] | None:
    body = json.dumps(payload or {}).encode("utf-8") if payload is not None else None
    req = Request(url, data=body, method=method.upper())
    req.add_header("Accept", "application/json")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            obj = json.loads(raw)
            return obj if isinstance(obj, dict) else None
    except (URLError, OSError, ValueError, TimeoutError):
        return None


def register_remote_runtime(child_id: str, management_port: int, host: str | None = None) -> None:
    with _LOCK:
        _REMOTE_MGMT_ENDPOINTS[child_id] = {
            "host": str(host or "").strip() or None,
            "port": int(management_port),
        }


def unregister_remote_runtime(child_id: str) -> None:
    with _LOCK:
        _REMOTE_MGMT_ENDPOINTS.pop(child_id, None)


def get_or_create_runtime(
    child_id: str,
    *,
    child_type: str,
    client_listener_port: int,
    management_port: int,
    execution_mode: str = "simulation",
    tls_certfile: str | None = None,
    tls_keyfile: str | None = None,
    tls_ca_file: str | None = None,
    tls_require_client_cert: bool = False,
) -> ChildRuntime:
    with _LOCK:
        r = _RUNTIMES.get(child_id)
        if r is None:
            r = ChildRuntime(child_id, child_type, client_listener_port, management_port)
            r.execution_mode = execution_mode
            r.stats.measurement_type = "simulated" if execution_mode == "simulation" else "observed"
            _RUNTIMES[child_id] = r
        else:
            r.execution_mode = execution_mode
            r.stats.measurement_type = "simulated" if execution_mode == "simulation" else "observed"
        r.tls_certfile = tls_certfile
        r.tls_keyfile = tls_keyfile
        r.tls_ca_file = tls_ca_file
        r.tls_require_client_cert = tls_require_client_cert
        return r


def start_child_runtime(
    child_id: str,
    *,
    child_type: str,
    client_listener_port: int,
    management_port: int,
    execution_mode: str = "simulation",
    tls_certfile: str | None = None,
    tls_keyfile: str | None = None,
    tls_ca_file: str | None = None,
    tls_require_client_cert: bool = False,
) -> dict[str, Any]:
    rt = get_or_create_runtime(
        child_id,
        child_type=child_type,
        client_listener_port=client_listener_port,
        management_port=management_port,
        execution_mode=execution_mode,
        tls_certfile=tls_certfile,
        tls_keyfile=tls_keyfile,
        tls_ca_file=tls_ca_file,
        tls_require_client_cert=tls_require_client_cert,
    )
    ok, err = rt.start()
    return {"ok": ok, "child_id": child_id, "error": err}


def stop_child_runtime(child_id: str) -> dict[str, Any]:
    with _LOCK:
        r = _RUNTIMES.pop(child_id, None)
        _REMOTE_MGMT_ENDPOINTS.pop(child_id, None)
    if r:
        r.stop()
        return {"ok": True, "child_id": child_id}
    return {"ok": True, "child_id": child_id, "message": "not_running"}


def runtime_stats(child_id: str) -> ChildRuntimeStats | None:
    with _LOCK:
        endpoint = _REMOTE_MGMT_ENDPOINTS.get(child_id) or {}
        r = _RUNTIMES.get(child_id)
    mgmt_port = int(endpoint.get("port") or 0)
    if mgmt_port > 0:
        host_candidates: list[str] = []
        endpoint_host = str(endpoint.get("host") or "").strip()
        if endpoint_host:
            host_candidates.append(endpoint_host)
        host_candidates.append(child_id)
        host_candidates.append("127.0.0.1")
        dedup_hosts: list[str] = []
        for h in host_candidates:
            if h and h not in dedup_hosts:
                dedup_hosts.append(h)
        listener: dict[str, Any] | None = None
        mgmt: dict[str, Any] | None = None
        for host in dedup_hosts:
            l = _http_json(f"http://{host}:{mgmt_port}/listener-status")
            m = _http_json(f"http://{host}:{mgmt_port}/management-status")
            if isinstance(l, dict) and isinstance(m, dict):
                listener = l
                mgmt = m
                break
        if isinstance(listener, dict) and isinstance(mgmt, dict):
            file_received_counts = listener.get("file_received_counts")
            if not isinstance(file_received_counts, dict):
                file_received_counts = {}
            file_alert_counts = listener.get("file_alert_counts")
            if not isinstance(file_alert_counts, dict):
                file_alert_counts = {}
            file_escalation_counts = listener.get("file_escalation_counts")
            if not isinstance(file_escalation_counts, dict):
                file_escalation_counts = {}
            file_rule_match_counts = listener.get("file_rule_match_counts")
            if not isinstance(file_rule_match_counts, dict):
                file_rule_match_counts = {}
            file_attack_packet_counts = listener.get("file_attack_packet_counts")
            if not isinstance(file_attack_packet_counts, dict):
                file_attack_packet_counts = {}
            file_benign_packet_counts = listener.get("file_benign_packet_counts")
            if not isinstance(file_benign_packet_counts, dict):
                file_benign_packet_counts = {}
            rule_hits_by_family = listener.get("rule_hits_by_family")
            if not isinstance(rule_hits_by_family, dict):
                rule_hits_by_family = mgmt.get("rule_hits_by_family")
            if not isinstance(rule_hits_by_family, dict):
                rule_hits_by_family = {}
            recent_rule_matches = mgmt.get("recent_rule_matches")
            if not isinstance(recent_rule_matches, list):
                recent_rule_matches = listener.get("recent_rule_matches")
            if not isinstance(recent_rule_matches, list):
                recent_rule_matches = []
            configured_window_sizes_s = mgmt.get("configured_window_sizes_s")
            if not isinstance(configured_window_sizes_s, list):
                configured_window_sizes_s = listener.get("configured_window_sizes_s")
            if not isinstance(configured_window_sizes_s, list):
                configured_window_sizes_s = [1, 5, 30]
            win_sizes = [int(x) for x in configured_window_sizes_s if isinstance(x, (int, float, str)) and str(x).strip().isdigit()]
            if not win_sizes:
                win_sizes = [1, 5, 30]
            return ChildRuntimeStats(
                child_id=child_id,
                client_listener_port=int(listener.get("listener_port") or 0),
                management_port=int(mgmt_port),
                received_packets=int(listener.get("received_packets") or 0),
                rule_match_count=int(listener.get("rule_match_count") or 0),
                alert_count=int(listener.get("alert_count") or 0),
                escalation_count=int(listener.get("escalation_count") or 0),
                file_received_counts={str(k): int(v or 0) for k, v in file_received_counts.items()},
                file_rule_match_counts={str(k): int(v or 0) for k, v in file_rule_match_counts.items()},
                file_attack_packet_counts={str(k): int(v or 0) for k, v in file_attack_packet_counts.items()},
                file_benign_packet_counts={str(k): int(v or 0) for k, v in file_benign_packet_counts.items()},
                file_alert_counts={str(k): int(v or 0) for k, v in file_alert_counts.items()},
                file_escalation_counts={str(k): int(v or 0) for k, v in file_escalation_counts.items()},
                rule_hits_by_family={str(k): int(v or 0) for k, v in rule_hits_by_family.items()},
                recent_rule_matches=[row for row in recent_rule_matches if isinstance(row, dict)][-_recent_rule_match_export_limit():],
                health=str(mgmt.get("health") or "unknown"),
                parent_ack_pending=int(mgmt.get("parent_ack_pending") or 0),
                metric_source="docker_child_runtime",
                measurement_type="observed",
                mtls_enabled=bool(mgmt.get("mtls_enabled")),
                mtls_ready=bool(mgmt.get("mtls_ready")),
                mtls_error=str(mgmt.get("mtls_error")) if mgmt.get("mtls_error") else None,
                rule_sync_status=str(mgmt.get("rule_sync_status") or "unknown"),
                active_rule_count=int(mgmt.get("active_rule_count") or 0),
                rulepack_version=str(mgmt.get("rulepack_version") or "").strip() or None,
                packet_feature_extraction_active=bool(
                    mgmt.get("packet_feature_extraction_active", listener.get("packet_feature_extraction_active"))
                ),
                window_aggregator_active=bool(mgmt.get("window_aggregator_active", listener.get("window_aggregator_active"))),
                rule_evaluation_pipeline_active=bool(
                    mgmt.get("rule_evaluation_pipeline_active", listener.get("rule_evaluation_pipeline_active"))
                ),
                configured_window_sizes_s=win_sizes,
            )
    if r:
        return r.stats
    return None


def runtime_set_rules(child_id: str, rules: list[dict[str, Any]], *, rulepack_version: str | None = None) -> bool:
    with _LOCK:
        r = _RUNTIMES.get(child_id)
        endpoint = _REMOTE_MGMT_ENDPOINTS.get(child_id) or {}
    mgmt_port = int(endpoint.get("port") or 0)
    payload: dict[str, Any] = {"rules": rules}
    if rulepack_version:
        payload["rulepack_version"] = str(rulepack_version)
    if mgmt_port > 0:
        host_candidates: list[str] = []
        endpoint_host = str(endpoint.get("host") or "").strip()
        if endpoint_host:
            host_candidates.append(endpoint_host)
        host_candidates.append(child_id)
        host_candidates.append("127.0.0.1")
        for host in host_candidates:
            if not host:
                continue
            resp = _http_json(
                f"http://{host}:{mgmt_port}/rules/sync",
                method="POST",
                payload=payload,
                timeout=4.0,
            )
            if bool(isinstance(resp, dict) and resp.get("ok")):
                return True
    if r:
        r.update_rules(rules, rulepack_version=rulepack_version)
        return True
    return False


def simulation_process_state() -> dict[str, Any]:
    """Lightweight in-process Simulation Stack state (no Parent network attachment)."""
    with _LOCK:
        ssid = getattr(simulation_process_state, "_simulation_session_id", None)
        rid = getattr(simulation_process_state, "_replay_run_id", None)
        return {
            "active_children": list(_RUNTIMES.keys()),
            "simulation_session_id": ssid,
            "replay_run_id": rid,
            "session_id": ssid,
            "running": getattr(simulation_process_state, "_running", False),
        }


def simulation_set_running(
    running: bool,
    *,
    simulation_session_id: str | None = None,
    replay_run_id: str | None = None,
) -> None:
    simulation_process_state._running = running  # type: ignore[attr-defined]
    if not running:
        simulation_process_state._simulation_session_id = None  # type: ignore[attr-defined]
        simulation_process_state._replay_run_id = None  # type: ignore[attr-defined]
    else:
        simulation_process_state._simulation_session_id = simulation_session_id  # type: ignore[attr-defined]
        simulation_process_state._replay_run_id = replay_run_id  # type: ignore[attr-defined]


def push_udp_to_child(host: str, port: int, payload: bytes) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(payload, (host, port))
        sock.close()
        return True
    except OSError:
        return False


def new_event_id() -> str:
    return str(uuid.uuid4())
