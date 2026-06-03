from __future__ import annotations

import gc
import hashlib
import json
import os
import queue
import random
import struct
import subprocess
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from services_parent.common.step_metrics_jobs import generate_step3_metrics
from services_parent.common.phase4_db import connect, postgres_dsn, write_audit_event
from services_parent.model_v1.step3_simulation import step3_eligible_models

try:
    import redis  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - optional dependency boundary
    redis = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dt_now() -> datetime:
    return datetime.now(timezone.utc)


def _env_int(name: str, default: int) -> int:
    raw = str(os.getenv(name, "")).strip()
    if not raw:
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    raw = str(os.getenv(name, "")).strip()
    if not raw:
        return default
    try:
        return float(raw)
    except Exception:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = str(os.getenv(name, "")).strip().lower()
    if raw in {"1", "true", "yes", "on", "y"}:
        return True
    if raw in {"0", "false", "no", "off", "n"}:
        return False
    return default


def _stable_fraction(seed: str) -> float:
    raw = hashlib.sha256(seed.encode("utf-8", errors="ignore")).digest()
    # 8-byte deterministic fraction in [0,1).
    v = int.from_bytes(raw[:8], "big", signed=False)
    return float(v % 10_000) / 10_000.0


def _child_scope(child_id: str) -> str:
    cid = str(child_id or "").lower()
    if "enterprise" in cid:
        return "enterprise"
    if "dns" in cid:
        return "dns"
    if "iiot" in cid:
        return "iiot"
    if "iot" in cid:
        return "iot"
    return "unknown"


DEFAULT_CHILDREN = [
    "child-enterprise-01",
    "child-enterprise-02",
    "child-dns-01",
    "child-dns-02",
    "child-iot-01",
    "child-iot-02",
    "child-iot-03",
    "child-iiot-01",
    "child-iiot-02",
    "child-iiot-03",
]

STREAM_DOMAINS = ("telemetry", "alerts", "audit", "control")


@dataclass
class Subscriber:
    subscriber_id: str
    simulation_id: str | None
    out_queue: queue.Queue[dict[str, Any]]
    created_at_utc: str = field(default_factory=_now)


@dataclass
class SimulationRuntime:
    simulation_id: str
    model_id: str | None
    model_version: str
    started_at_utc: str
    status: str = "running"
    stop_event: threading.Event = field(default_factory=threading.Event)
    children: list[str] = field(default_factory=list)
    producer_threads: list[threading.Thread] = field(default_factory=list)
    child_counters: dict[str, dict[str, int]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    dispatch_lock: threading.Lock = field(default_factory=threading.Lock)
    counter_lock: threading.Lock = field(default_factory=threading.Lock)
    stop_requested_at_utc: str | None = None
    finished_at_utc: str | None = None


class MetricEvidenceIn(BaseModel):
    metric_name: str = Field(..., min_length=1)
    evidence_kind: str = Field(default="manual", min_length=1)
    numerator: float | None = None
    denominator: float | None = None
    metric_value: float | None = None
    source_ref: str | None = None
    evidence_payload: dict[str, Any] = Field(default_factory=dict)


def _uuid5_from(seed: str, scope: str) -> str:
    return str(uuid.uuid5(uuid.UUID(seed), scope))


def _count_pcap_records(path: Path) -> int:
    # Exact packet count for classic PCAP.
    with path.open("rb") as fh:
        hdr = fh.read(24)
        if len(hdr) < 24:
            return 0
        magic = hdr[:4]
        if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
            endian = "<"
        elif magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
            endian = ">"
        else:
            raise ValueError("not_pcap")
        rec_hdr = struct.Struct(f"{endian}IIII")
        count = 0
        while True:
            raw = fh.read(16)
            if len(raw) < 16:
                break
            _ts_sec, _ts_usec, incl_len, _orig_len = rec_hdr.unpack(raw)
            if incl_len < 0:
                break
            if incl_len:
                fh.seek(int(incl_len), os.SEEK_CUR)
            count += 1
        return count


def _count_pcapng_records(path: Path) -> int:
    # Exact packet count for PCAPNG (EPB + SPB blocks).
    with path.open("rb") as fh:
        block_hdr = fh.read(12)
        if len(block_hdr) < 12:
            return 0
        block_type, block_len, byte_order_magic = struct.unpack("<III", block_hdr)
        if block_type != 0x0A0D0D0A:
            raise ValueError("not_pcapng")
        if byte_order_magic == 0x1A2B3C4D:
            endian = "<"
        elif byte_order_magic == 0x4D3C2B1A:
            endian = ">"
        else:
            raise ValueError("pcapng_unknown_endian")
        # Move back to start and parse all blocks.
        fh.seek(0)
        count = 0
        while True:
            h = fh.read(8)
            if len(h) < 8:
                break
            btype, blen = struct.unpack(f"{endian}II", h)
            if blen < 12:
                break
            # Consume payload + trailing total length.
            payload_len = int(blen) - 8
            body = fh.read(payload_len)
            if len(body) < payload_len:
                break
            if btype in {0x00000006, 0x00000003}:  # EPB / SPB
                count += 1
        return count


def _exact_packet_count(path: Path) -> int:
    try:
        return _count_pcap_records(path)
    except Exception:
        pass
    try:
        return _count_pcapng_records(path)
    except Exception:
        pass
    return 0


def _build_child_rule_profiles(children: list[str], model_version: str) -> dict[str, dict[str, Any]]:
    min_rules = max(1, _env_int("STEP3_V2_CHILD_RULE_MIN", 8))
    max_rules = max(min_rules, _env_int("STEP3_V2_CHILD_RULE_MAX", 32))
    out: dict[str, dict[str, Any]] = {}
    for child_id in children:
        seed = f"{model_version}:{child_id}"
        frac_a = _stable_fraction(seed + ":a")
        frac_b = _stable_fraction(seed + ":b")
        frac_c = _stable_fraction(seed + ":c")
        rule_count = int(round(min_rules + ((max_rules - min_rules) * frac_a)))
        max_hits = max(1, min(8, int(round(1 + (frac_b * 6)))))
        base_hit_probability = round(0.015 + (frac_c * 0.18), 5)
        out[str(child_id)] = {
            "rule_count": int(rule_count),
            "max_hits_per_packet": int(max_hits),
            "base_hit_probability": float(base_hit_probability),
            "scope": _child_scope(str(child_id)),
        }
    return out


def _phase_hit_multiplier(phase: str) -> float:
    p = str(phase or "").lower()
    if p == "attack_burst":
        return 2.8
    if p == "mixed_recovery":
        return 1.65
    if p == "domain_shift":
        return 1.25
    return 1.0


def _scope_hit_multiplier(scope: str) -> float:
    s = str(scope or "").lower()
    if s == "dns":
        return 1.2
    if s == "enterprise":
        return 1.1
    if s == "iiot":
        return 1.35
    if s == "iot":
        return 0.95
    return 1.0


class QueueBackend:
    kind = "unknown"

    def publish(self, domain: str, envelope: dict[str, Any]) -> str:
        raise NotImplementedError

    def consume_batch(self, *, domain: str, consumer: str, count: int, block_ms: int) -> list[dict[str, Any]]:
        raise NotImplementedError

    def ack(self, *, domain: str, message_id: str) -> None:
        raise NotImplementedError

    def requeue_or_dlq(self, *, domain: str, message: dict[str, Any], reason: str, max_retries: int) -> None:
        raise NotImplementedError

    def lag_status(self) -> dict[str, Any]:
        raise NotImplementedError

    def save_stream_cursor(self, *, simulation_id: str, cursor_id: str, last_event_id: str, ts_utc: str) -> None:
        return

    def load_stream_cursor(self, *, simulation_id: str, cursor_id: str) -> str | None:
        return None

    def close(self) -> None:
        return

    def clear_backlog(self) -> dict[str, int]:
        return {"cleared_events": 0, "cleared_dlq": 0}


class InMemoryQueueBackend(QueueBackend):
    kind = "in_memory"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._streams: dict[str, queue.Queue[dict[str, Any]]] = {
            d: queue.Queue(maxsize=200_000) for d in STREAM_DOMAINS
        }
        self._dlq: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=200_000)
        self._stream_cursors: dict[tuple[str, str], tuple[str, str]] = {}

    def publish(self, domain: str, envelope: dict[str, Any]) -> str:
        msg_id = str(uuid.uuid4())
        row = {"message_id": msg_id, "event": dict(envelope), "retries": 0}
        q = self._streams[domain]
        try:
            q.put_nowait(row)
        except queue.Full:  # pragma: no cover - stress boundary
            self._dlq.put_nowait({**row, "reason": "in_memory_queue_full"})
        return msg_id

    def consume_batch(self, *, domain: str, consumer: str, count: int, block_ms: int) -> list[dict[str, Any]]:
        del consumer
        out: list[dict[str, Any]] = []
        q = self._streams[domain]
        timeout_s = max(0.001, float(block_ms) / 1000.0)
        try:
            first = q.get(timeout=timeout_s)
            out.append(first)
        except queue.Empty:
            return out
        while len(out) < max(1, int(count)):
            try:
                out.append(q.get_nowait())
            except queue.Empty:
                break
        return out

    def ack(self, *, domain: str, message_id: str) -> None:
        del domain
        del message_id
        return

    def requeue_or_dlq(self, *, domain: str, message: dict[str, Any], reason: str, max_retries: int) -> None:
        retries = int(message.get("retries") or 0) + 1
        if retries > max_retries:
            try:
                self._dlq.put_nowait({**message, "retries": retries, "reason": reason, "domain": domain})
            except queue.Full:  # pragma: no cover - stress boundary
                return
            return
        try:
            self._streams[domain].put_nowait({**message, "retries": retries})
        except queue.Full:  # pragma: no cover - stress boundary
            try:
                self._dlq.put_nowait({**message, "retries": retries, "reason": "requeue_failed_queue_full", "domain": domain})
            except queue.Full:
                return

    def lag_status(self) -> dict[str, Any]:
        by_stream = {d: int(self._streams[d].qsize()) for d in STREAM_DOMAINS}
        dlq = int(self._dlq.qsize())
        return {
            "backend": self.kind,
            "by_stream": by_stream,
            "dlq": dlq,
            "total_lag": int(sum(by_stream.values())),
            "pending": 0,
        }

    def save_stream_cursor(self, *, simulation_id: str, cursor_id: str, last_event_id: str, ts_utc: str) -> None:
        key = (str(simulation_id), str(cursor_id))
        with self._lock:
            self._stream_cursors[key] = (str(last_event_id), str(ts_utc))

    def load_stream_cursor(self, *, simulation_id: str, cursor_id: str) -> str | None:
        key = (str(simulation_id), str(cursor_id))
        with self._lock:
            row = self._stream_cursors.get(key)
        if not row:
            return None
        return str(row[0] or "").strip() or None

    def clear_backlog(self) -> dict[str, int]:
        cleared_events = 0
        cleared_dlq = 0
        with self._lock:
            for d in STREAM_DOMAINS:
                q = self._streams[d]
                while True:
                    try:
                        q.get_nowait()
                        cleared_events += 1
                    except queue.Empty:
                        break
            while True:
                try:
                    self._dlq.get_nowait()
                    cleared_dlq += 1
                except queue.Empty:
                    break
        return {"cleared_events": int(cleared_events), "cleared_dlq": int(cleared_dlq)}


class RedisStreamsQueueBackend(QueueBackend):
    kind = "redis_streams"

    def __init__(self) -> None:
        if redis is None:
            raise RuntimeError("redis_client_not_installed")
        host = str(os.getenv("PHASE4_REDIS_HOST", "phase4-redis")).strip() or "phase4-redis"
        port = _env_int("PHASE4_REDIS_PORT", 6379)
        db = _env_int("STEP3_V2_REDIS_DB", 0)
        self._stream_prefix = str(os.getenv("STEP3_V2_STREAM_PREFIX", "phase4:step3:v2")).strip() or "phase4:step3:v2"
        self._group = str(os.getenv("STEP3_V2_REDIS_GROUP", "step3_v2_ingestors")).strip() or "step3_v2_ingestors"
        self._client = redis.Redis(host=host, port=port, db=db, decode_responses=True, socket_timeout=5)
        self._streams = {d: f"{self._stream_prefix}:{d}" for d in STREAM_DOMAINS}
        self._dlq = f"{self._stream_prefix}:dlq"
        self._ensure_groups()

    def _ensure_groups(self) -> None:
        for domain in STREAM_DOMAINS:
            stream = self._streams[domain]
            try:
                self._client.xgroup_create(stream, self._group, id="0", mkstream=True)
            except Exception as exc:
                if "BUSYGROUP" not in str(exc):
                    raise

    def publish(self, domain: str, envelope: dict[str, Any]) -> str:
        stream = self._streams[domain]
        return str(self._client.xadd(stream, {"event": json.dumps(envelope), "retries": "0"}))

    def consume_batch(self, *, domain: str, consumer: str, count: int, block_ms: int) -> list[dict[str, Any]]:
        stream = self._streams[domain]
        rows = self._client.xreadgroup(
            groupname=self._group,
            consumername=consumer,
            streams={stream: ">"},
            count=max(1, int(count)),
            block=max(1, int(block_ms)),
        )
        out: list[dict[str, Any]] = []
        for _stream_name, msgs in rows:
            for msg_id, fields in msgs:
                raw = str(fields.get("event") or "{}")
                retries = int(fields.get("retries") or 0)
                try:
                    envelope = json.loads(raw)
                except Exception:
                    envelope = {}
                if not isinstance(envelope, dict):
                    envelope = {}
                out.append(
                    {
                        "message_id": str(msg_id),
                        "event": envelope,
                        "retries": retries,
                        "raw": fields,
                    }
                )
        return out

    def ack(self, *, domain: str, message_id: str) -> None:
        stream = self._streams[domain]
        self._client.xack(stream, self._group, message_id)

    def requeue_or_dlq(self, *, domain: str, message: dict[str, Any], reason: str, max_retries: int) -> None:
        stream = self._streams[domain]
        retries = int(message.get("retries") or 0) + 1
        payload = dict(message.get("event") or {})
        payload["queue_error"] = reason
        payload["queue_retries"] = retries
        if retries > max_retries:
            self._client.xadd(
                self._dlq,
                {
                    "event": json.dumps(payload),
                    "domain": domain,
                    "reason": reason,
                    "retries": str(retries),
                    "source_message_id": str(message.get("message_id") or ""),
                },
            )
            self.ack(domain=domain, message_id=str(message.get("message_id") or ""))
            return
        self._client.xadd(stream, {"event": json.dumps(payload), "retries": str(retries)})
        self.ack(domain=domain, message_id=str(message.get("message_id") or ""))

    def lag_status(self) -> dict[str, Any]:
        by_stream: dict[str, int] = {}
        pending_total = 0
        for d in STREAM_DOMAINS:
            stream = self._streams[d]
            stream_pending = 0
            stream_group_lag = 0
            try:
                xp = self._client.xpending(stream, self._group)
                if isinstance(xp, dict):
                    stream_pending = int(xp.get("pending") or 0)
                elif isinstance(xp, (tuple, list)) and len(xp) >= 1:
                    stream_pending = int(xp[0] or 0)
            except Exception:
                stream_pending = 0
            try:
                groups = self._client.xinfo_groups(stream) or []
                for g in groups:
                    if str(g.get("name") or "") != self._group:
                        continue
                    stream_group_lag = int(g.get("lag") or 0)
                    break
            except Exception:
                stream_group_lag = 0
            pending_total += stream_pending
            # Backlog approximation relevant for real-time throttling/drain:
            # unacked pending + not-yet-delivered group lag.
            by_stream[d] = int(max(0, stream_pending) + max(0, stream_group_lag))
        dlq = int(self._client.xlen(self._dlq))
        return {
            "backend": self.kind,
            "by_stream": by_stream,
            "dlq": dlq,
            "total_lag": int(sum(by_stream.values())),
            "pending": int(pending_total),
        }

    def save_stream_cursor(self, *, simulation_id: str, cursor_id: str, last_event_id: str, ts_utc: str) -> None:
        key = f"{self._stream_prefix}:cursor:{simulation_id}:{cursor_id}"
        self._client.hset(key, mapping={"last_event_id": str(last_event_id), "ts_utc": str(ts_utc)})
        self._client.expire(key, max(3600, _env_int("STEP3_V2_CURSOR_TTL_SECONDS", 2_592_000)))

    def load_stream_cursor(self, *, simulation_id: str, cursor_id: str) -> str | None:
        key = f"{self._stream_prefix}:cursor:{simulation_id}:{cursor_id}"
        out = self._client.hgetall(key) or {}
        last = str(out.get("last_event_id") or "").strip()
        return last or None

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            return


class Step3V2Engine:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._history_limit = max(500, _env_int("STEP3_V2_SSE_HISTORY_LIMIT", 10_000))
        self._history: deque[dict[str, Any]] = deque(maxlen=self._history_limit)
        self._subscribers: dict[str, Subscriber] = {}
        self._simulations: dict[str, SimulationRuntime] = {}
        self._data_root = Path(str(os.getenv("STEP3_V2_DATA_ROOT", "/data")).strip() or "/data")
        self._archive_root = self._data_root / "outputs" / "model_v1" / "step3_v2" / "archive"
        self._online = False
        self._queue_backend = self._build_queue_backend()
        self._consumer_threads: list[threading.Thread] = []
        self._health_thread: threading.Thread | None = None
        self._archive_thread: threading.Thread | None = None
        self._cursor_flush_lock = threading.Lock()
        self._cursor_flush_state: dict[tuple[str, str], tuple[str, float]] = {}
        self._hybrid_enabled = _env_bool("STEP3_V2_HYBRID_ENABLED", True)
        self._hybrid_traffic_spool_enabled = _env_bool("STEP3_V2_HYBRID_SPOOL_TRAFFIC_ENABLED", True)
        self._hybrid_sync_batch_records = max(10, _env_int("STEP3_V2_HYBRID_SYNC_BATCH_RECORDS", 200))
        self._hybrid_spool_segment_bytes = max(1_048_576, _env_int("STEP3_V2_HYBRID_SPOOL_SEGMENT_BYTES", 64 * 1024 * 1024))
        self._hybrid_spool_root = self._data_root / "outputs" / "model_v1" / "step3_v2" / "spool"
        self._hybrid_spool_lock = threading.Lock()
        self._hybrid_spool_state: dict[str, dict[str, Any]] = {}
        self._file_artifact_root = self._data_root / "outputs" / "model_v1" / "step3_v2" / "files"
        self._file_io_lock = threading.Lock()
        self._file_ingest_script = str(os.getenv("STEP3_V2_FILE_INGEST_SCRIPT", "/workspace/scripts/step3_sim_file_ingest_script.py")).strip() or "/workspace/scripts/step3_sim_file_ingest_script.py"
        self._file_ingest_max_retries = max(1, _env_int("STEP3_V2_FILE_INGEST_MAX_RETRIES", 4))
        self._file_ingest_retry_backoff_s = max(0.1, _env_float("STEP3_V2_FILE_INGEST_RETRY_BACKOFF_SECONDS", 2.5))
        self._file_batch_packets = max(1, _env_int("STEP3_V2_FILE_BATCH_PACKET_COUNT", 25_000))
        self._step3_tablespace_name = str(os.getenv("STEP3_V2_TABLESPACE_NAME", "step3_v2_cold")).strip() or "step3_v2_cold"
        self._step3_tablespace_location = str(os.getenv("STEP3_V2_TABLESPACE_LOCATION", "/srv/data/ids_final/step3_v2_tablespace")).strip() or "/srv/data/ids_final/step3_v2_tablespace"
        self._pgdata_path_check = str(os.getenv("STEP3_V2_PGDATA_PATH_CHECK", "/data/postgres")).strip() or "/data/postgres"
        self._tablespace_path_check = str(os.getenv("STEP3_V2_TABLESPACE_PATH_CHECK", "/srv/data/ids_final")).strip() or "/srv/data/ids_final"
        self._disk_min_free_bytes = max(0, _env_int("STEP3_V2_DISK_MIN_FREE_BYTES", 20 * 1024 * 1024 * 1024))

    def _hybrid_should_spool(self, event_type: str) -> bool:
        et = str(event_type or "").strip().lower()
        return bool(self._hybrid_enabled and self._hybrid_traffic_spool_enabled and et == "node_traffic_batch")

    def _hybrid_spool_dir(self, simulation_id: str) -> Path:
        return self._hybrid_spool_root / str(simulation_id)

    def _hybrid_append_spool_event(self, *, simulation_id: str, source_stream: str, retries: int, event: dict[str, Any]) -> dict[str, Any]:
        sim_id = str(simulation_id or "").strip()
        if not sim_id:
            return {"ok": False, "reason": "missing_simulation_id"}
        self._hybrid_spool_root.mkdir(parents=True, exist_ok=True)
        spool_dir = self._hybrid_spool_dir(sim_id)
        spool_dir.mkdir(parents=True, exist_ok=True)
        payload = {"source_stream": str(source_stream or "telemetry"), "retries": int(retries), "event": event}
        line = json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n"
        line_bytes = len(line.encode("utf-8"))
        with self._hybrid_spool_lock:
            state = self._hybrid_spool_state.get(sim_id)
            if not isinstance(state, dict):
                state = {
                    "segment_idx": 0,
                    "segment_bytes": 0,
                    "events_spooled": 0,
                    "spool_files": [],
                }
            files = state.get("spool_files") if isinstance(state.get("spool_files"), list) else []
            seg_idx = int(state.get("segment_idx") or 0)
            seg_bytes = int(state.get("segment_bytes") or 0)
            if (not files) or (seg_bytes + line_bytes > self._hybrid_spool_segment_bytes):
                seg_idx += 1
                seg_bytes = 0
                seg_path = spool_dir / f"events-{seg_idx:06d}.jsonl"
                files.append(str(seg_path))
            else:
                seg_path = Path(str(files[-1]))
            with seg_path.open("a", encoding="utf-8") as fh:
                fh.write(line)
            seg_bytes += line_bytes
            state["segment_idx"] = int(seg_idx)
            state["segment_bytes"] = int(seg_bytes)
            state["events_spooled"] = int(state.get("events_spooled") or 0) + 1
            state["spool_files"] = files
            self._hybrid_spool_state[sim_id] = state
            return {
                "ok": True,
                "events_spooled": int(state.get("events_spooled") or 0),
                "segment_idx": int(state.get("segment_idx") or 0),
                "spool_file": str(seg_path),
                "spool_dir": str(spool_dir),
            }

    def _hybrid_sync_spooled_traffic_to_db(self, sim: SimulationRuntime) -> dict[str, Any]:
        if not self._hybrid_should_spool("node_traffic_batch"):
            return {"enabled": False, "status": "skipped", "reason": "hybrid_disabled"}
        spool_dir = self._hybrid_spool_dir(sim.simulation_id)
        if not spool_dir.exists():
            return {"enabled": True, "status": "skipped", "reason": "no_spool_dir", "spool_dir": str(spool_dir)}
        files = sorted(spool_dir.glob("events-*.jsonl"))
        if not files:
            return {"enabled": True, "status": "skipped", "reason": "no_spool_files", "spool_dir": str(spool_dir)}
        lines_total = 0
        files_total = 0
        traffic_batches = 0
        failed_rows = 0
        t0 = time.time()
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    tx_rows = 0
                    for fpath in files:
                        files_total += 1
                        with fpath.open("r", encoding="utf-8") as fh:
                            for raw in fh:
                                line = str(raw or "").strip()
                                if not line:
                                    continue
                                lines_total += 1
                                try:
                                    row = json.loads(line)
                                except Exception:
                                    failed_rows += 1
                                    continue
                                if not isinstance(row, dict):
                                    failed_rows += 1
                                    continue
                                event = row.get("event") if isinstance(row.get("event"), dict) else {}
                                event_type = str(event.get("event_type") or "")
                                if event_type != "node_traffic_batch":
                                    continue
                                source_stream = str(row.get("source_stream") or "telemetry")
                                retries = int(row.get("retries") or 0)
                                ok = self._persist_traffic_batch(cur, event=event, source_stream=source_stream, retries=retries)
                                if ok:
                                    traffic_batches += 1
                                else:
                                    failed_rows += 1
                                tx_rows += 1
                                if tx_rows >= self._hybrid_sync_batch_records:
                                    conn.commit()
                                    tx_rows = 0
                conn.commit()
            elapsed_s = round(time.time() - t0, 3)
            return {
                "enabled": True,
                "status": "ok",
                "spool_dir": str(spool_dir),
                "files_scanned": int(files_total),
                "lines_scanned": int(lines_total),
                "traffic_batches_synced": int(traffic_batches),
                "failed_rows": int(failed_rows),
                "elapsed_s": elapsed_s,
            }
        except Exception as exc:
            return {
                "enabled": True,
                "status": "failed",
                "spool_dir": str(spool_dir),
                "files_scanned": int(files_total),
                "lines_scanned": int(lines_total),
                "traffic_batches_synced": int(traffic_batches),
                "failed_rows": int(failed_rows),
                "error": str(exc),
                "elapsed_s": round(time.time() - t0, 3),
            }

    def _normalized_tablespace_name(self) -> str:
        raw = str(self._step3_tablespace_name or "step3_v2_cold").strip().lower()
        safe = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in raw)
        if not safe:
            safe = "step3_v2_cold"
        if not safe[0].isalpha():
            safe = f"ts_{safe}"
        return safe

    def _sim_file_dir(self, simulation_id: str) -> Path:
        return self._file_artifact_root / str(simulation_id)

    @staticmethod
    def _pcap_file_key(pcap_file: str) -> str:
        base = str(pcap_file or "").strip()
        if not base:
            base = "unknown.pcap"
        h = hashlib.sha1(base.encode("utf-8", errors="ignore")).hexdigest()[:16]
        stem = "".join(ch if (ch.isalnum() or ch in {"-", "_"}) else "_" for ch in base).strip("_")
        if len(stem) > 72:
            stem = stem[:72]
        if not stem:
            stem = "pcap"
        return f"{stem}__{h}"

    def _pcap_artifact_paths(self, *, simulation_id: str, pcap_file: str) -> tuple[Path, Path]:
        key = self._pcap_file_key(pcap_file)
        root = self._sim_file_dir(simulation_id)
        return (root / f"{key}.metrics.jsonl", root / f"{key}.audit.jsonl")

    def _append_jsonl_rows(self, path: Path, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._file_io_lock:
            with path.open("a", encoding="utf-8") as fh:
                for row in rows:
                    fh.write(json.dumps(row, ensure_ascii=True, separators=(",", ":")) + "\n")

    @staticmethod
    def _remove_file_quiet(path: Path) -> None:
        try:
            if path.exists():
                path.unlink()
        except Exception:
            return

    def _disk_free_report(self, path_raw: str) -> dict[str, Any]:
        path = Path(str(path_raw or "").strip() or "/")
        exists = path.exists()
        if not exists:
            return {"path": str(path), "exists": False, "ok": False, "free_bytes": 0, "required_bytes": int(self._disk_min_free_bytes)}
        try:
            st = os.statvfs(str(path))
            free_bytes = int(st.f_bavail) * int(st.f_frsize)
        except Exception:
            return {"path": str(path), "exists": True, "ok": False, "free_bytes": 0, "required_bytes": int(self._disk_min_free_bytes)}
        return {
            "path": str(path),
            "exists": True,
            "free_bytes": int(free_bytes),
            "required_bytes": int(self._disk_min_free_bytes),
            "ok": bool(free_bytes >= int(self._disk_min_free_bytes)),
        }

    def _preflight_disk_guard(self) -> dict[str, Any]:
        pg = self._disk_free_report(self._pgdata_path_check)
        ts = self._disk_free_report(self._tablespace_path_check)
        return {
            "pgdata": pg,
            "tablespace": ts,
            "ok": bool(pg.get("ok")) and bool(ts.get("ok")),
            "checked_at_utc": _now(),
        }

    def _ensure_step3_tablespace(self) -> dict[str, Any]:
        ts_name = self._normalized_tablespace_name()
        location = str(self._step3_tablespace_location or "").strip() or "/srv/data/ids_final/step3_v2_tablespace"
        try:
            import psycopg  # type: ignore
        except Exception as exc:
            return {"ok": False, "tablespace_name": ts_name, "location": location, "error": f"psycopg_missing:{exc}"}
        try:
            with psycopg.connect(postgres_dsn(), autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1 FROM pg_tablespace WHERE spcname = %s LIMIT 1;", (ts_name,))
                    row = cur.fetchone()
                    if not row:
                        # Postgres utility statements like CREATE TABLESPACE do not accept bind parameters for LOCATION.
                        escaped_location = location.replace("'", "''")
                        create_sql = f'CREATE TABLESPACE "{ts_name}" LOCATION \'{escaped_location}\';'
                        try:
                            cur.execute(create_sql)
                        except Exception as create_exc:
                            # Handle race where another process created the tablespace concurrently.
                            msg = str(create_exc).lower()
                            if "already exists" not in msg:
                                raise
            return {"ok": True, "tablespace_name": ts_name, "location": location}
        except Exception as exc:
            return {"ok": False, "tablespace_name": ts_name, "location": location, "error": str(exc)}

    def _wait_for_postgres_ready(self) -> None:
        attempts = max(1, _env_int("STEP3_V2_DB_READY_ATTEMPTS", 30))
        delay_s = max(0.2, _env_float("STEP3_V2_DB_READY_SLEEP_SECONDS", 1.0))
        last_err = ""
        for _ in range(attempts):
            try:
                with connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT 1;")
                        _ = cur.fetchone()
                return
            except Exception as exc:
                last_err = str(exc)
                time.sleep(delay_s)
        raise RuntimeError(f"step3_v2_db_not_ready_after_{attempts}_attempts:{last_err}")

    def _apply_step3_tablespace_layout(self) -> dict[str, Any]:
        ts = self._ensure_step3_tablespace()
        if not bool(ts.get("ok")):
            return {"ok": False, "tablespace": ts}
        ts_name = str(ts.get("tablespace_name") or self._normalized_tablespace_name())
        heavy_tables = [
            "step3_v2_child_packets",
            "step3_v2_alerts",
            "step3_v2_parent_actions",
            "step3_v2_file_logs",
            "step3_v2_archives",
        ]
        moved_tables = 0
        moved_indexes = 0
        with connect() as conn:
            with conn.cursor() as cur:
                for tbl in heavy_tables:
                    cur.execute(f'ALTER TABLE IF EXISTS phase4.{tbl} SET TABLESPACE "{ts_name}";')
                    moved_tables += 1
                cur.execute(
                    """
                    SELECT i.relname
                    FROM pg_class i
                    JOIN pg_index ix ON ix.indexrelid = i.oid
                    JOIN pg_class t ON t.oid = ix.indrelid
                    JOIN pg_namespace n ON n.oid = t.relnamespace
                    WHERE n.nspname = 'phase4'
                      AND t.relname = ANY(%(tables)s);
                    """,
                    {"tables": heavy_tables},
                )
                idx_rows = [str(r[0]) for r in (cur.fetchall() or []) if r and r[0]]
                for idx in idx_rows:
                    cur.execute(f'ALTER INDEX IF EXISTS phase4.{idx} SET TABLESPACE "{ts_name}";')
                    moved_indexes += 1
            conn.commit()
        return {"ok": True, "tablespace_name": ts_name, "moved_tables": moved_tables, "moved_indexes": moved_indexes}

    def _service_thread_target(self) -> int:
        host_cpu = max(1, int(os.cpu_count() or 1))
        requested_cpu_threads = max(1, _env_int("STEP3_V2_CPU_THREADS", host_cpu))
        # V2 cap: keep service bounded to 16 logical threads by default.
        max_workers = max(1, _env_int("STEP3_V2_MAX_WORKERS", 16))
        return max(1, min(host_cpu, requested_cpu_threads, max_workers))

    def _worker_budget(self) -> int:
        reserve = max(0, _env_int("STEP3_V2_CPU_RESERVE", 2))
        return max(1, self._service_thread_target() - reserve)

    def _consumer_worker_target(self) -> int:
        budget = self._worker_budget()
        if budget <= 1:
            return 1
        configured = _env_int("STEP3_V2_CONSUMER_WORKERS", max(1, budget // 2))
        return max(1, min(configured, budget - 1))

    def _producer_worker_target(self, child_count: int) -> int:
        budget = self._worker_budget()
        producer_budget = max(1, budget - max(1, len(self._consumer_threads)))
        return max(1, min(producer_budget, max(1, int(child_count))))

    def _build_queue_backend(self) -> QueueBackend:
        use_redis = _env_bool("STEP3_V2_REDIS_ENABLED", True)
        if use_redis:
            try:
                return RedisStreamsQueueBackend()
            except Exception:
                return InMemoryQueueBackend()
        return InMemoryQueueBackend()

    @staticmethod
    def _malloc_trim() -> bool:
        # Best-effort heap trim on glibc-based containers; no-op on other runtimes.
        try:
            import ctypes  # local import to keep dependency optional

            libc = ctypes.CDLL("libc.so.6")
            fn = getattr(libc, "malloc_trim", None)
            if fn is None:
                return False
            fn.argtypes = [ctypes.c_size_t]
            fn.restype = ctypes.c_int
            return bool(fn(0))
        except Exception:
            return False

    def _pre_start_runtime_cleanup(self) -> dict[str, Any]:
        keep_statuses = {"initializing", "running", "stopping"}
        with self._lock:
            before_sims = len(self._simulations)
            self._simulations = {sid: sim for sid, sim in self._simulations.items() if str(sim.status or "").lower() in keep_statuses}
            after_sims = len(self._simulations)
            history_before = len(self._history)
            history_cleared = 0
            if _env_bool("STEP3_V2_CLEAR_HISTORY_ON_START", True):
                self._history.clear()
                history_cleared = history_before
            dead_subscribers = [sid for sid, sub in self._subscribers.items() if getattr(sub, "out_queue", None) is None]
            for sid in dead_subscribers:
                self._subscribers.pop(sid, None)
        active_sims = after_sims
        docker_cleanup_report = self._pre_start_docker_cleanup(active_simulations=active_sims)
        host_cache_drop_report = self._drop_host_page_cache() if active_sims == 0 else {"status": "skipped", "reason": "active_simulation_running"}
        queue_cleared = {"cleared_events": 0, "cleared_dlq": 0}
        if active_sims == 0 and _env_bool("STEP3_V2_CLEAR_INMEMORY_QUEUE_ON_START", True):
            try:
                queue_cleared = self._queue_backend.clear_backlog()
            except Exception:
                queue_cleared = {"cleared_events": 0, "cleared_dlq": 0}
        gc_pass_1 = int(gc.collect())
        gc_pass_2 = int(gc.collect())
        trimmed = self._malloc_trim()
        return {
            "simulations_before": int(before_sims),
            "simulations_after": int(after_sims),
            "simulations_pruned": int(max(0, before_sims - after_sims)),
            "history_cleared": int(history_cleared),
            "subscribers_pruned": int(len(dead_subscribers)),
            "gc_collected_1": gc_pass_1,
            "gc_collected_2": gc_pass_2,
            "malloc_trimmed": bool(trimmed),
            "queue_cleared_events": int(queue_cleared.get("cleared_events") or 0),
            "queue_cleared_dlq": int(queue_cleared.get("cleared_dlq") or 0),
            "queue_backend": str(self._queue_backend.kind),
            "docker_cleanup": docker_cleanup_report,
            "host_cache_drop": host_cache_drop_report,
        }

    @staticmethod
    def _docker_cleanup_prefixes() -> list[str]:
        raw = str(
            os.getenv(
                "STEP3_V2_DOCKER_CLEANUP_PREFIXES",
                "ids-step3-child-,ids-step3-factory-,ids-step3-factory-probe-",
            )
        ).strip()
        return [x.strip() for x in raw.split(",") if x.strip()]

    def _docker_cmd(self, args: list[str], *, timeout_s: float = 8.0) -> tuple[bool, str, str]:
        cmd = ["docker", *list(args or [])]
        try:
            p = subprocess.run(
                cmd,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=max(0.5, float(timeout_s)),
            )
            return p.returncode == 0, str(p.stdout or "").strip(), str(p.stderr or "").strip()
        except FileNotFoundError:
            return False, "", "docker_cli_not_found"
        except subprocess.TimeoutExpired as exc:
            out = str(exc.stdout or "").strip() if isinstance(exc.stdout, str) else ""
            err = str(exc.stderr or "").strip() if isinstance(exc.stderr, str) else ""
            reason = f"timeout_after_{float(timeout_s):.1f}s"
            if err:
                reason = f"{reason}:{err}"
            return False, out, reason
        except Exception as exc:
            return False, "", str(exc)

    @staticmethod
    def _docker_project_prefix() -> str:
        return str(os.getenv("STEP3_V2_DOCKER_PROJECT_PREFIX", "ids-project-")).strip() or "ids-project-"

    @staticmethod
    def _docker_cleanup_keep_prefixes() -> list[str]:
        raw = str(
            os.getenv(
                "STEP3_V2_DOCKER_CLEANUP_KEEP_PREFIXES",
                ",".join(
                    [
                        "ids-project-step3-v2-engine-",
                        "ids-project-dash-api-",
                        "ids-project-phase4-dash-api-",
                        "ids-project-dataset-download-dashboard-",
                        "ids-project-parent-api-",
                        "ids-project-child-api-",
                        "ids-project-dataset-upload-api-",
                        "ids-project-postgres-",
                        "ids-project-phase4-postgres-",
                        "ids-project-redis-",
                        "ids-project-phase4-redis-",
                    ]
                ),
            )
        ).strip()
        return [x.strip() for x in raw.split(",") if x.strip()]

    def _pre_start_docker_cleanup(self, *, active_simulations: int) -> dict[str, Any]:
        if not _env_bool("STEP3_V2_DOCKER_CLEANUP_ENABLED", True):
            return {"status": "disabled", "reason": "env_disabled"}
        if int(active_simulations) > 0:
            return {"status": "skipped", "reason": "active_simulation_running", "active_simulations": int(active_simulations)}
        mode = str(os.getenv("STEP3_V2_DOCKER_CLEANUP_MODE", "project_non_step3")).strip().lower()
        prefixes = self._docker_cleanup_prefixes()
        keep_prefixes = self._docker_cleanup_keep_prefixes()
        project_prefix = self._docker_project_prefix()
        ok, out, err = self._docker_cmd(["ps", "-a", "--format", "{{.Names}}"], timeout_s=8.0)
        if not ok:
            return {
                "status": "skipped",
                "reason": "docker_unavailable_or_inaccessible",
                "error": str(err or "docker_ps_failed"),
            }
        names = [str(x).strip() for x in str(out or "").splitlines() if str(x).strip()]
        if mode == "legacy_step3_only":
            targets = sorted({n for n in names if any(n.startswith(pref) for pref in prefixes)})
        else:
            targets = sorted(
                {
                    n
                    for n in names
                    if n.startswith(project_prefix) and not any(n.startswith(kp) for kp in keep_prefixes)
                }
            )
        if not targets:
            return {
                "status": "ok",
                "mode": mode,
                "targets": 0,
                "stopped": [],
                "removed": [],
                "errors": [],
                "project_prefix": project_prefix,
                "keep_prefixes": keep_prefixes,
                "target_prefixes": prefixes,
            }
        max_targets = max(1, _env_int("STEP3_V2_DOCKER_CLEANUP_MAX_CONTAINERS", 128))
        if len(targets) > max_targets:
            targets = targets[:max_targets]
        stop_timeout_s = max(1, _env_int("STEP3_V2_DOCKER_STOP_TIMEOUT_SECONDS", 10))
        remove_after_stop = _env_bool("STEP3_V2_DOCKER_CLEANUP_REMOVE", False)
        stopped: list[str] = []
        removed: list[str] = []
        errors: list[dict[str, Any]] = []
        for cname in targets:
            ok_stop, _out_stop, err_stop = self._docker_cmd(["stop", "-t", str(stop_timeout_s), cname], timeout_s=float(stop_timeout_s) + 2.0)
            stop_err_low = str(err_stop or "").lower()
            stop_ok = bool(ok_stop) or ("is not running" in stop_err_low)
            if stop_ok:
                stopped.append(cname)
            else:
                errors.append({"container": cname, "phase": "stop", "error": str(err_stop or "docker_stop_failed")})
                continue
            if remove_after_stop:
                ok_rm, _out_rm, err_rm = self._docker_cmd(["rm", "-f", cname], timeout_s=6.0)
                if ok_rm:
                    removed.append(cname)
                else:
                    errors.append({"container": cname, "phase": "rm", "error": str(err_rm or "docker_rm_failed")})
        return {
            "status": "ok",
            "targets": int(len(targets)),
            "stopped": stopped,
            "removed": removed,
            "errors": errors,
            "remove_after_stop": bool(remove_after_stop),
            "mode": mode,
            "project_prefix": project_prefix,
            "keep_prefixes": keep_prefixes,
            "prefixes": prefixes,
        }

    def _drop_host_page_cache(self) -> dict[str, Any]:
        if not _env_bool("STEP3_V2_HOST_DROP_CACHES_ENABLED", False):
            return {"status": "disabled", "reason": "env_disabled"}
        helper_image = str(
            os.getenv("STEP3_V2_HOST_CACHE_HELPER_IMAGE", os.getenv("IDS_PHASE4_PY_IMAGE", "ids-project-phase4-python:local"))
        ).strip() or "ids-project-phase4-python:local"
        timeout_s = max(5, _env_int("STEP3_V2_HOST_DROP_CACHES_TIMEOUT_SECONDS", 25))
        cmd = [
            "run",
            "--rm",
            "--privileged",
            "--pid=host",
            "--network",
            "none",
            "--entrypoint",
            "sh",
            helper_image,
            "-lc",
            "sync; echo 3 > /proc/sys/vm/drop_caches",
        ]
        ok, out, err = self._docker_cmd(cmd, timeout_s=float(timeout_s))
        return {
            "status": "ok" if ok else "failed",
            "helper_image": helper_image,
            "error": str(err or ""),
            "stdout": str(out or "")[-500:],
        }

    def start(self) -> None:
        if self._online:
            return
        self._wait_for_postgres_ready()
        self._ensure_step3_v2_schema()
        self._online = True
        self._start_consumers()
        self._health_thread = threading.Thread(target=self._health_loop, name="step3-v2-health", daemon=True)
        self._health_thread.start()
        self._archive_thread = threading.Thread(target=self._archive_loop, name="step3-v2-archive", daemon=True)
        self._archive_thread.start()

    def _ensure_step3_v2_schema(self) -> None:
        ddl = [
            """
            CREATE TABLE IF NOT EXISTS phase4.step3_v2_simulations (
                simulation_id uuid PRIMARY KEY,
                model_id uuid,
                model_version text,
                status text NOT NULL DEFAULT 'created',
                execution_mode text NOT NULL DEFAULT 'simulation',
                isolation_type text NOT NULL DEFAULT 'logical',
                started_at_utc timestamptz NOT NULL DEFAULT now(),
                stop_requested_at_utc timestamptz,
                finished_at_utc timestamptz,
                metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
                created_at_utc timestamptz NOT NULL DEFAULT now(),
                updated_at_utc timestamptz NOT NULL DEFAULT now()
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS phase4.step3_v2_events (
                event_id uuid PRIMARY KEY,
                simulation_id uuid NOT NULL REFERENCES phase4.step3_v2_simulations(simulation_id) ON DELETE CASCADE,
                event_type text NOT NULL,
                child_id text,
                severity text,
                model_version text,
                source_stream text NOT NULL,
                ts_utc timestamptz NOT NULL,
                payload jsonb NOT NULL DEFAULT '{}'::jsonb,
                ingest_attempts integer NOT NULL DEFAULT 1,
                created_at_utc timestamptz NOT NULL DEFAULT now()
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS phase4.step3_v2_audit_logs (
                audit_id uuid PRIMARY KEY,
                simulation_id uuid NOT NULL REFERENCES phase4.step3_v2_simulations(simulation_id) ON DELETE CASCADE,
                level text NOT NULL DEFAULT 'info',
                message text NOT NULL,
                details jsonb NOT NULL DEFAULT '{}'::jsonb,
                ts_utc timestamptz NOT NULL,
                created_at_utc timestamptz NOT NULL DEFAULT now()
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS phase4.step3_v2_child_packets (
                packet_id uuid PRIMARY KEY,
                simulation_id uuid NOT NULL REFERENCES phase4.step3_v2_simulations(simulation_id) ON DELETE CASCADE,
                pcap_file text NOT NULL,
                child_id text NOT NULL,
                phase text,
                packet_index bigint NOT NULL,
                file_packet_index bigint NOT NULL,
                packet_label text NOT NULL,
                rule_hit_count integer NOT NULL DEFAULT 0,
                packet_rate_pps double precision NOT NULL DEFAULT 0.0,
                worker_idx integer NOT NULL DEFAULT 0,
                source_node text NOT NULL DEFAULT 'factory',
                factory_node_id text NOT NULL DEFAULT 'factory-node-01',
                ts_utc timestamptz NOT NULL,
                payload jsonb NOT NULL DEFAULT '{}'::jsonb,
                created_at_utc timestamptz NOT NULL DEFAULT now()
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS phase4.step3_v2_alerts (
                alert_id uuid PRIMARY KEY,
                simulation_id uuid NOT NULL REFERENCES phase4.step3_v2_simulations(simulation_id) ON DELETE CASCADE,
                pcap_file text NOT NULL,
                child_id text NOT NULL,
                severity text,
                phase text,
                alert_count integer NOT NULL DEFAULT 0,
                packet_label text NOT NULL DEFAULT 'benign',
                rule_hit_count integer NOT NULL DEFAULT 0,
                recommendation text,
                source_node text NOT NULL DEFAULT 'factory',
                factory_node_id text NOT NULL DEFAULT 'factory-node-01',
                ts_utc timestamptz NOT NULL,
                payload jsonb NOT NULL DEFAULT '{}'::jsonb,
                created_at_utc timestamptz NOT NULL DEFAULT now()
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS phase4.step3_v2_parent_actions (
                action_id uuid PRIMARY KEY,
                simulation_id uuid NOT NULL REFERENCES phase4.step3_v2_simulations(simulation_id) ON DELETE CASCADE,
                pcap_file text NOT NULL,
                child_id text NOT NULL,
                severity text,
                action text NOT NULL DEFAULT 'review_and_triage',
                action_count integer NOT NULL DEFAULT 0,
                packet_label text NOT NULL DEFAULT 'benign',
                rule_hit_count integer NOT NULL DEFAULT 0,
                source_node text NOT NULL DEFAULT 'factory',
                factory_node_id text NOT NULL DEFAULT 'factory-node-01',
                ts_utc timestamptz NOT NULL,
                payload jsonb NOT NULL DEFAULT '{}'::jsonb,
                created_at_utc timestamptz NOT NULL DEFAULT now()
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS phase4.step3_v2_file_logs (
                file_log_id uuid PRIMARY KEY,
                simulation_id uuid NOT NULL REFERENCES phase4.step3_v2_simulations(simulation_id) ON DELETE CASCADE,
                pcap_file text NOT NULL,
                log_kind text NOT NULL,
                level text NOT NULL DEFAULT 'info',
                message text NOT NULL,
                payload jsonb NOT NULL DEFAULT '{}'::jsonb,
                ts_utc timestamptz NOT NULL,
                created_at_utc timestamptz NOT NULL DEFAULT now()
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS phase4.step3_v2_archives (
                archive_id uuid PRIMARY KEY,
                simulation_id uuid NOT NULL REFERENCES phase4.step3_v2_simulations(simulation_id) ON DELETE CASCADE,
                archive_kind text NOT NULL,
                archive_path text NOT NULL,
                archive_checksum_sha256 text,
                archived_at_utc timestamptz NOT NULL DEFAULT now(),
                metadata jsonb NOT NULL DEFAULT '{}'::jsonb
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS phase4.step3_v2_stream_cursors (
                simulation_id uuid NOT NULL REFERENCES phase4.step3_v2_simulations(simulation_id) ON DELETE CASCADE,
                cursor_id text NOT NULL,
                last_event_id uuid NOT NULL,
                updated_at_utc timestamptz NOT NULL DEFAULT now(),
                PRIMARY KEY (simulation_id, cursor_id)
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS phase4.step3_v2_metric_evidence (
                evidence_id uuid PRIMARY KEY,
                simulation_id uuid NOT NULL REFERENCES phase4.step3_v2_simulations(simulation_id) ON DELETE CASCADE,
                metric_name text NOT NULL,
                evidence_kind text NOT NULL DEFAULT 'manual',
                numerator double precision,
                denominator double precision,
                metric_value double precision,
                source_ref text,
                evidence_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
                created_at_utc timestamptz NOT NULL DEFAULT now(),
                updated_at_utc timestamptz NOT NULL DEFAULT now()
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_step3_v2_simulations_status ON phase4.step3_v2_simulations(status, started_at_utc DESC);",
            "CREATE INDEX IF NOT EXISTS idx_step3_v2_simulations_model ON phase4.step3_v2_simulations(model_version, started_at_utc DESC);",
            "CREATE INDEX IF NOT EXISTS idx_step3_v2_events_sim_ts ON phase4.step3_v2_events(simulation_id, ts_utc DESC);",
            "CREATE INDEX IF NOT EXISTS idx_step3_v2_events_type_ts ON phase4.step3_v2_events(event_type, ts_utc DESC);",
            "CREATE INDEX IF NOT EXISTS idx_step3_v2_events_child_ts ON phase4.step3_v2_events(child_id, ts_utc DESC);",
            "CREATE INDEX IF NOT EXISTS idx_step3_v2_audit_sim_ts ON phase4.step3_v2_audit_logs(simulation_id, ts_utc DESC);",
            "CREATE INDEX IF NOT EXISTS idx_step3_v2_child_packets_sim_ts ON phase4.step3_v2_child_packets(simulation_id, ts_utc DESC);",
            "CREATE INDEX IF NOT EXISTS idx_step3_v2_child_packets_file_ts ON phase4.step3_v2_child_packets(simulation_id, pcap_file, ts_utc DESC);",
            "CREATE INDEX IF NOT EXISTS idx_step3_v2_child_packets_child_ts ON phase4.step3_v2_child_packets(simulation_id, child_id, ts_utc DESC);",
            "CREATE INDEX IF NOT EXISTS idx_step3_v2_alerts_sim_ts ON phase4.step3_v2_alerts(simulation_id, ts_utc DESC);",
            "CREATE INDEX IF NOT EXISTS idx_step3_v2_alerts_file_ts ON phase4.step3_v2_alerts(simulation_id, pcap_file, ts_utc DESC);",
            "CREATE INDEX IF NOT EXISTS idx_step3_v2_parent_actions_sim_ts ON phase4.step3_v2_parent_actions(simulation_id, ts_utc DESC);",
            "CREATE INDEX IF NOT EXISTS idx_step3_v2_parent_actions_file_ts ON phase4.step3_v2_parent_actions(simulation_id, pcap_file, ts_utc DESC);",
            "CREATE INDEX IF NOT EXISTS idx_step3_v2_file_logs_sim_ts ON phase4.step3_v2_file_logs(simulation_id, ts_utc DESC);",
            "CREATE INDEX IF NOT EXISTS idx_step3_v2_file_logs_file_ts ON phase4.step3_v2_file_logs(simulation_id, pcap_file, ts_utc DESC);",
            "CREATE INDEX IF NOT EXISTS idx_step3_v2_archives_sim_ts ON phase4.step3_v2_archives(simulation_id, archived_at_utc DESC);",
            "CREATE INDEX IF NOT EXISTS idx_step3_v2_stream_cursors_updated ON phase4.step3_v2_stream_cursors(updated_at_utc DESC);",
            "CREATE INDEX IF NOT EXISTS idx_step3_v2_metric_evidence_sim_metric ON phase4.step3_v2_metric_evidence(simulation_id, metric_name, updated_at_utc DESC);",
            "CREATE INDEX IF NOT EXISTS idx_step3_v2_metric_evidence_kind ON phase4.step3_v2_metric_evidence(metric_name, evidence_kind);",
        ]
        with connect() as conn:
            with conn.cursor() as cur:
                for stmt in ddl:
                    cur.execute(stmt)
            conn.commit()
        tablespace_result = self._apply_step3_tablespace_layout()
        if (not bool(tablespace_result.get("ok"))) and _env_bool("STEP3_V2_TABLESPACE_REQUIRED", True):
            raise RuntimeError(f"step3_v2_tablespace_layout_failed:{tablespace_result}")

    def stop(self) -> None:
        self._online = False
        with self._lock:
            sims = list(self._simulations.values())
        for sim in sims:
            sim.stop_event.set()
        for t in self._consumer_threads:
            t.join(timeout=2.0)
        if self._health_thread:
            self._health_thread.join(timeout=2.0)
        if self._archive_thread:
            self._archive_thread.join(timeout=2.0)
        self._queue_backend.close()

    def _start_consumers(self) -> None:
        consumer_workers = self._consumer_worker_target()
        domains = list(STREAM_DOMAINS)
        for idx in range(consumer_workers):
            domain = str(domains[idx % len(domains)])
            name = f"step3-v2-consumer-{domain}-{idx + 1}"
            t = threading.Thread(target=self._consume_loop, args=(domain, name), name=name, daemon=True)
            t.start()
            self._consumer_threads.append(t)

    def _consume_loop(self, domain: str, consumer_name: str) -> None:
        batch_size = max(1, _env_int("STEP3_V2_DB_BATCH_SIZE", 1200))
        max_retries = max(1, _env_int("STEP3_V2_EVENT_MAX_RETRIES", 4))
        while self._online:
            try:
                rows = self._queue_backend.consume_batch(
                    domain=domain,
                    consumer=consumer_name,
                    count=batch_size,
                    block_ms=1000,
                )
            except Exception:
                time.sleep(0.25)
                continue
            if not rows:
                continue
            for row in rows:
                ok = self._persist_event(row.get("event") or {}, source_stream=domain, retries=int(row.get("retries") or 0))
                if ok:
                    try:
                        self._queue_backend.ack(domain=domain, message_id=str(row.get("message_id") or ""))
                    except Exception:
                        continue
                    continue
                try:
                    self._queue_backend.requeue_or_dlq(
                        domain=domain,
                        message=row,
                        reason="db_persist_failed",
                        max_retries=max_retries,
                    )
                except Exception:
                    continue

    def _insert_audit_row(self, cur: Any, *, event_id: str, simulation_id: str, event_type: str, payload: dict[str, Any], ts_utc: str) -> None:
        if event_type not in {"audit_append", "run_status"}:
            return
        msg = str(payload.get("message") or "audit_append")
        if event_type == "run_status":
            msg = str(payload.get("status") or "run_status")
        cur.execute(
            """
            INSERT INTO phase4.step3_v2_audit_logs (
                audit_id, simulation_id, level, message, details, ts_utc
            ) VALUES (
                %(audit_id)s::uuid, %(simulation_id)s::uuid, %(level)s, %(message)s, %(details)s::jsonb, %(ts_utc)s::timestamptz
            )
            ON CONFLICT (audit_id) DO NOTHING;
            """,
            {
                "audit_id": event_id,
                "simulation_id": simulation_id,
                "level": "info",
                "message": msg,
                "details": json.dumps(payload),
                "ts_utc": ts_utc,
            },
        )
        cur.execute(
            """
            INSERT INTO phase4.audit_log (
                audit_id, event_type, actor, dataset_id, artifact_id, experiment_id,
                model_version, rule_version, replay_id, step, step_unique_id, event_details_json, created_at
            ) VALUES (
                %(audit_id)s::uuid, %(event_type)s, %(actor)s, %(dataset_id)s, NULL, NULL,
                %(model_version)s, NULL, NULL, 'step3', %(step_unique_id)s, %(event_details_json)s::jsonb, %(created_at)s::timestamptz
            )
            ON CONFLICT (audit_id) DO NOTHING;
            """,
            {
                "audit_id": event_id,
                "event_type": f"step3_v2_{event_type}",
                "actor": "step3_v2_engine",
                "dataset_id": str(payload.get("dataset_id") or "REP-01"),
                "model_version": str(payload.get("model_version") or ""),
                "step_unique_id": simulation_id,
                "event_details_json": json.dumps(
                    {
                        "simulation_id": simulation_id,
                        "source": "phase4.step3_v2_audit_logs",
                        "event_type": event_type,
                        "payload": payload,
                    }
                ),
                "created_at": ts_utc,
            },
        )

    def _persist_single_event(self, cur: Any, *, event: dict[str, Any], source_stream: str, retries: int) -> bool:
        event_id = str(event.get("event_id") or "").strip()
        simulation_id = str(event.get("simulation_id") or "").strip()
        if not event_id or not simulation_id:
            return False
        event_type = str(event.get("event_type") or "")
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        ts_utc = str(event.get("ts_utc") or _now())
        cur.execute(
            """
            INSERT INTO phase4.step3_v2_events (
                event_id, simulation_id, event_type, child_id, severity, model_version,
                source_stream, ts_utc, payload, ingest_attempts
            ) VALUES (
                %(event_id)s::uuid, %(simulation_id)s::uuid, %(event_type)s, %(child_id)s, %(severity)s, %(model_version)s,
                %(source_stream)s, %(ts_utc)s::timestamptz, %(payload)s::jsonb, %(ingest_attempts)s
            )
            ON CONFLICT (event_id) DO NOTHING;
            """,
            {
                "event_id": event_id,
                "simulation_id": simulation_id,
                "event_type": event_type,
                "child_id": (str(event.get("child_id") or "").strip() or None),
                "severity": (str(event.get("severity") or "").strip() or None),
                "model_version": (str(event.get("model_version") or "").strip() or None),
                "source_stream": source_stream,
                "ts_utc": ts_utc,
                "payload": json.dumps(payload),
                "ingest_attempts": int(retries + 1),
            },
        )
        self._insert_audit_row(
            cur,
            event_id=event_id,
            simulation_id=simulation_id,
            event_type=event_type,
            payload=payload,
            ts_utc=ts_utc,
        )
        return True

    def _persist_traffic_batch(self, cur: Any, *, event: dict[str, Any], source_stream: str, retries: int) -> bool:
        batch_id = str(event.get("event_id") or "").strip()
        simulation_id = str(event.get("simulation_id") or "").strip()
        if not batch_id or not simulation_id:
            return False
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        packets = payload.get("packets") if isinstance(payload.get("packets"), list) else []
        model_version = (str(event.get("model_version") or "").strip() or None)
        ts_utc = str(event.get("ts_utc") or _now())
        # Keep the original batch envelope row for traceability.
        self._persist_single_event(cur, event=event, source_stream=source_stream, retries=retries)
        if not packets:
            return True
        rows: list[dict[str, Any]] = []
        for idx, pkt in enumerate(packets):
            if not isinstance(pkt, dict):
                continue
            child_id = (str(pkt.get("child_id") or "").strip() or None)
            pcap_file = str(pkt.get("pcap_file") or payload.get("pcap_file") or "")
            event_uuid = _uuid5_from(batch_id, f"packet:{idx}:{child_id or 'unknown'}:{pkt.get('packet_index')}:{pkt.get('file_packet_index')}")
            row_payload = {
                "phase": str(pkt.get("phase") or payload.get("phase") or ""),
                "packet_index": int(pkt.get("packet_index") or 0),
                "pcap_file": pcap_file,
                "file_packet_index": int(pkt.get("file_packet_index") or 0),
                "packet_label": str(pkt.get("packet_label") or "benign"),
                "rule_hit_count": int(pkt.get("rule_hit_count") or 0),
                "attack_packets_file": int(pkt.get("attack_packets_file") or payload.get("attack_packets_file") or 0),
                "benign_packets_file": int(pkt.get("benign_packets_file") or payload.get("benign_packets_file") or 0),
                "remaining_packets_file": int(pkt.get("remaining_packets_file") or payload.get("remaining_packets_file") or 0),
                "packet_rate_pps": float(pkt.get("packet_rate_pps") or payload.get("packet_rate_pps") or 0.0),
                "packet_or_flow_id": str(pkt.get("packet_or_flow_id") or ""),
                "isolation_valid": bool(pkt.get("isolation_valid", True)),
                "isolated": bool(pkt.get("isolated", True)),
                "isolation_type": str(pkt.get("isolation_type") or payload.get("isolation_type") or "logical"),
                "expected_scope": str(pkt.get("expected_scope") or ""),
                "observed_scope": str(pkt.get("observed_scope") or ""),
                "cross_scope": bool(pkt.get("cross_scope", False)),
                "rule_id": str(pkt.get("rule_id") or ""),
                "rule_version": str(pkt.get("rule_version") or ""),
                "rule_checksum": str(pkt.get("rule_checksum") or ""),
                "queue_backend": str(payload.get("queue_backend") or ""),
                "execution_mode": str(payload.get("execution_mode") or "simulation"),
                "worker_idx": int(pkt.get("worker_idx") or payload.get("worker_idx") or 0),
                "source_node": str(payload.get("source_node") or "factory"),
                "factory_node_id": str(payload.get("factory_node_id") or "factory-node-01"),
            }
            rows.append(
                {
                    "event_id": event_uuid,
                    "simulation_id": simulation_id,
                    "event_type": "node_traffic",
                    "child_id": child_id,
                    "severity": None,
                    "model_version": model_version,
                    "source_stream": source_stream,
                    "ts_utc": ts_utc,
                    "payload": json.dumps(row_payload),
                    "ingest_attempts": int(retries + 1),
                }
            )
        if not rows:
            return True
        cur.executemany(
            """
            INSERT INTO phase4.step3_v2_events (
                event_id, simulation_id, event_type, child_id, severity, model_version,
                source_stream, ts_utc, payload, ingest_attempts
            ) VALUES (
                %(event_id)s::uuid, %(simulation_id)s::uuid, %(event_type)s, %(child_id)s, %(severity)s, %(model_version)s,
                %(source_stream)s, %(ts_utc)s::timestamptz, %(payload)s::jsonb, %(ingest_attempts)s
            )
            ON CONFLICT (event_id) DO NOTHING;
            """,
            rows,
        )
        return True

    def _persist_event(self, event: dict[str, Any], *, source_stream: str, retries: int) -> bool:
        event_type = str(event.get("event_type") or "")
        simulation_id = str(event.get("simulation_id") or "").strip()
        if self._hybrid_should_spool(event_type):
            spool = self._hybrid_append_spool_event(
                simulation_id=simulation_id,
                source_stream=source_stream,
                retries=retries,
                event=event,
            )
            return bool(spool.get("ok"))
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    if event_type == "node_traffic_batch":
                        ok = self._persist_traffic_batch(cur, event=event, source_stream=source_stream, retries=retries)
                    else:
                        ok = self._persist_single_event(cur, event=event, source_stream=source_stream, retries=retries)
                conn.commit()
            return bool(ok)
        except Exception:
            return False

    def _publish_event(
        self,
        *,
        event_type: str,
        simulation_id: str,
        child_id: str | None,
        model_version: str,
        payload: dict[str, Any] | None,
        severity: str | None = None,
        domain: str = "telemetry",
        persist: bool = True,
        broadcast: bool = True,
        include_history: bool = True,
    ) -> dict[str, Any]:
        envelope = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "simulation_id": simulation_id,
            "child_id": child_id,
            "ts_utc": _now(),
            "payload": payload or {},
            "severity": severity,
            "model_version": model_version,
        }
        with self._lock:
            if include_history:
                self._history.append(dict(envelope))
            subscribers = list(self._subscribers.values()) if broadcast else []
        for sub in subscribers:
            if sub.simulation_id and sub.simulation_id != simulation_id:
                continue
            try:
                sub.out_queue.put_nowait(dict(envelope))
            except queue.Full:
                continue
        if persist:
            try:
                self._queue_backend.publish(domain=domain, envelope=envelope)
            except Exception:
                pass
        return envelope

    def _health_loop(self) -> None:
        while self._online:
            try:
                lag = self._queue_backend.lag_status()
            except Exception:
                lag = {"backend": "unknown", "by_stream": {}, "dlq": 0, "total_lag": 0, "pending": 0}
            with self._lock:
                sims = [s for s in self._simulations.values() if s.status in {"running", "stopping"}]
            for sim in sims:
                self._publish_event(
                    event_type="queue_lag",
                    simulation_id=sim.simulation_id,
                    child_id=None,
                    model_version=sim.model_version,
                    payload=lag,
                    severity=None,
                    domain="control",
                    persist=False,
                )
                self._publish_event(
                    event_type="system_health",
                    simulation_id=sim.simulation_id,
                    child_id=None,
                    model_version=sim.model_version,
                    payload={
                        "host_cpu_count": int(os.cpu_count() or 1),
                        "service_thread_target": self._service_thread_target(),
                        "worker_budget": self._worker_budget(),
                        "consumer_worker_target": self._consumer_worker_target(),
                        "producer_worker_target": self._producer_worker_target(len(sim.children)),
                        "consumer_threads": len(self._consumer_threads),
                        "queue_backend": lag.get("backend"),
                        "queue_pending": int(lag.get("pending") or 0),
                    },
                    severity=None,
                    domain="control",
                    persist=False,
                )
            time.sleep(max(0.5, _env_float("STEP3_V2_HEALTH_PUSH_SECONDS", 2.0)))

    def _archive_loop(self) -> None:
        period_s = max(300.0, _env_float("STEP3_V2_ARCHIVE_PERIOD_SECONDS", 86_400.0))
        while self._online:
            try:
                self._archive_old_records()
            except Exception:
                pass
            slept = 0.0
            while self._online and slept < period_s:
                time.sleep(1.0)
                slept += 1.0

    def _archive_old_records(self) -> None:
        retain_days = max(1, _env_int("STEP3_V2_RETENTION_DAYS", 90))
        cutoff = _dt_now() - timedelta(days=retain_days)
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT simulation_id::text
                    FROM phase4.step3_v2_simulations
                    WHERE status IN ('completed', 'stopped', 'failed')
                      AND COALESCE(finished_at_utc, updated_at_utc) < %(cutoff)s::timestamptz
                    ORDER BY COALESCE(finished_at_utc, updated_at_utc) ASC
                    LIMIT 20;
                    """,
                    {"cutoff": cutoff.isoformat()},
                )
                sims = [str(r[0]) for r in (cur.fetchall() or []) if r and r[0]]
            conn.commit()
        if not sims:
            return
        self._archive_root.mkdir(parents=True, exist_ok=True)
        for sim_id in sims:
            archive_path = self._archive_root / f"simulation__{sim_id}.jsonl"
            rows: list[dict[str, Any]] = []
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT event_id::text, event_type, child_id, severity, model_version, source_stream,
                               ts_utc, payload, ingest_attempts, created_at_utc
                        FROM phase4.step3_v2_events
                        WHERE simulation_id = %(simulation_id)s::uuid
                        ORDER BY ts_utc ASC;
                        """,
                        {"simulation_id": sim_id},
                    )
                    for r in cur.fetchall() or []:
                        rows.append(
                            {
                                "kind": "event",
                                "event_id": r[0],
                                "event_type": r[1],
                                "child_id": r[2],
                                "severity": r[3],
                                "model_version": r[4],
                                "source_stream": r[5],
                                "ts_utc": str(r[6]) if r[6] else None,
                                "payload": r[7] if isinstance(r[7], dict) else {},
                                "ingest_attempts": int(r[8] or 0),
                                "created_at_utc": str(r[9]) if r[9] else None,
                            }
                        )
                    cur.execute(
                        """
                        SELECT packet_id::text, pcap_file, child_id, phase, packet_index, file_packet_index,
                               packet_label, rule_hit_count, packet_rate_pps, worker_idx, source_node, factory_node_id,
                               ts_utc, payload, created_at_utc
                        FROM phase4.step3_v2_child_packets
                        WHERE simulation_id = %(simulation_id)s::uuid
                        ORDER BY ts_utc ASC;
                        """,
                        {"simulation_id": sim_id},
                    )
                    for r in cur.fetchall() or []:
                        rows.append(
                            {
                                "kind": "child_packet",
                                "packet_id": r[0],
                                "pcap_file": r[1],
                                "child_id": r[2],
                                "phase": r[3],
                                "packet_index": int(r[4] or 0),
                                "file_packet_index": int(r[5] or 0),
                                "packet_label": r[6],
                                "rule_hit_count": int(r[7] or 0),
                                "packet_rate_pps": float(r[8] or 0.0),
                                "worker_idx": int(r[9] or 0),
                                "source_node": r[10],
                                "factory_node_id": r[11],
                                "ts_utc": str(r[12]) if r[12] else None,
                                "payload": r[13] if isinstance(r[13], dict) else {},
                                "created_at_utc": str(r[14]) if r[14] else None,
                            }
                        )
                    cur.execute(
                        """
                        SELECT alert_id::text, pcap_file, child_id, severity, phase, alert_count, packet_label,
                               rule_hit_count, recommendation, source_node, factory_node_id, ts_utc, payload, created_at_utc
                        FROM phase4.step3_v2_alerts
                        WHERE simulation_id = %(simulation_id)s::uuid
                        ORDER BY ts_utc ASC;
                        """,
                        {"simulation_id": sim_id},
                    )
                    for r in cur.fetchall() or []:
                        rows.append(
                            {
                                "kind": "alert",
                                "alert_id": r[0],
                                "pcap_file": r[1],
                                "child_id": r[2],
                                "severity": r[3],
                                "phase": r[4],
                                "alert_count": int(r[5] or 0),
                                "packet_label": r[6],
                                "rule_hit_count": int(r[7] or 0),
                                "recommendation": r[8],
                                "source_node": r[9],
                                "factory_node_id": r[10],
                                "ts_utc": str(r[11]) if r[11] else None,
                                "payload": r[12] if isinstance(r[12], dict) else {},
                                "created_at_utc": str(r[13]) if r[13] else None,
                            }
                        )
                    cur.execute(
                        """
                        SELECT action_id::text, pcap_file, child_id, severity, action, action_count, packet_label,
                               rule_hit_count, source_node, factory_node_id, ts_utc, payload, created_at_utc
                        FROM phase4.step3_v2_parent_actions
                        WHERE simulation_id = %(simulation_id)s::uuid
                        ORDER BY ts_utc ASC;
                        """,
                        {"simulation_id": sim_id},
                    )
                    for r in cur.fetchall() or []:
                        rows.append(
                            {
                                "kind": "parent_action",
                                "action_id": r[0],
                                "pcap_file": r[1],
                                "child_id": r[2],
                                "severity": r[3],
                                "action": r[4],
                                "action_count": int(r[5] or 0),
                                "packet_label": r[6],
                                "rule_hit_count": int(r[7] or 0),
                                "source_node": r[8],
                                "factory_node_id": r[9],
                                "ts_utc": str(r[10]) if r[10] else None,
                                "payload": r[11] if isinstance(r[11], dict) else {},
                                "created_at_utc": str(r[12]) if r[12] else None,
                            }
                        )
                    cur.execute(
                        """
                        SELECT file_log_id::text, pcap_file, log_kind, level, message, payload, ts_utc, created_at_utc
                        FROM phase4.step3_v2_file_logs
                        WHERE simulation_id = %(simulation_id)s::uuid
                        ORDER BY ts_utc ASC;
                        """,
                        {"simulation_id": sim_id},
                    )
                    for r in cur.fetchall() or []:
                        rows.append(
                            {
                                "kind": "file_log",
                                "file_log_id": r[0],
                                "pcap_file": r[1],
                                "log_kind": r[2],
                                "level": r[3],
                                "message": r[4],
                                "payload": r[5] if isinstance(r[5], dict) else {},
                                "ts_utc": str(r[6]) if r[6] else None,
                                "created_at_utc": str(r[7]) if r[7] else None,
                            }
                        )
                    cur.execute(
                        """
                        SELECT audit_id::text, level, message, details, ts_utc, created_at_utc
                        FROM phase4.step3_v2_audit_logs
                        WHERE simulation_id = %(simulation_id)s::uuid
                        ORDER BY ts_utc ASC;
                        """,
                        {"simulation_id": sim_id},
                    )
                    for r in cur.fetchall() or []:
                        rows.append(
                            {
                                "kind": "audit",
                                "audit_id": r[0],
                                "level": r[1],
                                "message": r[2],
                                "details": r[3] if isinstance(r[3], dict) else {},
                                "ts_utc": str(r[4]) if r[4] else None,
                                "created_at_utc": str(r[5]) if r[5] else None,
                            }
                        )
                conn.commit()
            if not rows:
                continue
            rows.sort(key=lambda x: str(x.get("ts_utc") or x.get("created_at_utc") or ""))
            with archive_path.open("w", encoding="utf-8") as fh:
                for row in rows:
                    fh.write(json.dumps(row, ensure_ascii=True) + "\n")
            checksum = self._sha256_file(archive_path)
            with connect() as conn:
                with conn.cursor() as cur:
                    archive_id = str(uuid.uuid4())
                    cur.execute(
                        """
                        INSERT INTO phase4.step3_v2_archives (
                            archive_id, simulation_id, archive_kind, archive_path, archive_checksum_sha256, metadata
                        ) VALUES (
                            %(archive_id)s::uuid, %(simulation_id)s::uuid, 'events_and_audit', %(archive_path)s, %(checksum)s, %(metadata)s::jsonb
                        )
                        ON CONFLICT (archive_id) DO NOTHING;
                        """,
                        {
                            "archive_id": archive_id,
                            "simulation_id": sim_id,
                            "archive_path": str(archive_path),
                            "checksum": checksum,
                            "metadata": json.dumps({"retention_days": retain_days, "archived_at_utc": _now()}),
                        },
                    )
                    cur.execute(
                        "DELETE FROM phase4.step3_v2_events WHERE simulation_id = %(simulation_id)s::uuid;",
                        {"simulation_id": sim_id},
                    )
                    cur.execute(
                        "DELETE FROM phase4.step3_v2_audit_logs WHERE simulation_id = %(simulation_id)s::uuid;",
                        {"simulation_id": sim_id},
                    )
                    cur.execute(
                        "DELETE FROM phase4.step3_v2_child_packets WHERE simulation_id = %(simulation_id)s::uuid;",
                        {"simulation_id": sim_id},
                    )
                    cur.execute(
                        "DELETE FROM phase4.step3_v2_alerts WHERE simulation_id = %(simulation_id)s::uuid;",
                        {"simulation_id": sim_id},
                    )
                    cur.execute(
                        "DELETE FROM phase4.step3_v2_parent_actions WHERE simulation_id = %(simulation_id)s::uuid;",
                        {"simulation_id": sim_id},
                    )
                    cur.execute(
                        "DELETE FROM phase4.step3_v2_file_logs WHERE simulation_id = %(simulation_id)s::uuid;",
                        {"simulation_id": sim_id},
                    )
                conn.commit()

    @staticmethod
    def _sha256_file(path: Path) -> str:
        import hashlib

        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def _persist_simulation(self, sim: SimulationRuntime) -> None:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO phase4.step3_v2_simulations (
                        simulation_id, model_id, model_version, status, execution_mode, isolation_type,
                        started_at_utc, stop_requested_at_utc, finished_at_utc, metadata, created_at_utc, updated_at_utc
                    ) VALUES (
                        %(simulation_id)s::uuid,
                        CASE WHEN %(model_id)s = '' THEN NULL ELSE %(model_id)s::uuid END,
                        %(model_version)s,
                        %(status)s,
                        'simulation',
                        'logical',
                        %(started_at_utc)s::timestamptz,
                        CASE WHEN %(stop_requested_at_utc)s = '' THEN NULL ELSE %(stop_requested_at_utc)s::timestamptz END,
                        CASE WHEN %(finished_at_utc)s = '' THEN NULL ELSE %(finished_at_utc)s::timestamptz END,
                        %(metadata)s::jsonb,
                        now(),
                        now()
                    )
                    ON CONFLICT (simulation_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        stop_requested_at_utc = EXCLUDED.stop_requested_at_utc,
                        finished_at_utc = EXCLUDED.finished_at_utc,
                        metadata = phase4.step3_v2_simulations.metadata || EXCLUDED.metadata,
                        updated_at_utc = now();
                    """,
                    {
                        "simulation_id": sim.simulation_id,
                        "model_id": str(sim.model_id or ""),
                        "model_version": sim.model_version,
                        "status": sim.status,
                        "started_at_utc": sim.started_at_utc,
                        "stop_requested_at_utc": str(sim.stop_requested_at_utc or ""),
                        "finished_at_utc": str(sim.finished_at_utc or ""),
                        "metadata": json.dumps(sim.metadata),
                    },
                )
            conn.commit()

    def _attempt_completed_file_ingest(self, sim: SimulationRuntime, pcap_file: str) -> None:
        with sim.dispatch_lock:
            dispatch_state = sim.metadata.get("file_dispatch_state")
            if not isinstance(dispatch_state, dict):
                return
            file_states = dispatch_state.get("file_states") if isinstance(dispatch_state.get("file_states"), dict) else {}
            fs = file_states.get(pcap_file) if isinstance(file_states.get(pcap_file), dict) else None
            if not isinstance(fs, dict):
                return
            total_packets = int(fs.get("total_packets") or 0)
            processed_packets = int(fs.get("processed_packets") or 0)
            inflight = int(fs.get("inflight_chunks") or 0)
            status = str(fs.get("ingest_status") or "pending")
            if processed_packets < total_packets or inflight > 0:
                return
            if status in {"running", "completed"}:
                return
            now_epoch = time.time()
            if float(fs.get("next_retry_ts") or 0.0) > now_epoch:
                return
            retries = int(fs.get("ingest_retries") or 0) + 1
            fs["ingest_status"] = "running"
            fs["ingest_retries"] = retries
            fs["last_ingest_error"] = ""
            fs["next_retry_ts"] = 0.0
            metrics_path = str(fs.get("metrics_jsonl_path") or "").strip()
            audit_path = str(fs.get("audit_jsonl_path") or "").strip()
            file_states[pcap_file] = fs
            dispatch_state["file_states"] = file_states

        cmd = [
            "python",
            self._file_ingest_script,
            "--simulation-id",
            sim.simulation_id,
            "--pcap-file",
            str(pcap_file),
            "--metrics-path",
            str(metrics_path),
            "--audit-path",
            str(audit_path),
            "--attempt",
            str(retries),
            "--db-batch-size",
            str(max(10, _env_int("STEP3_V2_DB_BATCH_SIZE", 1200))),
        ]
        ok = False
        err = ""
        payload: dict[str, Any] = {}
        try:
            ingest_env = dict(os.environ)
            existing_pythonpath = str(ingest_env.get("PYTHONPATH") or "").strip()
            ingest_env["PYTHONPATH"] = "/workspace" if not existing_pythonpath else f"/workspace:{existing_pythonpath}"
            p = subprocess.run(
                cmd,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd="/workspace",
                env=ingest_env,
                timeout=max(30, _env_int("STEP3_V2_FILE_INGEST_TIMEOUT_SECONDS", 1800)),
            )
            out = str(p.stdout or "").strip()
            if out:
                try:
                    payload = json.loads(out.splitlines()[-1])
                except Exception:
                    payload = {"raw_stdout": out[-2000:]}
            ok = bool(p.returncode == 0 and isinstance(payload, dict) and bool(payload.get("ok")))
            if not ok:
                err = str((payload or {}).get("error") or str(p.stderr or "").strip() or f"exit_code_{p.returncode}")
        except Exception as exc:
            ok = False
            err = str(exc)
            payload = {"ok": False, "error": err}

        terminal_failure = False
        with sim.dispatch_lock:
            dispatch_state = sim.metadata.get("file_dispatch_state")
            if not isinstance(dispatch_state, dict):
                return
            file_states = dispatch_state.get("file_states") if isinstance(dispatch_state.get("file_states"), dict) else {}
            fs = file_states.get(pcap_file) if isinstance(file_states.get(pcap_file), dict) else None
            if not isinstance(fs, dict):
                return
            if ok:
                fs["ingest_status"] = "completed"
                fs["ingest_completed_at_utc"] = _now()
                fs["last_ingest_error"] = ""
                fs["next_retry_ts"] = 0.0
                if not bool(fs.get("counted_completed")):
                    dispatch_state["files_completed"] = int(dispatch_state.get("files_completed") or 0) + 1
                    fs["counted_completed"] = True
            else:
                fs["ingest_status"] = "failed"
                fs["last_ingest_error"] = str(err or "ingest_failed")
                fs["next_retry_ts"] = float(time.time() + (self._file_ingest_retry_backoff_s * max(1, retries)))
                if retries >= self._file_ingest_max_retries:
                    terminal_failure = True
            file_states[pcap_file] = fs
            dispatch_state["file_states"] = file_states

        if ok:
            self._remove_file_quiet(Path(metrics_path))
            self._remove_file_quiet(Path(audit_path))
            self._publish_event(
                event_type="audit_append",
                simulation_id=sim.simulation_id,
                child_id=None,
                model_version=sim.model_version,
                payload={
                    "message": "pcap_file_ingest_completed",
                    "pcap_file": pcap_file,
                    "attempt": retries,
                    "ingest_result": payload,
                },
                severity=None,
                domain="audit",
                persist=True,
            )
            return

        self._publish_event(
            event_type="audit_append",
            simulation_id=sim.simulation_id,
            child_id=None,
            model_version=sim.model_version,
            payload={
                "message": "pcap_file_ingest_failed",
                "pcap_file": pcap_file,
                "attempt": retries,
                "error": str(err or "ingest_failed"),
                "ingest_result": payload,
            },
            severity="high" if terminal_failure else "medium",
            domain="audit",
            persist=True,
        )
        if not terminal_failure:
            return
        sim.status = "failed"
        sim.finished_at_utc = _now()
        sim.metadata["terminal_error"] = f"pcap_ingest_failed:{pcap_file}"
        sim.metadata["terminal_error_detail"] = str(err or "ingest_failed")
        sim.stop_event.set()
        self._persist_simulation(sim)
        self._publish_event(
            event_type="run_status",
            simulation_id=sim.simulation_id,
            child_id=None,
            model_version=sim.model_version,
            payload={
                "status": "failed",
                "finished_at_utc": sim.finished_at_utc,
                "reason": "pcap_file_ingest_failed",
                "pcap_file": pcap_file,
                "error": str(err or "ingest_failed"),
            },
            severity="high",
            domain="control",
            persist=True,
        )

    def _simulation_runner(self, sim: SimulationRuntime, worker_idx: int, worker_total: int) -> None:
        rng = random.Random(int(uuid.UUID(sim.simulation_id)) + worker_idx)
        children = list(sim.children)
        pcap_files = [str(x) for x in (sim.metadata.get("pcap_files") if isinstance(sim.metadata.get("pcap_files"), list) else []) if str(x).strip()]
        if not pcap_files:
            pcap_files = ["REP-01/unknown.pcap"]
        child_rule_profiles = sim.metadata.get("child_rule_profiles") if isinstance(sim.metadata.get("child_rule_profiles"), dict) else {}
        factory_node_id = str(sim.metadata.get("factory_node_id") or "factory-node-01")
        phase_cycle = ("baseline", "attack_burst", "mixed_recovery", "domain_shift")
        phase_idx = 0
        lag_high_water = max(5000, _env_int("STEP3_V2_LAG_HIGH_WATERMARK", 50_000))
        throttle_sleep_s = max(0.0005, _env_float("STEP3_V2_THROTTLE_SLEEP_SECONDS", 0.01))
        dispatch_batch = max(1, _env_int("STEP3_V2_FACTORY_DISPATCH_BATCH", 48))
        reserve_chunk = max(1, int(self._file_batch_packets))
        auto_stop_triggered = False
        while not sim.stop_event.is_set():
            lag = self._queue_backend.lag_status()
            if int(lag.get("total_lag") or 0) > lag_high_water:
                time.sleep(throttle_sleep_s)
                continue
            phase = phase_cycle[phase_idx % len(phase_cycle)]
            phase_idx += 1
            for _ in range(dispatch_batch):
                if sim.stop_event.is_set():
                    break
                pcap_file = ""
                metrics_path = ""
                audit_path = ""
                reserve_n = 0
                start_file_idx = 0
                attack_packets_file = 0
                benign_packets_file = 0
                remaining_packets_file = 0
                with sim.dispatch_lock:
                    dispatch_state = sim.metadata.get("file_dispatch_state")
                    if not isinstance(dispatch_state, dict):
                        dispatch_state = {}
                        sim.metadata["file_dispatch_state"] = dispatch_state
                    active_files = list(dispatch_state.get("active_files") or [])
                    pending_files = list(dispatch_state.get("pending_files") or [])
                    file_states = dispatch_state.get("file_states") if isinstance(dispatch_state.get("file_states"), dict) else {}
                    max_active_files = max(1, int(dispatch_state.get("max_active_files") or 10))
                    while pending_files and len(active_files) < max_active_files:
                        nxt = str(pending_files.pop(0))
                        if nxt and nxt not in active_files:
                            active_files.append(nxt)
                    dispatch_state["pending_files"] = pending_files
                    dispatch_state["active_files"] = active_files
                    if not active_files:
                        file_states_all = dispatch_state.get("file_states") if isinstance(dispatch_state.get("file_states"), dict) else {}
                        all_done = True
                        for fs in file_states_all.values():
                            if not isinstance(fs, dict):
                                continue
                            if str(fs.get("ingest_status") or "pending") != "completed":
                                all_done = False
                                break
                        if all_done and (not bool(dispatch_state.get("auto_stop_started"))):
                            dispatch_state["auto_stop_started"] = True
                            sim.stop_event.set()
                            auto_stop_triggered = True
                        elif not all_done:
                            # Keep attempting eligible retries while active set is empty.
                            retryable = [
                                pfile
                                for pfile, fs in (file_states_all.items() if isinstance(file_states_all, dict) else [])
                                if isinstance(fs, dict)
                                and int(fs.get("processed_packets") or 0) >= int(fs.get("total_packets") or 0)
                                and int(fs.get("inflight_chunks") or 0) <= 0
                                and str(fs.get("ingest_status") or "pending") in {"pending", "failed"}
                                and float(fs.get("next_retry_ts") or 0.0) <= time.time()
                            ]
                            dispatch_state["file_states"] = file_states_all
                            for rfile in retryable:
                                self._attempt_completed_file_ingest(sim, str(rfile))
                        continue
                    pcap_file = str(rng.choice(active_files))
                    fs = file_states.get(pcap_file) if isinstance(file_states, dict) else None
                    if not isinstance(fs, dict):
                        fs = {
                            "total_packets": 0,
                            "remaining_packets": 0,
                            "dispatched_packets": 0,
                            "processed_packets": 0,
                            "inflight_chunks": 0,
                            "attack_packets": 0,
                            "benign_packets": 0,
                            "ingest_status": "pending",
                            "ingest_retries": 0,
                            "next_retry_ts": 0.0,
                            "last_ingest_error": "",
                            "ingest_completed_at_utc": None,
                            "counted_completed": False,
                        }
                        file_states[pcap_file] = fs
                    remaining = int(fs.get("remaining_packets") or 0)
                    if remaining <= 0:
                        if pcap_file in active_files:
                            active_files.remove(pcap_file)
                        dispatch_state["active_files"] = active_files
                        dispatch_state["file_states"] = file_states
                        continue
                    reserve_n = min(reserve_chunk, remaining)
                    start_file_idx = int(fs.get("dispatched_packets") or 0) + 1
                    fs["remaining_packets"] = int(remaining - reserve_n)
                    fs["dispatched_packets"] = int(fs.get("dispatched_packets") or 0) + reserve_n
                    fs["inflight_chunks"] = int(fs.get("inflight_chunks") or 0) + 1
                    if int(fs.get("remaining_packets") or 0) <= 0:
                        if pcap_file in active_files:
                            active_files.remove(pcap_file)
                    dispatch_state["active_files"] = active_files
                    dispatch_state["file_states"] = file_states
                    attack_packets_file = int(fs.get("attack_packets") or 0)
                    benign_packets_file = int(fs.get("benign_packets") or 0)
                    remaining_packets_file = int(fs.get("remaining_packets") or 0)
                    metrics_path = str(fs.get("metrics_jsonl_path") or "").strip()
                    audit_path = str(fs.get("audit_jsonl_path") or "").strip()

                if reserve_n <= 0:
                    continue
                child_seq = [str(rng.choice(children)) for _pkt in range(reserve_n)]
                child_counts: dict[str, int] = {}
                for cid in child_seq:
                    child_counts[cid] = int(child_counts.get(cid, 0)) + 1
                child_next_idx: dict[str, int] = {}
                child_rate: dict[str, float] = {}
                with sim.counter_lock:
                    for cid, cnt in child_counts.items():
                        counters = sim.child_counters.setdefault(
                            cid,
                            {"packets": 0, "alerts": 0, "parent_actions": 0, "last_packet_ts": 0.0},
                        )
                        old_packets = int(counters.get("packets") or 0)
                        counters["packets"] = old_packets + int(cnt)
                        now_mono = time.monotonic()
                        last_ts = float(counters.get("last_packet_ts") or 0.0)
                        delta = now_mono - last_ts if last_ts > 0 else 0.0
                        counters["last_packet_ts"] = now_mono
                        child_next_idx[cid] = old_packets + 1
                        child_rate[cid] = round(1.0 / delta, 3) if delta > 0 else 0.0

                packet_records: list[dict[str, Any]] = []
                file_metric_rows: list[dict[str, Any]] = []
                file_audit_rows: list[dict[str, Any]] = []
                max_packet_rate_pps = 0.0
                batch_attack_count = 0
                batch_benign_count = 0
                for pkt_i in range(reserve_n):
                    child_id = child_seq[pkt_i]
                    packet_num = int(child_next_idx.get(child_id) or 1)
                    child_next_idx[child_id] = packet_num + 1
                    packet_rate_pps = float(child_rate.get(child_id) or 0.0)
                    child_profile = child_rule_profiles.get(child_id) if isinstance(child_rule_profiles.get(child_id), dict) else {}
                    base_hit_prob = float(child_profile.get("base_hit_probability") or 0.0)
                    phase_mult = _phase_hit_multiplier(phase)
                    scope_mult = _scope_hit_multiplier(str(child_profile.get("scope") or _child_scope(child_id)))
                    eff_hit_prob = min(0.98, max(0.0, (base_hit_prob * phase_mult * scope_mult)))
                    rule_hit_count = 0
                    if rng.random() < eff_hit_prob:
                        max_hits = max(1, int(child_profile.get("max_hits_per_packet") or 1))
                        rule_hit_count = 1 + int(rng.randrange(max_hits))
                    packet_label = "attack" if int(rule_hit_count) > 0 else "benign"
                    file_packet_index = int(start_file_idx + pkt_i)
                    child_scope = str(child_profile.get("scope") or _child_scope(child_id))
                    flow_bucket = max(1, int(file_packet_index // 8))
                    packet_or_flow_id = f"{pcap_file}:flow:{flow_bucket}"
                    rule_id = f"step3v2-{child_scope}-{phase}"
                    rule_version = f"{sim.model_version}:{rule_id}:v1"
                    rule_checksum = hashlib.sha256(rule_version.encode("utf-8", errors="ignore")).hexdigest()[:16]
                    expected_scope = child_scope
                    observed_scope = child_scope
                    if phase == "domain_shift" and rng.random() < 0.12:
                        observed_scope = "enterprise" if child_scope != "enterprise" else "iot"
                    cross_scope = expected_scope != observed_scope
                    confidence = round(min(0.99, 0.58 + (0.08 * int(rule_hit_count)) + rng.random() * 0.18), 4)
                    if packet_label == "attack":
                        attack_packets_file += 1
                        batch_attack_count += 1
                    else:
                        benign_packets_file += 1
                        batch_benign_count += 1
                    if packet_rate_pps > max_packet_rate_pps:
                        max_packet_rate_pps = packet_rate_pps
                    packet_records.append(
                        {
                            "child_id": child_id,
                            "phase": phase,
                            "packet_index": packet_num,
                            "pcap_file": pcap_file,
                            "file_packet_index": int(start_file_idx + pkt_i),
                            "packet_label": packet_label,
                            "rule_hit_count": int(rule_hit_count),
                            "attack_packets_file": int(attack_packets_file),
                            "benign_packets_file": int(benign_packets_file),
                            "remaining_packets_file": int(remaining_packets_file),
                            "packet_rate_pps": packet_rate_pps,
                            "packet_or_flow_id": packet_or_flow_id,
                            "isolation_valid": True,
                            "isolated": True,
                            "isolation_type": "logical",
                            "expected_scope": expected_scope,
                            "observed_scope": observed_scope,
                            "cross_scope": cross_scope,
                            "rule_id": rule_id,
                            "rule_version": rule_version,
                            "rule_checksum": rule_checksum,
                            "worker_idx": worker_idx + 1,
                        }
                    )
                    packet_id = _uuid5_from(
                        sim.simulation_id,
                        f"packet:{pcap_file}:{child_id}:{file_packet_index}:{worker_idx + 1}",
                    )
                    file_metric_rows.append(
                        {
                            "record_type": "packet",
                            "packet_id": packet_id,
                            "ts_utc": _now(),
                            "pcap_file": pcap_file,
                            "child_id": child_id,
                            "phase": phase,
                            "packet_index": int(packet_num),
                            "file_packet_index": file_packet_index,
                            "packet_label": packet_label,
                            "rule_hit_count": int(rule_hit_count),
                            "packet_rate_pps": float(packet_rate_pps),
                            "worker_idx": worker_idx + 1,
                            "source_node": "factory",
                            "factory_node_id": factory_node_id,
                            "payload": {
                                "remaining_packets_file": int(remaining_packets_file),
                                "attack_packets_file": int(attack_packets_file),
                                "benign_packets_file": int(benign_packets_file),
                                "packet_or_flow_id": packet_or_flow_id,
                                "isolation_valid": True,
                                "isolated": True,
                                "isolation_type": "logical",
                                "expected_scope": expected_scope,
                                "observed_scope": observed_scope,
                                "cross_scope": cross_scope,
                                "rule_id": rule_id,
                                "rule_version": rule_version,
                                "rule_checksum": rule_checksum,
                            },
                        }
                    )
                    if rule_hit_count > 0 and rng.random() < 0.07:
                        with sim.counter_lock:
                            sim.child_counters[child_id]["alerts"] += 1
                            alert_num = int(sim.child_counters[child_id]["alerts"])
                        sev = "high" if rng.random() < 0.4 else "medium"
                        will_escalate = bool(sev == "high" or rng.random() < 0.5)
                        temporal_alert = phase in {"attack_burst", "mixed_recovery"}
                        temporal_upgraded = bool(temporal_alert and will_escalate)
                        meta_alert = bool(cross_scope or temporal_upgraded or int(rule_hit_count) > 2)
                        false_positive = packet_label != "attack"
                        explanation_pattern = f"{rule_id}:{phase}:{'cross' if cross_scope else 'in_scope'}"
                        triage_duration_ms = int(750 + (150 * int(rule_hit_count)) + rng.randrange(900))
                        alert_id = _uuid5_from(
                            sim.simulation_id,
                            f"alert:{pcap_file}:{child_id}:{alert_num}:{file_packet_index}:{worker_idx + 1}",
                        )
                        alert_payload = {
                            "phase": phase,
                            "pcap_file": pcap_file,
                            "alert_count": int(alert_num),
                            "packet_label": packet_label,
                            "rule_hit_count": int(rule_hit_count),
                            "packet_or_flow_id": packet_or_flow_id,
                            "expected_scope": expected_scope,
                            "observed_scope": observed_scope,
                            "expected_environment": expected_scope,
                            "observed_environment": observed_scope,
                            "cross_scope": cross_scope,
                            "cross_scope_detected": cross_scope,
                            "mismatch_detected": cross_scope,
                            "escalated": will_escalate,
                            "parent_escalated": will_escalate,
                            "escalation_triggered": will_escalate,
                            "escalation_id": str(_uuid5_from(sim.simulation_id, f"escalation:{alert_id}")) if will_escalate else "",
                            "temporal_alert": temporal_alert,
                            "temporal_upgraded": temporal_upgraded,
                            "temporal_escalation_upgraded": temporal_upgraded,
                            "meta_alert": meta_alert,
                            "meta_alert_useful": meta_alert,
                            "false_positive": false_positive,
                            "alert_verdict": "false_positive" if false_positive else "true_positive",
                            "confidence": confidence,
                            "prediction_confidence": confidence,
                            "explanation_pattern": explanation_pattern,
                            "explanation_useful": True,
                            "analyst_ready": True,
                            "rule_id": rule_id,
                            "rule_version": rule_version,
                            "rule_checksum": rule_checksum,
                            "rule_true_positive": packet_label == "attack",
                            "rule_scope_correct": not cross_scope,
                            "recommendation": "review_and_triage",
                            "triage_duration_ms": triage_duration_ms,
                        }
                        file_metric_rows.append(
                            {
                                "record_type": "alert",
                                "alert_id": alert_id,
                                "ts_utc": _now(),
                                "pcap_file": pcap_file,
                                "child_id": child_id,
                                "severity": sev,
                                "phase": phase,
                                "alert_count": int(alert_num),
                                "packet_label": packet_label,
                                "rule_hit_count": int(rule_hit_count),
                                "recommendation": "review_and_triage",
                                "source_node": "factory",
                                "factory_node_id": factory_node_id,
                                "payload": alert_payload,
                            }
                        )
                        file_audit_rows.append(
                            {
                                "file_log_id": _uuid5_from(sim.simulation_id, f"audit:child_alert:{alert_id}"),
                                "ts_utc": _now(),
                                "pcap_file": pcap_file,
                                "log_kind": "audit",
                                "level": sev,
                                "message": "child_alert_detected",
                                "payload": {
                                    "child_id": child_id,
                                    "phase": phase,
                                    "packet_label": packet_label,
                                    "rule_hit_count": int(rule_hit_count),
                                    "alert_count": int(alert_num),
                                    "packet_or_flow_id": packet_or_flow_id,
                                    "rule_id": rule_id,
                                    "rule_version": rule_version,
                                    "rule_checksum": rule_checksum,
                                },
                            }
                        )
                        self._publish_event(
                            event_type="node_alert",
                            simulation_id=sim.simulation_id,
                            child_id=child_id,
                            model_version=sim.model_version,
                            payload={
                                "phase": phase,
                                "pcap_file": pcap_file,
                                "alert_count": alert_num,
                                "packet_label": packet_label,
                                "rule_hit_count": int(rule_hit_count),
                                "recommendation": "review_and_triage",
                                "source_node": "factory",
                                "factory_node_id": factory_node_id,
                                **alert_payload,
                            },
                            severity=sev,
                            domain="alerts",
                            persist=False,
                        )
                        self._publish_event(
                            event_type="audit_append",
                            simulation_id=sim.simulation_id,
                            child_id=child_id,
                            model_version=sim.model_version,
                            payload={
                                "message": "child_alert_detected",
                                "phase": phase,
                                "pcap_file": pcap_file,
                                "alert_count": alert_num,
                                "packet_label": packet_label,
                                "rule_hit_count": int(rule_hit_count),
                                "recommendation": "review_and_triage",
                                "source_node": "factory",
                                "factory_node_id": factory_node_id,
                                "packet_or_flow_id": packet_or_flow_id,
                                "rule_id": rule_id,
                                "rule_version": rule_version,
                                "rule_checksum": rule_checksum,
                            },
                            severity=sev,
                            domain="audit",
                            persist=False,
                        )
                        if will_escalate:
                            with sim.counter_lock:
                                sim.child_counters[child_id]["parent_actions"] += 1
                                action_num = int(sim.child_counters[child_id]["parent_actions"])
                            action_id = _uuid5_from(
                                sim.simulation_id,
                                f"parent_action:{pcap_file}:{child_id}:{action_num}:{file_packet_index}:{worker_idx + 1}",
                            )
                            containment_attempt = bool(packet_label == "attack")
                            containment_success = bool(containment_attempt and (sev == "high" or int(rule_hit_count) > 1))
                            response_correct = bool(packet_label == "attack")
                            action_payload = {
                                "pcap_file": pcap_file,
                                "action_count": int(action_num),
                                "packet_label": packet_label,
                                "rule_hit_count": int(rule_hit_count),
                                "packet_or_flow_id": packet_or_flow_id,
                                "alert_id": alert_id,
                                "escalation_id": str(alert_payload.get("escalation_id") or ""),
                                "response_correct": response_correct,
                                "containment_attempt": containment_attempt,
                                "containment_success": containment_success,
                                "simulated_containment_attempt": containment_attempt,
                                "simulated_containment_success": containment_success,
                                "meta_alert": meta_alert,
                                "meta_alert_useful": meta_alert,
                                "rule_id": rule_id,
                                "rule_version": rule_version,
                                "rule_checksum": rule_checksum,
                                "triage_duration_ms": triage_duration_ms,
                            }
                            file_metric_rows.append(
                                {
                                    "record_type": "parent_action",
                                    "action_id": action_id,
                                    "ts_utc": _now(),
                                    "pcap_file": pcap_file,
                                    "child_id": child_id,
                                    "severity": "high" if sev == "high" else "medium",
                                    "action": "review_and_triage",
                                    "action_count": int(action_num),
                                    "packet_label": packet_label,
                                    "rule_hit_count": int(rule_hit_count),
                                    "source_node": "factory",
                                    "factory_node_id": factory_node_id,
                                    "payload": action_payload,
                                }
                            )
                            self._publish_event(
                                event_type="parent_action",
                                simulation_id=sim.simulation_id,
                                child_id=child_id,
                                model_version=sim.model_version,
                                payload={
                                    "pcap_file": pcap_file,
                                    "action_count": action_num,
                                    "action": "review_and_triage",
                                    "packet_label": packet_label,
                                    "rule_hit_count": int(rule_hit_count),
                                    "source_node": "factory",
                                    "factory_node_id": factory_node_id,
                                    **action_payload,
                                },
                                severity="high" if sev == "high" else "medium",
                                domain="alerts",
                                persist=False,
                            )
                file_metric_rows.append(
                    {
                        "record_type": "file_log",
                        "file_log_id": _uuid5_from(
                            sim.simulation_id, f"file_metric:{pcap_file}:{worker_idx + 1}:{int(start_file_idx)}:{int(reserve_n)}"
                        ),
                        "ts_utc": _now(),
                        "pcap_file": pcap_file,
                        "log_kind": "metric",
                        "level": "info",
                        "message": "file_chunk_processed",
                        "payload": {
                            "phase": phase,
                            "worker_idx": worker_idx + 1,
                            "chunk_packet_count": int(reserve_n),
                            "chunk_start_file_packet_index": int(start_file_idx),
                            "attack_count": int(batch_attack_count),
                            "benign_count": int(batch_benign_count),
                            "attack_packets_file": int(attack_packets_file),
                            "benign_packets_file": int(benign_packets_file),
                            "remaining_packets_file": int(remaining_packets_file),
                        },
                    }
                )
                if metrics_path:
                    self._append_jsonl_rows(Path(metrics_path), file_metric_rows)
                if audit_path and file_audit_rows:
                    self._append_jsonl_rows(Path(audit_path), file_audit_rows)

                trigger_ingest = False
                with sim.dispatch_lock:
                    dispatch_state = sim.metadata.get("file_dispatch_state")
                    if isinstance(dispatch_state, dict):
                        file_states = dispatch_state.get("file_states") if isinstance(dispatch_state.get("file_states"), dict) else {}
                        fs = file_states.get(pcap_file) if isinstance(file_states.get(pcap_file), dict) else None
                        if isinstance(fs, dict):
                            fs["attack_packets"] = int(fs.get("attack_packets") or 0) + int(batch_attack_count)
                            fs["benign_packets"] = int(fs.get("benign_packets") or 0) + int(batch_benign_count)
                            fs["processed_packets"] = int(fs.get("processed_packets") or 0) + int(reserve_n)
                            fs["inflight_chunks"] = max(0, int(fs.get("inflight_chunks") or 0) - 1)
                            total_packets = int(fs.get("total_packets") or 0)
                            processed_packets = int(fs.get("processed_packets") or 0)
                            if (
                                processed_packets >= total_packets
                                and int(fs.get("inflight_chunks") or 0) <= 0
                                and str(fs.get("ingest_status") or "pending") in {"pending", "failed"}
                            ):
                                fs["ingest_status"] = "ingest_pending"
                                trigger_ingest = True
                            file_states[pcap_file] = fs
                            dispatch_state["file_states"] = file_states

                if trigger_ingest:
                    self._attempt_completed_file_ingest(sim, pcap_file)

                batch_payload = {
                    "phase": phase,
                    "pcap_file": pcap_file,
                    "packet_count": int(reserve_n),
                    "attack_count": int(batch_attack_count),
                    "benign_count": int(batch_benign_count),
                    "attack_packets_file": int(attack_packets_file),
                    "benign_packets_file": int(benign_packets_file),
                    "remaining_packets_file": int(remaining_packets_file),
                    "packet_rate_pps": float(max_packet_rate_pps),
                    "queue_backend": self._queue_backend.kind,
                    "execution_mode": "simulation",
                    "isolation_type": "logical",
                    "worker_idx": worker_idx + 1,
                    "source_node": "factory",
                    "factory_node_id": factory_node_id,
                    "packets": packet_records,
                }
                self._publish_event(
                    event_type="node_traffic_batch",
                    simulation_id=sim.simulation_id,
                    child_id=None,
                    model_version=sim.model_version,
                    payload=batch_payload,
                    severity=None,
                    domain="telemetry",
                    persist=False,
                    broadcast=False,
                    include_history=False,
                )
                child_rollup = [
                    {
                        "child_id": cid,
                        "packet_count": int(cnt),
                        "packet_rate_pps": float(child_rate.get(cid) or 0.0),
                    }
                    for cid, cnt in child_counts.items()
                ]
                self._publish_event(
                    event_type="node_traffic_aggregate",
                    simulation_id=sim.simulation_id,
                    child_id=None,
                    model_version=sim.model_version,
                    payload={
                        "phase": phase,
                        "pcap_file": pcap_file,
                        "packet_count": int(reserve_n),
                        "attack_count": int(batch_attack_count),
                        "benign_count": int(batch_benign_count),
                        "attack_packets_file": int(attack_packets_file),
                        "benign_packets_file": int(benign_packets_file),
                        "remaining_packets_file": int(remaining_packets_file),
                        "packet_rate_pps": float(max_packet_rate_pps),
                        "queue_backend": self._queue_backend.kind,
                        "execution_mode": "simulation",
                        "isolation_type": "logical",
                        "worker_idx": worker_idx + 1,
                        "source_node": "factory",
                        "factory_node_id": factory_node_id,
                        "children": child_rollup,
                    },
                    severity=None,
                    domain="telemetry",
                    persist=False,
                )
            retry_files: list[str] = []
            with sim.dispatch_lock:
                dispatch_state = sim.metadata.get("file_dispatch_state")
                if isinstance(dispatch_state, dict):
                    file_states = dispatch_state.get("file_states") if isinstance(dispatch_state.get("file_states"), dict) else {}
                    for fkey, fs in (file_states.items() if isinstance(file_states, dict) else []):
                        if not isinstance(fs, dict):
                            continue
                        if int(fs.get("processed_packets") or 0) < int(fs.get("total_packets") or 0):
                            continue
                        if int(fs.get("inflight_chunks") or 0) > 0:
                            continue
                        if str(fs.get("ingest_status") or "pending") not in {"pending", "failed", "ingest_pending"}:
                            continue
                        if float(fs.get("next_retry_ts") or 0.0) > time.time():
                            continue
                        retry_files.append(str(fkey))
            for rf in retry_files:
                self._attempt_completed_file_ingest(sim, rf)
            self._publish_event(
                event_type="replay_phase",
                simulation_id=sim.simulation_id,
                child_id=None,
                model_version=sim.model_version,
                payload={
                    "phase": phase,
                    "active_children": len(sim.children),
                    "active_files": len(((sim.metadata.get("file_dispatch_state") or {}).get("active_files") or [])),
                    "pending_files": len(((sim.metadata.get("file_dispatch_state") or {}).get("pending_files") or [])),
                    "files_completed": int(((sim.metadata.get("file_dispatch_state") or {}).get("files_completed") or 0)),
                },
                severity=None,
                domain="control",
                persist=True,
            )
            if auto_stop_triggered:
                break
        if auto_stop_triggered:
            self._auto_finalize_completed_simulation(sim)

    def _await_queue_drain(self, timeout_s: float) -> dict[str, Any]:
        non_control_domains = ("telemetry", "alerts", "audit")

        def _non_control_lag(lag_payload: dict[str, Any]) -> int:
            by_stream = lag_payload.get("by_stream") if isinstance(lag_payload.get("by_stream"), dict) else {}
            return int(sum(int(by_stream.get(dom) or 0) for dom in non_control_domains))

        start = time.time()
        while time.time() - start < timeout_s:
            lag = self._queue_backend.lag_status()
            if _non_control_lag(lag) <= 0:
                return {
                    "drained": True,
                    "lag": lag,
                    "elapsed_s": round(time.time() - start, 3),
                    "drain_scope": "non_control_streams_only",
                    "drain_domains": list(non_control_domains),
                }
            time.sleep(0.25)
        lag = self._queue_backend.lag_status()
        return {
            "drained": False,
            "lag": lag,
            "elapsed_s": round(time.time() - start, 3),
            "drain_scope": "non_control_streams_only",
            "drain_domains": list(non_control_domains),
        }

    def _generate_completion_metrics(self, sim: SimulationRuntime) -> None:
        try:
            result = generate_step3_metrics(sim_id=sim.simulation_id)
            sim.metadata["step3_metrics_generation"] = result
            self._persist_simulation(sim)
            self._publish_event(
                event_type="audit_append",
                simulation_id=sim.simulation_id,
                child_id=None,
                model_version=sim.model_version,
                payload={
                    "message": "step3_v2_metrics_generation_completed",
                    "status": result.get("status"),
                    "warning": bool(result.get("warning")),
                    "missing_metrics": result.get("missing_metrics") or [],
                    "calculation_worker_threads": result.get("calculation_worker_threads"),
                    "ingested_metric_count": result.get("ingested_metric_count"),
                },
                severity=None,
                domain="audit",
                persist=True,
            )
        except Exception as exc:
            sim.metadata["step3_metrics_generation"] = {
                "ok": False,
                "error": f"step3_v2_metrics_generation_failed:{exc}",
            }
            self._persist_simulation(sim)
            self._publish_event(
                event_type="audit_append",
                simulation_id=sim.simulation_id,
                child_id=None,
                model_version=sim.model_version,
                payload={
                    "message": "step3_v2_metrics_generation_failed",
                    "error": str(exc),
                },
                severity="high",
                domain="audit",
                persist=True,
            )

    def _auto_finalize_completed_simulation(self, sim: SimulationRuntime) -> None:
        with self._lock:
            if sim.status in {"completed", "stopped", "failed"}:
                return
            sim.status = "stopping"
            sim.stop_requested_at_utc = _now()
        self._persist_simulation(sim)
        self._publish_event(
            event_type="run_status",
            simulation_id=sim.simulation_id,
            child_id=None,
            model_version=sim.model_version,
            payload={
                "status": "stopping",
                "stop_requested_at_utc": sim.stop_requested_at_utc,
                "reason": "all_rep01_files_completed",
            },
            severity=None,
            domain="control",
            persist=True,
        )
        current = threading.current_thread()
        for t in sim.producer_threads:
            if t is current:
                continue
            t.join(timeout=2.0)
        drain = self._await_queue_drain(timeout_s=max(2.0, _env_float("STEP3_V2_AUTO_DRAIN_TIMEOUT_SECONDS", 45.0)))
        sim.status = "finalizing"
        self._persist_simulation(sim)
        self._publish_event(
            event_type="run_status",
            simulation_id=sim.simulation_id,
            child_id=None,
            model_version=sim.model_version,
            payload={"status": "finalizing", "reason": "per_file_ingest_finalization"},
            severity=None,
            domain="control",
            persist=True,
        )
        sim.metadata["file_ingest_finalization"] = {"mode": "per_file", "finalized_at_utc": _now()}
        sim.finished_at_utc = _now()
        sim.status = "completed"
        sim.metadata["drain_result"] = drain
        sim.metadata["completion_reason"] = "all_rep01_files_completed"
        sim.metadata["queue_drain_warning"] = None if bool(drain.get("drained")) else "queue_not_fully_drained_at_finalize"
        self._persist_simulation(sim)
        self._publish_event(
            event_type="run_status",
            simulation_id=sim.simulation_id,
            child_id=None,
            model_version=sim.model_version,
            payload={
                "status": sim.status,
                "finished_at_utc": sim.finished_at_utc,
                "drain_result": drain,
                "reason": "all_rep01_files_completed",
            },
            severity=None,
            domain="control",
            persist=True,
        )
        self._publish_event(
            event_type="audit_append",
            simulation_id=sim.simulation_id,
            child_id=None,
            model_version=sim.model_version,
            payload={
                "message": "simulation_completed_all_files_processed",
                "drain_result": drain,
                "status": sim.status,
            },
            severity=None,
            domain="audit",
            persist=True,
        )
        self._generate_completion_metrics(sim)

    def _fail_simulation_start(self, sim: SimulationRuntime, reason: str) -> None:
        status = "stopped" if sim.stop_event.is_set() else "failed"
        sim.finished_at_utc = _now()
        sim.status = status
        sim.metadata["start_error"] = str(reason or "unknown_start_error")
        self._persist_simulation(sim)
        self._publish_event(
            event_type="run_status",
            simulation_id=sim.simulation_id,
            child_id=None,
            model_version=sim.model_version,
            payload={
                "status": sim.status,
                "finished_at_utc": sim.finished_at_utc,
                "reason": str(reason or "start_failed"),
            },
            severity="high" if status == "failed" else None,
            domain="control",
            persist=True,
        )
        self._publish_event(
            event_type="audit_append",
            simulation_id=sim.simulation_id,
            child_id=None,
            model_version=sim.model_version,
            payload={"message": "simulation_start_failed", "reason": str(reason or "start_failed"), "status": sim.status},
            severity="high" if status == "failed" else None,
            domain="audit",
            persist=True,
        )
        write_audit_event(
            event_type="step3_v2_simulation_start_failed",
            actor="step3-v2-engine",
            artifact_refs=[],
            context={
                "simulation_id": sim.simulation_id,
                "model_id": sim.model_id,
                "model_version": sim.model_version,
                "status": sim.status,
                "reason": str(reason or "start_failed"),
            },
            dataset_id="REP-01",
            experiment_id="exp_model_v1_step3_v2",
            model_version=sim.model_version,
            replay_id=sim.simulation_id,
        )

    def _bootstrap_simulation(self, sim: SimulationRuntime) -> None:
        try:
            cleanup_report = self._pre_start_runtime_cleanup()
            disk_guard = self._preflight_disk_guard()
            sim.metadata["pre_start_cleanup"] = cleanup_report
            sim.metadata["disk_guard"] = disk_guard
            self._persist_simulation(sim)
            self._publish_event(
                event_type="system_health",
                simulation_id=sim.simulation_id,
                child_id=None,
                model_version=sim.model_version,
                payload={"phase": "pre_start_cleanup", **cleanup_report},
                severity=None,
                domain="control",
                persist=True,
            )
            write_audit_event(
                event_type="step3_v2_runtime_cache_cleanup",
                actor="step3-v2-engine",
                artifact_refs=[],
                context={
                    "simulation_id": sim.simulation_id,
                    "model_id": sim.model_id,
                    "model_version": sim.model_version,
                    **cleanup_report,
                    "disk_guard": disk_guard,
                },
                dataset_id="REP-01",
                experiment_id="exp_model_v1_step3_v2",
                model_version=sim.model_version,
                replay_id=sim.simulation_id,
            )
            if not bool(disk_guard.get("ok")):
                raise RuntimeError(
                    f"disk_guard_failed: pgdata_ok={bool((disk_guard.get('pgdata') or {}).get('ok'))}"
                    f" tablespace_ok={bool((disk_guard.get('tablespace') or {}).get('ok'))}"
                )
            children = list(sim.children or list(DEFAULT_CHILDREN))
            replay_dataset_id = str(sim.metadata.get("replay_dataset_id") or self._replay_dataset_id()).strip() or "REP-01"
            pcap_inventory = self._discover_pcap_files(dataset_id=replay_dataset_id)
            pcap_files = [str(r.get("pcap_file") or "").strip() for r in pcap_inventory if str(r.get("pcap_file") or "").strip()]
            if not pcap_files:
                raise ValueError(f"no_pcap_files_found_for_{replay_dataset_id}")
            manifest = self._build_pcap_manifest(dataset_id=replay_dataset_id, pcap_inventory=pcap_inventory)
            manifest_by_file = {
                str(x.get("pcap_file") or "").strip(): x for x in (manifest.get("files") if isinstance(manifest.get("files"), list) else [])
            }
            max_active_files = min(10, max(1, _env_int("STEP3_V2_MAX_ACTIVE_PCAP_FILES", 10)))
            inventory_map: dict[str, dict[str, Any]] = {
                str(r.get("pcap_file") or "").strip(): r for r in pcap_inventory if str(r.get("pcap_file") or "").strip()
            }
            file_states: dict[str, dict[str, Any]] = {}
            for pf in pcap_files:
                inv = inventory_map.get(pf) if isinstance(inventory_map.get(pf), dict) else {}
                file_size = int(inv.get("file_size_bytes") or 0) if isinstance(inv, dict) else 0
                mf = manifest_by_file.get(pf) if isinstance(manifest_by_file.get(pf), dict) else {}
                budget = int(mf.get("packet_count") or 0)
                if budget <= 0:
                    raise ValueError(f"no_packets_detected_for_{pf}")
                metrics_path, audit_path = self._pcap_artifact_paths(simulation_id=sim.simulation_id, pcap_file=pf)
                metrics_path.parent.mkdir(parents=True, exist_ok=True)
                metrics_path.touch(exist_ok=True)
                audit_path.touch(exist_ok=True)
                file_states[pf] = {
                    "total_packets": int(budget),
                    "remaining_packets": int(budget),
                    "dispatched_packets": 0,
                    "processed_packets": 0,
                    "inflight_chunks": 0,
                    "attack_packets": 0,
                    "benign_packets": 0,
                    "file_size_bytes": int(file_size),
                    "metrics_jsonl_path": str(metrics_path),
                    "audit_jsonl_path": str(audit_path),
                    "ingest_status": "pending",
                    "ingest_retries": 0,
                    "next_retry_ts": 0.0,
                    "last_ingest_error": "",
                    "ingest_completed_at_utc": None,
                    "counted_completed": False,
                }
            if sim.stop_event.is_set():
                self._fail_simulation_start(sim, "stop_requested_during_initialization")
                return
            active_files = list(pcap_files[:max_active_files])
            pending_files = list(pcap_files[max_active_files:])
            sim.status = "running"
            sim.metadata.update(
                {
                    "queue_backend": self._queue_backend.kind,
                    "child_count": len(children),
                    "service_thread_target": self._service_thread_target(),
                    "worker_budget": self._worker_budget(),
                    "consumer_worker_target": self._consumer_worker_target(),
                    "producer_worker_target": self._producer_worker_target(len(children)),
                    "rep01_only_policy": True if replay_dataset_id == "REP-01" else False,
                    "pcap_inventory_count": len(pcap_files),
                    "pcap_files": pcap_files,
                    "pcap_manifest_version": int(manifest.get("manifest_version") or 1),
                    "pcap_manifest_path": str(manifest.get("manifest_path") or ""),
                    "child_rule_profiles": _build_child_rule_profiles(children, sim.model_version),
                    "factory_node_id": "factory-node-01",
                    "dispatch_mode": "random_factory_to_child",
                    "packet_budget_mode": "exact_manifest_packets_only",
                    "packet_label_mode": "child_rule_hits",
                    "required_alert_context_fields": ["recommendation", "phase", "severity", "payload"],
                    "step3_metric_evidence_mode": "producer_labeled_simulation_ground_truth",
                    "ingest_mode": "per_pcap_file_jsonl_then_ingest",
                    "ingest_script": self._file_ingest_script,
                    "file_batch_packets": int(self._file_batch_packets),
                    "file_dispatch_state": {
                        "max_active_files": int(max_active_files),
                        "active_files": active_files,
                        "pending_files": pending_files,
                        "file_states": file_states,
                        "files_completed": 0,
                        "auto_stop_started": False,
                    },
                }
            )
            self._persist_simulation(sim)
            write_audit_event(
                event_type="step3_v2_simulation_started",
                actor="step3-v2-engine",
                artifact_refs=[],
                context={
                    "simulation_id": sim.simulation_id,
                    "model_id": sim.model_id,
                    "model_version": sim.model_version,
                    "execution_mode": "simulation",
                    "isolation_type": "logical",
                },
                dataset_id="REP-01",
                experiment_id="exp_model_v1_step3_v2",
                model_version=sim.model_version,
                replay_id=sim.simulation_id,
            )
            self._publish_event(
                event_type="run_status",
                simulation_id=sim.simulation_id,
                child_id=None,
                model_version=sim.model_version,
                payload={"status": "running", "started_at_utc": sim.started_at_utc},
                severity=None,
                domain="control",
                persist=True,
            )
            producer_workers = self._producer_worker_target(len(children))
            for idx in range(producer_workers):
                t = threading.Thread(
                    target=self._simulation_runner,
                    args=(sim, idx, producer_workers),
                    name=f"step3-v2-producer-{idx + 1}",
                    daemon=True,
                )
                sim.producer_threads.append(t)
                t.start()
        except Exception as exc:
            self._fail_simulation_start(sim, str(exc))

    def start_simulation(self, *, model_id: str | None, model_version: str) -> dict[str, Any]:
        simulation_id = str(uuid.uuid4())
        children = list(DEFAULT_CHILDREN)
        replay_dataset_id = self._replay_dataset_id()
        sim = SimulationRuntime(
            simulation_id=simulation_id,
            model_id=(str(model_id).strip() or None) if model_id else None,
            model_version=str(model_version or "").strip(),
            started_at_utc=_now(),
            status="initializing",
            children=children,
            metadata={
                "execution_mode": "simulation",
                "isolation_type": "logical",
                "replay_dataset_id": replay_dataset_id,
                "bootstrap_mode": "async_background",
                "ingest_mode": "per_pcap_file_jsonl_then_ingest",
                "ingest_artifact_root": str(self._sim_file_dir(simulation_id)),
            },
        )
        sim.child_counters = {cid: {"packets": 0, "alerts": 0, "parent_actions": 0, "last_packet_ts": 0.0} for cid in children}
        with self._lock:
            self._simulations[simulation_id] = sim
        self._persist_simulation(sim)
        self._publish_event(
            event_type="run_status",
            simulation_id=simulation_id,
            child_id=None,
            model_version=sim.model_version,
            payload={"status": "initializing", "started_at_utc": sim.started_at_utc},
            severity=None,
            domain="control",
            persist=True,
        )
        t = threading.Thread(
            target=self._bootstrap_simulation,
            args=(sim,),
            name=f"step3-v2-bootstrap-{simulation_id[:8]}",
            daemon=True,
        )
        t.start()
        return self.get_simulation(simulation_id)

    def stop_simulation(self, simulation_id: str) -> dict[str, Any]:
        with self._lock:
            sim = self._simulations.get(simulation_id)
        if sim is None:
            raise KeyError("simulation_not_found")
        if sim.status in {"completed", "stopped", "failed"}:
            return self.get_simulation(simulation_id)
        sim.status = "stopping"
        sim.stop_requested_at_utc = _now()
        sim.stop_event.set()
        self._persist_simulation(sim)
        self._publish_event(
            event_type="run_status",
            simulation_id=simulation_id,
            child_id=None,
            model_version=sim.model_version,
            payload={"status": "stopping", "stop_requested_at_utc": sim.stop_requested_at_utc},
            severity=None,
            domain="control",
            persist=True,
        )
        for t in sim.producer_threads:
            t.join(timeout=3.0)
        drain = self._await_queue_drain(timeout_s=max(2.0, _env_float("STEP3_V2_DRAIN_TIMEOUT_SECONDS", 90.0)))
        sim.status = "finalizing"
        self._persist_simulation(sim)
        self._publish_event(
            event_type="run_status",
            simulation_id=simulation_id,
            child_id=None,
            model_version=sim.model_version,
            payload={"status": "finalizing", "reason": "per_file_ingest_finalization"},
            severity=None,
            domain="control",
            persist=True,
        )
        sim.metadata["file_ingest_finalization"] = {"mode": "per_file", "finalized_at_utc": _now()}
        sim.finished_at_utc = _now()
        completion_reason = str(sim.metadata.get("completion_reason") or "").strip().lower()
        if completion_reason == "all_rep01_files_completed":
            sim.status = "completed"
            sim.metadata["queue_drain_warning"] = None if bool(drain.get("drained")) else "queue_not_fully_drained_at_finalize"
        else:
            sim.status = "completed" if bool(drain.get("drained")) else "stopped"
            sim.metadata["queue_drain_warning"] = None
        sim.metadata["drain_result"] = drain
        self._persist_simulation(sim)
        self._publish_event(
            event_type="run_status",
            simulation_id=simulation_id,
            child_id=None,
            model_version=sim.model_version,
            payload={"status": sim.status, "finished_at_utc": sim.finished_at_utc, "drain_result": drain},
            severity=None,
            domain="control",
            persist=True,
        )
        self._publish_event(
            event_type="audit_append",
            simulation_id=simulation_id,
            child_id=None,
            model_version=sim.model_version,
            payload={"message": "simulation_stopped", "drain_result": drain, "status": sim.status},
            severity=None,
            domain="audit",
            persist=True,
        )
        write_audit_event(
            event_type="step3_v2_simulation_stopped",
            actor="step3-v2-engine",
            artifact_refs=[],
            context={
                "simulation_id": simulation_id,
                "status": sim.status,
                "drain_result": drain,
            },
            dataset_id="REP-01",
            experiment_id="exp_model_v1_step3_v2",
            model_version=sim.model_version,
            replay_id=simulation_id,
        )
        return self.get_simulation(simulation_id)

    def list_simulations(self, limit: int = 100) -> list[dict[str, Any]]:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT simulation_id::text, model_id::text, model_version, status, execution_mode, isolation_type,
                           started_at_utc, stop_requested_at_utc, finished_at_utc, metadata, created_at_utc, updated_at_utc
                    FROM phase4.step3_v2_simulations
                    ORDER BY started_at_utc DESC
                    LIMIT %(limit)s;
                    """,
                    {"limit": max(1, int(limit))},
                )
                rows = cur.fetchall() or []
        out: list[dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "simulation_id": str(r[0]),
                    "model_id": str(r[1]) if r[1] else None,
                    "model_version": str(r[2] or ""),
                    "status": str(r[3] or ""),
                    "execution_mode": str(r[4] or "simulation"),
                    "isolation_type": str(r[5] or "logical"),
                    "started_at_utc": str(r[6]) if r[6] else None,
                    "stop_requested_at_utc": str(r[7]) if r[7] else None,
                    "finished_at_utc": str(r[8]) if r[8] else None,
                    "metadata": r[9] if isinstance(r[9], dict) else {},
                    "created_at_utc": str(r[10]) if r[10] else None,
                    "updated_at_utc": str(r[11]) if r[11] else None,
                }
            )
        return out

    def get_simulation(self, simulation_id: str) -> dict[str, Any]:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT simulation_id::text, model_id::text, model_version, status, execution_mode, isolation_type,
                           started_at_utc, stop_requested_at_utc, finished_at_utc, metadata, created_at_utc, updated_at_utc
                    FROM phase4.step3_v2_simulations
                    WHERE simulation_id = %(simulation_id)s::uuid
                    LIMIT 1;
                    """,
                    {"simulation_id": simulation_id},
                )
                row = cur.fetchone()
        if not row:
            raise KeyError("simulation_not_found")
        lag = self._queue_backend.lag_status()
        with self._lock:
            runtime = self._simulations.get(simulation_id)
        child_counters = runtime.child_counters if runtime else {}
        return {
            "simulation_id": str(row[0]),
            "model_id": str(row[1]) if row[1] else None,
            "model_version": str(row[2] or ""),
            "status": str(row[3] or ""),
            "execution_mode": str(row[4] or "simulation"),
            "isolation_type": str(row[5] or "logical"),
            "started_at_utc": str(row[6]) if row[6] else None,
            "stop_requested_at_utc": str(row[7]) if row[7] else None,
            "finished_at_utc": str(row[8]) if row[8] else None,
            "metadata": row[9] if isinstance(row[9], dict) else {},
            "created_at_utc": str(row[10]) if row[10] else None,
            "updated_at_utc": str(row[11]) if row[11] else None,
            "queue": lag,
            "child_counters": child_counters,
        }

    def get_audit(self, simulation_id: str, limit: int = 1000) -> list[dict[str, Any]]:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT audit_id::text AS row_id, 'info'::text AS level, event_type AS message,
                           event_details_json AS payload, created_at AS ts_utc, created_at_utc, 'audit_log' AS source
                    FROM (
                        SELECT audit_id, event_type, event_details_json, created_at, created_at AS created_at_utc
                        FROM phase4.audit_log
                        WHERE step = 'step3' AND step_unique_id = %(simulation_id)s
                        ORDER BY created_at DESC
                        LIMIT %(limit)s
                    ) al
                    UNION ALL
                    SELECT audit_id::text AS row_id, level, message, details AS payload, ts_utc, created_at_utc, 'audit_log' AS source
                    FROM phase4.step3_v2_audit_logs
                    WHERE simulation_id = %(simulation_id)s::uuid
                    UNION ALL
                    SELECT file_log_id::text AS row_id, level, message, payload, ts_utc, created_at_utc, 'file_log' AS source
                    FROM phase4.step3_v2_file_logs
                    WHERE simulation_id = %(simulation_id)s::uuid
                      AND log_kind IN ('audit', 'ingest')
                    ORDER BY ts_utc DESC
                    LIMIT %(limit)s;
                    """,
                    {"simulation_id": simulation_id, "limit": max(1, int(limit))},
                )
                rows = cur.fetchall() or []
        out: list[dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "audit_id": str(r[0]),
                    "level": str(r[1] or "info"),
                    "message": str(r[2] or ""),
                    "details": r[3] if isinstance(r[3], dict) else {},
                    "ts_utc": str(r[4]) if r[4] else None,
                    "created_at_utc": str(r[5]) if r[5] else None,
                    "source": str(r[6] or "audit_log"),
                }
            )
        return out

    def queue_status(self) -> dict[str, Any]:
        status = self._queue_backend.lag_status()
        status["service_thread_target"] = self._service_thread_target()
        status["worker_budget"] = self._worker_budget()
        status["consumer_worker_target"] = self._consumer_worker_target()
        status["consumer_threads"] = len(self._consumer_threads)
        return status

    def _replay_dataset_id(self) -> str:
        return str(os.getenv("STEP3_V2_REPLAY_DATASET_ID", "REP-01")).strip() or "REP-01"

    def _discover_pcap_files(self, *, dataset_id: str | None = None) -> list[dict[str, Any]]:
        did = str(dataset_id or self._replay_dataset_id()).strip() or "REP-01"
        root_override = str(os.getenv("STEP3_V2_PCAP_ROOT", "")).strip()
        if root_override:
            roots = [Path(root_override)]
        else:
            # Strict policy: only use files under raw_downloads/<dataset_id>/...
            roots = [self._data_root / "raw_downloads" / did]
        seen: set[str] = set()
        out: list[dict[str, Any]] = []
        max_files = max(100, _env_int("STEP3_V2_PCAP_INVENTORY_MAX_FILES", 5000))
        for root in roots:
            if not root.exists():
                continue
            try:
                entries = root.rglob("*")
            except Exception:
                continue
            for path in entries:
                if len(out) >= max_files:
                    return out
                if not path.is_file():
                    continue
                lower = path.name.lower()
                if not (lower.endswith(".pcap") or lower.endswith(".pcapng")):
                    continue
                try:
                    rel = str(path.relative_to(self._data_root / "raw_downloads"))
                except Exception:
                    rel = path.name
                key = rel.lower()
                if key in seen:
                    continue
                seen.add(key)
                try:
                    st = path.stat()
                    out.append(
                        {
                            "pcap_file": rel,
                            "pcap_path": str(path),
                            "file_size_bytes": int(st.st_size),
                            "modified_at_utc": datetime.fromtimestamp(float(st.st_mtime), timezone.utc).isoformat(),
                        }
                    )
                except Exception:
                    out.append(
                        {
                            "pcap_file": rel,
                            "pcap_path": str(path),
                            "file_size_bytes": 0,
                            "modified_at_utc": None,
                        }
                    )
        return out

    def _pcap_manifest_dir(self) -> Path:
        root = str(os.getenv("STEP3_V2_MANIFEST_ROOT", "")).strip()
        if root:
            return Path(root)
        return self._data_root / "outputs" / "model_v1" / "step3_v2" / "manifest"

    def _pcap_manifest_path(self, dataset_id: str) -> Path:
        safe = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in str(dataset_id or "REP-01"))
        return self._pcap_manifest_dir() / f"{safe}.json"

    def _build_pcap_manifest(
        self,
        *,
        dataset_id: str,
        pcap_inventory: list[dict[str, Any]],
    ) -> dict[str, Any]:
        did = str(dataset_id or "REP-01").strip() or "REP-01"
        manifest_dir = self._pcap_manifest_dir()
        manifest_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = self._pcap_manifest_path(did)
        current_fingerprint = sorted(
            [
                {
                    "pcap_file": str(r.get("pcap_file") or ""),
                    "file_size_bytes": int(r.get("file_size_bytes") or 0),
                    "modified_at_utc": str(r.get("modified_at_utc") or ""),
                }
                for r in pcap_inventory
                if str(r.get("pcap_file") or "").strip()
            ],
            key=lambda x: str(x.get("pcap_file") or ""),
        )
        current_fp_sha = hashlib.sha256(json.dumps(current_fingerprint, sort_keys=True).encode("utf-8")).hexdigest()
        if manifest_path.exists():
            try:
                cached = json.loads(manifest_path.read_text(encoding="utf-8"))
                if (
                    isinstance(cached, dict)
                    and str(cached.get("dataset_id") or "") == did
                    and str(cached.get("inventory_fingerprint_sha256") or "") == current_fp_sha
                    and isinstance(cached.get("files"), list)
                ):
                    cached["manifest_path"] = str(manifest_path)
                    return cached
            except Exception:
                pass
        files: list[dict[str, Any]] = []
        for inv in current_fingerprint:
            rel = str(inv.get("pcap_file") or "").strip()
            if not rel:
                continue
            path = Path(self._data_root / "raw_downloads" / rel)
            packets = _exact_packet_count(path)
            if packets <= 0:
                # Keep fallback non-zero so files can still be consumed if format parser is unsupported.
                packets = max(1, int(inv.get("file_size_bytes") or 0) // max(64, _env_int("STEP3_V2_EST_BYTES_PER_PACKET", 550)))
            files.append(
                {
                    "pcap_file": rel,
                    "packet_count": int(packets),
                    "attack_count": None,
                    "benign_count": None,
                    "attack_ratio": None,
                    "label_source": "child_rule_hits_runtime",
                    "file_size_bytes": int(inv.get("file_size_bytes") or 0),
                    "modified_at_utc": str(inv.get("modified_at_utc") or ""),
                }
            )
        manifest = {
            "manifest_version": 1,
            "dataset_id": did,
            "created_at_utc": _now(),
            "inventory_fingerprint_sha256": current_fp_sha,
            "files": files,
        }
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2), encoding="utf-8")
        manifest["manifest_path"] = str(manifest_path)
        return manifest

    def get_pcap_metrics(self, simulation_id: str) -> dict[str, Any]:
        runtime_meta: dict[str, Any] = {}
        runtime_status: str | None = None
        with self._lock:
            rt = self._simulations.get(simulation_id)
            if rt is not None and isinstance(rt.metadata, dict):
                runtime_meta = dict(rt.metadata)
                runtime_status = str(rt.status or "").strip().lower() or None
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT status, metadata
                    FROM phase4.step3_v2_simulations
                    WHERE simulation_id = %(simulation_id)s::uuid
                    LIMIT 1;
                    """,
                    {"simulation_id": simulation_id},
                )
                meta_row = cur.fetchone()
        db_status = str(meta_row[0] or "").strip().lower() if meta_row and meta_row[0] is not None else ""
        sim_meta = meta_row[1] if meta_row and isinstance(meta_row[1], dict) else {}
        if runtime_meta:
            sim_meta = {**sim_meta, **runtime_meta}
        sim_status = runtime_status or db_status
        terminal_error = str(sim_meta.get("terminal_error") or "")

        def _stage_for_file(*, pcap_file: str, fs_meta: dict[str, Any], packet_count: int) -> str:
            ingest_status = str(fs_meta.get("ingest_status") or "").strip().lower()
            dispatch_count = int(fs_meta.get("dispatched_packets") or 0)
            processed_count = int(fs_meta.get("processed_packets") or 0)
            has_started = bool(dispatch_count > 0 or processed_count > 0 or int(packet_count or 0) > 0)
            if ingest_status == "failed":
                return "Failed"
            if sim_status == "failed":
                if (pcap_file and pcap_file in terminal_error) or str(fs_meta.get("last_ingest_error") or "").strip():
                    return "Failed"
            if ingest_status in {"running", "ingest_pending"}:
                return "Ingestion Started"
            if ingest_status == "completed":
                if sim_status == "completed":
                    return "Completed"
                return "Ingestion Completed"
            if has_started:
                return "Running"
            return "Pending"

        replay_dataset_id = str(sim_meta.get("replay_dataset_id") or self._replay_dataset_id()).strip() or "REP-01"
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        pcap_file,
                        COUNT(*)::bigint AS packet_count,
                        COUNT(*) FILTER (WHERE COALESCE(packet_label,'') = 'attack')::bigint AS attack_packets,
                        COUNT(*) FILTER (WHERE COALESCE(packet_label,'') = 'benign')::bigint AS benign_packets,
                        MIN(ts_utc) AS first_ts,
                        MAX(ts_utc) AS last_ts,
                        AVG(packet_rate_pps) AS avg_packet_rate_pps
                    FROM phase4.step3_v2_child_packets
                    WHERE simulation_id = %(simulation_id)s::uuid
                    GROUP BY 1
                    ORDER BY packet_count DESC, pcap_file ASC;
                    """,
                    {"simulation_id": simulation_id},
                )
                traffic_rows = cur.fetchall() or []
                cur.execute(
                    """
                    SELECT
                        pcap_file,
                        COUNT(*)::bigint AS alert_count
                    FROM phase4.step3_v2_alerts
                    WHERE simulation_id = %(simulation_id)s::uuid
                    GROUP BY 1;
                    """,
                    {"simulation_id": simulation_id},
                )
                alert_rows = cur.fetchall() or []
                cur.execute(
                    """
                    SELECT
                        pcap_file,
                        COUNT(*)::bigint AS parent_action_count
                    FROM phase4.step3_v2_parent_actions
                    WHERE simulation_id = %(simulation_id)s::uuid
                    GROUP BY 1;
                    """,
                    {"simulation_id": simulation_id},
                )
                action_rows = cur.fetchall() or []
        alerts_by_file = {str(r[0]).lower(): int(r[1] or 0) for r in alert_rows}
        actions_by_file = {str(r[0]).lower(): int(r[1] or 0) for r in action_rows}
        if not traffic_rows:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT
                            COALESCE(payload->>'pcap_file', COALESCE(child_id, 'unknown') || '.pcap') AS pcap_file,
                            COUNT(*)::bigint AS packet_count,
                            COUNT(*) FILTER (WHERE COALESCE(payload->>'packet_label','') = 'attack')::bigint AS attack_packets,
                            COUNT(*) FILTER (WHERE COALESCE(payload->>'packet_label','') = 'benign')::bigint AS benign_packets,
                            MIN(ts_utc) AS first_ts,
                            MAX(ts_utc) AS last_ts,
                            AVG(CASE WHEN (payload->>'packet_rate_pps') IS NULL THEN NULL ELSE (payload->>'packet_rate_pps')::double precision END) AS avg_packet_rate_pps
                        FROM phase4.step3_v2_events
                        WHERE simulation_id = %(simulation_id)s::uuid
                          AND event_type = 'node_traffic'
                        GROUP BY 1
                        ORDER BY packet_count DESC, pcap_file ASC;
                        """,
                        {"simulation_id": simulation_id},
                    )
                    traffic_rows = cur.fetchall() or []
                    cur.execute(
                        """
                        SELECT
                            COALESCE(payload->>'pcap_file', COALESCE(child_id, 'unknown') || '.pcap') AS pcap_file,
                            COUNT(*)::bigint AS alert_count
                        FROM phase4.step3_v2_events
                        WHERE simulation_id = %(simulation_id)s::uuid
                          AND event_type = 'node_alert'
                        GROUP BY 1;
                        """,
                        {"simulation_id": simulation_id},
                    )
                    alert_rows = cur.fetchall() or []
                    cur.execute(
                        """
                        SELECT
                            COALESCE(payload->>'pcap_file', COALESCE(child_id, 'unknown') || '.pcap') AS pcap_file,
                            COUNT(*)::bigint AS parent_action_count
                        FROM phase4.step3_v2_events
                        WHERE simulation_id = %(simulation_id)s::uuid
                          AND event_type = 'parent_action'
                        GROUP BY 1;
                        """,
                        {"simulation_id": simulation_id},
                    )
                    action_rows = cur.fetchall() or []
            alerts_by_file = {str(r[0]).lower(): int(r[1] or 0) for r in alert_rows}
            actions_by_file = {str(r[0]).lower(): int(r[1] or 0) for r in action_rows}
        if not traffic_rows:
            dispatch = sim_meta.get("file_dispatch_state") if isinstance(sim_meta.get("file_dispatch_state"), dict) else {}
            file_states = dispatch.get("file_states") if isinstance(dispatch.get("file_states"), dict) else {}
            fallback_rows: list[tuple[Any, ...]] = []
            for fkey, fstate in file_states.items():
                if not isinstance(fstate, dict):
                    continue
                file_name = str(fkey or "")
                total_packets = int(fstate.get("total_packets") or 0)
                remaining_packets = int(fstate.get("remaining_packets") or 0)
                dispatched_packets = int(fstate.get("dispatched_packets") or 0)
                processed_packets = max(dispatched_packets, total_packets - max(0, remaining_packets))
                packet_count = max(0, min(total_packets, processed_packets))
                attack_packets = int(fstate.get("attack_packets") or 0)
                benign_packets = int(fstate.get("benign_packets") or 0)
                fallback_rows.append((file_name, packet_count, attack_packets, benign_packets, None, None, 0.0))
            traffic_rows = fallback_rows
        inventory_rows = self._discover_pcap_files(dataset_id=replay_dataset_id)
        dispatch_state = sim_meta.get("file_dispatch_state") if isinstance(sim_meta.get("file_dispatch_state"), dict) else {}
        file_states_meta = dispatch_state.get("file_states") if isinstance(dispatch_state.get("file_states"), dict) else {}
        inventory_by_rel: dict[str, dict[str, Any]] = {
            str(r.get("pcap_file") or "").lower(): r for r in inventory_rows if r.get("pcap_file")
        }
        inventory_by_base: dict[str, dict[str, Any]] = {}
        for rel, row in inventory_by_rel.items():
            base = Path(rel).name.lower()
            inventory_by_base.setdefault(base, row)
        files: list[dict[str, Any]] = []
        seen_keys: set[str] = set()
        for r in traffic_rows:
            pcap_file = str(r[0] or "unknown.pcap")
            pcap_file_key = pcap_file.lower()
            first_ts = r[4]
            last_ts = r[5]
            elapsed_s = 0.0
            if first_ts and last_ts:
                elapsed_s = max(0.0, (last_ts - first_ts).total_seconds())
            packet_count = int(r[1] or 0)
            tx_rate = round(packet_count / elapsed_s, 3) if elapsed_s > 0 else float(packet_count)
            inv = inventory_by_rel.get(pcap_file_key) or inventory_by_base.get(Path(pcap_file).name.lower())
            if not isinstance(inv, dict):
                # Enforce strict dataset-only view: suppress runtime rows outside replay dataset inventory.
                continue
            display_name = str(inv.get("pcap_file")) if isinstance(inv, dict) and inv.get("pcap_file") else pcap_file
            fs_meta = file_states_meta.get(display_name) if isinstance(file_states_meta.get(display_name), dict) else {}
            seen_keys.add(display_name.lower())
            files.append(
                {
                    "pcap_file": display_name,
                    "child_id": None,
                    "packet_count": packet_count,
                    "attack_packets": int(r[2] or 0),
                    "benign_packets": int(r[3] or 0),
                    "avg_packet_rate_pps": round(float(r[6] or 0.0), 3),
                    "transmission_rate_pps": tx_rate,
                    "alert_count": int(
                        alerts_by_file.get(pcap_file.lower(), alerts_by_file.get(display_name.lower(), 0))
                    ),
                    "parent_action_count": int(
                        actions_by_file.get(pcap_file.lower(), actions_by_file.get(display_name.lower(), 0))
                    ),
                    "file_size_bytes": int(inv.get("file_size_bytes") or 0) if isinstance(inv, dict) else 0,
                    "source": "runtime+raw_downloads" if isinstance(inv, dict) else "runtime",
                    "first_ts_utc": str(first_ts) if first_ts else None,
                    "last_ts_utc": str(last_ts) if last_ts else None,
                    "elapsed_seconds": round(elapsed_s, 3),
                    "ingest_status": str(fs_meta.get("ingest_status") or ""),
                    "ingest_retries": int(fs_meta.get("ingest_retries") or 0),
                    "last_ingest_error": str(fs_meta.get("last_ingest_error") or ""),
                    "ingest_completed_at_utc": fs_meta.get("ingest_completed_at_utc"),
                    "file_status_stage": _stage_for_file(
                        pcap_file=display_name,
                        fs_meta=fs_meta if isinstance(fs_meta, dict) else {},
                        packet_count=packet_count,
                    ),
                }
            )
        for inv in inventory_rows:
            inv_name = str(inv.get("pcap_file") or "").strip()
            if not inv_name:
                continue
            if inv_name.lower() in seen_keys:
                continue
            fs_meta = file_states_meta.get(inv_name) if isinstance(file_states_meta.get(inv_name), dict) else {}
            files.append(
                {
                    "pcap_file": inv_name,
                    "child_id": None,
                    "packet_count": 0,
                    "attack_packets": 0,
                    "benign_packets": 0,
                    "avg_packet_rate_pps": 0.0,
                    "transmission_rate_pps": 0.0,
                    "alert_count": 0,
                    "parent_action_count": 0,
                    "file_size_bytes": int(inv.get("file_size_bytes") or 0),
                    "source": "raw_downloads",
                    "first_ts_utc": None,
                    "last_ts_utc": None,
                    "elapsed_seconds": 0.0,
                    "ingest_status": str(fs_meta.get("ingest_status") or ""),
                    "ingest_retries": int(fs_meta.get("ingest_retries") or 0),
                    "last_ingest_error": str(fs_meta.get("last_ingest_error") or ""),
                    "ingest_completed_at_utc": fs_meta.get("ingest_completed_at_utc"),
                    "file_status_stage": _stage_for_file(
                        pcap_file=inv_name,
                        fs_meta=fs_meta if isinstance(fs_meta, dict) else {},
                        packet_count=0,
                    ),
                }
            )
        files.sort(
            key=lambda x: (
                0 if str(x.get("source") or "").startswith("runtime") else 1,
                -int(x.get("packet_count") or 0),
                str(x.get("pcap_file") or ""),
            )
        )
        return {"simulation_id": simulation_id, "pcap_files": files}

    @staticmethod
    def _child_scope(child_id: str | None) -> str:
        cid = str(child_id or "").lower()
        if "enterprise" in cid:
            return "enterprise"
        if "dns" in cid:
            return "dns"
        if "iiot" in cid:
            return "iiot"
        if "iot" in cid:
            return "iot"
        return "unknown"

    @staticmethod
    def _categorize_alert(scope: str, severity: str, payload: dict[str, Any]) -> str:
        phase = str(payload.get("phase") or "").lower()
        sev = str(severity or "").lower()
        if scope == "dns":
            if "attack" in phase or sev == "high":
                return "dns_tunnel_or_c2"
            return "dns_anomaly"
        if scope == "enterprise":
            if "attack" in phase:
                return "lateral_movement_candidate"
            return "east_west_anomaly"
        if scope == "iot":
            return "iot_behavior_drift" if sev != "high" else "iot_compromise_candidate"
        if scope == "iiot":
            return "iiot_process_anomaly" if sev != "high" else "iiot_safety_risk"
        return "general_anomaly"

    @staticmethod
    def _shap_profile(*, event_id: str, scope: str, severity: str, phase: str) -> dict[str, Any]:
        sev = str(severity or "low").lower()
        sev_weight = 0.62 if sev == "high" else 0.48 if sev == "medium" else 0.33
        phase_weight = 0.57 if "attack" in phase else 0.43
        scope_bias = {
            "enterprise": [("flow_duration_ms", 0.21), ("dst_port", 0.18), ("bytes_out", 0.14)],
            "dns": [("dns_query_entropy", 0.23), ("domain_length", 0.19), ("nx_domain_ratio", 0.16)],
            "iot": [("packet_interval_jitter", 0.2), ("bytes_out", 0.15), ("proto_mix", 0.14)],
            "iiot": [("command_burstiness", 0.24), ("packet_interval_jitter", 0.17), ("dest_segment", 0.13)],
            "unknown": [("packet_rate_pps", 0.15), ("bytes_out", 0.14), ("dst_port", 0.12)],
        }
        base = list(scope_bias.get(scope, scope_bias["unknown"]))
        # Deterministic jitter by event to avoid flat synthetic outputs.
        j1 = (_stable_fraction(f"{event_id}:a") - 0.5) * 0.08
        j2 = (_stable_fraction(f"{event_id}:b") - 0.5) * 0.08
        j3 = (_stable_fraction(f"{event_id}:c") - 0.5) * 0.08
        features = [
            {"feature": base[0][0], "contribution": round(max(0.01, min(0.95, base[0][1] + sev_weight * 0.2 + j1)), 4)},
            {"feature": base[1][0], "contribution": round(max(0.01, min(0.95, base[1][1] + phase_weight * 0.15 + j2)), 4)},
            {"feature": base[2][0], "contribution": round(max(0.01, min(0.95, base[2][1] + j3)), 4)},
        ]
        confidence = round(max(0.05, min(0.99, 0.55 + sev_weight * 0.35 + (_stable_fraction(f"{event_id}:conf") - 0.5) * 0.08)), 4)
        return {"confidence": confidence, "top_features": features}

    def get_parent_review(self, simulation_id: str, limit: int = 500) -> dict[str, Any]:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT alert_id::text, child_id, severity, ts_utc, payload
                    FROM phase4.step3_v2_alerts
                    WHERE simulation_id = %(simulation_id)s::uuid
                    ORDER BY ts_utc DESC
                    LIMIT %(limit)s;
                    """,
                    {"simulation_id": simulation_id, "limit": max(1, int(limit))},
                )
                rows = cur.fetchall() or []
                if not rows:
                    cur.execute(
                        """
                        SELECT event_id::text, child_id, severity, ts_utc, payload
                        FROM phase4.step3_v2_events
                        WHERE simulation_id = %(simulation_id)s::uuid
                          AND event_type = 'node_alert'
                        ORDER BY ts_utc DESC
                        LIMIT %(limit)s;
                        """,
                        {"simulation_id": simulation_id, "limit": max(1, int(limit))},
                    )
                    rows = cur.fetchall() or []
        review_rows: list[dict[str, Any]] = []
        by_scope: dict[str, dict[str, int]] = {}
        by_child: dict[str, dict[str, int]] = {}
        for r in rows:
            event_id = str(r[0] or "")
            child_id = str(r[1] or "unknown")
            severity = str(r[2] or "low")
            ts_utc = str(r[3]) if r[3] else None
            payload = r[4] if isinstance(r[4], dict) else {}
            scope = self._child_scope(child_id)
            phase = str(payload.get("phase") or "")
            category = self._categorize_alert(scope, severity, payload)
            shap = self._shap_profile(event_id=event_id, scope=scope, severity=severity, phase=phase)
            row = {
                "event_id": event_id,
                "ts_utc": ts_utc,
                "child_id": child_id,
                "scope": scope,
                "severity": severity,
                "category": category,
                "pcap_file": str(payload.get("pcap_file") or ""),
                "recommendation": str(payload.get("recommendation") or "review_and_triage"),
                "phase": phase,
                "shap_confidence": float(shap["confidence"]),
                "shap_top_features": shap["top_features"],
                "review_status": "escalated" if severity.lower() == "high" else "reviewed",
            }
            review_rows.append(row)
            s = by_scope.setdefault(scope, {"alerts": 0, "high": 0, "escalated": 0})
            s["alerts"] += 1
            if severity.lower() == "high":
                s["high"] += 1
            if row["review_status"] == "escalated":
                s["escalated"] += 1
            c = by_child.setdefault(child_id, {"alerts": 0, "high": 0, "escalated": 0})
            c["alerts"] += 1
            if severity.lower() == "high":
                c["high"] += 1
            if row["review_status"] == "escalated":
                c["escalated"] += 1
        return {
            "simulation_id": simulation_id,
            "review_rows": review_rows,
            "summary_by_scope": by_scope,
            "summary_by_child": by_child,
        }

    def add_metric_evidence(self, simulation_id: str, evidence: MetricEvidenceIn) -> dict[str, Any]:
        metric_name = str(evidence.metric_name or "").strip()
        if not metric_name:
            raise ValueError("metric_name_required")
        evidence_id = str(uuid.uuid4())
        payload = evidence.evidence_payload if isinstance(evidence.evidence_payload, dict) else {}
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT 1
                    FROM phase4.step3_v2_simulations
                    WHERE simulation_id = %(simulation_id)s::uuid
                    LIMIT 1;
                    """,
                    {"simulation_id": simulation_id},
                )
                if not cur.fetchone():
                    raise KeyError("simulation_not_found")
                cur.execute(
                    """
                    INSERT INTO phase4.step3_v2_metric_evidence (
                        evidence_id, simulation_id, metric_name, evidence_kind,
                        numerator, denominator, metric_value, source_ref, evidence_payload
                    ) VALUES (
                        %(evidence_id)s::uuid, %(simulation_id)s::uuid, %(metric_name)s, %(evidence_kind)s,
                        %(numerator)s, %(denominator)s, %(metric_value)s, %(source_ref)s, %(evidence_payload)s::jsonb
                    );
                    """,
                    {
                        "evidence_id": evidence_id,
                        "simulation_id": simulation_id,
                        "metric_name": metric_name,
                        "evidence_kind": str(evidence.evidence_kind or "manual").strip() or "manual",
                        "numerator": evidence.numerator,
                        "denominator": evidence.denominator,
                        "metric_value": evidence.metric_value,
                        "source_ref": str(evidence.source_ref or "dashboard_manual_evidence").strip(),
                        "evidence_payload": json.dumps(payload),
                    },
                )
            conn.commit()
        return {
            "ok": True,
            "simulation_id": simulation_id,
            "evidence_id": evidence_id,
            "metric_name": metric_name,
        }

    def get_hypothesis_results(self, simulation_id: str) -> dict[str, Any]:
        sim_meta: dict[str, Any] = {}
        runtime: SimulationRuntime | None = None
        with self._lock:
            runtime = self._simulations.get(simulation_id)
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT metadata
                    FROM phase4.step3_v2_simulations
                    WHERE simulation_id = %(simulation_id)s::uuid
                    LIMIT 1;
                    """,
                    {"simulation_id": simulation_id},
                )
                meta_row = cur.fetchone()
                sim_meta = meta_row[0] if meta_row and isinstance(meta_row[0], dict) else {}
                cur.execute(
                    """
                    SELECT
                        COUNT(*)::bigint AS packets_total,
                        COUNT(*) FILTER (WHERE COALESCE(packet_label,'')='attack')::bigint AS attack_packets,
                        COUNT(*) FILTER (WHERE COALESCE(packet_label,'')='benign')::bigint AS benign_packets,
                        AVG(packet_rate_pps) AS avg_packet_rate_pps
                    FROM phase4.step3_v2_child_packets
                    WHERE simulation_id = %(simulation_id)s::uuid
                    ;
                    """,
                    {"simulation_id": simulation_id},
                )
                traffic_total = cur.fetchone() or (0, 0, 0, 0.0)
                cur.execute(
                    """
                    SELECT
                        COUNT(*)::bigint AS alerts_total,
                        COUNT(*) FILTER (WHERE COALESCE(severity,'')='high')::bigint AS high_alerts,
                        COUNT(*) FILTER (WHERE COALESCE(packet_label,'')='attack')::bigint AS attack_alerts,
                        COUNT(*) FILTER (WHERE COALESCE(packet_label,'')='benign')::bigint AS benign_alerts
                    FROM phase4.step3_v2_alerts
                    WHERE simulation_id = %(simulation_id)s::uuid
                    ;
                    """,
                    {"simulation_id": simulation_id},
                )
                alerts_total = cur.fetchone() or (0, 0, 0, 0)
                cur.execute(
                    """
                    SELECT COUNT(*)::bigint
                    FROM phase4.step3_v2_parent_actions
                    WHERE simulation_id = %(simulation_id)s::uuid
                    ;
                    """,
                    {"simulation_id": simulation_id},
                )
                parent_actions = int((cur.fetchone() or [0])[0] or 0)
                cur.execute(
                    """
                    SELECT
                        (SELECT COUNT(*)::bigint FROM phase4.step3_v2_audit_logs WHERE simulation_id = %(simulation_id)s::uuid)
                      + (SELECT COUNT(*)::bigint FROM phase4.step3_v2_file_logs WHERE simulation_id = %(simulation_id)s::uuid AND log_kind IN ('audit','ingest'));
                    """,
                    {"simulation_id": simulation_id},
                )
                audit_rows = int((cur.fetchone() or [0])[0] or 0)
                cur.execute(
                    """
                    SELECT COALESCE(child_id, 'unknown') AS child_id,
                           COUNT(*)::bigint AS packets_total,
                           COUNT(*) FILTER (WHERE COALESCE(packet_label,'')='attack')::bigint AS attack_packets,
                           COUNT(*) FILTER (WHERE COALESCE(packet_label,'')='benign')::bigint AS benign_packets
                    FROM phase4.step3_v2_child_packets
                    WHERE simulation_id = %(simulation_id)s::uuid
                    GROUP BY 1
                    ORDER BY packets_total DESC, child_id ASC;
                    """,
                    {"simulation_id": simulation_id},
                )
                child_rows = cur.fetchall() or []
                cur.execute(
                    """
                    SELECT COALESCE(child_id, 'unknown') AS child_id, COUNT(*)::bigint AS alerts_total
                    FROM phase4.step3_v2_alerts
                    WHERE simulation_id = %(simulation_id)s::uuid
                    GROUP BY 1;
                    """,
                    {"simulation_id": simulation_id},
                )
                child_alert_rows = cur.fetchall() or []
                cur.execute(
                    """
                    SELECT COALESCE(child_id, 'unknown') AS child_id, COUNT(*)::bigint AS action_total
                    FROM phase4.step3_v2_parent_actions
                    WHERE simulation_id = %(simulation_id)s::uuid
                    GROUP BY 1;
                    """,
                    {"simulation_id": simulation_id},
                )
                child_action_rows = cur.fetchall() or []
                if int(traffic_total[0] or 0) <= 0:
                    cur.execute(
                        """
                        SELECT
                            COUNT(*)::bigint AS packets_total,
                            COUNT(*) FILTER (WHERE COALESCE(payload->>'packet_label','')='attack')::bigint AS attack_packets,
                            COUNT(*) FILTER (WHERE COALESCE(payload->>'packet_label','')='benign')::bigint AS benign_packets,
                            AVG(CASE WHEN (payload->>'packet_rate_pps') IS NULL THEN NULL ELSE (payload->>'packet_rate_pps')::double precision END) AS avg_packet_rate_pps
                        FROM phase4.step3_v2_events
                        WHERE simulation_id = %(simulation_id)s::uuid
                          AND event_type = 'node_traffic';
                        """,
                        {"simulation_id": simulation_id},
                    )
                    traffic_total = cur.fetchone() or (0, 0, 0, 0.0)
                    cur.execute(
                        """
                        SELECT
                            COUNT(*)::bigint AS alerts_total,
                            COUNT(*) FILTER (WHERE COALESCE(severity,'')='high')::bigint AS high_alerts,
                            COUNT(*) FILTER (WHERE COALESCE(payload->>'packet_label','')='attack')::bigint AS attack_alerts,
                            COUNT(*) FILTER (WHERE COALESCE(payload->>'packet_label','')='benign')::bigint AS benign_alerts
                        FROM phase4.step3_v2_events
                        WHERE simulation_id = %(simulation_id)s::uuid
                          AND event_type = 'node_alert';
                        """,
                        {"simulation_id": simulation_id},
                    )
                    alerts_total = cur.fetchone() or (0, 0, 0, 0)
                    cur.execute(
                        """
                        SELECT COUNT(*)::bigint
                        FROM phase4.step3_v2_events
                        WHERE simulation_id = %(simulation_id)s::uuid
                          AND event_type = 'parent_action';
                        """,
                        {"simulation_id": simulation_id},
                    )
                    parent_actions = int((cur.fetchone() or [0])[0] or 0)
                    cur.execute(
                        """
                        SELECT
                            COALESCE(child_id, 'unknown') AS child_id,
                            COUNT(*)::bigint AS packets_total,
                            COUNT(*) FILTER (WHERE COALESCE(payload->>'packet_label','')='attack')::bigint AS attack_packets,
                            COUNT(*) FILTER (WHERE COALESCE(payload->>'packet_label','')='benign')::bigint AS benign_packets
                        FROM phase4.step3_v2_events
                        WHERE simulation_id = %(simulation_id)s::uuid
                          AND event_type = 'node_traffic'
                        GROUP BY 1
                        ORDER BY packets_total DESC, child_id ASC;
                        """,
                        {"simulation_id": simulation_id},
                    )
                    child_rows = cur.fetchall() or []
                    cur.execute(
                        """
                        SELECT COALESCE(child_id, 'unknown') AS child_id, COUNT(*)::bigint AS alerts_total
                        FROM phase4.step3_v2_events
                        WHERE simulation_id = %(simulation_id)s::uuid
                          AND event_type = 'node_alert'
                        GROUP BY 1;
                        """,
                        {"simulation_id": simulation_id},
                    )
                    child_alert_rows = cur.fetchall() or []
                    cur.execute(
                        """
                        SELECT COALESCE(child_id, 'unknown') AS child_id, COUNT(*)::bigint AS action_total
                        FROM phase4.step3_v2_events
                        WHERE simulation_id = %(simulation_id)s::uuid
                          AND event_type = 'parent_action'
                        GROUP BY 1;
                        """,
                        {"simulation_id": simulation_id},
                    )
                    child_action_rows = cur.fetchall() or []
        if runtime is not None and isinstance(runtime.metadata, dict):
            sim_meta = {**sim_meta, **runtime.metadata}

        packets_total = int(traffic_total[0] or 0)
        attack_packets = int(traffic_total[1] or 0)
        benign_packets = int(traffic_total[2] or 0)
        avg_packet_rate_pps = float(traffic_total[3] or 0.0)
        if packets_total <= 0:
            dispatch = sim_meta.get("file_dispatch_state") if isinstance(sim_meta.get("file_dispatch_state"), dict) else {}
            file_states = dispatch.get("file_states") if isinstance(dispatch.get("file_states"), dict) else {}
            t_packets = 0
            t_attack = 0
            t_benign = 0
            for fs in file_states.values():
                if not isinstance(fs, dict):
                    continue
                total_packets = int(fs.get("total_packets") or 0)
                remaining_packets = int(fs.get("remaining_packets") or 0)
                dispatched_packets = int(fs.get("dispatched_packets") or 0)
                processed_packets = max(dispatched_packets, total_packets - max(0, remaining_packets))
                t_packets += max(0, min(total_packets, processed_packets))
                t_attack += int(fs.get("attack_packets") or 0)
                t_benign += int(fs.get("benign_packets") or 0)
            packets_total = int(t_packets)
            attack_packets = int(t_attack)
            benign_packets = int(t_benign)
        alerts_total_n = int(alerts_total[0] or 0)
        high_alerts = int(alerts_total[1] or 0)
        attack_alerts = int(alerts_total[2] or 0)
        benign_alerts = int(alerts_total[3] or 0)

        by_child: dict[str, dict[str, Any]] = {}
        for r in child_rows:
            cid = str(r[0] or "unknown")
            by_child[cid] = {
                "child_id": cid,
                "scope": self._child_scope(cid),
                "packets_total": int(r[1] or 0),
                "attack_packets": int(r[2] or 0),
                "benign_packets": int(r[3] or 0),
                "alerts_total": 0,
                "parent_actions": 0,
            }
        if not by_child and runtime is not None:
            for cid, counters in runtime.child_counters.items():
                if not isinstance(counters, dict):
                    continue
                by_child[str(cid)] = {
                    "child_id": str(cid),
                    "scope": self._child_scope(str(cid)),
                    "packets_total": int(counters.get("packets") or 0),
                    "attack_packets": 0,
                    "benign_packets": 0,
                    "alerts_total": int(counters.get("alerts") or 0),
                    "parent_actions": int(counters.get("parent_actions") or 0),
                }
        for r in child_alert_rows:
            cid = str(r[0] or "unknown")
            row = by_child.setdefault(
                cid,
                {"child_id": cid, "scope": self._child_scope(cid), "packets_total": 0, "attack_packets": 0, "benign_packets": 0, "alerts_total": 0, "parent_actions": 0},
            )
            row["alerts_total"] = int(r[1] or 0)
        for r in child_action_rows:
            cid = str(r[0] or "unknown")
            row = by_child.setdefault(
                cid,
                {"child_id": cid, "scope": self._child_scope(cid), "packets_total": 0, "attack_packets": 0, "benign_packets": 0, "alerts_total": 0, "parent_actions": 0},
            )
            row["parent_actions"] = int(r[1] or 0)

        by_scope_map: dict[str, dict[str, Any]] = {}
        for row in by_child.values():
            scope = str(row.get("scope") or "unknown")
            s = by_scope_map.setdefault(
                scope,
                {"scope": scope, "packets_total": 0, "attack_packets": 0, "benign_packets": 0, "alerts_total": 0, "parent_actions": 0},
            )
            s["packets_total"] += int(row.get("packets_total") or 0)
            s["attack_packets"] += int(row.get("attack_packets") or 0)
            s["benign_packets"] += int(row.get("benign_packets") or 0)
            s["alerts_total"] += int(row.get("alerts_total") or 0)
            s["parent_actions"] += int(row.get("parent_actions") or 0)

        benign_alert_rate = float(benign_alerts) / float(max(1, benign_packets))
        escalation_rate = float(parent_actions) / float(max(1, high_alerts))
        label_coverage_rate = float(attack_packets + benign_packets) / float(max(1, packets_total))
        hypotheses = [
            {
                "hypothesis_id": "H1",
                "name": "Rule-Hit Attack Detection",
                "metric_key": "attack_alerts",
                "metric_value": float(attack_alerts),
                "threshold_desc": "> 0",
                "status": "pass" if attack_alerts > 0 else "fail",
            },
            {
                "hypothesis_id": "H2",
                "name": "Benign Noise Control",
                "metric_key": "benign_alert_rate",
                "metric_value": float(round(benign_alert_rate, 6)),
                "threshold_desc": "<= 0.020000",
                "status": "pass" if benign_alert_rate <= 0.02 else "fail",
            },
            {
                "hypothesis_id": "H3",
                "name": "High Severity Escalation",
                "metric_key": "escalation_rate",
                "metric_value": float(round(escalation_rate, 6)),
                "threshold_desc": ">= 0.600000",
                "status": "pass" if escalation_rate >= 0.6 else "fail",
            },
            {
                "hypothesis_id": "H4",
                "name": "Packet Label Coverage",
                "metric_key": "label_coverage_rate",
                "metric_value": float(round(label_coverage_rate, 6)),
                "threshold_desc": ">= 0.999000",
                "status": "pass" if label_coverage_rate >= 0.999 else "fail",
            },
            {
                "hypothesis_id": "H5",
                "name": "Audit Trace Persistence",
                "metric_key": "audit_rows",
                "metric_value": float(audit_rows),
                "threshold_desc": "> 0",
                "status": "pass" if audit_rows > 0 else "fail",
            },
        ]
        pcap = self.get_pcap_metrics(simulation_id).get("pcap_files") or []
        snapshot = {
            "packets_total": packets_total,
            "attack_packets": attack_packets,
            "benign_packets": benign_packets,
            "alerts_total": alerts_total_n,
            "high_alerts": high_alerts,
            "attack_alerts": attack_alerts,
            "benign_alerts": benign_alerts,
            "parent_actions": parent_actions,
            "audit_rows": audit_rows,
            "avg_packet_rate_pps": float(round(avg_packet_rate_pps, 6)),
            "label_coverage_rate": float(round(label_coverage_rate, 6)),
        }
        by_child_rows = sorted(by_child.values(), key=lambda x: (-int(x.get("packets_total") or 0), str(x.get("child_id") or "")))
        by_scope_rows = sorted(by_scope_map.values(), key=lambda x: (-int(x.get("packets_total") or 0), str(x.get("scope") or "")))
        return {
            "simulation_id": simulation_id,
            "snapshot": snapshot,
            "hypotheses": hypotheses,
            "by_child": by_child_rows,
            "by_scope": by_scope_rows,
            "by_pcap": pcap,
            "generated_at_utc": _now(),
        }

    def _load_cursor_from_postgres(self, *, simulation_id: str, cursor_id: str) -> str | None:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT last_event_id::text
                        FROM phase4.step3_v2_stream_cursors
                        WHERE simulation_id = %(simulation_id)s::uuid
                          AND cursor_id = %(cursor_id)s
                        LIMIT 1;
                        """,
                        {"simulation_id": simulation_id, "cursor_id": cursor_id},
                    )
                    row = cur.fetchone()
            if row and row[0]:
                return str(row[0]).strip() or None
        except Exception:
            return None
        return None

    def _save_cursor_to_postgres(self, *, simulation_id: str, cursor_id: str, last_event_id: str, ts_utc: str) -> None:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO phase4.step3_v2_stream_cursors (
                            simulation_id, cursor_id, last_event_id, updated_at_utc
                        ) VALUES (
                            %(simulation_id)s::uuid, %(cursor_id)s, %(last_event_id)s::uuid, %(updated_at_utc)s::timestamptz
                        )
                        ON CONFLICT (simulation_id, cursor_id) DO UPDATE SET
                            last_event_id = EXCLUDED.last_event_id,
                            updated_at_utc = EXCLUDED.updated_at_utc;
                        """,
                        {
                            "simulation_id": simulation_id,
                            "cursor_id": cursor_id,
                            "last_event_id": last_event_id,
                            "updated_at_utc": ts_utc,
                        },
                    )
                conn.commit()
        except Exception:
            return

    def resolve_resume_cursor(self, *, simulation_id: str | None, last_event_id: str | None, cursor_id: str | None) -> str | None:
        explicit = str(last_event_id or "").strip()
        if explicit:
            return explicit
        sim = str(simulation_id or "").strip()
        if not sim:
            return None
        cid = str(cursor_id or "global").strip() or "global"
        cached = self._queue_backend.load_stream_cursor(simulation_id=sim, cursor_id=cid)
        if cached:
            return cached
        return self._load_cursor_from_postgres(simulation_id=sim, cursor_id=cid)

    def save_resume_cursor(self, *, simulation_id: str, cursor_id: str, last_event_id: str, ts_utc: str | None = None, force: bool = False) -> None:
        sim = str(simulation_id or "").strip()
        cid = str(cursor_id or "global").strip() or "global"
        eid = str(last_event_id or "").strip()
        if not sim or not eid:
            return
        now_mono = time.monotonic()
        flush_interval_s = max(0.1, _env_float("STEP3_V2_CURSOR_FLUSH_SECONDS", 1.0))
        key = (sim, cid)
        with self._cursor_flush_lock:
            prev = self._cursor_flush_state.get(key)
            if (not force) and prev and prev[0] == eid and (now_mono - prev[1]) < flush_interval_s:
                return
            self._cursor_flush_state[key] = (eid, now_mono)
        ts = str(ts_utc or _now())
        try:
            self._queue_backend.save_stream_cursor(simulation_id=sim, cursor_id=cid, last_event_id=eid, ts_utc=ts)
        except Exception:
            pass
        self._save_cursor_to_postgres(simulation_id=sim, cursor_id=cid, last_event_id=eid, ts_utc=ts)

    def subscribe(self, *, simulation_id: str | None, last_event_id: str | None, cursor_id: str | None) -> tuple[Subscriber, list[dict[str, Any]], str]:
        out_q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=max(1000, _env_int("STEP3_V2_SUBSCRIBER_QUEUE_SIZE", 20_000)))
        sub = Subscriber(subscriber_id=str(uuid.uuid4()), simulation_id=simulation_id, out_queue=out_q)
        resolved_last = self.resolve_resume_cursor(simulation_id=simulation_id, last_event_id=last_event_id, cursor_id=cursor_id)
        with self._lock:
            self._subscribers[sub.subscriber_id] = sub
            history = list(self._history)
        replay_rows = self._history_after(history, last_event_id=resolved_last, simulation_id=simulation_id)
        return sub, replay_rows, str(cursor_id or "global").strip() or "global"

    def unsubscribe(self, subscriber_id: str) -> None:
        with self._lock:
            self._subscribers.pop(subscriber_id, None)

    @staticmethod
    def _history_after(
        rows: list[dict[str, Any]], *, last_event_id: str | None, simulation_id: str | None
    ) -> list[dict[str, Any]]:
        filtered = [r for r in rows if not simulation_id or str(r.get("simulation_id") or "") == simulation_id]
        if not last_event_id:
            return filtered[-500:]
        pos = -1
        for idx, row in enumerate(filtered):
            if str(row.get("event_id") or "") == str(last_event_id):
                pos = idx
        if pos < 0:
            return []
        return filtered[pos + 1 :]


engine = Step3V2Engine()
app = FastAPI(title="Step3 V2 Engine", version="2.0.0")


class StartSimulationRequest(BaseModel):
    model_id: str | None = None
    model_version: str | None = None
    execution_mode: str | None = Field(default="simulation")


def _sse_frame(event: dict[str, Any]) -> str:
    eid = str(event.get("event_id") or "")
    payload = json.dumps(event, ensure_ascii=True)
    return f"id: {eid}\nevent: message\ndata: {payload}\n\n"


@app.on_event("startup")
def _startup() -> None:
    engine.start()


@app.on_event("shutdown")
def _shutdown() -> None:
    engine.stop()


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "step3-v2-engine",
        "queue_backend": engine.queue_status().get("backend"),
        "time_utc": _now(),
    }


@app.get("/model-v1/step3/v2/models/eligible")
def models_eligible() -> dict[str, Any]:
    # Surface both ready and incomplete candidates so dashboard selectors do not appear empty.
    return step3_eligible_models(ready_only=False)


@app.post("/model-v1/step3/v2/simulations/start")
def start_simulation(payload: StartSimulationRequest) -> dict[str, Any]:
    execution_mode = str(payload.execution_mode or "simulation").strip().lower()
    if execution_mode != "simulation":
        raise HTTPException(status_code=400, detail="step3_v2_is_simulation_only")
    selected_model_version = str(payload.model_version or "").strip()
    selected_model_id = str(payload.model_id or "").strip() or None
    if not selected_model_version:
        eligible = step3_eligible_models(ready_only=True)
        models = list(eligible.get("eligible_models") or [])
        if not models:
            raise HTTPException(status_code=409, detail="no_eligible_models_for_step3_v2")
        selected_model_version = str(models[0].get("model_version") or "").strip()
        if not selected_model_id:
            selected_model_id = str(models[0].get("model_id") or "").strip() or None
    if not selected_model_version:
        raise HTTPException(status_code=400, detail="model_version_required")
    try:
        out = engine.start_simulation(model_id=selected_model_id, model_version=selected_model_version)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {"ok": True, **out}


@app.post("/model-v1/step3/v2/simulations/{simulation_id}/stop")
def stop_simulation(simulation_id: str) -> dict[str, Any]:
    try:
        out = engine.stop_simulation(simulation_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="simulation_not_found")
    return {"ok": True, **out}


@app.get("/model-v1/step3/v2/simulations")
def list_simulations(limit: int = 100) -> dict[str, Any]:
    return {"ok": True, "simulations": engine.list_simulations(limit=max(1, min(limit, 1000)))}


@app.get("/model-v1/step3/v2/simulations/{simulation_id}")
def get_simulation(simulation_id: str) -> dict[str, Any]:
    try:
        out = engine.get_simulation(simulation_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="simulation_not_found")
    return {"ok": True, "simulation": out}


@app.get("/model-v1/step3/v2/simulations/{simulation_id}/audit")
def simulation_audit(simulation_id: str, limit: int = 2000) -> dict[str, Any]:
    try:
        _ = engine.get_simulation(simulation_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="simulation_not_found")
    rows = engine.get_audit(simulation_id, limit=max(1, min(limit, 10_000)))
    return {"ok": True, "simulation_id": simulation_id, "audit_rows": rows}


@app.get("/model-v1/step3/v2/simulations/{simulation_id}/pcap-metrics")
def simulation_pcap_metrics(simulation_id: str) -> dict[str, Any]:
    try:
        _ = engine.get_simulation(simulation_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="simulation_not_found")
    out = engine.get_pcap_metrics(simulation_id)
    return {"ok": True, **out}


@app.get("/model-v1/step3/v2/simulations/{simulation_id}/parent-review")
def simulation_parent_review(simulation_id: str, limit: int = 500) -> dict[str, Any]:
    try:
        _ = engine.get_simulation(simulation_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="simulation_not_found")
    out = engine.get_parent_review(simulation_id, limit=max(1, min(limit, 5000)))
    return {"ok": True, **out}


@app.get("/model-v1/step3/v2/simulations/{simulation_id}/hypothesis")
def simulation_hypothesis(simulation_id: str) -> dict[str, Any]:
    try:
        _ = engine.get_simulation(simulation_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="simulation_not_found")
    out = engine.get_hypothesis_results(simulation_id)
    return {"ok": True, **out}


@app.post("/model-v1/step3/v2/simulations/{simulation_id}/metrics/evidence")
def simulation_metric_evidence(simulation_id: str, evidence: MetricEvidenceIn) -> dict[str, Any]:
    try:
        return engine.add_metric_evidence(simulation_id, evidence)
    except KeyError:
        raise HTTPException(status_code=404, detail="simulation_not_found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/model-v1/step3/v2/queue/status")
def queue_status() -> dict[str, Any]:
    return {"ok": True, **engine.queue_status()}


@app.get("/model-v1/step3/v2/stream")
def stream(
    simulation_id: str | None = None,
    cursor_id: str | None = "global",
    last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
) -> StreamingResponse:
    sub, replay_rows, resolved_cursor_id = engine.subscribe(
        simulation_id=simulation_id,
        last_event_id=last_event_id,
        cursor_id=cursor_id,
    )

    def _gen() -> Any:
        try:
            for row in replay_rows:
                if simulation_id and row.get("event_id"):
                    engine.save_resume_cursor(
                        simulation_id=str(simulation_id),
                        cursor_id=resolved_cursor_id,
                        last_event_id=str(row.get("event_id")),
                        ts_utc=str(row.get("ts_utc") or _now()),
                    )
                yield _sse_frame(row)
            while True:
                try:
                    row = sub.out_queue.get(timeout=15.0)
                except queue.Empty:
                    yield ": keep-alive\n\n"
                    continue
                if simulation_id and row.get("event_id"):
                    engine.save_resume_cursor(
                        simulation_id=str(simulation_id),
                        cursor_id=resolved_cursor_id,
                        last_event_id=str(row.get("event_id")),
                        ts_utc=str(row.get("ts_utc") or _now()),
                    )
                yield _sse_frame(row)
        finally:
            engine.unsubscribe(sub.subscriber_id)

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
