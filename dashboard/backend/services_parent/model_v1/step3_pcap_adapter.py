"""REP-01 PCAP adapter: segment, convert to replay events, push to Child client listener ports (UDP).

Does not touch Model V1 training or evaluation. Optional ``dpkt`` accelerates PCAP parsing;
otherwise a minimal file reader counts packets for phase sizing.
"""

from __future__ import annotations

import json
import struct
from concurrent.futures import Executor, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from services_parent.model_v1.step3_config import STEP3_ADAPTER_WORKERS, STEP3_REPLAY_MAX_WORKERS

try:
    import dpkt  # type: ignore[import-not-found]

    _HAS_DPKT = True
except Exception:
    _HAS_DPKT = False


REPLAY_PHASES = ("baseline", "attack_burst", "mixed_recovery", "domain_shift")


@dataclass
class ReplayChunk:
    phase: str
    chunk_index: int
    packet_count: int
    payload_bytes: int
    metadata: dict[str, Any]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def resolve_rep01_pcap_paths(data_root: Path) -> list[Path]:
    """Locate candidate REP-01 PCAP files under governed replay staging (best-effort)."""
    roots = [
        # Primary governed mount path from manifest/server scratch bind.
        data_root / "raw_downloads" / "REP-01",
        # Backward-compatible legacy replay staging path.
        data_root / "raw_downloads" / "replay" / "REP-01",
        data_root / "raw" / "REP-01",
        Path(__file__).resolve().parents[2] / "data" / "raw" / "REP-01",
    ]
    out: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for pat in ("**/*.pcap", "**/*.pcapng"):
            for p in root.glob(pat):
                if p.is_file() and p.stat().st_size > 0:
                    out.append(p)
    return sorted(set(out), key=lambda x: str(x))


def _pcap_packet_iter_legacy(fh: Any) -> Iterator[tuple[bytes, float | None]]:
    """Minimal PCAP (microsecond) reader without dpkt."""
    hdr = fh.read(24)
    if len(hdr) < 24:
        return
    magic = hdr[:4]
    # Parse by raw bytes to avoid host-endian confusion.
    if magic == b"\xd4\xc3\xb2\xa1":  # little-endian, microseconds
        le = True
        ts_scale = 1e-6
    elif magic == b"\xa1\xb2\xc3\xd4":  # big-endian, microseconds
        le = False
        ts_scale = 1e-6
    elif magic == b"\x4d\x3c\xb2\xa1":  # little-endian, nanoseconds
        le = True
        ts_scale = 1e-9
    elif magic == b"\xa1\xb2\x3c\x4d":  # big-endian, nanoseconds
        le = False
        ts_scale = 1e-9
    else:
        return

    def u32(off: int) -> int:
        return struct.unpack_from("<I" if le else ">I", hdr, off)[0]

    snaplen = u32(16)
    while True:
        ph = fh.read(16)
        if len(ph) < 16:
            break
        if le:
            ts_sec, ts_frac, incl_len, _orig = struct.unpack("<IIII", ph)
        else:
            ts_sec, ts_frac, incl_len, _orig = struct.unpack(">IIII", ph)
        if incl_len <= 0:
            continue
        if snaplen > 0 and incl_len > max(snaplen, 16 * 1024 * 1024):
            break
        ts = float(ts_sec) + float(ts_frac) * ts_scale
        buf = fh.read(incl_len)
        if len(buf) < incl_len:
            break
        if len(buf) > snaplen:
            buf = buf[:snaplen]
        yield buf, ts


def _pcap_packet_iter(path: Path) -> Iterator[tuple[bytes, float | None]]:
    if _HAS_DPKT:
        with path.open("rb") as fh:
            try:
                yielded = False
                r = dpkt.pcap.Reader(fh)
                for ts, buf in r:
                    yielded = True
                    yield bytes(buf), float(ts)
                if yielded:
                    return
            except Exception:
                pass
            fh.seek(0)
            try:
                yielded = False
                r2 = dpkt.pcapng.Reader(fh)
                for ts, buf in r2:
                    yielded = True
                    yield bytes(buf), float(ts)
                if yielded:
                    return
            except Exception:
                fh.seek(0)
    with path.open("rb") as fh:
        yield from _pcap_packet_iter_legacy(fh)


def count_capture_packets(path: Path) -> int:
    """Count packets in a PCAP/PCAPNG file best-effort, without truncation sampling."""
    p = Path(path)
    if not p.is_file():
        return 0
    n = 0
    for _buf, _ts in _pcap_packet_iter(p):
        n += 1
    return n


def resolve_rep01_packet_inventory(data_root: Path) -> dict[str, Any]:
    """Return packet inventory across all discovered REP-01 capture files."""
    paths = resolve_rep01_pcap_paths(data_root)
    files: list[dict[str, Any]] = []
    total_packets = 0
    for p in paths:
        cnt = count_capture_packets(p)
        total_packets += int(cnt)
        files.append(
            {
                "path": str(p),
                "packets": int(cnt),
                "size_bytes": int(p.stat().st_size) if p.exists() else 0,
            }
        )
    return {
        "files_count": len(paths),
        "packets_total": int(total_packets),
        "files": files,
    }


def segment_pcap_into_chunks(
    pcap_path: Path | None,
    *,
    execution_mode: str = "simulation",
    chunks_per_phase: int = 4,
    max_packets_per_chunk: int = 500,
) -> tuple[list[ReplayChunk], dict[str, Any]]:
    """Split PCAP into phase-tagged chunks for parallel workers (no synthetic fallback)."""
    stats: dict[str, Any] = {
        "pcap_path": str(pcap_path) if pcap_path else None,
        "dpkt": _HAS_DPKT,
        "phases": list(REPLAY_PHASES),
        "synthetic": False,
        "execution_mode": execution_mode,
        "error": None,
    }
    chunks: list[ReplayChunk] = []
    if not pcap_path or not pcap_path.is_file():
        stats["error"] = "pcap_missing"
        return [], stats

    packets: list[tuple[bytes, float | None]] = []
    for buf, ts in _pcap_packet_iter(pcap_path):
        packets.append((buf, ts))
    stats["total_packets_sampled"] = len(packets)
    if not packets:
        stats["error"] = "pcap_empty"
        return [], stats

    n = len(packets)
    phase_buckets = {p: [] for p in REPLAY_PHASES}
    for i, item in enumerate(packets):
        phase = REPLAY_PHASES[i % len(REPLAY_PHASES)]
        phase_buckets[phase].append(item)

    for phase in REPLAY_PHASES:
        items = phase_buckets[phase]
        if not items:
            continue
        step = max(1, len(items) // chunks_per_phase)
        for ci in range(0, len(items), step):
            sl = items[ci : ci + step]
            if not sl:
                continue
            plen = sum(len(x[0]) for x in sl)
            chunks.append(
                ReplayChunk(
                    phase=phase,
                    chunk_index=len(chunks),
                    packet_count=len(sl),
                    payload_bytes=plen,
                    metadata={"source": "pcap", "path": str(pcap_path)},
                )
            )
    if not chunks:
        stats["error"] = "pcap_no_chunks"
        return [], stats
    return chunks, stats


def chunk_to_udp_payload(
    chunk: ReplayChunk,
    *,
    replay_run_id: str,
    phase_id: str,
    stream_id: str,
    child_id: str,
    event_id: str,
    simulation_session_id: str | None = None,
) -> bytes:
    body = {
        "replay_run_id": replay_run_id,
        "simulation_session_id": simulation_session_id,
        "phase_id": phase_id,
        "stream_id": stream_id,
        "child_id": child_id,
        "replay_phase": chunk.phase,
        "chunk_index": chunk.chunk_index,
        "packet_count": chunk.packet_count,
        "payload_bytes": chunk.payload_bytes,
        "event_id": event_id,
        "timestamp_utc": _now_iso(),
        "metadata": chunk.metadata,
    }
    raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    if len(raw) > 60_000:
        return raw[:60_000]
    return raw


def make_executor(max_workers: int) -> Executor:
    """Thread pool for adapter/route work (UDP sockets and in-process Child listeners are not picklable)."""
    return ThreadPoolExecutor(max_workers=min(max_workers, STEP3_REPLAY_MAX_WORKERS))


def run_chunk_workers(
    chunks: list[ReplayChunk],
    worker_fn: Callable[[ReplayChunk], Any],
    *,
    max_workers: int | None = None,
) -> list[Any]:
    mw = max_workers or STEP3_ADAPTER_WORKERS
    if not chunks:
        return []
    ex = make_executor(mw)
    try:
        futs = [ex.submit(worker_fn, ch) for ch in chunks]
        return [f.result() for f in futs]
    finally:
        ex.shutdown(wait=True, cancel_futures=False)
