"""Postgres-backed logging and audit helpers for Phase 4 services."""

from __future__ import annotations

import json
import os
import uuid
import csv
import time
import hashlib
import mimetypes
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

_SCHEMA_READY = False

# When PHASE4_SCHEMA_ON_CONNECT=0 (or PROJECT_SCHEMA_ON_CONNECT=0 for backward compatibility),
# connect() skips DDL;
# run migration-service once to call run_workflow_schema_migration().
# Serialize ensure_workflow_schema on connect for legacy/local runs where multiple
# threads might race the first connection in one process.
_PHASE4_SCHEMA_ADVISORY_CLASS = 542_001
_PHASE4_SCHEMA_ADVISORY_OBJ = 1


def _env_first(*keys: str, default: str) -> str:
    """Return the first non-empty env var from keys, otherwise default."""
    for key in keys:
        value = os.getenv(key)
        if value is not None:
            value = value.strip()
            if value:
                return value
    return default


def schema_ensure_on_connect() -> bool:
    """If false, connect() performs no DDL (expect migration-service to have run)."""
    v = _env_first("PHASE4_SCHEMA_ON_CONNECT", "PROJECT_SCHEMA_ON_CONNECT", default="1").lower()
    return v in ("1", "true", "yes", "on")


def run_workflow_schema_migration() -> int:
    """One-shot apply ensure_workflow_schema (Compose migration-service). Returns shell exit code."""
    import sys
    import traceback

    attempts = max(1, _env_int("PHASE4_MIGRATION_MAX_ATTEMPTS", 30))
    retry_seconds = max(0.1, _env_float("PHASE4_MIGRATION_RETRY_SECONDS", 2.0))
    psycopg = _psycopg()

    last_exc: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with psycopg.connect(postgres_dsn()) as conn:
                ensure_workflow_schema(conn)
            if attempt > 1:
                print(
                    f"phase4_workflow_schema migration completed successfully after retry {attempt}/{attempts}.",
                    file=sys.stderr,
                )
            else:
                print("phase4_workflow_schema migration completed successfully.", file=sys.stderr)
            return 0
        except Exception as exc:  # pragma: no cover - runtime / DB boundary
            last_exc = exc
            if attempt >= attempts or not _is_retryable_migration_error(exc):
                print(f"phase4_workflow_schema migration failed: {exc}", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
                return 1
            print(
                f"phase4_workflow_schema migration retry {attempt}/{attempts} after error: {exc}",
                file=sys.stderr,
            )
            time.sleep(retry_seconds)

    if last_exc is not None:
        print(f"phase4_workflow_schema migration failed: {last_exc}", file=sys.stderr)
        traceback.print_exception(type(last_exc), last_exc, last_exc.__traceback__, file=sys.stderr)
    else:
        print("phase4_workflow_schema migration failed: unknown error", file=sys.stderr)
    return 1


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _is_retryable_migration_error(exc: Exception) -> bool:
    text = str(exc).lower()
    cls = exc.__class__.__name__.lower()
    retryable_class = "operationalerror" in cls or "interfaceerror" in cls
    retryable_text = any(
        token in text
        for token in (
            "connection failed",
            "connection refused",
            "could not connect",
            "timeout expired",
            "network is unreachable",
            "name or service not known",
            "temporary failure in name resolution",
            "server closed the connection",
            "the database system is starting up",
        )
    )
    return retryable_class or retryable_text


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iso_or_str(value: Any) -> str | None:
    """JSON-friendly timestamp: datetime → isoformat, else str; None stays None."""
    if value is None:
        return None
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            return iso()
        except Exception:
            return str(value)
    return str(value)


def _uuid_or_none(value: Any) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return str(uuid.UUID(raw))
    except Exception:
        return None


def _text_or_none(value: Any) -> str | None:
    raw = str(value or "").strip()
    return raw or None


def _audit_step_link(
    *,
    event_type: str,
    step: str | None,
    step_unique_id: str | None,
    context: dict[str, Any] | None,
    dataset_id: str | None,
    import_batch_id: str | None,
    experiment_id: str | None,
    model_version: str | None,
    replay_id: str | None,
) -> tuple[str | None, str | None]:
    ctx = context if isinstance(context, dict) else {}
    workflow_id = str(ctx.get("workflow_id") or "").strip().lower()
    event_hint = str(event_type or ctx.get("event_type") or "").strip().lower()
    step_raw = str(step or ctx.get("step") or ctx.get("step_name") or "").strip().lower()
    if step_raw in {"step1", "step2", "step3", "step4"}:
        resolved_step: str | None = step_raw
    elif step_raw in {"step3_scaffold", "step3_v2"}:
        resolved_step = "step3"
    else:
        resolved_step = None
    if resolved_step is None:
        for token, mapped in (
            ("step1", "step1"),
            ("step2", "step2"),
            ("step3", "step3"),
            ("step4", "step4"),
            ("step3_scaffold", "step3"),
            ("step3_v2", "step3"),
        ):
            if token in workflow_id or token in event_hint:
                resolved_step = mapped
                break

    resolved_unique = _text_or_none(step_unique_id) or _text_or_none(ctx.get("step_unique_id"))
    generic_run_id = _text_or_none(ctx.get("run_id"))

    step1_candidates = [
        _text_or_none(ctx.get("step1_run_id")),
        _text_or_none(ctx.get("source_step1_run_id")),
        _text_or_none(ctx.get("lineage_step1_run_id")),
        generic_run_id if resolved_step == "step1" else None,
        _text_or_none(import_batch_id),
        _text_or_none(dataset_id),
    ]
    step2_candidates = [
        generic_run_id if resolved_step == "step2" else None,
        _text_or_none(ctx.get("model_id")),
        _text_or_none(ctx.get("step2_run_id")),
        _text_or_none(ctx.get("lineage_step2_run_id")),
        _text_or_none(experiment_id),
        _text_or_none(model_version),
    ]
    step3_candidates = [
        generic_run_id if resolved_step == "step3" else None,
        _text_or_none(ctx.get("simulation_id")),
        _text_or_none(ctx.get("sim_id")),
        _text_or_none(ctx.get("simulation_session_id")),
        _text_or_none(ctx.get("replay_run_id")),
        _text_or_none(ctx.get("preparation_replay_id")),
        _text_or_none(ctx.get("prepare_replay_id")),
        _uuid_or_none(ctx.get("replay_id")),
        _uuid_or_none(replay_id),
    ]
    step4_candidates = [
        generic_run_id if resolved_step == "step4" else None,
        _text_or_none(ctx.get("step4_run_id")),
        _text_or_none(ctx.get("completion_run_id")),
        _text_or_none(ctx.get("lineage_sim_id")),
        _text_or_none(ctx.get("lineage_model_id")),
    ]

    def _first_nonempty(values: list[str | None]) -> str | None:
        for value in values:
            if value:
                return value
        return None

    if resolved_step is None:
        if _first_nonempty(step3_candidates):
            resolved_step = "step3"
        elif _first_nonempty(step2_candidates):
            resolved_step = "step2"
        elif _first_nonempty(step1_candidates):
            resolved_step = "step1"
        elif _first_nonempty(step4_candidates):
            resolved_step = "step4"

    if not resolved_unique:
        if resolved_step == "step1":
            resolved_unique = _first_nonempty(step1_candidates)
        elif resolved_step == "step2":
            resolved_unique = _first_nonempty(step2_candidates)
        elif resolved_step == "step3":
            resolved_unique = _first_nonempty(step3_candidates)
        elif resolved_step == "step4":
            resolved_unique = _first_nonempty(step4_candidates)
        else:
            resolved_unique = _first_nonempty(step3_candidates + step2_candidates + step1_candidates + step4_candidates)

    return resolved_step, resolved_unique


def _psycopg():
    try:
        import psycopg  # type: ignore
    except ImportError as exc:  # pragma: no cover - environment boundary
        raise RuntimeError(
            "psycopg is required for Phase 4 Postgres workflow logging. "
            "Install psycopg[binary] in the service container."
        ) from exc
    return psycopg


def postgres_dsn() -> str:
    host = _env_first("PHASE4_POSTGRES_HOST", "PROJECT_POSTGRES_HOST", default="phase4-postgres")
    port = _env_first("PHASE4_POSTGRES_PORT", "PROJECT_POSTGRES_PORT", default="5432")
    db = _env_first("PHASE4_POSTGRES_DB", "PROJECT_POSTGRES_DB", default="ids_phase4")
    user = _env_first("PHASE4_POSTGRES_USER", "PROJECT_POSTGRES_USER", default="ids_phase4")
    password = _env_first(
        "PHASE4_POSTGRES_PASSWORD",
        "PROJECT_POSTGRES_PASSWORD",
        default="ids_phase4_local_change_me",
    )
    return f"host={host} port={port} dbname={db} user={user} password={password}"


@contextmanager
def connect() -> Iterator[Any]:
    global _SCHEMA_READY
    psycopg = _psycopg()
    with psycopg.connect(postgres_dsn()) as conn:
        if not _SCHEMA_READY:
            if schema_ensure_on_connect():
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT pg_advisory_lock(%s, %s);",
                        (_PHASE4_SCHEMA_ADVISORY_CLASS, _PHASE4_SCHEMA_ADVISORY_OBJ),
                    )
                try:
                    ensure_workflow_schema(conn)
                finally:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT pg_advisory_unlock(%s, %s);",
                            (_PHASE4_SCHEMA_ADVISORY_CLASS, _PHASE4_SCHEMA_ADVISORY_OBJ),
                        )
            _SCHEMA_READY = True
        yield conn


def ensure_workflow_schema(conn: Any) -> None:
    with conn.cursor() as cur:
        core_sql = """
            CREATE SCHEMA IF NOT EXISTS phase4;

            CREATE TABLE IF NOT EXISTS phase4.import_batches (
                import_batch_id uuid PRIMARY KEY,
                dataset_id text NOT NULL,
                dataset_name text,
                dataset_domain text,
                started_at_utc timestamptz NOT NULL DEFAULT now(),
                completed_at_utc timestamptz,
                status text NOT NULL DEFAULT 'started',
                schema_version text NOT NULL DEFAULT 'canonical_event_v1',
                categorization_config_version text NOT NULL DEFAULT 'categorization_config_v1',
                notes jsonb NOT NULL DEFAULT '{}'::jsonb
            );

            CREATE TABLE IF NOT EXISTS phase4.raw_artifacts (
                raw_artifact_id uuid PRIMARY KEY,
                import_batch_id uuid REFERENCES phase4.import_batches(import_batch_id),
                dataset_id text NOT NULL,
                artifact_path text NOT NULL,
                artifact_type text NOT NULL,
                sha256 text NOT NULL,
                adapter_action text NOT NULL,
                adapter_notes jsonb NOT NULL DEFAULT '[]'::jsonb,
                discovered_at_utc timestamptz NOT NULL DEFAULT now()
            );

            CREATE TABLE IF NOT EXISTS phase4.audit_events (
                event_id uuid PRIMARY KEY,
                event_type text NOT NULL,
                timestamp_utc timestamptz NOT NULL,
                actor text NOT NULL,
                dataset_id text,
                import_batch_id uuid,
                artifact_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
                context jsonb NOT NULL DEFAULT '{}'::jsonb
            );

            CREATE TABLE IF NOT EXISTS phase4.canonical_events_template (
                event_id text NOT NULL,
                timestamp_utc timestamptz NOT NULL,
                source_ip text NOT NULL,
                source_port integer,
                destination_ip text NOT NULL,
                destination_port integer,
                protocol text NOT NULL,
                protocol_family text,
                source_domain text NOT NULL,
                source_zone text NOT NULL,
                expected_environment text NOT NULL,
                observed_environment text NOT NULL DEFAULT 'unknown',
                vector_class text NOT NULL,
                attack_category text NOT NULL DEFAULT 'unknown_suspicious',
                scope_match text NOT NULL CHECK (scope_match IN ('in_scope', 'cross_scope', 'unknown')),
                cross_scope_flag boolean NOT NULL DEFAULT false,
                escalation_reason text NOT NULL DEFAULT 'none',
                categorization_confidence numeric(4, 2) NOT NULL CHECK (categorization_confidence >= 0 AND categorization_confidence <= 1),
                adapter_version text,
                source_file text,
                source_path text,
                checksum text,
                label_original text,
                label_harmonized text NOT NULL,
                bytes_in numeric,
                bytes_out numeric,
                duration_ms numeric,
                dataset_source text NOT NULL,
                split text NOT NULL CHECK (split IN ('train', 'validation', 'test', 'replay')),
                import_batch_id uuid,
                raw_artifact_sha256 text,
                ingested_at_utc timestamptz NOT NULL DEFAULT now()
            );

            CREATE TABLE IF NOT EXISTS phase4.dataset_logs (
                dl_id bigserial PRIMARY KEY,
                dataset_id text NOT NULL,
                dataset_name text,
                filename text NOT NULL,
                filepath text NOT NULL,
                artifact_type text NOT NULL,
                sha256 text,
                size_bytes bigint,
                stage text NOT NULL CHECK (stage IN ('upload', 'normalise', 'categorise', 'split', 'ingest', 'postgres', 'discard')),
                status text NOT NULL CHECK (status IN ('pending', 'running', 'received', 'approved', 'declined', 'discarded', 'completed', 'failed')),
                manifest_match boolean NOT NULL DEFAULT false,
                manifest_role text,
                approval_status text,
                decline_reason text,
                import_batch_id uuid,
                created_at_utc timestamptz NOT NULL DEFAULT now(),
                updated_at_utc timestamptz NOT NULL DEFAULT now(),
                completed_at_utc timestamptz,
                metadata jsonb NOT NULL DEFAULT '{}'::jsonb
            );

            CREATE TABLE IF NOT EXISTS phase4.split_manifests (
                split_manifest_id uuid PRIMARY KEY,
                import_batch_id uuid REFERENCES phase4.import_batches(import_batch_id),
                dataset_id text NOT NULL,
                train_count bigint NOT NULL DEFAULT 0,
                validation_count bigint NOT NULL DEFAULT 0,
                test_count bigint NOT NULL DEFAULT 0,
                replay_count bigint NOT NULL DEFAULT 0,
                created_at_utc timestamptz NOT NULL DEFAULT now(),
                split_policy text NOT NULL DEFAULT 'sha256_event_id_mod_10'
            );

            CREATE TABLE IF NOT EXISTS phase4.canonical_events_train (
                LIKE phase4.canonical_events_template INCLUDING ALL,
                CHECK (split = 'train')
            );

            CREATE TABLE IF NOT EXISTS phase4.canonical_events_validation (
                LIKE phase4.canonical_events_template INCLUDING ALL,
                CHECK (split = 'validation')
            );

            CREATE TABLE IF NOT EXISTS phase4.canonical_events_test (
                LIKE phase4.canonical_events_template INCLUDING ALL,
                CHECK (split = 'test')
            );

            CREATE TABLE IF NOT EXISTS phase4.canonical_events_replay (
                LIKE phase4.canonical_events_template INCLUDING ALL,
                CHECK (split = 'replay')
            );

            CREATE TABLE IF NOT EXISTS phase4.dataset_train (
                LIKE phase4.canonical_events_template INCLUDING ALL,
                CHECK (split = 'train')
            );

            CREATE TABLE IF NOT EXISTS phase4.dataset_validate (
                LIKE phase4.canonical_events_template INCLUDING ALL,
                CHECK (split = 'validation')
            );

            CREATE TABLE IF NOT EXISTS phase4.dataset_test (
                LIKE phase4.canonical_events_template INCLUDING ALL,
                CHECK (split = 'test')
            );

            CREATE TABLE IF NOT EXISTS phase4.dataset_replay (
                LIKE phase4.canonical_events_template INCLUDING ALL,
                CHECK (split = 'replay')
            );

            CREATE INDEX IF NOT EXISTS idx_phase4_dataset_logs_dataset_stage ON phase4.dataset_logs(dataset_id, stage, status, created_at_utc);
            CREATE INDEX IF NOT EXISTS idx_phase4_dataset_logs_filename ON phase4.dataset_logs(dataset_id, filename, created_at_utc);
            CREATE INDEX IF NOT EXISTS idx_phase4_audit_dataset_import ON phase4.audit_events(dataset_id, import_batch_id, timestamp_utc);
            CREATE INDEX IF NOT EXISTS idx_phase4_train_dataset_event ON phase4.canonical_events_train(dataset_source, event_id);
            CREATE INDEX IF NOT EXISTS idx_phase4_validation_dataset_event ON phase4.canonical_events_validation(dataset_source, event_id);
            CREATE INDEX IF NOT EXISTS idx_phase4_test_dataset_event ON phase4.canonical_events_test(dataset_source, event_id);
            CREATE INDEX IF NOT EXISTS idx_phase4_replay_dataset_event ON phase4.canonical_events_replay(dataset_source, event_id);
            CREATE INDEX IF NOT EXISTS idx_phase4_dataset_train_event ON phase4.dataset_train(dataset_source, event_id);
            CREATE INDEX IF NOT EXISTS idx_phase4_dataset_validate_event ON phase4.dataset_validate(dataset_source, event_id);
            CREATE INDEX IF NOT EXISTS idx_phase4_dataset_test_event ON phase4.dataset_test(dataset_source, event_id);
            CREATE INDEX IF NOT EXISTS idx_phase4_dataset_replay_event ON phase4.dataset_replay(dataset_source, event_id);
            """
        _execute_sql_statements(cur, sql=core_sql, source="phase4_db.ensure_workflow_schema(core)")
        ensure_governance_registry_schema(cur)
        ensure_governed_views_schema(cur)
        ensure_hypothesis_results_schema(cur)
        ensure_model_v1_workflow_schema(cur)
        ensure_step3_v2_schema(cur)
    conn.commit()


def governance_schema_path() -> Path:
    return Path(__file__).resolve().parents[2] / "schemas" / "postgres_phase4_governance_v1.sql"


def governed_views_schema_path() -> Path:
    return Path(__file__).resolve().parents[2] / "schemas" / "postgres_phase4_governed_views_v1.sql"


def hypothesis_results_schema_path() -> Path:
    return Path(__file__).resolve().parents[2] / "schemas" / "postgres_phase4_hypothesis_results_v1.sql"


def model_v1_workflow_schema_path() -> Path:
    return Path(__file__).resolve().parents[2] / "schemas" / "postgres_phase4_model_v1_workflow.sql"


def step3_v2_schema_path() -> Path:
    return Path(__file__).resolve().parents[2] / "schemas" / "postgres_phase4_step3_v2.sql"


def _strip_standalone_comment_lines(sql: str) -> str:
    """Remove full-line SQL comments so ';' splitting does not drop the next statement."""
    lines: list[str] = []
    for line in sql.splitlines():
        if line.lstrip().startswith("--"):
            continue
        lines.append(line)
    return "\n".join(lines)


def _split_sql_statements(sql: str) -> list[str]:
    """Split on semicolons outside single-quoted strings and dollar-quoted ($$ ... $$) bodies."""
    statements: list[str] = []
    n = len(sql)
    stmt_start = 0
    i = 0
    while i < n:
        c = sql[i]
        if c == "'":
            i += 1
            while i < n:
                if sql[i] == "'":
                    if i + 1 < n and sql[i + 1] == "'":
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue
        if c == "$":
            j = i + 1
            while j < n and sql[j] != "$":
                j += 1
            if j >= n:
                i += 1
                continue
            tag = sql[i + 1 : j]
            close = "$" + tag + "$"
            j += 1
            end = sql.find(close, j)
            if end == -1:
                i += 1
                continue
            i = end + len(close)
            continue
        if c == ";":
            chunk = sql[stmt_start:i].strip()
            if chunk:
                statements.append(chunk)
            stmt_start = i + 1
        i += 1
    tail = sql[stmt_start:n].strip()
    if tail:
        statements.append(tail)
    return statements


def _sql_preview(stmt: str, *, limit: int = 220) -> str:
    compact = " ".join((stmt or "").split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def _execute_sql_statements(cur: Any, *, sql: str, source: str) -> None:
    statements = _split_sql_statements(sql)
    verbose = _env_first("PHASE4_MIGRATION_VERBOSE", default="0").lower() in {"1", "true", "yes", "on"}
    total = len(statements)
    for idx, stmt in enumerate(statements, start=1):
        if not stmt.strip():
            continue
        if verbose:
            print(f"[phase4-migrate] {source} statement {idx}/{total}: {_sql_preview(stmt)}")
        try:
            cur.execute(stmt)
        except Exception as exc:
            raise RuntimeError(
                f"{source} statement {idx}/{total} failed: {_sql_preview(stmt)} :: {exc}"
            ) from exc


def ensure_governance_registry_schema(cur: Any) -> None:
    """Apply registry / leakage / result-table DDL (idempotent)."""
    path = governance_schema_path()
    if not path.is_file():
        return
    sql = _strip_standalone_comment_lines(path.read_text(encoding="utf-8"))
    _execute_sql_statements(cur, sql=sql, source=str(path))


def ensure_governed_views_schema(cur: Any) -> None:
    """Apply canonical_records, split constraints, governed views, and SQL leakage writers."""
    path = governed_views_schema_path()
    if not path.is_file():
        return
    sql = _strip_standalone_comment_lines(path.read_text(encoding="utf-8"))
    _execute_sql_statements(cur, sql=sql, source=str(path))


def ensure_hypothesis_results_schema(cur: Any) -> None:
    """Apply H1(1)–H1(5) hypothesis result table DDL (idempotent)."""
    path = hypothesis_results_schema_path()
    if not path.is_file():
        return
    sql = _strip_standalone_comment_lines(path.read_text(encoding="utf-8"))
    _execute_sql_statements(cur, sql=sql, source=str(path))


def ensure_model_v1_workflow_schema(cur: Any) -> None:
    """Apply Model V1 workflow orchestration schema (idempotent)."""
    path = model_v1_workflow_schema_path()
    if not path.is_file():
        return
    sql = _strip_standalone_comment_lines(path.read_text(encoding="utf-8"))
    _execute_sql_statements(cur, sql=sql, source=str(path))


def ensure_step3_v2_schema(cur: Any) -> None:
    """Apply Step 3 V2 queue/event/runtime schema (idempotent)."""
    path = step3_v2_schema_path()
    if not path.is_file():
        return
    sql = _strip_standalone_comment_lines(path.read_text(encoding="utf-8"))
    _execute_sql_statements(cur, sql=sql, source=str(path))


def json_param(value: Any) -> Any:
    return json.dumps(value or {})


def insert_dataset_log(
    *,
    dataset_id: str,
    dataset_name: str | None,
    filename: str,
    filepath: str,
    artifact_type: str,
    stage: str,
    status: str,
    sha256: str | None = None,
    size_bytes: int | None = None,
    manifest_match: bool = False,
    manifest_role: str | None = None,
    approval_status: str | None = None,
    decline_reason: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> int:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.dataset_logs (
                    dataset_id,
                    dataset_name,
                    filename,
                    filepath,
                    artifact_type,
                    sha256,
                    size_bytes,
                    stage,
                    status,
                    manifest_match,
                    manifest_role,
                    approval_status,
                    decline_reason,
                    metadata,
                    completed_at_utc
                )
                VALUES (
                    %(dataset_id)s,
                    %(dataset_name)s,
                    %(filename)s,
                    %(filepath)s,
                    %(artifact_type)s,
                    %(sha256)s,
                    %(size_bytes)s,
                    %(stage)s,
                    %(status)s,
                    %(manifest_match)s,
                    %(manifest_role)s,
                    %(approval_status)s,
                    %(decline_reason)s,
                    %(metadata)s::jsonb,
                    CASE WHEN %(status)s IN ('received', 'approved', 'declined', 'discarded', 'completed', 'failed')
                        THEN now()
                        ELSE NULL
                    END
                )
                RETURNING dl_id;
                """,
                {
                    "dataset_id": dataset_id,
                    "dataset_name": dataset_name,
                    "filename": filename,
                    "filepath": filepath,
                    "artifact_type": artifact_type,
                    "sha256": sha256,
                    "size_bytes": size_bytes,
                    "stage": stage,
                    "status": status,
                    "manifest_match": manifest_match,
                    "manifest_role": manifest_role,
                    "approval_status": approval_status,
                    "decline_reason": decline_reason,
                    "metadata": json_param(metadata),
                },
            )
            dl_id = int(cur.fetchone()[0])
        conn.commit()
    return dl_id


def create_import_batch(
    *,
    import_batch_id: str,
    dataset_id: str,
    dataset_name: str | None,
    dataset_domain: str | None,
    status: str = "started",
    notes: dict[str, Any] | None = None,
) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.import_batches (
                    import_batch_id,
                    dataset_id,
                    dataset_name,
                    dataset_domain,
                    status,
                    notes
                )
                VALUES (
                    %(import_batch_id)s,
                    %(dataset_id)s,
                    %(dataset_name)s,
                    %(dataset_domain)s,
                    %(status)s,
                    %(notes)s::jsonb
                )
                ON CONFLICT (import_batch_id) DO NOTHING;
                """,
                {
                    "import_batch_id": import_batch_id,
                    "dataset_id": dataset_id,
                    "dataset_name": dataset_name,
                    "dataset_domain": dataset_domain,
                    "status": status,
                    "notes": json_param(notes),
                },
            )
        conn.commit()


def complete_import_batch(import_batch_id: str, status: str, notes: dict[str, Any] | None = None) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE phase4.import_batches
                SET status = %(status)s,
                    completed_at_utc = now(),
                    notes = notes || %(notes)s::jsonb
                WHERE import_batch_id = %(import_batch_id)s;
                """,
                {
                    "import_batch_id": import_batch_id,
                    "status": status,
                    "notes": json_param(notes),
                },
            )
        conn.commit()


def insert_raw_artifact(
    *,
    raw_artifact_id: str,
    import_batch_id: str,
    dataset_id: str,
    artifact_path: str,
    artifact_type: str,
    sha256: str,
    adapter_action: str,
    adapter_notes: list[str] | None = None,
) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.raw_artifacts (
                    raw_artifact_id,
                    import_batch_id,
                    dataset_id,
                    artifact_path,
                    artifact_type,
                    sha256,
                    adapter_action,
                    adapter_notes
                )
                VALUES (
                    %(raw_artifact_id)s,
                    %(import_batch_id)s,
                    %(dataset_id)s,
                    %(artifact_path)s,
                    %(artifact_type)s,
                    %(sha256)s,
                    %(adapter_action)s,
                    %(adapter_notes)s::jsonb
                )
                ON CONFLICT (raw_artifact_id) DO NOTHING;
                """,
                {
                    "raw_artifact_id": raw_artifact_id,
                    "import_batch_id": import_batch_id,
                    "dataset_id": dataset_id,
                    "artifact_path": artifact_path,
                    "artifact_type": artifact_type,
                    "sha256": sha256,
                    "adapter_action": adapter_action,
                    "adapter_notes": json.dumps(adapter_notes or []),
                },
            )
        conn.commit()


def update_dataset_log_for_file(
    *,
    dataset_id: str,
    filename: str,
    stage: str,
    status: str,
    filepath: str | None = None,
    sha256: str | None = None,
    size_bytes: int | None = None,
    manifest_match: bool | None = None,
    manifest_role: str | None = None,
    approval_status: str | None = None,
    decline_reason: str | None = None,
    import_batch_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    assignments = [
        "stage = %(stage)s",
        "status = %(status)s",
        "updated_at_utc = now()",
        "completed_at_utc = CASE WHEN %(status)s IN ('received', 'approved', 'declined', 'discarded', 'completed', 'failed') THEN now() ELSE completed_at_utc END",
    ]
    params: dict[str, Any] = {
        "dataset_id": dataset_id,
        "filename": filename,
        "stage": stage,
        "status": status,
    }
    optional = {
        "filepath": filepath,
        "sha256": sha256,
        "size_bytes": size_bytes,
        "manifest_match": manifest_match,
        "manifest_role": manifest_role,
        "approval_status": approval_status,
        "decline_reason": decline_reason,
        "import_batch_id": import_batch_id,
    }
    for key, value in optional.items():
        if value is not None:
            assignments.append(f"{key} = %({key})s")
            params[key] = value
    if metadata is not None:
        assignments.append("metadata = metadata || %(metadata)s::jsonb")
        params["metadata"] = json_param(metadata)

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE phase4.dataset_logs
                SET {", ".join(assignments)}
                WHERE dl_id = (
                    SELECT dl_id
                    FROM phase4.dataset_logs
                    WHERE dataset_id = %(dataset_id)s
                      AND filename = %(filename)s
                    ORDER BY created_at_utc DESC, dl_id DESC
                    LIMIT 1
                );
                """,
                params,
            )
        conn.commit()


def list_dataset_logs(dataset_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    where = "WHERE dataset_id = %(dataset_id)s" if dataset_id else ""
    params = {"dataset_id": dataset_id, "limit": limit}
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT
                    dl_id,
                    dataset_id,
                    dataset_name,
                    filename,
                    filepath,
                    artifact_type,
                    sha256,
                    size_bytes,
                    stage,
                    status,
                    manifest_match,
                    manifest_role,
                    approval_status,
                    decline_reason,
                    created_at_utc,
                    updated_at_utc,
                    completed_at_utc,
                    metadata
                FROM phase4.dataset_logs
                {where}
                ORDER BY created_at_utc DESC, dl_id DESC
                LIMIT %(limit)s;
                """,
                params,
            )
            columns = [desc.name for desc in cur.description]
            rows = [dict(zip(columns, row)) for row in cur.fetchall()]

    for row in rows:
        for key in ("created_at_utc", "updated_at_utc", "completed_at_utc"):
            row[key] = _iso_or_str(row.get(key))
    return rows


def write_audit_event(
    *,
    event_type: str,
    actor: str,
    artifact_refs: list[str],
    context: dict[str, Any] | None = None,
    dataset_id: str | None = None,
    import_batch_id: str | None = None,
    audit_log_path: Path | None = None,
    experiment_id: str | None = None,
    model_version: str | None = None,
    rule_version: str | None = None,
    replay_id: str | None = None,
    artifact_id: str | None = None,
    step: str | None = None,
    step_unique_id: str | None = None,
) -> str:
    event_id = str(uuid.uuid4())
    timestamp = utc_now()
    context_payload = context or {}
    audit_step, audit_step_unique_id = _audit_step_link(
        event_type=event_type,
        step=step,
        step_unique_id=step_unique_id,
        context=context_payload,
        dataset_id=dataset_id,
        import_batch_id=import_batch_id,
        experiment_id=experiment_id,
        model_version=model_version,
        replay_id=replay_id,
    )
    if audit_step and not audit_step_unique_id:
        audit_step_unique_id = (
            _text_or_none(context_payload.get("workflow_id"))
            or _text_or_none(context_payload.get("dataset_id"))
            or _text_or_none(import_batch_id)
            or event_id
        )
    audit_artifact_uuid = _uuid_or_none(artifact_id)
    audit_replay_uuid = _uuid_or_none(replay_id)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS phase4.audit_logs (
                    audit_id uuid PRIMARY KEY,
                    event_type text NOT NULL,
                    actor text NOT NULL,
                    dataset_id text,
                    artifact_id uuid,
                    experiment_id text,
                    model_version text,
                    rule_version text,
                    replay_id uuid,
                    step text,
                    step_unique_id text,
                    event_details_json jsonb NOT NULL DEFAULT '{}'::jsonb,
                    created_at timestamptz NOT NULL DEFAULT now()
                );
                """
            )
            cur.execute(
                """
                INSERT INTO phase4.audit_log (
                    audit_id,
                    event_type,
                    actor,
                    dataset_id,
                    artifact_id,
                    experiment_id,
                    model_version,
                    rule_version,
                    replay_id,
                    step,
                    step_unique_id,
                    event_details_json,
                    created_at
                )
                VALUES (
                    %(audit_id)s::uuid,
                    %(event_type)s,
                    %(actor)s,
                    %(dataset_id)s,
                    CASE WHEN %(artifact_id)s = '' THEN NULL ELSE %(artifact_id)s::uuid END,
                    %(experiment_id)s,
                    %(model_version)s,
                    %(rule_version)s,
                    CASE WHEN %(replay_id)s = '' THEN NULL ELSE %(replay_id)s::uuid END,
                    %(step)s,
                    %(step_unique_id)s,
                    %(event_details_json)s::jsonb,
                    %(created_at)s::timestamptz
                );
                """,
                {
                    "audit_id": event_id,
                    "event_type": event_type,
                    "actor": actor,
                    "dataset_id": dataset_id,
                    "artifact_id": audit_artifact_uuid or "",
                    "experiment_id": experiment_id,
                    "model_version": model_version,
                    "rule_version": rule_version,
                    "replay_id": audit_replay_uuid or "",
                    "step": audit_step,
                    "step_unique_id": audit_step_unique_id,
                    "created_at": timestamp,
                    "event_details_json": json.dumps(
                        {
                            "event_id": event_id,
                            "artifact_refs": artifact_refs,
                            "context": context_payload,
                            "import_batch_id": import_batch_id,
                            "artifact_id": audit_artifact_uuid,
                            "replay_id": audit_replay_uuid,
                            "step": audit_step,
                            "step_unique_id": audit_step_unique_id,
                        }
                    ),
                },
            )
            cur.execute(
                """
                INSERT INTO phase4.audit_logs (
                    audit_id,
                    event_type,
                    actor,
                    dataset_id,
                    artifact_id,
                    experiment_id,
                    model_version,
                    rule_version,
                    replay_id,
                    step,
                    step_unique_id,
                    event_details_json,
                    created_at
                )
                VALUES (
                    %(audit_id)s::uuid,
                    %(event_type)s,
                    %(actor)s,
                    %(dataset_id)s,
                    CASE WHEN %(artifact_id)s = '' THEN NULL ELSE %(artifact_id)s::uuid END,
                    %(experiment_id)s,
                    %(model_version)s,
                    %(rule_version)s,
                    CASE WHEN %(replay_id)s = '' THEN NULL ELSE %(replay_id)s::uuid END,
                    %(step)s,
                    %(step_unique_id)s,
                    %(event_details_json)s::jsonb,
                    %(created_at)s::timestamptz
                )
                ON CONFLICT (audit_id) DO NOTHING;
                """,
                {
                    "audit_id": event_id,
                    "event_type": event_type,
                    "actor": actor,
                    "dataset_id": dataset_id,
                    "artifact_id": audit_artifact_uuid or "",
                    "experiment_id": experiment_id,
                    "model_version": model_version,
                    "rule_version": rule_version,
                    "replay_id": audit_replay_uuid or "",
                    "step": audit_step,
                    "step_unique_id": audit_step_unique_id,
                    "created_at": timestamp,
                    "event_details_json": json.dumps(
                        {
                            "event_id": event_id,
                            "artifact_refs": artifact_refs,
                            "context": context_payload,
                            "import_batch_id": import_batch_id,
                            "artifact_id": audit_artifact_uuid,
                            "replay_id": audit_replay_uuid,
                            "step": audit_step,
                            "step_unique_id": audit_step_unique_id,
                        }
                    ),
                },
            )
        conn.commit()

    # phase4.audit_log is the authoritative audit log sink.
    _ = audit_log_path
    return event_id


def list_audit_events(limit: int = 200) -> list[dict[str, Any]]:
    """Return recent pipeline audit rows (AUDIT layer: ``phase4.audit_log``)."""
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        audit_id::text,
                        event_type,
                        created_at,
                        actor,
                        dataset_id,
                        COALESCE(event_details_json->>'import_batch_id', '') AS import_batch_id,
                        event_details_json,
                        experiment_id,
                        model_version,
                        rule_version,
                        replay_id::text
                    FROM phase4.audit_log
                    ORDER BY created_at DESC, audit_id DESC
                    LIMIT %(limit)s;
                    """,
                    {"limit": limit},
                )
                rows = []
                for rid, et, ts, actor, dataset_id, import_batch_id, details, experiment_id, model_version, rule_version, replay_id in cur.fetchall():
                    details_json = details if isinstance(details, dict) else {}
                    rows.append(
                        {
                            "event_id": str(rid or ""),
                            "event_type": str(et or ""),
                            "timestamp_utc": _iso_or_str(ts),
                            "actor": str(actor or ""),
                            "dataset_id": dataset_id,
                            "import_batch_id": str(import_batch_id or "") or None,
                            "artifact_refs": details_json.get("artifact_refs") if isinstance(details_json.get("artifact_refs"), list) else [],
                            "context": details_json.get("context") if isinstance(details_json.get("context"), dict) else {},
                            "experiment_id": experiment_id,
                            "model_version": model_version,
                            "rule_version": rule_version,
                            "replay_id": replay_id,
                        }
                    )
                for row in rows:
                    row["timestamp_utc"] = _iso_or_str(row.get("timestamp_utc"))
                return rows
    except Exception:
        return []


def copy_csv_to_split_table(conn: Any, csv_path: Path, table_name: str) -> int:
    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        header = fh.readline().strip()
        if not header:
            return 0
        columns = [item.strip() for item in header.split(",")]
        with conn.cursor() as cur:
            before = conn.execute(f"SELECT count(*) FROM {table_name};").fetchone()[0]
            with cur.copy(
                f"COPY {table_name} ({', '.join(columns)}) FROM STDIN WITH (FORMAT csv)"
            ) as copy:
                for line in fh:
                    copy.write(line)
            after = conn.execute(f"SELECT count(*) FROM {table_name};").fetchone()[0]
    return int(after - before)


def copy_csv_to_dataset_splits(
    conn: Any,
    *,
    csv_path: Path,
    dataset_id: str,
    split_name: str,
    experiment_id: str,
    model_version: str,
    dataset_role: str | None,
    source_step1_run_id: str | None,
    source_step1_lineage_hash: str | None,
) -> int:
    """Load normalized split CSV into phase4.dataset_splits as authoritative Step 1 output."""
    if not csv_path.is_file():
        return 0
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema='phase4' AND table_name='dataset_splits';
            """
        )
        columns = {str(r[0]) for r in cur.fetchall()}
    allowed_cols = [
        "dataset_id",
        "experiment_id",
        "model_version",
        "split_name",
        "row_hash",
        "source_row_id",
        "canonical_record_id",
        "label",
        "label_harmonized",
        "label_original",
        "source_domain",
        "source_role",
        "source_zone",
        "expected_environment",
        "observed_environment",
        "protocol_family",
        "vector_class",
        "attack_category",
        "scope_match",
        "cross_scope_flag",
        "escalation_reason",
        "categorization_confidence",
        "adapter_version",
        "source_file",
        "source_path",
        "checksum",
        "source_step1_run_id",
        "source_step1_lineage_hash",
    ]
    insert_cols = [c for c in allowed_cols if c in columns]
    if not insert_cols:
        return 0
    placeholders = ", ".join([f"%({c})s" for c in insert_cols])
    insert_sql = f"INSERT INTO phase4.dataset_splits ({', '.join(insert_cols)}) VALUES ({placeholders});"
    rows: list[dict[str, Any]] = []
    with csv_path.open("r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            rows.append(
                {
                    "dataset_id": dataset_id,
                    "experiment_id": experiment_id,
                    "model_version": model_version,
                    "split_name": split_name,
                    "row_hash": str(row.get("row_hash") or "").strip(),
                    "source_row_id": str(row.get("event_id") or "").strip() or None,
                    "canonical_record_id": str(row.get("event_id") or "").strip() or None,
                    "label": str(row.get("label_harmonized") or "").strip() or None,
                    "label_harmonized": str(row.get("label_harmonized") or "").strip() or None,
                    "label_original": str(row.get("label_original") or "").strip(),
                    "source_domain": str(row.get("source_domain") or "").strip() or None,
                    "source_role": str(dataset_role or "").strip() or None,
                    "source_zone": str(row.get("source_zone") or "").strip() or None,
                    "expected_environment": str(row.get("expected_environment") or "").strip() or None,
                    "observed_environment": str(row.get("observed_environment") or "").strip() or None,
                    "protocol_family": str(row.get("protocol_family") or "").strip() or None,
                    "vector_class": str(row.get("vector_class") or "").strip() or None,
                    "attack_category": str(row.get("attack_category") or "").strip() or None,
                    "scope_match": str(row.get("scope_match") or "").strip() or None,
                    "cross_scope_flag": (
                        str(row.get("cross_scope_flag") or "").strip().lower() in {"1", "true", "yes", "y", "on"}
                    ),
                    "escalation_reason": str(row.get("escalation_reason") or "").strip() or None,
                    "categorization_confidence": float(row.get("categorization_confidence") or 0.0)
                    if str(row.get("categorization_confidence") or "").strip()
                    else None,
                    "adapter_version": str(row.get("adapter_version") or "").strip() or None,
                    "source_file": str(row.get("source_file") or "").strip() or None,
                    "source_path": str(row.get("source_path") or "").strip() or None,
                    "checksum": str(row.get("checksum") or "").strip() or None,
                    "source_step1_run_id": source_step1_run_id,
                    "source_step1_lineage_hash": source_step1_lineage_hash,
                }
            )
    if not rows:
        return 0
    with conn.cursor() as cur:
        if source_step1_run_id and "source_step1_run_id" in columns:
            cur.execute(
                """
                DELETE FROM phase4.dataset_splits
                WHERE dataset_id = %(dataset_id)s
                  AND split_name = %(split_name)s
                  AND source_step1_run_id = %(run_id)s;
                """,
                {"dataset_id": dataset_id, "split_name": split_name, "run_id": source_step1_run_id},
            )
        cur.executemany(insert_sql, [{k: v for k, v in row.items() if k in insert_cols} for row in rows])
    return len(rows)


def copy_normalized_csv_to_dataset_splits(
    conn: Any,
    *,
    csv_path: Path,
    dataset_id: str,
    experiment_id: str,
    model_version: str,
    dataset_role: str | None,
    source_step1_run_id: str | None,
    source_step1_lineage_hash: str | None,
) -> dict[str, int]:
    """Append normalized rows into phase4.dataset_splits using per-row split labels from CSV."""
    if not csv_path.is_file():
        return {}
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema='phase4' AND table_name='dataset_splits';
            """
        )
        columns = {str(r[0]) for r in cur.fetchall()}
    allowed_cols = [
        "dataset_id",
        "experiment_id",
        "model_version",
        "split_name",
        "row_hash",
        "source_row_id",
        "canonical_record_id",
        "label",
        "label_harmonized",
        "label_original",
        "source_domain",
        "source_role",
        "source_zone",
        "expected_environment",
        "observed_environment",
        "protocol_family",
        "vector_class",
        "attack_category",
        "scope_match",
        "cross_scope_flag",
        "escalation_reason",
        "categorization_confidence",
        "adapter_version",
        "source_file",
        "source_path",
        "checksum",
        "source_step1_run_id",
        "source_step1_lineage_hash",
    ]
    insert_cols = [c for c in allowed_cols if c in columns]
    if not insert_cols:
        return {}
    placeholders = ", ".join([f"%({c})s" for c in insert_cols])
    insert_sql = f"INSERT INTO phase4.dataset_splits ({', '.join(insert_cols)}) VALUES ({placeholders});"
    rows: list[dict[str, Any]] = []
    loaded_counts: dict[str, int] = {}
    with csv_path.open("r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            split_name = str(row.get("split") or "").strip().lower()
            if split_name == "validation":
                split_name = "validate"
            if not split_name:
                continue
            loaded_counts[split_name] = loaded_counts.get(split_name, 0) + 1
            rows.append(
                {
                    "dataset_id": dataset_id,
                    "experiment_id": experiment_id,
                    "model_version": model_version,
                    "split_name": split_name,
                    "row_hash": str(row.get("row_hash") or "").strip(),
                    "source_row_id": str(row.get("event_id") or "").strip() or None,
                    "canonical_record_id": str(row.get("event_id") or "").strip() or None,
                    "label": str(row.get("label_harmonized") or "").strip() or None,
                    "label_harmonized": str(row.get("label_harmonized") or "").strip() or None,
                    "label_original": str(row.get("label_original") or "").strip(),
                    "source_domain": str(row.get("source_domain") or "").strip() or None,
                    "source_role": str(dataset_role or "").strip() or None,
                    "source_zone": str(row.get("source_zone") or "").strip() or None,
                    "expected_environment": str(row.get("expected_environment") or "").strip() or None,
                    "observed_environment": str(row.get("observed_environment") or "").strip() or None,
                    "protocol_family": str(row.get("protocol_family") or "").strip() or None,
                    "vector_class": str(row.get("vector_class") or "").strip() or None,
                    "attack_category": str(row.get("attack_category") or "").strip() or None,
                    "scope_match": str(row.get("scope_match") or "").strip() or None,
                    "cross_scope_flag": (
                        str(row.get("cross_scope_flag") or "").strip().lower() in {"1", "true", "yes", "y", "on"}
                    ),
                    "escalation_reason": str(row.get("escalation_reason") or "").strip() or None,
                    "categorization_confidence": float(row.get("categorization_confidence") or 0.0)
                    if str(row.get("categorization_confidence") or "").strip()
                    else None,
                    "adapter_version": str(row.get("adapter_version") or "").strip() or None,
                    "source_file": str(row.get("source_file") or "").strip() or None,
                    "source_path": str(row.get("source_path") or "").strip() or None,
                    "checksum": str(row.get("checksum") or "").strip() or None,
                    "source_step1_run_id": source_step1_run_id,
                    "source_step1_lineage_hash": source_step1_lineage_hash,
                }
            )
    if not rows:
        return {}
    with conn.cursor() as cur:
        cur.executemany(insert_sql, [{k: v for k, v in row.items() if k in insert_cols} for row in rows])
    return loaded_counts


def upsert_workflow_runtime_state(
    *,
    step_name: str,
    workflow_id: str,
    run_id: str | None = None,
    current_phase: str | None = None,
    phase_status: str | None = None,
    status: str | None = None,
    source: str = "dashboard_api",
    state_payload: dict[str, Any] | None = None,
) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.workflow_runtime_state (
                    step_name,
                    workflow_id,
                    run_id,
                    current_phase,
                    phase_status,
                    status,
                    source,
                    state_payload,
                    updated_at_utc
                )
                VALUES (
                    %(step_name)s,
                    %(workflow_id)s,
                    CASE WHEN %(run_id)s = '' THEN NULL ELSE %(run_id)s::uuid END,
                    %(current_phase)s,
                    %(phase_status)s,
                    COALESCE(%(status)s, 'pending'),
                    %(source)s,
                    %(state_payload)s::jsonb,
                    now()
                )
                ON CONFLICT (step_name, workflow_id)
                DO UPDATE SET
                    run_id = COALESCE(EXCLUDED.run_id, phase4.workflow_runtime_state.run_id),
                    current_phase = COALESCE(EXCLUDED.current_phase, phase4.workflow_runtime_state.current_phase),
                    phase_status = COALESCE(EXCLUDED.phase_status, phase4.workflow_runtime_state.phase_status),
                    status = COALESCE(EXCLUDED.status, phase4.workflow_runtime_state.status),
                    source = COALESCE(EXCLUDED.source, phase4.workflow_runtime_state.source),
                    state_payload = COALESCE(EXCLUDED.state_payload, phase4.workflow_runtime_state.state_payload),
                    updated_at_utc = now();
                """,
                {
                    "step_name": step_name,
                    "workflow_id": workflow_id,
                    "run_id": (run_id or "").strip(),
                    "current_phase": current_phase,
                    "phase_status": phase_status,
                    "status": status,
                    "source": source,
                    "state_payload": json.dumps(state_payload or {}),
                },
            )
        conn.commit()


def create_workflow_request(
    *,
    request_id: str,
    step_name: str,
    stage_name: str,
    workflow_id: str | None = None,
    run_id: str | None = None,
    dataset_id: str | None = None,
    requested_by: str | None = None,
    status: str = "queued",
    request_payload: dict[str, Any] | None = None,
) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.workflow_requests (
                    request_id,
                    step_name,
                    stage_name,
                    workflow_id,
                    run_id,
                    dataset_id,
                    requested_by,
                    status,
                    request_payload,
                    requested_at_utc,
                    updated_at_utc
                )
                VALUES (
                    %(request_id)s::uuid,
                    %(step_name)s,
                    %(stage_name)s,
                    %(workflow_id)s,
                    CASE WHEN %(run_id)s = '' THEN NULL ELSE %(run_id)s::uuid END,
                    %(dataset_id)s,
                    %(requested_by)s,
                    %(status)s,
                    %(request_payload)s::jsonb,
                    now(),
                    now()
                )
                ON CONFLICT (request_id)
                DO UPDATE SET
                    status = EXCLUDED.status,
                    workflow_id = COALESCE(EXCLUDED.workflow_id, phase4.workflow_requests.workflow_id),
                    run_id = COALESCE(EXCLUDED.run_id, phase4.workflow_requests.run_id),
                    dataset_id = COALESCE(EXCLUDED.dataset_id, phase4.workflow_requests.dataset_id),
                    requested_by = COALESCE(EXCLUDED.requested_by, phase4.workflow_requests.requested_by),
                    request_payload = EXCLUDED.request_payload,
                    updated_at_utc = now();
                """,
                {
                    "request_id": request_id,
                    "step_name": step_name,
                    "stage_name": stage_name,
                    "workflow_id": workflow_id,
                    "run_id": (run_id or "").strip(),
                    "dataset_id": dataset_id,
                    "requested_by": requested_by,
                    "status": status,
                    "request_payload": json.dumps(request_payload or {}),
                },
            )
        conn.commit()


def update_workflow_request_status(
    request_id: str,
    *,
    status: str,
    run_id: str | None = None,
    workflow_id: str | None = None,
    request_payload: dict[str, Any] | None = None,
    completed: bool = False,
) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE phase4.workflow_requests
                SET status = %(status)s,
                    run_id = COALESCE(CASE WHEN %(run_id)s = '' THEN NULL ELSE %(run_id)s::uuid END, run_id),
                    workflow_id = COALESCE(%(workflow_id)s, workflow_id),
                    request_payload = COALESCE(%(request_payload)s::jsonb, request_payload),
                    updated_at_utc = now(),
                    completed_at_utc = CASE WHEN %(completed)s THEN now() ELSE completed_at_utc END
                WHERE request_id = %(request_id)s::uuid;
                """,
                {
                    "request_id": request_id,
                    "status": status,
                    "run_id": (run_id or "").strip(),
                    "workflow_id": workflow_id,
                    "request_payload": json.dumps(request_payload) if request_payload is not None else None,
                    "completed": completed,
                },
            )
        conn.commit()


def _sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def register_file_artifact(
    *,
    file_path: str,
    artifact_type: str,
    run_id: str | None = None,
    model_id: str | None = None,
    model_version: str | None = None,
    step_name: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    p = Path(file_path)
    if not str(file_path).strip():
        return None
    p_abs = p.resolve()
    content_type = mimetypes.guess_type(str(p_abs))[0] or "application/octet-stream"
    size_bytes = p_abs.stat().st_size if p_abs.exists() and p_abs.is_file() else None
    sha256 = _sha256_file(p_abs) if p_abs.exists() and p_abs.is_file() else None
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.file_artifacts (
                    artifact_id,
                    run_id,
                    model_id,
                    model_version,
                    step_name,
                    artifact_type,
                    file_path,
                    content_type,
                    size_bytes,
                    sha256,
                    metadata,
                    created_at_utc,
                    updated_at_utc
                )
                VALUES (
                    %(artifact_id)s::uuid,
                    CASE WHEN %(run_id)s = '' THEN NULL ELSE %(run_id)s::uuid END,
                    %(model_id)s,
                    %(model_version)s,
                    %(step_name)s,
                    %(artifact_type)s,
                    %(file_path)s,
                    %(content_type)s,
                    %(size_bytes)s,
                    %(sha256)s,
                    %(metadata)s::jsonb,
                    now(),
                    now()
                )
                ON CONFLICT (file_path)
                DO UPDATE SET
                    run_id = COALESCE(EXCLUDED.run_id, phase4.file_artifacts.run_id),
                    model_id = COALESCE(EXCLUDED.model_id, phase4.file_artifacts.model_id),
                    model_version = COALESCE(EXCLUDED.model_version, phase4.file_artifacts.model_version),
                    step_name = COALESCE(EXCLUDED.step_name, phase4.file_artifacts.step_name),
                    artifact_type = COALESCE(EXCLUDED.artifact_type, phase4.file_artifacts.artifact_type),
                    content_type = COALESCE(EXCLUDED.content_type, phase4.file_artifacts.content_type),
                    size_bytes = COALESCE(EXCLUDED.size_bytes, phase4.file_artifacts.size_bytes),
                    sha256 = COALESCE(EXCLUDED.sha256, phase4.file_artifacts.sha256),
                    metadata = COALESCE(EXCLUDED.metadata, phase4.file_artifacts.metadata),
                    updated_at_utc = now()
                RETURNING artifact_id::text, file_path, content_type, size_bytes, sha256;
                """,
                {
                    "artifact_id": str(uuid.uuid4()),
                    "run_id": (run_id or "").strip(),
                    "model_id": model_id,
                    "model_version": model_version,
                    "step_name": step_name,
                    "artifact_type": artifact_type,
                    "file_path": str(p_abs),
                    "content_type": content_type,
                    "size_bytes": size_bytes,
                    "sha256": sha256,
                    "metadata": json.dumps(metadata or {}),
                },
            )
            row = cur.fetchone()
        conn.commit()
    if not row:
        return None
    return {
        "artifact_id": row[0],
        "file_path": row[1],
        "content_type": row[2],
        "size_bytes": row[3],
        "sha256": row[4],
    }


def resolve_file_artifact(artifact_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT artifact_id::text, run_id::text, model_id, model_version, step_name,
                       artifact_type, file_path, content_type, size_bytes, sha256, metadata
                FROM phase4.file_artifacts
                WHERE artifact_id = %(artifact_id)s::uuid
                LIMIT 1;
                """,
                {"artifact_id": artifact_id},
            )
            row = cur.fetchone()
            if not row:
                return None
            cols = [d.name for d in cur.description]
            return dict(zip(cols, row))


def upsert_step3_model_preparation(
    *,
    model_version: str,
    model_id: str | None,
    replay_id: str | None = None,
    verified_ok: bool,
    checks: list[dict[str, Any]] | None,
) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.step3_model_preparation (
                    model_version, model_id, replay_id, verified_ok, checks, verified_at_utc
                )
                VALUES (
                    %(mv)s,
                    CASE WHEN %(mid)s = '' THEN NULL ELSE %(mid)s::uuid END,
                    CASE WHEN %(replay_id)s = '' THEN NULL ELSE %(replay_id)s::uuid END,
                    %(ok)s,
                    %(checks)s::jsonb,
                    now()
                )
                ON CONFLICT (model_version)
                DO UPDATE SET
                    model_id = COALESCE(EXCLUDED.model_id, phase4.step3_model_preparation.model_id),
                    replay_id = COALESCE(EXCLUDED.replay_id, phase4.step3_model_preparation.replay_id),
                    verified_ok = EXCLUDED.verified_ok,
                    checks = EXCLUDED.checks,
                    verified_at_utc = now();
                """,
                {
                    "mv": model_version,
                    "mid": (model_id or "").strip(),
                    "replay_id": (_uuid_or_none(replay_id) or ""),
                    "ok": verified_ok,
                    "checks": json.dumps(checks or []),
                },
            )
        conn.commit()


def upsert_step3_preparation_run(
    *,
    replay_id: str,
    model_id: str | None,
    model_version: str,
    status: str,
    verified_ok: bool | None = None,
    prepare_payload: dict[str, Any] | None = None,
    prepare_result: dict[str, Any] | None = None,
    verify_result: dict[str, Any] | None = None,
    checks: list[dict[str, Any]] | None = None,
) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.step3_preparation_runs (
                    replay_id, model_id, model_version, status, verified_ok,
                    prepare_payload, prepare_result, verify_result, checks, created_at_utc, updated_at_utc
                )
                VALUES (
                    %(rid)s::uuid,
                    CASE WHEN %(mid)s = '' THEN NULL ELSE %(mid)s::uuid END,
                    %(mv)s,
                    %(status)s,
                    COALESCE(%(verified_ok)s, false),
                    %(prepare_payload)s::jsonb,
                    %(prepare_result)s::jsonb,
                    %(verify_result)s::jsonb,
                    %(checks)s::jsonb,
                    now(),
                    now()
                )
                ON CONFLICT (replay_id)
                DO UPDATE SET
                    model_id = COALESCE(EXCLUDED.model_id, phase4.step3_preparation_runs.model_id),
                    model_version = EXCLUDED.model_version,
                    status = EXCLUDED.status,
                    verified_ok = COALESCE(EXCLUDED.verified_ok, phase4.step3_preparation_runs.verified_ok),
                    prepare_payload = CASE
                        WHEN EXCLUDED.prepare_payload = '{}'::jsonb
                        THEN phase4.step3_preparation_runs.prepare_payload
                        ELSE phase4.step3_preparation_runs.prepare_payload || EXCLUDED.prepare_payload
                    END,
                    prepare_result = CASE
                        WHEN EXCLUDED.prepare_result = '{}'::jsonb
                        THEN phase4.step3_preparation_runs.prepare_result
                        ELSE EXCLUDED.prepare_result
                    END,
                    verify_result = CASE
                        WHEN EXCLUDED.verify_result = '{}'::jsonb
                        THEN phase4.step3_preparation_runs.verify_result
                        ELSE EXCLUDED.verify_result
                    END,
                    checks = CASE
                        WHEN EXCLUDED.checks = '[]'::jsonb
                        THEN phase4.step3_preparation_runs.checks
                        ELSE EXCLUDED.checks
                    END,
                    updated_at_utc = now();
                """,
                {
                    "rid": replay_id,
                    "mid": (model_id or "").strip(),
                    "mv": model_version,
                    "status": status,
                    "verified_ok": verified_ok,
                    "prepare_payload": json.dumps(prepare_payload or {}),
                    "prepare_result": json.dumps(prepare_result or {}),
                    "verify_result": json.dumps(verify_result or {}),
                    "checks": json.dumps(checks or []),
                },
            )
        conn.commit()


def get_latest_step3_preparation_run(*, model_version: str) -> dict[str, Any] | None:
    mv = str(model_version or "").strip()
    if not mv:
        return None
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT replay_id::text, model_id::text, model_version, status, verified_ok,
                       prepare_payload, prepare_result, verify_result, checks,
                       created_at_utc, updated_at_utc
                FROM phase4.step3_preparation_runs
                WHERE model_version = %(mv)s
                ORDER BY created_at_utc DESC
                LIMIT 1;
                """,
                {"mv": mv},
            )
            row = cur.fetchone()
    if not row:
        return None
    return {
        "replay_id": row[0],
        "model_id": row[1],
        "model_version": row[2],
        "status": row[3],
        "verified_ok": bool(row[4]),
        "prepare_payload": row[5] or {},
        "prepare_result": row[6] or {},
        "verify_result": row[7] or {},
        "checks": row[8] or [],
        "created_at": _iso_or_str(row[9]),
        "updated_at": _iso_or_str(row[10]),
    }


def upsert_step3_replay_metrics(
    *,
    replay_run_id: str,
    model_id: str | None,
    model_version: str | None,
    preparation_replay_id: str | None,
    simulation_session_id: str | None,
    metrics: dict[str, Any] | None,
) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.step3_replay_metrics (
                    replay_run_id, replay_id, model_id, model_version, preparation_replay_id, simulation_session_id, metrics, created_at_utc, updated_at_utc
                )
                VALUES (
                    %(rid)s::uuid,
                    CASE WHEN %(replay_id)s = '' THEN NULL ELSE %(replay_id)s::uuid END,
                    CASE WHEN %(mid)s = '' THEN NULL ELSE %(mid)s::uuid END,
                    %(mv)s,
                    CASE WHEN %(prid)s = '' THEN NULL ELSE %(prid)s::uuid END,
                    CASE WHEN %(sid)s = '' THEN NULL ELSE %(sid)s::uuid END,
                    %(metrics)s::jsonb,
                    now(),
                    now()
                )
                ON CONFLICT (replay_run_id)
                DO UPDATE SET
                    replay_id = COALESCE(EXCLUDED.replay_id, phase4.step3_replay_metrics.replay_id),
                    model_id = COALESCE(EXCLUDED.model_id, phase4.step3_replay_metrics.model_id),
                    model_version = COALESCE(EXCLUDED.model_version, phase4.step3_replay_metrics.model_version),
                    preparation_replay_id = COALESCE(EXCLUDED.preparation_replay_id, phase4.step3_replay_metrics.preparation_replay_id),
                    simulation_session_id = COALESCE(EXCLUDED.simulation_session_id, phase4.step3_replay_metrics.simulation_session_id),
                    metrics = EXCLUDED.metrics,
                    updated_at_utc = now();
                """,
                {
                    "rid": replay_run_id,
                    "replay_id": (_uuid_or_none(preparation_replay_id) or _uuid_or_none(replay_run_id) or ""),
                    "mid": (model_id or "").strip(),
                    "mv": model_version,
                    "prid": (preparation_replay_id or "").strip(),
                    "sid": (simulation_session_id or "").strip(),
                    "metrics": json.dumps(metrics or {}),
                },
            )
        conn.commit()


def get_step3_replay_metrics(*, replay_run_id: str) -> dict[str, Any] | None:
    rid = str(replay_run_id or "").strip()
    if not rid:
        return None
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT replay_run_id::text, replay_id::text, model_id::text, model_version, preparation_replay_id::text,
                       simulation_session_id::text, metrics, created_at_utc, updated_at_utc
                FROM phase4.step3_replay_metrics
                WHERE replay_run_id = %(rid)s::uuid
                LIMIT 1;
                """,
                {"rid": rid},
            )
            row = cur.fetchone()
    if not row:
        return None
    # Step 3 metrics are keyed by sim_id (replay_id/preparation_replay_id), with
    # simulation_session_id and replay_run_id only as compatibility fallbacks.
    sid = str(row[1] or row[4] or row[5] or row[0] or "").strip()
    metrics_payload = row[6] or {}
    if not isinstance(metrics_payload, dict):
        metrics_payload = {}
    try:
        if sid:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT metric, metric_value
                        FROM phase4.metrics
                        WHERE step = 'step3'
                          AND step_unique_id = %(sid)s
                          AND calculation_status = 'measured'
                        ORDER BY metric;
                        """,
                        {"sid": sid},
                    )
                    for metric_name, metric_value in cur.fetchall() or []:
                        if metric_value is None:
                            continue
                        metrics_payload[str(metric_name)] = float(metric_value)
    except Exception:
        pass
    return {
        "replay_run_id": row[0],
        "replay_id": row[1],
        "model_id": row[2],
        "model_version": row[3],
        "preparation_replay_id": row[4],
        "simulation_session_id": row[5],
        "metrics": metrics_payload,
        "created_at": _iso_or_str(row[7]),
        "updated_at": _iso_or_str(row[8]),
    }


def register_step3_pcap_catalog(
    *,
    file_path: str,
    byte_size: int | None = None,
    traffic_profile: str = "mixed",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    p = Path(file_path)
    raw = str(p.resolve()) if p.exists() else file_path
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    meta = metadata or {}
    replay_id = (
        _uuid_or_none(meta.get("replay_id"))
        or _uuid_or_none(meta.get("preparation_replay_id"))
        or _uuid_or_none(meta.get("replay_run_id"))
    )
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO phase4.step3_pcap_catalog (
                    replay_id, path_sha256, file_path, byte_size, traffic_profile, metadata, registered_at_utc
                )
                VALUES (CASE WHEN %(replay_id)s = '' THEN NULL ELSE %(replay_id)s::uuid END, %(sha)s, %(fp)s, %(sz)s, %(tp)s, %(meta)s::jsonb, now())
                ON CONFLICT (path_sha256) DO UPDATE SET
                    replay_id = COALESCE(EXCLUDED.replay_id, phase4.step3_pcap_catalog.replay_id),
                    file_path = EXCLUDED.file_path,
                    byte_size = COALESCE(EXCLUDED.byte_size, phase4.step3_pcap_catalog.byte_size),
                    traffic_profile = EXCLUDED.traffic_profile,
                    metadata = phase4.step3_pcap_catalog.metadata || EXCLUDED.metadata,
                    registered_at_utc = now()
                RETURNING catalog_id::text, path_sha256, file_path, byte_size, traffic_profile;
                """,
                {
                    "replay_id": replay_id or "",
                    "sha": digest,
                    "fp": raw,
                    "sz": byte_size,
                    "tp": traffic_profile,
                    "meta": json.dumps(meta),
                },
            )
            row = cur.fetchone()
        conn.commit()
    if not row:
        return None
    return {
        "catalog_id": row[0],
        "path_sha256": row[1],
        "file_path": row[2],
        "byte_size": row[3],
        "traffic_profile": row[4],
    }


def count_step3_pcap_catalog() -> int:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*)::bigint FROM phase4.step3_pcap_catalog;")
            r = cur.fetchone()
    return int(r[0] or 0) if r else 0
