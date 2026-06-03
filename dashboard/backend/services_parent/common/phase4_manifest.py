"""Manifest helpers for governed Phase 4 dataset artifact handling."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

# Host prefix in manifest `server_target_dir` (HPC) → remapped under `--data-root` in Docker (e.g. /data).
_DEFAULT_MANIFEST_HOST_ROOT = "/srv/scratch/ids_final_amity"


def resolve_dataset_raw_dir_with_source(data_root: Path, dataset: dict[str, Any]) -> tuple[Path, str]:
    """Resolve the dataset raw folder and record how it was chosen.

    Precedence (when ``PROJECT_IGNORE_SERVER_TARGET_DIR`` is unset):
    1. ``server_target_dir`` from the manifest, if it exists as a directory on this host
       (HPC layout: e.g. ``/srv/scratch/.../raw_downloads/ENT-01`` even when ``--data-root`` points elsewhere).
    2. ``repo_target_dir`` under ``data_root`` (Docker: ``/data`` + ``raw_downloads/ENT-01``).
    """
    dataset_id = str(dataset.get("dataset_id", "")).strip()
    if not (os.environ.get("PROJECT_IGNORE_SERVER_TARGET_DIR") or "").strip():
        server_dir = str(dataset.get("server_target_dir") or "").strip()
        if server_dir:
            norm = server_dir.replace("\\", "/").rstrip("/")
            try:
                p = Path(server_dir).expanduser()
                if p.is_dir():
                    return p.resolve(strict=False), "server_target_dir"
            except OSError:
                pass
            # Inside Docker / another layout, the literal host path may not exist; map
            # e.g. /srv/scratch/ids_final_amity/raw_downloads/ENT-01 → {data_root}/raw_downloads/ENT-01
            host_root = (os.environ.get("PROJECT_MANIFEST_HOST_ROOT") or _DEFAULT_MANIFEST_HOST_ROOT).strip().rstrip("/")
            if host_root and (norm == host_root or norm.startswith(host_root + "/")):
                suffix = norm[len(host_root) :].lstrip("/")
                if suffix:
                    try:
                        alt = (data_root / suffix).resolve(strict=False)
                        if alt.is_dir():
                            return alt, "server_target_remapped"
                    except OSError:
                        pass

    repo_target_dir = str(dataset.get("repo_target_dir", f"raw_downloads/{dataset_id}")).replace("\\", "/").strip("/")
    rel = Path(repo_target_dir)
    root = data_root.resolve(strict=False)
    target = rel if rel.is_absolute() else (data_root / rel)
    resolved = target.resolve(strict=False)
    if not rel.is_absolute():
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"repo_target_dir escapes data root: {repo_target_dir}") from exc
    return resolved, "repo_target_dir"


def resolve_dataset_raw_dir(data_root: Path, dataset: dict[str, Any]) -> Path:
    """Resolve on-disk folder for a dataset (see :func:`resolve_dataset_raw_dir_with_source`)."""
    return resolve_dataset_raw_dir_with_source(data_root, dataset)[0]


def _manifest_file_step0_status(candidate: Path, raw_resolved: Path) -> tuple[str, str | None]:
    """Return (status, detail) for one expected filename under *raw_resolved*.

    status: ``ok`` | ``path_escape`` | ``missing`` | ``permission_denied`` | ``unreadable`` | ``not_regular_file`` | ``error``
    """
    try:
        candidate.relative_to(raw_resolved)
    except ValueError:
        return "path_escape", "path escapes dataset raw directory"
    try:
        st = candidate.stat()
    except FileNotFoundError:
        return "missing", None
    except PermissionError as exc:
        return "permission_denied", str(exc) or "PermissionError"
    except OSError as exc:
        return "error", str(exc)
    if stat.S_ISREG(st.st_mode):
        if not os.access(str(candidate), os.R_OK, follow_symlinks=True):
            return "unreadable", "os.access reports not readable (check chmod / ACL)"
        return "ok", None
    if stat.S_ISDIR(st.st_mode):
        return "not_regular_file", "a directory exists with this name, not a file"
    return "not_regular_file", "not a regular file (symlink to dir or special)"


def _case_insensitive_name_hints(expected_names: list[str], dir_names: list[str]) -> list[dict[str, str]]:
    """If disk has same name with different case, report for Linux ext4 debugging."""
    by_lower = {}
    for n in dir_names:
        k = n.lower()
        if k not in by_lower:
            by_lower[k] = n
    out: list[dict[str, str]] = []
    for exp in expected_names:
        if exp in dir_names:
            continue
        other = by_lower.get(exp.lower())
        if other and other != exp:
            out.append({"expected_manifest_name": exp, "actual_filename_on_disk": other})
    return out


def _process_csv_path_filenames(paths: list[Any]) -> list[str]:
    """process_csv_paths are filenames only; strip any directory prefix and de-duplicate."""
    out: list[str] = []
    seen: set[str] = set()
    for p in paths:
        s = str(p).strip()
        if not s:
            continue
        name = Path(s.replace("\\", "/")).name
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def process_csv_readiness(
    data_root: Path,
    dataset: dict[str, Any],
    *,
    precomputed_raw: tuple[Path, str] | None = None,
) -> dict[str, Any]:
    """Step-0: manifest process_csv_paths must exist as files under the dataset raw folder.

    Pass ``precomputed_raw`` from :func:`resolve_dataset_raw_dir_with_source` to avoid duplicate resolution.
    """
    if precomputed_raw is not None:
        raw_dir, raw_source = precomputed_raw
    else:
        raw_dir, raw_source = resolve_dataset_raw_dir_with_source(data_root, dataset)
    rel_paths = _process_csv_path_filenames(list(dataset.get("process_csv_paths") or []))
    if not rel_paths:
        return {
            "step0_ready": True,
            "step0_reason": "no_process_csv_paths",
            "process_csv_paths": [],
            "dataset_raw_dir": str(raw_dir),
            "dataset_raw_source": raw_source,
            "expected_files": [],
            "present_files": [],
            "missing_files": [],
        }
    raw_resolved = raw_dir.resolve(strict=False)
    present: list[str] = []
    missing: list[str] = []
    per_file: list[dict[str, Any]] = []
    names_on_disk: list[str] = []
    list_err: str | None = None
    try:
        names_on_disk = sorted(os.listdir(raw_resolved))
    except OSError as exc:
        list_err = str(exc)

    for name in rel_paths:
        candidate = (raw_resolved / name).resolve(strict=False)
        st, det = _manifest_file_step0_status(candidate, raw_resolved)
        row: dict[str, Any] = {"filename": name, "status": st}
        if det:
            row["detail"] = det
        per_file.append(row)
        if st == "ok":
            present.append(name)
        else:
            missing.append(name)

    case_hints = _case_insensitive_name_hints(missing, names_on_disk) if missing and names_on_disk else []

    n_ok = len(present)
    n_bad = len(missing)
    if n_bad == 0:
        step0_reason = "process_csv_paths_ok"
    else:
        statii = {r["status"] for r in per_file if r["status"] != "ok"}
        if statii.issubset({"permission_denied", "unreadable"}) and "missing" not in statii:
            step0_reason = "process_csv_paths_inaccessible"
        else:
            step0_reason = "process_csv_paths_missing"

    dir_hint: dict[str, Any] = {
        "dataset_raw_listing_count": len(names_on_disk),
        "dataset_raw_listing_sample": names_on_disk[:20],
    }
    if list_err:
        dir_hint["dataset_raw_listing_error"] = list_err
    if case_hints:
        dir_hint["step0_case_mismatch_hints"] = case_hints
    dir_hint["step0_per_file"] = per_file
    if not present and n_bad and list_err and "Permission" in list_err:
        dir_hint["step0_suggested_actions"] = (
            "Directory listing failed — check that the process user can traverse parent directories "
            "and read this folder (chmod a+rx on directories, chmod a+r on files, or chgrp to the service user). "
            "NFS: verify root_squash and export permissions for the Docker host."
        )
    elif n_bad and any(
        r["status"] in ("permission_denied", "unreadable") for r in per_file
    ):
        dir_hint["step0_suggested_actions"] = (
            "At least one path exists but is not readable by this process. On the host: "
            "chmod 644 for CSVs, 755 for directories; or add ACL/group read for the user running Docker. "
            "In Docker: the container may run as a different uid than the file owner (see user: in compose or --user)."
        )
    elif case_hints:
        dir_hint["step0_suggested_actions"] = (
            "Filename case does not match the manifest (Linux is case-sensitive). Rename to match or update the manifest."
        )

    return {
        "step0_ready": n_bad == 0,
        "step0_reason": step0_reason,
        "process_csv_paths": rel_paths,
        "dataset_raw_dir": str(raw_dir),
        "dataset_raw_source": raw_source,
        "expected_files": rel_paths,
        "present_files": present,
        "missing_files": missing,
        **dir_hint,
    }

# Raw evidence storage accepts arbitrary file extensions. Normalization adapters
# decide which staged CSV artifacts are processable.
SUPPORTED_ARTIFACT_SUFFIXES = {".csv", ".zip", ".pcap", ".pcapng"}


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_manifest(manifest_path: Path) -> dict[str, Any]:
    payload = read_json(manifest_path)
    payload["datasets_by_id"] = {
        item["dataset_id"]: item
        for item in payload.get("datasets", [])
        if item.get("dataset_id")
    }
    return payload


def load_hybrid_policy(policy_path: Path | None) -> dict[str, Any]:
    if not policy_path or not policy_path.is_file():
        return {}
    return read_json(policy_path).get("datasets", {})


def artifact_type_for(filename: str) -> str:
    suffix = Path(filename).suffix.lower()
    if suffix == ".zip":
        return "zip"
    if suffix == ".csv":
        return "csv"
    if suffix in {".pcap", ".pcapng"}:
        return suffix.lstrip(".")
    return suffix.lstrip(".") or "unknown"


def _policy_artifacts(dataset_policy: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts = list(dataset_policy.get("registered_artifacts", []))
    known = {item.get("filename") for item in artifacts}

    for filename in dataset_policy.get("training_flow_archives", []):
        if filename not in known:
            artifacts.append(
                {
                    "filename": filename,
                    "artifact_type": "zip",
                    "role": "training_flow_archive",
                    "required": True,
                    "process_for_splits": False,
                    "destination": "raw_downloads",
                }
            )
            known.add(filename)

    for filename in dataset_policy.get("reference_archives", []):
        if filename not in known:
            artifacts.append(
                {
                    "filename": filename,
                    "artifact_type": "zip",
                    "role": "reference_archive",
                    "required": False,
                    "process_for_splits": False,
                    "destination": "raw_downloads",
                }
            )
            known.add(filename)

    for filename in dataset_policy.get("pcap_replay_artifacts", []):
        if filename not in known:
            artifacts.append(
                {
                    "filename": filename,
                    "artifact_type": artifact_type_for(filename),
                    "role": "pcap_replay_artifact",
                    "required": False,
                    "process_for_splits": False,
                    "destination": "raw_downloads",
                }
            )
            known.add(filename)

    return artifacts


def registered_artifacts(dataset: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts = list(dataset.get("registered_artifacts", []))
    artifacts.extend(_policy_artifacts(dataset.get("hybrid_policy", {}) or {}))
    deduped: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        filename = str(artifact.get("filename", "")).strip()
        if not filename:
            continue
        item = dict(artifact)
        item["filename"] = filename
        item.setdefault("artifact_type", artifact_type_for(filename))
        item.setdefault("role", "registered_artifact")
        item.setdefault("process_for_splits", item.get("artifact_type") == "csv")
        item.setdefault(
            "destination",
            "raw_downloads",
        )
        deduped[filename] = item
    return list(deduped.values())


def artifact_by_filename(dataset: dict[str, Any], filename: str) -> dict[str, Any] | None:
    for artifact in registered_artifacts(dataset):
        if artifact["filename"] == filename:
            return artifact
    return None


def attach_policy_to_datasets(
    manifest: dict[str, Any],
    hybrid_policy: dict[str, Any],
) -> list[dict[str, Any]]:
    datasets = manifest.get("datasets", [])
    for dataset in datasets:
        dataset["hybrid_policy"] = hybrid_policy.get(dataset.get("dataset_id"), {})
    return datasets


def dataset_with_policy(
    manifest_path: Path,
    hybrid_policy_path: Path | None,
    dataset_id: str,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    hybrid_policy = load_hybrid_policy(hybrid_policy_path)
    datasets = attach_policy_to_datasets(manifest, hybrid_policy)
    for dataset in datasets:
        if dataset.get("dataset_id") == dataset_id:
            return dataset
    raise ValueError(f"Unknown dataset_id: {dataset_id}")


def is_supported_artifact(filename: str) -> bool:
    return bool(filename.strip())
