"""Recoverable archival of completed assessment runs and their job history."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import uuid
from typing import Any

from backend.artifacts import resolve_run_directory
from backend.common import RUN_LIFECYCLE_LOCK, json_file
from runtime_data import JOBS_ROOT, RUNS_ROOT, TRASH_ROOT, WORKSPACE
from worker.queue import atomic_write_json


ACTIVE_JOB_STATUSES = {"queued", "running", "pausing", "cancelling"}
ACTIVE_ASSISTANT_STATUSES = {"queued", "running"}


class RunDeletionConflict(ValueError):
    """The run still has work that could write to it."""


def _tree_size(root: Path) -> int:
    """Measure regular files without following links outside an archive."""
    total = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    total += entry.stat(follow_symlinks=False).st_size
            except OSError:
                continue
    return total


def _archive_directory(archive_id: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", archive_id):
        raise ValueError("Invalid archive identifier.")
    root = (TRASH_ROOT / "runs").resolve()
    directory = (root / archive_id).resolve()
    try:
        directory.relative_to(root)
    except ValueError as error:
        raise ValueError("Archive escaped the trash directory.") from error
    if not directory.is_dir() or directory.is_symlink():
        raise FileNotFoundError("Deleted assessment archive not found.")
    return directory


def _archive_manifest(archive_id: str) -> tuple[Path, dict[str, Any]]:
    directory = _archive_directory(archive_id)
    manifest = json_file(directory / "archive.json") or {}
    if (
        manifest.get("archive_id") != archive_id
        or not re.fullmatch(r"[A-Za-z0-9._-]+", str(manifest.get("run_id") or ""))
        or not (directory / "run" / "report.json").is_file()
    ):
        raise ValueError("Deleted assessment archive is invalid or incomplete.")
    return directory, manifest


def trash_runs() -> list[dict[str, Any]]:
    root = TRASH_ROOT / "runs"
    if not root.is_dir():
        return []
    archives = []
    for candidate in root.iterdir():
        if not candidate.is_dir() or candidate.is_symlink():
            continue
        try:
            directory, manifest = _archive_manifest(candidate.name)
        except (FileNotFoundError, ValueError):
            continue
        report = json_file(directory / "run" / "report.json") or {}
        archives.append({
            "archive_id": candidate.name,
            "run_id": str(manifest["run_id"]),
            "package": str(report.get("package") or manifest["run_id"]),
            "archived_utc": str(manifest.get("archived_utc") or ""),
            "size_bytes": int(manifest.get("size_bytes") or _tree_size(directory)),
            "job_count": len(manifest.get("jobs") or []),
            "recoverable": bool(manifest.get("recoverable", True)),
        })
    return sorted(archives, key=lambda item: item["archived_utc"], reverse=True)


def _job_run_id(state: dict[str, Any], request: dict[str, Any]) -> str:
    recorded = str(state.get("run_id") or "")
    if re.fullmatch(r"[A-Za-z0-9._-]+", recorded):
        return recorded
    payload = request.get("payload") if isinstance(request.get("payload"), dict) else {}
    run_path = str(payload.get("run") or "")
    if run_path:
        return Path(run_path).name
    return ""


def _related_jobs(run_id: str) -> tuple[list[Path], list[str]]:
    related: list[Path] = []
    blockers: list[str] = []
    if not JOBS_ROOT.is_dir():
        return related, blockers
    for directory in JOBS_ROOT.iterdir():
        if not directory.is_dir() or not re.fullmatch(r"[a-f0-9]{32}", directory.name):
            continue
        state = json_file(directory / "job.json") or {}
        request = json_file(directory / "request.json") or {}
        payload = request.get("payload") if isinstance(request.get("payload"), dict) else {}
        recorded_run = _job_run_id(state, request)
        references_source = str(payload.get("derived_from_run") or "") == run_id
        status = str(state.get("status") or "")
        active = bool(state.get("running")) or status in ACTIVE_JOB_STATUSES
        if active and (recorded_run == run_id or references_source):
            blockers.append(directory.name)
        if recorded_run == run_id:
            related.append(directory)
    return related, blockers


def _active_assistant_requests(run_dir: Path) -> list[str]:
    requests = run_dir / "assistant" / "requests"
    if not requests.is_dir():
        return []
    active = []
    for path in requests.glob("*.json"):
        value = json_file(path) or {}
        if str(value.get("status") or "") in ACTIVE_ASSISTANT_STATUSES:
            active.append(str(value.get("id") or path.stem))
    return active


def archive_run(run_id: str, confirmation: str) -> dict[str, Any]:
    """Move one inactive run and its job records to recoverable runtime trash."""
    if not re.fullmatch(r"[A-Za-z0-9._-]+", run_id):
        raise ValueError("Invalid run identifier.")
    if confirmation != run_id:
        raise ValueError("Run deletion confirmation did not match the run identifier.")
    with RUN_LIFECYCLE_LOCK:
        run_dir = resolve_run_directory(run_id)
        marker = run_dir / ".archiving"
        marker.write_text(datetime.now(timezone.utc).isoformat() + "\n", encoding="utf-8")
        related_jobs, job_blockers = _related_jobs(run_id)
        assistant_blockers = _active_assistant_requests(run_dir)
        if job_blockers or assistant_blockers:
            marker.unlink(missing_ok=True)
            if job_blockers:
                raise RunDeletionConflict("Cancel or finish the active assessment job before deleting this run.")
            raise RunDeletionConflict("Wait for the active assistant request to finish before deleting this run.")

        timestamp = datetime.now(timezone.utc)
        archive_id = f"{run_id}-{timestamp.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
        archive_dir = TRASH_ROOT / "runs" / archive_id
        archived_run = archive_dir / "run"
        archived_jobs = archive_dir / "jobs"
        moved_jobs: list[tuple[Path, Path, dict[str, Any]]] = []
        try:
            archive_dir.mkdir(parents=True, exist_ok=False)
            for source in related_jobs:
                (source / ".archiving").write_text(timestamp.isoformat() + "\n", encoding="utf-8")
            os.replace(run_dir, archived_run)
            archived_jobs.mkdir()
            for source in related_jobs:
                state = json_file(source / "job.json") or {}
                original_state = dict(state)
                target = archived_jobs / source.name
                os.replace(source, target)
                moved_jobs.append((source, target, original_state))
                state.update({
                    "archived": True,
                    "archived_utc": timestamp.isoformat(),
                    "archived_run_id": run_id,
                })
                atomic_write_json(target / "job.json", state)
                (target / ".archiving").unlink(missing_ok=True)
            (archived_run / ".archiving").unlink(missing_ok=True)
            manifest = {
                "version": 1,
                "archive_id": archive_id,
                "run_id": run_id,
                "archived_utc": timestamp.isoformat(),
                "run": "run",
                "jobs": [target.name for _, target, _ in moved_jobs],
                "recoverable": True,
                "size_bytes": _tree_size(archive_dir),
            }
            (archive_dir / "archive.json").write_text(
                json.dumps(manifest, indent=2) + "\n", encoding="utf-8",
            )
        except Exception:
            for source, target, original_state in reversed(moved_jobs):
                if target.exists() and not source.exists():
                    os.replace(target, source)
                    atomic_write_json(source / "job.json", original_state)
            if archived_run.exists() and not run_dir.exists():
                os.replace(archived_run, run_dir)
            marker.unlink(missing_ok=True)
            for source in related_jobs:
                (source / ".archiving").unlink(missing_ok=True)
            try:
                archived_jobs.rmdir()
                archive_dir.rmdir()
            except OSError:
                pass
            raise
        return manifest


def restore_run(archive_id: str, confirmation: str) -> dict[str, Any]:
    """Restore one archived run and its completed job history without overwriting data."""
    with RUN_LIFECYCLE_LOCK:
        archive_dir, manifest = _archive_manifest(archive_id)
        run_id = str(manifest["run_id"])
        if confirmation != run_id:
            raise ValueError("Run restoration confirmation did not match the run identifier.")
        source_run = archive_dir / "run"
        target_run = RUNS_ROOT / run_id
        if target_run.exists():
            raise RunDeletionConflict("A run with this identifier already exists; restoration would overwrite it.")
        job_ids = [str(value) for value in manifest.get("jobs") or []]
        if any(not re.fullmatch(r"[a-f0-9]{32}", value) for value in job_ids):
            raise ValueError("Archive contains an invalid durable-job identifier.")
        sources = [(archive_dir / "jobs" / value, JOBS_ROOT / value) for value in job_ids]
        if any(not source.is_dir() for source, _ in sources):
            raise ValueError("Archive is missing recorded durable-job history.")
        if any(target.exists() for _, target in sources):
            raise RunDeletionConflict("A durable job from this archive already exists; restoration would overwrite it.")

        marker = archive_dir / ".restoring"
        marker.write_text(datetime.now(timezone.utc).isoformat() + "\n", encoding="utf-8")
        moved_jobs: list[tuple[Path, Path, dict[str, Any]]] = []
        run_moved = False
        try:
            os.replace(source_run, target_run)
            run_moved = True
            for source, target in sources:
                archived_state = json_file(source / "job.json") or {}
                os.replace(source, target)
                moved_jobs.append((source, target, archived_state))
                restored_state = dict(archived_state)
                for key in ("archived", "archived_utc", "archived_run_id"):
                    restored_state.pop(key, None)
                atomic_write_json(target / "job.json", restored_state)
            warnings = []
            if not (target_run / "original.apk").is_file():
                warnings.append("The restored run does not contain original.apk.")
            config = json_file(target_run / "codex-loop-config.json") or {}
            policy = str(config.get("success_spec") or "")
            if policy:
                policy_path = (WORKSPACE / policy).resolve()
                try:
                    policy_path.relative_to(WORKSPACE.resolve())
                except ValueError:
                    warnings.append("The recorded success policy path is invalid.")
                else:
                    if not policy_path.is_file():
                        warnings.append("The recorded success policy is no longer available.")
            result = {
                "archive_id": archive_id, "run_id": run_id, "restored": True,
                "jobs_restored": len(moved_jobs), "warnings": warnings,
            }
        except Exception:
            for source, target, archived_state in reversed(moved_jobs):
                if target.exists() and not source.exists():
                    os.replace(target, source)
                    atomic_write_json(source / "job.json", archived_state)
            if run_moved and target_run.exists() and not source_run.exists():
                os.replace(target_run, source_run)
            marker.unlink(missing_ok=True)
            raise
        try:
            (archive_dir / "archive.json").unlink(missing_ok=True)
            marker.unlink(missing_ok=True)
            (archive_dir / "jobs").rmdir()
            archive_dir.rmdir()
        except OSError:
            pass
        return result


def purge_run_archive(archive_id: str, confirmation: str) -> dict[str, Any]:
    """Permanently erase one exact, validated trash archive."""
    with RUN_LIFECYCLE_LOCK:
        archive_dir, manifest = _archive_manifest(archive_id)
        run_id = str(manifest["run_id"])
        if confirmation != run_id:
            raise ValueError("Permanent deletion confirmation did not match the run identifier.")
        size_bytes = int(manifest.get("size_bytes") or _tree_size(archive_dir))
        (archive_dir / ".purging").write_text(datetime.now(timezone.utc).isoformat() + "\n", encoding="utf-8")
        shutil.rmtree(archive_dir)
        return {
            "archive_id": archive_id, "run_id": run_id,
            "purged": True, "bytes_freed": size_bytes,
        }
