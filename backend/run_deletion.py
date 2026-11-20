"""Recoverable archival of completed assessment runs and their job history."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import uuid
from typing import Any

from backend.artifacts import resolve_run_directory
from backend.common import RUN_LIFECYCLE_LOCK, json_file
from runtime_data import JOBS_ROOT, TRASH_ROOT
from worker.queue import atomic_write_json


ACTIVE_JOB_STATUSES = {"queued", "running", "pausing", "cancelling"}
ACTIVE_ASSISTANT_STATUSES = {"queued", "running"}


class RunDeletionConflict(ValueError):
    """The run still has work that could write to it."""


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
