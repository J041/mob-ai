from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import uuid
from typing import Any

from assessment.runtime import WORKSPACE


STATE_ROOT = WORKSPACE / "worker" / ".state" / "jobs"
HEARTBEAT_PATH = WORKSPACE / "worker" / ".state" / "worker-heartbeat"
STATE_ROOT.mkdir(parents=True, exist_ok=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def recover_abandoned_jobs() -> None:
    """Make stale worker claims explicit without silently repeating device actions."""
    for directory in STATE_ROOT.iterdir():
        if not directory.is_dir():
            continue
        state_path = directory / "job.json"
        state = read_json(state_path)
        claim = directory / "claim.lock"
        if state.get("status") == "queued":
            claim.unlink(missing_ok=True)
        elif state.get("running") or state.get("status") == "running":
            state.update({
                "running": False,
                "status": "interrupted",
                "exit_code": None,
                "completed_utc": utc_now(),
                "detail": "The durable worker stopped during this attempt. Existing evidence was preserved; retry or recover the run from the dashboard.",
            })
            atomic_write_json(state_path, state)
            claim.unlink(missing_ok=True)


def enqueue_due_usage_limit_jobs() -> list[str]:
    """Durably resume opted-in quota checkpoints only after an explicit reset timestamp."""
    now = datetime.now(timezone.utc)
    directories = [path for path in STATE_ROOT.iterdir() if path.is_dir()]
    states = [(path, read_json(path / "job.json")) for path in directories]
    if any(state.get("running") or state.get("status") == "queued" for _, state in states):
        return []
    created: list[str] = []
    for directory, state in sorted(states, key=lambda item: item[0].stat().st_mtime):
        if (
            state.get("status") != "usage_limited"
            or not state.get("auto_resume")
            or state.get("auto_resume_job_id")
        ):
            continue
        reset_value = str(state.get("resume_after_utc") or "")
        try:
            reset_at = datetime.fromisoformat(reset_value.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            continue
        if reset_at > now:
            continue
        request = read_json(directory / "request.json")
        payload = dict(request.get("payload") or {})
        run_id = str(state.get("run_id") or "")
        if not run_id:
            continue
        newer = [
            other for other_directory, other in states
            if other_directory != directory and other.get("run_id") == run_id
            and int(other.get("attempt_number") or 0) > int(state.get("attempt_number") or 0)
        ]
        if newer:
            state["auto_resume_superseded_by"] = str(max(
                newer, key=lambda item: int(item.get("attempt_number") or 0),
            ).get("id") or "")
            atomic_write_json(directory / "job.json", state)
            continue
        payload["run"] = str(WORKSPACE / "runs" / run_id)
        payload["auto_resume_usage_limit"] = True
        job_id = uuid.uuid4().hex
        queued_utc = utc_now()
        target = STATE_ROOT / job_id
        target.mkdir(parents=True)
        next_state = {
            "id": job_id, "kind": "resume", "label": run_id, "queued_utc": queued_utc,
            "started_utc": "", "running": False, "exit_code": None, "status": "queued",
            "run_id": run_id, "attempt_number": max(
                (int(other.get("attempt_number") or 0) for _, other in states if other.get("run_id") == run_id),
                default=0,
            ) + 1,
            "attempt_kind": "usage_limit_resume", "parent_job_id": str(state.get("id") or ""),
            "auto_resumed": True,
        }
        atomic_write_json(target / "request.json", {"kind": "resume", "label": run_id, "payload": payload})
        atomic_write_json(target / "job.json", next_state)
        state.update({"auto_resume_job_id": job_id, "auto_resume_queued_utc": queued_utc})
        atomic_write_json(directory / "job.json", state)
        created.append(job_id)
        break
    return created


def claim_next_job(worker_id: str) -> tuple[Path, dict[str, Any], dict[str, Any]] | None:
    directories = sorted(
        (path for path in STATE_ROOT.iterdir() if path.is_dir()),
        key=lambda path: path.stat().st_mtime,
    )
    for directory in directories:
        state_path = directory / "job.json"
        state = read_json(state_path)
        if state.get("status") != "queued":
            continue
        claim_path = directory / "claim.lock"
        try:
            descriptor = os.open(claim_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(f"{worker_id}\n")
        state = read_json(state_path)
        if state.get("status") != "queued":
            claim_path.unlink(missing_ok=True)
            continue
        state.update({
            "running": True,
            "status": "running",
            "started_utc": utc_now(),
            "worker_id": worker_id,
        })
        atomic_write_json(state_path, state)
        request = read_json(directory / "request.json")
        return directory, state, request
    return None


def touch_heartbeat(worker_id: str) -> None:
    HEARTBEAT_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = HEARTBEAT_PATH.with_name(f".{HEARTBEAT_PATH.name}.{worker_id}.tmp")
    temporary.write_text(f"{utc_now()} {worker_id}\n", encoding="utf-8")
    os.replace(temporary, HEARTBEAT_PATH)
