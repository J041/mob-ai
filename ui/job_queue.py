from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import uuid
from typing import Any

from ui.orchestrator import WORKSPACE


STATE_ROOT = WORKSPACE / "ui" / ".state" / "jobs"
HEARTBEAT_PATH = WORKSPACE / "ui" / ".state" / "worker-heartbeat"
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
