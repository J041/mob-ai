"""Durable job history, attempt lineage, and queue submission service."""

from __future__ import annotations

from pathlib import Path
import re
import threading
import uuid

from assessment.state import (
    checkpoint_recovery_available, frida_recovery_available, usage_limit_recovery_available,
)
from backend.auth import provider_authenticated
from backend.common import json_file, utc_now
from backend.providers import PROVIDER_IDS
from worker.queue import STATE_ROOT, atomic_write_json

_lock = threading.RLock()

def job_log_tail(job_id: str, limit: int = 120_000) -> str:
    log_path = STATE_ROOT / job_id / "output.log"
    if not log_path.is_file():
        return ""
    with log_path.open("rb") as stream:
        stream.seek(max(0, log_path.stat().st_size - limit))
        return stream.read().decode("utf-8", errors="replace")


def job_log_head(job_id: str, limit: int = 8_000) -> str:
    log_path = STATE_ROOT / job_id / "output.log"
    if not log_path.is_file():
        return ""
    with log_path.open("rb") as stream:
        return stream.read(limit).decode("utf-8", errors="replace")


def infer_job_run_id(state: dict, log_text: str) -> str:
    recorded = str(state.get("run_id") or "")
    if re.fullmatch(r"[A-Za-z0-9._-]+", recorded):
        return recorded
    matches = re.findall(r"(?:/workspace/)?runs/([A-Za-z0-9._-]+)", log_text)
    return matches[-1] if matches else ""


def infer_attempt_kind(state: dict, log_text: str) -> str:
    recorded = str(state.get("attempt_kind") or "")
    if recorded:
        return recorded
    if state.get("kind") == "start":
        return "initial"
    if "--observation-mode only" in log_text:
        return "frida_recovery" if "--start-frida-server" in log_text else "observation_recovery"
    if "--candidate-script" in log_text and "checkpoint-recovery" in log_text:
        return "validation_recovery"
    return "resume"


def job_state(job_id: str, *, include_output: bool = True) -> dict:
    if not re.fullmatch(r"[a-f0-9]{32}", job_id):
        raise ValueError("Invalid job identifier.")
    stored = json_file(STATE_ROOT / job_id / "job.json")
    if not stored:
        raise FileNotFoundError("Job not found.")
    state = dict(stored)
    log_text = job_log_tail(job_id, 120_000 if include_output else 32_000)
    inference_text = job_log_head(job_id) + "\n" + log_text
    state["run_id"] = infer_job_run_id(state, inference_text)
    state["attempt_kind"] = infer_attempt_kind(state, inference_text)
    if include_output:
        state["stdout"] = log_text
        state["stderr"] = ""
    return state


def jobs() -> list[dict]:
    directories = sorted((path for path in STATE_ROOT.iterdir() if path.is_dir()), key=lambda path: path.stat().st_mtime, reverse=True)
    result = []
    for directory in directories[:20]:
        try:
            result.append(job_state(directory.name, include_output=False))
        except (ValueError, FileNotFoundError):
            pass
    previous_by_run: dict[str, str] = {}
    count_by_run: dict[str, int] = {}
    for state in sorted(result, key=lambda item: str(item.get("started_utc") or item.get("queued_utc") or "")):
        run_id = str(state.get("run_id") or "")
        if not run_id:
            state.setdefault("attempt_number", 1)
            state.setdefault("parent_job_id", "")
            continue
        count_by_run[run_id] = count_by_run.get(run_id, 0) + 1
        state["attempt_number"] = int(state.get("attempt_number") or count_by_run[run_id])
        state["parent_job_id"] = str(state.get("parent_job_id") or previous_by_run.get(run_id) or "")
        previous_by_run[run_id] = state["id"]
    return result


def resume_attempt_kind(run_dir: Path) -> str:
    summary = json_file(run_dir / "codex-loop-result.json") or {}
    if usage_limit_recovery_available(summary):
        return "usage_limit_resume"
    if frida_recovery_available(summary):
        return "frida_recovery"
    if checkpoint_recovery_available(summary):
        stage = str((summary.get("checkpoint") or {}).get("stage") or "")
        return f"{stage}_recovery" if stage else "checkpoint_recovery"
    return "resume"


def start_job(kind: str, label: str, payload: dict) -> dict:
    provider = str(payload.get("provider") or "codex")
    if provider not in PROVIDER_IDS:
        raise ValueError("Unsupported reasoning provider.")
    if not provider_authenticated(provider):
        account = "ChatGPT" if provider == "codex" else "Claude"
        raise ValueError(f"{account} is not connected. Connect it from the dashboard first.")
    run_id = Path(payload["run"]).name if kind in {"resume", "retry"} else ""
    existing = jobs() if run_id else []
    related = [job for job in existing if job.get("run_id") == run_id]
    parent_job_id = related[0]["id"] if related else ""
    attempt_number = max((int(job.get("attempt_number") or 0) for job in related), default=0) + 1
    attempt_kind = "diagnostic_retry" if kind == "retry" else (resume_attempt_kind(Path(payload["run"])) if kind == "resume" else "initial")
    with _lock:
        if any(job.get("running") or job.get("status") == "queued" for job in jobs()):
            raise ValueError("Another assessment job is running or queued.")
        job_id = uuid.uuid4().hex
        directory = STATE_ROOT / job_id
        directory.mkdir(parents=True)
        state = {
            "id": job_id, "kind": kind, "label": label, "queued_utc": utc_now(),
            "started_utc": "", "running": False, "exit_code": None, "status": "queued",
            "run_id": run_id, "attempt_number": attempt_number,
            "attempt_kind": attempt_kind, "parent_job_id": parent_job_id,
        }
        atomic_write_json(directory / "request.json", {"kind": kind, "label": label, "payload": payload})
        atomic_write_json(directory / "job.json", state)
    return job_state(job_id)


