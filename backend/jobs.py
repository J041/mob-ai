"""Durable job history, attempt lineage, and queue submission service."""

from __future__ import annotations

from pathlib import Path
import re
import threading
import time
import uuid

from assessment.state import (
    checkpoint_recovery_available, frida_recovery_available, pause_recovery_available,
    usage_limit_recovery_available,
)
from backend.auth import provider_authenticated
from backend.common import json_file, utc_now
from backend.providers import PROVIDER_IDS
from worker.queue import STATE_ROOT, atomic_write_json

_lock = threading.RLock()
_log_cache: dict[tuple[str, str], str] = {}
_log_cache_lock = threading.Lock()
_job_usage_cache: dict[str, tuple[tuple[int, int], dict]] = {}


def _read_job_log(log_path: Path, limit: int, mode: str) -> str:
    """Read a live bind-mounted log without surfacing transient Docker I/O races."""
    cache_key = (str(log_path), mode)
    if not log_path.is_file():
        return ""
    for attempt in range(4):
        try:
            with log_path.open("rb") as stream:
                if mode == "tail":
                    stream.seek(max(0, log_path.stat().st_size - limit))
                value = stream.read(limit if mode == "head" else -1).decode("utf-8", errors="replace")
            with _log_cache_lock:
                _log_cache[cache_key] = value
            return value
        except OSError:
            if attempt < 3:
                time.sleep(0.025 * (2 ** attempt))
    with _log_cache_lock:
        return _log_cache.get(cache_key, "")

def job_log_tail(job_id: str, limit: int = 120_000) -> str:
    log_path = STATE_ROOT / job_id / "output.log"
    return _read_job_log(log_path, limit, "tail")


def job_log_head(job_id: str, limit: int = 8_000) -> str:
    log_path = STATE_ROOT / job_id / "output.log"
    return _read_job_log(log_path, limit, "head")


def legacy_job_token_usage(job_id: str) -> dict:
    log_path = STATE_ROOT / job_id / "output.log"
    try:
        stat = log_path.stat()
    except OSError:
        stat = None
    signature = (stat.st_mtime_ns, stat.st_size) if stat else (0, 0)
    cached = _job_usage_cache.get(str(log_path))
    if cached and cached[0] == signature:
        return dict(cached[1])
    text = _read_job_log(log_path, stat.st_size if stat else 0, "full") if stat else ""
    values = [
        int(value.replace(",", ""))
        for value in re.findall(r"(?m)^tokens used\s*\r?\n\s*([\d,]+)\s*$", text, re.I)
    ]
    usage = {
        "input_tokens": 0, "cached_input_tokens": 0,
        "cache_creation_input_tokens": 0, "output_tokens": 0,
        "reasoning_output_tokens": 0, "total_tokens": sum(values),
        "calls": len(values), "detailed_calls": 0,
        "total_only_calls": len(values), "complete": False,
    }
    _job_usage_cache[str(log_path)] = (signature, usage)
    return dict(usage)


def request_job_control(job_id: str, action: str) -> dict:
    """Durably request queued/running cancellation or a safe-boundary pause."""
    if not re.fullmatch(r"[a-f0-9]{32}", job_id):
        raise ValueError("Invalid job identifier.")
    if action not in {"cancel", "pause"}:
        raise ValueError("Unsupported job control action.")
    directory = STATE_ROOT / job_id
    state_path = directory / "job.json"
    with _lock:
        state = json_file(state_path)
        if not state:
            raise FileNotFoundError("Job not found.")
        status = str(state.get("status") or "")
        if action == "cancel":
            if status == "queued" and not state.get("running"):
                state.update({
                    "status": "cancelled", "running": False, "exit_code": None,
                    "cancel_requested": True, "cancel_requested_utc": utc_now(),
                    "completed_utc": utc_now(),
                    "detail": "Cancelled before the durable worker started this job.",
                })
                (directory / "claim.lock").unlink(missing_ok=True)
            elif state.get("running") or status in {"running", "pausing", "cancelling"}:
                state.update({
                    "status": "cancelling", "cancel_requested": True,
                    "cancel_requested_utc": utc_now(),
                    "detail": "Cancellation requested; stopping the active assessment process.",
                })
            else:
                raise ValueError(f"Job cannot be cancelled from status {status!r}.")
        else:
            if not state.get("running") or status not in {"running", "pausing"}:
                raise ValueError("Only a running job can pause after its current stage.")
            state.update({
                "status": "pausing", "pause_requested": True,
                "pause_requested_utc": utc_now(),
                "detail": "Pause requested; the current safe stage will finish before checkpointing.",
            })
        atomic_write_json(state_path, state)
    return job_state(job_id)


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
    if include_output and not isinstance(state.get("token_usage"), dict):
        state["token_usage"] = legacy_job_token_usage(job_id)
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
    if pause_recovery_available(summary):
        return "pause_resume"
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


