"""Persist and present durable job progress as a normalized stage timeline."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import uuid
from typing import Any


ASSESSMENT_STAGES = (
    ("queued", "Queued", "Waiting for the durable worker."),
    ("static_analysis", "Static analysis", "Preparing and decompiling the APK."),
    ("observation", "Observation", "Collecting baseline device and runtime evidence."),
    ("native_analysis", "Native analysis", "Selecting and reviewing relevant native binaries."),
    ("reasoning", "Reasoning", "Reviewing evidence and producing a bounded candidate hook."),
    ("validation", "Validation", "Testing the candidate against the success policy."),
)
DEEP_GOAL_STAGES = (
    ASSESSMENT_STAGES[0],
    ("reasoning", "Reasoning", "Performing the optional read-only deep investigation."),
)
BYPASS_STAGES = (
    ASSESSMENT_STAGES[0],
    ("device_session", "Device session", "Launching the validated bypass on the recorded target."),
)

TERMINAL_FAILURES = {
    "human_review", "provider_error", "environment_error", "pipeline_error",
    "codex_error", "codex_boundary_error", "assessment_failed", "worker_error",
    "needs_input", "error", "failed", "interrupted", "usage_limited", "max_iterations",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def normalize_stage(raw: str, kind: str) -> str:
    value = raw.strip().lower()
    if value in {"", "queued", "starting"}:
        return "queued"
    if kind == "launch_bypass":
        return "device_session"
    if kind == "deep_goal":
        return "reasoning"
    if value.startswith("static") or value in {"prepare", "decompile", "jadx"}:
        return "static_analysis"
    if (
        value.startswith("native") or value.startswith("ghidra")
        or "native_selection" in value or "replenishment" in value
    ):
        return "native_analysis"
    if value.startswith("provider") or value.startswith("reasoning"):
        return "reasoning"
    if value.startswith("validation") or re.fullmatch(r"iteration_\d+", value):
        return "validation"
    if (
        value.startswith("observation") or value.startswith("diagnostic")
        or value.startswith("adaptive_diagnostics") or value.startswith("frida_")
        or value in {"device_state", "app_stop"}
    ):
        return "observation"
    return "queued"


def stage_detail(raw: str, normalized: str) -> tuple[str, str]:
    iteration = re.search(r"(?:iteration_|_iteration_)(\d+)", raw)
    number = iteration.group(1) if iteration else ""
    if normalized == "static_analysis":
        return "Preparing APK metadata, JADX output and native inventory.", "report.json"
    if normalized == "observation":
        detail = "Collecting baseline ADB, Frida and Logcat evidence."
        return detail, "observations.json"
    if normalized == "native_analysis":
        detail = f"Preparing native evidence for iteration {number}." if number else "Selecting and preparing native evidence."
        return detail, "native-selection.json"
    if normalized == "reasoning":
        detail = f"Provider reasoning for iteration {number}." if number else "Provider is reviewing the recorded evidence."
        artifact = f"agent/iteration-{number}/" if number else "agent/"
        return detail, artifact
    if normalized == "validation":
        detail = f"Validating candidate from iteration {number}." if number else "Evaluating the candidate against the success policy."
        artifact = f"agent/iteration-{number}/pipeline.log" if number else "result.json"
        return detail, artifact
    if normalized == "device_session":
        return "Starting and monitoring the validated Frida bypass session.", "launches/"
    return "Waiting for the durable worker to claim this job.", ""


class JobProgressRecorder:
    """Append stage transitions to a sidecar without racing job-control state writes."""

    def __init__(self, path: Path, kind: str, queued_utc: str = "") -> None:
        self.path = path
        self.kind = kind
        self.queued_utc = queued_utc or utc_now()

    @classmethod
    def initialize(cls, path: Path, kind: str, queued_utc: str) -> None:
        if path.is_file():
            return
        _atomic_write(path, {
            "version": 1, "kind": kind, "current_stage": "queued",
            "updated_utc": queued_utc, "terminal_status": "",
            "history": [{"stage": "queued", "started_utc": queued_utc, "completed_utc": ""}],
        })

    def transition(self, raw_stage: str) -> None:
        now = utc_now()
        value = _read(self.path)
        history = list(value.get("history") or [])
        if history and history[-1].get("stage") == raw_stage and not history[-1].get("completed_utc"):
            return
        if history and not history[-1].get("completed_utc"):
            history[-1]["completed_utc"] = now
        history.append({"stage": raw_stage, "started_utc": now, "completed_utc": ""})
        _atomic_write(self.path, {
            "version": 1, "kind": self.kind, "current_stage": raw_stage,
            "updated_utc": now, "terminal_status": "", "history": history,
        })

    def finish(self, status: str) -> None:
        now = utc_now()
        value = _read(self.path)
        history = list(value.get("history") or [])
        if history and not history[-1].get("completed_utc"):
            history[-1]["completed_utc"] = now
        value.update({
            "version": 1, "kind": self.kind,
            "current_stage": str(value.get("current_stage") or "queued"),
            "updated_utc": now, "terminal_status": status, "history": history,
        })
        _atomic_write(self.path, value)


def _seconds(started: str, completed: str = "") -> int:
    try:
        start = datetime.fromisoformat(started.replace("Z", "+00:00"))
        end = datetime.fromisoformat(completed.replace("Z", "+00:00")) if completed else datetime.now(timezone.utc)
        return max(0, int((end - start).total_seconds()))
    except (ValueError, AttributeError):
        return 0


def build_job_timeline(state: dict[str, Any], progress: dict[str, Any]) -> dict[str, Any]:
    kind = str(state.get("kind") or progress.get("kind") or "start")
    definitions = DEEP_GOAL_STAGES if kind == "deep_goal" else BYPASS_STAGES if kind == "launch_bypass" else ASSESSMENT_STAGES
    history = [item for item in (progress.get("history") or []) if isinstance(item, dict)]
    if not history:
        queued = str(state.get("queued_utc") or utc_now())
        history = [{"stage": "queued", "started_utc": queued, "completed_utc": str(state.get("started_utc") or "")}]
    current_raw = str(progress.get("current_stage") or history[-1].get("stage") or "queued")
    current = normalize_stage(current_raw, kind)
    terminal = str(state.get("status") or progress.get("terminal_status") or "")
    running = bool(state.get("running")) or terminal in {"queued", "running", "pausing", "cancelling"}
    stages: list[dict[str, Any]] = []
    order = [item[0] for item in definitions]
    current_index = order.index(current) if current in order else 0
    for stage_index, (identifier, label, description) in enumerate(definitions):
        visits = [item for item in history if normalize_stage(str(item.get("stage") or ""), kind) == identifier]
        started = str(visits[-1].get("started_utc") or "") if visits else ""
        completed = str(visits[-1].get("completed_utc") or "") if visits else ""
        if running and identifier == current:
            stage_status = "active" if terminal in {"queued", "running"} else terminal
        elif visits:
            if not running and identifier == current and terminal in TERMINAL_FAILURES:
                stage_status = "failed"
            elif not running and identifier == current and terminal in {"paused", "cancelled"}:
                stage_status = terminal
            else:
                stage_status = "completed"
        elif (running and stage_index < current_index) or (not running and terminal not in {"", "queued"}):
            stage_status = "skipped"
        else:
            stage_status = "waiting"
        detail, artifact = stage_detail(current_raw if identifier == current else identifier, identifier)
        stages.append({
            "id": identifier, "label": label, "description": description,
            "status": stage_status, "started_utc": started, "completed_utc": completed,
            "elapsed_seconds": _seconds(started, completed) if started else 0,
            "visits": len(visits), "detail": detail, "artifact": artifact,
        })
    active = next((stage for stage in stages if stage["id"] == current), stages[0])
    return {
        "current_stage": current, "raw_stage": current_raw,
        "detail": active["detail"], "artifact": active["artifact"],
        "updated_utc": str(progress.get("updated_utc") or state.get("queued_utc") or ""),
        "stages": stages,
    }
