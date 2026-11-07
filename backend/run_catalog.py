"""Read-only assessment run catalog and recorded policy metadata."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re

from assessment.outcomes import terminal_outcome
from assessment.runtime import RUNS_ROOT, WORKSPACE, sha256, workspace_relative
from assessment.usage import assessment_token_usage
from assessment.goals import goal_summary
from assessment.state import (
    checkpoint_recovery_available, frida_recovery_available, pause_recovery_available,
    usage_limit_recovery_available,
)
from backend.common import json_file

def recorded_success_policy(config: dict | None) -> dict:
    """Return safe display metadata for the immutable policy bound to a run."""
    config = config or {}
    relative = str(config.get("success_spec") or "")
    expected_hash = str(config.get("success_spec_sha256") or "")
    policy: dict = {}
    valid = False
    if relative:
        try:
            path = (WORKSPACE / relative).resolve()
            path.relative_to(WORKSPACE)
            policy = json_file(path) or {}
            valid = bool(policy and expected_hash and sha256(path) == expected_hash)
        except (ValueError, OSError):
            pass
    checks = []
    expected_activity = ""
    expected_ui_pattern = ""
    forbidden_ui_pattern = ""
    for check in policy.get("checks") or []:
        check_type = str(check.get("type") or "") if isinstance(check, dict) else ""
        if check_type:
            checks.append(check_type)
        if check_type == "activity_reached":
            expected_activity = str(check.get("activity") or "")
        elif check_type == "ui_text_regex":
            expected_ui_pattern = str(check.get("pattern") or "")
        elif check_type == "ui_text_not_regex":
            forbidden_ui_pattern = str(check.get("pattern") or "")
    return {
        "name": str(policy.get("name") or "Recorded success policy"),
        "preset": str(policy.get("preset") or "advanced"),
        "repeat": int(policy.get("repeat") or 1),
        "min_passes": int(policy.get("min_passes") or policy.get("repeat") or 1),
        "baseline_required": bool(policy.get("baseline_required")),
        "checks": checks,
        "sha256": expected_hash,
        "valid": valid,
        "path": relative,
        "expected_activity": expected_activity,
        "expected_ui_pattern": expected_ui_pattern,
        "forbidden_ui_pattern": forbidden_ui_pattern,
    }


def runs() -> list[dict]:
    if not RUNS_ROOT.is_dir():
        return []
    result: list[dict] = []
    for directory in sorted(RUNS_ROOT.iterdir(), key=lambda path: path.stat().st_mtime, reverse=True):
        if not directory.is_dir():
            continue
        report = json_file(directory / "report.json")
        if not report:
            continue
        latest = json_file(directory / "result.json") or {}
        loop = json_file(directory / "codex-loop-result.json")
        config = json_file(directory / "codex-loop-config.json")
        native_selection = json_file(directory / "native-selection.json") or {}
        native_batches = native_selection.get("batches") or []
        native_queue = native_selection.get("queue") or []
        native_libraries = {
            str(name)
            for batch in native_batches if isinstance(batch, dict)
            for name in (batch.get("libraries") or []) if name
        }
        native_libraries.update(
            str(item.get("library")) for item in native_queue
            if isinstance(item, dict) and item.get("library")
        )
        native_processed = sum(
            len(batch.get("libraries") or []) for batch in native_batches
            if isinstance(batch, dict) and batch.get("status") in {"inconclusive", "resolved"}
        )
        policy = recorded_success_policy(config)
        frida_recoverable = bool(loop and config and frida_recovery_available(loop))
        checkpoint_recoverable = bool(loop and config and checkpoint_recovery_available(loop))
        usage_recoverable = bool(loop and config and usage_limit_recovery_available(loop))
        pause_recoverable = bool(loop and config and pause_recovery_available(loop))
        usage = (loop.get("usage") or {}) if loop else {}
        terminal = terminal_outcome(loop)
        token_usage = assessment_token_usage(directory)
        resumable = bool(loop and loop.get("status") == "max_iterations" and config)
        retryable = bool(loop and config and (directory / "original.apk").is_file())
        actual_model = str(config.get("model") or "") if config else ""
        actual_effort = str(config.get("reasoning_effort") or "") if config else ""
        if (not actual_model or not actual_effort) and (directory / "agent").is_dir():
            logs = sorted((directory / "agent").glob("iteration-*/codex.log"), key=lambda path: path.stat().st_mtime, reverse=True)
            if logs:
                header = logs[0].read_text(encoding="utf-8", errors="replace")[:4000]
                model_match = re.search(r"(?m)^model:\s*(\S+)", header)
                effort_match = re.search(r"(?m)^reasoning effort:\s*(\S+)", header)
                actual_model = actual_model or (model_match.group(1) if model_match else "")
                actual_effort = actual_effort or (effort_match.group(1) if effort_match else "")
        result.append({
            "id": directory.name,
            "path": workspace_relative(directory),
            "package": str(report.get("package") or ""),
            "apk_sha256": str(report.get("sha256") or ""),
            "created_utc": str(report.get("created_utc") or ""),
            "static_findings": len(report.get("findings") or []),
            "observation_events": int(latest.get("observation_events") or 0),
            "status": str(loop.get("status") if loop else ("success" if latest.get("success") else "analysis")),
            "detail": str(loop.get("detail") if loop else ""),
            "terminal": terminal,
            "iterations": len(loop.get("iterations") or []) if loop else 0,
            "token_usage": token_usage,
            "resumable": resumable,
            "frida_recoverable": frida_recoverable,
            "checkpoint_recoverable": checkpoint_recoverable,
            "usage_recoverable": usage_recoverable,
            "pause_recoverable": pause_recoverable,
            "continuable": bool(
                resumable or frida_recoverable or checkpoint_recoverable
                or usage_recoverable or pause_recoverable
            ),
            "retryable": retryable,
            "recovery_stage": str(((loop.get("checkpoint") or {}).get("stage") if loop else "") or ""),
            "reason": str((loop.get("reason") if loop else "") or ""),
            "usage_reset_utc": str(usage.get("reset_utc") or ""),
            "usage_auto_resume": bool(usage.get("auto_resume")),
            "frida_server": str(config.get("start_frida_server") if config else ""),
            "frida_version": str(config.get("frida_version") if config else ""),
            "reasoning_mode": str((config.get("reasoning_mode") if config else "single") or "single"),
            "provider": str((config.get("provider") if config else "codex") or "codex"),
            "model": actual_model,
            "reasoning_effort": actual_effort,
            "specialist_count": int(config.get("specialist_count") or 3) if config else 3,
            "target": str(config.get("target") if config else latest.get("device") or ""),
            "transport": str(config.get("transport") if config else latest.get("transport") or ""),
            "success_policy": policy,
            "apk_name": Path(str(config.get("apk") or "original.apk")).name if config else "original.apk",
            "observation_seconds": int(config.get("observation_seconds") or 15) if config else 15,
            "run_seconds": int(config.get("run_seconds") or 20) if config else 20,
            "derived_from_run": str(config.get("derived_from_run") or "") if config else "",
            "native_queue": {
                "status": str(native_selection.get("queue_status") or "not_started"),
                "batch": int((native_batches[-1].get("number") if native_batches else 0) or 0),
                "batches": ((len(native_libraries) + 4) // 5) if native_libraries else 0,
                "processed": native_processed,
                "total": len(native_libraries),
                "queued": len(native_queue),
            },
            "goal": goal_summary(directory),
            "updated_utc": datetime.fromtimestamp(directory.stat().st_mtime, timezone.utc).isoformat(),
        })
    return result


