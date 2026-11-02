"""Run-summary persistence and recovery-state predicates."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from ui.orchestrator_outcomes import terminal_outcome
from ui.orchestrator_runtime import workspace_relative, write_json


def write_summary(
    run_dir: Path, status: str, records: list[Any], detail: str, *,
    checkpoint: dict[str, Any] | None = None, reason: str = "",
    usage: dict[str, Any] | None = None,
) -> None:
    payload = {
        "status": status,
        "detail": detail,
        "reason": reason,
        "recoverable": status in {"environment_error", "usage_limited"} and bool(checkpoint),
        "checkpoint": checkpoint,
        "usage": usage,
        "run_directory": workspace_relative(run_dir),
        "completed_utc": datetime.now(timezone.utc).isoformat(),
        "iterations": records,
    }
    payload["terminal"] = terminal_outcome(payload)
    write_json(run_dir / "codex-loop-result.json", payload)



def frida_recovery_available(summary: dict[str, Any]) -> bool:
    """Limit human-review continuation to recognizable Frida transport failures."""
    if summary.get("status") != "human_review":
        return False
    evidence = json.dumps({
        "detail": summary.get("detail"),
        "last_iteration": (summary.get("iterations") or [{}])[-1],
    }, ensure_ascii=False).lower()
    failures = (
        "connection refused", "connection closed", "failed to spawn",
        "inaccessible or not found", "frida-server", "port 27042",
    )
    return "frida" in evidence and any(marker in evidence for marker in failures)


def checkpoint_recovery_available(summary: dict[str, Any]) -> bool:
    checkpoint = summary.get("checkpoint") or {}
    return bool(
        summary.get("status") == "environment_error"
        and summary.get("recoverable")
        and checkpoint.get("stage") in {"observation", "validation"}
    )


def usage_limit_recovery_available(summary: dict[str, Any]) -> bool:
    checkpoint = summary.get("checkpoint") or {}
    return bool(
        summary.get("status") == "usage_limited"
        and summary.get("recoverable")
        and checkpoint.get("stage") in {"native_selection", "provider", "native_replenishment"}
    )

