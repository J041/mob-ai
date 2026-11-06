"""Persistent Codex Goal contract for an assessment run."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from assessment.runtime import WORKSPACE, read_json, workspace_relative, write_json


GOAL_FILE = "assessment-goal.json"
GOAL_WORKSPACE = Path("agent") / "codex-goal"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _policy(config: dict[str, Any]) -> dict[str, Any]:
    relative = str(config.get("success_spec") or "")
    if not relative:
        return {}
    path = (WORKSPACE / relative).resolve()
    try:
        path.relative_to(WORKSPACE.resolve())
    except ValueError:
        return {}
    return read_json(path) if path.is_file() else {}


def ensure_assessment_goal(run_dir: Path, config: dict[str, Any]) -> dict[str, Any]:
    """Create the run-scoped completion contract without replacing prior Goal state."""
    path = run_dir / GOAL_FILE
    if path.is_file():
        value = read_json(path)
        if isinstance(value, dict) and value.get("objective"):
            return value

    policy = _policy(config)
    package = str(config.get("package") or "the recorded package")
    policy_name = str(policy.get("name") or "the recorded success policy")
    objective = (
        f"Produce the smallest evidence-based Frida bypass for {package} that is proven by "
        f"the deterministic '{policy_name}' success policy."
    )
    value: dict[str, Any] = {
        "version": 1,
        "provider": "codex",
        "status": "pending_activation",
        "objective": objective,
        "verification_surface": {
            "policy": policy_name,
            "policy_path": str(config.get("success_spec") or ""),
            "policy_sha256": str(config.get("success_spec_sha256") or ""),
            "required_result": "result.json success=true with every recorded check passing",
        },
        "constraints": [
            "Prefer a narrow Frida hook before any reviewed static patch.",
            "Never claim success; only deterministic validation may establish it.",
            "Preserve the original APK and operate only inside this assessment run.",
            "Do not run ADB, Frida, install commands, or device operations from the reasoning turn.",
        ],
        "boundaries": {
            "editable": "agent/codex-goal/candidate.js",
            "device_execution": "deterministic orchestrator only",
            "maximum_iterations": "bounded by each recorded pipeline invocation",
        },
        "iteration_policy": (
            "After each failed validation, compare the newest static, runtime, native, and policy evidence; "
            "make the next smallest causally justified hook change or request one bounded diagnostic pass."
        ),
        "blocked_stop_condition": (
            "Request human review when no evidence-based hook or remaining allowlisted diagnostic can "
            "resolve the failure, or when the next action would cross the recorded safety boundary."
        ),
        "thread_id": "",
        "activation_verified": False,
        "created_utc": _utc_now(),
        "updated_utc": _utc_now(),
    }
    write_json(path, value)
    return value


def goal_workspace(run_dir: Path) -> Path:
    path = run_dir / GOAL_WORKSPACE
    path.mkdir(parents=True, exist_ok=True)
    return path


def goal_instruction(goal: dict[str, Any], *, first_turn: bool) -> str:
    contract = {
        key: goal.get(key)
        for key in (
            "objective", "verification_surface", "constraints", "boundaries",
            "iteration_policy", "blocked_stop_condition",
        )
    }
    rendered = json.dumps(contract, indent=2, ensure_ascii=False)
    if first_turn:
        lifecycle = """This is the first reasoning turn in a persistent Codex assessment thread.
Before inspecting or editing assessment evidence, call the Codex `create_goal` tool exactly once with the objective below. The Goal has no separate token budget. Keep it active until deterministic validation reports success; do not mark it complete from reasoning alone."""
    else:
        lifecycle = """Continue the active Codex Goal already attached to this persistent assessment thread. Do not create a second Goal. Treat the newest deterministic validation and evidence as the current Goal progress."""
    return f"""{lifecycle}

Assessment Goal contract:
{rendered}

The deterministic orchestrator, not the Goal dispatcher, controls iteration count, device execution, and completion evidence.
"""


def codex_thread_id(output: str) -> str:
    for line in (output or "").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and event.get("type") == "thread.started":
            value = str(event.get("thread_id") or "")
            if value:
                return value
    return ""


def goal_tool_observed(output: str, tool: str) -> bool:
    """Find a Goal lifecycle tool name without depending on one JSON event shape."""
    def contains_tool(value: object) -> bool:
        if isinstance(value, dict):
            if any(value.get(key) == tool for key in ("name", "tool", "tool_name")):
                return True
            return any(contains_tool(child) for child in value.values())
        if isinstance(value, list):
            return any(contains_tool(child) for child in value)
        return False

    for line in (output or "").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if contains_tool(event):
            return True
    return False


def record_goal_turn(
    run_dir: Path, output: str, *, iteration: int, resumed: bool,
) -> dict[str, Any]:
    path = run_dir / GOAL_FILE
    goal = read_json(path)
    thread_id = codex_thread_id(output)
    if thread_id:
        goal["thread_id"] = thread_id
    if not resumed:
        goal["activation_verified"] = goal_tool_observed(output, "create_goal")
        goal["status"] = "active" if goal["activation_verified"] else "activation_unverified"
    goal["last_iteration"] = iteration
    goal["updated_utc"] = _utc_now()
    write_json(path, goal)
    return goal


def update_goal_for_pipeline_status(run_dir: Path, status: str, detail: str) -> None:
    """Mirror deterministic pipeline state without pretending it changed Codex thread state."""
    path = run_dir / GOAL_FILE
    if not path.is_file():
        return
    goal = read_json(path)
    if status in {"success", "success_without_bypass"}:
        goal_status = "complete"
    elif status == "human_review":
        goal_status = "needs_input"
    elif status in {"assessment_failed", "codex_boundary_error"}:
        goal_status = "blocked"
    else:
        goal_status = "active" if goal.get("thread_id") else str(goal.get("status") or "pending_activation")
    goal.update({
        "status": goal_status,
        "pipeline_status": status,
        "pipeline_detail": detail,
        "updated_utc": _utc_now(),
    })
    write_json(path, goal)


def goal_summary(run_dir: Path) -> dict[str, Any]:
    path = run_dir / GOAL_FILE
    if not path.is_file():
        return {}
    value = read_json(path)
    return {
        "status": str(value.get("status") or ""),
        "objective": str(value.get("objective") or ""),
        "activation_verified": bool(value.get("activation_verified")),
        "persistent_thread": bool(value.get("thread_id")),
        "path": workspace_relative(path),
    }
