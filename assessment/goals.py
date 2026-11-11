"""Codex Goal event helpers used only by optional deep investigations."""

from __future__ import annotations

import json


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
            if any(value.get(key) == tool for key in ("name", "tool", "tool_name", "function", "function_name")):
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
