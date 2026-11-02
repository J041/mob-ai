"""Shared web-control-plane serialization and process-output helpers."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re


ANSI_ESCAPE = re.compile(r"\x1B(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\))")


def strip_terminal_controls(value: str) -> str:
    value = ANSI_ESCAPE.sub("", value).replace("\r", "")
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)


def subprocess_capture_text(*values) -> str:
    """Normalize process output, which TimeoutExpired may expose as bytes despite text=True."""
    return strip_terminal_controls("".join(
        value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value or "")
        for value in values
    ))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def truthy(value: object) -> bool:
    return str(value or "").lower() in {"1", "true", "yes", "on"}


def json_file(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig")) if path.is_file() else None
    except (OSError, json.JSONDecodeError):
        return None
