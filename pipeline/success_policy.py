"""Shared validation for deterministic success-policy JSON documents."""

from __future__ import annotations

import re
from typing import Any


SUPPORTED_CHECK_TYPES = frozenset({
    "process_alive", "foreground_package", "activity_reached", "no_crash",
    "ui_text_regex", "ui_text_not_regex", "log_regex", "frida_regex",
    "output_regex", "log_not_regex",
})
REGEX_CHECK_TYPES = frozenset({
    "ui_text_regex", "ui_text_not_regex", "log_regex", "frida_regex",
    "output_regex", "log_not_regex",
})


def validate_success_policy(data: Any) -> dict[str, object]:
    """Return the normalized policy or raise ValueError with a user-facing reason."""
    if not isinstance(data, dict) or data.get("mode", "all") not in {"all", "any"}:
        raise ValueError("Success spec must be an object with mode 'all' or 'any'")
    checks = data.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ValueError("Success spec requires a non-empty 'checks' array")
    for index, check in enumerate(checks, 1):
        if not isinstance(check, dict) or check.get("type") not in SUPPORTED_CHECK_TYPES:
            supported = ", ".join(sorted(SUPPORTED_CHECK_TYPES))
            raise ValueError(f"Invalid success check #{index}; supported types: {supported}")
        if check["type"] == "activity_reached" and (
            not isinstance(check.get("activity"), str) or not check["activity"]
        ):
            raise ValueError(f"Success check #{index} requires a non-empty activity name")
        if check["type"] == "foreground_package" and "package" in check and (
            not isinstance(check.get("package"), str) or not check["package"]
        ):
            raise ValueError(f"Success check #{index} package must be a non-empty string")
        if check["type"] in REGEX_CHECK_TYPES:
            if not isinstance(check.get("pattern"), str) or not check["pattern"]:
                raise ValueError(f"Success check #{index} requires a non-empty regex pattern")
            try:
                re.compile(check["pattern"])
            except re.error as error:
                raise ValueError(f"Invalid regex in success check #{index}: {error}") from error
    repeat = data.get("repeat", 1)
    min_passes = data.get("min_passes", repeat)
    if not isinstance(repeat, int) or isinstance(repeat, bool) or not 1 <= repeat <= 3:
        raise ValueError("Success spec 'repeat' must be an integer from 1 to 3")
    if not isinstance(min_passes, int) or isinstance(min_passes, bool) or not 1 <= min_passes <= repeat:
        raise ValueError("Success spec 'min_passes' must be between 1 and repeat")
    return {
        "mode": data.get("mode", "all"), "checks": checks,
        "repeat": repeat, "min_passes": min_passes,
        "baseline_required": bool(data.get("baseline_required", False)),
        "name": str(data.get("name") or "Success policy"),
    }
