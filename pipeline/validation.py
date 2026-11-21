"""Structured success-policy loading and deterministic evidence evaluation."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Callable

try:
    from pipeline.success_policy import validate_success_policy
except ModuleNotFoundError:  # Direct execution from /workspace/pipeline.
    from success_policy import validate_success_policy  # type: ignore


def load_success_spec(path: Path | None) -> dict[str, object] | None:
    if path is None:
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    try:
        return validate_success_policy(data)
    except ValueError as error:
        raise RuntimeError(str(error)) from error


def evaluate_success(
    args, package: str, frida_output: str, logcat: str,
    spec: dict[str, object] | None, *, adb_runner: Callable,
) -> tuple[bool, list[dict[str, object]]]:
    if spec is None:
        if not args.success_regex:
            return False, []
        matched = re.search(args.success_regex, frida_output + "\n" + logcat, re.I | re.M) is not None
        return matched, [{"type": "output_regex", "pattern": args.success_regex, "passed": matched}]

    results: list[dict[str, object]] = []
    ui_xml: str | None = None

    def get_ui_xml() -> str:
        nonlocal ui_xml
        if ui_xml is None:
            remote = "/sdcard/mob-ai-window.xml"
            dumped = adb_runner(args, "shell", "uiautomator", "dump", remote, check=False)
            if dumped.returncode == 0:
                ui_xml = adb_runner(args, "shell", "cat", remote, check=False).stdout
            else:
                ui_xml = ""
            adb_runner(args, "shell", "rm", "-f", remote, check=False)
        return ui_xml

    for check in spec["checks"]:
        kind = str(check["type"])
        result: dict[str, object] = {"type": kind, "passed": False}
        if kind == "process_alive":
            probe = adb_runner(args, "shell", "pidof", package, check=False)
            result.update(passed=probe.returncode == 0 and bool(probe.stdout.strip()), evidence=probe.stdout.strip()[:500])
        elif kind == "foreground_package":
            expected = str(check.get("package") or package)
            probe = adb_runner(args, "shell", "dumpsys", "activity", "activities", check=False)
            resumed = "\n".join(line.strip() for line in probe.stdout.splitlines() if "ResumedActivity" in line)
            result.update(package=expected, passed=expected in resumed, evidence=resumed[:500])
        elif kind == "activity_reached":
            expected = str(check["activity"])
            probe = adb_runner(args, "shell", "dumpsys", "activity", "activities", check=False)
            resumed = "\n".join(
                line.strip() for line in probe.stdout.splitlines()
                if "ResumedActivity" in line or "topResumedActivity" in line
            )
            result.update(activity=expected, passed=expected in resumed, evidence=resumed[:500])
        elif kind == "no_crash":
            crash_pattern = (
                r"FATAL EXCEPTION|AndroidRuntime.*Process:|has died:|Force finishing activity|"
                r"Fatal signal\s+\d+|signal\s+\d+\s+\(SIG(?:SEGV|BUS|ABRT|ILL|FPE)\)|"
                r"APP CRASH\((?:NATIVE|EXCEPTION)\)"
            )
            matched = re.search(crash_pattern, logcat, re.I | re.M) is not None
            result.update(passed=not matched, pattern=crash_pattern)
        else:
            pattern = str(check["pattern"])
            if kind in {"ui_text_regex", "ui_text_not_regex"}:
                haystack = get_ui_xml()
            else:
                haystack = {
                    "log_regex": logcat,
                    "log_not_regex": logcat,
                    "frida_regex": frida_output,
                    "output_regex": frida_output + "\n" + logcat,
                }[kind]
            matched = re.search(pattern, haystack, re.I | re.M) is not None
            passed = not matched if kind in {"log_not_regex", "ui_text_not_regex"} else matched
            result.update(pattern=pattern, passed=passed)
            if kind.startswith("ui_text_"):
                result["evidence"] = haystack[:500]
        results.append(result)
    passed_values = [bool(result["passed"]) for result in results]
    success = all(passed_values) if spec["mode"] == "all" else any(passed_values)
    return success, results
