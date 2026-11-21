"""Success-policy generation, validation, and persistence services."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Callable
import uuid

from werkzeug.utils import secure_filename

from assessment.runtime import write_json, workspace_relative
from pipeline.success_policy import validate_success_policy
from runtime_data import POLICY_ROOT


MAX_POLICY_BYTES = 256 * 1024
WorkspaceResolver = Callable[[str], Path]


def create_success_policy(body: dict, resolve_workspace_item: WorkspaceResolver) -> Path:
    preset = str(body.get("policy_preset") or "basic")
    if preset == "advanced":
        return resolve_workspace_item(str(body.get("success_spec") or ""))
    if preset not in {"basic", "detection_removed", "screen_reached", "custom"}:
        raise ValueError("Invalid success-policy preset.")
    repeat = int(body.get("policy_repeat") or 2)
    if not 1 <= repeat <= 3:
        raise ValueError("Repeat validation must be between 1 and 3 runs.")
    min_passes = int(body.get("policy_min_passes") or repeat)
    if not 1 <= min_passes <= repeat:
        raise ValueError("Required validation passes must be between 1 and the repeat count.")
    activity = str(body.get("expected_activity") or "").strip() if preset in {"screen_reached", "custom"} else ""
    expected_text = str(body.get("expected_ui_pattern") or "").strip() if preset in {"screen_reached", "custom"} else ""
    use_regex = bool(body.get("policy_use_regex"))
    ui_phrases = str(body.get("forbidden_ui_phrases") or "").strip()
    log_phrases = str(body.get("forbidden_log_phrases") or "").strip()
    ui_regex = str(body.get("forbidden_ui_pattern") or "").strip()
    log_regex = str(body.get("forbidden_log_pattern") or "").strip()
    if ui_regex and not (ui_phrases or log_phrases or body.get("policy_use_regex") is not None):
        use_regex = True
        log_regex = log_regex or ui_regex

    def literal_pattern(value: str, label: str) -> str:
        phrases = [item.strip() for item in re.split(r"[,\r\n]+", value) if item.strip()]
        if len(phrases) > 20:
            raise ValueError(f"{label} accepts at most 20 phrases.")
        if any(len(item) > 200 for item in phrases):
            raise ValueError(f"{label} phrases must be 200 characters or fewer.")
        return "(?:" + "|".join(re.escape(item) for item in phrases) + ")" if phrases else ""

    forbidden_ui = ui_regex if use_regex else literal_pattern(ui_phrases, "Visible warning")
    forbidden_log = log_regex if use_regex else literal_pattern(log_phrases, "Log warning")
    if preset not in {"detection_removed", "custom"}:
        forbidden_ui = forbidden_log = ""
    for label, pattern in (
        ("expected UI pattern", expected_text),
        ("forbidden UI pattern", forbidden_ui),
        ("forbidden Logcat pattern", forbidden_log),
    ):
        if pattern:
            try:
                re.compile(pattern)
            except re.error as error:
                raise ValueError(f"Invalid {label}: {error}") from error
    checks: list[dict] = [
        {"type": "process_alive"},
        {"type": "foreground_package"},
        {"type": "no_crash"},
    ]
    if activity:
        checks.append({"type": "activity_reached", "activity": activity})
    if expected_text:
        checks.append({"type": "ui_text_regex", "pattern": expected_text})
    if forbidden_ui:
        checks.append({"type": "ui_text_not_regex", "pattern": forbidden_ui})
    if forbidden_log:
        checks.append({"type": "log_not_regex", "pattern": forbidden_log})
    if preset == "screen_reached" and not (activity or expected_text):
        raise ValueError("Screen-reached policy requires an activity name or expected UI text.")
    if preset == "detection_removed" and not (forbidden_ui or forbidden_log):
        raise ValueError("Detection-removed policy requires a visible-UI or Logcat warning.")
    policy = {
        "version": 2,
        "name": {
            "basic": "Basic launch",
            "detection_removed": "Detection warning removed",
            "screen_reached": "Expected screen reached",
            "custom": "Custom generated policy",
        }[preset],
        "generated_by": "mob-ai-policy-builder",
        "preset": preset,
        "mode": "all",
        "baseline_required": True,
        "repeat": repeat,
        "min_passes": min_passes,
        "checks": checks,
        "builder": {
            "pattern_mode": "regex" if use_regex else "phrases",
            "forbidden_ui_input": ui_regex if use_regex else ui_phrases,
            "forbidden_log_input": log_regex if use_regex else log_phrases,
        },
    }
    path = POLICY_ROOT / f"policy-{uuid.uuid4().hex}.json"
    write_json(path, policy)
    return path


def validated_policy_document(content: str) -> tuple[dict[str, object], str]:
    if not isinstance(content, str) or not content.strip():
        raise ValueError("Paste or import a JSON success policy.")
    if len(content.encode("utf-8")) > MAX_POLICY_BYTES:
        raise ValueError("Success-policy JSON must be 256 KB or smaller.")
    try:
        source = json.loads(content)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON at line {error.lineno}, column {error.colno}: {error.msg}"
        ) from error
    policy = validate_success_policy(source)
    canonical = {"version": 2, **policy}
    return policy, json.dumps(canonical, indent=2) + "\n"


def load_success_policy(path: Path) -> dict[str, object]:
    if path.stat().st_size > MAX_POLICY_BYTES:
        raise ValueError("Success-policy JSON must be 256 KB or smaller.")
    policy, document = validated_policy_document(path.read_text(encoding="utf-8"))
    return {"path": workspace_relative(path), "policy": policy, "document": document}


def store_success_policy(content: str, name: str) -> dict[str, object]:
    policy, document = validated_policy_document(content)
    original = secure_filename(str(name or "custom-success-policy.json"))
    if not original.lower().endswith(".json"):
        original += ".json"
    destination = POLICY_ROOT / f"custom-{uuid.uuid4().hex[:12]}-{original}"
    temporary = destination.with_suffix(".uploading")
    try:
        temporary.write_text(document, encoding="utf-8")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "path": workspace_relative(destination), "name": destination.name,
        "policy": policy, "document": document,
    }
