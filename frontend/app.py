from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid

from flask import Flask, jsonify, request, send_file, send_from_directory
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from pipeline.diagnostic_recipes import diagnostic_recipe_catalog
from frontend.orchestrator_outcomes import terminal_outcome
from frontend.orchestrator_runtime import (
    LoopError, RUNS_ROOT, WORKSPACE, read_json, sha256, workspace_relative, write_json,
)
from frontend.orchestrator_state import (
    checkpoint_recovery_available, frida_recovery_available,
    usage_limit_recovery_available,
)
from frontend.job_queue import HEARTBEAT_PATH, STATE_ROOT, atomic_write_json
from frontend.providers import PROVIDER_IDS
from frontend.web_artifacts import (
    ARTIFACT_PREVIEW_SUFFIXES, artifact_manifest, resolve_run_artifact,
    resolve_run_directory,
)
from frontend.web_assistant import (
    assistant_evidence_bundle, assistant_evidence_snapshot, assistant_history,
    assistant_request_state, failed_assistant_requests, run_assistant_turn,
    start_assistant_request,
)
from frontend.web_auth import (
    REASONING_EFFORTS,
    auth_state, claude_auth_state, claude_login_status, codex_authenticated,
    codex_login_status, codex_model_catalog, provider_auth_state,
    provider_authenticated, provider_model_catalog, read_codex_models,
    read_connected_account_models, sign_out_claude, sign_out_codex,
    start_claude_auth, start_device_auth,
)
from frontend.web_common import json_file, strip_terminal_controls, subprocess_capture_text, truthy, utc_now


STATIC_ROOT = WORKSPACE / "frontend" / "dist"
UPLOAD_ROOT = WORKSPACE / "uploads"
POLICY_ROOT = WORKSPACE / "policies" / "generated"
WIRELESS_DEVICES_PATH = WORKSPACE / "frontend" / ".state" / "wireless-devices.json"
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
POLICY_ROOT.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MOB_AI_MAX_UPLOAD_MB", "1024")) * 1024 * 1024
_lock = threading.RLock()
_readiness: dict[str, dict] = {}

REASONING_MODES = {"single", "parallel"}
def endpoint_host(endpoint: str) -> str:
    value = endpoint.strip()
    if value.startswith("[") and "]" in value:
        return value[1:value.index("]")].lower()
    return value.rsplit(":", 1)[0].lower() if ":" in value else value.lower()


def wireless_registry() -> list[dict]:
    payload = json_file(WIRELESS_DEVICES_PATH) or {}
    devices = (payload.get("devices") or []) if isinstance(payload, dict) else []
    return [dict(item) for item in devices if isinstance(item, dict) and item.get("id")]


def record_wireless_device(*, pairing_endpoint: str = "", connection_endpoint: str = "", connected: bool = False) -> dict:
    """Persist non-secret host knowledge; pairing codes never enter this structure."""
    now = utc_now()
    host = endpoint_host(connection_endpoint or pairing_endpoint)
    with _lock:
        devices = wireless_registry()
        item = next((entry for entry in devices if any((
            connection_endpoint and entry.get("connection_endpoint") == connection_endpoint,
            pairing_endpoint and entry.get("pairing_endpoint") == pairing_endpoint,
            host and entry.get("host") == host,
        ))), None)
        if item is None:
            item = {"id": uuid.uuid4().hex, "host": host}
            devices.append(item)
        if pairing_endpoint:
            previous_pairing = str(item.get("pairing_endpoint") or "")
            if previous_pairing != pairing_endpoint:
                item.pop("connection_endpoint", None)
                item.pop("last_connected_utc", None)
            item["pairing_endpoint"] = pairing_endpoint
            item["paired_utc"] = now
        if connection_endpoint:
            item["connection_endpoint"] = connection_endpoint
        if connected:
            item["last_connected_utc"] = now
        item["updated_utc"] = now
        atomic_write_json(WIRELESS_DEVICES_PATH, {"devices": devices})
        return dict(item)


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


def resolve_workspace_item(value: str, *, directory: bool = False) -> Path:
    if not value or Path(value).is_absolute():
        raise ValueError("Use a workspace-relative path.")
    path = (WORKSPACE / value).resolve()
    try:
        path.relative_to(WORKSPACE)
    except ValueError as error:
        raise ValueError("Path escaped the workspace.") from error
    if directory and not path.is_dir():
        raise ValueError(f"Directory not found: {value}")
    if not directory and not path.is_file():
        raise ValueError(f"File not found: {value}")
    return path


def token(value: str, name: str, pattern: str) -> str:
    if not value or not re.fullmatch(pattern, value):
        raise ValueError(f"Invalid {name}.")
    return value




def success_policy(body: dict) -> Path:
    preset = str(body.get("policy_preset") or "basic")
    if preset == "advanced":
        return resolve_workspace_item(str(body.get("success_spec") or ""))
    if preset not in {"basic", "detection_removed", "screen_reached", "custom"}:
        raise ValueError("Invalid success-policy preset.")
    repeat = int(body.get("policy_repeat") or 2)
    if not 1 <= repeat <= 3:
        raise ValueError("Repeat validation must be between 1 and 3 runs.")
    activity = str(body.get("expected_activity") or "").strip() if preset in {"screen_reached", "custom"} else ""
    expected_text = str(body.get("expected_ui_pattern") or "").strip() if preset in {"screen_reached", "custom"} else ""
    forbidden_text = str(body.get("forbidden_ui_pattern") or "").strip() if preset in {"detection_removed", "custom"} else ""
    for label, pattern in (("expected UI pattern", expected_text), ("forbidden UI pattern", forbidden_text)):
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
    if forbidden_text:
        checks.extend([
            {"type": "ui_text_not_regex", "pattern": forbidden_text},
            {"type": "log_not_regex", "pattern": forbidden_text},
        ])
    if preset == "screen_reached" and not (activity or expected_text):
        raise ValueError("Screen-reached policy requires an activity name or expected UI text.")
    if preset == "detection_removed" and not forbidden_text:
        raise ValueError("Detection-removed policy requires a forbidden warning pattern.")
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
        "min_passes": repeat,
        "checks": checks,
    }
    path = POLICY_ROOT / f"policy-{uuid.uuid4().hex}.json"
    write_json(path, policy)
    return path



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
        usage = (loop.get("usage") or {}) if loop else {}
        terminal = terminal_outcome(loop)
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
            "resumable": resumable,
            "frida_recoverable": frida_recoverable,
            "checkpoint_recoverable": checkpoint_recoverable,
            "usage_recoverable": usage_recoverable,
            "continuable": bool(resumable or frida_recoverable or checkpoint_recoverable or usage_recoverable),
            "retryable": retryable,
            "recovery_stage": str(((loop.get("checkpoint") or {}).get("stage") if loop else "") or ""),
            "reason": str((loop.get("reason") if loop else "") or ""),
            "usage_reset_utc": str(usage.get("reset_utc") or ""),
            "usage_auto_resume": bool(usage.get("auto_resume")),
            "frida_server": str(config.get("start_frida_server") if config else ""),
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
            "updated_utc": datetime.fromtimestamp(directory.stat().st_mtime, timezone.utc).isoformat(),
        })
    return result


def job_log_tail(job_id: str, limit: int = 120_000) -> str:
    log_path = STATE_ROOT / job_id / "output.log"
    if not log_path.is_file():
        return ""
    with log_path.open("rb") as stream:
        stream.seek(max(0, log_path.stat().st_size - limit))
        return stream.read().decode("utf-8", errors="replace")


def job_log_head(job_id: str, limit: int = 8_000) -> str:
    log_path = STATE_ROOT / job_id / "output.log"
    if not log_path.is_file():
        return ""
    with log_path.open("rb") as stream:
        return stream.read(limit).decode("utf-8", errors="replace")


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


def parse_start(body: dict) -> tuple[str, dict]:
    if not body.get("authorized"):
        raise ValueError("Confirm ownership or explicit testing authorization.")
    derived_from_run = str(body.get("source_run") or "")
    derived_from_policy_sha256 = ""
    label = ""
    if derived_from_run:
        token(derived_from_run, "source run", r"[A-Za-z0-9._-]+")
        source_dir = resolve_run_directory(derived_from_run)
        source_config = json_file(source_dir / "codex-loop-config.json") or {}
        apk = source_dir / "original.apk"
        if not apk.is_file() or sha256(apk) != str(source_config.get("apk_sha256") or ""):
            raise ValueError("The reassessment source APK is missing or has changed.")
        derived_from_policy_sha256 = str(source_config.get("success_spec_sha256") or "")
        source_report = json_file(source_dir / "report.json") or {}
        label = f"{source_report.get('package') or derived_from_run} policy reassessment"
    else:
        apk = resolve_workspace_item(str(body.get("apk") or ""))
        label = apk.name
    if apk.suffix.lower() != ".apk":
        raise ValueError("Select an APK file.")
    transport = str(body.get("transport") or "")
    if transport not in {"adb", "wireless"}:
        raise ValueError("Invalid transport.")
    target = token(str(body.get("target") or ""), "device target", r"[A-Za-z0-9._:\-\[\]]+")
    maximum = int(body.get("max_iterations") or 0)
    observation = int(body.get("observation_seconds") or 0)
    run_seconds = int(body.get("run_seconds") or 0)
    if not 1 <= maximum <= 10:
        raise ValueError("Max iterations must be between 1 and 10.")
    if not 1 <= observation <= 600 or not 1 <= run_seconds <= 600:
        raise ValueError("Observation and runtime windows must be between 1 and 600 seconds.")
    frida_server = str(body.get("frida_server") or "")
    if frida_server:
        token(frida_server, "Frida Server path", r"/[A-Za-z0-9_./-]+")
    readiness_token = str(body.get("readiness_token") or "")
    with _lock:
        readiness = _readiness.get(readiness_token)
    if not readiness or readiness["expires"] < time.monotonic():
        raise ValueError("Run the device readiness check before starting the assessment.")
    if any((
        readiness["target"] != target,
        readiness["transport"] != transport,
        readiness["frida_server"] != frida_server,
    )):
        raise ValueError("Device settings changed after readiness passed; run the check again.")
    package = str(body.get("package") or "")
    if package:
        token(package, "package name", r"[A-Za-z0-9_.]+")
    provider = str(body.get("provider") or "codex")
    if provider not in PROVIDER_IDS:
        raise ValueError("Unsupported reasoning provider.")
    model = str(body.get("model") or "")
    if model:
        token(model, "model", r"[A-Za-z0-9._:\-]+")
    reasoning_effort = str(body.get("reasoning_effort") or "")
    if reasoning_effort and reasoning_effort not in REASONING_EFFORTS:
        raise ValueError("Invalid thinking level.")
    reasoning_mode = str(body.get("reasoning_mode") or "single")
    if reasoning_mode not in REASONING_MODES:
        raise ValueError("Invalid reasoning mode.")
    specialist_count = int(body.get("specialist_count") or 3)
    if not 2 <= specialist_count <= 3:
        raise ValueError("Parallel specialist count must be 2 or 3.")
    spec = success_policy(body)
    return label, {
        "apk": str(apk), "success_spec": str(spec), "transport": transport, "target": target,
        "max_iterations": maximum, "observation_seconds": observation, "run_seconds": run_seconds,
        "install": bool(body.get("install")), "frida_server": frida_server, "package": package,
        "provider": provider, "model": model, "reasoning_effort": reasoning_effort, "readiness_token": readiness_token,
        "reasoning_mode": reasoning_mode, "specialist_count": specialist_count,
        "auto_resume_usage_limit": bool(body.get("auto_resume_usage_limit")),
        "derived_from_run": derived_from_run,
        "derived_from_policy_sha256": derived_from_policy_sha256,
    }


def parse_resume(body: dict) -> tuple[str, dict]:
    if not body.get("authorized"):
        raise ValueError("Confirm testing authorization before resuming.")
    run_dir = resolve_workspace_item(str(body.get("run") or ""), directory=True)
    try:
        run_dir.relative_to(RUNS_ROOT.resolve())
    except ValueError as error:
        raise ValueError("Resume target must be inside runs/.") from error
    config = json_file(run_dir / "codex-loop-config.json") or {}
    recorded_target = str(config.get("target") or "")
    recorded_transport = str(config.get("transport") or "adb")
    recorded_frida = str(config.get("start_frida_server") or "")
    target_value = str(body.get("target") or recorded_target)
    target = token(target_value, "device target", r"[A-Za-z0-9._:\-\[\]]+") if target_value else ""
    transport = str(body.get("transport") or recorded_transport)
    if transport not in {"adb", "wireless"}:
        raise ValueError("Invalid transport.")
    maximum = int(body.get("max_iterations") or 0)
    if not 1 <= maximum <= 10:
        raise ValueError("Additional iterations must be between 1 and 10.")
    provider = str(body.get("provider") or "codex")
    if provider not in PROVIDER_IDS:
        raise ValueError("Unsupported reasoning provider.")
    model = str(body.get("model") or "")
    if model:
        token(model, "model", r"[A-Za-z0-9._:\-]+")
    reasoning_effort = str(body.get("reasoning_effort") or "")
    if reasoning_effort and reasoning_effort not in REASONING_EFFORTS:
        raise ValueError("Invalid thinking level.")
    reasoning_mode = str(body.get("reasoning_mode") or "")
    if reasoning_mode and reasoning_mode not in REASONING_MODES:
        raise ValueError("Invalid reasoning mode.")
    specialist_count = int(body.get("specialist_count") or 3)
    if not 2 <= specialist_count <= 3:
        raise ValueError("Parallel specialist count must be 2 or 3.")
    frida_server = str(body.get("frida_server") or recorded_frida)
    if frida_server:
        token(frida_server, "Frida Server path", r"/[A-Za-z0-9_./-]+")
    settings_changed = bool(recorded_target and any((
        target != recorded_target,
        transport != recorded_transport,
        frida_server != recorded_frida,
    )))
    readiness_token = str(body.get("readiness_token") or "")
    if settings_changed:
        with _lock:
            readiness = _readiness.get(readiness_token)
        if not readiness or readiness["expires"] < time.monotonic():
            raise ValueError("Run device readiness after changing the continuation target or Frida path.")
        if any((
            readiness["target"] != target,
            readiness["transport"] != transport,
            readiness["frida_server"] != frida_server,
        )):
            raise ValueError("Continuation device settings changed after readiness passed; run the check again.")
    policy_hash = str(body.get("success_spec_sha256") or "")
    if policy_hash:
        token(policy_hash, "success-policy hash", r"[a-f0-9]{64}")
        recorded_hash = str(config.get("success_spec_sha256") or "")
        if recorded_hash and policy_hash != recorded_hash:
            raise ValueError("The selected success policy does not match this assessment run.")
    return run_dir.name, {
        "run": str(run_dir), "max_iterations": maximum, "provider": provider, "model": model,
        "reasoning_effort": reasoning_effort, "frida_server": frida_server,
        "reasoning_mode": reasoning_mode, "specialist_count": specialist_count,
        "auto_resume_usage_limit": bool(body.get("auto_resume_usage_limit")),
        "success_spec_sha256": policy_hash,
        "target": target, "transport": transport, "readiness_token": readiness_token,
        "target_settings_changed": settings_changed,
    }


def parse_retry(body: dict) -> tuple[str, dict]:
    label, payload = parse_resume(body)
    run_dir = Path(payload["run"])
    if not (run_dir / "codex-loop-result.json").is_file():
        raise ValueError("Diagnostic retry requires a completed assessment run.")
    return label, payload


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
    return response


@app.errorhandler(ValueError)
@app.errorhandler(LoopError)
def bad_request(error):
    return jsonify(error=str(error)), 400


@app.errorhandler(404)
def not_found(_error):
    return jsonify(error="Not found."), 404


@app.errorhandler(RequestEntityTooLarge)
def upload_too_large(_error):
    limit = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
    return jsonify(error=f"Upload exceeds the {limit} MB limit."), 413


@app.get("/api/health")
def health():
    worker_age = time.time() - HEARTBEAT_PATH.stat().st_mtime if HEARTBEAT_PATH.is_file() else None
    return jsonify(
        status="ok", codex_available=bool(shutil.which("codex")), claude_available=bool(shutil.which("claude")),
        worker_available=worker_age is not None and worker_age < 30,
    )


@app.get("/api/overview")
def overview():
    apk_paths = [*WORKSPACE.glob("*.apk"), *UPLOAD_ROOT.glob("*.apk")]
    apks = [{"name": path.name, "path": workspace_relative(path), "size": path.stat().st_size} for path in apk_paths if path.is_file()]
    specs = [{"name": path.name, "path": workspace_relative(path)} for path in WORKSPACE.glob("*.json") if re.search(r"success|policy|spec", path.name, re.I)]
    example = WORKSPACE / "pipeline" / "success-spec.example.json"
    if example.is_file():
        specs.append({"name": example.name, "path": workspace_relative(example)})
    codex_state = provider_auth_state("codex")
    claude_state = provider_auth_state("claude")
    codex_models = provider_model_catalog("codex")
    claude_models = provider_model_catalog("claude")
    return jsonify(
        apks=apks, success_specs=specs, runs=runs(), jobs=jobs(),
        diagnostic_recipes=diagnostic_recipe_catalog(),
        codex=codex_state, models=codex_models,
        providers={"codex": codex_state, "claude": claude_state},
        model_catalogs={"codex": codex_models, "claude": claude_models},
    )


@app.get("/api/models")
def models():
    provider = str(request.args.get("provider") or "codex")
    return jsonify(provider_model_catalog(provider, force=request.args.get("refresh") == "1"))


@app.get("/api/providers")
def providers():
    return jsonify(providers={provider: provider_auth_state(provider) for provider in sorted(PROVIDER_IDS)})


@app.get("/api/providers/<provider>/auth")
def get_provider_auth(provider: str):
    return jsonify(provider_auth_state(provider))


@app.post("/api/providers/<provider>/auth/login")
def begin_provider_auth(provider: str):
    if provider == "codex":
        return jsonify(start_device_auth()), 202
    if provider == "claude":
        return jsonify(start_claude_auth()), 202
    raise ValueError("Unsupported reasoning provider.")


@app.post("/api/providers/<provider>/auth/logout")
def logout_provider_auth(provider: str):
    if provider == "codex":
        return jsonify(sign_out_codex())
    if provider == "claude":
        return jsonify(sign_out_claude())
    raise ValueError("Unsupported reasoning provider.")


@app.get("/api/auth")
def get_auth():
    return jsonify(auth_state())


@app.post("/api/auth/device")
def begin_auth():
    return jsonify(start_device_auth()), 202


@app.post("/api/auth/logout")
def logout_auth():
    return jsonify(sign_out_codex())


@app.post("/api/apks")
def upload_apk():
    uploaded = request.files.get("apk")
    if not uploaded or not uploaded.filename:
        raise ValueError("Choose an APK file to upload.")
    original = secure_filename(uploaded.filename)
    if not original or Path(original).suffix.lower() != ".apk":
        raise ValueError("The uploaded file must have an .apk extension.")
    destination = UPLOAD_ROOT / f"{uuid.uuid4().hex[:12]}-{original}"
    temporary = destination.with_suffix(".uploading")
    try:
        uploaded.save(temporary)
        if not temporary.is_file() or temporary.stat().st_size < 4:
            raise ValueError("The uploaded APK is empty.")
        with temporary.open("rb") as stream:
            if stream.read(4) != b"PK\x03\x04":
                raise ValueError("The uploaded file is not an APK/ZIP archive.")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return jsonify(
        name=original, path=workspace_relative(destination), size=destination.stat().st_size,
    ), 201


def discovered_mdns_services() -> list[dict]:
    try:
        result = subprocess.run(["adb", "mdns", "services"], text=True, capture_output=True, timeout=12)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode:
        return []
    services = []
    for line in result.stdout.splitlines():
        match = re.match(r"^\s*(\S+)\s+(_adb-tls-(pairing|connect)\._tcp)\s+(\S+:\d+)\s*$", line)
        if match:
            services.append({
                "name": match.group(1), "service": match.group(2),
                "kind": match.group(3), "endpoint": match.group(4),
            })
    return services


def wireless_device_view(found: list[dict], mdns: list[dict]) -> list[dict]:
    records = wireless_registry()
    live_by_serial = {item["serial"]: item for item in found}
    connect_services = [item for item in mdns if item["kind"] == "connect"]
    output: list[dict] = []
    represented: set[str] = set()
    for record in records:
        endpoint = str(record.get("connection_endpoint") or "")
        paired_utc = str(record.get("paired_utc") or "")
        last_connected_utc = str(record.get("last_connected_utc") or "")
        if paired_utc and paired_utc > last_connected_utc:
            endpoint = ""
        host = str(record.get("host") or endpoint_host(endpoint or str(record.get("pairing_endpoint") or "")))
        discovered = next((item for item in connect_services if endpoint_host(item["endpoint"]) == host), None)
        target = endpoint or str((discovered or {}).get("endpoint") or "")
        live = live_by_serial.get(target) or live_by_serial.get(endpoint)
        adb_state = str((live or {}).get("state") or "")
        status = "connected" if adb_state == "device" else adb_state if adb_state in {"offline", "unauthorized"} else "previously_paired"
        if target:
            represented.add(target)
        output.append({
            "id": record["id"], "host": host, "endpoint": target,
            "pairing_endpoint": str(record.get("pairing_endpoint") or ""),
            "status": status, "adb_state": adb_state, "paired": True,
            "discovered": bool(discovered), "connectable": bool(target and status != "connected"),
            "paired_utc": paired_utc,
            "last_connected_utc": last_connected_utc,
            "connection_required": not bool(target),
            "details": str((live or {}).get("details") or ""),
        })
    for live in found:
        serial = str(live["serial"])
        if serial in represented or not re.fullmatch(r"(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9._-]+):\d+", serial):
            continue
        output.append({
            "id": f"live-{serial}", "host": endpoint_host(serial), "endpoint": serial,
            "pairing_endpoint": "", "status": "connected" if live["state"] == "device" else live["state"],
            "adb_state": live["state"], "paired": False, "discovered": False,
            "connectable": live["state"] != "device", "paired_utc": "", "last_connected_utc": "",
            "details": live.get("details") or "",
        })
        represented.add(serial)
    for service in connect_services:
        endpoint = service["endpoint"]
        if endpoint in represented:
            continue
        output.append({
            "id": f"mdns-{service['name']}", "host": endpoint_host(endpoint), "endpoint": endpoint,
            "pairing_endpoint": "", "status": "discovered", "adb_state": "", "paired": False,
            "discovered": True, "connectable": True, "paired_utc": "", "last_connected_utc": "",
            "details": service["name"],
        })
    order = {"connected": 0, "unauthorized": 1, "offline": 2, "previously_paired": 3, "discovered": 4}
    return sorted(output, key=lambda item: (order.get(item["status"], 9), item.get("host") or ""))


@app.get("/api/devices")
def devices():
    result = subprocess.run(["adb", "devices", "-l"], text=True, capture_output=True, timeout=20)
    if result.returncode:
        raise ValueError(f"ADB discovery failed: {result.stderr or result.stdout}")
    found = []
    for line in result.stdout.splitlines():
        match = re.match(r"^([^\s]+)\s+(device|offline|unauthorized)(?:\s+(.*))?$", line)
        if match:
            found.append({"serial": match.group(1), "state": match.group(2), "details": match.group(3) or ""})
    mdns = discovered_mdns_services()
    return jsonify(devices=found, wireless_devices=wireless_device_view(found, mdns))


@app.post("/api/devices/connect")
def connect_wireless_device():
    body = request.get_json(force=True, silent=False) or {}
    endpoint = token(str(body.get("endpoint") or ""), "wireless connection address", r"[A-Za-z0-9._:\-\[\]]+")
    result = subprocess.run(["adb", "connect", endpoint], text=True, capture_output=True, timeout=25)
    detail = strip_terminal_controls(result.stdout or result.stderr or "").strip()
    connected = result.returncode == 0 and bool(re.search(r"connected to|already connected", detail, re.I))
    if not connected:
        raise ValueError(f"Wireless ADB connection failed: {detail or 'No response from ADB.'}")
    record_wireless_device(connection_endpoint=endpoint, connected=True)
    return jsonify(connected=True, endpoint=endpoint, message="Wireless device connected.")


def adb_result(target: str, *arguments: str, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["adb", "-s", target, *arguments], text=True, capture_output=True, timeout=timeout,
    )


def readiness_check(name: str, passed: bool, detail: str, *, required: bool = True) -> dict:
    return {
        "name": name, "passed": bool(passed), "required": required,
        "detail": strip_terminal_controls(detail).strip()[-1200:],
    }


@app.post("/api/devices/readiness")
def device_readiness():
    transport = str(request.form.get("transport") or "")
    if transport not in {"adb", "wireless"}:
        raise ValueError("Invalid transport.")
    target = token(str(request.form.get("target") or ""), "device target", r"[A-Za-z0-9._:\-\[\]]+")
    frida_server = str(request.form.get("frida_server") or "")
    if frida_server:
        token(frida_server, "Frida Server path", r"/[A-Za-z0-9_./-]+")
    uploaded = request.files.get("frida_binary")
    start_frida = truthy(request.form.get("start_frida"))
    authorized = truthy(request.form.get("authorized"))
    if (uploaded and uploaded.filename) or start_frida:
        if not authorized:
            raise ValueError("Confirm testing authorization before deploying or starting Frida Server.")

    checks: list[dict] = []
    if transport == "wireless":
        connected = subprocess.run(
            ["adb", "connect", target], text=True, capture_output=True, timeout=25,
        )
        wireless_ready = connected.returncode == 0 and bool(re.search(r"connected to|already connected", connected.stdout, re.I))
        checks.append(readiness_check("Wireless ADB", wireless_ready, connected.stdout or connected.stderr))
        if wireless_ready:
            record_wireless_device(connection_endpoint=target, connected=True)
    state = adb_result(target, "get-state")
    device_ready = state.returncode == 0 and state.stdout.strip() == "device"
    checks.append(readiness_check("ADB device", device_ready, state.stdout or state.stderr))
    if not device_ready:
        return jsonify(ready=False, target=target, transport=transport, checks=checks, token="")

    abi = adb_result(target, "shell", "getprop", "ro.product.cpu.abi")
    sdk = adb_result(target, "shell", "getprop", "ro.build.version.sdk")
    checks.append(readiness_check("Device ABI", abi.returncode == 0 and bool(abi.stdout.strip()), abi.stdout or abi.stderr))
    checks.append(readiness_check("Android SDK", sdk.returncode == 0 and sdk.stdout.strip().isdigit(), sdk.stdout or sdk.stderr))
    root = adb_result(target, "shell", "su", "-c", "id")
    root_ready = root.returncode == 0 and "uid=0" in root.stdout
    checks.append(readiness_check("Root shell", root_ready, root.stdout or root.stderr))
    storage = adb_result(target, "shell", "df", "-k", "/data/local/tmp")
    checks.append(readiness_check("Temporary storage", storage.returncode == 0, storage.stdout or storage.stderr))
    selinux = adb_result(target, "shell", "getenforce")
    checks.append(readiness_check("SELinux", selinux.returncode == 0, selinux.stdout or selinux.stderr, required=False))

    temporary_path: Path | None = None
    try:
        if uploaded and uploaded.filename:
            if not frida_server:
                raise ValueError("Enter a device-side Frida Server path before deploying a binary.")
            with tempfile.NamedTemporaryFile(prefix="mob-ai-frida-", delete=False) as temporary:
                temporary_path = Path(temporary.name)
                uploaded.save(temporary)
            if temporary_path.stat().st_size < 1024:
                raise ValueError("The selected Frida Server binary is unexpectedly small.")
            pushed = subprocess.run(
                ["adb", "-s", target, "push", str(temporary_path), frida_server],
                text=True, capture_output=True, timeout=120,
            )
            checks.append(readiness_check("Frida deployment", pushed.returncode == 0, pushed.stdout or pushed.stderr))
            if pushed.returncode == 0:
                chmod = adb_result(target, "shell", "su", "-c", f"chmod 755 {frida_server}")
                checks.append(readiness_check("Frida executable", chmod.returncode == 0, chmod.stdout or chmod.stderr or frida_server))

        host_version = subprocess.run(
            ["frida", "--version"], text=True, capture_output=True, timeout=15,
        )
        checks.append(readiness_check("Frida client", host_version.returncode == 0, host_version.stdout or host_version.stderr))
        if frida_server:
            executable = adb_result(target, "shell", "su", "-c", f"test -x {frida_server}")
            checks.append(readiness_check("Frida Server path", executable.returncode == 0, frida_server if executable.returncode == 0 else executable.stdout or executable.stderr or "Missing or not executable"))
            server_version = adb_result(target, "shell", "su", "-c", f"{frida_server} --version", timeout=30)
            server_text = (server_version.stdout or server_version.stderr).strip()
            versions_match = (
                host_version.returncode == 0 and server_version.returncode == 0
                and host_version.stdout.strip() == server_text
            )
            checks.append(readiness_check(
                "Frida version match", versions_match,
                f"client {host_version.stdout.strip() or 'unknown'} / server {server_text or 'unknown'}",
            ))
            if start_frida and executable.returncode == 0:
                started = adb_result(
                    target, "shell", "su", "-c",
                    f"{frida_server} -D >/dev/null 2>&1 &", timeout=20,
                )
                checks.append(readiness_check("Frida start", started.returncode == 0, started.stdout or started.stderr or "Start command accepted"))
        forwarded = adb_result(target, "forward", "tcp:27042", "tcp:27042")
        checks.append(readiness_check("Frida port forwarding", forwarded.returncode == 0, forwarded.stdout or forwarded.stderr))
        frida_probe = subprocess.run(
            ["frida-ps", "-H", "127.0.0.1:27042"], text=True,
            capture_output=True, timeout=20,
        )
        checks.append(readiness_check("Frida connection", frida_probe.returncode == 0, frida_probe.stdout or frida_probe.stderr))
    finally:
        if temporary_path:
            temporary_path.unlink(missing_ok=True)

    ready = all(check["passed"] for check in checks if check["required"])
    readiness_token = ""
    if ready:
        readiness_token = uuid.uuid4().hex
        with _lock:
            now = time.monotonic()
            _readiness.clear()
            _readiness[readiness_token] = {
                "target": target, "transport": transport, "frida_server": frida_server,
                "created": now, "expires": now + 600,
            }
    return jsonify(
        ready=ready, target=target, transport=transport, abi=abi.stdout.strip(),
        sdk=sdk.stdout.strip(), checks=checks, token=readiness_token,
    )


@app.post("/api/devices/pair")
def pair_wireless_device():
    body = request.get_json(force=True, silent=False) or {}
    endpoint = token(str(body.get("endpoint") or ""), "pairing address", r"[A-Za-z0-9._:\-\[\]]+")
    pairing_code = str(body.get("code") or "")
    if not re.fullmatch(r"[0-9]{6}", pairing_code):
        raise ValueError("Wireless pairing code must contain exactly six digits.")
    try:
        result = subprocess.run(
            ["adb", "pair", endpoint], input=pairing_code + "\n",
            text=True, capture_output=True, timeout=45,
        )
        if result.returncode:
            detail = (result.stderr or result.stdout or "ADB pairing failed.").strip()
            # Some ADB builds append the OS error-string for errno 0 to a real
            # protocol failure, producing the contradictory suffix ": Success".
            detail = re.sub(r"(?i):\s*success\s*$", "", detail).rstrip()
            detail = detail.replace(pairing_code, "******")[-1000:]
            raise ValueError(f"Wireless pairing failed: {detail}")
    except subprocess.TimeoutExpired as error:
        raise ValueError("Wireless pairing timed out. Confirm the pairing address and try again.") from error
    finally:
        pairing_code = ""
    matching_connections = [
        service["endpoint"] for service in discovered_mdns_services()
        if service["kind"] == "connect" and endpoint_host(service["endpoint"]) == endpoint_host(endpoint)
    ]
    connection_endpoint = matching_connections[0] if len(matching_connections) == 1 else ""
    record_wireless_device(pairing_endpoint=endpoint, connection_endpoint=connection_endpoint)
    return jsonify(
        paired=True, endpoint=endpoint, connection_endpoint=connection_endpoint,
        message="Wireless debugging paired successfully.",
    )


@app.get("/api/runs")
def list_runs():
    return jsonify(runs=runs())


@app.get("/api/runs/<run_id>/artifacts")
def list_run_artifacts(run_id: str):
    try:
        manifest = artifact_manifest(run_id)
    except FileNotFoundError as error:
        return jsonify(error=str(error)), 404
    manifest.pop("allowed", None)
    return jsonify(manifest)


@app.get("/api/runs/<run_id>/artifacts/content")
def preview_run_artifact(run_id: str):
    try:
        path = resolve_run_artifact(run_id, str(request.args.get("path") or ""))
    except FileNotFoundError as error:
        return jsonify(error=str(error)), 404
    if path.suffix.lower() not in ARTIFACT_PREVIEW_SUFFIXES:
        return jsonify(error="This artifact is download-only."), 400
    limit = 1_000_000
    with path.open("rb") as stream:
        payload = stream.read(limit + 1)
    truncated = len(payload) > limit
    content = payload[:limit].decode("utf-8", errors="replace")
    return jsonify(path=path.name, content=content, truncated=truncated)


@app.get("/api/runs/<run_id>/artifacts/download")
def download_run_artifact(run_id: str):
    try:
        path = resolve_run_artifact(run_id, str(request.args.get("path") or ""))
    except FileNotFoundError as error:
        return jsonify(error=str(error)), 404
    return send_file(path, as_attachment=True, download_name=path.name, max_age=0)


@app.get("/api/runs/<run_id>/assistant")
def get_run_assistant(run_id: str):
    try:
        history = assistant_history(run_id)
        failures = failed_assistant_requests(run_id)
    except FileNotFoundError as error:
        return jsonify(error=str(error)), 404
    return jsonify(run_id=run_id, turns=history, failures=failures)


@app.post("/api/runs/<run_id>/assistant")
def ask_run_assistant(run_id: str):
    body = request.get_json(force=True, silent=False) or {}
    try:
        state = start_assistant_request(run_id, body)
    except FileNotFoundError as error:
        return jsonify(error=str(error)), 404
    return jsonify(state), 202


@app.get("/api/runs/<run_id>/assistant/requests/<request_id>")
def get_run_assistant_request(run_id: str, request_id: str):
    try:
        state = assistant_request_state(run_id, request_id)
    except FileNotFoundError as error:
        return jsonify(error=str(error)), 404
    return jsonify(state)


@app.get("/api/jobs")
def list_jobs():
    return jsonify(jobs=jobs())


@app.get("/api/jobs/<job_id>")
def get_job(job_id: str):
    try:
        return jsonify(job_state(job_id))
    except FileNotFoundError as error:
        return jsonify(error=str(error)), 404


@app.post("/api/start")
def start():
    label, payload = parse_start(request.get_json(force=True, silent=False) or {})
    return jsonify(start_job("start", label, payload)), 202


@app.post("/api/resume")
def resume():
    label, payload = parse_resume(request.get_json(force=True, silent=False) or {})
    return jsonify(start_job("resume", label, payload)), 202


@app.post("/api/retry")
def retry():
    label, payload = parse_retry(request.get_json(force=True, silent=False) or {})
    return jsonify(start_job("retry", label, payload)), 202


@app.get("/")
def index():
    return send_from_directory(STATIC_ROOT, "index.html")


@app.get("/<path:name>")
def static_file(name: str):
    return send_from_directory(STATIC_ROOT, name)
