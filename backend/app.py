from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import uuid

from flask import Flask, Response, jsonify, request, send_file, send_from_directory, stream_with_context
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from pipeline.diagnostic_recipes import diagnostic_recipe_catalog
from pipeline.frida_runtimes import frida_command, installed_frida_runtimes, validate_frida_version
from assessment.runtime import (
    LoopError, RUNS_ROOT, WORKSPACE, read_json, sha256, workspace_relative, write_json,
)
from assessment.state import (
    checkpoint_recovery_available, frida_recovery_available,
    usage_limit_recovery_available,
)
from worker.queue import HEARTBEAT_PATH, atomic_write_json
from backend.providers import PROVIDER_IDS
from backend.artifacts import (
    ARTIFACT_PREVIEW_SUFFIXES, artifact_manifest, resolve_run_artifact,
    resolve_run_directory,
)
from backend.assistant import (
    assistant_evidence_bundle, assistant_evidence_snapshot, assistant_history,
    assistant_request_state, failed_assistant_requests, run_assistant_turn,
    start_assistant_request,
)
from backend.auth import (
    REASONING_EFFORTS,
    auth_state, claude_auth_state, claude_login_status, codex_authenticated,
    codex_login_status, codex_model_catalog, provider_auth_state,
    provider_authenticated, provider_model_catalog, read_codex_models,
    read_connected_account_models, sign_out_claude, sign_out_codex,
    start_claude_auth, start_device_auth,
)
from backend.common import json_file, strip_terminal_controls, subprocess_capture_text, truthy, utc_now
from backend.requests import ContinuationRequest, DeviceReadinessRequest, StartAssessmentRequest
from backend.events import overview_event_stream
from backend.run_catalog import recorded_success_policy, runs
from backend.jobs import (
    infer_attempt_kind, infer_job_run_id, job_state, jobs, request_job_control, start_job,
)
from backend.routes import (
    create_auth_blueprint, create_devices_blueprint, create_jobs_blueprint,
    create_runs_blueprint, create_system_blueprint,
)


STATIC_ROOT = WORKSPACE / "frontend"
UPLOAD_ROOT = WORKSPACE / "uploads"
POLICY_ROOT = WORKSPACE / "policies" / "generated"
WIRELESS_DEVICES_PATH = WORKSPACE / "worker" / ".state" / "wireless-devices.json"
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



def parse_start(body: dict) -> tuple[str, dict]:
    body = StartAssessmentRequest.from_mapping(body)
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
    frida_version = validate_frida_version(str(body.get("frida_version") or ""))
    readiness_token = str(body.get("readiness_token") or "")
    with _lock:
        readiness = _readiness.get(readiness_token)
    if not readiness or readiness["expires"] < time.monotonic():
        raise ValueError("Run the device readiness check before starting the assessment.")
    if any((
        readiness["target"] != target,
        readiness["transport"] != transport,
        readiness["frida_server"] != frida_server,
        "frida_version" in readiness and readiness["frida_version"] != frida_version,
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
        "install": bool(body.get("install")), "frida_server": frida_server,
        "frida_version": frida_version, "package": package,
        "provider": provider, "model": model, "reasoning_effort": reasoning_effort, "readiness_token": readiness_token,
        "reasoning_mode": reasoning_mode, "specialist_count": specialist_count,
        "auto_resume_usage_limit": bool(body.get("auto_resume_usage_limit")),
        "derived_from_run": derived_from_run,
        "derived_from_policy_sha256": derived_from_policy_sha256,
    }


def parse_resume(body: dict) -> tuple[str, dict]:
    body = ContinuationRequest.from_mapping(body)
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
    recorded_frida_version = str(config.get("frida_version") or "")
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
    frida_version = validate_frida_version(str(body.get("frida_version") or recorded_frida_version))
    settings_changed = bool(recorded_target and any((
        target != recorded_target,
        transport != recorded_transport,
        frida_server != recorded_frida,
        frida_version != recorded_frida_version,
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
            "frida_version" in readiness and readiness["frida_version"] != frida_version,
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
        "frida_version": frida_version,
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


def health():
    worker_age = time.time() - HEARTBEAT_PATH.stat().st_mtime if HEARTBEAT_PATH.is_file() else None
    return jsonify(
        status="ok", codex_available=bool(shutil.which("codex")), claude_available=bool(shutil.which("claude")),
        worker_available=worker_age is not None and worker_age < 30,
    )


def overview_payload() -> dict:
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
    return {
        "apks": apks, "success_specs": specs, "runs": runs(), "jobs": jobs(),
        "diagnostic_recipes": diagnostic_recipe_catalog(),
        "codex": codex_state, "models": codex_models,
        "providers": {"codex": codex_state, "claude": claude_state},
        "model_catalogs": {"codex": codex_models, "claude": claude_models},
        "frida_runtimes": list(installed_frida_runtimes()),
    }


def overview():
    return jsonify(overview_payload())


def events():
    response = Response(
        stream_with_context(overview_event_stream(overview_payload)),
        content_type="text/event-stream; charset=utf-8",
    )
    response.headers["Cache-Control"] = "no-cache, no-transform"
    response.headers["X-Accel-Buffering"] = "no"
    return response


def models():
    provider = str(request.args.get("provider") or "codex")
    return jsonify(provider_model_catalog(provider, force=request.args.get("refresh") == "1"))


def providers():
    return jsonify(providers={provider: provider_auth_state(provider) for provider in sorted(PROVIDER_IDS)})


def get_provider_auth(provider: str):
    return jsonify(provider_auth_state(provider))


def begin_provider_auth(provider: str):
    if provider == "codex":
        return jsonify(start_device_auth()), 202
    if provider == "claude":
        return jsonify(start_claude_auth()), 202
    raise ValueError("Unsupported reasoning provider.")


def logout_provider_auth(provider: str):
    if provider == "codex":
        return jsonify(sign_out_codex())
    if provider == "claude":
        return jsonify(sign_out_claude())
    raise ValueError("Unsupported reasoning provider.")


def get_auth():
    return jsonify(auth_state())


def begin_auth():
    return jsonify(start_device_auth()), 202


def logout_auth():
    return jsonify(sign_out_codex())


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


def device_readiness():
    readiness_request = DeviceReadinessRequest(
        transport=str(request.form.get("transport") or ""),
        target=str(request.form.get("target") or ""),
        frida_server=str(request.form.get("frida_server") or ""),
        frida_version=str(request.form.get("frida_version") or ""),
        start_frida=truthy(request.form.get("start_frida")),
        authorized=truthy(request.form.get("authorized")),
    )
    transport = readiness_request.transport
    if transport not in {"adb", "wireless"}:
        raise ValueError("Invalid transport.")
    target = token(readiness_request.target, "device target", r"[A-Za-z0-9._:\-\[\]]+")
    frida_server = readiness_request.frida_server
    frida_version = validate_frida_version(readiness_request.frida_version)
    if frida_server:
        token(frida_server, "Frida Server path", r"/[A-Za-z0-9_./-]+")
    uploaded = request.files.get("frida_binary")
    start_frida = readiness_request.start_frida
    authorized = readiness_request.authorized
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
            [*frida_command(frida_version, "frida"), "--version"],
            text=True, capture_output=True, timeout=15,
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
            [*frida_command(frida_version, "frida-ps"), "-H", "127.0.0.1:27042"], text=True,
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
                "frida_version": frida_version,
                "created": now, "expires": now + 600,
            }
    return jsonify(
        ready=ready, target=target, transport=transport, abi=abi.stdout.strip(),
        sdk=sdk.stdout.strip(), frida_version=frida_version,
        checks=checks, token=readiness_token,
    )


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


def list_runs():
    return jsonify(runs=runs())


def list_run_artifacts(run_id: str):
    try:
        manifest = artifact_manifest(run_id)
    except FileNotFoundError as error:
        return jsonify(error=str(error)), 404
    manifest.pop("allowed", None)
    return jsonify(manifest)


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


def download_run_artifact(run_id: str):
    try:
        path = resolve_run_artifact(run_id, str(request.args.get("path") or ""))
    except FileNotFoundError as error:
        return jsonify(error=str(error)), 404
    return send_file(path, as_attachment=True, download_name=path.name, max_age=0)


def get_run_assistant(run_id: str):
    try:
        history = assistant_history(run_id)
        failures = failed_assistant_requests(run_id)
    except FileNotFoundError as error:
        return jsonify(error=str(error)), 404
    return jsonify(run_id=run_id, turns=history, failures=failures)


def ask_run_assistant(run_id: str):
    body = request.get_json(force=True, silent=False) or {}
    try:
        state = start_assistant_request(run_id, body)
    except FileNotFoundError as error:
        return jsonify(error=str(error)), 404
    return jsonify(state), 202


def get_run_assistant_request(run_id: str, request_id: str):
    try:
        state = assistant_request_state(run_id, request_id)
    except FileNotFoundError as error:
        return jsonify(error=str(error)), 404
    return jsonify(state)


def list_jobs():
    return jsonify(jobs=jobs())


def get_job(job_id: str):
    try:
        return jsonify(job_state(job_id))
    except FileNotFoundError as error:
        return jsonify(error=str(error)), 404


def cancel_job(job_id: str):
    try:
        return jsonify(request_job_control(job_id, "cancel")), 202
    except FileNotFoundError as error:
        return jsonify(error=str(error)), 404


def pause_job(job_id: str):
    try:
        return jsonify(request_job_control(job_id, "pause")), 202
    except FileNotFoundError as error:
        return jsonify(error=str(error)), 404


def start():
    label, payload = parse_start(request.get_json(force=True, silent=False) or {})
    return jsonify(start_job("start", label, payload)), 202


def resume():
    label, payload = parse_resume(request.get_json(force=True, silent=False) or {})
    return jsonify(start_job("resume", label, payload)), 202


def retry():
    label, payload = parse_retry(request.get_json(force=True, silent=False) or {})
    return jsonify(start_job("retry", label, payload)), 202


_handlers = SimpleNamespace(**{
    name: globals()[name] for name in (
        "health", "overview", "events", "models", "providers", "upload_apk",
        "get_provider_auth", "begin_provider_auth", "logout_provider_auth",
        "get_auth", "begin_auth", "logout_auth", "devices",
        "connect_wireless_device", "device_readiness", "pair_wireless_device",
        "list_runs", "list_run_artifacts", "preview_run_artifact",
        "download_run_artifact", "get_run_assistant", "ask_run_assistant",
        "get_run_assistant_request", "list_jobs", "get_job", "cancel_job", "pause_job", "start",
        "resume", "retry",
    )
})
app.register_blueprint(create_system_blueprint(_handlers))
app.register_blueprint(create_auth_blueprint(_handlers))
app.register_blueprint(create_devices_blueprint(_handlers))
app.register_blueprint(create_runs_blueprint(_handlers))
app.register_blueprint(create_jobs_blueprint(_handlers))


@app.get("/")
def index():
    return send_from_directory(STATIC_ROOT, "index.html")


@app.get("/<path:name>")
def static_file(name: str):
    return send_from_directory(STATIC_ROOT, name)
