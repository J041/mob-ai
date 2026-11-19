from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import time
from types import SimpleNamespace
import uuid

from flask import Flask, Response, jsonify, request, send_file, send_from_directory, stream_with_context
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from pipeline.diagnostic_recipes import diagnostic_recipe_catalog
from pipeline.frida_runtimes import installed_frida_runtimes, validate_frida_version
from assessment.runtime import (
    LoopError, RUNS_ROOT, WORKSPACE, read_json, sha256, workspace_relative, write_json,
)
from assessment.state import (
    checkpoint_recovery_available, frida_recovery_available,
    usage_limit_recovery_available,
)
from assessment.deep_goal import (
    DEEP_GOAL_DEFAULT_TOKENS, DEEP_GOAL_MAX_TOKENS, DEEP_GOAL_MIN_TOKENS,
    deep_goal_eligibility,
)
from assessment.successful_bypass import successful_candidate_path
from worker.queue import HEARTBEAT_PATH
from worker.job_types import public_job_type_catalog
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
from backend.common import json_file, strip_terminal_controls, subprocess_capture_text, token
from backend.requests import ContinuationRequest, StartAssessmentRequest
from backend.device_service import (
    WIRELESS_DEVICES_PATH, _lock, _readiness, adb_result, connect_wireless_device,
    device_readiness, devices, discovered_mdns_services, endpoint_host,
    frida_server_processes, pair_wireless_device, parse_frida_server_processes,
    readiness_check, record_wireless_device, replace_frida_server,
    wireless_device_view, wireless_registry,
)
from backend.events import overview_event_stream
from backend.run_catalog import recorded_success_policy, runs
from backend.jobs import (
    infer_attempt_kind, infer_job_run_id, job_count, job_state, jobs, request_job_control, start_job,
)
from backend.routes import (
    create_auth_blueprint, create_devices_blueprint, create_jobs_blueprint,
    create_runs_blueprint, create_system_blueprint,
)


STATIC_ROOT = WORKSPACE / "frontend"
UPLOAD_ROOT = WORKSPACE / "uploads"
POLICY_ROOT = WORKSPACE / "policies" / "generated"
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
POLICY_ROOT.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MOB_AI_MAX_UPLOAD_MB", "1024")) * 1024 * 1024
REASONING_MODES = {"single", "parallel"}
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


def parse_deep_investigation(run_id: str, body: dict) -> tuple[str, dict]:
    if not body.get("confirmed"):
        raise ValueError("Confirm the optional deep investigation before starting it.")
    run_dir = resolve_run_directory(run_id)
    eligible, reason = deep_goal_eligibility(run_dir)
    if not eligible:
        raise ValueError(reason)
    config = json_file(run_dir / "codex-loop-config.json") or {}
    model = str(body.get("model") or config.get("model") or "")
    if model:
        token(model, "model", r"[A-Za-z0-9._:\-]+")
    reasoning_effort = str(body.get("reasoning_effort") or config.get("reasoning_effort") or "")
    if reasoning_effort and reasoning_effort not in REASONING_EFFORTS:
        raise ValueError("Invalid thinking level.")
    token_budget = int(body.get("token_budget") or DEEP_GOAL_DEFAULT_TOKENS)
    if not DEEP_GOAL_MIN_TOKENS <= token_budget <= DEEP_GOAL_MAX_TOKENS:
        raise ValueError(
            f"Deep-investigation token budget must be between {DEEP_GOAL_MIN_TOKENS} and {DEEP_GOAL_MAX_TOKENS}."
        )
    report = json_file(run_dir / "report.json") or {}
    label = f"{report.get('package') or run_id} deep investigation"
    return label, {
        "run": str(run_dir), "provider": "codex", "model": model,
        "reasoning_effort": reasoning_effort, "token_budget": token_budget,
    }


def parse_bypass_launch(run_id: str, body: dict) -> tuple[str, dict]:
    if not body.get("authorized") or not body.get("confirmed"):
        raise ValueError("Confirm authorization before launching the APK with its bypass script.")
    run_dir = resolve_run_directory(run_id)
    loop = json_file(run_dir / "codex-loop-result.json") or {}
    script = successful_candidate_path(run_dir, loop)
    if not script:
        raise ValueError("This assessment has no validated successful bypass script.")
    config = json_file(run_dir / "codex-loop-config.json") or {}
    report = json_file(run_dir / "report.json") or {}
    if not config.get("target") or not report.get("package"):
        raise ValueError("The successful run has no recorded device target or package name.")
    label = f"{report.get('package') or run_id} bypass session"
    return label, {"run": str(run_dir), "successful_script": script}


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
    job_items = jobs()
    return {
        "apks": apks, "success_specs": specs, "runs": runs(), "jobs": job_items,
        "jobs_has_more": job_count() > len(job_items),
        "job_types": public_job_type_catalog(),
        "diagnostic_recipes": diagnostic_recipe_catalog(),
        "deep_goal": {
            "default_token_budget": DEEP_GOAL_DEFAULT_TOKENS,
            "minimum_token_budget": DEEP_GOAL_MIN_TOKENS,
            "maximum_token_budget": DEEP_GOAL_MAX_TOKENS,
        },
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
    limit = min(50, max(1, int(request.args.get("limit") or 20)))
    offset = max(0, int(request.args.get("offset") or 0))
    items = jobs(limit=limit, offset=offset)
    total = job_count()
    next_offset = offset + len(items)
    return jsonify(
        jobs=items, has_more=next_offset < total,
        next_offset=next_offset, total=total,
    )


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


def start_deep_investigation(run_id: str):
    label, payload = parse_deep_investigation(
        run_id, request.get_json(force=True, silent=False) or {},
    )
    return jsonify(start_job("deep_goal", label, payload)), 202


def start_bypass_launch(run_id: str):
    label, payload = parse_bypass_launch(
        run_id, request.get_json(force=True, silent=False) or {},
    )
    return jsonify(start_job("launch_bypass", label, payload)), 202


_handlers = SimpleNamespace(**{
    name: globals()[name] for name in (
        "health", "overview", "events", "models", "providers", "upload_apk",
        "get_provider_auth", "begin_provider_auth", "logout_provider_auth",
        "get_auth", "begin_auth", "logout_auth", "devices",
        "connect_wireless_device", "device_readiness", "pair_wireless_device",
        "list_runs", "list_run_artifacts", "preview_run_artifact",
        "download_run_artifact", "get_run_assistant", "ask_run_assistant",
        "get_run_assistant_request", "start_deep_investigation", "start_bypass_launch", "list_jobs", "get_job", "cancel_job", "pause_job", "start",
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
