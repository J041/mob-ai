from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from ui.orchestrator import (
    EnvironmentFailure, LoopError, LoopRunner, RUNS_ROOT, WORKSPACE,
    checkpoint_recovery_available, frida_recovery_available, read_json,
    workspace_relative, write_json,
)


STATIC_ROOT = WORKSPACE / "ui" / "dist"
STATE_ROOT = WORKSPACE / "ui" / ".state" / "jobs"
UPLOAD_ROOT = WORKSPACE / "uploads"
POLICY_ROOT = WORKSPACE / "policies" / "generated"
STATE_ROOT.mkdir(parents=True, exist_ok=True)
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
POLICY_ROOT.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MOB_AI_MAX_UPLOAD_MB", "1024")) * 1024 * 1024
_jobs: dict[str, dict] = {}
_lock = threading.RLock()
_auth_lock = threading.RLock()
_auth_process: subprocess.Popen | None = None
_auth_state = {"running": False, "output": "", "exit_code": None, "started_utc": None}
_auth_cache = {"checked": 0.0, "authenticated": False, "detail": "Not checked."}
_model_cache = {"checked": 0.0, "models": [], "source": "not_checked"}
_readiness: dict[str, dict] = {}


MODEL_FALLBACK = [
    {"id": "gpt-6-astra", "display_name": "GPT-6 Astra", "is_default": False},
    {"id": "gpt-6.1-sol", "display_name": "GPT-6.1 Sol", "is_default": False},
    {"id": "gpt-6.1-terra", "display_name": "GPT-6.1 Terra", "is_default": False},
    {"id": "gpt-6-luna", "display_name": "GPT-6 Luna", "is_default": False},
]
REASONING_EFFORTS = {"none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra"}
DEFAULT_REASONING_LEVELS = [
    {"effort": "low", "description": "Faster responses with lighter reasoning."},
    {"effort": "medium", "description": "Balanced speed and reasoning depth."},
    {"effort": "high", "description": "Greater depth for complex problems."},
    {"effort": "xhigh", "description": "Extra depth for difficult agentic work."},
    {"effort": "max", "description": "Maximum reasoning for the hardest problems."},
]

ANSI_ESCAPE = re.compile(r"\x1B(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\))")


def strip_terminal_controls(value: str) -> str:
    value = ANSI_ESCAPE.sub("", value).replace("\r", "")
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def truthy(value: object) -> bool:
    return str(value or "").lower() in {"1", "true", "yes", "on"}


def json_file(path: Path):
    try:
        return read_json(path) if path.is_file() else None
    except (OSError, json.JSONDecodeError):
        return None


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


def codex_login_status(*, force: bool = False) -> dict:
    now = time.monotonic()
    with _auth_lock:
        if not force and now - float(_auth_cache["checked"]) < 10:
            return dict(_auth_cache)
    try:
        result = subprocess.run(
            ["codex", "login", "status"], text=True, capture_output=True, timeout=15,
        )
        detail = (result.stdout or result.stderr or "Not signed in.").strip()
        authenticated = result.returncode == 0
    except (OSError, subprocess.SubprocessError) as error:
        authenticated, detail = False, f"Codex login status failed: {error}"
    with _auth_lock:
        _auth_cache.update({"checked": now, "authenticated": authenticated, "detail": detail})
        return dict(_auth_cache)


def codex_authenticated() -> bool:
    return bool(codex_login_status()["authenticated"])


def codex_client_version() -> str:
    result = subprocess.run(
        ["codex", "--version"], text=True, capture_output=True, timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError("Could not determine the installed Codex version.")
    match = re.search(r"\b(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)\b", result.stdout)
    if not match:
        raise RuntimeError("Codex returned an unrecognized version string.")
    return match.group(1)


def read_connected_account_models() -> list[dict]:
    """Read the model catalog associated with the currently connected ChatGPT account."""
    auth_path = Path.home() / ".codex" / "auth.json"
    auth = json.loads(auth_path.read_text(encoding="utf-8"))
    tokens = auth.get("tokens") or {}
    access_token = str(tokens.get("access_token") or "")
    account_id = str(tokens.get("account_id") or "")
    if not access_token or not account_id:
        raise RuntimeError("The connected ChatGPT account has no usable Codex credential.")

    version = codex_client_version()
    query = urllib.parse.urlencode({"client_version": version})
    request_object = urllib.request.Request(
        f"https://chatgpt.com/backend-api/codex/models?{query}",
        headers={
            "Authorization": f"Bearer {access_token}",
            "ChatGPT-Account-ID": account_id,
            "Accept": "application/json",
            "User-Agent": f"mob-ai/codex-{version}",
        },
    )
    with urllib.request.urlopen(request_object, timeout=20) as response:
        payload = json.loads(response.read(2 * 1024 * 1024).decode("utf-8"))

    models: list[dict] = []
    for item in payload.get("models") or []:
        if item.get("visibility") != "list":
            continue
        identifier = str(item.get("slug") or "")
        if not re.fullmatch(r"[A-Za-z0-9._:\-]+", identifier):
            continue
        reasoning_levels = []
        for level in item.get("supported_reasoning_levels") or []:
            effort = str(level.get("effort") or "") if isinstance(level, dict) else str(level)
            if effort not in REASONING_EFFORTS:
                continue
            reasoning_levels.append({
                "effort": effort,
                "description": str(level.get("description") or "") if isinstance(level, dict) else "",
            })
        default_effort = str(item.get("default_reasoning_level") or "")
        models.append({
            "id": identifier,
            "display_name": str(item.get("display_name") or identifier),
            "is_default": False,
            "reasoning_levels": reasoning_levels,
            "default_reasoning_effort": default_effort if default_effort in REASONING_EFFORTS else "",
        })
    if not models:
        raise RuntimeError("The connected account returned no visible Codex models.")
    return models


def read_codex_models() -> list[dict]:
    process = subprocess.Popen(
        ["codex", "app-server"], cwd="/tmp", text=True,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        bufsize=1,
    )
    responses: queue.Queue[str | None] = queue.Queue()

    def collect() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            responses.put(line)
        responses.put(None)

    threading.Thread(target=collect, name="mob-ai-model-catalog", daemon=True).start()

    def send(message: dict) -> None:
        assert process.stdin is not None
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()

    def receive(identifier: int, timeout: float = 15) -> dict:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(["codex", "app-server"], timeout)
            line = responses.get(timeout=remaining)
            if line is None:
                raise RuntimeError("Codex app-server closed before returning the model catalog.")
            try:
                response = json.loads(line)
            except json.JSONDecodeError:
                continue
            if response.get("id") == identifier:
                if response.get("error"):
                    raise RuntimeError(str(response["error"]))
                return response

    try:
        send({"method": "initialize", "id": 0, "params": {"clientInfo": {
            "name": "mob_ai", "title": "Mob-AI Control Room", "version": "1.0.0",
        }}})
        receive(0)
        send({"method": "initialized", "params": {}})
        send({"method": "model/list", "id": 1, "params": {"limit": 100, "includeHidden": False}})
        response = receive(1)
        return list((response.get("result") or {}).get("data") or [])
    finally:
        if process.stdin:
            process.stdin.close()
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def codex_model_catalog(*, force: bool = False) -> dict:
    now = time.monotonic()
    with _auth_lock:
        if not force and now - float(_model_cache["checked"]) < 300:
            return {"models": list(_model_cache["models"]), "source": _model_cache["source"]}
    models: list[dict] = []
    source = "fallback"
    authenticated = codex_authenticated()
    if not authenticated:
        with _auth_lock:
            _model_cache.update({"checked": now, "models": [], "source": "authentication_required"})
        return {"models": [], "source": "authentication_required"}
    if authenticated:
        try:
            models = read_connected_account_models()
            source = "connected_chatgpt_account"
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError, urllib.error.URLError):
            pass
    try:
        if not models:
            for item in read_codex_models():
                identifier = str(item.get("model") or item.get("id") or "")
                if not re.fullmatch(r"[A-Za-z0-9._:\-]+", identifier):
                    continue
                models.append({
                    "id": identifier,
                    "display_name": str(item.get("displayName") or identifier),
                    "is_default": bool(item.get("isDefault")),
                    "reasoning_levels": [],
                    "default_reasoning_effort": "",
                })
            if models:
                source = "codex_app_server"
    except (OSError, RuntimeError, subprocess.SubprocessError, queue.Empty):
        pass
    if not models:
        models = [dict(model) for model in MODEL_FALLBACK]
    for model in models:
        if not model.get("reasoning_levels"):
            model["reasoning_levels"] = [dict(level) for level in DEFAULT_REASONING_LEVELS]
        model.setdefault("default_reasoning_effort", "")
    with _auth_lock:
        _model_cache.update({"checked": now, "models": models, "source": source})
    return {"models": models, "source": source}


def auth_state() -> dict:
    login = codex_login_status()
    with _auth_lock:
        flow = dict(_auth_state)
    return {
        "available": bool(shutil.which("codex")),
        "authenticated": login["authenticated"],
        "detail": login["detail"],
        "device_flow": flow,
    }


def start_device_auth() -> dict:
    global _auth_process
    if codex_login_status(force=True)["authenticated"]:
        return auth_state()
    with _auth_lock:
        if _auth_state["running"]:
            return auth_state()
        _auth_state.update({
            "running": True, "output": "Starting ChatGPT device sign-in…",
            "exit_code": None, "started_utc": utc_now(),
        })
        try:
            login_environment = os.environ.copy()
            login_environment["NO_COLOR"] = "1"
            _auth_process = subprocess.Popen(
                ["codex", "login", "--device-auth"], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1,
                env=login_environment,
            )
        except OSError as error:
            _auth_state.update({"running": False, "output": str(error), "exit_code": 2})
            raise ValueError(f"Could not start Codex device sign-in: {error}") from error

    def collect() -> None:
        global _auth_process
        assert _auth_process is not None and _auth_process.stdout is not None
        chunks: list[str] = []
        for line in _auth_process.stdout:
            chunks.append(line)
            with _auth_lock:
                _auth_state["output"] = strip_terminal_controls("".join(chunks))[-16_000:]
        exit_code = _auth_process.wait()
        with _auth_lock:
            _auth_state.update({"running": False, "exit_code": exit_code})
            _auth_process = None
            _auth_cache["checked"] = 0.0
            _model_cache["checked"] = 0.0

    threading.Thread(target=collect, name="mob-ai-codex-login", daemon=True).start()
    return auth_state()


def sign_out_codex() -> dict:
    with _auth_lock:
        if _auth_state["running"]:
            raise ValueError("Wait for the current ChatGPT sign-in attempt to finish before signing out.")
    try:
        result = subprocess.run(
            ["codex", "logout"], text=True, capture_output=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError(f"Could not sign out of ChatGPT: {error}") from error
    if result.returncode != 0:
        detail = strip_terminal_controls(result.stderr or result.stdout or "Codex logout failed.").strip()
        raise ValueError(detail)
    now = time.monotonic()
    with _auth_lock:
        _auth_cache.update({"checked": now, "authenticated": False, "detail": "Not signed in."})
        _model_cache.update({"checked": now, "models": [], "source": "authentication_required"})
        _auth_state.update({
            "running": False, "output": "", "exit_code": None, "started_utc": None,
        })
    return auth_state()


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
        frida_recoverable = bool(loop and config and frida_recovery_available(loop))
        checkpoint_recoverable = bool(loop and config and checkpoint_recovery_available(loop))
        resumable = bool(loop and loop.get("status") == "max_iterations" and config)
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
            "iterations": len(loop.get("iterations") or []) if loop else 0,
            "resumable": resumable,
            "frida_recoverable": frida_recoverable,
            "checkpoint_recoverable": checkpoint_recoverable,
            "continuable": bool(resumable or frida_recoverable or checkpoint_recoverable),
            "recovery_stage": str(((loop.get("checkpoint") or {}).get("stage") if loop else "") or ""),
            "reason": str((loop.get("reason") if loop else "") or ""),
            "frida_server": str(config.get("start_frida_server") if config else ""),
            "target": str(config.get("target") if config else latest.get("device") or ""),
            "transport": str(config.get("transport") if config else latest.get("transport") or ""),
            "updated_utc": datetime.fromtimestamp(directory.stat().st_mtime, timezone.utc).isoformat(),
        })
    return result


def job_state(job_id: str) -> dict:
    if not re.fullmatch(r"[a-f0-9]{32}", job_id):
        raise ValueError("Invalid job identifier.")
    with _lock:
        live = _jobs.get(job_id)
    stored = json_file(STATE_ROOT / job_id / "job.json")
    if not stored:
        raise FileNotFoundError("Job not found.")
    state = dict(stored)
    if live:
        state.update({"running": live["running"], "exit_code": live.get("exit_code"), "status": live.get("status")})
    elif state.get("running"):
        state.update({"running": False, "exit_code": None, "status": "interrupted"})
    log_path = STATE_ROOT / job_id / "output.log"
    if log_path.is_file():
        with log_path.open("rb") as stream:
            stream.seek(max(0, log_path.stat().st_size - 120_000))
            state["stdout"] = stream.read().decode("utf-8", errors="replace")
    else:
        state["stdout"] = ""
    state["stderr"] = ""
    return state


def jobs() -> list[dict]:
    directories = sorted((path for path in STATE_ROOT.iterdir() if path.is_dir()), key=lambda path: path.stat().st_mtime, reverse=True)
    result = []
    for directory in directories[:20]:
        try:
            result.append(job_state(directory.name))
        except (ValueError, FileNotFoundError):
            pass
    return result


def start_job(kind: str, label: str, payload: dict) -> dict:
    if not codex_authenticated():
        raise ValueError("Codex is not signed in. Connect a ChatGPT account from the dashboard first.")
    with _lock:
        if any(job["running"] for job in _jobs.values()):
            raise ValueError("Another assessment job is already running.")
        job_id = uuid.uuid4().hex
        directory = STATE_ROOT / job_id
        directory.mkdir(parents=True)
        state = {
            "id": job_id, "kind": kind, "label": label, "started_utc": utc_now(),
            "running": True, "exit_code": None, "status": "running",
        }
        _jobs[job_id] = state
        write_json(directory / "job.json", state)

    def worker() -> None:
        exit_code = 1
        status = "error"
        with (directory / "output.log").open("a", encoding="utf-8", buffering=1) as log:
            try:
                runner = LoopRunner(log)
                if kind == "resume":
                    status, run_dir = runner.resume(payload)
                else:
                    status, run_dir = runner.new(payload)
                log.write(f"\nLoop finished: {status}\nRun directory: {run_dir}\n")
                exit_code = 0 if status in {"success", "success_without_bypass"} else 1
            except EnvironmentFailure as error:
                log.write(f"\nerror: {error}\n")
                status = "environment_error"
                exit_code = 2
            except (LoopError, ValueError) as error:
                log.write(f"\nerror: {error}\n")
                status = "needs_input"
                exit_code = 2
            except (OSError, subprocess.SubprocessError) as error:
                log.write(f"\nerror: {error}\n")
                status = "environment_error"
                exit_code = 2
            finally:
                with _lock:
                    state.update({"running": False, "exit_code": exit_code, "status": status, "completed_utc": utc_now()})
                    write_json(directory / "job.json", state)

    threading.Thread(target=worker, name=f"mob-ai-{job_id}", daemon=True).start()
    return job_state(job_id)


def parse_start(body: dict) -> tuple[str, dict]:
    if not body.get("authorized"):
        raise ValueError("Confirm ownership or explicit testing authorization.")
    apk = resolve_workspace_item(str(body.get("apk") or ""))
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
    model = str(body.get("model") or "")
    if model:
        token(model, "model", r"[A-Za-z0-9._:\-]+")
    reasoning_effort = str(body.get("reasoning_effort") or "")
    if reasoning_effort and reasoning_effort not in REASONING_EFFORTS:
        raise ValueError("Invalid thinking level.")
    spec = success_policy(body)
    return apk.name, {
        "apk": str(apk), "success_spec": str(spec), "transport": transport, "target": target,
        "max_iterations": maximum, "observation_seconds": observation, "run_seconds": run_seconds,
        "install": bool(body.get("install")), "frida_server": frida_server, "package": package,
        "model": model, "reasoning_effort": reasoning_effort, "readiness_token": readiness_token,
    }


def parse_resume(body: dict) -> tuple[str, dict]:
    if not body.get("authorized"):
        raise ValueError("Confirm testing authorization before resuming.")
    run_dir = resolve_workspace_item(str(body.get("run") or ""), directory=True)
    try:
        run_dir.relative_to(RUNS_ROOT.resolve())
    except ValueError as error:
        raise ValueError("Resume target must be inside runs/.") from error
    maximum = int(body.get("max_iterations") or 0)
    if not 1 <= maximum <= 10:
        raise ValueError("Additional iterations must be between 1 and 10.")
    model = str(body.get("model") or "")
    if model:
        token(model, "model", r"[A-Za-z0-9._:\-]+")
    reasoning_effort = str(body.get("reasoning_effort") or "")
    if reasoning_effort and reasoning_effort not in REASONING_EFFORTS:
        raise ValueError("Invalid thinking level.")
    frida_server = str(body.get("frida_server") or "")
    if frida_server:
        token(frida_server, "Frida Server path", r"/[A-Za-z0-9_./-]+")
    return run_dir.name, {
        "run": str(run_dir), "max_iterations": maximum, "model": model,
        "reasoning_effort": reasoning_effort, "frida_server": frida_server,
    }


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
    return jsonify(status="ok", codex_available=bool(shutil.which("codex")))


@app.get("/api/overview")
def overview():
    apk_paths = [*WORKSPACE.glob("*.apk"), *UPLOAD_ROOT.glob("*.apk")]
    apks = [{"name": path.name, "path": workspace_relative(path), "size": path.stat().st_size} for path in apk_paths if path.is_file()]
    specs = [{"name": path.name, "path": workspace_relative(path)} for path in WORKSPACE.glob("*.json") if re.search(r"success|policy|spec", path.name, re.I)]
    example = WORKSPACE / "pipeline" / "success-spec.example.json"
    if example.is_file():
        specs.append({"name": example.name, "path": workspace_relative(example)})
    return jsonify(
        apks=apks, success_specs=specs, runs=runs(), jobs=jobs(),
        codex=auth_state(), models=codex_model_catalog(),
    )


@app.get("/api/models")
def models():
    return jsonify(codex_model_catalog(force=request.args.get("refresh") == "1"))


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
    return jsonify(devices=found)


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
        checks.append(readiness_check(
            "Wireless ADB", connected.returncode == 0 and bool(re.search(r"connected to|already connected", connected.stdout, re.I)),
            connected.stdout or connected.stderr,
        ))
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
            detail = detail.replace(pairing_code, "******")[-1000:]
            raise ValueError(f"Wireless pairing failed: {detail}")
    except subprocess.TimeoutExpired as error:
        raise ValueError("Wireless pairing timed out. Confirm the pairing address and try again.") from error
    finally:
        pairing_code = ""
    return jsonify(paired=True, endpoint=endpoint, message="Wireless debugging paired successfully.")


@app.get("/api/runs")
def list_runs():
    return jsonify(runs=runs())


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


@app.get("/")
def index():
    return send_from_directory(STATIC_ROOT, "index.html")


@app.get("/<path:name>")
def static_file(name: str):
    return send_from_directory(STATIC_ROOT, name)
