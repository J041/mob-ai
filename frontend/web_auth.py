"""Provider authentication and connected-account model discovery."""

from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from frontend.web_common import strip_terminal_controls, utc_now


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

_auth_lock = threading.RLock()
_auth_process: subprocess.Popen | None = None
_auth_state = {"running": False, "output": "", "exit_code": None, "started_utc": None}
_auth_cache = {"checked": 0.0, "authenticated": False, "detail": "Not checked."}
_model_cache = {"checked": 0.0, "models": [], "source": "not_checked"}
_claude_auth_process: subprocess.Popen | None = None
_claude_auth_state = {"running": False, "output": "", "exit_code": None, "started_utc": None}
_claude_auth_cache = {"checked": 0.0, "authenticated": False, "detail": "Not checked."}


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
    local_models: list[dict] = []
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
        local_models = read_codex_models()
        if models:
            local_by_id = {str(item.get("model") or item.get("id") or ""): item for item in local_models}
            for model in models:
                local = local_by_id.get(model["id"]) or {}
                model["is_default"] = bool(local.get("isDefault"))
                local_effort = str(local.get("defaultReasoningEffort") or "")
                if not model.get("default_reasoning_effort") and local_effort in REASONING_EFFORTS:
                    model["default_reasoning_effort"] = local_effort
        else:
            for item in local_models:
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
        if models and source != "connected_chatgpt_account":
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


def claude_login_status(*, force: bool = False) -> dict:
    now = time.monotonic()
    with _auth_lock:
        if not force and now - float(_claude_auth_cache["checked"]) < 10:
            return dict(_claude_auth_cache)
    try:
        result = subprocess.run(["claude", "auth", "status", "--json"], text=True, capture_output=True, timeout=15)
        detail = strip_terminal_controls(result.stdout or result.stderr or "Not signed in.").strip()
        authenticated = result.returncode == 0
        if authenticated:
            try:
                payload = json.loads(result.stdout)
                authenticated = bool(payload.get("loggedIn", payload.get("authenticated", True)))
                detail = str(payload.get("email") or payload.get("subscriptionType") or "Claude account connected.")
            except json.JSONDecodeError:
                pass
    except (OSError, subprocess.SubprocessError) as error:
        authenticated, detail = False, f"Claude login status failed: {error}"
    with _auth_lock:
        _claude_auth_cache.update({"checked": now, "authenticated": authenticated, "detail": detail})
        return dict(_claude_auth_cache)


def claude_auth_state() -> dict:
    login = claude_login_status()
    with _auth_lock:
        flow = dict(_claude_auth_state)
    return {
        "id": "claude", "label": "Claude", "account_label": "Claude.ai",
        "available": bool(shutil.which("claude")), "authenticated": login["authenticated"],
        "detail": login["detail"], "device_flow": flow,
    }


def start_claude_auth() -> dict:
    global _claude_auth_process
    if claude_login_status(force=True)["authenticated"]:
        return claude_auth_state()
    with _auth_lock:
        if _claude_auth_state["running"]:
            return claude_auth_state()
        _claude_auth_state.update({
            "running": True, "output": "Starting Claude browser sign-in…",
            "exit_code": None, "started_utc": utc_now(),
        })
        try:
            environment = os.environ.copy()
            environment.update({"NO_COLOR": "1", "DISABLE_AUTOUPDATER": "1"})
            _claude_auth_process = subprocess.Popen(
                ["claude", "auth", "login"], text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, bufsize=1, env=environment,
            )
        except OSError as error:
            _claude_auth_state.update({"running": False, "output": str(error), "exit_code": 2})
            raise ValueError(f"Could not start Claude sign-in: {error}") from error

    def collect() -> None:
        global _claude_auth_process
        assert _claude_auth_process is not None and _claude_auth_process.stdout is not None
        chunks: list[str] = []
        for line in _claude_auth_process.stdout:
            chunks.append(line)
            with _auth_lock:
                _claude_auth_state["output"] = strip_terminal_controls("".join(chunks))[-16_000:]
        exit_code = _claude_auth_process.wait()
        with _auth_lock:
            _claude_auth_state.update({"running": False, "exit_code": exit_code})
            _claude_auth_process = None
            _claude_auth_cache["checked"] = 0.0

    threading.Thread(target=collect, name="mob-ai-claude-login", daemon=True).start()
    return claude_auth_state()


def sign_out_claude() -> dict:
    with _auth_lock:
        if _claude_auth_state["running"]:
            raise ValueError("Wait for the current Claude sign-in attempt to finish before signing out.")
    result = subprocess.run(["claude", "auth", "logout"], text=True, capture_output=True, timeout=30)
    if result.returncode != 0:
        raise ValueError(strip_terminal_controls(result.stderr or result.stdout or "Claude logout failed.").strip())
    with _auth_lock:
        _claude_auth_cache.update({"checked": time.monotonic(), "authenticated": False, "detail": "Not signed in."})
        _claude_auth_state.update({"running": False, "output": "", "exit_code": None, "started_utc": None})
    return claude_auth_state()


def provider_auth_state(provider: str) -> dict:
    if provider == "codex":
        return {"id": "codex", "label": "Codex", "account_label": "ChatGPT", **auth_state()}
    if provider == "claude":
        return claude_auth_state()
    raise ValueError("Unsupported reasoning provider.")


def provider_authenticated(provider: str) -> bool:
    if provider == "codex":
        return codex_authenticated()
    if provider == "claude":
        return bool(claude_login_status()["authenticated"])
    return False


def provider_model_catalog(provider: str, *, force: bool = False) -> dict:
    if provider == "codex":
        return codex_model_catalog(force=force)
    if provider != "claude":
        raise ValueError("Unsupported reasoning provider.")
    if not claude_login_status(force=force)["authenticated"]:
        return {"provider": "claude", "models": [], "source": "authentication_required"}
    levels = [dict(level) for level in DEFAULT_REASONING_LEVELS if level["effort"] in {"low", "medium", "high"}]
    return {"provider": "claude", "source": "claude_code", "models": [
        {"id": "sonnet", "display_name": "Claude Sonnet", "is_default": True, "reasoning_levels": levels, "default_reasoning_effort": "high"},
        {"id": "opus", "display_name": "Claude Opus", "is_default": False, "reasoning_levels": levels, "default_reasoning_effort": "high"},
    ]}

