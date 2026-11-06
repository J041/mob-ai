"""Shared runtime primitives for the Mob-AI assessment orchestrator."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import threading
from typing import Any, TextIO
import urllib.error
import urllib.parse
import urllib.request

from assessment.control_points import CONTROL_POINT_STAGES, CONTROL_POINT_STATUSES, HOOK_LAYERS

from pipeline.diagnostic_recipes import DIAGNOSTIC_ACTIONS


WORKSPACE = Path(os.environ.get("MOB_AI_WORKSPACE", "/workspace")).resolve()
RUNS_ROOT = WORKSPACE / "runs"
PIPELINE = WORKSPACE / "pipeline" / "pipeline.py"
DECISION_SCHEMA = WORKSPACE / "pipeline" / "codex-decision.schema.json"
NATIVE_SELECTION_SCHEMA = WORKSPACE / "pipeline" / "native-selection.schema.json"
NATIVE_REPLENISHMENT_SCHEMA = WORKSPACE / "pipeline" / "native-replenishment.schema.json"
CODEX = shutil.which("codex") or "codex"
GHIDRA_BRIDGE = "/opt/ghidra-mcp/venv/bin/bridge-mcp-ghidra"
GHIDRA_URL = os.environ.get("GHIDRA_MCP_URL", "http://reverse-engineering:8089")
GHIDRA_TOKEN = os.environ.get("GHIDRA_MCP_AUTH_TOKEN", "")
GHIDRA_BRIDGE_URL = os.environ.get(
    "MOB_AI_GHIDRA_BRIDGE_URL",
    f"http://127.0.0.1:{os.environ.get('MOB_AI_GHIDRA_PROXY_PORT', '18089')}",
)
ADB_TRANSPORT_MARKER = "MOB_AI_ADB_TRANSPORT_ERROR "
NATIVE_BATCH_SIZE = 5
NATIVE_TOTAL_LIMIT = 15
GHIDRA_PREP_TIMEOUT_SECONDS = int(os.environ.get("MOB_AI_GHIDRA_PREP_TIMEOUT", "600"))


class LoopError(RuntimeError):
    """A bounded orchestration or compatibility failure."""


class EnvironmentFailure(LoopError):
    """An operational dependency failed before an assessment conclusion was possible."""


class ProviderUsageLimit(LoopError):
    """The selected account exhausted an included provider allowance."""

    def __init__(self, provider: str, usage: dict[str, str]):
        super().__init__(usage.get("detail") or f"{provider} usage allowance exhausted.")
        self.provider = provider
        self.usage = usage


class JobCancelled(RuntimeError):
    """The operator cancelled the active durable job."""


class JobPaused(RuntimeError):
    """The operator requested a pause at a safe orchestration boundary."""


class JobControl:
    """Process-local control for the single job owned by a durable worker."""

    def __init__(self) -> None:
        self.cancel_requested = threading.Event()
        self.pause_requested = threading.Event()
        self._lock = threading.Lock()
        self._process: subprocess.Popen | None = None
        self.stage = "starting"
        self.run_dir: Path | None = None

    def request_cancel(self) -> None:
        self.cancel_requested.set()
        with self._lock:
            process = self._process
        if process is not None:
            self._terminate(process)

    def request_pause(self) -> None:
        self.pause_requested.set()

    def register(self, process: subprocess.Popen) -> None:
        with self._lock:
            self._process = process
        if self.cancel_requested.is_set():
            self._terminate(process)

    def unregister(self, process: subprocess.Popen) -> None:
        with self._lock:
            if self._process is process:
                self._process = None

    @staticmethod
    def _terminate(process: subprocess.Popen) -> None:
        if process.poll() is not None:
            return
        try:
            if hasattr(os, "killpg"):
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            else:
                process.terminate()
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                if hasattr(os, "killpg"):
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                else:
                    process.kill()
            except OSError:
                pass


_job_control: JobControl | None = None
_job_control_lock = threading.Lock()


def install_job_control(control: JobControl | None) -> None:
    global _job_control
    with _job_control_lock:
        _job_control = control


def set_control_run_dir(run_dir: Path) -> None:
    if _job_control is not None:
        _job_control.run_dir = run_dir


def control_checkpoint(stage: str, run_dir: Path | None = None, *, allow_pause: bool = True) -> None:
    control = _job_control
    if control is None:
        return
    control.stage = stage
    if run_dir is not None:
        control.run_dir = run_dir
    if control.cancel_requested.is_set():
        raise JobCancelled("The assessment was cancelled by the operator.")
    if allow_pause and control.pause_requested.is_set():
        raise JobPaused("The assessment paused after completing its current stage.")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def workspace_relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(WORKSPACE).as_posix()
    except ValueError as error:
        raise LoopError(f"Artifact escaped the workspace: {path}") from error


def normalize_android_abi(value: str) -> str:
    aliases = {
        "arm64": "arm64-v8a", "aarch64": "arm64-v8a",
        "arm": "armeabi-v7a", "armeabi": "armeabi-v7a",
        "x64": "x86_64", "amd64": "x86_64",
    }
    normalized = value.strip().lower().replace("'", "").replace('"', "")
    return aliases.get(normalized, normalized)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def adb_transport_failure(output: str) -> dict[str, Any] | None:
    """Extract the pipeline's safe, structured ADB disconnect marker."""
    for line in reversed(output.splitlines()):
        if not line.startswith(ADB_TRANSPORT_MARKER):
            continue
        try:
            value = json.loads(line.removeprefix(ADB_TRANSPORT_MARKER))
        except json.JSONDecodeError:
            return {"reason": "ADB transport became unavailable."}
        if isinstance(value, dict):
            return value
    return None


def adb_transport_detail(output: str, fallback: str) -> tuple[str, str]:
    failure = adb_transport_failure(output)
    if not failure:
        return fallback, ""
    device = str(failure.get("device") or "the selected device")
    reason = str(failure.get("reason") or "became unavailable")
    command = str(failure.get("command") or "ADB command")
    return (
        f"Wireless/ADB target {device} disconnected during `{command}`: {reason}. "
        "Reconnect the exact device, run readiness, then recover this checkpoint.",
        "device_transport_failure",
    )


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def recorded_device_abi(run_dir: Path) -> str:
    result_path = run_dir / "result.json"
    if result_path.is_file():
        value = read_json(result_path)
        if isinstance(value, dict) and value.get("device_abi"):
            return normalize_android_abi(str(value["device_abi"]))
    logs = run_dir / "logs"
    if logs.is_dir():
        pattern = re.compile(r"\bABI\s*:\s*['\"]?([A-Za-z0-9_-]+)", re.I)
        for path in sorted(logs.glob("*.log")):
            if path.stat().st_size > 5_000_000:
                continue
            match = pattern.search(path.read_text(encoding="utf-8", errors="ignore"))
            if match:
                return normalize_android_abi(match.group(1))
    return ""


def container_path(path: Path) -> str:
    return f"/workspace/{workspace_relative(path)}"


def validate_decision_schema_registry(path: Path = DECISION_SCHEMA) -> None:
    """Fail closed if the CLI's concrete JSON enum drifts from the registry."""
    try:
        schema = read_json(path)
        values = schema["properties"]["diagnostic_actions"]["items"]["enum"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise LoopError("The provider decision schema has no diagnostic recipe enum.") from error
    if set(values) != set(DIAGNOSTIC_ACTIONS) or len(values) != len(DIAGNOSTIC_ACTIONS):
        raise LoopError("The provider decision schema diagnostic recipes do not match the shared registry.")
    try:
        properties = schema["properties"]
        hook_layers = properties["hook_layer"]["enum"]
        coverage = properties["control_point_coverage"]
        item_properties = coverage["items"]["properties"]
        stages = item_properties["stage"]["enum"]
        statuses = item_properties["status"]["enum"]
    except (KeyError, TypeError) as error:
        raise LoopError("The provider decision schema has no control-point registry.") from error
    if (
        tuple(stages) != CONTROL_POINT_STAGES
        or set(statuses) != set(CONTROL_POINT_STATUSES)
        or set(hook_layers) != set(HOOK_LAYERS)
        or coverage.get("minItems") != len(CONTROL_POINT_STAGES)
        or coverage.get("maxItems") != len(CONTROL_POINT_STAGES)
    ):
        raise LoopError("The provider decision schema control-point values do not match the shared registry.")


def ghidra_request(method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Call the private Ghidra backend without exposing its bearer token in process arguments."""
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if GHIDRA_TOKEN:
        headers["Authorization"] = f"Bearer {GHIDRA_TOKEN}"
    request = urllib.request.Request(
        f"{GHIDRA_URL.rstrip('/')}{path}", data=body, headers=headers, method=method,
    )
    try:
        timeout = 300 if method == "POST" and path == "/import_file" else 30
        with urllib.request.urlopen(request, timeout=timeout) as response:
            value = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as error:
        detail = error.read(2000).decode("utf-8", errors="replace")
        raise LoopError(f"Ghidra backend returned HTTP {error.code}: {detail}") from error
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise LoopError(f"Ghidra backend request failed: {error}") from error
    if not isinstance(value, dict):
        raise LoopError("Ghidra backend returned a non-object response.")
    if value.get("success") is False or value.get("error"):
        raise LoopError(f"Ghidra backend rejected the request: {value.get('error') or value}")
    return value


def attempt_fingerprint(candidate_hash: str, validation: Any) -> str:
    compact = json.dumps(validation, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((candidate_hash.lower() + compact).encode()).hexdigest()


def run_logged(
    command: list[str], log: TextIO, *, cwd: Path = WORKSPACE,
    input_text: str | None = None, artifact: Path | None = None, stage: str = "command",
) -> tuple[int, str]:
    control_checkpoint(stage, allow_pause=False)
    log.write(f"+ {' '.join(command)}\n")
    log.flush()
    artifact_stream = artifact.open("w", encoding="utf-8") if artifact else None
    try:
        process = subprocess.Popen(
            command, cwd=cwd, text=True, stdin=subprocess.PIPE if input_text is not None else None,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1,
            start_new_session=True,
        )
        if _job_control is not None:
            _job_control.register(process)
        if input_text is not None and process.stdin:
            process.stdin.write(input_text)
            process.stdin.close()
        chunks: list[str] = []
        assert process.stdout is not None
        for line in process.stdout:
            chunks.append(line)
            log.write(line)
            log.flush()
            if artifact_stream:
                artifact_stream.write(line)
                artifact_stream.flush()
        exit_code = process.wait()
        control_checkpoint(stage, allow_pause=False)
        return exit_code, "".join(chunks)
    finally:
        if 'process' in locals() and _job_control is not None:
            _job_control.unregister(process)
        if 'process' in locals() and process.stdout:
            process.stdout.close()
        if 'process' in locals() and process.stdin and not process.stdin.closed:
            process.stdin.close()
        if artifact_stream:
            artifact_stream.close()


def pipeline_args(*values: str) -> list[str]:
    return ["python3", str(PIPELINE), *values]


def target_args(config: dict[str, Any]) -> list[str]:
    if config["transport"] == "wireless":
        return ["--wireless-connect", config["target"]]
    return ["--device", config["target"]]


def codex_config() -> str:
    bridge_env = {
        "GHIDRA_MCP_URL": GHIDRA_BRIDGE_URL,
        "GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS": "1",
    }
    if GHIDRA_TOKEN:
        bridge_env["GHIDRA_MCP_AUTH_TOKEN"] = GHIDRA_TOKEN
    env_toml = ", ".join(f"{key} = {json.dumps(value)}" for key, value in bridge_env.items())
    return f'''[mcp_servers.ghidra]
command = "{GHIDRA_BRIDGE}"
args = ["--transport", "stdio", "--default-groups", "listing,function,program,xref,analysis,malware"]
env = {{ {env_toml} }}
enabled = true
required = false
startup_timeout_sec = 180
tool_timeout_sec = 300
default_tools_approval_mode = "auto"
'''


def codex_config_overrides() -> list[str]:
    """Force container-native MCP settings even when host project config is present."""
    bridge_env = {
        "GHIDRA_MCP_URL": GHIDRA_BRIDGE_URL,
        "GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS": "1",
    }
    if GHIDRA_TOKEN:
        bridge_env["GHIDRA_MCP_AUTH_TOKEN"] = GHIDRA_TOKEN
    env_toml = "{ " + ", ".join(
        f"{key} = {json.dumps(value)}" for key, value in bridge_env.items()
    ) + " }"
    values = {
        "mcp_servers.ghidra.command": json.dumps(GHIDRA_BRIDGE),
        "mcp_servers.ghidra.args": json.dumps([
            "--transport", "stdio", "--default-groups",
            "listing,function,program,xref,analysis,malware",
        ]),
        "mcp_servers.ghidra.env": env_toml,
        "mcp_servers.ghidra.enabled": "true",
        "mcp_servers.ghidra.required": "false",
        "mcp_servers.ghidra.startup_timeout_sec": "180",
        "mcp_servers.ghidra.tool_timeout_sec": "300",
        "mcp_servers.ghidra.default_tools_approval_mode": json.dumps("auto"),
    }
    result: list[str] = []
    for key, value in values.items():
        result.extend(["--config", f"{key}={value}"])
    return result


def claude_mcp_config() -> dict[str, Any]:
    environment = {
        "GHIDRA_MCP_URL": GHIDRA_BRIDGE_URL,
        "GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS": "1",
    }
    if GHIDRA_TOKEN:
        environment["GHIDRA_MCP_AUTH_TOKEN"] = GHIDRA_TOKEN
    return {"mcpServers": {"ghidra": {
        "type": "stdio", "command": GHIDRA_BRIDGE,
        "args": [
            "--transport", "stdio", "--default-groups",
            "listing,function,program,xref,analysis,malware",
        ], "env": environment,
    }}}


def codex_reasoning_args(config: dict[str, Any]) -> list[str]:
    effort = str(config.get("reasoning_effort") or "")
    return ["--config", f"model_reasoning_effort={json.dumps(effort)}"] if effort else []


def codex_multi_agent_args(config: dict[str, Any]) -> list[str]:
    return ["--enable", "multi_agent"] if config.get("reasoning_mode") == "parallel" else ["--disable", "multi_agent"]
