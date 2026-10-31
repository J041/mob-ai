from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, TextIO
import zipfile

from pipeline.pipeline import scan_native
from ui.providers import ProviderRequest, provider_adapter, validate_provider_output


WORKSPACE = Path(os.environ.get("MOB_AI_WORKSPACE", "/workspace")).resolve()
RUNS_ROOT = WORKSPACE / "runs"
PIPELINE = WORKSPACE / "pipeline" / "pipeline.py"
DECISION_SCHEMA = WORKSPACE / "pipeline" / "codex-decision.schema.json"
NATIVE_SELECTION_SCHEMA = WORKSPACE / "pipeline" / "native-selection.schema.json"
CODEX = shutil.which("codex") or "codex"
GHIDRA_BRIDGE = "/opt/ghidra-mcp/venv/bin/bridge-mcp-ghidra"
GHIDRA_URL = os.environ.get("GHIDRA_MCP_URL", "http://reverse-engineering:8089")
GHIDRA_TOKEN = os.environ.get("GHIDRA_MCP_AUTH_TOKEN", "")


class LoopError(RuntimeError):
    """A bounded orchestration or compatibility failure."""


class EnvironmentFailure(LoopError):
    """An operational dependency failed before an assessment conclusion was possible."""


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


def container_path(path: Path) -> str:
    return f"/workspace/{workspace_relative(path)}"


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def attempt_fingerprint(candidate_hash: str, validation: Any) -> str:
    compact = json.dumps(validation, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((candidate_hash.lower() + compact).encode()).hexdigest()


def run_logged(
    command: list[str], log: TextIO, *, cwd: Path = WORKSPACE,
    input_text: str | None = None, artifact: Path | None = None,
) -> tuple[int, str]:
    log.write(f"+ {' '.join(command)}\n")
    log.flush()
    artifact_stream = artifact.open("w", encoding="utf-8") if artifact else None
    try:
        process = subprocess.Popen(
            command, cwd=cwd, text=True, stdin=subprocess.PIPE if input_text is not None else None,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1,
        )
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
        return process.wait(), "".join(chunks)
    finally:
        if artifact_stream:
            artifact_stream.close()


def pipeline_args(*values: str) -> list[str]:
    return ["python3", str(PIPELINE), *values]


def target_args(config: dict[str, Any]) -> list[str]:
    if config["transport"] == "wireless":
        return ["--wireless-connect", config["target"]]
    return ["--device", config["target"]]


def write_summary(
    run_dir: Path, status: str, records: list[Any], detail: str, *,
    checkpoint: dict[str, Any] | None = None, reason: str = "",
) -> None:
    payload = {
        "status": status,
        "detail": detail,
        "reason": reason,
        "recoverable": status == "environment_error" and bool(checkpoint),
        "checkpoint": checkpoint,
        "run_directory": workspace_relative(run_dir),
        "completed_utc": datetime.now(timezone.utc).isoformat(),
        "iterations": records,
    }
    write_json(run_dir / "codex-loop-result.json", payload)


def frida_recovery_available(summary: dict[str, Any]) -> bool:
    """Limit human-review continuation to recognizable Frida transport failures."""
    if summary.get("status") != "human_review":
        return False
    evidence = json.dumps({
        "detail": summary.get("detail"),
        "last_iteration": (summary.get("iterations") or [{}])[-1],
    }, ensure_ascii=False).lower()
    failures = (
        "connection refused", "connection closed", "failed to spawn",
        "inaccessible or not found", "frida-server", "port 27042",
    )
    return "frida" in evidence and any(marker in evidence for marker in failures)


def checkpoint_recovery_available(summary: dict[str, Any]) -> bool:
    checkpoint = summary.get("checkpoint") or {}
    return bool(
        summary.get("status") == "environment_error"
        and summary.get("recoverable")
        and checkpoint.get("stage") in {"observation", "validation"}
    )


def codex_config() -> str:
    bridge_env = {"GHIDRA_MCP_URL": GHIDRA_URL}
    if GHIDRA_TOKEN:
        bridge_env["GHIDRA_MCP_AUTH_TOKEN"] = GHIDRA_TOKEN
    env_toml = ", ".join(f"{key} = {json.dumps(value)}" for key, value in bridge_env.items())
    return f'''[mcp_servers.ghidra]
command = "{GHIDRA_BRIDGE}"
args = ["--transport", "stdio"]
env = {{ {env_toml} }}
enabled = true
required = false
startup_timeout_sec = 180
tool_timeout_sec = 300
default_tools_approval_mode = "auto"
'''


def codex_config_overrides() -> list[str]:
    """Force container-native MCP settings even when host project config is present."""
    bridge_env = {"GHIDRA_MCP_URL": GHIDRA_URL}
    if GHIDRA_TOKEN:
        bridge_env["GHIDRA_MCP_AUTH_TOKEN"] = GHIDRA_TOKEN
    env_toml = "{ " + ", ".join(
        f"{key} = {json.dumps(value)}" for key, value in bridge_env.items()
    ) + " }"
    values = {
        "mcp_servers.ghidra.command": json.dumps(GHIDRA_BRIDGE),
        "mcp_servers.ghidra.args": json.dumps(["--transport", "stdio"]),
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
    environment = {"GHIDRA_MCP_URL": GHIDRA_URL}
    if GHIDRA_TOKEN:
        environment["GHIDRA_MCP_AUTH_TOKEN"] = GHIDRA_TOKEN
    return {"mcpServers": {"ghidra": {
        "type": "stdio", "command": GHIDRA_BRIDGE,
        "args": ["--transport", "stdio"], "env": environment,
    }}}


def codex_reasoning_args(config: dict[str, Any]) -> list[str]:
    effort = str(config.get("reasoning_effort") or "")
    return ["--config", f"model_reasoning_effort={json.dumps(effort)}"] if effort else []


def codex_multi_agent_args(config: dict[str, Any]) -> list[str]:
    return ["--enable", "multi_agent"] if config.get("reasoning_mode") == "parallel" else ["--disable", "multi_agent"]


class LoopRunner:
    def __init__(self, log: TextIO):
        self.log = log

    def new(self, request: dict[str, Any]) -> tuple[str, Path]:
        apk = Path(request["apk"]).resolve()
        success_spec = Path(request["success_spec"]).resolve()
        config: dict[str, Any] = {
            "version": 1,
            "apk": workspace_relative(apk),
            "apk_sha256": sha256(apk),
            "success_spec": workspace_relative(success_spec),
            "success_spec_sha256": sha256(success_spec),
            "transport": request["transport"],
            "target": request["target"],
            "package": request.get("package") or "",
            "observation_seconds": int(request["observation_seconds"]),
            "run_seconds": int(request["run_seconds"]),
            "start_frida_server": request.get("frida_server") or "",
            "model": request.get("model") or "",
            "provider": request.get("provider") or "codex",
            "reasoning_effort": request.get("reasoning_effort") or "",
            "reasoning_mode": request.get("reasoning_mode") or "single",
            "specialist_count": int(request.get("specialist_count") or 3),
            "derived_from_run": str(request.get("derived_from_run") or ""),
            "derived_from_policy_sha256": str(request.get("derived_from_policy_sha256") or ""),
        }
        command = pipeline_args(
            container_path(apk), "--authorized", "--strategy", "frida",
            "--observation-mode", "only", "--observation-seconds", str(config["observation_seconds"]),
            "--run-seconds", str(config["run_seconds"]), "--success-spec", container_path(success_spec),
            *target_args(config),
        )
        if config["derived_from_run"]:
            source_run = (RUNS_ROOT / config["derived_from_run"]).resolve()
            try:
                source_run.relative_to(RUNS_ROOT.resolve())
            except ValueError as error:
                raise LoopError("Reassessment source escaped the runs directory.") from error
            source_apk = source_run / "original.apk"
            if not source_run.is_dir() or not source_apk.is_file() or sha256(source_apk) != config["apk_sha256"]:
                raise LoopError("Reassessment source does not contain the same APK.")
            command.extend(["--reuse-static", container_path(source_run)])
        if request.get("install"):
            command.append("--install")
        if config["start_frida_server"]:
            command.extend(["--start-frida-server", config["start_frida_server"]])
        if config["package"]:
            command.extend(["--package", config["package"]])
        exit_code, output = run_logged(command, self.log)
        match = re.search(r"Run directory:\s+(?P<path>/workspace/\S+)", output)
        if not match:
            raise EnvironmentFailure("The observation phase failed before creating a run checkpoint.")
        run_dir = (WORKSPACE / match.group("path").removeprefix("/workspace/")).resolve()
        config["created_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(run_dir / "codex-loop-config.json", config)
        (run_dir / "agent").mkdir(exist_ok=True)
        result_path = run_dir / "result.json"
        if exit_code not in {0, 1} or not result_path.is_file():
            detail = f"Device observation failed operationally with exit code {exit_code}."
            write_summary(
                run_dir, "environment_error", [], detail,
                checkpoint={"stage": "observation"}, reason="observation_operational_failure",
            )
            return "environment_error", run_dir
        result = read_json(result_path)
        config["package"] = str(result.get("package") or config["package"])
        config["baseline"] = {
            "passed": bool(result.get("success")),
            "checks": result.get("checks") or [],
        }
        write_json(run_dir / "codex-loop-config.json", config)
        if result.get("success"):
            write_summary(run_dir, "success_without_bypass", [], "The observation run already satisfied the success policy.")
            return "success_without_bypass", run_dir
        status = self._iterations(
            run_dir, config, [], start_iteration=1,
            additional=int(request["max_iterations"]), previous_candidate=None,
            previous_fingerprint=None, restart_frida=False,
        )
        return status, run_dir

    def _load_existing_run(self, request: dict[str, Any]) -> tuple[Path, dict[str, Any], dict[str, Any], list[Any]]:
        run_dir = Path(request["run"]).resolve()
        try:
            run_dir.relative_to(RUNS_ROOT.resolve())
        except ValueError as error:
            raise LoopError("Resume target must be inside /workspace/runs.") from error
        required = [
            run_dir / "agent", run_dir / "codex-loop-config.json", run_dir / "codex-loop-result.json",
            run_dir / "report.json", run_dir / "original.apk",
        ]
        missing = [str(path) for path in required if not path.exists()]
        if missing:
            raise LoopError(f"Cannot resume; required artifact is missing: {missing[0]}")
        config = read_json(run_dir / "codex-loop-config.json")
        requested_policy_hash = str(request.get("success_spec_sha256") or "")
        if requested_policy_hash and requested_policy_hash != str(config.get("success_spec_sha256") or ""):
            raise LoopError("The selected success policy does not match this assessment run.")
        summary = read_json(run_dir / "codex-loop-result.json")
        if config.get("version") != 1:
            raise LoopError("Unsupported loop configuration version.")
        if sha256(run_dir / "original.apk") != config["apk_sha256"]:
            raise LoopError("original.apk no longer matches the recorded APK hash.")
        spec = (WORKSPACE / config["success_spec"]).resolve()
        if not spec.is_file() or sha256(spec) != config["success_spec_sha256"]:
            raise LoopError("The recorded success policy is missing or has changed.")
        records = list(summary.get("iterations") or [])
        return run_dir, config, summary, records

    def resume(self, request: dict[str, Any]) -> tuple[str, Path]:
        run_dir, config, summary, records = self._load_existing_run(request)
        if checkpoint_recovery_available(summary):
            resumed_frida = str(request.get("frida_server") or config.get("start_frida_server") or "")
            checkpoint = summary.get("checkpoint") or {}
            if checkpoint.get("stage") == "observation":
                return self._recover_observation(
                    run_dir, config, records, resumed_frida,
                    additional=int(request["max_iterations"]),
                    provider=str(request.get("provider") or ""),
                    model=str(request.get("model") or ""),
                    reasoning_effort=str(request.get("reasoning_effort") or ""),
                    reasoning_mode=str(request.get("reasoning_mode") or ""),
                    specialist_count=int(request.get("specialist_count") or 3),
                )
            return self._recover_validation(
                run_dir, config, records, checkpoint,
                additional=int(request["max_iterations"]),
                provider=str(request.get("provider") or ""),
                model=str(request.get("model") or ""),
                reasoning_effort=str(request.get("reasoning_effort") or ""),
                reasoning_mode=str(request.get("reasoning_mode") or ""),
                specialist_count=int(request.get("specialist_count") or 3),
            )
        if summary.get("status") == "human_review" and frida_recovery_available(summary):
            frida_server = str(request.get("frida_server") or "")
            if not frida_server:
                raise LoopError("A device-side Frida Server path is required for this recovery.")
            return self._recover_observation(
                run_dir, config, records, frida_server,
                additional=int(request["max_iterations"]),
                provider=str(request.get("provider") or ""),
                model=str(request.get("model") or ""),
                reasoning_effort=str(request.get("reasoning_effort") or ""),
                reasoning_mode=str(request.get("reasoning_mode") or ""),
                specialist_count=int(request.get("specialist_count") or 3),
            )
        if not records:
            raise LoopError("The prior run has no completed iteration records.")
        if summary.get("status") != "max_iterations":
            raise LoopError(f"Only max_iterations or recoverable Frida runs can continue; this run ended with {summary.get('status')!r}.")
        last = max(records, key=lambda item: int(item["iteration"]))
        previous_candidate = (WORKSPACE / last["candidate"]).resolve()
        try:
            previous_candidate.relative_to(run_dir)
        except ValueError as error:
            raise LoopError("The recorded candidate is outside the run directory.") from error
        if not previous_candidate.is_file() or sha256(previous_candidate) != last["candidate_sha256"]:
            raise LoopError("The last candidate is missing or changed after validation.")
        prior_fingerprint = attempt_fingerprint(last["candidate_sha256"], last["validation"])
        start = int(last["iteration"]) + 1
        resumed_config = dict(config)
        if request.get("model"):
            resumed_config["model"] = request["model"]
        if request.get("provider"):
            resumed_config["provider"] = request["provider"]
        if request.get("reasoning_effort"):
            resumed_config["reasoning_effort"] = request["reasoning_effort"]
        if request.get("reasoning_mode"):
            resumed_config["reasoning_mode"] = request["reasoning_mode"]
            resumed_config["specialist_count"] = int(request.get("specialist_count") or 3)
        status = self._iterations(
            run_dir, resumed_config, records, start_iteration=start,
            additional=int(request["max_iterations"]), previous_candidate=previous_candidate,
            previous_fingerprint=prior_fingerprint, restart_frida=bool(config.get("start_frida_server")),
        )
        return status, run_dir

    def retry_with_diagnostics(self, request: dict[str, Any]) -> tuple[str, Path]:
        """Rerun observation for any completed run while preserving its evidence."""
        run_dir, config, _summary, records = self._load_existing_run(request)
        retry_number = 1
        while (run_dir / "agent" / f"diagnostic-retry-{retry_number}").exists():
            retry_number += 1
        retry_dir = run_dir / "agent" / f"diagnostic-retry-{retry_number}"
        before_dir = retry_dir / "before"
        after_dir = retry_dir / "after"
        retry_dir.mkdir(parents=True)
        archived = {
            "result.json", "observations.json", "adaptive-plan.json", "codex-loop-result.json",
            "logs/observation-frida.log", "logs/observation-logcat.log",
            "logs/diagnostic-crash-buffer.log", "logs/diagnostic-exit-info.log",
            "logs/diagnostic-native-crashes.log", "logs/diagnostic-tombstone-access.log",
        }
        for relative in archived:
            source = run_dir / relative
            if source.is_file():
                destination = before_dir / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
        write_json(retry_dir / "request.json", {
            "retry": retry_number,
            "mode": "diagnostics",
            "previous_status": _summary.get("status") or "unknown",
            "started_utc": datetime.now(timezone.utc).isoformat(),
        })
        result_path = run_dir / "result.json"
        result_path.unlink(missing_ok=True)
        command = pipeline_args(
            "--authorized", "--strategy", "frida", "--resume", container_path(run_dir),
            "--observation-mode", "only", "--diagnostics",
            "--observation-seconds", str(config["observation_seconds"]),
            "--run-seconds", str(config["run_seconds"]),
            "--success-spec", f"/workspace/{config['success_spec']}",
            *target_args(config),
        )
        frida_server = str(request.get("frida_server") or config.get("start_frida_server") or "")
        if frida_server:
            command.extend(["--start-frida-server", frida_server])
        if config.get("package"):
            command.extend(["--package", config["package"]])
        exit_code, _ = run_logged(command, self.log, artifact=retry_dir / "pipeline.log")
        if exit_code not in {0, 1} or not result_path.is_file():
            previous_result = before_dir / "result.json"
            if previous_result.is_file():
                shutil.copy2(previous_result, result_path)
            detail = "Diagnostic retry failed operationally; verify device and Frida readiness, then retry again."
            write_summary(
                run_dir, "environment_error", records, detail,
                checkpoint={"stage": "observation"}, reason="diagnostic_retry_failure",
            )
            return "environment_error", run_dir

        recovered = read_json(result_path)
        for relative in archived - {"codex-loop-result.json"}:
            source = run_dir / relative
            if source.is_file():
                destination = after_dir / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
        previous_log = (before_dir / "logs" / "observation-logcat.log").read_text(encoding="utf-8", errors="replace") if (before_dir / "logs" / "observation-logcat.log").is_file() else ""
        current_log = (run_dir / "logs" / "observation-logcat.log").read_text(encoding="utf-8", errors="replace") if (run_dir / "logs" / "observation-logcat.log").is_file() else ""
        signal_pattern = re.compile(r"SIG[A-Z]+|BUS_[A-Z]+", re.I)
        write_json(retry_dir / "comparison.json", {
            "retry": retry_number,
            "previous_signals": sorted(set(signal_pattern.findall(previous_log))),
            "current_signals": sorted(set(signal_pattern.findall(current_log))),
            "same_success_result": bool((_summary.get("status") in {"success", "success_without_bypass"}) == bool(recovered.get("success"))),
            "diagnostic_files": (read_json(run_dir / "observations.json").get("diagnostics") or {}) if (run_dir / "observations.json").is_file() else {},
        })

        resumed_config = dict(config)
        resumed_config["start_frida_server"] = frida_server
        resumed_config["package"] = str(recovered.get("package") or resumed_config.get("package") or "")
        resumed_config["baseline"] = {"passed": bool(recovered.get("success")), "checks": recovered.get("checks") or []}
        history = list(resumed_config.get("diagnostic_retry_history") or [])
        history.append({"retry": retry_number, "directory": workspace_relative(retry_dir), "completed_utc": datetime.now(timezone.utc).isoformat()})
        resumed_config["diagnostic_retry_history"] = history
        for field in ("provider", "model", "reasoning_effort", "reasoning_mode"):
            if request.get(field):
                resumed_config[field] = request[field]
        if request.get("reasoning_mode"):
            resumed_config["specialist_count"] = int(request.get("specialist_count") or 3)
        write_json(run_dir / "codex-loop-config.json", resumed_config)
        if recovered.get("success"):
            write_summary(run_dir, "success_without_bypass", records, f"Diagnostic retry {retry_number} satisfied the recorded success policy.")
            return "success_without_bypass", run_dir
        last_iteration = max((int(item["iteration"]) for item in records), default=0)
        previous_candidate = run_dir / "agent" / f"iteration-{last_iteration}" / "candidate.js"
        if not previous_candidate.is_file():
            previous_candidate = None
        return self._iterations(
            run_dir, resumed_config, records, start_iteration=last_iteration + 1,
            additional=int(request["max_iterations"]), previous_candidate=previous_candidate,
            previous_fingerprint=None, restart_frida=False,
        ), run_dir

    def _recover_observation(
        self, run_dir: Path, config: dict[str, Any], records: list[Any], frida_server: str, *,
        additional: int, provider: str, model: str, reasoning_effort: str,
        reasoning_mode: str, specialist_count: int,
    ) -> tuple[str, Path]:
        recovery_number = 1
        while (run_dir / "agent" / f"checkpoint-recovery-{recovery_number}").exists():
            recovery_number += 1
        recovery_dir = run_dir / "agent" / f"checkpoint-recovery-{recovery_number}"
        recovery_dir.mkdir(parents=True)
        archived = {
            "result.json", "observations.json", "adaptive-plan.json",
            "logs/observation-frida.log", "logs/observation-logcat.log",
        }
        for relative in archived:
            source = run_dir / relative
            if source.is_file():
                destination = recovery_dir / "before" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
        write_json(recovery_dir / "request.json", {
            "recovery": recovery_number,
            "previous_frida_server": config.get("start_frida_server") or "",
            "frida_server": frida_server,
            "started_utc": datetime.now(timezone.utc).isoformat(),
        })
        result_path = run_dir / "result.json"
        result_path.unlink(missing_ok=True)
        command = pipeline_args(
            "--authorized", "--strategy", "frida", "--resume", container_path(run_dir),
            "--observation-mode", "only", "--observation-seconds", str(config["observation_seconds"]),
            "--run-seconds", str(config["run_seconds"]), "--success-spec", f"/workspace/{config['success_spec']}",
            *target_args(config),
        )
        if frida_server:
            command.extend(["--start-frida-server", frida_server])
        if config.get("package"):
            command.extend(["--package", config["package"]])
        exit_code, _ = run_logged(command, self.log, artifact=recovery_dir / "pipeline.log")
        if exit_code not in {0, 1} or not result_path.is_file():
            archived_result = recovery_dir / "before" / "result.json"
            if archived_result.is_file():
                shutil.copy2(archived_result, result_path)
            detail = "Observation checkpoint recovery failed; verify ADB and Frida readiness, then retry this checkpoint."
            write_summary(
                run_dir, "environment_error", records, detail,
                checkpoint={"stage": "observation"}, reason="observation_recovery_failure",
            )
            return "environment_error", run_dir
        recovered = read_json(result_path)
        shutil.copy2(result_path, recovery_dir / "result.json")
        resumed_config = dict(config)
        resumed_config["start_frida_server"] = frida_server
        resumed_config["package"] = str(recovered.get("package") or resumed_config.get("package") or "")
        resumed_config["baseline"] = {
            "passed": bool(recovered.get("success")),
            "checks": recovered.get("checks") or [],
        }
        history = list(resumed_config.get("frida_server_history") or [])
        history.append({
            "recovery": recovery_number,
            "previous": config.get("start_frida_server") or "",
            "current": frida_server,
            "updated_utc": datetime.now(timezone.utc).isoformat(),
        })
        resumed_config["frida_server_history"] = history
        if provider:
            resumed_config["provider"] = provider
        if model:
            resumed_config["model"] = model
        if reasoning_effort:
            resumed_config["reasoning_effort"] = reasoning_effort
        if reasoning_mode:
            resumed_config["reasoning_mode"] = reasoning_mode
            resumed_config["specialist_count"] = specialist_count
        write_json(run_dir / "codex-loop-config.json", resumed_config)
        if recovered.get("success"):
            write_summary(
                run_dir, "success_without_bypass", records,
                f"Frida recovery {recovery_number} restored observation and the baseline satisfied the success policy.",
            )
            return "success_without_bypass", run_dir
        last_iteration = max((int(item["iteration"]) for item in records), default=0)
        previous_candidate = run_dir / "agent" / f"iteration-{last_iteration}" / "candidate.js"
        if not previous_candidate.is_file():
            previous_candidate = None
        status = self._iterations(
            run_dir, resumed_config, records, start_iteration=last_iteration + 1,
            additional=additional, previous_candidate=previous_candidate,
            previous_fingerprint=None, restart_frida=False,
        )
        return status, run_dir

    def _recover_validation(
        self, run_dir: Path, config: dict[str, Any], records: list[Any], checkpoint: dict[str, Any], *,
        additional: int, provider: str, model: str, reasoning_effort: str,
        reasoning_mode: str, specialist_count: int,
    ) -> tuple[str, Path]:
        iteration = int(checkpoint.get("iteration") or 0)
        candidate_value = str(checkpoint.get("candidate") or "")
        candidate = (WORKSPACE / candidate_value).resolve()
        try:
            candidate.relative_to(run_dir)
        except ValueError as error:
            raise LoopError("The validation checkpoint candidate escaped the run directory.") from error
        iteration_dir = run_dir / "agent" / f"iteration-{iteration}"
        decision_path = iteration_dir / "decision.json"
        if not candidate.is_file() or not decision_path.is_file():
            raise LoopError("The validation checkpoint is missing its candidate or Codex decision.")
        recovery_number = 1
        while (run_dir / "agent" / f"checkpoint-recovery-{recovery_number}").exists():
            recovery_number += 1
        recovery_dir = run_dir / "agent" / f"checkpoint-recovery-{recovery_number}"
        recovery_dir.mkdir(parents=True)
        result_path = run_dir / "result.json"
        command = pipeline_args(
            "--authorized", "--strategy", "frida", "--resume", container_path(run_dir),
            "--observation-mode", "off", "--candidate-script", container_path(candidate),
            "--run-seconds", str(config["run_seconds"]), "--success-spec", f"/workspace/{config['success_spec']}",
            *target_args(config),
        )
        if config.get("package"):
            command.extend(["--package", config["package"]])
        if config.get("start_frida_server"):
            command.extend(["--start-frida-server", config["start_frida_server"]])
        result_path.unlink(missing_ok=True)
        exit_code, _ = run_logged(command, self.log, artifact=recovery_dir / "pipeline.log")
        if exit_code not in {0, 1} or not result_path.is_file():
            write_summary(
                run_dir, "environment_error", records,
                f"Validation checkpoint recovery failed operationally in iteration {iteration}.",
                checkpoint={
                    "stage": "validation", "iteration": iteration,
                    "candidate": workspace_relative(candidate),
                },
                reason="validation_recovery_failure",
            )
            return "environment_error", run_dir
        validation = read_json(result_path)
        shutil.copy2(result_path, recovery_dir / "validation.json")
        shutil.copy2(result_path, iteration_dir / "validation.json")
        decision = read_json(decision_path)
        candidate_hash = sha256(candidate)
        record = {
            "iteration": iteration, "candidate": workspace_relative(candidate),
            "candidate_sha256": candidate_hash, "codex": decision,
            "pipeline_exit_code": exit_code, "validation": validation,
            "recovered_by": workspace_relative(recovery_dir),
        }
        records.append(record)
        write_json(iteration_dir / "record.json", record)
        if validation.get("success"):
            write_summary(run_dir, "success", records, f"Success policy passed after recovering validation in iteration {iteration}.")
            return "success", run_dir
        if decision.get("decision") == "no_change":
            write_summary(
                run_dir, "assessment_failed", records,
                "Validation completed, but the policy remained unsatisfied and Codex proposed no justified change.",
                reason="no_justified_change",
            )
            return "assessment_failed", run_dir
        resumed_config = dict(config)
        if provider:
            resumed_config["provider"] = provider
        if model:
            resumed_config["model"] = model
        if reasoning_effort:
            resumed_config["reasoning_effort"] = reasoning_effort
        if reasoning_mode:
            resumed_config["reasoning_mode"] = reasoning_mode
            resumed_config["specialist_count"] = specialist_count
        status = self._iterations(
            run_dir, resumed_config, records, start_iteration=iteration + 1,
            additional=additional, previous_candidate=candidate,
            previous_fingerprint=attempt_fingerprint(candidate_hash, validation), restart_frida=False,
        )
        return status, run_dir

    def _iterations(
        self, run_dir: Path, config: dict[str, Any], records: list[Any], *, start_iteration: int,
        additional: int, previous_candidate: Path | None, previous_fingerprint: str | None,
        restart_frida: bool,
    ) -> str:
        agent_dir = run_dir / "agent"
        try:
            self._ensure_native_selection(run_dir, config)
        except (LoopError, OSError, zipfile.BadZipFile, json.JSONDecodeError) as error:
            write_summary(
                run_dir, "provider_error", records,
                f"Native target selection failed before iteration {start_iteration}: {error}",
                reason="native_selection_failure",
            )
            return "provider_error"
        end_iteration = start_iteration + additional - 1
        for iteration in range(start_iteration, end_iteration + 1):
            iteration_dir = agent_dir / f"iteration-{iteration}"
            if iteration_dir.exists():
                raise LoopError(f"Refusing to overwrite {iteration_dir}.")
            iteration_dir.mkdir(parents=True)
            codex_dir = iteration_dir / ".codex"
            codex_dir.mkdir()
            config_path = codex_dir / "config.toml"
            config_path.write_text(codex_config(), encoding="utf-8")
            provider = str(config.get("provider") or "codex")
            adapter = provider_adapter(provider)
            mcp_path = iteration_dir / "provider-mcp.json"
            if provider == "claude":
                write_json(mcp_path, claude_mcp_config())
            candidate = iteration_dir / "candidate.js"
            if previous_candidate:
                shutil.copy2(previous_candidate, candidate)
            else:
                shutil.copy2(run_dir / "frida" / "bypass-level-1.js", candidate)
            prior_dir = agent_dir / f"iteration-{iteration - 1}" if iteration > 1 else None
            prompt = self._prompt(
                run_dir, candidate, prior_dir, iteration, start_iteration, end_iteration,
                reasoning_mode=str(config.get("reasoning_mode") or "single"),
                specialist_count=int(config.get("specialist_count") or 3),
            )
            prompt_path = iteration_dir / "prompt.txt"
            decision_path = iteration_dir / "decision.json"
            provider_log = iteration_dir / f"{provider}.log"
            prompt_path.write_text(prompt, encoding="utf-8")
            protected = {prompt_path: sha256(prompt_path), config_path: sha256(config_path)}
            if mcp_path.is_file():
                protected[mcp_path] = sha256(mcp_path)
            provider_request = ProviderRequest(
                provider=provider, prompt=prompt, cwd=iteration_dir,
                schema_path=DECISION_SCHEMA, output_path=decision_path,
                model=str(config.get("model") or ""),
                reasoning_effort=str(config.get("reasoning_effort") or ""),
                reasoning_mode=str(config.get("reasoning_mode") or "single"),
                writable=True, mcp_config=mcp_path if mcp_path.is_file() else None,
                extra_args=tuple(codex_config_overrides()) if provider == "codex" else (),
            )
            command, provider_prompt = adapter.prepare(provider_request)
            exit_code, output = run_logged(
                command, self.log, cwd=iteration_dir, input_text=provider_prompt, artifact=provider_log,
            )
            completed = adapter.finalize(provider_request, exit_code, output)
            if not completed or not validate_provider_output(decision_path, DECISION_SCHEMA):
                write_summary(run_dir, "provider_error", records, f"{adapter.label} failed in iteration {iteration}.")
                return "provider_error"
            allowed = {candidate.resolve(), prompt_path.resolve(), decision_path.resolve(), provider_log.resolve(), config_path.resolve()}
            if mcp_path.is_file():
                allowed.add(mcp_path.resolve())
            unexpected = [path for path in iteration_dir.rglob("*") if path.is_file() and path.resolve() not in allowed]
            if any(sha256(path) != digest for path, digest in protected.items()) or unexpected:
                write_summary(run_dir, "codex_boundary_error", records, f"Codex wrote outside candidate.js in iteration {iteration}.")
                return "codex_boundary_error"
            decision = read_json(decision_path)
            if decision.get("decision") == "human_review":
                record = {"iteration": iteration, "codex": decision, "validation": None}
                records.append(record)
                write_json(iteration_dir / "record.json", record)
                write_summary(run_dir, "human_review", records, decision.get("rationale", "Codex requested review."))
                return "human_review"

            result_path = run_dir / "result.json"
            if result_path.exists():
                shutil.move(result_path, iteration_dir / "pre-validation-result.json")
            command = pipeline_args(
                "--authorized", "--strategy", "frida", "--resume", container_path(run_dir),
                "--observation-mode", "off", "--candidate-script", container_path(candidate),
                "--run-seconds", str(config["run_seconds"]), "--success-spec", f"/workspace/{config['success_spec']}",
                *target_args(config),
            )
            if config.get("package"):
                command.extend(["--package", config["package"]])
            if restart_frida and iteration == start_iteration:
                command.extend(["--start-frida-server", config["start_frida_server"]])
            exit_code, _ = run_logged(command, self.log, artifact=iteration_dir / "pipeline.log")
            if exit_code not in {0, 1} or not result_path.is_file():
                write_summary(
                    run_dir, "environment_error", records,
                    f"Candidate validation failed operationally in iteration {iteration}.",
                    checkpoint={
                        "stage": "validation", "iteration": iteration,
                        "candidate": workspace_relative(candidate),
                    },
                    reason="validation_operational_failure",
                )
                return "environment_error"
            validation = read_json(result_path)
            shutil.copy2(result_path, iteration_dir / "validation.json")
            for pattern in ("frida-1*.log", "logcat-1*.log"):
                for source in (run_dir / "logs").glob(pattern):
                    shutil.copy2(source, iteration_dir / source.name)
            candidate_hash = sha256(candidate)
            fingerprint = attempt_fingerprint(candidate_hash, validation)
            record = {
                "iteration": iteration, "candidate": workspace_relative(candidate),
                "candidate_sha256": candidate_hash, "codex": decision,
                "pipeline_exit_code": exit_code, "validation": validation,
            }
            records.append(record)
            write_json(iteration_dir / "record.json", record)
            if validation.get("success"):
                write_summary(run_dir, "success", records, f"Success policy passed in iteration {iteration}.")
                return "success"
            if previous_fingerprint and fingerprint == previous_fingerprint:
                write_summary(
                    run_dir, "assessment_failed", records,
                    "Two consecutive attempts produced the same candidate and validation result.",
                    reason="no_progress",
                )
                return "assessment_failed"
            if decision.get("decision") == "no_change":
                write_summary(
                    run_dir, "assessment_failed", records,
                    "Codex found no justified change and validation still failed.",
                    reason="no_justified_change",
                )
                return "assessment_failed"
            previous_fingerprint = fingerprint
            previous_candidate = candidate
        write_summary(run_dir, "max_iterations", records, f"The policy did not pass within this invocation's {additional} attempts.")
        return "max_iterations"

    def _ensure_native_selection(self, run_dir: Path, config: dict[str, Any]) -> dict[str, Any]:
        """Ask the selected reasoning provider to choose bounded native-analysis targets."""
        selection_path = run_dir / "native-selection.json"
        if selection_path.is_file():
            value = read_json(selection_path)
            if not isinstance(value, dict) or not isinstance(value.get("selected"), list):
                raise LoopError("The recorded native selection is invalid.")
            return value

        report = read_json(run_dir / "report.json")
        if "native_libraries" not in report:
            report["findings"] = [
                item for item in report.get("findings", [])
                if not isinstance(item, dict) or item.get("kind") != "native_indicator"
            ]
            report["native_libraries"] = scan_native(run_dir / "original.apk", run_dir / "jadx")
            write_json(run_dir / "report.json", report)
        inventory = report.get("native_libraries") or []
        if not isinstance(inventory, list):
            raise LoopError("The native library inventory is invalid.")
        available = {
            str(item.get("archive_path")): item
            for item in inventory
            if isinstance(item, dict) and item.get("archive_path")
        }
        if not available:
            value = {
                "provider": str(config.get("provider") or "codex"),
                "model": str(config.get("model") or ""),
                "rationale": "The APK contains no bounded native libraries to analyze.",
                "evidence_used": ["report.json native_libraries inventory"],
                "selected": [],
                "created_utc": datetime.now(timezone.utc).isoformat(),
            }
            write_json(selection_path, value)
            return value

        selection_root = run_dir / "agent" / "native-selection"
        selection_root.mkdir(parents=True, exist_ok=True)
        attempt = 1
        while (selection_root / f"attempt-{attempt}").exists():
            attempt += 1
        selection_dir = selection_root / f"attempt-{attempt}"
        selection_dir.mkdir()
        prompt_path = selection_dir / "prompt.txt"
        response_path = selection_dir / "decision.json"
        provider = str(config.get("provider") or "codex")
        adapter = provider_adapter(provider)
        prompt = f"""You are the native-target triage step in an explicitly authorized Android assessment.

Read-only assessment evidence: {run_dir}
Native inventory: {run_dir / 'report.json'} under the native_libraries field
Runtime evidence: observations.json, result.json, logs/, and any diagnostic crash records
Static evidence: JADX sources and AndroidManifest.xml below {run_dir / 'jadx'}

Select at most five native libraries that genuinely warrant Ghidra analysis. Base the selection on causal evidence such as application-owned names, System.loadLibrary call sites, native/JNI declarations, protected application startup, crash context, or relationships to observed checks. Raw string matches may be supporting context but must never be the sole reason for selection. Prefer the ABI matching runtime evidence and avoid duplicate architectures unless an ABI comparison is specifically justified. Select only exact archive_path values present in report.json. An empty selection is valid when native analysis is not justified.

Do not edit any file, invoke a device, or claim assessment success. Return only the required structured selection.
"""
        prompt_path.write_text(prompt, encoding="utf-8")
        request = ProviderRequest(
            provider=provider, prompt=prompt, cwd=selection_dir,
            schema_path=NATIVE_SELECTION_SCHEMA, output_path=response_path,
            model=str(config.get("model") or ""),
            reasoning_effort=str(config.get("reasoning_effort") or ""),
            reasoning_mode="single", writable=False,
            extra_args=("--config", "mcp_servers.ghidra.enabled=false") if provider == "codex" else (),
        )
        command, provider_prompt = adapter.prepare(request)
        exit_code, output = run_logged(
            command, self.log, cwd=selection_dir, input_text=provider_prompt,
            artifact=selection_dir / f"{provider}.log",
        )
        if not adapter.finalize(request, exit_code, output) or not validate_provider_output(response_path, NATIVE_SELECTION_SCHEMA):
            raise LoopError(f"{adapter.label} did not return a valid native target selection.")
        decision = read_json(response_path)
        raw_selected = decision.get("selected") or []
        if not isinstance(raw_selected, list) or len(raw_selected) > 5:
            raise LoopError("Native selection exceeded the five-library limit.")

        selected: list[dict[str, Any]] = []
        seen: set[str] = set()
        with zipfile.ZipFile(run_dir / "original.apk") as archive:
            archive_names = set(archive.namelist())
            for raw in raw_selected:
                if not isinstance(raw, dict):
                    raise LoopError("Native selection contained a non-object target.")
                archive_path = str(raw.get("archive_path") or "")
                priority = str(raw.get("priority") or "")
                reason = str(raw.get("reason") or "").strip()
                if archive_path not in available or archive_path not in archive_names:
                    raise LoopError(f"Native selection referenced a library outside the inventory: {archive_path}")
                if archive_path in seen or priority not in {"high", "medium", "low"} or not reason:
                    raise LoopError(f"Native selection metadata is invalid for {archive_path}.")
                seen.add(archive_path)
                inventory_item = available[archive_path]
                destination = run_dir / "native" / "selected" / str(inventory_item["abi"]) / str(inventory_item["name"])
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(archive_path))
                if sha256(destination) != str(inventory_item.get("sha256") or ""):
                    raise LoopError(f"Extracted native library hash mismatch: {archive_path}")
                selected.append({
                    "archive_path": archive_path,
                    "abi": inventory_item["abi"],
                    "name": inventory_item["name"],
                    "sha256": inventory_item["sha256"],
                    "priority": priority,
                    "reason": reason,
                    "load_references": inventory_item.get("load_references") or [],
                    "extracted": workspace_relative(destination),
                })

        value = {
            "provider": provider,
            "model": str(config.get("model") or ""),
            "rationale": str(decision.get("rationale") or ""),
            "evidence_used": decision.get("evidence_used") or [],
            "selected": selected,
            "created_utc": datetime.now(timezone.utc).isoformat(),
        }
        write_json(selection_path, value)
        config["native_selection"] = workspace_relative(selection_path)
        write_json(run_dir / "codex-loop-config.json", config)
        return value

    @staticmethod
    def _prompt(
        run_dir: Path, candidate: Path, prior_dir: Path | None,
        iteration: int, start_iteration: int, end_iteration: int, *,
        reasoning_mode: str, specialist_count: int,
    ) -> str:
        selection_path = run_dir / "native-selection.json"
        selection = read_json(selection_path) if selection_path.is_file() else {"selected": []}
        selected_targets = selection.get("selected") or []
        if selected_targets:
            rendered_targets = "\n".join(
                f"- {item.get('extracted')} [{item.get('priority')}]: {item.get('reason')}"
                for item in selected_targets if isinstance(item, dict)
            )
            native_guidance = f"""Codex/provider native triage selected these exact targets:
{rendered_targets}
Use Ghidra MCP for these targets when native evidence affects the decision. If list_instances is empty, import or open the selected binary through the MCP tools and wait for analysis instead of treating an empty instance list as completed native review. Import is authorized only for these isolated run artifacts; do not patch a binary."""
        else:
            native_guidance = "Native triage selected no Ghidra targets. Do not infer a native detector from raw string matches alone."
        if reasoning_mode == "parallel":
            delegation = f"""Parallel specialist mode is enabled. Spawn no more than {specialist_count} read-only subagents for independent evidence review, then wait for them and synthesize their findings before deciding:
- static specialist: JADX Java/Kotlin detector evidence;
- runtime specialist: observations, Frida output, logcat, and success-check failures;
- native specialist when native evidence exists: suspicious libraries through read-only Ghidra MCP.
With only two useful scopes, do not create an unnecessary third specialist. Subagents must not edit candidate.js or any other file, run device tools, or claim success. The root agent is the only writer and remains responsible for the final structured decision."""
        else:
            delegation = "Single-agent mode is enabled. Do not spawn subagents; inspect and decide within this root session."
        return f"""You are the reasoning step in an explicitly authorized Android application assessment loop.

Iteration: {iteration} (this invocation covers {start_iteration} through {end_iteration})
Read-only run evidence directory: {run_dir}
Editable candidate hook: {candidate}
Previous iteration evidence: {prior_dir or 'none'}
Ghidra MCP container path prefix for this run: {container_path(run_dir)}
Native target selection: {container_path(selection_path)}

{delegation}

{native_guidance}

Goal: make the smallest evidence-based change to the candidate Frida hook that can satisfy the success policy. Inspect report.json, observations.json, adaptive-plan.json, JADX output, and prior Frida/logcat/validation records. If native evidence is relevant, use read-only Ghidra MCP tools for native libraries from this run.

Hard boundaries:
- Edit only {candidate}. Do not modify the APK, pipeline, policy, reports, logs, or another file.
- Do not run ADB, Frida, the pipeline, install commands, or interact with a device. Deterministic orchestration performs validation.
- Do not rebuild or resign the APK.
- Keep hooks narrowly tied to observed anti-root, anti-debugging, or anti-hooking behavior. Do not disable unrelated controls.
- If evidence is insufficient, the next change is speculative/high-risk, or success requires remote-attestation defeat, return human_review without editing.
- Never claim success; only the structured policy establishes it.

Return the required structured decision after inspecting and, when justified, editing the candidate.
"""
