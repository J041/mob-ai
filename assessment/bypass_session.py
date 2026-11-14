"""Launch a validated successful Frida hook as an operator-controlled session."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, TextIO

from assessment.runtime import (
    RUNS_ROOT, EnvironmentFailure, JobCancelled, LoopError, read_json, run_logged,
    set_control_run_dir, write_json,
)
from assessment.successful_bypass import successful_candidate_path
from pipeline.frida_runtimes import frida_command


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_directory(value: str) -> Path:
    run_dir = Path(value).resolve()
    try:
        run_dir.relative_to(RUNS_ROOT.resolve())
    except ValueError as error:
        raise LoopError("Bypass session run escaped the runs directory.") from error
    if not run_dir.is_dir():
        raise LoopError("Bypass session run was not found.")
    return run_dir


def _command(command: list[str], log: TextIO, stage: str) -> str:
    code, output = run_logged(command, log, stage=stage)
    if code:
        detail = output.strip().splitlines()[-1] if output.strip() else f"exit code {code}"
        raise EnvironmentFailure(f"{stage.replace('_', ' ').title()} failed: {detail}")
    return output


def run_successful_bypass(payload: dict[str, Any], log: TextIO) -> tuple[str, Path]:
    """Attach the recorded successful script until the app exits or the job is cancelled."""
    run_dir = _run_directory(str(payload.get("run") or ""))
    set_control_run_dir(run_dir)
    config = read_json(run_dir / "codex-loop-config.json")
    loop = read_json(run_dir / "codex-loop-result.json")
    report = read_json(run_dir / "report.json")
    if not isinstance(config, dict) or not isinstance(loop, dict) or not isinstance(report, dict):
        raise LoopError("The successful run metadata is incomplete.")
    candidate_relative = successful_candidate_path(run_dir, loop)
    if not candidate_relative:
        raise LoopError("This run has no validated successful Frida script.")
    candidate = (run_dir / candidate_relative).resolve()
    target = str(config.get("target") or "")
    package = str(report.get("package") or config.get("package") or "")
    transport = str(config.get("transport") or "adb")
    frida_server = str(config.get("start_frida_server") or "")
    frida_version = str(config.get("frida_version") or "")
    if not target or not re.fullmatch(r"[A-Za-z0-9._:\-\[\]]+", target):
        raise LoopError("The run has no valid recorded device target.")
    if not package or not re.fullmatch(r"[A-Za-z0-9._]+", package):
        raise LoopError("The run has no valid recorded package name.")
    if frida_server and not re.fullmatch(r"/[A-Za-z0-9_./-]+", frida_server):
        raise LoopError("The recorded Frida Server path is invalid.")

    session_root = run_dir / "launches"
    session_root.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    session_dir = session_root / f"bypass-{stamp}"
    suffix = 1
    while session_dir.exists():
        suffix += 1
        session_dir = session_root / f"bypass-{stamp}-{suffix}"
    session_dir.mkdir()
    metadata = {
        "status": "starting", "started_utc": _utc_now(), "completed_utc": "",
        "target": target, "transport": transport, "package": package,
        "script": candidate_relative, "frida_version": frida_version,
    }
    write_json(session_dir / "session.json", metadata)

    try:
        if transport == "wireless":
            output = _command(["adb", "connect", target], log, "wireless_connect")
            if not re.search(r"connected to|already connected", output, re.I):
                raise EnvironmentFailure(f"Wireless ADB did not connect to {target}.")
        state = _command(["adb", "-s", target, "get-state"], log, "device_state")
        if state.strip() != "device":
            raise EnvironmentFailure(f"Recorded device {target} is not in the ADB device state.")
        _command(["adb", "-s", target, "forward", "tcp:27042", "tcp:27042"], log, "frida_forward")

        frida_ps = frida_command(frida_version, "frida-ps")
        probe_code, _probe_output = run_logged(
            [*frida_ps, "-H", "127.0.0.1:27042"], log, stage="frida_probe",
        )
        if probe_code:
            if not frida_server:
                raise EnvironmentFailure("Frida Server is unreachable and this run has no recorded server path.")
            _command(
                ["adb", "-s", target, "shell", "su", "-c", f"test -x {frida_server}"],
                log, "frida_server_check",
            )
            _command(
                ["adb", "-s", target, "shell", "su", "-c", f"{frida_server} -D"],
                log, "frida_server_start",
            )
            _command([*frida_ps, "-H", "127.0.0.1:27042"], log, "frida_probe")

        _command(["adb", "-s", target, "shell", "am", "force-stop", package], log, "app_stop")
        metadata["status"] = "running"
        write_json(session_dir / "session.json", metadata)
        frida = frida_command(frida_version, "frida")
        code, _output = run_logged(
            [*frida, "-H", "127.0.0.1:27042", "-f", package, "-l", str(candidate),
             "-q", "-t", "inf", "--exit-on-error"],
            log, artifact=session_dir / "frida.log", stage="bypass_session",
        )
        if code:
            raise EnvironmentFailure(f"Frida bypass session exited with code {code}.")
        metadata.update({"status": "ended", "completed_utc": _utc_now()})
        write_json(session_dir / "session.json", metadata)
        return "bypass_session_ended", run_dir
    except JobCancelled:
        metadata.update({"status": "cancelled", "completed_utc": _utc_now()})
        write_json(session_dir / "session.json", metadata)
        raise
    except Exception:
        metadata.update({"status": "error", "completed_utc": _utc_now()})
        write_json(session_dir / "session.json", metadata)
        raise
