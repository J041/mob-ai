"""Deterministic adaptive-diagnostic execution for the assessment loop."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, TextIO

from ui.orchestrator_runtime import (
    EnvironmentFailure, container_path, pipeline_args, read_json, run_logged,
    target_args, workspace_relative,
)


def run_adaptive_diagnostics(
    log: TextIO, run_dir: Path, config: dict[str, Any], iteration_dir: Path,
    iteration: int, actions: list[str], *,
    command_runner: Callable[..., tuple[int, str]] = run_logged,
) -> dict[str, Any]:
    """Run one allowlisted pass and return its bounded manifest summary."""
    diagnostics_root = run_dir / "diagnostics"
    existing = {
        path.resolve() for path in diagnostics_root.glob("pass-*/manifest.json")
    } if diagnostics_root.is_dir() else set()
    command = pipeline_args(
        "--authorized", "--strategy", "frida", "--resume", container_path(run_dir),
        "--diagnostic-actions", ",".join(actions),
        "--observation-seconds", str(config["observation_seconds"]),
        *target_args(config),
    )
    if config.get("package"):
        command.extend(["--package", config["package"]])
    if config.get("start_frida_server"):
        command.extend(["--start-frida-server", config["start_frida_server"]])
    exit_code, _ = command_runner(command, log, artifact=iteration_dir / "diagnostics.log")
    manifests = sorted(
        (
            path for path in diagnostics_root.glob("pass-*/manifest.json")
            if path.resolve() not in existing
        ),
        key=lambda path: path.stat().st_mtime,
    ) if diagnostics_root.is_dir() else []
    if exit_code != 0 or not manifests:
        raise EnvironmentFailure(
            f"Adaptive diagnostics failed operationally in iteration {iteration}."
        )
    manifest = manifests[-1]
    value = read_json(manifest)
    return {
        "actions": actions,
        "recipes": list(value.get("recipes") or []),
        "manifest": workspace_relative(manifest),
        "event_count": len(value.get("events") or []),
        "artifact_count": len(value.get("artifacts") or []),
        "errors": list(value.get("errors") or []),
    }
