"""Shared construction and lifecycle management for Frida CLI sessions."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
import time
from typing import Callable

try:
    from pipeline.frida_runtimes import frida_command
except ModuleNotFoundError:  # Direct execution from /workspace/pipeline.
    from frida_runtimes import frida_command  # type: ignore


FRIDA_SHUTDOWN_GRACE_SECONDS = 10
LOCAL_FRIDA_ENDPOINT = "127.0.0.1:27042"
FRIDA_SERVER_PATH_RE = re.compile(r"/[A-Za-z0-9_./-]+")


class FridaSessionError(RuntimeError):
    """The selected Frida transport could not be prepared or executed."""


@dataclass(frozen=True)
class CommandOutcome:
    returncode: int
    output: str = ""
    timed_out: bool = False


AdbRunner = Callable[[list[str], str, bool], CommandOutcome]
HostRunner = Callable[[list[str], str, int | None, Path | None], CommandOutcome]


def timeout_output(error: subprocess.TimeoutExpired) -> str:
    output = error.stdout or b""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return str(output)


@dataclass
class FridaSessionRunner:
    """Own the common ADB transport, server readiness, and Frida CLI contract."""

    target: str
    endpoint: str
    version: str
    server_path: str
    adb_runner: AdbRunner
    host_runner: HostRunner
    sleep: Callable[[float], None] = time.sleep

    def __post_init__(self) -> None:
        if self.server_path and not FRIDA_SERVER_PATH_RE.fullmatch(self.server_path):
            raise FridaSessionError("Frida Server path must be a simple absolute device path.")

    def _adb(self, command: list[str], stage: str, *, check: bool = True) -> CommandOutcome:
        result = self.adb_runner(command, stage, check)
        if check and result.returncode:
            detail = result.output.strip().splitlines()[-1] if result.output.strip() else f"exit code {result.returncode}"
            raise FridaSessionError(f"{stage.replace('_', ' ').title()} failed: {detail}")
        return result

    def _host(
        self, command: list[str], stage: str, *, timeout: int | None = None,
        artifact: Path | None = None,
    ) -> CommandOutcome:
        try:
            return self.host_runner(command, stage, timeout, artifact)
        except subprocess.TimeoutExpired as error:
            output = timeout_output(error)
            if artifact is not None:
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_text(output, encoding="utf-8", errors="replace")
            return CommandOutcome(returncode=124, output=output, timed_out=True)

    def check_device(self) -> None:
        """Require the recorded target to be the exact online ADB device."""
        state = self._adb(["get-state"], "device_state", check=False)
        if state.returncode or state.output.strip() != "device":
            raise FridaSessionError(f"Recorded device {self.target} is not in the ADB device state.")

    def prepare(self, *, check_device: bool = True) -> None:
        """Verify the transport, establish forwarding, and ensure the server is reachable."""
        if check_device:
            self.check_device()

        if self.endpoint == LOCAL_FRIDA_ENDPOINT:
            self._adb(["forward", "tcp:27042", "tcp:27042"], "frida_forward")

        probe = self._probe()
        if probe.returncode == 0:
            return
        if not self.server_path:
            raise FridaSessionError(
                f"Frida Server is unreachable at {self.endpoint} and no server path was supplied."
            )

        executable = self._adb(
            ["shell", "su", "-c", f"test -x {self.server_path}"],
            "frida_server_check", check=False,
        )
        if executable.returncode:
            raise FridaSessionError(
                f"Frida Server is missing or not executable at {self.server_path}."
            )
        self._adb(
            ["shell", "su", "-c", f"{self.server_path} -D"],
            "frida_server_start",
        )
        self.sleep(2)
        probe = self._probe()
        if probe.returncode:
            raise FridaSessionError(
                f"Frida Server started from {self.server_path} but is not reachable at {self.endpoint}."
            )

    def _probe(self) -> CommandOutcome:
        command = [*frida_command(self.version, "frida-ps"), "-H", self.endpoint]
        return self._host(command, "frida_probe", timeout=15)

    def command(self, package: str, script: Path, duration_seconds: int | None) -> list[str]:
        """Build the one canonical non-interactive spawn command used by every session."""
        duration = "inf" if duration_seconds is None else str(duration_seconds)
        return [
            *frida_command(self.version, "frida"),
            "-H", self.endpoint, "-f", package, "-l", str(script),
            "-q", "-t", duration, "--exit-on-error",
        ]

    def run_script(
        self, package: str, script: Path, *, duration_seconds: int | None,
        artifact: Path, stage: str,
    ) -> CommandOutcome:
        timeout = None if duration_seconds is None else duration_seconds + FRIDA_SHUTDOWN_GRACE_SECONDS
        return self._host(
            self.command(package, script, duration_seconds), stage,
            timeout=timeout, artifact=artifact,
        )
