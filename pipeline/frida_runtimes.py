"""Discovery and command selection for isolated Frida client runtimes."""

from __future__ import annotations

from functools import lru_cache
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


RUNTIME_ROOT = Path(os.environ.get("MOB_AI_FRIDA_RUNTIME_ROOT", "/opt/frida-runtimes"))
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){2}")


def _version(executable: str) -> str:
    try:
        result = subprocess.run(
            [executable, "--version"], text=True, capture_output=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    value = (result.stdout or result.stderr).strip()
    return value if result.returncode == 0 and VERSION_RE.fullmatch(value) else ""


@lru_cache(maxsize=1)
def installed_frida_runtimes() -> tuple[dict[str, object], ...]:
    """Return only runtimes that are actually executable in this container."""
    found: dict[str, dict[str, object]] = {}
    system = shutil.which("frida")
    if system:
        version = _version(system)
        if version:
            found[version] = {
                "version": version, "default": True, "source": "container default",
            }
    if RUNTIME_ROOT.is_dir():
        for directory in sorted(RUNTIME_ROOT.iterdir()):
            executable = directory / "bin" / "frida"
            if not executable.is_file():
                continue
            version = _version(str(executable))
            if version and version not in found:
                found[version] = {
                    "version": version, "default": False, "source": "isolated runtime",
                }
    return tuple(found.values())


def default_frida_version() -> str:
    runtimes = installed_frida_runtimes()
    default = next((item for item in runtimes if item["default"]), None)
    return str((default or (runtimes[0] if runtimes else {})).get("version") or "")


def validate_frida_version(value: str) -> str:
    version = value.strip() or default_frida_version()
    installed = {str(item["version"]) for item in installed_frida_runtimes()}
    if not installed and not version:
        return ""
    if version not in installed:
        raise ValueError(f"Frida client {version or 'unknown'} is not installed in this container.")
    return version


def frida_command(version: str, tool: str) -> list[str]:
    selected = validate_frida_version(version)
    if not selected:
        return [shutil.which(tool) or tool]
    if selected == default_frida_version():
        executable = shutil.which(tool)
    else:
        candidate = RUNTIME_ROOT / selected / "bin" / tool
        executable = str(candidate) if candidate.is_file() else None
    if not executable:
        raise ValueError(f"{tool} is unavailable in the selected Frida {selected} runtime.")
    return [executable]


def activate_frida_runtime(version: str) -> None:
    """Re-exec the pipeline in the selected venv so Python and CLI bindings agree."""
    selected = validate_frida_version(version)
    if selected == default_frida_version():
        return
    runtime = RUNTIME_ROOT / selected
    marker = os.environ.get("MOB_AI_FRIDA_RUNTIME_ACTIVE", "")
    if marker == selected:
        os.environ["PATH"] = f"{runtime / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}"
        return
    python = runtime / "bin" / "python3"
    if not python.is_file():
        raise RuntimeError(f"Frida {selected} runtime has no Python interpreter.")
    environment = os.environ.copy()
    environment["MOB_AI_FRIDA_RUNTIME_ACTIVE"] = selected
    environment["PATH"] = f"{runtime / 'bin'}{os.pathsep}{environment.get('PATH', '')}"
    os.execve(str(python), [str(python), *sys.argv], environment)
