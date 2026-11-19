"""Portable runtime-data paths and safe migration from the legacy repository layout."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # Windows hosts use Docker, but keep path inspection importable.
    fcntl = None


WORKSPACE = Path(os.environ.get("MOB_AI_WORKSPACE", "/workspace")).resolve()


def _data_root() -> Path:
    configured = Path(os.environ.get("MOB_AI_DATA_ROOT", ".mob-ai-data"))
    value = configured if configured.is_absolute() else WORKSPACE / configured
    resolved = value.resolve()
    try:
        resolved.relative_to(WORKSPACE)
    except ValueError as error:
        raise RuntimeError("MOB_AI_DATA_ROOT must resolve inside the mounted workspace.") from error
    if resolved == WORKSPACE:
        raise RuntimeError("MOB_AI_DATA_ROOT cannot be the workspace root.")
    return resolved


DATA_ROOT = _data_root()
RUNS_ROOT = DATA_ROOT / "runs"
UPLOAD_ROOT = DATA_ROOT / "uploads"
POLICY_ROOT = DATA_ROOT / "policies"
STATE_ROOT = DATA_ROOT / "state"
JOBS_ROOT = STATE_ROOT / "jobs"
WIRELESS_DEVICES_PATH = STATE_ROOT / "wireless-devices.json"
HEARTBEAT_PATH = STATE_ROOT / "worker-heartbeat"
EXPORTS_ROOT = DATA_ROOT / "exports"
TEMP_ROOT = DATA_ROOT / "temp"
MIGRATION_MANIFEST = DATA_ROOT / "migration-v1.json"


@dataclass(frozen=True)
class RuntimeLayout:
    workspace: Path
    data_root: Path

    @property
    def mappings(self) -> tuple[tuple[Path, Path], ...]:
        return (
            (self.workspace / "runs", self.data_root / "runs"),
            (self.workspace / "uploads", self.data_root / "uploads"),
            (self.workspace / "policies" / "generated", self.data_root / "policies"),
            (self.workspace / "worker" / ".state", self.data_root / "state"),
        )

    @property
    def required_directories(self) -> tuple[Path, ...]:
        return (
            self.data_root / "runs", self.data_root / "uploads",
            self.data_root / "policies", self.data_root / "state" / "jobs",
            self.data_root / "exports", self.data_root / "temp",
        )


def _is_empty(path: Path) -> bool:
    return path.is_dir() and next(path.iterdir(), None) is None


def _remove_empty(path: Path) -> None:
    if path.is_dir() and not path.is_symlink() and _is_empty(path):
        path.rmdir()


def _ensure_legacy_link(legacy: Path, target: Path) -> str:
    if legacy.is_symlink():
        if legacy.resolve() != target.resolve():
            raise RuntimeError(f"Legacy runtime link points to the wrong location: {legacy}")
        return "existing-link"
    if legacy.exists():
        raise RuntimeError(f"Legacy runtime path still contains data after migration: {legacy}")
    legacy.parent.mkdir(parents=True, exist_ok=True)
    relative = os.path.relpath(target, legacy.parent)
    try:
        legacy.symlink_to(relative, target_is_directory=True)
    except OSError as error:
        raise RuntimeError(
            f"Could not create compatibility link {legacy} -> {target}. "
            "The workspace filesystem must support symbolic links."
        ) from error
    return "created-link"


def _migrate_mapping(legacy: Path, target: Path) -> dict[str, str]:
    record = {"legacy": str(legacy), "target": str(target), "action": "none"}
    if legacy.is_symlink():
        record["action"] = _ensure_legacy_link(legacy, target)
        target.mkdir(parents=True, exist_ok=True)
        return record

    if legacy.exists() and target.exists():
        legacy_empty = _is_empty(legacy)
        target_empty = _is_empty(target)
        if not legacy_empty and not target_empty:
            raise RuntimeError(
                f"Refusing to merge two non-empty runtime locations: {legacy} and {target}."
            )
        if target_empty and not legacy_empty:
            target.rmdir()
            os.replace(legacy, target)
            record["action"] = "moved-legacy-data"
        else:
            _remove_empty(legacy)
            record["action"] = "kept-consolidated-data"
    elif legacy.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        os.replace(legacy, target)
        record["action"] = "moved-legacy-data"
    else:
        target.mkdir(parents=True, exist_ok=True)
        record["action"] = "initialized"

    link_action = _ensure_legacy_link(legacy, target)
    record["link"] = link_action
    return record


def initialize_runtime_data(
    *, workspace: Path = WORKSPACE, data_root: Path = DATA_ROOT,
    migrate_legacy: bool = True,
) -> dict[str, Any]:
    """Create the portable layout and migrate legacy paths without merging data."""
    workspace = workspace.resolve()
    data_root = data_root.resolve()
    try:
        data_root.relative_to(workspace)
    except ValueError as error:
        raise RuntimeError("Runtime data root must remain inside the workspace.") from error
    if data_root == workspace:
        raise RuntimeError("Runtime data root cannot be the workspace root.")
    data_root.mkdir(parents=True, exist_ok=True)
    lock_path = data_root / ".migration.lock"
    with lock_path.open("a+", encoding="utf-8") as lock:
        if fcntl is not None:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        layout = RuntimeLayout(workspace, data_root)
        actions = []
        if migrate_legacy:
            actions = [_migrate_mapping(legacy, target) for legacy, target in layout.mappings]
        for directory in layout.required_directories:
            directory.mkdir(parents=True, exist_ok=True)
        manifest = {
            "version": 1,
            "data_root": str(data_root),
            "updated_utc": datetime.now(timezone.utc).isoformat(),
            "actions": actions,
        }
        manifest_path = data_root / "migration-v1.json"
        temporary = manifest_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, manifest_path)
        return manifest


def runtime_summary() -> dict[str, str]:
    return {
        "root": str(DATA_ROOT), "runs": str(RUNS_ROOT), "uploads": str(UPLOAD_ROOT),
        "policies": str(POLICY_ROOT), "jobs": str(JOBS_ROOT),
        "exports": str(EXPORTS_ROOT), "temp": str(TEMP_ROOT),
    }
