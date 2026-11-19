"""Incremental, run-scoped evidence index for the read-only assistant."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import uuid
from typing import Any

from backend.artifacts import ARTIFACT_PREVIEW_SUFFIXES, artifact_manifest

try:
    import fcntl
except ImportError:  # The production services run in Linux containers.
    fcntl = None


INDEX_VERSION = 1
INDEX_TEXT_LIMIT = 180_000
INDEX_TERM_LIMIT = 4096
INDEX_TOKEN_PATTERN = re.compile(r"[a-z0-9_.-]{3,64}")
INDEX_THEME_PATTERNS = {
    "status": ("status", "success", "policy", "human_review", "human review", "failed", "ended", "stop"),
    "crash": ("crash", "sigsegv", "sigbus", "signal", "tombstone", "exit", "abort", "fault"),
    "attempt": ("attempt", "compare", "comparison", "changed", "difference", "retry", "rerun"),
    "hook": ("frida", "hook", "root", "magisk", "debugger", "bypass", "detection"),
    "native": ("ghidra", "native", "binary", ".so", "library", "symbol"),
    "plan": ("harder", "rerun", "retry", "next", "recommend", "plan", "improve"),
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def evidence_index_path(run_dir: Path) -> Path:
    return run_dir / "assistant" / "index" / "manifest.json"


def load_evidence_index(run_dir: Path) -> dict[str, Any]:
    """Load a checkpoint index without rescanning the run tree."""
    value = _read_json(evidence_index_path(run_dir.resolve()))
    entries = value.get("entries") if value.get("version") == INDEX_VERSION else None
    if not isinstance(entries, dict):
        return {}
    cached = dict(value)
    cached["stats"] = {
        "files": len(entries), "changed": 0, "reused": len(entries),
        "removed": 0, "source": "checkpoint",
    }
    return cached


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_indexable_text(path: Path, limit: int = INDEX_TEXT_LIMIT) -> str:
    with path.open("rb") as stream:
        return stream.read(limit).decode("utf-8", errors="replace")


def _safe_artifact(run_dir: Path, relative: str) -> Path | None:
    normalized = PurePosixPath(str(relative).replace("\\", "/")).as_posix().lstrip("/")
    if not normalized or ".." in PurePosixPath(normalized).parts or normalized.startswith("assistant/"):
        return None
    path = (run_dir / normalized).resolve()
    try:
        path.relative_to(run_dir.resolve())
    except ValueError:
        return None
    suffixes = ARTIFACT_PREVIEW_SUFFIXES | {".smali", ".java", ".kt"}
    if not path.is_file() or path.suffix.lower() not in suffixes:
        return None
    if normalized.endswith(("codex.log", "claude.log")):
        return None
    return path


def _entry(path: Path, relative: str, stat: os.stat_result) -> dict[str, Any]:
    content = _read_indexable_text(path)
    lowered = content.lower()
    counts = Counter(INDEX_TOKEN_PATTERN.findall(lowered))
    terms = {term: min(count, 9999) for term, count in counts.most_common(INDEX_TERM_LIMIT)}
    themes = {
        theme: sum(lowered.count(marker) for marker in markers)
        for theme, markers in INDEX_THEME_PATTERNS.items()
    }
    return {
        "path": relative,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "indexed_characters": len(content),
        "truncated": stat.st_size > INDEX_TEXT_LIMIT,
        "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        "terms": terms,
        "themes": themes,
    }


def refresh_evidence_index(run_dir: Path, allowed: set[str] | None = None) -> dict[str, Any]:
    """Refresh changed evidence entries and atomically persist the run index."""
    run_dir = run_dir.resolve()
    if allowed is None:
        try:
            allowed = set(artifact_manifest(run_dir.name)["allowed"])
        except (FileNotFoundError, ValueError):
            allowed = set()
    index_path = evidence_index_path(run_dir)
    index_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = index_path.parent / ".lock"
    with lock_path.open("a+", encoding="utf-8") as lock:
        if fcntl is not None:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        previous = _read_json(index_path)
        old_entries = previous.get("entries") if previous.get("version") == INDEX_VERSION else {}
        old_entries = old_entries if isinstance(old_entries, dict) else {}
        entries: dict[str, dict[str, Any]] = {}
        changed = 0
        reused = 0
        for relative in sorted(allowed):
            path = _safe_artifact(run_dir, relative)
            if path is None:
                continue
            stat = path.stat()
            old = old_entries.get(relative)
            if (
                isinstance(old, dict)
                and int(old.get("size", -1)) == stat.st_size
                and int(old.get("mtime_ns", -1)) == stat.st_mtime_ns
            ):
                entries[relative] = old
                reused += 1
            else:
                entries[relative] = _entry(path, relative, stat)
                changed += 1
        removed = len(set(old_entries) - set(entries))
        value = {
            "version": INDEX_VERSION,
            "updated_utc": _utc_now(),
            "run_id": run_dir.name,
            "entries": entries,
            "stats": {
                "files": len(entries), "changed": changed,
                "reused": reused, "removed": removed,
            },
        }
        _atomic_write(index_path, value)
        return value


def refresh_run_evidence_index(run_dir: Path) -> dict[str, Any]:
    """Stage-boundary entrypoint used by the durable assessment worker."""
    return refresh_evidence_index(run_dir)
