"""Run artifact catalog, preview, and download path validation."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
import re

from assessment.outcomes import terminal_outcome
from assessment.runtime import RUNS_ROOT


ARTIFACT_PREVIEW_SUFFIXES = {".json", ".jsonl", ".log", ".txt", ".js", ".md", ".toml", ".xml", ".yaml", ".yml", ".csv"}
ARTIFACT_CATEGORIES = (
    ("findings", "Findings", "Static and runtime discovery reports.", ("report.json", "adaptive-plan.json", "observations.json", "native-selection.json")),
    ("hooks", "Generated hooks", "Generated and Codex-refined Frida scripts.", ("frida/*.js", "agent/iteration-*/candidate.js")),
    ("comparisons", "Attempt comparisons", "Before/after evidence from diagnostic retries.", ("agent/diagnostic-retry-*/comparison.json",)),
    ("runtime-diagnostics", "Runtime diagnostics", "Bounded adaptive traces, executable mappings and runtime payload captures.", ("diagnostics/**/*", "agent/iteration-*/diagnostics.log")),
    ("logs", "Logcat and crash reports", "Runtime, crash-buffer, exit-info and tombstone evidence.", ("logs/*.log", "agent/**/logs/*.log", "agent/**/pipeline.log")),
    ("decisions", "Agent decisions", "Structured native triage, token usage, iteration records and provider execution logs.", ("codex-loop-result.json", "provider-usage.jsonl", "agent/native-selection/**/*", "agent/iteration-*/decision.json", "agent/iteration-*/record.json", "agent/iteration-*/codex.log", "agent/iteration-*/claude.log")),
    ("ghidra", "Ghidra results", "Selected native inputs and saved analysis results produced through Ghidra.", ("native/selected/**/*", "ghidra/**/*", "ghidra-results/**/*", "agent/**/ghidra-*")),
    ("success", "Success-policy checks", "Recorded policy, baseline and validation outcomes.", ("result.json", "codex-loop-config.json", "agent/**/result.json")),
    ("assistant", "Assistant conversation", "Run-scoped questions, cited answers and read-only agent logs.", ("assistant/**/*",)),
)


def json_file(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return None


def resolve_run_directory(run_id: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", run_id):
        raise ValueError("Invalid run identifier.")
    directory = (RUNS_ROOT / run_id).resolve()
    try:
        directory.relative_to(RUNS_ROOT.resolve())
    except ValueError as error:
        raise ValueError("Run escaped the runs directory.") from error
    if not directory.is_dir() or not (directory / "report.json").is_file():
        raise FileNotFoundError("Assessment run not found.")
    return directory


def artifact_manifest(run_id: str) -> dict:
    directory = resolve_run_directory(run_id)
    report = json_file(directory / "report.json") or {}
    summary = json_file(directory / "codex-loop-result.json") or {}
    terminal = terminal_outcome(summary)
    categories = []
    allowed: set[str] = set()
    for identifier, label, description, patterns in ARTIFACT_CATEGORIES:
        paths: set[Path] = set()
        for pattern in patterns:
            paths.update(path for path in directory.glob(pattern) if path.is_file())
        files = []
        for path in sorted(paths, key=lambda item: item.relative_to(directory).as_posix()):
            resolved = path.resolve()
            try:
                relative = resolved.relative_to(directory).as_posix()
            except ValueError:
                continue
            allowed.add(relative)
            stat = resolved.stat()
            files.append({
                "path": relative,
                "name": resolved.name,
                "size": stat.st_size,
                "updated_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                "previewable": resolved.suffix.lower() in ARTIFACT_PREVIEW_SUFFIXES,
            })
        categories.append({"id": identifier, "label": label, "description": description, "files": files})
    return {
        "run": {
            "id": run_id,
            "package": str(report.get("package") or run_id),
            "status": str(summary.get("status") or "analysis"),
            "terminal": terminal,
            "created_utc": str(report.get("created_utc") or ""),
        },
        "categories": categories,
        "allowed": allowed,
    }


def resolve_run_artifact(run_id: str, relative: str) -> Path:
    normalized = PurePosixPath(str(relative).replace("\\", "/")).as_posix().lstrip("/")
    parts = PurePosixPath(normalized).parts
    allowed = any((
        normalized in {"report.json", "adaptive-plan.json", "observations.json", "native-selection.json", "codex-loop-result.json", "provider-usage.jsonl", "result.json", "codex-loop-config.json"},
        len(parts) == 2 and parts[0] == "frida" and normalized.endswith(".js"),
        len(parts) == 3 and parts[0] == "agent" and parts[1].startswith("iteration-") and parts[2] in {"candidate.js", "decision.json", "record.json", "codex.log", "claude.log", "diagnostics.log", "result.json", "provider-mcp.json"},
        len(parts) == 3 and parts[0] == "agent" and parts[1].startswith("diagnostic-retry-") and parts[2] in {"comparison.json", "pipeline.log", "result.json"},
        bool(parts) and parts[0] == "logs" and normalized.endswith(".log"),
        len(parts) >= 3 and parts[0] == "agent" and "logs" in parts[2:] and normalized.endswith(".log"),
        len(parts) >= 3 and parts[0] == "agent" and parts[-1] in {"pipeline.log", "result.json"},
        len(parts) >= 4 and parts[0:2] == ("agent", "native-selection") and normalized.endswith((".json", ".txt", ".log")),
        bool(parts) and parts[0] in {"ghidra", "ghidra-results"},
        len(parts) >= 4 and parts[0:2] == ("native", "selected"),
        len(parts) >= 3 and parts[0] == "agent" and parts[-1].startswith("ghidra-"),
        len(parts) >= 3 and parts[0] == "diagnostics" and parts[1].startswith("pass-") and normalized.endswith((".json", ".js", ".log", ".bin")),
        len(parts) >= 2 and parts[0] == "assistant" and normalized.endswith((".json", ".jsonl", ".txt", ".log")),
    ))
    if not allowed or ".." in parts:
        raise FileNotFoundError("Artifact not found in this run's evidence manifest.")
    directory = resolve_run_directory(run_id)
    path = (directory / normalized).resolve()
    try:
        path.relative_to(directory)
    except ValueError as error:
        raise FileNotFoundError("Artifact escaped the assessment run.") from error
    if not path.is_file():
        raise FileNotFoundError("Artifact not found.")
    return path

