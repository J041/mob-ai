"""Deterministic Ghidra import, analysis, and MCP preparation."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import shutil
import time
from typing import Any
import urllib.parse

from assessment.runtime import (
    GHIDRA_PREP_TIMEOUT_SECONDS, WORKSPACE, LoopError, ghidra_request,
    read_json, sha256, workspace_relative, write_json,
)

@staticmethod
def ensure_ghidra_programs_open(programs: list[dict[str, Any]]) -> None:
    """Open every analyzed target through trusted orchestration before MCP reasoning."""
    targets = [
        item for item in programs
        if item.get("status") == "complete" and str(item.get("program") or "")
    ]
    if not targets:
        return

    def open_roster() -> dict[str, dict[str, Any]]:
        response = ghidra_request("GET", "/list_open_programs")
        data = response.get("data") if isinstance(response.get("data"), dict) else response
        values = data.get("programs") if isinstance(data, dict) else []
        return {
            str(item.get("name") or ""): item for item in values
            if isinstance(item, dict) and item.get("name")
        }

    roster = open_roster()
    for entry in targets:
        program = str(entry["program"])
        if program not in roster:
            ghidra_request("POST", "/open_program", {
                "path": program,
                "auto_analyze": False,
            })
    roster = open_roster()
    missing = [str(item["program"]) for item in targets if str(item["program"]) not in roster]
    if missing:
        raise LoopError(f"Ghidra did not keep prepared programs open: {', '.join(missing)}")
    for entry in targets:
        opened = roster[str(entry["program"])]
        entry.update({
            "mcp_ready": True,
            "open_path": opened.get("path"),
            "is_current": bool(opened.get("is_current")),
        })

@staticmethod
def prepare_ghidra_batch(run_dir: Path) -> dict[str, Any]:
    """Import and fully auto-analyze the active native batch before provider reasoning."""
    selection_path = run_dir / "native-selection.json"
    selection = read_json(selection_path) if selection_path.is_file() else {}
    selected = [item for item in (selection.get("selected") or []) if isinstance(item, dict)]
    batches = selection.get("batches") or []
    batch_number = int((batches[-1].get("number") if batches else 0) or 0)
    preparation_dir = run_dir / "ghidra" / "preparation"
    preparation_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = preparation_dir / f"batch-{batch_number}.json"
    variants: list[dict[str, Any]] = []
    for item in selected:
        primary = item.get("primary")
        if isinstance(primary, dict):
            variants.append(primary)
        cross = item.get("cross_abi")
        if isinstance(cross, dict):
            variants.extend(value for value in (cross.get("variants") or []) if isinstance(value, dict))
    expected = sorted(str(item.get("sha256") or "") for item in variants)
    existing = read_json(manifest_path) if manifest_path.is_file() else {}
    if existing.get("status") == "complete" and existing.get("expected_sha256") == expected:
        ensure_ghidra_programs_open(existing.get("programs") or [])
        existing["updated_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(manifest_path, existing)
        return existing
    if not variants:
        value = {
            "batch": batch_number, "status": "not_required", "expected_sha256": [],
            "programs": [], "updated_utc": datetime.now(timezone.utc).isoformat(),
        }
        write_json(manifest_path, value)
        return value

    inputs_dir = run_dir / "ghidra" / "inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)
    prior_programs = {
        str(item.get("key")): item for item in (existing.get("programs") or [])
        if isinstance(item, dict) and item.get("key") and item.get("status") != "import_error"
    }
    programs: list[dict[str, Any]] = []
    value: dict[str, Any] = {
        "batch": batch_number, "status": "preparing", "expected_sha256": expected,
        "programs": programs, "updated_utc": datetime.now(timezone.utc).isoformat(),
    }
    for variant in variants:
        digest = str(variant.get("sha256") or "")
        abi = str(variant.get("abi") or "unknown")
        name = str(variant.get("name") or Path(str(variant.get("extracted") or "native.so")).name)
        key = f"{digest[:12]}-{abi}-{name}"
        if key in prior_programs:
            programs.append(prior_programs[key])
            continue
        source = (WORKSPACE / str(variant.get("extracted") or "")).resolve()
        try:
            source.relative_to(run_dir.resolve())
        except ValueError as error:
            raise LoopError(f"Selected Ghidra input escaped its run: {source}") from error
        if not source.is_file() or sha256(source) != digest:
            raise LoopError(f"Selected Ghidra input failed hash verification: {source}")
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", key)
        isolated_input = inputs_dir / safe_name
        if not isolated_input.is_file() or sha256(isolated_input) != digest:
            shutil.copy2(source, isolated_input)
        entry: dict[str, Any] = {
            "key": key, "library": name, "abi": abi, "sha256": digest,
            "input": workspace_relative(isolated_input),
            "project_folder": f"/mob-ai/{run_dir.name}/batch-{batch_number}/{digest[:12]}-{abi}",
            "status": "importing",
        }
        programs.append(entry)
        value["updated_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(manifest_path, value)
        try:
            imported = ghidra_request("POST", "/import_file", {
                "file_path": f"/workspace/{entry['input']}",
                "project_folder": entry["project_folder"], "auto_analyze": True,
            })
            data = imported.get("data") if isinstance(imported.get("data"), dict) else imported
            entry["program"] = str(data.get("name") or isolated_input.name)
            entry["status"] = "analyzing" if data.get("analyzing", False) else "complete"
            if entry["status"] == "complete":
                entry["function_count"] = data.get("function_count")
        except LoopError as error:
            entry.update({"status": "import_error", "error": str(error)})
        write_json(manifest_path, value)

    deadline = time.monotonic() + GHIDRA_PREP_TIMEOUT_SECONDS
    pending = [item for item in programs if item.get("status") in {"importing", "analyzing", "timeout"}]
    while pending and time.monotonic() < deadline:
        for entry in list(pending):
            try:
                query = urllib.parse.urlencode({"program": entry["program"]})
                response = ghidra_request("GET", f"/analysis_status?{query}")
                data = response.get("data") if isinstance(response.get("data"), dict) else response
                if not data.get("analyzing", True):
                    entry.update({
                        "status": "complete", "function_count": data.get("function_count"),
                        "analysis_status": data,
                    })
                    pending.remove(entry)
            except LoopError as error:
                entry["last_poll_error"] = str(error)
        value["updated_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(manifest_path, value)
        if pending:
            time.sleep(2)
    for entry in pending:
        entry.update({"status": "timeout", "error": "Ghidra auto-analysis did not finish before the bounded timeout."})
    value.update({
        "status": "complete" if programs and all(item.get("status") == "complete" for item in programs) else "partial",
        "programs": programs, "updated_utc": datetime.now(timezone.utc).isoformat(),
    })
    ensure_ghidra_programs_open(programs)
    value["updated_utc"] = datetime.now(timezone.utc).isoformat()
    write_json(manifest_path, value)
    return value

