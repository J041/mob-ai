"""Native inventory, bounded queue, and deterministic Ghidra preparation."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import time
from typing import Any
import urllib.parse
import zipfile

from pipeline.pipeline import group_native_libraries, scan_native
from ui.orchestrator_runtime import (
    GHIDRA_PREP_TIMEOUT_SECONDS, NATIVE_BATCH_SIZE, NATIVE_REPLENISHMENT_SCHEMA,
    NATIVE_SELECTION_SCHEMA, NATIVE_TOTAL_LIMIT, WORKSPACE, LoopError,
    ProviderUsageLimit, ghidra_request, normalize_android_abi, read_json,
    recorded_device_abi, run_logged, sha256, workspace_relative, write_json,
)
from ui.providers import ProviderRequest, detect_usage_limit, provider_adapter, validate_provider_output


class NativeAnalysisMixin:
    @staticmethod
    def _materialize_native_targets(
        run_dir: Path, raw_selected: list[Any], runtime_abi: str,
    ) -> list[dict[str, Any]]:
        report = read_json(run_dir / "report.json")
        groups = report.get("native_library_groups") or []
        available_groups = {
            str(item.get("library")): item
            for item in groups if isinstance(item, dict) and item.get("library")
        }
        if len(raw_selected) > NATIVE_BATCH_SIZE:
            raise LoopError(f"Native selection exceeded the {NATIVE_BATCH_SIZE}-library batch limit.")
        selected: list[dict[str, Any]] = []
        seen: set[str] = set()
        with zipfile.ZipFile(run_dir / "original.apk") as archive:
            archive_names = set(archive.namelist())

            def extract_variant(variant: dict[str, Any], library: str) -> dict[str, Any]:
                archive_path = str(variant.get("archive_path") or "")
                abi = normalize_android_abi(str(variant.get("abi") or ""))
                if archive_path not in archive_names or not abi:
                    raise LoopError(f"Native inventory variant is unavailable for {library}: {archive_path}")
                destination = run_dir / "native" / "selected" / abi / library
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(archive_path))
                if sha256(destination) != str(variant.get("sha256") or ""):
                    raise LoopError(f"Extracted native library hash mismatch: {archive_path}")
                return {
                    "archive_path": archive_path, "abi": abi, "name": library,
                    "sha256": variant.get("sha256"), "extracted": workspace_relative(destination),
                }

            for raw in raw_selected:
                if not isinstance(raw, dict):
                    raise LoopError("Native selection contained a non-object target.")
                library = str(raw.get("library") or "")
                priority = str(raw.get("priority") or "")
                reason = str(raw.get("reason") or "").strip()
                if library not in available_groups:
                    raise LoopError(f"Native selection referenced a library outside the grouped inventory: {library}")
                if library in seen or priority not in {"high", "medium", "low"} or not reason:
                    raise LoopError(f"Native selection metadata is invalid for {library}.")
                seen.add(library)
                group = available_groups[library]
                variants = [item for item in group.get("variants", []) if isinstance(item, dict)]
                by_abi = {normalize_android_abi(str(item.get("abi") or "")): item for item in variants}
                if runtime_abi and runtime_abi in by_abi:
                    primary_abi = runtime_abi
                elif len(by_abi) == 1:
                    primary_abi = next(iter(by_abi))
                else:
                    raise LoopError(
                        f"Cannot select the matching ABI for {library}; recorded device ABI is "
                        f"{runtime_abi or 'unknown'} and available variants are {', '.join(sorted(by_abi))}."
                    )
                primary = extract_variant(by_abi[primary_abi], library)
                cross_value = raw.get("cross_abi")
                cross_result: dict[str, Any] | None = None
                if cross_value is not None:
                    if not isinstance(cross_value, dict):
                        raise LoopError(f"Cross-ABI request is invalid for {library}.")
                    cross_reason = str(cross_value.get("reason") or "").strip()
                    requested = cross_value.get("abis")
                    if not cross_reason or not isinstance(requested, list) or not requested:
                        raise LoopError(f"Cross-ABI comparison requires ABIs and a reason for {library}.")
                    normalized = [normalize_android_abi(str(value)) for value in requested]
                    if len(set(normalized)) != len(normalized) or primary_abi in normalized:
                        raise LoopError(f"Cross-ABI comparison duplicates a variant for {library}.")
                    if any(abi not in by_abi for abi in normalized):
                        raise LoopError(f"Cross-ABI comparison references an unavailable variant for {library}.")
                    cross_result = {
                        "reason": cross_reason,
                        "variants": [extract_variant(by_abi[abi], library) for abi in normalized],
                    }
                selected.append({
                    "library": library, "priority": priority, "reason": reason,
                    "load_references": group.get("load_references") or [], "primary": primary,
                    **({"cross_abi": cross_result} if cross_result else {}),
                })
        return selected

    @staticmethod
    def _ensure_ghidra_programs_open(programs: list[dict[str, Any]]) -> None:
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
    def _prepare_ghidra_batch(run_dir: Path) -> dict[str, Any]:
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
            NativeAnalysisMixin._ensure_ghidra_programs_open(existing.get("programs") or [])
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
        NativeAnalysisMixin._ensure_ghidra_programs_open(programs)
        value["updated_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(manifest_path, value)
        return value

    def _replenish_native_queue(self, run_dir: Path, config: dict[str, Any], iteration: int) -> bool:
        selection_path = run_dir / "native-selection.json"
        if not selection_path.is_file():
            return False
        selection = read_json(selection_path)
        queue = selection.get("queue") or []
        if not selection.get("adaptive_queue") or len(queue) >= NATIVE_BATCH_SIZE:
            return False
        batches = selection.get("batches") or []
        seen = {
            str(name) for batch in batches if isinstance(batch, dict)
            for name in (batch.get("libraries") or []) if name
        }
        seen.update(
            str(item.get("library")) for item in queue
            if isinstance(item, dict) and item.get("library")
        )
        report = read_json(run_dir / "report.json")
        available = {
            str(item.get("library")) for item in (report.get("native_library_groups") or [])
            if isinstance(item, dict) and item.get("library")
        }
        remaining = sorted(available - seen)
        slots = min(NATIVE_BATCH_SIZE - len(queue), NATIVE_TOTAL_LIMIT - len(seen), len(remaining))
        if slots <= 0:
            return False

        replenishment_root = run_dir / "agent" / "native-selection"
        replenishment_root.mkdir(parents=True, exist_ok=True)
        number = 1
        while (replenishment_root / f"replenishment-{number}").exists():
            number += 1
        attempt_dir = replenishment_root / f"replenishment-{number}"
        attempt_dir.mkdir()
        prompt_path = attempt_dir / "prompt.txt"
        response_path = attempt_dir / "decision.json"
        provider = str(config.get("provider") or selection.get("provider") or "codex")
        adapter = provider_adapter(provider)
        prompt = f"""You are replenishing the bounded native-analysis queue in an explicitly authorized Android assessment.

Run evidence: {run_dir}
Completed iteration: {iteration}
Completed iteration record: {run_dir / 'agent' / f'iteration-{iteration}' / 'record.json'}
Native inventory and logical groups: {run_dir / 'report.json'}
Native queue and completed batch history: {selection_path}
Already selected or queued libraries (never select these again): {json.dumps(sorted(seen))}
Eligible remaining exact library names: {json.dumps(remaining)}

The active batch was inconclusive. Add at most {slots} previously unqueued logical libraries only when the completed Ghidra/runtime evidence provides a concrete reason to inspect them. Return an empty added array when no remaining library is justified. Raw strings alone are insufficient. Preserve device-ABI selection; request another ABI only through cross_abi with an explicit comparison reason, and set cross_abi to null otherwise.

Do not edit files, invoke devices, rerun tools, or claim success. Return only the required structured replenishment decision.
"""
        prompt_path.write_text(prompt, encoding="utf-8")
        request = ProviderRequest(
            provider=provider, prompt=prompt, cwd=attempt_dir,
            schema_path=NATIVE_REPLENISHMENT_SCHEMA, output_path=response_path,
            model=str(config.get("model") or selection.get("model") or ""),
            reasoning_effort=str(config.get("reasoning_effort") or ""),
            reasoning_mode="single", writable=False,
            extra_args=("--config", "mcp_servers.ghidra.enabled=false") if provider == "codex" else (),
        )
        try:
            command, provider_prompt = adapter.prepare(request)
            exit_code, output = run_logged(
                command, self.log, cwd=attempt_dir, input_text=provider_prompt,
                artifact=attempt_dir / f"{provider}.log",
            )
            limit = detect_usage_limit(output)
            if limit:
                raise ProviderUsageLimit(provider, limit)
            valid = adapter.finalize(request, exit_code, output) and validate_provider_output(
                response_path, NATIVE_REPLENISHMENT_SCHEMA,
            )
            if not valid:
                raise LoopError(f"{adapter.label} did not return a valid native queue replenishment.")
            decision = read_json(response_path)
            additions = decision.get("added") or []
            names = [str(item.get("library") or "") for item in additions if isinstance(item, dict)]
            if (
                not isinstance(additions, list) or len(additions) > slots or len(names) != len(additions)
                or len(set(names)) != len(names) or any(name not in remaining for name in names)
            ):
                raise LoopError("Native queue replenishment contained duplicate, ineligible, or excessive targets.")
        except ProviderUsageLimit:
            raise
        except (LoopError, OSError, ValueError, json.JSONDecodeError) as error:
            selection.setdefault("replenishments", []).append({
                "number": number, "iteration": iteration, "status": "error", "detail": str(error),
                "created_utc": datetime.now(timezone.utc).isoformat(),
            })
            write_json(selection_path, selection)
            return False

        selection["queue"] = queue + additions
        selection.setdefault("replenishments", []).append({
            "number": number, "iteration": iteration, "status": "added" if additions else "no_additions",
            "libraries": names, "rationale": str(decision.get("rationale") or ""),
            "evidence_used": decision.get("evidence_used") or [],
            "created_utc": datetime.now(timezone.utc).isoformat(),
        })
        write_json(selection_path, selection)
        return bool(additions)

    def _advance_native_queue(self, run_dir: Path, iteration: int, reason: str) -> bool:
        selection_path = run_dir / "native-selection.json"
        if not selection_path.is_file():
            return False
        selection = read_json(selection_path)
        batches = selection.setdefault("batches", [])
        if batches and batches[-1].get("status") == "active":
            batches[-1].update({
                "status": "inconclusive", "completed_after_iteration": iteration,
                "outcome": reason,
            })
        queue = selection.get("queue") or []
        if not queue:
            selection["selected"] = []
            selection["queue_status"] = "exhausted"
            write_json(selection_path, selection)
            return False
        raw_batch = queue[:NATIVE_BATCH_SIZE]
        selection["queue"] = queue[NATIVE_BATCH_SIZE:]
        selection["selected"] = self._materialize_native_targets(
            run_dir, raw_batch, str(selection.get("device_abi") or ""),
        )
        batches.append({
            "number": len(batches) + 1, "status": "active",
            "libraries": [item["library"] for item in selection["selected"]],
            "activated_after_iteration": iteration,
        })
        selection["queue_status"] = "active"
        write_json(selection_path, selection)
        return True

    @staticmethod
    def _resolve_native_queue(run_dir: Path, iteration: int) -> None:
        selection_path = run_dir / "native-selection.json"
        if not selection_path.is_file():
            return
        selection = read_json(selection_path)
        batches = selection.get("batches") or []
        if batches and batches[-1].get("status") == "active":
            batches[-1].update({"status": "resolved", "completed_after_iteration": iteration})
        selection["queue_status"] = "resolved"
        write_json(selection_path, selection)

    def _ensure_native_selection(self, run_dir: Path, config: dict[str, Any]) -> dict[str, Any]:
        """Ask the selected reasoning provider to choose bounded native-analysis targets."""
        selection_path = run_dir / "native-selection.json"
        if selection_path.is_file():
            value = read_json(selection_path)
            if not isinstance(value, dict) or not isinstance(value.get("selected"), list):
                raise LoopError("The recorded native selection is invalid.")
            if "queue" not in value:
                libraries = [
                    str(item.get("library") or item.get("name") or "")
                    for item in value["selected"] if isinstance(item, dict)
                ]
                value.update({
                    "queue": [], "queue_status": "active" if libraries else "exhausted",
                    "adaptive_queue": False, "replenishments": [],
                    "limits": {"batch_size": NATIVE_BATCH_SIZE, "total_libraries": NATIVE_TOTAL_LIMIT},
                    "batches": ([{"number": 1, "status": "active", "libraries": libraries}] if libraries else []),
                })
                write_json(selection_path, value)
            elif "adaptive_queue" not in value:
                value.update({"adaptive_queue": True, "replenishments": []})
                write_json(selection_path, value)
            return value

        report = read_json(run_dir / "report.json")
        if "native_libraries" not in report:
            report["findings"] = [
                item for item in report.get("findings", [])
                if not isinstance(item, dict) or item.get("kind") != "native_indicator"
            ]
            report["native_libraries"] = scan_native(run_dir / "original.apk", run_dir / "jadx")
        report["native_library_groups"] = group_native_libraries(report.get("native_libraries") or [])
        write_json(run_dir / "report.json", report)
        inventory = report.get("native_libraries") or []
        if not isinstance(inventory, list):
            raise LoopError("The native library inventory is invalid.")
        groups = report.get("native_library_groups") or []
        if not isinstance(groups, list):
            raise LoopError("The grouped native library inventory is invalid.")
        available_groups = {
            str(item.get("library")): item
            for item in groups
            if isinstance(item, dict) and item.get("library")
        }
        if not available_groups:
            value = {
                "provider": str(config.get("provider") or "codex"),
                "model": str(config.get("model") or ""),
                "rationale": "The APK contains no bounded native libraries to analyze.",
                "evidence_used": ["report.json native_libraries inventory"],
                "selected": [],
                "queue": [], "queue_status": "exhausted", "batches": [],
                "adaptive_queue": True, "replenishments": [],
                "limits": {"batch_size": NATIVE_BATCH_SIZE, "total_libraries": NATIVE_TOTAL_LIMIT},
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
        runtime_abi = recorded_device_abi(run_dir)
        prompt = f"""You are the native-target triage step in an explicitly authorized Android assessment.

Read-only assessment evidence: {run_dir}
Logical native inventory: {run_dir / 'report.json'} under the native_library_groups field
Recorded device ABI: {runtime_abi or 'unknown'}
Runtime evidence: observations.json, result.json, logs/, and any diagnostic crash records
Static evidence: JADX sources and AndroidManifest.xml below {run_dir / 'jadx'}

Rank no more than {NATIVE_TOTAL_LIMIT} logical library names that genuinely warrant Ghidra analysis. Put the highest-priority {NATIVE_BATCH_SIZE} or fewer in selected and the remaining ranked targets in queued. All ABI variants of one library are one selection slot. Base the ranking on causal evidence such as application-owned names, System.loadLibrary call sites, native/JNI declarations, protected application startup, crash context, or relationships to observed checks. Raw string matches may be supporting context but must never be the sole reason for selection. The orchestrator automatically selects the variant matching the recorded device ABI. Request other available ABIs only through cross_abi with a specific comparison reason; those variants do not consume extra library slots. Set cross_abi to null when no comparison is justified. Do not duplicate a library between selected and queued. Select only exact library values present in native_library_groups. Empty selected and queued arrays are valid when native analysis is not justified.

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
        limit = detect_usage_limit(output)
        if limit:
            raise ProviderUsageLimit(provider, limit)
        if not adapter.finalize(request, exit_code, output) or not validate_provider_output(response_path, NATIVE_SELECTION_SCHEMA):
            raise LoopError(f"{adapter.label} did not return a valid native target selection.")
        decision = read_json(response_path)
        raw_selected = decision.get("selected") or []
        raw_queue = decision.get("queued") or []
        if not isinstance(raw_selected, list) or not isinstance(raw_queue, list):
            raise LoopError("Native selection and queue must be arrays.")
        if len(raw_selected) > NATIVE_BATCH_SIZE or len(raw_selected) + len(raw_queue) > NATIVE_TOTAL_LIMIT:
            raise LoopError("Native selection exceeded the bounded batch or total queue limit.")
        if not raw_selected and raw_queue:
            raw_selected, raw_queue = raw_queue[:NATIVE_BATCH_SIZE], raw_queue[NATIVE_BATCH_SIZE:]
        ranked = raw_selected + raw_queue
        names = [str(item.get("library") or "") for item in ranked if isinstance(item, dict)]
        if len(names) != len(ranked) or len(set(names)) != len(names) or any(name not in available_groups for name in names):
            raise LoopError("Native queue contains duplicate, malformed, or unavailable logical libraries.")
        selected = self._materialize_native_targets(run_dir, raw_selected, runtime_abi)

        value = {
            "provider": provider,
            "model": str(config.get("model") or ""),
            "rationale": str(decision.get("rationale") or ""),
            "evidence_used": decision.get("evidence_used") or [],
            "selected": selected,
            "queue": raw_queue,
            "queue_status": "active" if selected else "exhausted",
            "adaptive_queue": True,
            "replenishments": [],
            "limits": {"batch_size": NATIVE_BATCH_SIZE, "total_libraries": NATIVE_TOTAL_LIMIT},
            "batches": ([{
                "number": 1, "status": "active",
                "libraries": [item["library"] for item in selected],
                "activated_before_iteration": 1,
            }] if selected else []),
            "device_abi": runtime_abi,
            "created_utc": datetime.now(timezone.utc).isoformat(),
        }
        write_json(selection_path, value)
        config["native_selection"] = workspace_relative(selection_path)
        write_json(run_dir / "codex-loop-config.json", config)
        return value

