"""Native inventory, bounded queue, and deterministic Ghidra preparation."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any
import zipfile

from pipeline.pipeline import group_native_libraries, scan_native
from assessment.usage import record_provider_usage
from assessment.runtime import (
    NATIVE_BATCH_SIZE, NATIVE_REPLENISHMENT_SCHEMA,
    NATIVE_SELECTION_SCHEMA, NATIVE_TOTAL_LIMIT, WORKSPACE, LoopError,
    ProviderUsageLimit, normalize_android_abi, read_json,
    recorded_device_abi, run_logged, sha256, workspace_relative, write_json,
)
from backend.providers import (
    ProviderRequest, detect_usage_limit, provider_adapter, provider_token_usage,
    validate_provider_output,
)
from assessment.ghidra import ensure_ghidra_programs_open, prepare_ghidra_batch
from assessment.native_inventory import NativeInventoryMixin
from assessment.native_queue import NativeQueueMixin


class NativeAnalysisMixin(NativeInventoryMixin, NativeQueueMixin):
    _ensure_ghidra_programs_open = staticmethod(ensure_ghidra_programs_open)
    _prepare_ghidra_batch = staticmethod(prepare_ghidra_batch)

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
        record_provider_usage(
            run_dir, provider_token_usage(provider, output), phase="native_selection",
            artifact=selection_dir / f"{provider}.log", model=str(config.get("model") or ""),
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

