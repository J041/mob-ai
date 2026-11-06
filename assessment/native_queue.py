"""Adaptive bounded native-analysis queue lifecycle."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from assessment.runtime import (
    NATIVE_BATCH_SIZE, NATIVE_REPLENISHMENT_SCHEMA, NATIVE_TOTAL_LIMIT, LoopError,
    ProviderUsageLimit, read_json, run_logged, write_json,
)
from assessment.usage import record_provider_usage
from backend.providers import (
    ProviderRequest, detect_usage_limit, provider_adapter, provider_token_usage,
    validate_provider_output,
)


class NativeQueueMixin:
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
            record_provider_usage(
                run_dir, provider_token_usage(provider, output), phase="native_replenishment",
                artifact=attempt_dir / f"{provider}.log", model=str(config.get("model") or ""),
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

