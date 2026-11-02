"""Checkpoint recovery and evidence-preserving retry workflows."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
from typing import Any

from assessment.runtime import (
    WORKSPACE, LoopError, ProviderUsageLimit, attempt_fingerprint, container_path,
    pipeline_args, read_json, run_logged, sha256, target_args,
    workspace_relative, write_json,
)
from assessment.state import write_summary


class RecoveryMixin:
    def _recover_usage_limit(
        self, run_dir: Path, config: dict[str, Any], summary: dict[str, Any],
        records: list[Any], request: dict[str, Any],
    ) -> tuple[str, Path]:
        """Restart the interrupted provider stage from its trusted pre-provider state."""
        checkpoint = summary.get("checkpoint") or {}
        stage = str(checkpoint.get("stage") or "")
        iteration = int(checkpoint.get("iteration") or (max(
            (int(item.get("iteration") or 0) for item in records if isinstance(item, dict)), default=0,
        ) + 1))
        previous_candidate: Path | None = None
        if stage == "provider":
            failed_dir = run_dir / "agent" / f"iteration-{iteration}"
            snapshot_name = Path(str(checkpoint.get("candidate_snapshot") or "candidate.before-provider.js")).name
            snapshot = failed_dir / snapshot_name
            expected_hash = str(checkpoint.get("candidate_snapshot_sha256") or "")
            if not failed_dir.is_dir() or not snapshot.is_file() or (expected_hash and sha256(snapshot) != expected_hash):
                raise LoopError("The usage-limit checkpoint is missing its trusted candidate snapshot.")
            recovery_number = 1
            while (run_dir / "agent" / f"usage-limit-recovery-{recovery_number}").exists():
                recovery_number += 1
            recovery_dir = run_dir / "agent" / f"usage-limit-recovery-{recovery_number}"
            shutil.move(str(failed_dir), str(recovery_dir))
            previous_candidate = recovery_dir / snapshot_name
            write_json(recovery_dir / "recovery.json", {
                "stage": stage,
                "iteration": iteration,
                "previous_usage": summary.get("usage") or {},
                "resumed_utc": datetime.now(timezone.utc).isoformat(),
            })
        elif stage == "native_replenishment":
            try:
                self._replenish_native_queue(run_dir, config, iteration)
            except ProviderUsageLimit as error:
                usage = dict(error.usage)
                usage.update({
                    "provider": error.provider,
                    "auto_resume": bool(config.get("auto_resume_usage_limit")),
                })
                write_summary(
                    run_dir, "usage_limited", records,
                    usage.get("detail") or f"{error.provider} usage allowance remains exhausted.",
                    checkpoint={"stage": stage, "iteration": iteration},
                    reason="provider_usage_limit", usage=usage,
                )
                return "usage_limited", run_dir
            self._advance_native_queue(run_dir, iteration, "replenishment_recovered")
            last = max(records, key=lambda item: int(item["iteration"])) if records else None
            if last:
                previous_candidate = (WORKSPACE / str(last["candidate"])).resolve()
            iteration += 1
        elif stage != "native_selection":
            raise LoopError(f"Unsupported usage-limit checkpoint stage: {stage!r}.")

        for field in ("provider", "model", "reasoning_effort", "reasoning_mode"):
            if request.get(field):
                config[field] = request[field]
        if request.get("reasoning_mode"):
            config["specialist_count"] = int(request.get("specialist_count") or 3)
        write_json(run_dir / "codex-loop-config.json", config)
        status = self._iterations(
            run_dir, config, records, start_iteration=iteration,
            additional=int(request["max_iterations"]), previous_candidate=previous_candidate,
            previous_fingerprint=None, restart_frida=False,
        )
        return status, run_dir

    def retry_with_diagnostics(self, request: dict[str, Any]) -> tuple[str, Path]:
        """Rerun observation for any completed run while preserving its evidence."""
        run_dir, config, _summary, records = self._load_existing_run(request)
        config.pop("_target_settings_changed", None)
        write_json(run_dir / "codex-loop-config.json", config)
        last_completed_iteration = max((int(item["iteration"]) for item in records), default=0)
        archived_incomplete = self._archive_incomplete_iteration(
            run_dir, last_completed_iteration + 1, str(_summary.get("status") or "failed"),
        )
        retry_number = 1
        while (run_dir / "agent" / f"diagnostic-retry-{retry_number}").exists():
            retry_number += 1
        retry_dir = run_dir / "agent" / f"diagnostic-retry-{retry_number}"
        before_dir = retry_dir / "before"
        after_dir = retry_dir / "after"
        retry_dir.mkdir(parents=True)
        archived = {
            "result.json", "observations.json", "adaptive-plan.json", "codex-loop-result.json",
            "logs/observation-frida.log", "logs/observation-logcat.log",
            "logs/diagnostic-crash-buffer.log", "logs/diagnostic-exit-info.log",
            "logs/diagnostic-native-crashes.log", "logs/diagnostic-tombstone-access.log",
        }
        for relative in archived:
            source = run_dir / relative
            if source.is_file():
                destination = before_dir / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
        write_json(retry_dir / "request.json", {
            "retry": retry_number,
            "mode": "diagnostics",
            "previous_status": _summary.get("status") or "unknown",
            "archived_incomplete_iteration": archived_incomplete,
            "started_utc": datetime.now(timezone.utc).isoformat(),
        })
        result_path = run_dir / "result.json"
        result_path.unlink(missing_ok=True)
        command = pipeline_args(
            "--authorized", "--strategy", "frida", "--resume", container_path(run_dir),
            "--observation-mode", "only", "--diagnostics",
            "--observation-seconds", str(config["observation_seconds"]),
            "--run-seconds", str(config["run_seconds"]),
            "--success-spec", f"/workspace/{config['success_spec']}",
            *target_args(config),
        )
        frida_server = str(request.get("frida_server") or config.get("start_frida_server") or "")
        if frida_server:
            command.extend(["--start-frida-server", frida_server])
        if config.get("package"):
            command.extend(["--package", config["package"]])
        exit_code, _ = run_logged(command, self.log, artifact=retry_dir / "pipeline.log")
        if exit_code not in {0, 1} or not result_path.is_file():
            previous_result = before_dir / "result.json"
            if previous_result.is_file():
                shutil.copy2(previous_result, result_path)
            detail = "Diagnostic retry failed operationally; verify device and Frida readiness, then retry again."
            write_summary(
                run_dir, "environment_error", records, detail,
                checkpoint={"stage": "observation"}, reason="diagnostic_retry_failure",
            )
            return "environment_error", run_dir

        recovered = read_json(result_path)
        for relative in archived - {"codex-loop-result.json"}:
            source = run_dir / relative
            if source.is_file():
                destination = after_dir / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
        previous_log = (before_dir / "logs" / "observation-logcat.log").read_text(encoding="utf-8", errors="replace") if (before_dir / "logs" / "observation-logcat.log").is_file() else ""
        current_log = (run_dir / "logs" / "observation-logcat.log").read_text(encoding="utf-8", errors="replace") if (run_dir / "logs" / "observation-logcat.log").is_file() else ""
        signal_pattern = re.compile(r"SIG[A-Z]+|BUS_[A-Z]+", re.I)
        write_json(retry_dir / "comparison.json", {
            "retry": retry_number,
            "previous_signals": sorted(set(signal_pattern.findall(previous_log))),
            "current_signals": sorted(set(signal_pattern.findall(current_log))),
            "same_success_result": bool((_summary.get("status") in {"success", "success_without_bypass"}) == bool(recovered.get("success"))),
            "diagnostic_files": (read_json(run_dir / "observations.json").get("diagnostics") or {}) if (run_dir / "observations.json").is_file() else {},
        })

        resumed_config = dict(config)
        resumed_config["start_frida_server"] = frida_server
        resumed_config["package"] = str(recovered.get("package") or resumed_config.get("package") or "")
        resumed_config["baseline"] = {"passed": bool(recovered.get("success")), "checks": recovered.get("checks") or []}
        history = list(resumed_config.get("diagnostic_retry_history") or [])
        history.append({"retry": retry_number, "directory": workspace_relative(retry_dir), "completed_utc": datetime.now(timezone.utc).isoformat()})
        resumed_config["diagnostic_retry_history"] = history
        for field in ("provider", "model", "reasoning_effort", "reasoning_mode"):
            if request.get(field):
                resumed_config[field] = request[field]
        if request.get("reasoning_mode"):
            resumed_config["specialist_count"] = int(request.get("specialist_count") or 3)
        write_json(run_dir / "codex-loop-config.json", resumed_config)
        if recovered.get("success"):
            write_summary(run_dir, "success_without_bypass", records, f"Diagnostic retry {retry_number} satisfied the recorded success policy.")
            return "success_without_bypass", run_dir
        last_iteration = max((int(item["iteration"]) for item in records), default=0)
        previous_candidate = run_dir / "agent" / f"iteration-{last_iteration}" / "candidate.js"
        if not previous_candidate.is_file():
            previous_candidate = None
        return self._iterations(
            run_dir, resumed_config, records, start_iteration=last_iteration + 1,
            additional=int(request["max_iterations"]), previous_candidate=previous_candidate,
            previous_fingerprint=None, restart_frida=False,
        ), run_dir

    @staticmethod
    def _archive_incomplete_iteration(run_dir: Path, iteration: int, reason: str) -> str:
        source = run_dir / "agent" / f"iteration-{iteration}"
        if not source.is_dir() or (source / "record.json").is_file():
            return ""
        archive_root = run_dir / "agent" / "incomplete-iterations"
        archive_root.mkdir(exist_ok=True)
        safe_reason = re.sub(r"[^a-z0-9_-]+", "-", reason.lower()).strip("-") or "failed"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        destination = archive_root / f"iteration-{iteration}-{safe_reason}-{stamp}"
        counter = 2
        while destination.exists():
            destination = archive_root / f"iteration-{iteration}-{safe_reason}-{stamp}-{counter}"
            counter += 1
        shutil.move(str(source), destination)
        return workspace_relative(destination)

    def _recover_observation(
        self, run_dir: Path, config: dict[str, Any], records: list[Any], frida_server: str, *,
        additional: int, provider: str, model: str, reasoning_effort: str,
        reasoning_mode: str, specialist_count: int,
    ) -> tuple[str, Path]:
        recovery_number = 1
        while (run_dir / "agent" / f"checkpoint-recovery-{recovery_number}").exists():
            recovery_number += 1
        recovery_dir = run_dir / "agent" / f"checkpoint-recovery-{recovery_number}"
        recovery_dir.mkdir(parents=True)
        archived = {
            "result.json", "observations.json", "adaptive-plan.json",
            "logs/observation-frida.log", "logs/observation-logcat.log",
        }
        for relative in archived:
            source = run_dir / relative
            if source.is_file():
                destination = recovery_dir / "before" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
        write_json(recovery_dir / "request.json", {
            "recovery": recovery_number,
            "previous_frida_server": config.get("start_frida_server") or "",
            "frida_server": frida_server,
            "started_utc": datetime.now(timezone.utc).isoformat(),
        })
        result_path = run_dir / "result.json"
        result_path.unlink(missing_ok=True)
        command = pipeline_args(
            "--authorized", "--strategy", "frida", "--resume", container_path(run_dir),
            "--observation-mode", "only", "--observation-seconds", str(config["observation_seconds"]),
            "--run-seconds", str(config["run_seconds"]), "--success-spec", f"/workspace/{config['success_spec']}",
            *target_args(config),
        )
        if frida_server:
            command.extend(["--start-frida-server", frida_server])
        if config.get("package"):
            command.extend(["--package", config["package"]])
        exit_code, _ = run_logged(command, self.log, artifact=recovery_dir / "pipeline.log")
        if exit_code not in {0, 1} or not result_path.is_file():
            archived_result = recovery_dir / "before" / "result.json"
            if archived_result.is_file():
                shutil.copy2(archived_result, result_path)
            detail = "Observation checkpoint recovery failed; verify ADB and Frida readiness, then retry this checkpoint."
            write_summary(
                run_dir, "environment_error", records, detail,
                checkpoint={"stage": "observation"}, reason="observation_recovery_failure",
            )
            return "environment_error", run_dir
        recovered = read_json(result_path)
        shutil.copy2(result_path, recovery_dir / "result.json")
        resumed_config = dict(config)
        resumed_config["start_frida_server"] = frida_server
        resumed_config["package"] = str(recovered.get("package") or resumed_config.get("package") or "")
        resumed_config["baseline"] = {
            "passed": bool(recovered.get("success")),
            "checks": recovered.get("checks") or [],
        }
        history = list(resumed_config.get("frida_server_history") or [])
        history.append({
            "recovery": recovery_number,
            "previous": config.get("start_frida_server") or "",
            "current": frida_server,
            "updated_utc": datetime.now(timezone.utc).isoformat(),
        })
        resumed_config["frida_server_history"] = history
        if provider:
            resumed_config["provider"] = provider
        if model:
            resumed_config["model"] = model
        if reasoning_effort:
            resumed_config["reasoning_effort"] = reasoning_effort
        if reasoning_mode:
            resumed_config["reasoning_mode"] = reasoning_mode
            resumed_config["specialist_count"] = specialist_count
        write_json(run_dir / "codex-loop-config.json", resumed_config)
        if recovered.get("success"):
            write_summary(
                run_dir, "success_without_bypass", records,
                f"Frida recovery {recovery_number} restored observation and the baseline satisfied the success policy.",
            )
            return "success_without_bypass", run_dir
        last_iteration = max((int(item["iteration"]) for item in records), default=0)
        previous_candidate = run_dir / "agent" / f"iteration-{last_iteration}" / "candidate.js"
        if not previous_candidate.is_file():
            previous_candidate = None
        status = self._iterations(
            run_dir, resumed_config, records, start_iteration=last_iteration + 1,
            additional=additional, previous_candidate=previous_candidate,
            previous_fingerprint=None, restart_frida=False,
        )
        return status, run_dir

    def _recover_validation(
        self, run_dir: Path, config: dict[str, Any], records: list[Any], checkpoint: dict[str, Any], *,
        additional: int, provider: str, model: str, reasoning_effort: str,
        reasoning_mode: str, specialist_count: int,
    ) -> tuple[str, Path]:
        iteration = int(checkpoint.get("iteration") or 0)
        candidate_value = str(checkpoint.get("candidate") or "")
        candidate = (WORKSPACE / candidate_value).resolve()
        try:
            candidate.relative_to(run_dir)
        except ValueError as error:
            raise LoopError("The validation checkpoint candidate escaped the run directory.") from error
        iteration_dir = run_dir / "agent" / f"iteration-{iteration}"
        decision_path = iteration_dir / "decision.json"
        if not candidate.is_file() or not decision_path.is_file():
            raise LoopError("The validation checkpoint is missing its candidate or Codex decision.")
        recovery_number = 1
        while (run_dir / "agent" / f"checkpoint-recovery-{recovery_number}").exists():
            recovery_number += 1
        recovery_dir = run_dir / "agent" / f"checkpoint-recovery-{recovery_number}"
        recovery_dir.mkdir(parents=True)
        result_path = run_dir / "result.json"
        command = pipeline_args(
            "--authorized", "--strategy", "frida", "--resume", container_path(run_dir),
            "--observation-mode", "off", "--candidate-script", container_path(candidate),
            "--run-seconds", str(config["run_seconds"]), "--success-spec", f"/workspace/{config['success_spec']}",
            *target_args(config),
        )
        if config.get("package"):
            command.extend(["--package", config["package"]])
        if config.get("start_frida_server"):
            command.extend(["--start-frida-server", config["start_frida_server"]])
        result_path.unlink(missing_ok=True)
        exit_code, _ = run_logged(command, self.log, artifact=recovery_dir / "pipeline.log")
        if exit_code not in {0, 1} or not result_path.is_file():
            write_summary(
                run_dir, "environment_error", records,
                f"Validation checkpoint recovery failed operationally in iteration {iteration}.",
                checkpoint={
                    "stage": "validation", "iteration": iteration,
                    "candidate": workspace_relative(candidate),
                },
                reason="validation_recovery_failure",
            )
            return "environment_error", run_dir
        validation = read_json(result_path)
        shutil.copy2(result_path, recovery_dir / "validation.json")
        shutil.copy2(result_path, iteration_dir / "validation.json")
        decision = read_json(decision_path)
        candidate_hash = sha256(candidate)
        record = {
            "iteration": iteration, "candidate": workspace_relative(candidate),
            "candidate_sha256": candidate_hash, "codex": decision,
            "pipeline_exit_code": exit_code, "validation": validation,
            "recovered_by": workspace_relative(recovery_dir),
        }
        records.append(record)
        write_json(iteration_dir / "record.json", record)
        if validation.get("success"):
            self._resolve_native_queue(run_dir, iteration)
            write_summary(run_dir, "success", records, f"Success policy passed after recovering validation in iteration {iteration}.")
            return "success", run_dir
        try:
            self._replenish_native_queue(run_dir, config, iteration)
        except ProviderUsageLimit as error:
            usage = dict(error.usage)
            usage.update({
                "provider": error.provider,
                "auto_resume": bool(config.get("auto_resume_usage_limit")),
            })
            write_summary(
                run_dir, "usage_limited", records,
                usage.get("detail") or f"{error.provider} usage allowance exhausted during native queue replenishment.",
                checkpoint={"stage": "native_replenishment", "iteration": iteration},
                reason="provider_usage_limit", usage=usage,
            )
            return "usage_limited", run_dir
        advanced_native = self._advance_native_queue(run_dir, iteration, "recovered_validation_failed")
        if decision.get("decision") == "no_change" and not advanced_native:
            write_summary(
                run_dir, "assessment_failed", records,
                "Validation completed, but the policy remained unsatisfied and Codex proposed no justified change.",
                reason="no_justified_change",
            )
            return "assessment_failed", run_dir
        resumed_config = dict(config)
        if provider:
            resumed_config["provider"] = provider
        if model:
            resumed_config["model"] = model
        if reasoning_effort:
            resumed_config["reasoning_effort"] = reasoning_effort
        if reasoning_mode:
            resumed_config["reasoning_mode"] = reasoning_mode
            resumed_config["specialist_count"] = specialist_count
        status = self._iterations(
            run_dir, resumed_config, records, start_iteration=iteration + 1,
            additional=additional, previous_candidate=candidate,
            previous_fingerprint=(None if advanced_native else attempt_fingerprint(candidate_hash, validation)),
            restart_frida=False,
        )
        return status, run_dir

