from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import re
import shutil
from typing import Any, TextIO
import zipfile

from pipeline.diagnostic_recipes import (
    DIAGNOSTIC_ACTIONS, DIAGNOSTIC_MAX_ACTIONS_PER_PASS, DIAGNOSTIC_MAX_ROUNDS,
)
from assessment.control_points import validate_control_point_decision
from assessment.diagnostics import run_adaptive_diagnostics
from assessment.native import NativeAnalysisMixin
from assessment.outcomes import terminal_outcome
from assessment.prompting import build_iteration_prompt
from assessment.recovery import RecoveryMixin
from assessment.state import (
    checkpoint_recovery_available, frida_recovery_available,
    pause_recovery_available, usage_limit_recovery_available, write_summary,
)
from assessment.runtime import (
    DECISION_SCHEMA, RUNS_ROOT, WORKSPACE, EnvironmentFailure, JobPaused, LoopError, ProviderUsageLimit,
    adb_transport_detail, attempt_fingerprint, claude_mcp_config, codex_config, codex_config_overrides,
    codex_multi_agent_args, codex_reasoning_args, container_path, control_checkpoint,
    pipeline_args, read_json, run_logged, sha256, target_args,
    set_control_run_dir, validate_decision_schema_registry, workspace_relative, write_json,
)
from assessment.usage import record_provider_usage
from backend.providers import (
    ProviderRequest, detect_usage_limit, provider_adapter, provider_token_usage,
    validate_provider_output,
)


class LoopRunner(RecoveryMixin, NativeAnalysisMixin):
    def __init__(self, log: TextIO):
        self.log = log

    def new(self, request: dict[str, Any]) -> tuple[str, Path]:
        apk = Path(request["apk"]).resolve()
        success_spec = Path(request["success_spec"]).resolve()
        config: dict[str, Any] = {
            "version": 1,
            "apk": workspace_relative(apk),
            "apk_sha256": sha256(apk),
            "success_spec": workspace_relative(success_spec),
            "success_spec_sha256": sha256(success_spec),
            "transport": request["transport"],
            "target": request["target"],
            "package": request.get("package") or "",
            "observation_seconds": int(request["observation_seconds"]),
            "run_seconds": int(request["run_seconds"]),
            "start_frida_server": request.get("frida_server") or "",
            "frida_version": request.get("frida_version") or "",
            "model": request.get("model") or "",
            "provider": request.get("provider") or "codex",
            "reasoning_effort": request.get("reasoning_effort") or "",
            "reasoning_mode": request.get("reasoning_mode") or "single",
            "specialist_count": int(request.get("specialist_count") or 3),
            "auto_resume_usage_limit": bool(request.get("auto_resume_usage_limit")),
            "derived_from_run": str(request.get("derived_from_run") or ""),
            "derived_from_policy_sha256": str(request.get("derived_from_policy_sha256") or ""),
        }
        command = pipeline_args(
            container_path(apk), "--authorized", "--strategy", "frida",
            "--observation-mode", "only", "--observation-seconds", str(config["observation_seconds"]),
            "--run-seconds", str(config["run_seconds"]), "--success-spec", container_path(success_spec),
            *target_args(config),
        )
        if config["derived_from_run"]:
            source_run = (RUNS_ROOT / config["derived_from_run"]).resolve()
            try:
                source_run.relative_to(RUNS_ROOT.resolve())
            except ValueError as error:
                raise LoopError("Reassessment source escaped the runs directory.") from error
            source_apk = source_run / "original.apk"
            if not source_run.is_dir() or not source_apk.is_file() or sha256(source_apk) != config["apk_sha256"]:
                raise LoopError("Reassessment source does not contain the same APK.")
            command.extend(["--reuse-static", container_path(source_run)])
        if request.get("install"):
            command.append("--install")
        if config["start_frida_server"]:
            command.extend(["--start-frida-server", config["start_frida_server"]])
        if config["package"]:
            command.extend(["--package", config["package"]])
        exit_code, output = run_logged(command, self.log, stage="observation")
        match = re.search(r"Run directory:\s+(?P<path>/workspace/\S+)", output)
        if not match:
            raise EnvironmentFailure("The observation phase failed before creating a run checkpoint.")
        run_dir = (WORKSPACE / match.group("path").removeprefix("/workspace/")).resolve()
        set_control_run_dir(run_dir)
        config["created_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(run_dir / "codex-loop-config.json", config)
        (run_dir / "agent").mkdir(exist_ok=True)
        result_path = run_dir / "result.json"
        if exit_code not in {0, 1} or not result_path.is_file():
            detail, transport_reason = adb_transport_detail(
                output, f"Device observation failed operationally with exit code {exit_code}.",
            )
            write_summary(
                run_dir, "environment_error", [], detail,
                checkpoint={"stage": "observation"},
                reason=transport_reason or "observation_operational_failure",
            )
            return "environment_error", run_dir
        result = read_json(result_path)
        config["package"] = str(result.get("package") or config["package"])
        config["baseline"] = {
            "passed": bool(result.get("success")),
            "checks": result.get("checks") or [],
        }
        write_json(run_dir / "codex-loop-config.json", config)
        if result.get("success"):
            write_summary(run_dir, "success_without_bypass", [], "The observation run already satisfied the success policy.")
            return "success_without_bypass", run_dir
        self._pause_boundary(run_dir, [], 1, "observation")
        status = self._iterations(
            run_dir, config, [], start_iteration=1,
            additional=int(request["max_iterations"]), previous_candidate=None,
            previous_fingerprint=None, restart_frida=False,
        )
        return status, run_dir

    def _load_existing_run(self, request: dict[str, Any]) -> tuple[Path, dict[str, Any], dict[str, Any], list[Any]]:
        run_dir = Path(request["run"]).resolve()
        set_control_run_dir(run_dir)
        try:
            run_dir.relative_to(RUNS_ROOT.resolve())
        except ValueError as error:
            raise LoopError(f"Resume target must be inside {RUNS_ROOT}.") from error
        required = [
            run_dir / "agent", run_dir / "codex-loop-config.json", run_dir / "codex-loop-result.json",
            run_dir / "report.json", run_dir / "original.apk",
        ]
        missing = [str(path) for path in required if not path.exists()]
        if missing:
            raise LoopError(f"Cannot resume; required artifact is missing: {missing[0]}")
        config = read_json(run_dir / "codex-loop-config.json")
        requested_policy_hash = str(request.get("success_spec_sha256") or "")
        if requested_policy_hash and requested_policy_hash != str(config.get("success_spec_sha256") or ""):
            raise LoopError("The selected success policy does not match this assessment run.")
        summary = read_json(run_dir / "codex-loop-result.json")
        if config.get("version") != 1:
            raise LoopError("Unsupported loop configuration version.")
        if sha256(run_dir / "original.apk") != config["apk_sha256"]:
            raise LoopError("original.apk no longer matches the recorded APK hash.")
        spec = (WORKSPACE / config["success_spec"]).resolve()
        if not spec.is_file() or sha256(spec) != config["success_spec_sha256"]:
            raise LoopError("The recorded success policy is missing or has changed.")
        requested_target = str(request.get("target") or config.get("target") or "")
        requested_transport = str(request.get("transport") or config.get("transport") or "adb")
        requested_frida = str(request.get("frida_server") or config.get("start_frida_server") or "")
        requested_frida_version = str(request.get("frida_version") or config.get("frida_version") or "")
        settings_changed = any((
            requested_target != str(config.get("target") or ""),
            requested_transport != str(config.get("transport") or "adb"),
            requested_frida != str(config.get("start_frida_server") or ""),
            requested_frida_version != str(config.get("frida_version") or ""),
        ))
        if settings_changed:
            history = list(config.get("target_history") or [])
            history.append({
                "target": config.get("target") or "", "transport": config.get("transport") or "adb",
                "frida_server": config.get("start_frida_server") or "",
                "frida_version": config.get("frida_version") or "",
                "replaced_utc": datetime.now(timezone.utc).isoformat(),
            })
            config.update({
                "target": requested_target, "transport": requested_transport,
                "start_frida_server": requested_frida, "frida_version": requested_frida_version,
                "target_history": history,
                "_target_settings_changed": True,
            })
        records = list(summary.get("iterations") or [])
        return run_dir, config, summary, records

    def resume(self, request: dict[str, Any]) -> tuple[str, Path]:
        run_dir, config, summary, records = self._load_existing_run(request)
        config["auto_resume_usage_limit"] = bool(
            request.get("auto_resume_usage_limit", config.get("auto_resume_usage_limit", False))
        )
        target_settings_changed = bool(config.pop("_target_settings_changed", False))
        if target_settings_changed:
            write_json(run_dir / "codex-loop-config.json", config)
            return self._recover_observation(
                run_dir, config, records, str(config.get("start_frida_server") or ""),
                additional=int(request["max_iterations"]),
                provider=str(request.get("provider") or ""),
                model=str(request.get("model") or ""),
                reasoning_effort=str(request.get("reasoning_effort") or ""),
                reasoning_mode=str(request.get("reasoning_mode") or ""),
                specialist_count=int(request.get("specialist_count") or 3),
            )
        if checkpoint_recovery_available(summary):
            resumed_frida = str(request.get("frida_server") or config.get("start_frida_server") or "")
            checkpoint = summary.get("checkpoint") or {}
            if checkpoint.get("stage") == "observation":
                return self._recover_observation(
                    run_dir, config, records, resumed_frida,
                    additional=int(request["max_iterations"]),
                    provider=str(request.get("provider") or ""),
                    model=str(request.get("model") or ""),
                    reasoning_effort=str(request.get("reasoning_effort") or ""),
                    reasoning_mode=str(request.get("reasoning_mode") or ""),
                    specialist_count=int(request.get("specialist_count") or 3),
                )
            if checkpoint.get("stage") == "adaptive_diagnostics":
                return self._recover_adaptive_diagnostics(
                    run_dir, config, records, checkpoint,
                    additional=int(request["max_iterations"]),
                    provider=str(request.get("provider") or ""),
                    model=str(request.get("model") or ""),
                    reasoning_effort=str(request.get("reasoning_effort") or ""),
                    reasoning_mode=str(request.get("reasoning_mode") or ""),
                    specialist_count=int(request.get("specialist_count") or 3),
                )
            return self._recover_validation(
                run_dir, config, records, checkpoint,
                additional=int(request["max_iterations"]),
                provider=str(request.get("provider") or ""),
                model=str(request.get("model") or ""),
                reasoning_effort=str(request.get("reasoning_effort") or ""),
                reasoning_mode=str(request.get("reasoning_mode") or ""),
                specialist_count=int(request.get("specialist_count") or 3),
            )
        if usage_limit_recovery_available(summary):
            return self._recover_usage_limit(run_dir, config, summary, records, request)
        if pause_recovery_available(summary):
            next_iteration = int((summary.get("checkpoint") or {}).get("next_iteration") or 1)
            resumed_config = dict(config)
            for field in ("provider", "model", "reasoning_effort", "reasoning_mode"):
                if request.get(field):
                    resumed_config[field] = request[field]
            if request.get("reasoning_mode"):
                resumed_config["specialist_count"] = int(request.get("specialist_count") or 3)
            write_json(run_dir / "codex-loop-config.json", resumed_config)
            previous_candidate = None
            previous_fingerprint = None
            if records:
                last = max(records, key=lambda item: int(item["iteration"]))
                candidate_value = str(last.get("candidate") or "")
                if not candidate_value:
                    raise LoopError("The paused checkpoint has no validated candidate to continue.")
                previous_candidate = (WORKSPACE / candidate_value).resolve()
                if not previous_candidate.is_file() or sha256(previous_candidate) != last.get("candidate_sha256"):
                    raise LoopError("The paused checkpoint candidate is missing or changed.")
                if last.get("validation") is not None:
                    previous_fingerprint = attempt_fingerprint(last["candidate_sha256"], last["validation"])
                next_iteration = max(next_iteration, int(last["iteration"]) + 1)
            return self._iterations(
                run_dir, resumed_config, records, start_iteration=next_iteration,
                additional=int(request["max_iterations"]), previous_candidate=previous_candidate,
                previous_fingerprint=previous_fingerprint,
                restart_frida=bool(resumed_config.get("start_frida_server")),
            ), run_dir
        if summary.get("status") == "human_review" and frida_recovery_available(summary):
            frida_server = str(request.get("frida_server") or "")
            if not frida_server:
                raise LoopError("A device-side Frida Server path is required for this recovery.")
            return self._recover_observation(
                run_dir, config, records, frida_server,
                additional=int(request["max_iterations"]),
                provider=str(request.get("provider") or ""),
                model=str(request.get("model") or ""),
                reasoning_effort=str(request.get("reasoning_effort") or ""),
                reasoning_mode=str(request.get("reasoning_mode") or ""),
                specialist_count=int(request.get("specialist_count") or 3),
            )
        if not records:
            raise LoopError("The prior run has no completed iteration records.")
        if summary.get("status") != "max_iterations":
            raise LoopError(f"Only max_iterations or recoverable Frida runs can continue; this run ended with {summary.get('status')!r}.")
        last = max(records, key=lambda item: int(item["iteration"]))
        previous_candidate = (WORKSPACE / last["candidate"]).resolve()
        try:
            previous_candidate.relative_to(run_dir)
        except ValueError as error:
            raise LoopError("The recorded candidate is outside the run directory.") from error
        if not previous_candidate.is_file() or sha256(previous_candidate) != last["candidate_sha256"]:
            raise LoopError("The last candidate is missing or changed after validation.")
        prior_fingerprint = attempt_fingerprint(last["candidate_sha256"], last["validation"])
        start = int(last["iteration"]) + 1
        resumed_config = dict(config)
        if request.get("model"):
            resumed_config["model"] = request["model"]
        if request.get("provider"):
            resumed_config["provider"] = request["provider"]
        if request.get("reasoning_effort"):
            resumed_config["reasoning_effort"] = request["reasoning_effort"]
        if request.get("reasoning_mode"):
            resumed_config["reasoning_mode"] = request["reasoning_mode"]
            resumed_config["specialist_count"] = int(request.get("specialist_count") or 3)
        status = self._iterations(
            run_dir, resumed_config, records, start_iteration=start,
            additional=int(request["max_iterations"]), previous_candidate=previous_candidate,
            previous_fingerprint=prior_fingerprint, restart_frida=bool(config.get("start_frida_server")),
        )
        return status, run_dir

    def _iterations(
        self, run_dir: Path, config: dict[str, Any], records: list[Any], *, start_iteration: int,
        additional: int, previous_candidate: Path | None, previous_fingerprint: str | None,
        restart_frida: bool,
    ) -> str:
        validate_decision_schema_registry()
        agent_dir = run_dir / "agent"
        control_checkpoint("native_selection", run_dir, allow_pause=False)
        try:
            self._ensure_native_selection(run_dir, config)
        except ProviderUsageLimit as error:
            usage = dict(error.usage)
            usage.update({
                "provider": error.provider,
                "auto_resume": bool(config.get("auto_resume_usage_limit")),
            })
            write_summary(
                run_dir, "usage_limited", records,
                usage.get("detail") or f"{error.provider} usage allowance exhausted during native selection.",
                checkpoint={"stage": "native_selection", "iteration": start_iteration},
                reason="provider_usage_limit", usage=usage,
            )
            return "usage_limited"
        except (LoopError, OSError, zipfile.BadZipFile, json.JSONDecodeError) as error:
            write_summary(
                run_dir, "provider_error", records,
                f"Native target selection failed before iteration {start_iteration}: {error}",
                reason="native_selection_failure",
            )
            return "provider_error"
        self._pause_boundary(run_dir, records, start_iteration, "native_selection")
        end_iteration = start_iteration + additional - 1
        for iteration in range(start_iteration, end_iteration + 1):
            iteration_dir = agent_dir / f"iteration-{iteration}"
            if iteration_dir.exists():
                raise LoopError(f"Refusing to overwrite {iteration_dir}.")
            iteration_dir.mkdir(parents=True)
            codex_dir = iteration_dir / ".codex"
            codex_dir.mkdir()
            config_path = codex_dir / "config.toml"
            config_path.write_text(codex_config(), encoding="utf-8")
            provider = str(config.get("provider") or "codex")
            adapter = provider_adapter(provider)
            mcp_path = iteration_dir / "provider-mcp.json"
            if provider == "claude":
                write_json(mcp_path, claude_mcp_config())
            candidate = iteration_dir / "candidate.js"
            if previous_candidate:
                shutil.copy2(previous_candidate, candidate)
            else:
                shutil.copy2(run_dir / "frida" / "bypass-level-1.js", candidate)
            provider_cwd = iteration_dir
            working_candidate = candidate
            prior_dir = agent_dir / f"iteration-{iteration - 1}" if iteration > 1 else None
            self.log.write(f"Preparing Ghidra native batch before iteration {iteration}...\n")
            self.log.flush()
            control_checkpoint(f"ghidra_preparation_iteration_{iteration}", run_dir, allow_pause=False)
            try:
                ghidra_preparation = self._prepare_ghidra_batch(run_dir)
            except (LoopError, OSError, json.JSONDecodeError) as error:
                write_summary(
                    run_dir, "environment_error", records,
                    f"Deterministic Ghidra preparation failed before iteration {iteration}: {error}",
                    checkpoint={"stage": "ghidra_preparation", "iteration": iteration},
                    reason="ghidra_preparation_failure",
                )
                return "environment_error"
            self.log.write(
                f"Ghidra batch {ghidra_preparation.get('batch', 0)} preparation: "
                f"{ghidra_preparation.get('status', 'unknown')}\n"
            )
            self.log.flush()
            prompt = self._prompt(
                run_dir, working_candidate, prior_dir, iteration, start_iteration, end_iteration,
                reasoning_mode=str(config.get("reasoning_mode") or "single"),
                specialist_count=int(config.get("specialist_count") or 3),
            )
            prompt_path = iteration_dir / "prompt.txt"
            decision_path = iteration_dir / "decision.json"
            provider_log = iteration_dir / f"{provider}.log"
            prompt_path.write_text(prompt, encoding="utf-8")
            candidate_snapshot = iteration_dir / "candidate.before-provider.js"
            shutil.copy2(working_candidate, candidate_snapshot)
            protected = {
                prompt_path: sha256(prompt_path), config_path: sha256(config_path),
                candidate_snapshot: sha256(candidate_snapshot),
            }
            if mcp_path.is_file():
                protected[mcp_path] = sha256(mcp_path)
            provider_request = ProviderRequest(
                provider=provider, prompt=prompt, cwd=provider_cwd,
                schema_path=DECISION_SCHEMA, output_path=decision_path,
                model=str(config.get("model") or ""),
                reasoning_effort=str(config.get("reasoning_effort") or ""),
                reasoning_mode=str(config.get("reasoning_mode") or "single"),
                writable=True, mcp_config=mcp_path if mcp_path.is_file() else None,
                extra_args=tuple(codex_config_overrides()) if provider == "codex" else (),
            )
            command, provider_prompt = adapter.prepare(provider_request)
            exit_code, output = run_logged(
                command, self.log, cwd=provider_cwd, input_text=provider_prompt, artifact=provider_log,
                stage=f"provider_iteration_{iteration}",
            )
            call_usage = provider_token_usage(provider, output)
            record_provider_usage(
                run_dir, call_usage, phase=f"iteration_{iteration}", artifact=provider_log,
                model=str(config.get("model") or ""),
            )
            completed = adapter.finalize(provider_request, exit_code, output)
            if not completed or not validate_provider_output(decision_path, DECISION_SCHEMA):
                limit = detect_usage_limit(output)
                if limit:
                    usage = dict(limit)
                    usage.update({
                        "provider": provider,
                        "auto_resume": bool(config.get("auto_resume_usage_limit")),
                    })
                    write_summary(
                        run_dir, "usage_limited", records,
                        usage.get("detail") or f"{adapter.label} usage allowance exhausted in iteration {iteration}.",
                        checkpoint={
                            "stage": "provider", "iteration": iteration,
                            "candidate_snapshot": workspace_relative(candidate_snapshot),
                            "candidate_snapshot_sha256": sha256(candidate_snapshot),
                        },
                        reason="provider_usage_limit", usage=usage,
                    )
                    return "usage_limited"
                write_summary(run_dir, "provider_error", records, f"{adapter.label} failed in iteration {iteration}.")
                return "provider_error"
            allowed = {
                candidate.resolve(), candidate_snapshot.resolve(), prompt_path.resolve(),
                decision_path.resolve(), provider_log.resolve(), config_path.resolve(),
            }
            if mcp_path.is_file():
                allowed.add(mcp_path.resolve())
            unexpected = [path for path in iteration_dir.rglob("*") if path.is_file() and path.resolve() not in allowed]
            if any(sha256(path) != digest for path, digest in protected.items()) or unexpected:
                write_summary(run_dir, "codex_boundary_error", records, f"Codex wrote outside candidate.js in iteration {iteration}.")
                return "codex_boundary_error"
            decision = read_json(decision_path)
            coverage_errors = validate_control_point_decision(decision)
            if coverage_errors:
                write_summary(
                    run_dir, "provider_error", records,
                    f"{adapter.label} returned incomplete control-point coverage in iteration {iteration}: "
                    + "; ".join(coverage_errors),
                    reason="control_point_coverage_invalid",
                )
                return "provider_error"
            if decision.get("decision") != "diagnostics" and decision.get("diagnostic_actions"):
                write_summary(
                    run_dir, "provider_error", records,
                    f"{adapter.label} returned diagnostic actions with decision {decision.get('decision')!r} in iteration {iteration}.",
                )
                return "provider_error"
            if decision.get("decision") == "diagnostics":
                if sha256(candidate) != sha256(candidate_snapshot):
                    write_summary(
                        run_dir, "codex_boundary_error", records,
                        f"{adapter.label} changed candidate.js while requesting read-only diagnostics in iteration {iteration}.",
                    )
                    return "codex_boundary_error"
                prior_rounds = sum(
                    1 for item in records
                    if isinstance(item, dict) and isinstance(item.get("diagnostics"), dict)
                )
                requested = list(dict.fromkeys(
                    str(item) for item in (decision.get("diagnostic_actions") or [])
                ))
                previously_requested = {
                    str(action)
                    for item in records if isinstance(item, dict)
                    for action in ((item.get("diagnostics") or {}).get("actions") or [])
                }
                actions = [action for action in requested if action not in previously_requested]
                if prior_rounds >= DIAGNOSTIC_MAX_ROUNDS or not actions:
                    reason = (
                        f"The bounded {DIAGNOSTIC_MAX_ROUNDS}-round diagnostic allowance is exhausted."
                        if prior_rounds >= DIAGNOSTIC_MAX_ROUNDS
                        else "The requested diagnostic actions were already completed."
                    )
                    record = {
                        "iteration": iteration, "codex": decision, "validation": None,
                        "provider_usage": call_usage,
                    }
                    records.append(record)
                    write_json(iteration_dir / "record.json", record)
                    write_summary(run_dir, "human_review", records, reason)
                    return "human_review"
                if len(actions) > DIAGNOSTIC_MAX_ACTIONS_PER_PASS or any(action not in DIAGNOSTIC_ACTIONS for action in actions):
                    write_summary(
                        run_dir, "provider_error", records,
                        f"{adapter.label} returned an invalid adaptive diagnostic request in iteration {iteration}.",
                    )
                    return "provider_error"
                try:
                    diagnostic = self._run_adaptive_diagnostics(
                        run_dir, config, iteration_dir, iteration, actions,
                    )
                except (EnvironmentFailure, OSError, json.JSONDecodeError) as error:
                    write_summary(
                        run_dir, "environment_error", records, str(error),
                        checkpoint={
                            "stage": "adaptive_diagnostics", "iteration": iteration,
                            "candidate": workspace_relative(candidate), "actions": actions,
                        },
                        reason="adaptive_diagnostics_failure",
                    )
                    return "environment_error"
                record = {
                    "iteration": iteration, "candidate": workspace_relative(candidate),
                    "candidate_sha256": sha256(candidate), "codex": decision,
                    "diagnostics": diagnostic, "validation": None,
                    "provider_usage": call_usage,
                }
                records.append(record)
                write_json(iteration_dir / "record.json", record)
                previous_candidate = candidate
                previous_fingerprint = None
                self._pause_boundary(run_dir, records, iteration + 1, f"diagnostics_iteration_{iteration}")
                continue
            if decision.get("decision") == "human_review":
                record = {
                    "iteration": iteration, "codex": decision, "validation": None,
                    "provider_usage": call_usage,
                }
                records.append(record)
                write_json(iteration_dir / "record.json", record)
                write_summary(run_dir, "human_review", records, decision.get("rationale", "Codex requested review."))
                return "human_review"

            result_path = run_dir / "result.json"
            if result_path.exists():
                shutil.move(result_path, iteration_dir / "pre-validation-result.json")
            command = pipeline_args(
                "--authorized", "--strategy", "frida", "--resume", container_path(run_dir),
                "--observation-mode", "off", "--candidate-script", container_path(candidate),
                "--run-seconds", str(config["run_seconds"]), "--success-spec", f"/workspace/{config['success_spec']}",
                *target_args(config),
            )
            if config.get("package"):
                command.extend(["--package", config["package"]])
            if restart_frida and iteration == start_iteration:
                command.extend(["--start-frida-server", config["start_frida_server"]])
            exit_code, pipeline_output = run_logged(
                command, self.log, artifact=iteration_dir / "pipeline.log",
                stage=f"validation_iteration_{iteration}",
            )
            if exit_code not in {0, 1} or not result_path.is_file():
                detail, transport_reason = adb_transport_detail(
                    pipeline_output,
                    f"Candidate validation failed operationally in iteration {iteration}.",
                )
                write_summary(
                    run_dir, "environment_error", records,
                    detail,
                    checkpoint={
                        "stage": "validation", "iteration": iteration,
                        "candidate": workspace_relative(candidate),
                    },
                    reason=transport_reason or "validation_operational_failure",
                )
                return "environment_error"
            validation = read_json(result_path)
            shutil.copy2(result_path, iteration_dir / "validation.json")
            for pattern in ("frida-1*.log", "logcat-1*.log"):
                for source in (run_dir / "logs").glob(pattern):
                    shutil.copy2(source, iteration_dir / source.name)
            candidate_hash = sha256(candidate)
            fingerprint = attempt_fingerprint(candidate_hash, validation)
            record = {
                "iteration": iteration, "candidate": workspace_relative(candidate),
                "candidate_sha256": candidate_hash, "codex": decision,
                "pipeline_exit_code": exit_code, "validation": validation,
                "provider_usage": call_usage,
            }
            records.append(record)
            write_json(iteration_dir / "record.json", record)
            if validation.get("success"):
                self._resolve_native_queue(run_dir, iteration)
                write_summary(run_dir, "success", records, f"Success policy passed in iteration {iteration}.")
                return "success"
            control_checkpoint(f"native_replenishment_iteration_{iteration}", run_dir, allow_pause=False)
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
                return "usage_limited"
            advanced_native = self._advance_native_queue(run_dir, iteration, "success_policy_failed")
            if previous_fingerprint and fingerprint == previous_fingerprint and not advanced_native:
                write_summary(
                    run_dir, "assessment_failed", records,
                    "Two consecutive attempts produced the same candidate and validation result.",
                    reason="no_progress",
                )
                return "assessment_failed"
            if decision.get("decision") == "no_change" and not advanced_native:
                write_summary(
                    run_dir, "assessment_failed", records,
                    "Codex found no justified change and validation still failed.",
                    reason="no_justified_change",
                )
                return "assessment_failed"
            previous_fingerprint = None if advanced_native else fingerprint
            previous_candidate = candidate
            self._pause_boundary(run_dir, records, iteration + 1, f"iteration_{iteration}")
        write_summary(run_dir, "max_iterations", records, f"The policy did not pass within this invocation's {additional} attempts.")
        return "max_iterations"

    @staticmethod
    def _pause_boundary(
        run_dir: Path, records: list[Any], next_iteration: int, completed_stage: str,
    ) -> None:
        try:
            control_checkpoint(completed_stage, run_dir)
        except JobPaused:
            write_summary(
                run_dir, "paused", records,
                f"Paused by the operator after completing {completed_stage.replace('_', ' ')}.",
                checkpoint={"stage": "iterations", "next_iteration": next_iteration},
                reason="operator_pause",
            )
            raise

    def _run_adaptive_diagnostics(
        self, run_dir: Path, config: dict[str, Any], iteration_dir: Path,
        iteration: int, actions: list[str],
    ) -> dict[str, Any]:
        return run_adaptive_diagnostics(
            self.log, run_dir, config, iteration_dir, iteration, actions,
            command_runner=run_logged,
        )

    @staticmethod
    def _prompt(
        run_dir: Path, candidate: Path, prior_dir: Path | None,
        iteration: int, start_iteration: int, end_iteration: int, *,
        reasoning_mode: str, specialist_count: int,
    ) -> str:
        return build_iteration_prompt(
            run_dir, candidate, prior_dir, iteration, start_iteration, end_iteration,
            reasoning_mode=reasoning_mode, specialist_count=specialist_count,
        )
