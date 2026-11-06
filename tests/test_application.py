from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO, StringIO
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from backend.app import (
    _readiness, app, artifact_manifest, codex_model_catalog, parse_resume, parse_retry, parse_start,
    infer_attempt_kind, infer_job_run_id, resolve_workspace_item, sign_out_codex,
    assistant_evidence_snapshot, assistant_history, recorded_success_policy, run_assistant_turn,
    record_wireless_device, start_job, strip_terminal_controls, success_policy,
    subprocess_capture_text,
    wireless_device_view,
)
from assessment.orchestrator import (
    WORKSPACE, LoopError, LoopRunner, attempt_fingerprint, codex_config_overrides,
    codex_multi_agent_args, codex_reasoning_args, checkpoint_recovery_available,
    frida_recovery_available, pause_recovery_available, terminal_outcome, usage_limit_recovery_available,
    validate_decision_schema_registry,
)
from assessment.control_points import CONTROL_POINT_STAGES, validate_control_point_decision
from assessment.runtime import JobControl, JobPaused, install_job_control
from backend.providers import (
    ProviderRequest, detect_usage_limit, provider_adapter, provider_token_usage,
    validate_provider_output,
)
from backend.events import activity_revision
from assessment.usage import assessment_token_usage, record_provider_usage, token_usage_delta
from assessment.goals import (
    ensure_assessment_goal, goal_instruction, record_goal_turn, update_goal_for_pipeline_status,
)


class WebAppTests(unittest.TestCase):
    def setUp(self) -> None:
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def test_health(self) -> None:
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")

    def test_usage_limit_detection_preserves_reported_reset(self) -> None:
        usage = detect_usage_limit(
            'ERROR {"code":"subscription_sharing_usage_limit_exceeded"} resets at 2026-11-01T05:30:00Z',
            now=datetime(2026, 11, 1, tzinfo=timezone.utc),
        )
        self.assertIsNotNone(usage)
        self.assertEqual(usage["code"], "subscription_sharing_usage_limit_exceeded")
        self.assertEqual(usage["reset_utc"], "2026-11-01T05:30:00+00:00")
        self.assertIsNone(detect_usage_limit("429 rate_limit_exceeded; retry after 2 seconds"))

    def test_provider_token_usage_normalizes_codex_and_claude(self) -> None:
        codex = provider_token_usage("codex", "\n".join((
            '{"type":"thread.started","thread_id":"t"}',
            '{"type":"turn.completed","usage":{"input_tokens":120,"cached_input_tokens":20,"output_tokens":30,"total_tokens":150}}',
        )))
        claude = provider_token_usage("claude", json.dumps({
            "result": "{}", "usage": {
                "input_tokens": 40, "cache_read_input_tokens": 10,
                "cache_creation_input_tokens": 5, "output_tokens": 15,
            },
        }))
        legacy = provider_token_usage("codex", "tokens used\n71,471\n")
        self.assertEqual(codex["total_tokens"], 150)
        self.assertEqual(codex["cached_input_tokens"], 20)
        self.assertEqual(claude["total_tokens"], 70)
        self.assertEqual(legacy["total_tokens"], 71471)
        self.assertFalse(legacy["detail_available"])

    def test_assessment_usage_ledger_backfills_legacy_and_tracks_delta(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORKSPACE) as temp:
            run = Path(temp)
            legacy_log = run / "agent" / "iteration-1" / "codex.log"
            legacy_log.parent.mkdir(parents=True)
            legacy_log.write_text("tokens used\n1,200\n", encoding="utf-8")
            before = assessment_token_usage(run)
            current_log = run / "agent" / "iteration-2" / "codex.log"
            current_log.parent.mkdir(parents=True)
            current_log.write_text("structured trace\n", encoding="utf-8")
            record_provider_usage(run, {
                "provider": "codex", "input_tokens": 300, "cached_input_tokens": 50,
                "cache_creation_input_tokens": 0, "output_tokens": 100,
                "reasoning_output_tokens": 20, "total_tokens": 400,
                "detail_available": True, "source": "structured",
            }, phase="iteration_2", artifact=current_log, model="test-model")
            after = assessment_token_usage(run)
            delta = token_usage_delta(after, before)
        self.assertEqual(before["total_tokens"], 1200)
        self.assertEqual(after["total_tokens"], 1600)
        self.assertEqual(after["calls"], 2)
        self.assertEqual(delta["total_tokens"], 400)

    def test_usage_limit_checkpoint_is_resumable(self) -> None:
        self.assertTrue(usage_limit_recovery_available({
            "status": "usage_limited", "recoverable": True,
            "checkpoint": {"stage": "provider", "iteration": 2},
        }))
        self.assertFalse(usage_limit_recovery_available({
            "status": "provider_error", "recoverable": False,
            "checkpoint": {"stage": "provider", "iteration": 2},
        }))

    def test_operator_pause_checkpoint_is_resumable(self) -> None:
        self.assertTrue(pause_recovery_available({
            "status": "paused", "recoverable": True,
            "checkpoint": {"stage": "iterations", "next_iteration": 4},
        }))
        self.assertFalse(pause_recovery_available({
            "status": "paused", "recoverable": True,
            "checkpoint": {"stage": "provider", "next_iteration": 4},
        }))

    def test_safe_boundary_pause_writes_a_continuation_checkpoint(self) -> None:
        control = JobControl()
        control.request_pause()
        install_job_control(control)
        try:
            with tempfile.TemporaryDirectory(dir=WORKSPACE) as temp:
                run = Path(temp)
                with self.assertRaises(JobPaused):
                    LoopRunner._pause_boundary(run, [], 3, "native_selection")
                summary = json.loads((run / "codex-loop-result.json").read_text(encoding="utf-8"))
        finally:
            install_job_control(None)
        self.assertEqual(summary["status"], "paused")
        self.assertEqual(summary["checkpoint"]["next_iteration"], 3)
        self.assertTrue(summary["recoverable"])

    def test_usage_limit_recovery_restarts_interrupted_iteration_from_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORKSPACE) as temp:
            run = Path(temp)
            failed = run / "agent" / "iteration-2"
            failed.mkdir(parents=True)
            snapshot = failed / "candidate.before-provider.js"
            snapshot.write_text("trusted candidate\n", encoding="utf-8")
            config = {"provider": "codex", "auto_resume_usage_limit": True}
            summary = {
                "usage": {"code": "usage_limit_exceeded"},
                "checkpoint": {
                    "stage": "provider", "iteration": 2,
                    "candidate_snapshot": str(snapshot),
                    "candidate_snapshot_sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                },
            }
            request = {"max_iterations": 3, "provider": "codex"}
            runner = LoopRunner(StringIO())
            with patch.object(runner, "_iterations", return_value="max_iterations") as iterations:
                status, returned = runner._recover_usage_limit(run, config, summary, [], request)
            self.assertEqual(status, "max_iterations")
            self.assertEqual(returned, run)
            self.assertFalse(failed.exists())
            recovered = next((run / "agent").glob("usage-limit-recovery-*"))
            self.assertEqual((recovered / snapshot.name).read_text(encoding="utf-8"), "trusted candidate\n")
            self.assertEqual(iterations.call_args.kwargs["start_iteration"], 2)
            self.assertEqual(iterations.call_args.kwargs["additional"], 3)
            self.assertEqual(iterations.call_args.kwargs["previous_candidate"], recovered / snapshot.name)

    @patch("backend.jobs.jobs", return_value=[])
    @patch("backend.auth.codex_authenticated", return_value=True)
    def test_start_job_is_durably_queued(self, _authenticated, _jobs) -> None:
        with tempfile.TemporaryDirectory() as temp, patch("backend.jobs.STATE_ROOT", Path(temp)):
            state = start_job("start", "sample.apk", {"apk": "/workspace/uploads/sample.apk"})
            directory = Path(temp) / state["id"]
            stored = json.loads((directory / "job.json").read_text(encoding="utf-8"))
            queued_request = json.loads((directory / "request.json").read_text(encoding="utf-8"))
        self.assertEqual(stored["status"], "queued")
        self.assertFalse(stored["running"])
        self.assertEqual(queued_request["payload"]["apk"], "/workspace/uploads/sample.apk")

    def test_overview_contract(self) -> None:
        payload = self.client.get("/api/overview").get_json()
        self.assertIn("codex", payload)
        self.assertIn("runs", payload)
        self.assertIn("success_specs", payload)
        self.assertTrue(payload["diagnostic_recipes"])
        self.assertIn("ui_description", payload["diagnostic_recipes"][0])
        self.assertIn("artifact_limits", payload["diagnostic_recipes"][0])

    def test_event_stream_emits_initial_overview(self) -> None:
        response = self.client.get("/api/events", buffered=False)
        try:
            event = next(response.response).decode("utf-8")
        finally:
            response.close()
        self.assertEqual(response.content_type, "text/event-stream; charset=utf-8")
        self.assertIn("event: overview", event)
        self.assertIn('"runs":', event)
        self.assertEqual(response.headers["X-Accel-Buffering"], "no")

    def test_event_revision_tracks_live_job_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jobs = root / "jobs" / ("a" * 32)
            jobs.mkdir(parents=True)
            runs_root = root / "runs"
            runs_root.mkdir()
            with patch("backend.events.JOB_STATE_ROOT", root), patch("backend.events.RUNS_ROOT", runs_root):
                before = activity_revision()
                (jobs / "output.log").write_text("new worker output\n", encoding="utf-8")
                after = activity_revision()
        self.assertNotEqual(before, after)

    def test_claude_adapter_normalizes_json_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            schema = root / "schema.json"
            output = root / "response.json"
            schema.write_text(json.dumps({
                "type": "object", "properties": {"answer": {"type": "string"}},
                "required": ["answer"], "additionalProperties": False,
            }), encoding="utf-8")
            request = ProviderRequest(
                provider="claude", prompt="Answer", cwd=root,
                schema_path=schema, output_path=output, model="sonnet",
            )
            adapter = provider_adapter("claude")
            command, prompt = adapter.prepare(request)
            completed = adapter.finalize(request, 0, json.dumps({"result": '{"answer":"grounded"}'}))
            valid = validate_provider_output(output, schema)
        self.assertIn("--output-format", command)
        self.assertIn("matching this schema exactly", prompt)
        self.assertTrue(completed)
        self.assertTrue(valid)

    def test_codex_adapter_requests_structured_usage_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            schema = root / "schema.json"
            schema.write_text('{}', encoding="utf-8")
            request = ProviderRequest(
                provider="codex", prompt="Answer", cwd=root,
                schema_path=schema, output_path=root / "answer.json",
            )
            command, _prompt = provider_adapter("codex").prepare(request)
        self.assertIn("--json", command)
        self.assertIn("--output-last-message", command)

    def test_codex_adapter_resumes_persistent_goal_thread(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            schema = root / "schema.json"
            schema.write_text('{}', encoding="utf-8")
            request = ProviderRequest(
                provider="codex", prompt="Continue the Goal", cwd=root,
                schema_path=schema, output_path=root / "answer.json",
                session_id="019a-test-thread",
            )
            command, _prompt = provider_adapter("codex").prepare(request)
        self.assertEqual(Path(command[0]).name, "codex")
        self.assertEqual(command[1:3], ["exec", "resume"])
        self.assertIn("019a-test-thread", command)
        self.assertNotIn("--sandbox", command)
        self.assertEqual(command[-1], "-")

    def test_assessment_goal_persists_thread_and_deterministic_status(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORKSPACE) as temp:
            run = Path(temp)
            policy = run / "policy.json"
            policy.write_text(json.dumps({
                "name": "Warning removed", "checks": [{"type": "process_alive"}],
            }), encoding="utf-8")
            goal = ensure_assessment_goal(run, {
                "package": "com.example", "success_spec": str(policy.relative_to(WORKSPACE)),
                "success_spec_sha256": hashlib.sha256(policy.read_bytes()).hexdigest(),
            })
            instruction = goal_instruction(goal, first_turn=True)
            output = "\n".join((
                '{"type":"thread.started","thread_id":"thread-123"}',
                '{"type":"item.completed","item":{"type":"tool_call","name":"create_goal"}}',
            ))
            active = record_goal_turn(run, output, iteration=1, resumed=False)
            update_goal_for_pipeline_status(run, "success", "All checks passed.")
            completed = json.loads((run / "assessment-goal.json").read_text(encoding="utf-8"))
        self.assertIn("call the Codex `create_goal` tool", instruction)
        self.assertEqual(active["thread_id"], "thread-123")
        self.assertTrue(active["activation_verified"])
        self.assertEqual(completed["status"], "complete")
        self.assertEqual(completed["pipeline_status"], "success")

    def test_diagnostic_decision_requires_allowlisted_actions(self) -> None:
        schema = WORKSPACE / "pipeline" / "codex-decision.schema.json"
        schema_value = json.loads(schema.read_text(encoding="utf-8"))
        self.assertNotIn("allOf", schema_value)
        self.assertEqual(set(schema_value["properties"]), set(schema_value["required"]))
        base = {
            "decision": "diagnostics", "rationale": "Need the unpacked JNI target.",
            "changes_made": [], "evidence_used": ["observations.json"],
            "remaining_risks": ["Runtime code is not yet attributed."],
            "hook_layer": "none",
            "control_point_coverage": [
                {
                    "stage": stage, "status": "unexplored",
                    "evidence": "The current evidence has not resolved this stage.",
                    "next_step": "Collect the requested bounded runtime evidence.",
                }
                for stage in CONTROL_POINT_STAGES
            ],
        }
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "decision.json"
            output.write_text(json.dumps(base), encoding="utf-8")
            self.assertFalse(validate_provider_output(output, schema))
            output.write_text(json.dumps({
                **base, "diagnostic_actions": ["trace_jni_registration"],
            }), encoding="utf-8")
            self.assertTrue(validate_provider_output(output, schema))
            output.write_text(json.dumps({
                **base, "diagnostic_actions": ["arbitrary_shell"],
            }), encoding="utf-8")
            self.assertFalse(validate_provider_output(output, schema))
            output.write_text(json.dumps({
                **base, "decision": "human_review", "diagnostic_actions": [],
            }), encoding="utf-8")
            self.assertTrue(validate_provider_output(output, schema))

    def test_control_point_coverage_blocks_premature_native_escalation_and_review(self) -> None:
        coverage = [
            {
                "stage": stage, "status": "unexplored",
                "evidence": "No app-owned control point has been assessed yet.",
                "next_step": "Inspect the decompiled call chain.",
            }
            for stage in CONTROL_POINT_STAGES
        ]
        native = {
            "decision": "updated", "hook_layer": "native",
            "control_point_coverage": coverage,
        }
        errors = validate_control_point_decision(native)
        self.assertTrue(any("native escalation" in error for error in errors))
        self.assertTrue(any("candidate control point" in error for error in errors))

        review = {
            "decision": "human_review", "hook_layer": "none",
            "control_point_coverage": coverage,
        }
        self.assertTrue(any("cannot leave control points unfinished" in error for error in validate_control_point_decision(review)))

    def test_control_point_coverage_accepts_narrow_sink_candidate(self) -> None:
        coverage = []
        for stage in CONTROL_POINT_STAGES:
            status = "candidate" if stage == "enforcement_sinks" else "tested"
            coverage.append({
                "stage": stage, "status": status,
                "evidence": f"JADX and validation evidence for {stage}.",
                "next_step": "Validate the exact app-owned sink hook twice." if status == "candidate" else "",
            })
        decision = {
            "decision": "updated", "hook_layer": "java",
            "control_point_coverage": coverage,
        }
        self.assertEqual(validate_control_point_decision(decision), [])

    def test_retry_archives_provider_iteration_without_record(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORKSPACE) as temp:
            run = Path(temp)
            incomplete = run / "agent" / "iteration-7"
            incomplete.mkdir(parents=True)
            (incomplete / "codex.log").write_text("invalid schema", encoding="utf-8")
            archived = LoopRunner._archive_incomplete_iteration(run, 7, "provider_error")
            destination = WORKSPACE / archived
            self.assertFalse(incomplete.exists())
            self.assertTrue((destination / "codex.log").is_file())
            self.assertIn("incomplete-iterations", archived)

    def test_start_requires_authorization(self) -> None:
        response = self.client.post("/api/start", json={})
        self.assertEqual(response.status_code, 400)
        self.assertIn("authorization", response.get_json()["error"].lower())

    @patch("backend.app.success_policy")
    @patch("backend.app.resolve_workspace_item")
    def test_start_requires_matching_readiness_token(self, resolve, policy) -> None:
        resolve.return_value = WORKSPACE / "uploads" / "sample.apk"
        policy.return_value = WORKSPACE / "policies" / "generated" / "policy.json"
        _readiness["ready-token"] = {
            "target": "emulator-5554", "transport": "adb",
            "frida_server": "/data/local/tmp/frida-server",
            "expires": float("inf"),
        }
        _, payload = parse_start({
            "authorized": True, "apk": "uploads/sample.apk", "transport": "adb",
            "target": "emulator-5554", "max_iterations": 3,
            "observation_seconds": 15, "run_seconds": 20,
            "frida_server": "/data/local/tmp/frida-server",
            "readiness_token": "ready-token", "policy_preset": "basic",
        })
        self.assertEqual(payload["readiness_token"], "ready-token")
        with self.assertRaisesRegex(ValueError, "settings changed"):
            parse_start({
                "authorized": True, "apk": "uploads/sample.apk", "transport": "adb",
                "target": "different-device", "max_iterations": 3,
                "observation_seconds": 15, "run_seconds": 20,
                "frida_server": "/data/local/tmp/frida-server",
                "readiness_token": "ready-token", "policy_preset": "basic",
            })

    @patch("backend.app.success_policy")
    def test_reassessment_uses_recorded_apk_and_links_source(self, policy) -> None:
        import hashlib
        with tempfile.TemporaryDirectory(dir=WORKSPACE / "runs") as temp:
            source = Path(temp)
            apk = source / "original.apk"
            apk.write_bytes(b"PK\x03\x04same-apk")
            digest = hashlib.sha256(apk.read_bytes()).hexdigest()
            (source / "report.json").write_text('{"package":"com.example"}', encoding="utf-8")
            (source / "codex-loop-config.json").write_text(json.dumps({
                "apk_sha256": digest, "success_spec_sha256": "a" * 64,
            }), encoding="utf-8")
            policy.return_value = WORKSPACE / "policies" / "generated" / "policy.json"
            _readiness["reassess-ready"] = {
                "target": "emulator-5554", "transport": "adb",
                "frida_server": "/data/local/tmp/frida-server", "expires": float("inf"),
            }
            _, payload = parse_start({
                "authorized": True, "source_run": source.name, "transport": "adb",
                "target": "emulator-5554", "max_iterations": 3,
                "observation_seconds": 15, "run_seconds": 20,
                "frida_server": "/data/local/tmp/frida-server",
                "readiness_token": "reassess-ready", "policy_preset": "basic",
            })
        self.assertEqual(payload["derived_from_run"], source.name)
        self.assertEqual(payload["derived_from_policy_sha256"], "a" * 64)
        self.assertEqual(Path(payload["apk"]).name, "original.apk")

    def test_apk_upload_is_stored_under_uploads(self) -> None:
        response = self.client.post(
            "/api/apks",
            data={"apk": (BytesIO(b"PK\x03\x04test-apk"), "sample.apk")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)
        path = WORKSPACE / response.get_json()["path"]
        try:
            self.assertEqual(path.parent.name, "uploads")
            self.assertTrue(path.is_file())
        finally:
            path.unlink(missing_ok=True)

    def test_apk_upload_rejects_non_zip_content(self) -> None:
        response = self.client.post(
            "/api/apks",
            data={"apk": (BytesIO(b"not an apk"), "sample.apk")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)

    def test_policy_builder_generates_repeatable_detection_policy(self) -> None:
        path = success_policy({
            "policy_preset": "detection_removed",
            "policy_repeat": 2,
            "forbidden_ui_pattern": "root detected|frida detected",
        })
        try:
            policy = json.loads(path.read_text(encoding="utf-8"))
            self.assertTrue(policy["baseline_required"])
            self.assertEqual(policy["repeat"], 2)
            kinds = {check["type"] for check in policy["checks"]}
            self.assertIn("ui_text_not_regex", kinds)
            self.assertIn("no_crash", kinds)
        finally:
            path.unlink(missing_ok=True)

    def test_basic_policy_ignores_hidden_text_fields(self) -> None:
        path = success_policy({
            "policy_preset": "basic", "policy_repeat": 1,
            "forbidden_ui_pattern": "stale hidden value",
        })
        try:
            policy = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                [check["type"] for check in policy["checks"]],
                ["process_alive", "foreground_package", "no_crash"],
            )
        finally:
            path.unlink(missing_ok=True)

    def test_recorded_success_policy_exposes_bound_policy_metadata(self) -> None:
        path = success_policy({"policy_preset": "basic", "policy_repeat": 2})
        try:
            import hashlib
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            metadata = recorded_success_policy({
                "success_spec": str(path.relative_to(WORKSPACE)).replace("\\", "/"),
                "success_spec_sha256": digest,
            })
            self.assertTrue(metadata["valid"])
            self.assertEqual(metadata["name"], "Basic launch")
            self.assertEqual(metadata["repeat"], 2)
            self.assertIn("process_alive", metadata["checks"])
        finally:
            path.unlink(missing_ok=True)

    @patch("backend.app.resolve_workspace_item")
    def test_resume_accepts_thinking_level(self, resolve) -> None:
        run = WORKSPACE / "runs" / "example"
        resolve.return_value = run
        _, request = parse_resume({
            "authorized": True, "run": "runs/example", "max_iterations": 2,
            "reasoning_effort": "xhigh",
        })
        self.assertEqual(request["reasoning_effort"], "xhigh")

    @patch("backend.app.resolve_workspace_item")
    def test_resume_accepts_claude_provider(self, resolve) -> None:
        resolve.return_value = WORKSPACE / "runs" / "example"
        _, request = parse_resume({
            "authorized": True, "run": "runs/example", "max_iterations": 2,
            "provider": "claude", "model": "sonnet", "reasoning_effort": "high",
        })
        self.assertEqual(request["provider"], "claude")
        self.assertEqual(request["model"], "sonnet")

    @patch("backend.app.json_file")
    @patch("backend.app.resolve_workspace_item")
    def test_resume_rejects_policy_from_another_run(self, resolve, read_json) -> None:
        resolve.return_value = WORKSPACE / "runs" / "example"
        read_json.return_value = {"success_spec_sha256": "a" * 64}
        with self.assertRaisesRegex(ValueError, "does not match"):
            parse_resume({
                "authorized": True, "run": "runs/example", "max_iterations": 2,
                "success_spec_sha256": "b" * 64,
            })

    @patch("backend.app.resolve_workspace_item")
    def test_retry_accepts_any_completed_run(self, resolve) -> None:
        run = WORKSPACE / "runs" / "example"
        resolve.return_value = run
        with patch.object(Path, "is_file", return_value=True):
            label, request = parse_retry({
                "authorized": True, "run": "runs/example", "max_iterations": 2,
                "reasoning_effort": "high",
            })
        self.assertEqual(label, "example")
        self.assertEqual(request["run"], str(run))

    @patch("backend.app.resolve_workspace_item")
    def test_retry_requires_completed_run(self, resolve) -> None:
        resolve.return_value = WORKSPACE / "runs" / "unfinished"
        with self.assertRaisesRegex(ValueError, "completed assessment"):
            parse_retry({"authorized": True, "run": "runs/unfinished", "max_iterations": 1})

    @patch("backend.app.resolve_workspace_item")
    def test_resume_accepts_parallel_specialists(self, resolve) -> None:
        resolve.return_value = WORKSPACE / "runs" / "example"
        _, request = parse_resume({
            "authorized": True, "run": "runs/example", "max_iterations": 2,
            "reasoning_mode": "parallel", "specialist_count": 2,
        })
        self.assertEqual(request["reasoning_mode"], "parallel")
        self.assertEqual(request["specialist_count"], 2)

    @patch("backend.app.resolve_workspace_item")
    def test_resume_rejects_invalid_parallel_specialist_count(self, resolve) -> None:
        resolve.return_value = WORKSPACE / "runs" / "example"
        with self.assertRaisesRegex(ValueError, "specialist count"):
            parse_resume({
                "authorized": True, "run": "runs/example", "max_iterations": 2,
                "reasoning_mode": "parallel", "specialist_count": 8,
            })

    @patch("backend.app.resolve_workspace_item")
    def test_resume_accepts_device_frida_server_path(self, resolve) -> None:
        resolve.return_value = WORKSPACE / "runs" / "example"
        _, request = parse_resume({
            "authorized": True, "run": "runs/example", "max_iterations": 2,
            "frida_server": "/data/local/tmp/frida-server-17.5.1",
        })
        self.assertEqual(request["frida_server"], "/data/local/tmp/frida-server-17.5.1")

    @patch("backend.app.json_file")
    @patch("backend.app.resolve_workspace_item")
    def test_resume_changed_target_requires_bound_readiness(self, resolve, read_json) -> None:
        resolve.return_value = WORKSPACE / "runs" / "example"
        read_json.return_value = {
            "target": "old-device", "transport": "adb",
            "start_frida_server": "/data/local/tmp/frida-server",
        }
        with self.assertRaisesRegex(ValueError, "Run device readiness"):
            parse_resume({
                "authorized": True, "run": "runs/example", "max_iterations": 2,
                "target": "new-device", "transport": "adb",
                "frida_server": "/data/local/tmp/frida-server",
            })

    @patch("backend.app.json_file")
    @patch("backend.app.resolve_workspace_item")
    def test_resume_accepts_ready_alternate_target(self, resolve, read_json) -> None:
        resolve.return_value = WORKSPACE / "runs" / "example"
        read_json.return_value = {
            "target": "old-device", "transport": "adb",
            "start_frida_server": "/data/local/tmp/frida-server",
        }
        readiness_token = "a" * 32
        with patch.dict(_readiness, {readiness_token: {
            "target": "192.168.1.20:38888", "transport": "wireless",
            "frida_server": "/data/local/tmp/frida-server", "expires": float("inf"),
        }}, clear=True):
            _, request = parse_resume({
                "authorized": True, "run": "runs/example", "max_iterations": 2,
                "target": "192.168.1.20:38888", "transport": "wireless",
                "frida_server": "/data/local/tmp/frida-server", "readiness_token": readiness_token,
            })
        self.assertEqual(request["target"], "192.168.1.20:38888")
        self.assertEqual(request["transport"], "wireless")
        self.assertTrue(request["target_settings_changed"])

    @patch("backend.app.resolve_workspace_item")
    def test_resume_rejects_unsafe_frida_server_path(self, resolve) -> None:
        resolve.return_value = WORKSPACE / "runs" / "example"
        with self.assertRaisesRegex(ValueError, "Frida Server path"):
            parse_resume({
                "authorized": True, "run": "runs/example", "max_iterations": 2,
                "frida_server": "/data/local/tmp/frida-server; reboot",
            })

    @patch("backend.app.resolve_workspace_item")
    def test_resume_rejects_unknown_thinking_level(self, resolve) -> None:
        resolve.return_value = WORKSPACE / "runs" / "example"
        with self.assertRaisesRegex(ValueError, "thinking level"):
            parse_resume({
                "authorized": True, "run": "runs/example", "max_iterations": 2,
                "reasoning_effort": "infinite",
            })

    def test_auth_output_strips_terminal_controls(self) -> None:
        value = "\x1b[94mhttps://auth.openai.com/codex/device\x1b[0m\r\n\x1b[90mABCD-EFGHIJ\x1b[0m"
        self.assertEqual(
            strip_terminal_controls(value),
            "https://auth.openai.com/codex/device\nABCD-EFGHIJ",
        )

    def test_timeout_output_accepts_bytes_for_visible_failure(self) -> None:
        self.assertEqual(subprocess_capture_text(b"partial\r\n", b"error\n"), "partial\nerror\n")

    @patch("backend.auth.subprocess.run")
    def test_sign_out_uses_codex_logout_and_clears_catalog(self, run) -> None:
        run.return_value = subprocess.CompletedProcess([], 0, "Logged out", "")
        result = sign_out_codex()
        self.assertFalse(result["authenticated"])
        run.assert_called_once_with(
            ["codex", "logout"], text=True, capture_output=True, timeout=30,
        )
        catalog = codex_model_catalog()
        self.assertEqual(catalog, {"models": [], "source": "authentication_required"})

    def test_workspace_path_cannot_escape(self) -> None:
        with self.assertRaises(ValueError):
            resolve_workspace_item("../outside.apk")

    def test_job_history_infers_run_and_recovery_kind(self) -> None:
        log = (
            "+ python3 pipeline.py --resume /workspace/runs/20261028T144917Z-239cb4621bdb "
            "--observation-mode only --start-frida-server /data/local/tmp/frida-server\n"
            "Run directory: /workspace/runs/20261028T144917Z-239cb4621bdb\n"
        )
        state = {"kind": "resume"}
        self.assertEqual(infer_job_run_id(state, log), "20261028T144917Z-239cb4621bdb")
        self.assertEqual(infer_attempt_kind(state, log), "frida_recovery")

    def test_initial_job_kind_is_preserved(self) -> None:
        self.assertEqual(infer_attempt_kind({"kind": "start"}, ""), "initial")

    def test_attempt_fingerprint_is_stable_and_sensitive(self) -> None:
        first = attempt_fingerprint("abc", {"success": False})
        self.assertEqual(first, attempt_fingerprint("abc", {"success": False}))
        self.assertNotEqual(first, attempt_fingerprint("def", {"success": False}))

    def test_only_frida_transport_human_review_is_recoverable(self) -> None:
        recoverable = {
            "status": "human_review",
            "detail": "Frida failed to spawn: connection closed.",
            "iterations": [],
        }
        unrelated = {
            "status": "human_review",
            "detail": "Remote attestation requires review.",
            "iterations": [],
        }
        self.assertTrue(frida_recovery_available(recoverable))
        self.assertFalse(frida_recovery_available(unrelated))

    def test_environment_checkpoint_is_recoverable(self) -> None:
        self.assertTrue(checkpoint_recovery_available({
            "status": "environment_error", "recoverable": True,
            "checkpoint": {"stage": "validation", "iteration": 2},
        }))
        self.assertTrue(checkpoint_recovery_available({
            "status": "environment_error", "recoverable": True,
            "checkpoint": {
                "stage": "adaptive_diagnostics", "iteration": 3,
                "actions": ["trace_termination_calls"],
            },
        }))
        self.assertFalse(checkpoint_recovery_available({
            "status": "human_review", "recoverable": False,
            "checkpoint": None,
        }))

    def test_terminal_outcome_explains_hidden_payload_and_remaining_diagnostics(self) -> None:
        outcome = terminal_outcome({
            "status": "human_review",
            "detail": "The hidden runtime payload was unavailable and the payload dump produced no artifacts.",
            "iterations": [
                {"iteration": 1, "diagnostics": {"actions": ["dump_runtime_payloads"]}},
                {"iteration": 2, "codex": {"decision": "human_review"}},
            ],
        })
        self.assertEqual(outcome["code"], "protected_payload_unavailable")
        self.assertEqual(outcome["diagnostics"], {"used": 1, "limit": 2, "remaining": 1})
        self.assertEqual(outcome["action"], "retry_diagnostics")

    def test_terminal_outcome_requires_completed_rounds_before_exhausted(self) -> None:
        summary = {
            "status": "human_review", "detail": "Both bounded diagnostic rounds are exhausted.",
            "iterations": [{"diagnostics": {}}, {"diagnostics": {}}],
        }
        self.assertEqual(terminal_outcome(summary)["code"], "diagnostic_budget_exhausted")

    def test_terminal_outcome_classifies_no_progress(self) -> None:
        outcome = terminal_outcome({
            "status": "assessment_failed", "reason": "no_progress",
            "detail": "Two consecutive validations matched.", "iterations": [],
        })
        self.assertEqual(outcome["code"], "no_progress")
        self.assertEqual(outcome["action"], "compare_attempts")

    def test_decision_schema_is_guarded_against_registry_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "schema.json"
            path.write_text(json.dumps({
                "properties": {"diagnostic_actions": {"items": {"enum": ["unknown_recipe"]}}},
            }), encoding="utf-8")
            with self.assertRaisesRegex(LoopError, "shared registry"):
                validate_decision_schema_registry(path)

    def test_codex_uses_container_native_ghidra_bridge(self) -> None:
        arguments = codex_config_overrides()
        rendered = " ".join(arguments)
        self.assertIn("/opt/ghidra-mcp/venv/bin/bridge-mcp-ghidra", rendered)
        self.assertIn("GHIDRA_MCP_AUTH_TOKEN", rendered)
        self.assertIn("http://127.0.0.1:18089", rendered)
        self.assertIn("GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS", rendered)
        self.assertIn("listing,function,program,xref,analysis,malware", rendered)
        self.assertNotIn("http://reverse-engineering:8089", rendered)
        self.assertNotIn("cmd.exe", rendered)

    def test_host_codex_ghidra_config_is_cross_platform(self) -> None:
        config = (WORKSPACE / ".codex" / "config.toml").read_text(encoding="utf-8")
        self.assertIn('command = "docker"', config)
        self.assertIn('"compose", "exec", "-T"', config)
        self.assertIn('GHIDRA_MCP_URL=http://127.0.0.1:18089', config)
        self.assertIn('GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1', config)
        self.assertIn('/opt/ghidra-mcp/venv/bin/bridge-mcp-ghidra', config)
        self.assertNotIn("cmd.exe", config)
        self.assertNotIn("C:\\", config)


if __name__ == "__main__":
    unittest.main()
