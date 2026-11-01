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

from ui.app import (
    _readiness, app, artifact_manifest, codex_model_catalog, parse_resume, parse_retry, parse_start,
    infer_attempt_kind, infer_job_run_id, resolve_workspace_item, sign_out_codex,
    assistant_evidence_snapshot, assistant_history, recorded_success_policy, run_assistant_turn,
    record_wireless_device, start_job, strip_terminal_controls, success_policy,
    subprocess_capture_text,
    wireless_device_view,
)
from ui.orchestrator import (
    WORKSPACE, LoopRunner, attempt_fingerprint, codex_config_overrides,
    codex_multi_agent_args, codex_reasoning_args, checkpoint_recovery_available,
    frida_recovery_available, usage_limit_recovery_available,
)
from ui.providers import ProviderRequest, detect_usage_limit, provider_adapter, validate_provider_output


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

    def test_usage_limit_checkpoint_is_resumable(self) -> None:
        self.assertTrue(usage_limit_recovery_available({
            "status": "usage_limited", "recoverable": True,
            "checkpoint": {"stage": "provider", "iteration": 2},
        }))
        self.assertFalse(usage_limit_recovery_available({
            "status": "provider_error", "recoverable": False,
            "checkpoint": {"stage": "provider", "iteration": 2},
        }))

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

    @patch("ui.app.jobs", return_value=[])
    @patch("ui.app.codex_authenticated", return_value=True)
    def test_start_job_is_durably_queued(self, _authenticated, _jobs) -> None:
        with tempfile.TemporaryDirectory() as temp, patch("ui.app.STATE_ROOT", Path(temp)):
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

    def test_reassessment_entry_is_in_continue_workflow(self) -> None:
        response = self.client.get("/")
        page = response.get_data(as_text=True)
        response.close()
        self.assertIn('id="reassessSelected"', page)
        self.assertIn('id="reassessmentBanner" hidden', page)
        self.assertNotIn("â", page)

    def test_attempt_history_uses_nonshrinking_scroll_content(self) -> None:
        response = self.client.get("/styles.css")
        styles = response.get_data(as_text=True)
        response.close()
        self.assertIn(".job-strip { flex: 0 0 clamp", styles)
        self.assertIn("display: flex; flex-direction: column", styles)
        self.assertIn(".job-group { flex: 0 0 auto", styles)

    def test_assessment_rows_share_grid_columns(self) -> None:
        response = self.client.get("/styles.css")
        styles = response.get_data(as_text=True)
        response.close()
        self.assertIn(".run-row { display: grid; grid-column: 1 / -1; grid-template-columns: subgrid", styles)

    def test_run_assistant_ui_is_available(self) -> None:
        response = self.client.get("/")
        page = response.get_data(as_text=True)
        response.close()
        self.assertIn('id="assistantDialog"', page)
        self.assertIn('data-assistant-prompt="Propose a bounded rerun', page)
        self.assertIn('id="claudeAuth"', page)
        self.assertIn('<option value="claude">Claude</option>', page)

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

    def test_diagnostic_decision_requires_allowlisted_actions(self) -> None:
        schema = WORKSPACE / "pipeline" / "codex-decision.schema.json"
        base = {
            "decision": "diagnostics", "rationale": "Need the unpacked JNI target.",
            "changes_made": [], "evidence_used": ["observations.json"],
            "remaining_risks": ["Runtime code is not yet attributed."],
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

    @patch("ui.app.codex_model_catalog", return_value={"models": [{
        "id": "test-model", "reasoning_levels": [{"effort": "high"}],
    }], "source": "test"})
    @patch("ui.app.codex_authenticated", return_value=True)
    @patch("ui.app.subprocess.run")
    def test_run_assistant_persists_cited_answer_and_action(self, run, _authenticated, _catalog) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            assessment = root / "run-123"
            assessment.mkdir()
            (assessment / "report.json").write_text('{"package":"com.example"}', encoding="utf-8")
            (assessment / "codex-loop-config.json").write_text(json.dumps({
                "package": "com.example", "model": "test-model", "reasoning_mode": "single",
            }), encoding="utf-8")
            (assessment / "codex-loop-result.json").write_text('{"status":"human_review"}', encoding="utf-8")

            def complete(command, **_kwargs):
                output_path = Path(command[command.index("--output-last-message") + 1])
                output_path.write_text(json.dumps({
                    "answer": "The recorded report identifies the package.",
                    "citations": [{"path": "report.json", "note": "Package metadata"}],
                    "suggested_action": {
                        "type": "rerun", "reason": "Gather stronger runtime evidence.",
                        "additional_iterations": 4, "model": "test-model",
                        "reasoning_effort": "high", "reasoning_mode": "parallel",
                        "specialist_count": 3,
                    },
                }), encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "ok", "")

            run.side_effect = complete
            with patch("ui.app.RUNS_ROOT", root):
                turn = run_assistant_turn("run-123", {
                    "question": "Why human review?", "model": "test-model",
                    "reasoning_effort": "high",
                })
                history = assistant_history("run-123")
                manifest = artifact_manifest("run-123")
        self.assertEqual(turn["citations"][0]["path"], "report.json")
        self.assertTrue(turn["grounded"])
        self.assertIn('"package":"com.example"', run.call_args.kwargs["input"])
        self.assertEqual(turn["suggested_action"]["type"], "rerun")
        self.assertEqual(history[0]["id"], turn["id"])
        self.assertTrue(any(category["id"] == "assistant" and category["files"] for category in manifest["categories"]))

    def test_assistant_evidence_is_question_ranked_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            run = Path(temp)
            files = {
                "codex-loop-result.json": '{"status":"human_review"}',
                "result.json": '{"success":false}',
                "codex-loop-config.json": '{"package":"com.example"}',
                "logs/diagnostic-native-crashes.log": ("noise\n" * 10000) + "SIGSEGV tombstone fault address",
                "frida/bypass-level-1.js": "Java.perform(function () { console.log('hook'); });",
                "agent/iteration-4/decision.json": '{"reason":"native crash needs diagnosis"}',
            }
            for relative, content in files.items():
                path = run / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            snapshot = assistant_evidence_snapshot(run, set(files), "What caused the latest SIGSEGV crash?")
        self.assertLessEqual(snapshot["characters"], 36000)
        self.assertIn("codex-loop-result.json", snapshot["paths"])
        self.assertIn("logs/diagnostic-native-crashes.log", snapshot["paths"])
        self.assertIn("SIGSEGV", snapshot["bundle"])

    def test_artifact_browser_classifies_previews_and_downloads(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run = root / "run-123"
            (run / "frida").mkdir(parents=True)
            (run / "logs").mkdir()
            (run / "agent" / "iteration-1").mkdir(parents=True)
            (run / "ghidra").mkdir()
            (run / "report.json").write_text('{"package":"com.example"}', encoding="utf-8")
            (run / "result.json").write_text('{"success":false,"checks":[]}', encoding="utf-8")
            (run / "frida" / "bypass.js").write_text("Java.perform(() => {});", encoding="utf-8")
            (run / "logs" / "observation-logcat.log").write_text("SIGBUS", encoding="utf-8")
            (run / "agent" / "iteration-1" / "decision.json").write_text('{"decision":"continue"}', encoding="utf-8")
            (run / "ghidra" / "native-analysis.txt").write_text("function guard", encoding="utf-8")
            with patch("ui.app.RUNS_ROOT", root):
                manifest = artifact_manifest("run-123")
                categories = {item["id"]: item["files"] for item in manifest["categories"]}
                self.assertEqual(categories["hooks"][0]["path"], "frida/bypass.js")
                self.assertEqual(categories["ghidra"][0]["path"], "ghidra/native-analysis.txt")
                preview = self.client.get("/api/runs/run-123/artifacts/content?path=logs/observation-logcat.log")
                download = self.client.get("/api/runs/run-123/artifacts/download?path=frida/bypass.js")
                traversal = self.client.get("/api/runs/run-123/artifacts/content?path=../outside.txt")
            self.assertEqual(preview.status_code, 200)
            self.assertEqual(preview.get_json()["content"], "SIGBUS")
            self.assertEqual(download.status_code, 200)
            self.assertIn("attachment", download.headers["Content-Disposition"])
            download.close()
            self.assertEqual(traversal.status_code, 404)

    def test_start_requires_authorization(self) -> None:
        response = self.client.post("/api/start", json={})
        self.assertEqual(response.status_code, 400)
        self.assertIn("authorization", response.get_json()["error"].lower())

    @patch("ui.app.success_policy")
    @patch("ui.app.resolve_workspace_item")
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

    @patch("ui.app.success_policy")
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

    @patch("ui.app.subprocess.run")
    def test_wireless_pairing_sends_code_over_stdin(self, run) -> None:
        run.return_value = subprocess.CompletedProcess([], 0, "Successfully paired", "")
        with tempfile.TemporaryDirectory() as temp, patch(
            "ui.app.WIRELESS_DEVICES_PATH", Path(temp) / "wireless-devices.json",
        ):
            response = self.client.post(
                "/api/devices/pair",
                json={"endpoint": "192.168.1.20:37001", "code": "123456"},
            )
            stored = (Path(temp) / "wireless-devices.json").read_text(encoding="utf-8")
        self.assertEqual(response.status_code, 200)
        command = run.call_args_list[0].args[0]
        self.assertEqual(command, ["adb", "pair", "192.168.1.20:37001"])
        self.assertNotIn("123456", command)
        self.assertEqual(run.call_args_list[0].kwargs["input"], "123456\n")
        self.assertNotIn("123456", stored)
        self.assertIn("192.168.1.20:37001", stored)

    def test_new_pairing_invalidates_stale_connection_for_same_host(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            registry = Path(temp) / "wireless-devices.json"
            registry.write_text(json.dumps({"devices": [{
                "id": "known-phone", "host": "192.168.1.20",
                "pairing_endpoint": "192.168.1.20:37001",
                "paired_utc": "2026-10-30T00:00:00+00:00",
                "connection_endpoint": "192.168.1.20:41993",
                "last_connected_utc": "2026-10-30T01:00:00+00:00",
            }]}), encoding="utf-8")
            with patch("ui.app.WIRELESS_DEVICES_PATH", registry):
                record_wireless_device(pairing_endpoint="192.168.1.20:39725")
                stored = json.loads(registry.read_text(encoding="utf-8"))["devices"][0]
        self.assertEqual(stored["pairing_endpoint"], "192.168.1.20:39725")
        self.assertNotIn("connection_endpoint", stored)
        self.assertNotIn("last_connected_utc", stored)

    def test_newer_pairing_hides_legacy_connection_until_rediscovered(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            registry = Path(temp) / "wireless-devices.json"
            registry.write_text(json.dumps({"devices": [{
                "id": "known-phone", "host": "192.168.1.20",
                "pairing_endpoint": "192.168.1.20:39725",
                "paired_utc": "2026-11-01T01:06:05+00:00",
                "connection_endpoint": "192.168.1.20:38501",
                "last_connected_utc": "2026-10-31T15:43:39+00:00",
            }]}), encoding="utf-8")
            with patch("ui.app.WIRELESS_DEVICES_PATH", registry):
                device = wireless_device_view([], [])[0]
        self.assertEqual(device["endpoint"], "")
        self.assertTrue(device["connection_required"])
        self.assertEqual(device["pairing_endpoint"], "192.168.1.20:39725")

    @patch("ui.app.subprocess.run")
    def test_device_discovery_distinguishes_previously_paired_and_discovered(self, run) -> None:
        run.side_effect = [
            subprocess.CompletedProcess([], 0, "List of devices attached\n", ""),
            subprocess.CompletedProcess([], 0, "List of discovered mdns services\nadb-phone _adb-tls-connect._tcp 192.168.1.20:41993\n", ""),
        ]
        with tempfile.TemporaryDirectory() as temp:
            registry = Path(temp) / "wireless-devices.json"
            registry.write_text(json.dumps({"devices": [{
                "id": "known-phone", "host": "192.168.1.20",
                "pairing_endpoint": "192.168.1.20:37001", "paired_utc": "2026-10-30T00:00:00+00:00",
            }]}), encoding="utf-8")
            with patch("ui.app.WIRELESS_DEVICES_PATH", registry):
                response = self.client.get("/api/devices")
        payload = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["wireless_devices"][0]["status"], "previously_paired")
        self.assertEqual(payload["wireless_devices"][0]["endpoint"], "192.168.1.20:41993")
        self.assertTrue(payload["wireless_devices"][0]["connectable"])

    def test_wireless_pairing_rejects_invalid_code(self) -> None:
        response = self.client.post(
            "/api/devices/pair",
            json={"endpoint": "192.168.1.20:37001", "code": "1234"},
        )
        self.assertEqual(response.status_code, 400)

    @patch("ui.app.subprocess.run")
    def test_device_readiness_returns_bound_token(self, run) -> None:
        def result(command, **_kwargs):
            rendered = " ".join(command)
            if command[:2] == ["frida", "--version"]:
                output = "16.7.19\n"
            elif command[0] == "frida-ps":
                output = "PID  Name\n1    system_server\n"
            elif "get-state" in command:
                output = "device\n"
            elif "ro.product.cpu.abi" in command:
                output = "arm64-v8a\n"
            elif "ro.build.version.sdk" in command:
                output = "35\n"
            elif rendered.endswith("su -c id"):
                output = "uid=0(root) gid=0(root)\n"
            elif "--version" in command[-1]:
                output = "16.7.19\n"
            elif "getenforce" in command:
                output = "Enforcing\n"
            else:
                output = "ok\n"
            return subprocess.CompletedProcess(command, 0, output, "")

        run.side_effect = result
        response = self.client.post("/api/devices/readiness", data={
            "transport": "adb", "target": "emulator-5554",
            "frida_server": "/data/local/tmp/frida-server",
            "start_frida": "false", "authorized": "false",
        })
        payload = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(payload["ready"])
        self.assertRegex(payload["token"], r"^[a-f0-9]{32}$")
        self.assertEqual(payload["abi"], "arm64-v8a")

    def test_device_readiness_requires_authorization_to_start_frida(self) -> None:
        response = self.client.post("/api/devices/readiness", data={
            "transport": "adb", "target": "emulator-5554",
            "frida_server": "/data/local/tmp/frida-server",
            "start_frida": "true", "authorized": "false",
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("authorization", response.get_json()["error"].lower())

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

    @patch("ui.app.codex_authenticated", return_value=True)
    @patch("ui.app.read_connected_account_models", side_effect=RuntimeError("catalog unavailable"))
    @patch("ui.app.read_codex_models")
    def test_model_catalog_uses_codex_app_server(self, read_models, read_account, authenticated) -> None:
        read_models.return_value = [{
            "id": "test-model", "model": "test-model",
            "displayName": "Test Model", "isDefault": True,
        }]
        catalog = codex_model_catalog(force=True)
        self.assertEqual(catalog["source"], "codex_app_server")
        self.assertEqual(catalog["models"][0]["id"], "test-model")
        self.assertTrue(catalog["models"][0]["is_default"])

    @patch("ui.app.codex_authenticated", return_value=False)
    @patch("ui.app.read_codex_models")
    def test_model_catalog_requires_connected_account(self, read_models, authenticated) -> None:
        catalog = codex_model_catalog(force=True)
        self.assertEqual(catalog, {"models": [], "source": "authentication_required"})
        read_models.assert_not_called()

    @patch("ui.app.codex_authenticated", return_value=True)
    @patch("ui.app.read_connected_account_models")
    @patch("ui.app.read_codex_models")
    def test_model_catalog_prefers_connected_account(self, read_local, read_account, authenticated) -> None:
        read_account.return_value = [{
            "id": "account-model", "display_name": "Account Model", "is_default": False,
            "reasoning_levels": [{"effort": "high", "description": "Deep reasoning"}],
            "default_reasoning_effort": "high",
        }]
        read_local.return_value = [{
            "id": "account-model", "model": "account-model",
            "displayName": "Account Model", "isDefault": True,
            "defaultReasoningEffort": "high",
        }]
        catalog = codex_model_catalog(force=True)
        self.assertEqual(catalog["source"], "connected_chatgpt_account")
        self.assertEqual(catalog["models"][0]["id"], "account-model")
        self.assertTrue(catalog["models"][0]["is_default"])
        read_local.assert_called_once()

    @patch("ui.app.resolve_workspace_item")
    def test_resume_accepts_thinking_level(self, resolve) -> None:
        run = WORKSPACE / "runs" / "example"
        resolve.return_value = run
        _, request = parse_resume({
            "authorized": True, "run": "runs/example", "max_iterations": 2,
            "reasoning_effort": "xhigh",
        })
        self.assertEqual(request["reasoning_effort"], "xhigh")

    @patch("ui.app.resolve_workspace_item")
    def test_resume_accepts_claude_provider(self, resolve) -> None:
        resolve.return_value = WORKSPACE / "runs" / "example"
        _, request = parse_resume({
            "authorized": True, "run": "runs/example", "max_iterations": 2,
            "provider": "claude", "model": "sonnet", "reasoning_effort": "high",
        })
        self.assertEqual(request["provider"], "claude")
        self.assertEqual(request["model"], "sonnet")

    @patch("ui.app.json_file")
    @patch("ui.app.resolve_workspace_item")
    def test_resume_rejects_policy_from_another_run(self, resolve, read_json) -> None:
        resolve.return_value = WORKSPACE / "runs" / "example"
        read_json.return_value = {"success_spec_sha256": "a" * 64}
        with self.assertRaisesRegex(ValueError, "does not match"):
            parse_resume({
                "authorized": True, "run": "runs/example", "max_iterations": 2,
                "success_spec_sha256": "b" * 64,
            })

    @patch("ui.app.resolve_workspace_item")
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

    @patch("ui.app.resolve_workspace_item")
    def test_retry_requires_completed_run(self, resolve) -> None:
        resolve.return_value = WORKSPACE / "runs" / "unfinished"
        with self.assertRaisesRegex(ValueError, "completed assessment"):
            parse_retry({"authorized": True, "run": "runs/unfinished", "max_iterations": 1})

    @patch("ui.app.resolve_workspace_item")
    def test_resume_accepts_parallel_specialists(self, resolve) -> None:
        resolve.return_value = WORKSPACE / "runs" / "example"
        _, request = parse_resume({
            "authorized": True, "run": "runs/example", "max_iterations": 2,
            "reasoning_mode": "parallel", "specialist_count": 2,
        })
        self.assertEqual(request["reasoning_mode"], "parallel")
        self.assertEqual(request["specialist_count"], 2)

    @patch("ui.app.resolve_workspace_item")
    def test_resume_rejects_invalid_parallel_specialist_count(self, resolve) -> None:
        resolve.return_value = WORKSPACE / "runs" / "example"
        with self.assertRaisesRegex(ValueError, "specialist count"):
            parse_resume({
                "authorized": True, "run": "runs/example", "max_iterations": 2,
                "reasoning_mode": "parallel", "specialist_count": 8,
            })

    @patch("ui.app.resolve_workspace_item")
    def test_resume_accepts_device_frida_server_path(self, resolve) -> None:
        resolve.return_value = WORKSPACE / "runs" / "example"
        _, request = parse_resume({
            "authorized": True, "run": "runs/example", "max_iterations": 2,
            "frida_server": "/data/local/tmp/frida-server-17.5.1",
        })
        self.assertEqual(request["frida_server"], "/data/local/tmp/frida-server-17.5.1")

    @patch("ui.app.json_file")
    @patch("ui.app.resolve_workspace_item")
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

    @patch("ui.app.json_file")
    @patch("ui.app.resolve_workspace_item")
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

    @patch("ui.app.resolve_workspace_item")
    def test_resume_rejects_unsafe_frida_server_path(self, resolve) -> None:
        resolve.return_value = WORKSPACE / "runs" / "example"
        with self.assertRaisesRegex(ValueError, "Frida Server path"):
            parse_resume({
                "authorized": True, "run": "runs/example", "max_iterations": 2,
                "frida_server": "/data/local/tmp/frida-server; reboot",
            })

    @patch("ui.app.resolve_workspace_item")
    def test_resume_rejects_unknown_thinking_level(self, resolve) -> None:
        resolve.return_value = WORKSPACE / "runs" / "example"
        with self.assertRaisesRegex(ValueError, "thinking level"):
            parse_resume({
                "authorized": True, "run": "runs/example", "max_iterations": 2,
                "reasoning_effort": "infinite",
            })

    def test_codex_reasoning_effort_is_quoted_config_override(self) -> None:
        self.assertEqual(
            codex_reasoning_args({"reasoning_effort": "high"}),
            ["--config", 'model_reasoning_effort="high"'],
        )
        self.assertEqual(codex_reasoning_args({}), [])

    def test_codex_multi_agent_feature_is_explicit_per_mode(self) -> None:
        self.assertEqual(codex_multi_agent_args({"reasoning_mode": "parallel"}), ["--enable", "multi_agent"])
        self.assertEqual(codex_multi_agent_args({"reasoning_mode": "single"}), ["--disable", "multi_agent"])

    def test_parallel_prompt_bounds_specialists_and_writes(self) -> None:
        run = WORKSPACE / "runs" / "example"
        prompt = LoopRunner._prompt(
            run, run / "agent" / "iteration-1" / "candidate.js", None, 1, 1, 3,
            reasoning_mode="parallel", specialist_count=3,
        )
        self.assertIn("no more than 3 read-only subagents", prompt)
        self.assertIn("root agent is the only writer", prompt)
        self.assertIn("native specialist", prompt)
        self.assertIn("decision `diagnostics`", prompt)
        self.assertIn("dump_runtime_payloads", prompt)
        self.assertIn("At most 2 diagnostic rounds", prompt)

    @patch("ui.orchestrator.run_logged")
    def test_adaptive_diagnostic_worker_uses_allowlisted_pipeline_action(self, run_logged) -> None:
        with tempfile.TemporaryDirectory(dir=WORKSPACE) as temp:
            run = Path(temp)
            iteration = run / "agent" / "iteration-2"
            iteration.mkdir(parents=True)

            def execute(command, _log, **_kwargs):
                manifest = run / "diagnostics" / "pass-1" / "manifest.json"
                manifest.parent.mkdir(parents=True)
                manifest.write_text(json.dumps({
                    "events": [{"kind": "jni-registration"}],
                    "artifacts": [], "errors": [],
                }), encoding="utf-8")
                self.assertIn("--diagnostic-actions", command)
                self.assertIn("trace_jni_registration", command)
                return 0, ""

            run_logged.side_effect = execute
            result = LoopRunner(StringIO())._run_adaptive_diagnostics(
                run,
                {
                    "transport": "adb", "target": "serial", "package": "com.example",
                    "observation_seconds": 15, "start_frida_server": "",
                },
                iteration, 2, ["trace_jni_registration"],
            )
            self.assertEqual(result["event_count"], 1)
            self.assertEqual(result["actions"], ["trace_jni_registration"])

    @patch("ui.orchestrator.run_logged", return_value=(0, ""))
    @patch("ui.orchestrator.provider_adapter")
    def test_native_selection_is_provider_chosen_bounded_and_extracted(self, adapter_factory, _run_logged) -> None:
        class FakeAdapter:
            label = "Codex"

            @staticmethod
            def prepare(request):
                return ["codex", "exec"], request.prompt

            @staticmethod
            def finalize(request, _exit_code, _output):
                if request.schema_path.name == "native-replenishment.schema.json":
                    request.output_path.write_text(json.dumps({
                        "rationale": "The first batch implicated a later JNI stage.",
                        "evidence_used": ["agent/iteration-1/record.json"],
                        "added": [{
                            "library": "liblater.so", "priority": "medium",
                            "reason": "JNI evidence links it to the unresolved startup stage.",
                            "cross_abi": None,
                        }],
                    }), encoding="utf-8")
                    return True
                request.output_path.write_text(json.dumps({
                    "rationale": "Application startup explicitly loads the protection library.",
                    "evidence_used": ["ProtectedApplication.java System.loadLibrary call"],
                    "selected": [{
                        "library": "libdexprotector.so",
                        "priority": "high",
                        "reason": "Loaded by protected application startup before the crash.",
                        "cross_abi": {
                            "abis": ["x86_64"],
                            "reason": "Compare exported detector behavior across architectures.",
                        },
                    }],
                    "queued": [{
                        "library": "libnext.so",
                        "priority": "medium",
                        "reason": "Loaded later in the protected application lifecycle.",
                        "cross_abi": None,
                    }],
                }), encoding="utf-8")
                return True

        adapter_factory.return_value = FakeAdapter()
        with tempfile.TemporaryDirectory(dir=WORKSPACE) as temp:
            run = Path(temp)
            payload = b"native-protection-library"
            x86_payload = b"native-protection-library-x86"
            next_payload = b"next-native-library"
            later_payload = b"later-native-library"
            with zipfile.ZipFile(run / "original.apk", "w") as archive:
                archive.writestr("lib/arm64-v8a/libdexprotector.so", payload)
                archive.writestr("lib/x86_64/libdexprotector.so", x86_payload)
                archive.writestr("lib/arm64-v8a/libnext.so", next_payload)
                archive.writestr("lib/arm64-v8a/liblater.so", later_payload)
            (run / "report.json").write_text(json.dumps({
                "native_libraries": [{
                    "archive_path": "lib/arm64-v8a/libdexprotector.so",
                    "abi": "arm64-v8a", "name": "libdexprotector.so",
                    "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
                    "load_references": ["sources/ProtectedApplication.java"],
                }, {
                    "archive_path": "lib/x86_64/libdexprotector.so",
                    "abi": "x86_64", "name": "libdexprotector.so",
                    "size": len(x86_payload), "sha256": hashlib.sha256(x86_payload).hexdigest(),
                    "load_references": ["sources/ProtectedApplication.java"],
                }, {
                    "archive_path": "lib/arm64-v8a/libnext.so",
                    "abi": "arm64-v8a", "name": "libnext.so",
                    "size": len(next_payload), "sha256": hashlib.sha256(next_payload).hexdigest(),
                    "load_references": ["sources/ProtectedApplication.java"],
                }, {
                    "archive_path": "lib/arm64-v8a/liblater.so",
                    "abi": "arm64-v8a", "name": "liblater.so",
                    "size": len(later_payload), "sha256": hashlib.sha256(later_payload).hexdigest(),
                    "load_references": ["sources/LaterStage.java"],
                }],
            }), encoding="utf-8")
            (run / "result.json").write_text(json.dumps({"device_abi": "arm64-v8a"}), encoding="utf-8")
            selection = LoopRunner(StringIO())._ensure_native_selection(run, {
                "provider": "codex", "model": "test-model", "reasoning_effort": "high",
            })
            extracted = WORKSPACE / selection["selected"][0]["primary"]["extracted"]
            self.assertEqual(extracted.read_bytes(), payload)
            self.assertEqual(selection["selected"][0]["priority"], "high")
            comparison = WORKSPACE / selection["selected"][0]["cross_abi"]["variants"][0]["extracted"]
            self.assertEqual(comparison.read_bytes(), x86_payload)
            self.assertEqual(len(selection["selected"]), 1)
            self.assertEqual(len(selection["queue"]), 1)

            opened: set[str] = set()

            def fake_ghidra(method, path, body=None):
                if path == "/list_open_programs":
                    return {"programs": [
                        {"name": name, "path": f"/{name}", "is_current": index == 0}
                        for index, name in enumerate(sorted(opened))
                    ]}
                if path == "/open_program":
                    opened.add(body["path"])
                    return {"success": True, "name": body["path"]}
                if path == "/import_file":
                    name = Path(body["file_path"]).name
                    opened.add(name)
                    return {"success": True, "data": {
                        "name": name, "analyzing": True,
                    }}
                return {"success": True, "data": {"analyzing": False, "function_count": 42}}

            with patch("ui.orchestrator.ghidra_request", side_effect=fake_ghidra) as ghidra:
                preparation = LoopRunner._prepare_ghidra_batch(run)
                cached = LoopRunner._prepare_ghidra_batch(run)
            self.assertEqual(preparation["status"], "complete")
            self.assertEqual(len(preparation["programs"]), 2)
            self.assertTrue(all(item["function_count"] == 42 for item in preparation["programs"]))
            self.assertTrue(all(item["mcp_ready"] for item in preparation["programs"]))
            self.assertEqual(cached["status"], preparation["status"])
            self.assertEqual(cached["programs"], preparation["programs"])
            self.assertEqual(ghidra.call_count, 8)
            self.assertTrue(LoopRunner(StringIO())._replenish_native_queue(run, {
                "provider": "codex", "model": "test-model", "reasoning_effort": "high",
            }, 1))
            self.assertTrue(LoopRunner(StringIO())._advance_native_queue(run, 1, "policy_failed"))
            advanced = json.loads((run / "native-selection.json").read_text(encoding="utf-8"))
            self.assertEqual(advanced["selected"][0]["library"], "libnext.so")
            self.assertEqual(advanced["selected"][1]["library"], "liblater.so")
            self.assertEqual(advanced["batches"][0]["status"], "inconclusive")
            self.assertEqual(advanced["batches"][1]["status"], "active")
            self.assertEqual((WORKSPACE / advanced["selected"][0]["primary"]["extracted"]).read_bytes(), next_payload)
            self.assertEqual(advanced["replenishments"][0]["libraries"], ["liblater.so"])
            self.assertFalse(LoopRunner(StringIO())._advance_native_queue(run, 2, "policy_failed"))
            exhausted = json.loads((run / "native-selection.json").read_text(encoding="utf-8"))
            self.assertEqual(exhausted["selected"], [])
            self.assertEqual(exhausted["queue_status"], "exhausted")
            self.assertTrue((run / "native-selection.json").is_file())

    def test_auth_output_strips_terminal_controls(self) -> None:
        value = "\x1b[94mhttps://auth.openai.com/codex/device\x1b[0m\r\n\x1b[90mABCD-EFGHIJ\x1b[0m"
        self.assertEqual(
            strip_terminal_controls(value),
            "https://auth.openai.com/codex/device\nABCD-EFGHIJ",
        )

    def test_timeout_output_accepts_bytes_for_visible_failure(self) -> None:
        self.assertEqual(subprocess_capture_text(b"partial\r\n", b"error\n"), "partial\nerror\n")

    @patch("ui.app.subprocess.run")
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
        self.assertFalse(checkpoint_recovery_available({
            "status": "human_review", "recoverable": False,
            "checkpoint": None,
        }))

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


if __name__ == "__main__":
    unittest.main()
