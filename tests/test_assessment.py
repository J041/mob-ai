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
    frida_recovery_available, terminal_outcome, usage_limit_recovery_available,
    validate_decision_schema_registry,
)
from assessment.runtime import adb_transport_detail
from backend.providers import ProviderRequest, detect_usage_limit, provider_adapter, validate_provider_output


class AssessmentTests(unittest.TestCase):
    def setUp(self) -> None:
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def test_codex_reasoning_effort_is_quoted_config_override(self) -> None:
        self.assertEqual(
            codex_reasoning_args({"reasoning_effort": "high"}),
            ["--config", 'model_reasoning_effort="high"'],
        )
        self.assertEqual(codex_reasoning_args({}), [])

    def test_codex_multi_agent_feature_is_explicit_per_mode(self) -> None:
        self.assertEqual(codex_multi_agent_args({"reasoning_mode": "parallel"}), ["--enable", "multi_agent"])
        self.assertEqual(codex_multi_agent_args({"reasoning_mode": "single"}), ["--disable", "multi_agent"])

    def test_adb_disconnect_marker_becomes_recoverable_detail(self) -> None:
        output = (
            'MOB_AI_ADB_TRANSPORT_ERROR '
            '{"device":"10.0.0.2:37123","reason":"adb: device offline",'
            '"command":"shell am force-stop com.example"}\n'
        )
        detail, reason = adb_transport_detail(output, "fallback")
        self.assertEqual(reason, "device_transport_failure")
        self.assertIn("10.0.0.2:37123", detail)
        self.assertIn("recover this checkpoint", detail)

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
        self.assertIn("detector_inputs", prompt)
        self.assertIn("enforcement_sinks", prompt)
        self.assertIn("Failure or missing telemetry from one Java hook", prompt)
        self.assertIn("Before returning human_review", prompt)

    @patch("assessment.orchestrator.run_logged")
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

    @patch("assessment.native.run_logged", return_value=(0, ""))
    @patch("assessment.native.provider_adapter")
    @patch("assessment.native_queue.run_logged", return_value=(0, ""))
    @patch("assessment.native_queue.provider_adapter")
    def test_native_selection_is_provider_chosen_bounded_and_extracted(
        self, queue_adapter_factory, _queue_run_logged, adapter_factory, _run_logged,
    ) -> None:
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
        queue_adapter_factory.return_value = FakeAdapter()
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

            with patch("assessment.ghidra.ghidra_request", side_effect=fake_ghidra) as ghidra:
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



if __name__ == "__main__":
    unittest.main()
