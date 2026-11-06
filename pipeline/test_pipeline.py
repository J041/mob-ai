import argparse
import json
import subprocess
import sys
import tempfile
import types
from pathlib import Path
import unittest
import zipfile
from unittest import mock

import pipeline

try:
    from pipeline.diagnostic_recipes import (
        BOUNDED_CAPTURE, DIAGNOSTIC_ACTIONS, DIAGNOSTIC_RECIPES,
        diagnostic_recipe_catalog,
    )
except ModuleNotFoundError:
    from diagnostic_recipes import (  # type: ignore
        BOUNDED_CAPTURE, DIAGNOSTIC_ACTIONS, DIAGNOSTIC_RECIPES,
        diagnostic_recipe_catalog,
    )


class PipelineTests(unittest.TestCase):
    def test_adaptive_diagnostic_actions_are_allowlisted_and_bounded(self):
        self.assertEqual(
            pipeline.parse_diagnostic_actions("trace_jni_registration,capture_native_exceptions"),
            ["trace_jni_registration", "capture_native_exceptions"],
        )
        with self.assertRaisesRegex(RuntimeError, "Unsupported diagnostic actions"):
            pipeline.parse_diagnostic_actions("shell_command")
        with self.assertRaisesRegex(RuntimeError, "at most 3"):
            pipeline.parse_diagnostic_actions(
                "trace_jni_registration,capture_native_exceptions,trace_termination_calls,inventory_executable_mappings"
            )
        self.assertEqual(
            pipeline.parse_diagnostic_actions(
                "compare_launch_modes,late_attach_observer,trace_dynamic_loading"
            ),
            ["compare_launch_modes", "late_attach_observer", "trace_dynamic_loading"],
        )

    def test_diagnostic_recipe_registry_has_complete_metadata(self):
        catalog = diagnostic_recipe_catalog()
        self.assertEqual(set(DIAGNOSTIC_RECIPES), set(DIAGNOSTIC_ACTIONS))
        self.assertEqual(len(catalog), len(DIAGNOSTIC_ACTIONS))
        for recipe in catalog:
            self.assertIn(recipe["invasiveness"], {"low", "moderate", "high"})
            self.assertTrue(recipe["prerequisites"])
            self.assertTrue(recipe["ui_description"])
            self.assertEqual(recipe["artifact_limits"]["scope"], "shared_pass")
        self.assertEqual(pipeline.DIAGNOSTIC_MAX_DUMPS, BOUNDED_CAPTURE.max_artifacts)
        self.assertEqual(pipeline.DIAGNOSTIC_MAX_DUMP_BYTES, BOUNDED_CAPTURE.max_artifact_bytes)
        self.assertEqual(pipeline.DIAGNOSTIC_MAX_TOTAL_BYTES, BOUNDED_CAPTURE.max_total_bytes)

    def test_structured_decision_schema_matches_recipe_registry(self):
        schema = json.loads((Path(__file__).parent / "codex-decision.schema.json").read_text(encoding="utf-8"))
        values = schema["properties"]["diagnostic_actions"]["items"]["enum"]
        self.assertEqual(set(values), set(DIAGNOSTIC_ACTIONS))
        self.assertEqual(len(values), len(DIAGNOSTIC_ACTIONS))
        coverage = schema["properties"]["control_point_coverage"]
        stages = coverage["items"]["properties"]["stage"]["enum"]
        self.assertEqual(coverage["minItems"], len(stages))
        self.assertEqual(coverage["maxItems"], len(stages))
        self.assertEqual(len(stages), len(set(stages)))

    def test_process_mapping_parser_preserves_executable_memfd(self):
        mappings = pipeline.parse_process_mappings(
            "7a1000-7a3000 r-xp 00000000 00:01 42 /memfd:payload (deleted)\n"
        )
        self.assertEqual(len(mappings), 1)
        self.assertEqual(mappings[0]["start"], 0x7A1000)
        self.assertEqual(mappings[0]["size"], 0x2000)
        self.assertEqual(mappings[0]["path"], "/memfd:payload (deleted)")

    def test_embedded_dex_payload_is_carved_from_selected_library(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "loader.so"
            dex = bytearray(112)
            dex[:8] = b"dex\n035\0"
            dex[32:36] = (112).to_bytes(4, "little")
            path.write_bytes(b"loader-prefix" + bytes(dex) + b"trailer")
            candidates = pipeline.embedded_payload_candidates(path)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0][0], len(b"loader-prefix"))
        self.assertEqual(candidates[0][1], bytes(dex))
        self.assertEqual(candidates[0][2], "dex")

    def test_adaptive_diagnostics_store_bounded_runtime_artifact(self):
        class FakeScript:
            def __init__(self):
                self.callback = None

            def on(self, _event, callback):
                self.callback = callback

            def load(self):
                assert self.callback is not None
                self.callback({
                    "type": "send",
                    "payload": {
                        "source": "mob-ai-diagnostics", "kind": "runtime-payload",
                        "detail": {"address": "0x1000", "reason": "mprotect"},
                    },
                }, b"ELF payload")

        class FakeSession:
            def create_script(self, _source):
                return FakeScript()

            def detach(self):
                pass

        class FakeDevice:
            def spawn(self, _package):
                return 123

            def attach(self, _pid):
                return FakeSession()

            def resume(self, _pid):
                pass

        fake_frida = types.SimpleNamespace(
            get_device_manager=lambda: types.SimpleNamespace(
                add_remote_device=lambda _endpoint: FakeDevice()
            )
        )
        args = argparse.Namespace(
            device="serial", frida_endpoint="127.0.0.1:27042", observation_seconds=0,
        )
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            response = subprocess.CompletedProcess([], 0, "diagnostic output", None)
            with mock.patch.dict(sys.modules, {"frida": fake_frida}), \
                    mock.patch.object(pipeline, "adb", return_value=response):
                manifest_path = pipeline.run_adaptive_diagnostics(
                    args, run_dir, "com.example", ["dump_runtime_payloads"],
                )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            artifact = manifest["artifacts"][0]
            self.assertEqual(manifest["recipes"][0]["name"], "dump_runtime_payloads")
            self.assertEqual(manifest["recipes"][0]["invasiveness"], "high")
            self.assertEqual(manifest["recipes"][0]["artifact_limits"]["scope"], "shared_pass")
            self.assertEqual(artifact["size"], len(b"ELF payload"))
            self.assertEqual((run_dir / artifact["path"]).read_bytes(), b"ELF payload")
            self.assertEqual((manifest_path.parent / "logcat.log").read_text(encoding="utf-8"), "diagnostic output")
            self.assertEqual((manifest_path.parent / "exit-info.log").read_text(encoding="utf-8"), "diagnostic output")

    def test_prepare_reuses_static_artifacts_for_identical_apk(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runs = root / "runs"
            runs.mkdir()
            source = root / "source-run"
            (source / "jadx").mkdir(parents=True)
            (source / "native").mkdir()
            apk = root / "sample.apk"
            apk.write_bytes(b"PK\x03\x04same-apk")
            (source / "original.apk").write_bytes(apk.read_bytes())
            (source / "jadx" / "Detector.java").write_text("class Detector {}", encoding="utf-8")
            (source / "native" / "libguard.so").write_bytes(b"native")
            (source / "report.json").write_text(json.dumps({
                "package": "com.example", "findings": [{"kind": "root_check"}],
                "native_libraries": [],
                "sha256": pipeline.sha256(apk),
            }), encoding="utf-8")
            with mock.patch.object(pipeline, "run") as run:
                run_dir, report = pipeline.prepare(apk, runs, source)
            run.assert_not_called()
            self.assertEqual(report["package"], "com.example")
            self.assertTrue((run_dir / "jadx" / "Detector.java").is_file())
            self.assertTrue((run_dir / "native" / "libguard.so").is_file())
            self.assertEqual(report["static_reused_from"], str(source.resolve()))

    def test_find_package_and_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            resources = root / "resources"
            resources.mkdir()
            (resources / "AndroidManifest.xml").write_text('<manifest package="com.example.lab"/>', encoding="utf-8")
            (root / "Detector.java").write_text('RootBeer root; Debug.isDebuggerConnected();', encoding="utf-8")
            self.assertEqual(pipeline.find_package(root), "com.example.lab")
            kinds = {item["kind"] for item in pipeline.scan(root)}
            self.assertEqual(kinds, {"root_framework", "debugger"})

    def test_native_scan_inventories_all_libraries_without_string_selection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            apk = root / "sample.apk"
            decoded = root / "decoded"
            source = decoded / "sources" / "Example.java"
            source.parent.mkdir(parents=True)
            source.write_text('class Example { void load() { System.loadLibrary("clean"); } }', encoding="utf-8")
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("lib/arm64-v8a/libguard.so", b"prefix TracerPid suffix")
                archive.writestr("lib/arm64-v8a/libclean.so", b"nothing interesting")
                archive.writestr("lib/x86_64/libclean.so", b"same logical library, other ABI")
            libraries = pipeline.scan_native(apk, decoded)
            self.assertEqual([item["name"] for item in libraries], ["libclean.so", "libguard.so", "libclean.so"])
            clean = next(item for item in libraries if item["name"] == "libclean.so")
            self.assertEqual(clean["load_references"], ["sources/Example.java"])
            self.assertNotIn("matches", clean)
            groups = pipeline.group_native_libraries(libraries)
            self.assertEqual([item["library"] for item in groups], ["libclean.so", "libguard.so"])
            clean_group = next(item for item in groups if item["library"] == "libclean.so")
            self.assertEqual([item["abi"] for item in clean_group["variants"]], ["arm64-v8a", "x86_64"])

    def test_generated_hooks_preserve_manual_edits(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            scripts = pipeline.make_frida_scripts(run_dir, 3)
            self.assertEqual(len(scripts), 3)
            self.assertNotIn("{{LEVEL}}", scripts[0].read_text(encoding="utf-8"))
            scripts[0].write_text("manual", encoding="utf-8")
            pipeline.make_frida_scripts(run_dir, 3)
            self.assertEqual(scripts[0].read_text(encoding="utf-8"), "manual")
            pipeline.make_frida_scripts(run_dir, 3, {"properties"})
            self.assertEqual(scripts[0].read_text(encoding="utf-8"), "manual")

    def test_generated_hooks_adapt_when_unedited(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            scripts = pipeline.make_frida_scripts(run_dir, 3, {"properties"})
            self.assertIn('["properties"]', scripts[0].read_text(encoding="utf-8"))
            pipeline.make_frida_scripts(run_dir, 3, {"anti-frida"})
            self.assertIn('["anti-frida"]', scripts[2].read_text(encoding="utf-8"))
            plan = json.loads((run_dir / "adaptive-plan.json").read_text(encoding="utf-8"))
            self.assertEqual(plan["selected_modules"], ["anti-frida"])

    def test_observation_events_drive_modules(self):
        output = 'noise\nMOB_AI_EVENT {"source":"mob-ai-observe","kind":"native-file","detail":"open:/system/bin/su"}\n'
        events = pipeline.parse_observation_events(output)
        self.assertEqual(len(events), 1)
        self.assertEqual(pipeline.infer_modules({"findings": []}, events), {"native-files"})

    def test_observation_diagnostics_capture_crash_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            (run_dir / "logs").mkdir()
            observer = run_dir / "observer.js"
            observer.write_text("'use strict';", encoding="utf-8")
            args = argparse.Namespace(
                device="serial", frida_endpoint="127.0.0.1:27042",
                observation_seconds=1, diagnostics=True,
            )

            def fake_run(command, **_kwargs):
                return subprocess.CompletedProcess(command, 0, "MOB_AI_EVENT {\"kind\":\"ready\"}\n", "")

            def fake_adb(_args, *command, **_kwargs):
                return subprocess.CompletedProcess(command, 0, " ".join(command), "")

            with mock.patch.object(pipeline, "install_observer", return_value=observer), \
                    mock.patch.object(pipeline, "run", side_effect=fake_run), \
                    mock.patch.object(pipeline, "adb", side_effect=fake_adb):
                result = pipeline.run_observation(args, run_dir, "com.example")

            self.assertEqual(set(result["diagnostics"]), {"crash_buffer", "exit_info", "native_crashes", "tombstone_access"})
            self.assertTrue((run_dir / "logs" / "diagnostic-crash-buffer.log").is_file())
            observations = json.loads((run_dir / "observations.json").read_text(encoding="utf-8"))
            self.assertIn("exit_info", observations["diagnostics"])

    def test_timeout_output_decodes_bytes(self):
        error = subprocess.TimeoutExpired(["frida"], 1, output=b"MOB_AI_EVENT {}\n")
        self.assertEqual(pipeline.timeout_output(error), "MOB_AI_EVENT {}\n")

    def test_structured_success_policy(self):
        args = argparse.Namespace(device="serial", success_regex=None)
        spec = {
            "mode": "all",
            "checks": [
                {"type": "process_alive"},
                {"type": "foreground_package"},
                {"type": "log_not_regex", "pattern": "FATAL EXCEPTION"},
                {"type": "frida_regex", "pattern": "ready"},
            ],
        }
        responses = [
            subprocess.CompletedProcess([], 0, "1234\n"),
            subprocess.CompletedProcess([], 0, "mResumedActivity: com.example.lab/.MainActivity\n"),
        ]
        with mock.patch.object(pipeline, "adb", side_effect=responses):
            passed, checks = pipeline.evaluate_success(args, "com.example.lab", "ready", "healthy", spec)
        self.assertTrue(passed)
        self.assertTrue(all(check["passed"] for check in checks))

    def test_no_crash_policy_detects_native_fatal_signal(self):
        args = argparse.Namespace(device="serial", success_regex=None)
        spec = {"mode": "all", "checks": [{"type": "no_crash"}]}
        passed, checks = pipeline.evaluate_success(
            args, "com.example", "", "Fatal signal 11 (SIGSEGV), code 1", spec,
        )
        self.assertFalse(passed)
        self.assertFalse(checks[0]["passed"])

    def test_success_policy_v2_repeat_and_ui_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "policy.json"
            path.write_text(json.dumps({
                "mode": "all",
                "baseline_required": True,
                "repeat": 2,
                "min_passes": 2,
                "checks": [
                    {"type": "no_crash"},
                    {"type": "activity_reached", "activity": ".HomeActivity"},
                    {"type": "ui_text_regex", "pattern": "Welcome"},
                    {"type": "ui_text_not_regex", "pattern": "root detected"},
                ],
            }), encoding="utf-8")
            policy = pipeline.load_success_spec(path)
        self.assertEqual(policy["repeat"], 2)
        self.assertEqual(policy["min_passes"], 2)
        self.assertTrue(policy["baseline_required"])

    def test_ui_text_policy_uses_uiautomator_hierarchy(self):
        args = argparse.Namespace(device="serial", success_regex=None)
        spec = {"mode": "all", "checks": [
            {"type": "ui_text_regex", "pattern": "Dashboard"},
            {"type": "ui_text_not_regex", "pattern": "root detected"},
        ]}
        responses = [
            subprocess.CompletedProcess([], 0, "UI hierarchy dumped"),
            subprocess.CompletedProcess([], 0, '<node text="Dashboard"/>'),
            subprocess.CompletedProcess([], 0, ""),
        ]
        with mock.patch.object(pipeline, "adb", side_effect=responses) as adb:
            passed, checks = pipeline.evaluate_success(args, "com.example", "", "", spec)
        self.assertTrue(passed)
        self.assertEqual(adb.call_count, 3)
        self.assertTrue(all(check["passed"] for check in checks))

    def test_repeat_validation_requires_multiple_passes(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            (run_dir / "logs").mkdir()
            script = run_dir / "candidate.js"
            script.write_text("'use strict';", encoding="utf-8")
            args = argparse.Namespace(
                device="serial", success_regex=None,
                frida_endpoint="127.0.0.1:27042", run_seconds=1,
            )
            spec = {
                "mode": "all", "repeat": 2, "min_passes": 2,
                "checks": [{"type": "log_regex", "pattern": "ready"}],
            }

            def fake_run(command, **kwargs):
                kwargs["log"].write_text("frida output", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "")

            def fake_adb(_args, *command, **_kwargs):
                output = "ready" if command[:2] == ("logcat", "-d") else ""
                return subprocess.CompletedProcess(command, 0, output)

            with mock.patch.object(pipeline, "run", side_effect=fake_run) as run, \
                    mock.patch.object(pipeline, "adb", side_effect=fake_adb):
                passed, attempts = pipeline.run_frida(args, run_dir, "com.example", [script], spec)
        self.assertTrue(passed)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(attempts[0]["pass_count"], 2)
        self.assertEqual(len(attempts[0]["repetitions"]), 2)

    def test_candidate_must_be_inside_run(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run_dir = root / "run"
            run_dir.mkdir()
            outside = root / "outside.js"
            outside.write_text("'use strict';", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "inside the selected run"):
                pipeline.validate_candidate_script(run_dir, outside)

    def test_candidate_inside_run_is_compiled(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            candidate = run_dir / "candidate.js"
            candidate.write_text("'use strict';", encoding="utf-8")
            fake_frida = mock.Mock()
            with mock.patch.dict("sys.modules", {"frida": fake_frida}):
                self.assertEqual(pipeline.validate_candidate_script(run_dir, candidate), candidate)
            fake_frida.Compiler.return_value.build.assert_called_once_with(str(candidate))

    def test_wireless_endpoint_validation(self):
        self.assertEqual(pipeline.validate_adb_endpoint("192.168.1.20:37123"), "192.168.1.20:37123")
        self.assertEqual(pipeline.validate_adb_endpoint("[2001:db8::1]:5555"), "[2001:db8::1]:5555")
        for invalid in ("192.168.1.20", "host:0", "host:65536", "host:port", "host;command:5555"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(RuntimeError):
                    pipeline.validate_adb_endpoint(invalid)

    def test_wireless_pair_connect_and_select(self):
        args = argparse.Namespace(
            wireless_connect="192.168.1.20:38888",
            wireless_pair="192.168.1.20:37777",
            wireless_pair_code="123456",
            device=None,
        )
        calls = []

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            if command[1] == "pair":
                output = "Successfully paired to 192.168.1.20:37777\n"
            elif command[1] == "connect":
                output = "connected to 192.168.1.20:38888\n"
            else:
                output = "device\n"
            return subprocess.CompletedProcess(command, 0, output)

        with mock.patch.object(pipeline, "run", side_effect=fake_run):
            pipeline.setup_wireless(args)
        self.assertEqual(args.device, "192.168.1.20:38888")
        self.assertEqual(calls[0][0], ["adb", "pair", "192.168.1.20:37777"])
        self.assertEqual(calls[0][1]["input_text"], "123456\n")
        self.assertNotIn("123456", calls[0][1]["display"])

    def test_prepare_device_rejects_missing_frida_server(self):
        args = argparse.Namespace(
            device="serial", install=False,
            start_frida_server="/data/local/tmp/missing-frida-server",
            frida_endpoint="127.0.0.1:27042",
        )
        responses = [
            subprocess.CompletedProcess([], 0, "device\n"),
            subprocess.CompletedProcess([], 1, ""),
        ]
        with mock.patch.object(pipeline, "adb", side_effect=responses):
            with self.assertRaisesRegex(RuntimeError, "missing or not executable"):
                pipeline.prepare_device(args, Path("sample.apk"))


if __name__ == "__main__":
    unittest.main()
