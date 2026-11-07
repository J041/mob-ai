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
    wireless_device_view, parse_frida_server_processes, replace_frida_server,
)
from assessment.orchestrator import (
    WORKSPACE, LoopError, LoopRunner, attempt_fingerprint, codex_config_overrides,
    codex_multi_agent_args, codex_reasoning_args, checkpoint_recovery_available,
    frida_recovery_available, terminal_outcome, usage_limit_recovery_available,
    validate_decision_schema_registry,
)
from backend.providers import ProviderRequest, detect_usage_limit, provider_adapter, validate_provider_output


class DeviceApiTests(unittest.TestCase):
    def setUp(self) -> None:
        app.config.update(TESTING=True)
        self.client = app.test_client()

    @patch("backend.app.subprocess.run")
    def test_wireless_pairing_sends_code_over_stdin(self, run) -> None:
        run.return_value = subprocess.CompletedProcess([], 0, "Successfully paired", "")
        with tempfile.TemporaryDirectory() as temp, patch(
            "backend.app.WIRELESS_DEVICES_PATH", Path(temp) / "wireless-devices.json",
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

    @patch("backend.app.subprocess.run")
    def test_wireless_pairing_removes_contradictory_success_suffix(self, run) -> None:
        run.return_value = subprocess.CompletedProcess(
            [], 1, "", "error: protocol fault (couldn't read status message): Success\n",
        )
        response = self.client.post(
            "/api/devices/pair",
            json={"endpoint": "192.168.1.20:37001", "code": "123456"},
        )
        payload = response.get_json()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            payload["error"],
            "Wireless pairing failed: error: protocol fault (couldn't read status message)",
        )

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
            with patch("backend.app.WIRELESS_DEVICES_PATH", registry):
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
            with patch("backend.app.WIRELESS_DEVICES_PATH", registry):
                device = wireless_device_view([], [])[0]
        self.assertEqual(device["endpoint"], "")
        self.assertTrue(device["connection_required"])
        self.assertEqual(device["pairing_endpoint"], "192.168.1.20:39725")

    @patch("backend.app.subprocess.run")
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
            with patch("backend.app.WIRELESS_DEVICES_PATH", registry):
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

    def test_frida_process_parser_ignores_unrelated_processes(self) -> None:
        processes = parse_frida_server_processes(
            "PID ARGS\n22 /data/local/tmp/frida-server -D\n"
            "44 com.example.frida-client\n55 re.frida.server\n66 system_server\n",
            "/data/local/tmp/frida-server",
        )
        self.assertEqual(set(processes), {22, 55})

    @patch("backend.app.time.sleep")
    @patch("backend.app.adb_result")
    def test_replace_frida_server_stops_only_recognized_processes(self, adb, _sleep) -> None:
        adb.side_effect = [
            subprocess.CompletedProcess([], 0, "PID ARGS\n22 /data/local/tmp/frida-server -D\n44 com.example.app\n", ""),
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, "PID ARGS\n44 com.example.app\n", ""),
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, "PID ARGS\n33 /data/local/tmp/frida-server -D\n44 com.example.app\n", ""),
        ]
        checks, pids = replace_frida_server("emulator-5554", "/data/local/tmp/frida-server")
        commands = [" ".join(map(str, call.args)) for call in adb.call_args_list]
        self.assertEqual(pids, {33})
        self.assertTrue(all(check["passed"] for check in checks))
        self.assertTrue(any(command.endswith("kill 22") for command in commands))
        self.assertFalse(any(command.endswith("kill 44") for command in commands))

    @patch("backend.app.subprocess.run")
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



if __name__ == "__main__":
    unittest.main()
