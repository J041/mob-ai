from __future__ import annotations

from io import BytesIO
import json
import subprocess
import unittest
from unittest.mock import patch

from ui.app import (
    _readiness, app, codex_model_catalog, parse_resume, parse_start,
    resolve_workspace_item, sign_out_codex, strip_terminal_controls, success_policy,
)
from ui.orchestrator import (
    WORKSPACE, attempt_fingerprint, codex_config_overrides, codex_reasoning_args,
    checkpoint_recovery_available, frida_recovery_available,
)


class WebAppTests(unittest.TestCase):
    def setUp(self) -> None:
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def test_health(self) -> None:
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")

    def test_overview_contract(self) -> None:
        payload = self.client.get("/api/overview").get_json()
        self.assertIn("codex", payload)
        self.assertIn("runs", payload)
        self.assertIn("success_specs", payload)

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
        response = self.client.post(
            "/api/devices/pair",
            json={"endpoint": "192.168.1.20:37001", "code": "123456"},
        )
        self.assertEqual(response.status_code, 200)
        command = run.call_args.args[0]
        self.assertEqual(command, ["adb", "pair", "192.168.1.20:37001"])
        self.assertNotIn("123456", command)
        self.assertEqual(run.call_args.kwargs["input"], "123456\n")

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
        catalog = codex_model_catalog(force=True)
        self.assertEqual(catalog["source"], "connected_chatgpt_account")
        self.assertEqual(catalog["models"][0]["id"], "account-model")
        read_local.assert_not_called()

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
    def test_resume_accepts_device_frida_server_path(self, resolve) -> None:
        resolve.return_value = WORKSPACE / "runs" / "example"
        _, request = parse_resume({
            "authorized": True, "run": "runs/example", "max_iterations": 2,
            "frida_server": "/data/local/tmp/frida-server-17.5.1",
        })
        self.assertEqual(request["frida_server"], "/data/local/tmp/frida-server-17.5.1")

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

    def test_auth_output_strips_terminal_controls(self) -> None:
        value = "\x1b[94mhttps://auth.openai.com/codex/device\x1b[0m\r\n\x1b[90mABCD-EFGHIJ\x1b[0m"
        self.assertEqual(
            strip_terminal_controls(value),
            "https://auth.openai.com/codex/device\nABCD-EFGHIJ",
        )

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
        self.assertNotIn("cmd.exe", rendered)


if __name__ == "__main__":
    unittest.main()
