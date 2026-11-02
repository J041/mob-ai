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
from backend.providers import ProviderRequest, detect_usage_limit, provider_adapter, validate_provider_output


class AuthenticationTests(unittest.TestCase):
    def setUp(self) -> None:
        app.config.update(TESTING=True)
        self.client = app.test_client()

    @patch("backend.auth.codex_authenticated", return_value=True)
    @patch("backend.auth.read_connected_account_models", side_effect=RuntimeError("catalog unavailable"))
    @patch("backend.auth.read_codex_models")
    def test_model_catalog_uses_codex_app_server(self, read_models, read_account, authenticated) -> None:
        read_models.return_value = [{
            "id": "test-model", "model": "test-model",
            "displayName": "Test Model", "isDefault": True,
        }]
        catalog = codex_model_catalog(force=True)
        self.assertEqual(catalog["source"], "codex_app_server")
        self.assertEqual(catalog["models"][0]["id"], "test-model")
        self.assertTrue(catalog["models"][0]["is_default"])

    @patch("backend.auth.codex_authenticated", return_value=False)
    @patch("backend.auth.read_codex_models")
    def test_model_catalog_requires_connected_account(self, read_models, authenticated) -> None:
        catalog = codex_model_catalog(force=True)
        self.assertEqual(catalog, {"models": [], "source": "authentication_required"})
        read_models.assert_not_called()

    @patch("backend.auth.codex_authenticated", return_value=True)
    @patch("backend.auth.read_connected_account_models")
    @patch("backend.auth.read_codex_models")
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

if __name__ == "__main__":
    unittest.main()
