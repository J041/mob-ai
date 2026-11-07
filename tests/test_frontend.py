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


class FrontendTests(unittest.TestCase):
    def setUp(self) -> None:
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def test_frontend_modules_are_served(self) -> None:
        response = self.client.get("/")
        page = response.get_data(as_text=True)
        response.close()
        self.assertIn('type="module"', page)
        self.assertIn('src="/scripts/app.js?v=20261102-packages"', page)
        for path in (
            "/scripts/app.js", "/scripts/core.js", "/scripts/models.js",
            "/scripts/artifacts.js", "/scripts/assistant.js", "/scripts/auth.js",
            "/scripts/devices.js", "/scripts/events.js", "/scripts/policy-builder.js",
            "/scripts/runs.js",
        ):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertIn("javascript", response.content_type, path)
            response.close()
        response = self.client.get("/scripts/app.js")
        app_script = response.get_data(as_text=True)
        response.close()
        self.assertIn("from './core.js'", app_script)
        self.assertIn("from './artifacts.js'", app_script)
        self.assertIn("from './models.js'", app_script)
        self.assertIn("connectOverviewEvents", app_script)

    def test_reassessment_entry_is_in_continue_workflow(self) -> None:
        response = self.client.get("/")
        page = response.get_data(as_text=True)
        response.close()
        self.assertIn('id="reassessSelected"', page)
        self.assertIn('id="reassessmentBanner" hidden', page)
        self.assertNotIn("â", page)

    def test_attempt_history_uses_nonshrinking_scroll_content(self) -> None:
        response = self.client.get("/styles/styles.css")
        styles = response.get_data(as_text=True)
        response.close()
        self.assertIn(".job-strip { flex: 0 0 clamp", styles)
        self.assertIn("display: flex; flex-direction: column", styles)

    def test_all_terminal_error_statuses_are_red(self) -> None:
        response = self.client.get("/styles/styles.css")
        styles = response.get_data(as_text=True)
        response.close()
        for status in (
            "provider-error", "environment-error", "pipeline-error", "codex-error",
            "codex-boundary-error", "assessment-failed", "worker-error", "needs-input",
        ):
            self.assertIn(f".job-status.status-{status}", styles)
            self.assertIn(f".attempt-chip b.status-{status}", styles)
        self.assertIn(".badge.provider_error", styles)
        self.assertIn(".badge.assessment_failed", styles)
        self.assertIn(".job-group { flex: 0 0 auto", styles)

    def test_actionable_terminal_status_ui_is_visible(self) -> None:
        response = self.client.get("/scripts/app.js")
        script = response.get_data(as_text=True)
        response.close()
        response = self.client.get("/scripts/runs.js")
        run_script = response.get_data(as_text=True)
        response.close()
        self.assertIn("terminal.recommended_action", script)
        self.assertIn("Recommended:", run_script)
        self.assertIn("job-terminal-reason", script)

    def test_successful_run_script_download_is_conditional(self) -> None:
        response = self.client.get("/scripts/app.js")
        script = response.get_data(as_text=True)
        response.close()
        self.assertIn("run.successful_script ?", script)
        self.assertIn("download-script", script)
        self.assertIn("/artifacts/download?path=", script)

    def test_resume_recommendation_does_not_inherit_icon_typography(self) -> None:
        response = self.client.get("/styles/styles.css")
        styles = response.get_data(as_text=True)
        response.close()
        self.assertIn(".resume-summary > span", styles)
        self.assertIn(".resume-summary .recommended-action { font: inherit; }", styles)
        self.assertNotIn(".resume-summary span {", styles)

    def test_agent_console_exposes_pause_and_cancel_controls(self) -> None:
        response = self.client.get("/")
        page = response.get_data(as_text=True)
        response.close()
        response = self.client.get("/scripts/app.js")
        script = response.get_data(as_text=True)
        response.close()
        self.assertIn('id="pauseJob"', page)
        self.assertIn('id="cancelJob"', page)
        self.assertIn("controlSelectedJob('pause')", script)
        self.assertIn("controlSelectedJob('cancel')", script)

    def test_run_and_attempt_token_usage_is_visible(self) -> None:
        response = self.client.get("/scripts/app.js")
        script = response.get_data(as_text=True)
        response.close()
        self.assertIn("function tokenLabel", script)
        self.assertIn("run.token_usage", script)
        self.assertIn("job.token_usage", script)
        self.assertIn("attempts &middot; ${escapeText(tokenLabel(run?.token_usage))}", script)

    def test_assessment_rows_share_grid_columns(self) -> None:
        response = self.client.get("/styles/styles.css")
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



if __name__ == "__main__":
    unittest.main()
