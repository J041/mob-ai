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


class RunEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        app.config.update(TESTING=True)
        self.client = app.test_client()

    @patch("backend.assistant.provider_model_catalog", return_value={"models": [{
        "id": "test-model", "reasoning_levels": [{"effort": "high"}],
    }], "source": "test"})
    @patch("backend.assistant.provider_authenticated", return_value=True)
    @patch("backend.assistant.subprocess.run")
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
            with patch("backend.artifacts.RUNS_ROOT", root):
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
            with patch("backend.artifacts.RUNS_ROOT", root):
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



if __name__ == "__main__":
    unittest.main()
