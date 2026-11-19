from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from assessment.runtime import JobControl
from worker.job_timeline import JobProgressRecorder, build_job_timeline


class JobTimelineTests(unittest.TestCase):
    def test_progress_transitions_build_the_six_assessment_stages(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "progress.json"
            JobProgressRecorder.initialize(path, "start", "2026-11-19T00:00:00+00:00")
            recorder = JobProgressRecorder(path, "start")
            for stage in (
                "starting", "static_analysis", "observation", "native_selection",
                "provider_iteration_1", "validation_iteration_1",
            ):
                recorder.transition(stage)
            progress = __import__("json").loads(path.read_text(encoding="utf-8"))
            timeline = build_job_timeline({"kind": "start", "status": "running", "running": True}, progress)
        self.assertEqual(
            [item["id"] for item in timeline["stages"]],
            ["queued", "static_analysis", "observation", "native_analysis", "reasoning", "validation"],
        )
        self.assertEqual(timeline["current_stage"], "validation")
        self.assertEqual(timeline["stages"][-1]["status"], "active")
        self.assertTrue(all(item["status"] == "completed" for item in timeline["stages"][:-1]))

    def test_failed_job_marks_current_stage_and_skips_future_stages(self) -> None:
        progress = {
            "kind": "start", "current_stage": "observation", "history": [
                {"stage": "queued", "started_utc": "2026-11-19T00:00:00+00:00", "completed_utc": "2026-11-19T00:00:01+00:00"},
                {"stage": "static_analysis", "started_utc": "2026-11-19T00:00:01+00:00", "completed_utc": "2026-11-19T00:00:02+00:00"},
                {"stage": "observation", "started_utc": "2026-11-19T00:00:02+00:00", "completed_utc": "2026-11-19T00:00:03+00:00"},
            ],
        }
        timeline = build_job_timeline(
            {"kind": "start", "status": "environment_error", "running": False}, progress,
        )
        statuses = {item["id"]: item["status"] for item in timeline["stages"]}
        self.assertEqual(statuses["observation"], "failed")
        self.assertEqual(statuses["native_analysis"], "skipped")

    def test_job_control_reports_real_stage_changes(self) -> None:
        observed = []
        control = JobControl(on_stage=observed.append)
        control.set_stage("static_analysis")
        control.set_stage("static_analysis")
        control.set_stage("observation")
        self.assertEqual(observed, ["static_analysis", "observation"])

    def test_resume_marks_reused_earlier_stages_as_skipped(self) -> None:
        progress = {
            "kind": "resume", "current_stage": "provider_iteration_4", "history": [
                {"stage": "queued", "started_utc": "2026-11-19T00:00:00+00:00", "completed_utc": "2026-11-19T00:00:01+00:00"},
                {"stage": "provider_iteration_4", "started_utc": "2026-11-19T00:00:01+00:00", "completed_utc": ""},
            ],
        }
        timeline = build_job_timeline(
            {"kind": "resume", "status": "running", "running": True}, progress,
        )
        statuses = {item["id"]: item["status"] for item in timeline["stages"]}
        self.assertEqual(statuses["static_analysis"], "skipped")
        self.assertEqual(statuses["observation"], "skipped")
        self.assertEqual(statuses["reasoning"], "active")


if __name__ == "__main__":
    unittest.main()
