from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from backend.run_deletion import RunDeletionConflict, archive_run


class RunDeletionTests(unittest.TestCase):
    def _run(self, runs: Path, run_id: str = "run-123") -> Path:
        directory = runs / run_id
        directory.mkdir(parents=True)
        (directory / "report.json").write_text('{"package":"com.example"}', encoding="utf-8")
        return directory

    def _job(self, jobs: Path, run_id: str, status: str = "human_review") -> Path:
        directory = jobs / ("a" * 32)
        directory.mkdir(parents=True)
        (directory / "job.json").write_text(json.dumps({
            "id": directory.name, "run_id": run_id,
            "status": status, "running": status == "running",
        }), encoding="utf-8")
        (directory / "request.json").write_text(json.dumps({
            "kind": "start", "payload": {},
        }), encoding="utf-8")
        return directory

    def test_archive_moves_run_and_completed_job_history(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runs, jobs, trash = root / "runs", root / "jobs", root / "trash"
            runs.mkdir(); jobs.mkdir(); trash.mkdir()
            run = self._run(runs)
            job = self._job(jobs, run.name)
            with (
                patch("backend.artifacts.RUNS_ROOT", runs),
                patch("backend.run_deletion.JOBS_ROOT", jobs),
                patch("backend.run_deletion.TRASH_ROOT", trash),
            ):
                result = archive_run(run.name, run.name)
            archive = trash / "runs" / result["archive_id"]
            self.assertFalse(run.exists())
            self.assertFalse(job.exists())
            self.assertTrue((archive / "run" / "report.json").is_file())
            self.assertTrue((archive / "jobs" / ("a" * 32) / "job.json").is_file())
            self.assertTrue((archive / "archive.json").is_file())
            self.assertTrue(result["recoverable"])

    def test_archive_rejects_active_job_and_preserves_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runs, jobs, trash = root / "runs", root / "jobs", root / "trash"
            runs.mkdir(); jobs.mkdir(); trash.mkdir()
            run = self._run(runs)
            self._job(jobs, run.name, "running")
            with (
                patch("backend.artifacts.RUNS_ROOT", runs),
                patch("backend.run_deletion.JOBS_ROOT", jobs),
                patch("backend.run_deletion.TRASH_ROOT", trash),
                self.assertRaisesRegex(RunDeletionConflict, "active assessment job"),
            ):
                archive_run(run.name, run.name)
            self.assertTrue(run.is_dir())
            self.assertFalse((run / ".archiving").exists())

    def test_archive_rejects_active_assistant_request(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runs, jobs, trash = root / "runs", root / "jobs", root / "trash"
            runs.mkdir(); jobs.mkdir(); trash.mkdir()
            run = self._run(runs)
            requests = run / "assistant" / "requests"
            requests.mkdir(parents=True)
            (requests / ("b" * 32 + ".json")).write_text(
                '{"id":"request","status":"running"}', encoding="utf-8",
            )
            with (
                patch("backend.artifacts.RUNS_ROOT", runs),
                patch("backend.run_deletion.JOBS_ROOT", jobs),
                patch("backend.run_deletion.TRASH_ROOT", trash),
                self.assertRaisesRegex(RunDeletionConflict, "assistant request"),
            ):
                archive_run(run.name, run.name)
            self.assertTrue(run.is_dir())

    def test_archive_requires_exact_run_confirmation(self) -> None:
        with self.assertRaisesRegex(ValueError, "confirmation"):
            archive_run("run-123", "another-run")


if __name__ == "__main__":
    unittest.main()
