from __future__ import annotations

import tempfile
from pathlib import Path
import unittest
from unittest import mock

from ui import job_queue, worker


class DurableWorkerTests(unittest.TestCase):
    def test_claim_is_atomic_and_persists_running_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory = root / ("a" * 32)
            directory.mkdir()
            state = {"id": "a" * 32, "status": "queued", "running": False}
            job_queue.atomic_write_json(directory / "job.json", state)
            job_queue.atomic_write_json(directory / "request.json", {"kind": "start", "payload": {"apk": "sample.apk"}})
            with mock.patch.object(job_queue, "STATE_ROOT", root):
                claimed = job_queue.claim_next_job("worker-test")
                duplicate = job_queue.claim_next_job("worker-other")
            self.assertIsNotNone(claimed)
            self.assertIsNone(duplicate)
            stored = job_queue.read_json(directory / "job.json")
            self.assertTrue(stored["running"])
            self.assertEqual(stored["status"], "running")
            self.assertEqual(stored["worker_id"], "worker-test")

    def test_start_job_completion_is_written_to_disk(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            state = {"id": "b" * 32, "kind": "start", "running": True, "status": "running", "started_utc": "now"}
            request = {"kind": "start", "payload": {"apk": "sample.apk"}}
            run_dir = Path(temp) / "runs" / "run-123"
            runner = mock.Mock()
            runner.new.return_value = ("success", run_dir)
            with mock.patch.object(worker, "LoopRunner", return_value=runner):
                worker.execute(directory, state, request)
            stored = job_queue.read_json(directory / "job.json")
            self.assertFalse(stored["running"])
            self.assertEqual(stored["status"], "success")
            self.assertEqual(stored["run_id"], "run-123")
            self.assertEqual(stored["exit_code"], 0)

    def test_abandoned_running_job_is_preserved_as_interrupted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory = root / ("c" * 32)
            directory.mkdir()
            job_queue.atomic_write_json(directory / "job.json", {
                "id": "c" * 32, "status": "running", "running": True,
            })
            (directory / "claim.lock").write_text("old-worker\n", encoding="utf-8")
            with mock.patch.object(job_queue, "STATE_ROOT", root):
                job_queue.recover_abandoned_jobs()
            stored = job_queue.read_json(directory / "job.json")
            self.assertFalse(stored["running"])
            self.assertEqual(stored["status"], "interrupted")
            self.assertTrue((directory / "job.json").is_file())
            self.assertFalse((directory / "claim.lock").exists())


if __name__ == "__main__":
    unittest.main()
