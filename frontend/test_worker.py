from __future__ import annotations

import http.server
from datetime import datetime, timedelta, timezone
import tempfile
from pathlib import Path
import threading
import unittest
import urllib.request
from unittest import mock

from frontend import job_queue, worker
from frontend.ghidra_proxy import GhidraLoopbackProxy


class DurableWorkerTests(unittest.TestCase):
    def test_due_usage_limit_job_is_requeued_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory = root / ("d" * 32)
            directory.mkdir()
            job_queue.atomic_write_json(directory / "job.json", {
                "id": "d" * 32, "kind": "start", "status": "usage_limited", "running": False,
                "run_id": "run-123", "attempt_number": 2, "auto_resume": True,
                "resume_after_utc": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
            })
            job_queue.atomic_write_json(directory / "request.json", {
                "kind": "start", "payload": {"max_iterations": 3, "provider": "codex"},
            })
            with mock.patch.object(job_queue, "STATE_ROOT", root):
                created = job_queue.enqueue_due_usage_limit_jobs()
                duplicate = job_queue.enqueue_due_usage_limit_jobs()
            self.assertEqual(len(created), 1)
            self.assertEqual(duplicate, [])
            queued = job_queue.read_json(root / created[0] / "job.json")
            request = job_queue.read_json(root / created[0] / "request.json")
            self.assertEqual(queued["status"], "queued")
            self.assertEqual(queued["attempt_kind"], "usage_limit_resume")
            self.assertTrue(request["payload"]["auto_resume_usage_limit"])
            self.assertEqual(Path(request["payload"]["run"]).name, "run-123")

    def test_ghidra_proxy_is_loopback_only_and_preserves_http(self) -> None:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                body = f"{self.path}|{self.headers.get('Authorization', '')}".encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format, *_args) -> None:
                pass

        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()
        proxy = GhidraLoopbackProxy(
            f"http://127.0.0.1:{upstream.server_address[1]}", port=0,
        ).start()
        try:
            request = urllib.request.Request(
                f"{proxy.url}/check_connection", headers={"Authorization": "Bearer test-token"},
            )
            with urllib.request.urlopen(request, timeout=3) as response:
                self.assertEqual(response.read().decode(), "/check_connection|Bearer test-token")
            self.assertTrue(proxy.url.startswith("http://127.0.0.1:"))
        finally:
            proxy.close()
            upstream.shutdown()
            upstream.server_close()
            thread.join(timeout=3)

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
