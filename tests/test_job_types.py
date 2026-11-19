from __future__ import annotations

import tempfile
from pathlib import Path
import unittest
from unittest import mock

from backend import jobs as job_service
from worker.job_types import JOB_TYPES, job_type, public_job_type_catalog
from worker.queue import atomic_write_json


class JobTypeRegistryTests(unittest.TestCase):
    def test_registry_defines_all_durable_job_semantics(self) -> None:
        self.assertEqual(
            set(JOB_TYPES), {"start", "resume", "retry", "deep_goal", "launch_bypass"},
        )
        for name, spec in JOB_TYPES.items():
            with self.subTest(name=name):
                self.assertTrue(spec.executor)
                self.assertTrue(spec.label)
                self.assertTrue(spec.default_attempt_kind)
                self.assertTrue(spec.successful_statuses)

        self.assertTrue(job_type("start").requires_provider)
        self.assertTrue(job_type("resume").counts_as_attempt)
        self.assertTrue(job_type("retry").supports_pause)
        self.assertFalse(job_type("deep_goal").counts_as_attempt)
        self.assertFalse(job_type("deep_goal").supports_pause)
        self.assertFalse(job_type("launch_bypass").requires_provider)
        self.assertEqual(job_type("launch_bypass").successful_statuses, {"bypass_session_ended"})

    def test_public_catalog_excludes_worker_executor_bindings(self) -> None:
        catalog = public_job_type_catalog()
        self.assertNotIn("executor", catalog["start"])
        self.assertEqual(catalog["retry"]["attempt_labels"]["diagnostic_retry"], "Rerun / retry")
        self.assertEqual(catalog["launch_bypass"]["control_noun"], "session")

    def test_non_pauseable_job_is_rejected_by_backend_control(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            identifier = "a" * 32
            directory = root / identifier
            directory.mkdir()
            atomic_write_json(directory / "job.json", {
                "id": identifier, "kind": "launch_bypass", "status": "running", "running": True,
            })
            with mock.patch.object(job_service, "STATE_ROOT", root):
                with self.assertRaisesRegex(ValueError, "do not support pausing"):
                    job_service.request_job_control(identifier, "pause")


if __name__ == "__main__":
    unittest.main()
