from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from runtime_data import initialize_runtime_data


class RuntimeDataTests(unittest.TestCase):
    def test_legacy_runtime_directories_move_under_one_root_and_keep_links(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            (workspace / "runs" / "run-1").mkdir(parents=True)
            (workspace / "runs" / "run-1" / "report.json").write_text("{}", encoding="utf-8")
            (workspace / "uploads").mkdir()
            (workspace / "uploads" / "sample.apk").write_bytes(b"PK\x03\x04")
            (workspace / "policies" / "generated").mkdir(parents=True)
            (workspace / "policies" / "generated" / "policy.json").write_text("{}", encoding="utf-8")
            (workspace / "worker" / ".state" / "jobs" / "abc").mkdir(parents=True)
            data_root = workspace / ".mob-ai-data"

            manifest = initialize_runtime_data(workspace=workspace, data_root=data_root)

            self.assertTrue((data_root / "runs" / "run-1" / "report.json").is_file())
            self.assertTrue((data_root / "uploads" / "sample.apk").is_file())
            self.assertTrue((data_root / "policies" / "policy.json").is_file())
            self.assertTrue((data_root / "state" / "jobs" / "abc").is_dir())
            self.assertTrue((workspace / "runs").is_symlink())
            self.assertEqual((workspace / "runs").resolve(), (data_root / "runs").resolve())
            self.assertEqual(manifest["version"], 1)
            saved = json.loads((data_root / "migration-v1.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["data_root"], str(data_root))

    def test_copied_data_root_recreates_legacy_compatibility_links(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            data_root = workspace / ".mob-ai-data"
            (data_root / "runs" / "run-1").mkdir(parents=True)
            initialize_runtime_data(workspace=workspace, data_root=data_root)
            self.assertTrue((workspace / "runs").is_symlink())
            self.assertTrue((workspace / "uploads").is_symlink())
            self.assertTrue((workspace / "policies" / "generated").is_symlink())
            self.assertTrue((workspace / "worker" / ".state").is_symlink())

    def test_migration_refuses_to_merge_two_nonempty_locations(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            data_root = workspace / ".mob-ai-data"
            (workspace / "runs").mkdir()
            (workspace / "runs" / "legacy.txt").write_text("legacy", encoding="utf-8")
            (data_root / "runs").mkdir(parents=True)
            (data_root / "runs" / "new.txt").write_text("new", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "Refusing to merge"):
                initialize_runtime_data(workspace=workspace, data_root=data_root)


if __name__ == "__main__":
    unittest.main()
