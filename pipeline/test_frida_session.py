from __future__ import annotations

import tempfile
from pathlib import Path
import unittest
from unittest import mock

try:
    from pipeline.frida_session import CommandOutcome, FridaSessionRunner
    import pipeline.frida_session as frida_session
except ModuleNotFoundError:  # Direct execution from /workspace/pipeline.
    from frida_session import CommandOutcome, FridaSessionRunner  # type: ignore
    import frida_session  # type: ignore


class FridaSessionRunnerTests(unittest.TestCase):
    def runner(self, adb_calls=None, host_calls=None, *, server_path=""):
        adb_calls = adb_calls if adb_calls is not None else []
        host_calls = host_calls if host_calls is not None else []

        def adb(command, stage, check):
            adb_calls.append((command, stage, check))
            if command == ["get-state"]:
                return CommandOutcome(0, "device\n")
            return CommandOutcome(0, "")

        def host(command, stage, timeout, artifact):
            host_calls.append((command, stage, timeout, artifact))
            return CommandOutcome(0, "")

        return FridaSessionRunner(
            target="device-123", endpoint="127.0.0.1:27042", version="",
            server_path=server_path, adb_runner=adb, host_runner=host,
            sleep=lambda _seconds: None,
        )

    def test_all_sessions_use_the_canonical_quiet_lifetime_flags(self):
        with mock.patch.object(frida_session, "frida_command", return_value=["frida"]):
            runner = self.runner()
            finite = runner.command("com.example", Path("candidate.js"), 20)
            persistent = runner.command("com.example", Path("candidate.js"), None)
        self.assertEqual(finite[-5:], ["candidate.js", "-q", "-t", "20", "--exit-on-error"])
        self.assertEqual(persistent[-5:], ["candidate.js", "-q", "-t", "inf", "--exit-on-error"])

    def test_prepare_forwards_and_probes_before_starting_server(self):
        adb_calls = []
        host_calls = []
        probes = iter([CommandOutcome(1, "closed"), CommandOutcome(0, "ready")])

        def host(command, stage, timeout, artifact):
            host_calls.append((command, stage, timeout, artifact))
            return next(probes)

        runner = self.runner(adb_calls, host_calls, server_path="/data/local/tmp/frida-server")
        runner.host_runner = host
        with mock.patch.object(frida_session, "frida_command", return_value=["frida-ps"]):
            runner.prepare()

        commands = [call[0] for call in adb_calls]
        self.assertEqual(commands[0], ["get-state"])
        self.assertIn(["forward", "tcp:27042", "tcp:27042"], commands)
        self.assertIn(
            ["shell", "su", "-c", "/data/local/tmp/frida-server -D"], commands,
        )
        self.assertEqual(len(host_calls), 2)

    def test_run_script_uses_shared_timeout_and_artifact(self):
        host_calls = []
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(
            frida_session, "frida_command", return_value=["frida"],
        ):
            runner = self.runner(host_calls=host_calls)
            artifact = Path(temp) / "frida.log"
            result = runner.run_script(
                "com.example", Path("candidate.js"), duration_seconds=15,
                artifact=artifact, stage="validation",
            )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(host_calls[0][1:], ("validation", 25, artifact))


if __name__ == "__main__":
    unittest.main()
