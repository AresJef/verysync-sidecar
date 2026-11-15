"""Real private-terminal and bounded-capture contracts, without foreign code."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "calibrate-arm-core.py"
SPEC = importlib.util.spec_from_file_location("calibrate_arm_core", SOURCE)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


@unittest.skipUnless(sys.platform in ("darwin", "linux"), "private Unix terminal contract")
class PrivateVersionProbeContracts(unittest.TestCase):
    def probe(self, source, timeout=2):
        with tempfile.TemporaryDirectory(prefix="vs-calibration-contract-") as directory:
            return HELPER.capture_version([sys.executable, "-c", source],
                                          dict(os.environ), Path(directory), timeout)

    def test_metadata_child_has_its_own_controlling_stderr_terminal(self):
        result = self.probe("""
import os, resource
assert os.isatty(2) and not os.isatty(0)
assert os.getsid(0) == os.getpid()
assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
terminal = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY)
os.close(terminal)
print('verysync v2.33.2 synthetic')
""")
        self.assertTrue(result["version_probe_passed"])
        self.assertEqual(result["exit_code"], 0)
        self.assertFalse(result["timed_out"])

    def test_wrong_version_or_nonzero_exit_cannot_pass(self):
        self.assertFalse(self.probe("print('verysync v2.33.1 synthetic')")["version_probe_passed"])
        failed = self.probe("import sys; print('verysync v2.33.2 synthetic'); sys.exit(7)")
        self.assertTrue(failed["version_matches"])
        self.assertEqual(failed["exit_code"], 7)
        self.assertFalse(failed["version_probe_passed"])

    def test_deadline_reaps_only_the_owned_child(self):
        result = self.probe("import time; time.sleep(60)", timeout=0.15)
        self.assertTrue(result["timed_out"])
        self.assertFalse(result["version_probe_passed"])
        self.assertEqual(result["termination_signal"], signal.SIGKILL)

    def test_stderr_is_drained_and_stdout_overflow_is_a_failure(self):
        drained = self.probe("import os; os.write(2, b'x' * 70000); print('verysync v2.33.2 synthetic')")
        self.assertTrue(drained["version_probe_passed"])
        overflow = self.probe("print('x' * 70000); print('verysync v2.33.2 synthetic')")
        self.assertTrue(overflow["output_exceeded_bound"])
        self.assertFalse(overflow["version_probe_passed"])

    def test_other_cpu_success_does_not_replace_requested_cpu(self):
        with tempfile.TemporaryDirectory(prefix="vs-calibration-selection-") as directory:
            root = Path(directory)
            emulator = root / "qemu-arm"
            emulator.write_bytes(b"synthetic; never executed")
            core = root / "verysync"
            core.write_bytes(b"synthetic; never executed")
            rows = [dict(exit_code=-4, version_probe_passed=False),
                    dict(exit_code=0, version_probe_passed=True),
                    dict(exit_code=0, version_probe_passed=True)]
            with patch.object(HELPER, "capture_version", side_effect=rows), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, "requested CPU"):
                    HELPER.calibrate(root, core, "arm926")
            self.assertTrue((root / "cpu-version-calibration.json").is_file())


if __name__ == "__main__":
    unittest.main()
