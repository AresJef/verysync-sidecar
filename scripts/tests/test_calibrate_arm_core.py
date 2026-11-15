"""Real private-terminal and bounded-capture contracts, without foreign code."""
import contextlib
import importlib.util
import io
import json
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
                    *[dict(exit_code=0, version_probe_passed=True) for _ in range(5)]]
            with patch.object(HELPER, "capture_version", side_effect=rows), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, "requested CPU"):
                    HELPER.calibrate(root, core, "arm926")
            self.assertTrue((root / "cpu-version-calibration.json").is_file())

    def test_each_launch_has_private_startup_disabled_state_and_registered_gate(self):
        with tempfile.TemporaryDirectory(prefix="vs-calibration-state-") as directory:
            root = Path(directory)
            emulator = root / "qemu-arm"
            emulator.write_bytes(b"synthetic; never executed")
            core = root / "verysync"
            core.write_bytes(b"synthetic; never executed")
            commands = []

            def inspect(command, child_env, state):
                config = state / "appconf.yaml"
                self.assertEqual(config.read_text(), "auto_startup: false\n")
                self.assertEqual(config.stat().st_mode & 0o777, 0o600)
                self.assertEqual(child_env["VSMONITORED"], "yes")
                commands.append(command)
                return {"exit_code": 0, "version_probe_passed": True}

            with patch.object(HELPER, "capture_version", side_effect=inspect), contextlib.redirect_stdout(io.StringIO()):
                HELPER.calibrate(root, core, "arm926")
            self.assertEqual(len(commands), 6)
            self.assertTrue(all(command[0] == str(core.resolve()) for command in commands[::2]))
            self.assertTrue(all(command[:3] == [str(emulator.resolve()), str(core.resolve()), str(core.resolve())]
                                for command in commands[1::2]))
            rows = json.loads((root / "cpu-version-calibration.json").read_text())
            self.assertEqual([row["execution_path"] for row in rows[:2]],
                             ["sdk_registered_exec", "explicit_emulator_exec"])

    def test_registered_launch_error_is_recorded_and_cannot_use_explicit_success(self):
        with tempfile.TemporaryDirectory(prefix="vs-calibration-exec-error-") as directory:
            root = Path(directory)
            (root / "qemu-arm").write_bytes(b"synthetic; never executed")
            core = root / "verysync"
            core.write_bytes(b"synthetic; never executed")
            results = [OSError(8, "private-canary"),
                       *[{"exit_code": 0, "version_probe_passed": True} for _ in range(5)]]
            with patch.object(HELPER, "capture_version", side_effect=results), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, "requested CPU"):
                    HELPER.calibrate(root, core, "arm926")
            text = (root / "cpu-version-calibration.json").read_text()
            rows = json.loads(text)
            self.assertEqual(len(rows), 6)
            self.assertEqual(rows[0]["launch_os_error"], 8)
            self.assertFalse(rows[0]["version_probe_passed"])
            self.assertNotIn("private-canary", text)


class OtherVersionProfileContracts(unittest.TestCase):
    def test_each_profile_uses_its_exact_interpreter_cpu_and_private_state(self):
        profiles = {
            "linux-loong64-standard": ("qemu-loongarch64", "la464"),
            "linux-ppc64le-standard": ("qemu-ppc64le", "power8"),
            "linux-riscv64-standard": ("qemu-riscv64", "rv64"),
            "linux-s390x-standard": ("qemu-s390x", "max"),
            "linux-mips-standard": ("qemu-mips", "24Kf"),
            "linux-mipsle-standard": ("qemu-mipsel", "24Kf"),
            "linux-mips64-standard": ("qemu-mips64", "MIPS64R2-generic"),
            "linux-mips64le-standard": ("qemu-mips64el", "MIPS64R2-generic"),
        }
        for profile, (emulator_name, cpu) in profiles.items():
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                emulator = root / emulator_name
                emulator.write_bytes(b"synthetic; never executed")
                core = root / "verysync"
                core.write_bytes(b"synthetic; never executed")
                commands = []
                states = []

                def inspect(command, child_env, state):
                    self.assertEqual(child_env["QEMU_CPU"], cpu)
                    self.assertEqual(child_env["VSMONITORED"], "yes")
                    self.assertEqual((state / "appconf.yaml").read_text(), "auto_startup: false\n")
                    self.assertEqual((state / "appconf.yaml").stat().st_mode & 0o777, 0o600)
                    self.assertEqual(Path(child_env["HOME"]).parent, state)
                    commands.append(command)
                    states.append(state)
                    return {"exit_code": 0, "version_probe_passed": True}

                with patch.object(HELPER, "capture_version", side_effect=inspect), contextlib.redirect_stdout(io.StringIO()):
                    HELPER.calibrate_linux_profile(root, core, profile)
                self.assertEqual(len(commands), 2)
                self.assertEqual(commands[0][:-3], [str(core)])
                self.assertEqual(commands[1][:-3], [str(emulator), str(core), str(core)])
                self.assertNotEqual(states[0], states[1])
                self.assertTrue(all(not state.exists() for state in states))

    def test_unknown_profile_is_rejected_before_any_launch(self):
        with patch.object(HELPER, "capture_version") as capture:
            with self.assertRaisesRegex(ValueError, "profile"):
                HELPER.calibrate_linux_profile(Path("unused"), Path("unused"), "unknown")
        capture.assert_not_called()

    def test_explicit_failure_is_retained_and_cannot_pass_with_registered_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "qemu-riscv64").write_bytes(b"synthetic; never executed")
            core = root / "verysync"
            core.write_bytes(b"synthetic; never executed")
            outcomes = [{"exit_code": 0, "version_probe_passed": True},
                        {"exit_code": -4, "version_probe_passed": False}]
            with patch.object(HELPER, "capture_version", side_effect=outcomes), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, "both"):
                    HELPER.calibrate_linux_profile(root, core, "linux-riscv64-standard")
            rows = json.loads((root / "cpu-version-calibration.json").read_text())
            self.assertEqual(len(rows), 2)
            self.assertFalse(rows[1]["version_probe_passed"])


if __name__ == "__main__":
    unittest.main()
