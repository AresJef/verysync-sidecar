"""Native browser acceptance may only mutate an explicitly owned hosted VM."""
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import threading
import subprocess
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

SPEC = importlib.util.spec_from_file_location("windows_browser_runner", Path(__file__).resolve().parents[1] / "run-windows-browser-tests.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class ScopeContracts(unittest.TestCase):
    def test_silent_child_timeout_terminates_and_reaps_before_reporting_stopped(self):
        released = threading.Event()
        class SilentOutput:
            def __iter__(self):
                if not released.wait(1):
                    raise RuntimeError("output remained blocked")
                return iter(())
        process = Mock()
        process.stdout = SilentOutput()
        process.wait.side_effect = [subprocess.TimeoutExpired("owned-test", 180), -1]
        job = Mock()
        job.spawn.return_value = process
        job.terminate.side_effect = released.set
        report = {}
        with patch.object(RUNNER, "WindowsChildJob", return_value=job):
            with self.assertRaises(subprocess.TimeoutExpired):
                RUNNER.run_bounded(["owned-test"], {}, io.BytesIO(), report)
        self.assertTrue(released.is_set())
        self.assertTrue(report["contained_processes_stopped"])
        self.assertNotIn("owned_job_empty_before_outer_termination", report)
        self.assertEqual(process.wait.call_args_list[0].kwargs, {"timeout": 180})
        self.assertEqual(process.wait.call_args_list[1].kwargs, {"timeout": 5})
        job.terminate.assert_called_once()
        job.close.assert_called_once()

    def test_zero_test_success_never_counts_as_native_acceptance(self):
        process = Mock()
        process.stdout = io.BytesIO(b"native Windows browser evidence: synthetic\ntest result: ok. 0 passed; 0 failed; 0 ignored;\n")
        process.wait.return_value = 0
        job = Mock(); job.spawn.return_value = process
        report = {}
        with patch.object(RUNNER, "WindowsChildJob", return_value=job), patch.object(RUNNER.sys, "stdout", SimpleNamespace(buffer=io.BytesIO())):
            RUNNER.run_bounded(["owned-test"], {}, io.BytesIO(), report)
        self.assertFalse(report["native_sdk_effects_verified"])
        self.assertTrue(report["contained_processes_stopped"])

    def test_ordinary_host_is_refused_before_creating_evidence_or_loading_native_api(self):
        with tempfile.TemporaryDirectory() as root:
            evidence = Path(root) / "not-created"
            args = ["runner", "--cargo", sys.executable, "--toolchain", "synthetic", "--evidence-dir", str(evidence)]
            with patch.object(sys, "argv", args), patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ValueError, "Windows VM required"):
                    RUNNER.main()
            self.assertFalse(evidence.exists())

    def test_self_hosted_markers_do_not_authorize_registry_mutation(self):
        with tempfile.TemporaryDirectory() as root:
            evidence = Path(root) / "not-created"
            pilot = Mock()
            pilot.require_scope.return_value = None
            args = ["runner", "--cargo", sys.executable, "--toolchain", "synthetic", "--evidence-dir", str(evidence)]
            with patch.object(sys, "argv", args), patch.dict(os.environ, {"RUNNER_ENVIRONMENT": "self-hosted"}), patch.object(RUNNER, "load", return_value=pilot) as loader:
                with self.assertRaisesRegex(ValueError, "standard hosted Windows VM"):
                    RUNNER.main()
                self.assertEqual(loader.call_count, 1)
            self.assertFalse(evidence.exists())

    def test_reused_pid_with_different_image_is_not_signalled(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            expected = root / "expected.exe"; expected.write_bytes(b"owned")
            different = root / "other.exe"; different.write_bytes(b"not owned")
            (root / "7.owned").write_bytes(b"test journal")
            kernel = Mock()
            kernel.OpenProcess.return_value = 7
            kernel.WaitForSingleObject.return_value = 258
            def query(handle, flags, buffer, count):
                buffer.value = str(different)
                return 1
            kernel.QueryFullProcessImageNameW.side_effect = query
            with patch.object(RUNNER.ctypes, "WinDLL", return_value=kernel, create=True):
                with self.assertRaisesRegex(RuntimeError, "image differs"):
                    RUNNER.finish_actors(root, expected)
            self.assertFalse((root / "7.stop").exists())
            kernel.CloseHandle.assert_called_once_with(7)
            kernel.WaitForSingleObject.assert_called_once_with(7, 0)


if __name__ == "__main__":
    unittest.main()
