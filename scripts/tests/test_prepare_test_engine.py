"""Safety contracts for the explicit CI download helper, with synthetic archives."""
import importlib.util
import ctypes
import os
from pathlib import Path
import shutil
import stat
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch, Mock
from types import SimpleNamespace
import warnings
import zipfile

SOURCE = Path(__file__).resolve().parents[1] / "prepare-test-engine.py"
SPEC = importlib.util.spec_from_file_location("prepare_test_engine", SOURCE)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)
ROOT = "verysync-macos-arm64-v2.33.2"


class ProcessInventoryContracts(unittest.TestCase):
    def test_passive_native_tcp_snapshot_contains_only_the_selected_pid(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            with patch.object(HELPER, "owned_processes", return_value=[os.getpid()]):
                observed = HELPER.owned_tcp_listeners()
            self.assertTrue(any(row["pid"] == os.getpid() and row["address"] == "127.0.0.1"
                                and row["port"] == port for row in observed["tcp_listeners"]))
            self.assertTrue(all(row["pid"] == os.getpid() for row in observed["tcp_listeners"]))

    def test_windows_query_failure_requires_proven_exit_and_live_failure_is_not_empty(self):
        # Synthetic native-call verdicts, distinct from the real OS inventory test.
        for wait in [0, 258, 0xffffffff]:
            kernel = SimpleNamespace(QueryFullProcessImageNameW=Mock(return_value=False),
                                     WaitForSingleObject=Mock(return_value=wait))
            with patch.object(ctypes, "get_last_error", return_value=5, create=True), \
                 patch.object(ctypes, "WinError", side_effect=lambda code: OSError(code, "synthetic query failure"), create=True):
                if wait == 0:
                    self.assertIsNone(HELPER.windows_retained_process_image(kernel, 123))
                else:
                    with self.assertRaises(OSError) as raised:
                        HELPER.windows_retained_process_image(kernel, 123)
                    self.assertEqual(raised.exception.errno, 5)
                    self.assertEqual(raised.exception.native_operation, "query_full_process_image")
                    self.assertEqual(raised.exception.native_wait, wait)
            kernel.WaitForSingleObject.assert_called_once_with(123, 0)

    def test_windows_successful_image_read_does_not_require_or_infer_exit(self):
        image_path = r"C:\private owned\program.exe"
        def query(handle, flags, image, size):
            image.value = image_path
            return True
        kernel = SimpleNamespace(QueryFullProcessImageNameW=Mock(side_effect=query),
                                 WaitForSingleObject=Mock())
        self.assertEqual(HELPER.windows_retained_process_image(kernel, 123), image_path)
        kernel.WaitForSingleObject.assert_not_called()

    def test_live_private_process_is_found_through_an_absolute_path_alias(self):
        with tempfile.TemporaryDirectory(prefix="vs-process-test-") as root:
            parent = Path(root)
            unused = parent / "unused"
            unused.mkdir()
            if os.name == "nt":
                source = Path(os.environ["SystemRoot"]) / "System32" / "ping.exe"
                binary = parent / "private-liveness.exe"
                arguments = ["-n", "60", "127.0.0.1"]
                flags = subprocess.CREATE_NO_WINDOW
            else:
                source = Path("/bin/sleep")
                binary = parent / "private-liveness"
                arguments = ["60"]
                flags = 0
            shutil.copyfile(source, binary)
            binary.chmod(0o700)
            alias = unused / ".." / binary.name
            process = subprocess.Popen(
                [str(binary.resolve()), *arguments], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=flags,
            )
            try:
                deadline = time.monotonic() + 5
                while process.pid not in HELPER.owned_processes(str(alias)):
                    if process.poll() is not None or time.monotonic() >= deadline:
                        self.fail("the retained exact private live process was not observed")
                    time.sleep(0.01)
                self.assertIn(process.pid, HELPER.owned_processes(str(binary.resolve())))
                with patch.dict(os.environ, {"VERYSYNC_TEST_BINARY": str(alias)}):
                    with self.assertRaises(RuntimeError):
                        HELPER.check_cleanup()
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            self.assertEqual(HELPER.owned_processes(str(alias)), [])


class ExtractionContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vs-archive-test-")
        self.parent = Path(self.temp.name)
        self.archive = self.parent / "synthetic.zip"
        self.destination = self.parent / "output"
        self.destination.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def extract(self):
        return HELPER.extract_executable(
            self.archive, self.destination, ROOT, "verysync", "zip"
        )

    def test_service_sample_with_same_basename_is_not_selected(self):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr(ROOT + "/etc/linux-init.d/verysync", b"service sample")
            archive.writestr(ROOT + "/verysync", b"synthetic binary payload")
        path = self.extract()
        self.assertEqual(path.read_bytes(), b"synthetic binary payload")

    def test_traversal_is_rejected_before_writing_output(self):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr(ROOT + "/verysync", b"synthetic payload")
            archive.writestr("../outside", b"must not be extracted")
        with self.assertRaises(ValueError):
            self.extract()
        self.assertFalse((self.parent / "outside").exists())
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_symlink_cannot_be_the_selected_executable(self):
        info = zipfile.ZipInfo(ROOT + "/verysync")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr(info, "unrelated-target")
        with self.assertRaises(ValueError):
            self.extract()

    def test_duplicate_selected_entries_are_rejected(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.archive, "w") as archive:
                archive.writestr(ROOT + "/verysync", b"first")
                archive.writestr(ROOT + "/verysync", b"second")
        with self.assertRaises(ValueError):
            self.extract()

    def test_existing_destination_file_is_not_overwritten(self):
        existing = self.destination / "verysync"
        existing.write_bytes(b"keep existing bytes")
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr(ROOT + "/verysync", b"new bytes")
        with self.assertRaises(FileExistsError):
            self.extract()
        self.assertEqual(existing.read_bytes(), b"keep existing bytes")


if __name__ == "__main__":
    unittest.main()
