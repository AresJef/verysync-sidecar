"""Safety contracts for the explicit CI download helper, with synthetic archives."""
import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest
import warnings
import zipfile

SOURCE = Path(__file__).resolve().parents[1] / "prepare-test-engine.py"
SPEC = importlib.util.spec_from_file_location("prepare_test_engine", SOURCE)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)
ROOT = "verysync-macos-arm64-v2.33.2"


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
