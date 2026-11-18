"""The grouped storage check distinguishes an exact SFTP child from its parent."""

import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "verify_backends", Path(__file__).resolve().parents[1] / "verify-native-storage-backends.py"
)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)

CHILD = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 15.89s\n"
OUTER = "test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 167.77s\n"


class StorageReceipts(unittest.TestCase):
    def test_exact_known_sftp_child_and_complete_outer_pass(self):
        self.assertTrue(CHECK.accepts_suite("local_sync_protocol_engine", CHILD + OUTER, 0, True))

    def test_missing_child_outer_skip_and_extra_child_fail(self):
        for log in (OUTER, CHILD + OUTER.replace("0 ignored", "1 ignored"), CHILD + CHILD + OUTER):
            with self.subTest(log=log):
                self.assertFalse(CHECK.accepts_suite("local_sync_protocol_engine", log, 0, True))

    def test_runtime_requires_actual_registered_refusal_contract(self):
        self.assertTrue(CHECK.accepts_suite("local_sync_runtime_engine", OUTER, 0, True))
        self.assertFalse(CHECK.accepts_suite("local_sync_runtime_engine", OUTER.replace("11 passed", "10 passed"), 0, True))

    def test_rust_failure_and_missing_cleanup_fail(self):
        self.assertFalse(CHECK.accepts_suite("local_sync_runtime_engine", OUTER, 101, True))
        self.assertFalse(CHECK.accepts_suite("local_sync_runtime_engine", OUTER, 0, False))


if __name__ == "__main__":
    unittest.main()
