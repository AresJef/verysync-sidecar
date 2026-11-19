"""Kernel ancestry and privilege guards for the CI-only mount setup."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "browser_namespace", Path(__file__).resolve().parents[1] / "browser-linux-namespace.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class NamespaceGuards(unittest.TestCase):
    def plan(self):
        return {"caller_pid": 101, "uid": 1001, "gid": 1001,
                "groups": [44, 1001], "parent_namespace": "mnt:[1]"}

    def status(self, path, *args, **kwargs):
        pid = Path(path).parts[-2]
        if pid == "202":
            return "PPid:\t101\n"
        if pid == "101":
            return "PPid:\t1\nUid:\t1001 1001 1001 1001\nGid:\t1001 1001 1001 1001\nGroups:\t44 1001\n"
        raise AssertionError("unexpected synthetic kernel path")

    def test_kernel_ancestor_and_distinct_namespace_are_both_required(self):
        with patch.object(HELPER.os, "getppid", return_value=202, create=True), \
             patch.object(HELPER.Path, "read_text", lambda path, *args, **kwargs: self.status(path, *args, **kwargs)), \
             patch.object(HELPER.os, "readlink", side_effect=lambda p: "mnt:[2]" if p == "/proc/self/ns/mnt" else "mnt:[1]"):
            HELPER.verify_caller(self.plan())
            for change in [{"caller_pid": 999}, {"parent_namespace": "invented namespace"},
                           {"uid": 1002}, {"gid": 1002}, {"groups": [1, 1001]}]:
                with self.assertRaises(ValueError):
                    HELPER.verify_caller(dict(self.plan(), **change))

    def test_same_kernel_namespace_is_refused_even_with_matching_plan(self):
        with patch.object(HELPER.os, "getppid", return_value=202, create=True), \
             patch.object(HELPER.Path, "read_text", lambda path, *args, **kwargs: self.status(path, *args, **kwargs)), \
             patch.object(HELPER.os, "readlink", return_value="mnt:[1]"):
            with self.assertRaises(ValueError):
                HELPER.verify_caller(self.plan())

    def test_root_identity_is_rejected_before_reading_any_source(self):
        with self.assertRaises(ValueError):
            HELPER.validate_plan({"uid": 0, "gid": 0}, 0)


if __name__ == "__main__":
    unittest.main()
