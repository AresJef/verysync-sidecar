"""Provisioning guards preserve host filesystems and actual failure outcomes."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "bounded_disk", Path(__file__).resolve().parents[1] / "run-bounded-disk-full-tests.py")
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class BoundedDiskContracts(unittest.TestCase):
    def test_local_invocation_cannot_provision_a_filesystem(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with patch.dict(os.environ, {}, clear=True), patch.object(DRIVER.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    DRIVER.OwnedVolume(root, root / "evidence")
                run.assert_not_called()
                self.assertEqual(list(root.iterdir()), [])

    def test_wrong_parent_and_reused_evidence_are_rejected_before_commands(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            reused = root / "evidence"
            reused.mkdir()
            env = {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux", "RUNNER_TEMP": str(root)}
            with patch.dict(os.environ, env), patch.object(sys, "platform", "linux"), patch.object(DRIVER.subprocess, "run") as run:
                for parent, evidence in [(root, reused), (root.parent, root / "fresh")]:
                    with self.assertRaises(ValueError):
                        DRIVER.OwnedVolume(parent, evidence)
                run.assert_not_called()

    def test_large_host_capacity_is_rejected_before_payload_marker(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            env = {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux", "RUNNER_TEMP": str(root)}
            with patch.dict(os.environ, env), patch.object(sys, "platform", "linux"):
                volume = DRIVER.OwnedVolume(root, root / "evidence")
                usage = type("Usage", (), {"total": 1024**4, "free": 1024**3})()
                with patch.object(volume, "command"), patch.object(volume, "linux_mount", return_value=True), patch.object(DRIVER.shutil, "disk_usage", return_value=usage):
                    with self.assertRaisesRegex(RuntimeError, "capacity"):
                        volume.attach()
                self.assertEqual(list(volume.mount.iterdir()), [])

    def test_foreign_mount_is_never_unmounted_or_deleted(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            env = {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux", "RUNNER_TEMP": str(root)}
            with patch.dict(os.environ, env), patch.object(sys, "platform", "linux"):
                volume = DRIVER.OwnedVolume(root, root / "evidence")
                mountinfo = f"42 1 0:1 / {volume.mount} rw - tmpfs another-owner rw\n"
                with patch.object(Path, "read_text", return_value=mountinfo), patch.object(volume, "command") as command:
                    with self.assertRaisesRegex(RuntimeError, "ownership"):
                        volume.cleanup()
                    command.assert_not_called()
                self.assertTrue(volume.mount.exists())
                self.assertFalse(volume.cleanup_verified)


if __name__ == "__main__":
    unittest.main()
