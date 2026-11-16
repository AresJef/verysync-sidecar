"""The standalone protocol pilot must refuse ordinary/local execution."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "probe-windows-browser-associations.py"
SPEC = importlib.util.spec_from_file_location("windows_browser_association_pilot", SOURCE)
PILOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PILOT)


class ScopeContracts(unittest.TestCase):
    def test_requires_windows_and_both_explicit_runner_markers_before_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "not-created"
            for platform, env in [("darwin", {}), ("linux", {}), ("win32", {}),
                                  ("win32", {"GITHUB_ACTIONS": "true"}),
                                  ("win32", {"RUNNER_OS": "Windows"})]:
                with patch.object(PILOT.sys, "platform", platform):
                    with self.assertRaises(ValueError):
                        PILOT.require_scope(path, env)
                self.assertFalse(path.exists())

    def test_only_fresh_child_of_explicit_runner_temporary_root_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as outside:
            root = Path(temporary).resolve()
            env = {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Windows", "RUNNER_TEMP": str(root)}
            original = os.environ.copy()
            with patch.object(PILOT.sys, "platform", "win32"):
                PILOT.require_scope(root / "not-created", env)
                for directory in [Path(outside) / "outside", root, Path("relative")]:
                    with self.assertRaises(ValueError):
                        PILOT.require_scope(directory, env)
            self.assertFalse((root / "not-created").exists())
            self.assertEqual(os.environ.copy(), original)
