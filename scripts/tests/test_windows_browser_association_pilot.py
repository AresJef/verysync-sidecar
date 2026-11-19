"""The standalone protocol pilot must refuse ordinary/local execution."""
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1] / "probe-windows-browser-associations.py"
SPEC = importlib.util.spec_from_file_location("windows_browser_association_pilot", SOURCE)
PILOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PILOT)


class ScopeContracts(unittest.TestCase):
    def test_effective_mode_reads_existing_user_choice_and_targets_only_current_progid(self):
        reg = SimpleNamespace(HKEY_CLASSES_ROOT="merged")
        choice = {"values": [["ProgId", 1, "OwnedBrowser.HTML"], ["Hash", 1, "original"]], "children": {}}
        def snapshot(_reg, path, *args, **kwargs):
            return choice if path.endswith("UserChoice") else None
        with patch.object(PILOT, "tree_snapshot", side_effect=snapshot), \
                patch.object(PILOT, "effective_handler", return_value="original.exe"), \
                patch.object(PILOT, "effective_association", return_value="OwnedBrowser.HTML"):
            transaction = PILOT.ProtocolTransaction(reg, use_effective_progid=True)
            self.assertEqual(transaction.targets, {"http": "OwnedBrowser.HTML", "https": "OwnedBrowser.HTML"})
            self.assertEqual(transaction.before, {"OwnedBrowser.HTML": None})
            self.assertEqual(len(transaction.choices), 2)
            self.assertTrue(all(value == choice for value in transaction.choices.values()))
            with self.assertRaisesRegex(ValueError, "existing UserChoice"):
                PILOT.ProtocolTransaction(reg)

    def test_effective_mode_rejects_unbounded_or_traversing_registry_targets(self):
        for target in [None, "", "../escape", "Applications\\browser.exe", "x" * 129]:
            with patch.object(PILOT, "tree_snapshot", return_value=None), \
                    patch.object(PILOT, "effective_handler", return_value="original.exe"), \
                    patch.object(PILOT, "effective_association", return_value=target):
                with self.assertRaisesRegex(ValueError, "bounded current native ProgID"):
                    PILOT.ProtocolTransaction(SimpleNamespace(), use_effective_progid=True)

    def test_merged_delegate_and_dde_are_refused_before_any_registry_write(self):
        reg = SimpleNamespace(HKEY_CLASSES_ROOT="merged")
        for delegated in [True, False]:
            with patch.object(PILOT, "tree_snapshot", return_value=None), \
                    patch.object(PILOT, "effective_handler", return_value="original.exe"), \
                    patch.object(PILOT, "effective_association", return_value="OwnedBrowser.HTML"):
                transaction = PILOT.ProtocolTransaction(reg, use_effective_progid=True)
            transaction.set_value = Mock()
            def snapshot(_reg, path, *args, **kwargs):
                self.assertEqual(kwargs.get("hive"), "merged")
                if delegated and path.endswith("command"):
                    return {"values": [["DelegateExecute", 1, "original-clsid"]], "children": {}}
                if not delegated and path.endswith("ddeexec"):
                    return {"values": [], "children": {}}
                return None
            with patch.object(PILOT, "tree_snapshot", side_effect=snapshot):
                with self.assertRaisesRegex(ValueError, "delegated|DDE"):
                    transaction.apply(Path("owned.exe"))
            transaction.set_value.assert_not_called()

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
