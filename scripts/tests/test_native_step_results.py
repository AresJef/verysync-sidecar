"""Mandatory browser outcomes do not silently become skipped CI acceptance."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "native_results", Path(__file__).resolve().parents[1] / "check-native-step-results.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class NativeStepContracts(unittest.TestCase):
    def successful_steps(self, family):
        steps = {key: {"outcome": "success"} for key in HELPER.COMMON}
        steps["native_mechanism_" + family] = {"outcome": "success"}
        if family == "windows":
            steps["native_windows_ui"] = {"outcome": "success"}
        return steps

    def test_macos_browser_must_exist_and_really_pass(self):
        steps = self.successful_steps("macos")
        for outcome in [None, "skipped", "failure", "cancelled"]:
            if outcome is not None:
                steps["native_browser_engine"] = {"outcome": outcome}
            self.assertIn("native_browser_engine", HELPER.failures("macos-arm64-standard", steps))
        steps["native_browser_engine"] = {"outcome": "success"}
        self.assertEqual(HELPER.failures("macos-arm64-standard", steps), [])

    def test_other_platform_browser_scope_does_not_waive_existing_gates(self):
        for family in ["windows", "linux"]:
            steps = self.successful_steps(family)
            steps["native_browser_engine"] = {"outcome": "skipped"}
            self.assertEqual(HELPER.failures(family + "-amd64-standard", steps), [])
            steps["native_mechanism_" + family] = {"outcome": "failure"}
            self.assertIn("native_mechanism_" + family,
                          HELPER.failures(family + "-amd64-standard", steps))

    def test_unknown_new_native_failure_remains_required(self):
        steps = self.successful_steps("linux")
        steps["native_future_effect"] = {"outcome": "failure"}
        self.assertIn("native_future_effect", HELPER.failures("linux-arm64-standard", steps))


if __name__ == "__main__":
    unittest.main()
