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

    def test_linux_browser_is_a_required_native_outcome(self):
        steps = self.successful_steps("linux")
        self.assertIn("native_browser_engine", HELPER.failures("linux-amd64-standard", steps))
        steps["native_browser_engine"] = {"outcome": "success"}
        self.assertEqual(HELPER.failures("linux-amd64-standard", steps), [])

    def test_other_platform_browser_scope_does_not_waive_existing_gates(self):
        for family in ["windows"]:
            steps = self.successful_steps(family)
            steps["native_browser_engine"] = {"outcome": "skipped"}
            self.assertEqual(HELPER.failures(family + "-amd64-standard", steps), [])
            steps["native_mechanism_" + family] = {"outcome": "failure"}
            self.assertIn("native_mechanism_" + family,
                          HELPER.failures(family + "-amd64-standard", steps))

    def test_unknown_new_native_failure_remains_required(self):
        steps = self.successful_steps("linux")
        steps["native_browser_engine"] = {"outcome": "success"}
        steps["native_future_effect"] = {"outcome": "failure"}
        self.assertIn("native_future_effect", HELPER.failures("linux-arm64-standard", steps))

    def test_disk_full_cannot_be_absent_skipped_or_failed_on_any_family(self):
        for family in ["macos", "linux", "windows"]:
            for outcome in [None, "skipped", "failure", "cancelled"]:
                steps = self.successful_steps(family)
                steps["native_browser_engine"] = {"outcome": "success"}
                steps.pop("native_disk_full_engine")
                if outcome is not None:
                    steps["native_disk_full_engine"] = {"outcome": outcome}
                self.assertIn("native_disk_full_engine", HELPER.failures(family + "-arm64-standard", steps))


class WindowsBrowserWorkflowContracts(unittest.TestCase):
    def job(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/engine-tests.yml").read_text()
        marker = "  windows-native-browser-acceptance:\n"
        self.assertTrue(marker in workflow, "required Windows native-browser CI job is absent")
        return workflow.split(marker, 1)[1].split("\n  host-watch-limit-positive:", 1)[0]

    def test_windows_sdk_acceptance_is_not_a_branch_or_manual_opt_in(self):
        job = self.job()
        self.assertNotIn("\n    if:", job)
        self.assertNotIn("continue-on-error:", job)
        for runner, target in [("windows-2022", "x86_64-pc-windows-msvc"),
                               ("windows-11-arm", "aarch64-pc-windows-msvc")]:
            self.assertIn("runner: " + runner, job)
            self.assertIn("rust: " + target, job)
        self.assertIn("--use-effective-progid", job)

    def test_manual_and_ready_runs_require_actual_sdk_execution_and_exact_cleanup(self):
        job = self.job()
        for name in ["Prepare the exact fixed private core for the SDK browser case",
                     "Require actual Windows SDK browser effects and native-root cancellation"]:
            step = job.split("      - name: " + name + "\n", 1)[1].split("      - name:", 1)[0]
            self.assertNotIn("        if:", step)
        self.assertIn("scripts/run-windows-browser-tests.py", job)
        self.assertIn("check=True", job)
        self.assertIn("if: always() && steps.browser_fixed_core.outcome == 'success'", job)
        self.assertIn("scripts/prepare-test-engine.py check-cleanup", job)


if __name__ == "__main__":
    unittest.main()
