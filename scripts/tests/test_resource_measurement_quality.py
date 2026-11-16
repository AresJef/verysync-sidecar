"""Quality validation never turns failed, missing or invalid counters into data."""
import copy
from contextlib import contextmanager
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location(
    "resource_metrics", Path(__file__).resolve().parents[1] / "measure-native-resources.py")
METRICS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(METRICS)


def fixture():
    def point(pid, at):
        return {"pid": pid, "creation_time": 100, "rss_bytes": 10000000,
                "cpu_user_s": 1, "cpu_system_s": 0,
                "read_start_ns": at, "read_end_ns": at+1000}
    before = [point(7, 1000000000), point(8, 1000002000)]
    after = [point(7, 3000000000), point(8, 3000002000)]
    report = {"exit_code": 0, "scenario": "idle", "repeats": 1,
              "identities": before, "before": before, "after": after,
              "events": [{"kind": "ready", "scenario": "idle", "repeats": 1,
                          "bytes_each": 8192, "files": 1}, {"kind": "begin"},
                         {"kind": "end", "elapsed_ns": 2000000000,
                          "completed_calls": 0, "transferred_bytes": 0},
                         {"kind": "complete", "all_actual_bytes_verified": True,
                          "source_config_identity_unchanged": True, "normal_owned_tree_exit": True}]}
    rows = [{"phase": "baseline", "start_ns": 990000000,
             "controller": point(7, 990000000), "engine": point(8, 990002000)}]
    for n in range(60):
        at = 1000010000 + n * 33500000
        rows.append({"phase": "measure", "start_ns": at,
                     "controller": point(7, at), "engine": point(8, at+2000)})
    return report, rows


class ResourceQualityContracts(unittest.TestCase):
    def test_observer_policy_never_calls_native_qos_on_other_systems(self):
        with patch.object(METRICS.sys, "platform", "linux"), patch("ctypes.CDLL") as library:
            self.assertEqual(METRICS.observer_thread_policy()["policy"], "unchanged")
            library.assert_not_called()

    def test_observer_qos_is_self_only_and_native_failure_is_not_silenced(self):
        library = Mock()
        library.qos_class_self.side_effect = [0x15, 0x19]
        library.pthread_set_qos_class_self_np.return_value = 0
        with patch.object(METRICS.sys, "platform", "darwin"), patch("ctypes.CDLL", return_value=library):
            receipt = METRICS.observer_thread_policy()
            self.assertEqual(receipt["observed"], 0x19)
            library.pthread_set_qos_class_self_np.assert_called_once_with(0x19, 0)
            library.qos_class_self.side_effect = [0x15, 0x15]
            library.pthread_set_qos_class_self_np.return_value = 1
            with self.assertRaisesRegex(RuntimeError, "QoS request failed"):
                METRICS.observer_thread_policy()

    def test_snapshot_batches_reads_without_reusing_a_previous_snapshot(self):
        class Process:
            pid = 7
            generation = 0
            active = False

            def is_running(self):
                if self.active:
                    raise AssertionError("identity must be checked before batching")
                return True

            @contextmanager
            def oneshot(self):
                self.generation += 1
                self.active = True
                try:
                    yield
                finally:
                    self.active = False

            def memory_info(self):
                return SimpleNamespace(rss=self.generation * 4096)

            def cpu_times(self):
                return SimpleNamespace(user=self.generation / 100, system=0)

            def create_time(self):
                return 100

        process = Process()
        first, second = METRICS.snapshot(process), METRICS.snapshot(process)
        self.assertEqual((first["rss_bytes"], second["rss_bytes"]), (4096, 8192))
        self.assertEqual((first["cpu_user_s"], second["cpu_user_s"]), (.01, .02))
        self.assertEqual(first["creation_time"], second["creation_time"])
        self.assertFalse(process.active)
        self.assertLessEqual(first["read_end_ns"], second["read_start_ns"])

    def test_snapshot_rejects_a_terminated_identity_before_reading_metrics(self):
        process = SimpleNamespace(is_running=lambda: False)
        with self.assertRaisesRegex(RuntimeError, "ended or was reused"):
            METRICS.snapshot(process)

    def test_observed_idle_zero_cpu_is_retained_as_valid(self):
        report, rows = fixture()
        result = METRICS.summarize(report, rows)
        self.assertEqual(result["status"], "VALID")
        self.assertEqual(result["engine"]["cpu_user_s"], 0)

    def test_failed_native_correctness_and_wrong_workload_are_errors(self):
        original, rows = fixture()
        for mutate in [lambda r: r.update(exit_code=101),
                       lambda r: r["events"][-1].update(normal_owned_tree_exit=False),
                       lambda r: r["events"][2].update(completed_calls=1),
                       lambda r: r["events"][0].update(bytes_each=1)]:
            report = copy.deepcopy(original)
            mutate(report)
            self.assertEqual(METRICS.summarize(report, rows)["status"], "ERROR")

    def test_reused_pid_and_decreasing_cpu_are_errors_not_zero(self):
        report, rows = fixture()
        for key, value in [("creation_time", 101), ("cpu_user_s", .5)]:
            changed = copy.deepcopy(rows)
            changed[20]["controller"][key] = value
            self.assertEqual(METRICS.summarize(report, changed)["status"], "ERROR")

    def test_lost_coverage_is_insufficient_instead_of_dropping_slow_rows(self):
        report, rows = fixture()
        incomplete = rows[:20] + rows[40:]
        result = METRICS.summarize(report, incomplete)
        self.assertEqual(result["status"], "INSUFFICIENT")
        self.assertEqual(result["samples"], 40)
        self.assertIn("sampling gap exceeded coverage limit", result["insufficient"])


if __name__ == "__main__":
    unittest.main()
