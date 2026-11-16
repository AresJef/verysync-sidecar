"""Quality validation never turns failed, missing or invalid counters into data."""
import copy
import importlib.util
from pathlib import Path
import unittest

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
