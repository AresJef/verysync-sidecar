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
    @staticmethod
    def mach_library(numer=125, denom=3, status=0):
        library = Mock()
        def fill(pointer):
            pointer._obj.numer = numer
            pointer._obj.denom = denom
            return status
        library.mach_timebase_info.side_effect = fill
        library.mach_wait_until.return_value = 0
        return library

    def test_absolute_timer_converts_native_units_and_skips_missed_deadlines_without_spinning(self):
        for numer, denom in [(125, 3), (1, 1), (7, 3)]:
            library = self.mach_library(numer, denom)
            period = (10_000_000 * denom + numer - 1) // numer
            first = 100 + period
            library.mach_absolute_time.side_effect = [100, first+2*period+5, first+3*period]
            with patch.object(METRICS.sys, "platform", "darwin"), patch("ctypes.CDLL", return_value=library):
                timer = METRICS.SamplerTicker(10, darwin_backend="mach")
                self.assertEqual(timer.backend, "darwin-mach-absolute-deadline")
                self.assertEqual(timer.parameters["period_ticks"], period)
                self.assertGreaterEqual(period*numer, 10_000_000*denom)
                self.assertLess(period*numer, 10_000_000*denom+numer)
                timer.wait()
                self.assertEqual(timer.expirations, 3)
                timer.wait()
                self.assertEqual(timer.expirations, 1)
                self.assertEqual([c.args[0] for c in library.mach_wait_until.call_args_list],
                                 [first, first+3*period])
                self.assertEqual(library.mach_absolute_time.call_count, 3)
                timer.close()

    def test_absolute_timer_native_failure_and_early_success_are_errors_without_retry(self):
        for status, returned, reason in [(14, 100, "mach-wait-failed"),
                                         (0, 100, "mach-wait-returned-early")]:
            library = self.mach_library()
            library.mach_absolute_time.side_effect = [100, returned]
            library.mach_wait_until.return_value = status
            with patch.object(METRICS.sys, "platform", "darwin"), patch("ctypes.CDLL", return_value=library):
                timer = METRICS.SamplerTicker(10, darwin_backend="mach")
                with self.assertRaises(METRICS.TimerWaitError) as caught:
                    timer.wait()
                self.assertEqual(caught.exception.diagnostic["reason"], reason)
                self.assertEqual(caught.exception.diagnostic["native_details"]["kernel_return"], status)
                self.assertEqual(library.mach_wait_until.call_count, 1)

    def test_absolute_timer_rejects_invalid_timebase_and_unrepresentable_deadline_before_wait(self):
        for numer, denom, status, clock in [(0, 3, 0, 100), (125, 0, 0, 100),
                                           (125, 3, 5, 100), (125, 3, 0, 2**64-1)]:
            library = self.mach_library(numer, denom, status)
            library.mach_absolute_time.return_value = clock
            with patch.object(METRICS.sys, "platform", "darwin"), patch("ctypes.CDLL", return_value=library):
                with self.assertRaises(METRICS.TimerWaitError):
                    METRICS.SamplerTicker(10, darwin_backend="mach")
                library.mach_wait_until.assert_not_called()

    def test_other_platform_timer_does_not_load_darwin_libraries_or_change_sleep(self):
        for platform in ["linux", "win32"]:
            with patch.object(METRICS.sys, "platform", platform), patch("ctypes.CDLL") as library, patch.object(METRICS.time, "sleep") as sleep:
                timer = METRICS.SamplerTicker(10)
                timer.wait()
                self.assertEqual(timer.backend, "monotonic-sleep")
                library.assert_not_called()
                sleep.assert_called_once_with(.01)

    def test_owned_cleanup_records_actual_exit_and_keeps_original_acquisition_failure(self):
        import tempfile
        import json
        for cleanup_fails in [False, True]:
            with tempfile.TemporaryDirectory() as root:
                child, timer = Mock(), Mock()
                child.poll.return_value = None
                child.returncode = None
                child.wait.side_effect = TimeoutError("owned cleanup deadline") if cleanup_fails else None
                child.wait.return_value = 101
                report = {"acquisition_error": {"phase": "measure", "type": "TimerWaitError",
                                                "message": "empty-return"}}
                if cleanup_fails:
                    with self.assertRaisesRegex(TimeoutError, "owned cleanup deadline"):
                        METRICS.finish_owned_observation(child, timer, report, Path(root))
                else:
                    METRICS.finish_owned_observation(child, timer, report, Path(root))
                saved = json.loads((Path(root) / "preparation-result.json").read_text())
                self.assertEqual(saved["acquisition_error"], report["acquisition_error"])
                self.assertEqual(saved["exit_code"], None if cleanup_fails else 101)
                self.assertEqual("cleanup_error" in saved, cleanup_fails)
                self.assertEqual(json.loads((Path(root) / "safe-error.json").read_text()),
                                 report["acquisition_error"])
                self.assertNotIn("quality", saved)
                timer.close.assert_called_once_with()

    def test_raw_sample_buffer_defers_io_and_preserves_every_row_on_failure(self):
        import tempfile
        import json
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "samples.jsonl"
            with self.assertRaisesRegex(RuntimeError, "native attempt failed"):
                with METRICS.BufferedSamples(path) as samples:
                    for n in range(7):
                        samples.append({"sequence": n, "raw": "native"})
                    self.assertFalse(path.exists())
                    raise RuntimeError("native attempt failed")
            rows = [json.loads(line) for line in path.read_bytes().splitlines()]
            self.assertEqual([row["sequence"] for row in rows], list(range(7)))
            self.assertEqual(len(rows), 7)

    def test_raw_sample_buffer_overflow_is_failure_without_dropping_saved_prefix(self):
        import tempfile
        import json
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "samples.jsonl"
            with patch.object(METRICS.BufferedSamples, "LIMIT", 3):
                with self.assertRaisesRegex(RuntimeError, "buffer limit exceeded"):
                    with METRICS.BufferedSamples(path) as samples:
                        for n in range(4):
                            samples.append({"sequence": n})
            self.assertEqual([json.loads(row)["sequence"] for row in path.read_bytes().splitlines()], [0, 1, 2])

    def test_non_darwin_process_activity_never_loads_foundation(self):
        with patch.object(METRICS.sys,"platform","linux"),patch("ctypes.CDLL") as library:
            self.assertIsNone(METRICS.observer_process_activity(worker_started=True))
            library.assert_not_called()

    def test_activity_cleanup_is_exact_and_failure_remains_an_error(self):
        guard=Mock();guard.report.return_value={"ended":True};report={}
        METRICS.finish_observer_activity(guard,report)
        guard.close.assert_called_once();self.assertTrue(report['observer_process_activity_after']['ended'])
        guard.close.side_effect=RuntimeError('synthetic native end failure')
        with self.assertRaises(RuntimeError):METRICS.finish_observer_activity(guard,report)
        self.assertEqual(report['activity_cleanup_error']['type'],'RuntimeError')

    def test_observer_policy_never_calls_native_qos_on_other_systems(self):
        with patch.object(METRICS.sys, "platform", "linux"), patch("ctypes.CDLL") as library:
            self.assertEqual(METRICS.observer_thread_policy()["policy"], "unchanged")
            library.assert_not_called()

    def test_observer_qos_is_self_only_and_native_failure_is_not_silenced(self):
        library = Mock()
        library.qos_class_self.side_effect = [0x15, 0x21]
        library.pthread_set_qos_class_self_np.return_value = 0
        with patch.object(METRICS.sys, "platform", "darwin"), patch("ctypes.CDLL", return_value=library):
            receipt = METRICS.observer_thread_policy(worker_started=True)
            self.assertEqual(receipt["observed"], 0x21)
            self.assertEqual(receipt["policy"], "darwin-user-interactive")
            self.assertTrue(receipt["worker_started_before_assignment"])
            library.pthread_set_qos_class_self_np.assert_called_once_with(0x21, 0)
            library.qos_class_self.side_effect = [0x15, 0x19]
            with self.assertRaisesRegex(RuntimeError, "QoS request failed"):
                METRICS.observer_thread_policy()
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

    def test_saved_observer_failure_cannot_be_revalidated_as_successful_native_data(self):
        for key in ["acquisition_error", "cleanup_error"]:
            report, rows = fixture()
            report[key] = {"type": "TimerWaitError", "message": "recorded failure"}
            self.assertEqual(METRICS.summarize(report, rows)["status"], "ERROR")

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
