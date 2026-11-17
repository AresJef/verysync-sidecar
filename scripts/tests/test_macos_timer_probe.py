"""A timer diagnostic must retain invalid/missing events as errors."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("timer_sampler",
    Path(__file__).resolve().parents[1] / "measure-native-resources.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class TimerProbeContracts(unittest.TestCase):
    def fake(self, queue):
        return SimpleNamespace(kqueue=lambda: queue, kevent=lambda *a, **k: (a, k),
            KQ_FILTER_TIMER=-7, KQ_EV_ADD=1, KQ_EV_ENABLE=4, KQ_EV_ERROR=16384)

    def test_registration_error_releases_its_exact_queue(self):
        queue = Mock()
        queue.control.side_effect = OSError("synthetic registration refusal")
        with patch.object(HELPER.sys, "platform", "darwin"), patch.object(HELPER, "select", self.fake(queue)), self.assertRaises(OSError):
            HELPER.SamplerTicker(10)
        queue.close.assert_called_once_with()

    def test_coalesced_expirations_are_retained_without_inventing_events(self):
        queue = Mock()
        queue.control.side_effect = [[], [SimpleNamespace(ident=1, filter=-7, flags=0, data=3)]]
        with patch.object(HELPER.sys, "platform", "darwin"), patch.object(HELPER, "select", self.fake(queue)):
            ticker = HELPER.SamplerTicker(10)
            try:
                self.assertEqual(ticker.backend, "darwin-critical-kqueue")
                self.assertEqual(ticker.parameters, {"interval_ns": 10_000_000, "fflags": 36})
                ticker.wait()
                self.assertEqual(ticker.expirations, 3)
                self.assertEqual(queue.control.call_args.args, (None, 1, 2))
            finally:
                ticker.close()
        queue.close.assert_called_once_with()

    def test_missing_error_wrong_identity_and_zero_expirations_do_not_become_samples(self):
        for event in [None, SimpleNamespace(ident=1, filter=-7, flags=16384, data=22),
                      SimpleNamespace(ident=2, filter=-7, flags=0, data=1),
                      SimpleNamespace(ident=1, filter=-1, flags=0, data=1),
                      SimpleNamespace(ident=1, filter=-7, flags=0, data=0)]:
            queue = Mock()
            queue.control.side_effect = [[], [] if event is None else [event]]
            with self.subTest(event=event), patch.object(HELPER.sys, "platform", "darwin"), patch.object(HELPER, "select", self.fake(queue)):
                ticker = HELPER.SamplerTicker(10)
                try:
                    with self.assertRaises(HELPER.TimerWaitError) as caught:
                        ticker.wait()
                    self.assertEqual(caught.exception.diagnostic["reason"],
                        "critical-timer-empty-return" if event is None else "critical-timer-invalid-event")
                    self.assertGreaterEqual(caught.exception.diagnostic["wait_ns"], 0)
                    self.assertEqual(queue.control.call_count, 2)
                finally:
                    ticker.close()
            queue.close.assert_called_once_with()

    def test_syscall_failure_retains_errno_and_wait_span_without_retry(self):
        queue = Mock()
        queue.control.side_effect = [[], OSError(22, "synthetic syscall refusal")]
        with patch.object(HELPER.sys, "platform", "darwin"), patch.object(HELPER, "select", self.fake(queue)):
            ticker = HELPER.SamplerTicker(10)
            try:
                with self.assertRaises(HELPER.TimerWaitError) as caught:
                    ticker.wait()
                detail = caught.exception.diagnostic
                self.assertEqual(detail["reason"], "critical-timer-syscall-failed")
                self.assertEqual(detail["native_details"]["errno"], 22)
                self.assertGreaterEqual(detail["wait_ns"], 0)
                self.assertEqual(queue.control.call_count, 2)
            finally:
                ticker.close()
        queue.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
