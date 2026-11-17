"""A timer diagnostic must retain invalid/missing events as errors."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("timer_probe",
    Path(__file__).resolve().parents[1] / "probe-macos-timers.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class TimerProbeContracts(unittest.TestCase):
    def fake(self, queue):
        return SimpleNamespace(kqueue=lambda: queue, kevent=lambda *a, **k: (a, k),
            KQ_FILTER_TIMER=-7, KQ_EV_ADD=1, KQ_EV_ENABLE=4, KQ_EV_ERROR=16384)

    def test_registration_error_releases_its_exact_queue(self):
        queue = Mock()
        queue.control.side_effect = OSError("synthetic registration refusal")
        with patch.object(HELPER, "select", self.fake(queue)), self.assertRaises(OSError):
            HELPER.CriticalKqueueTicker()
        queue.close.assert_called_once_with()

    def test_coalesced_expirations_are_retained_without_inventing_events(self):
        queue = Mock()
        queue.control.side_effect = [[], [SimpleNamespace(ident=1, filter=-7, flags=0, data=3)]]
        with patch.object(HELPER, "select", self.fake(queue)):
            ticker = HELPER.CriticalKqueueTicker()
            try:
                ticker.wait()
                self.assertEqual(ticker.expirations, 3)
                self.assertEqual(queue.control.call_args.args, (None, 1, 2))
            finally:
                ticker.close()
        queue.close.assert_called_once_with()

    def test_missing_error_wrong_identity_and_zero_expirations_do_not_become_samples(self):
        for event in [None, SimpleNamespace(ident=1, filter=-7, flags=16384, data=22),
                      SimpleNamespace(ident=2, filter=-7, flags=0, data=1),
                      SimpleNamespace(ident=1, filter=-7, flags=0, data=0)]:
            queue = Mock()
            queue.control.side_effect = [[], [] if event is None else [event]]
            with self.subTest(event=event), patch.object(HELPER, "select", self.fake(queue)):
                ticker = HELPER.CriticalKqueueTicker()
                try:
                    with self.assertRaises(RuntimeError):
                        ticker.wait()
                finally:
                    ticker.close()
            queue.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
