"""Wait diagnosis preserves actual counts/errors and cannot claim frozen identity."""
import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('diagnostic', Path(__file__).resolve().parents[1]/'diagnose-native-observer.py')
D = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)


class NativeObserverDiagnosisContracts(unittest.TestCase):
    def test_bootstrap_changes_effective_identity_and_explicitly_refuses_frozen_roles(self):
        original = {'sampler_sha256': hashlib.sha256(b'original sampler').hexdigest(), 'rust_sources_sha256': 'unchanged'}
        result = D.source_binding(original, b'diagnostic runner', b'original sampler')
        self.assertNotEqual(result['sampler_sha256'], original['sampler_sha256'])
        self.assertEqual(result['unmodified_sampler_file_sha256'], original['sampler_sha256'])
        self.assertEqual(result['rust_sources_sha256'], 'unchanged')
        self.assertTrue(result['diagnostic_only'])
        self.assertFalse(result['eligible_for_frozen_preparation_or_formal'])
        self.assertEqual(original.keys(), {'sampler_sha256', 'rust_sources_sha256'})

    def test_delayed_native_wait_keeps_wall_cpu_expirations_and_exact_cleanup(self):
        inner = Mock(backend='original', parameters={'original': True}, expirations=9)
        rows = []
        timer = D.DiagnosticTicker(inner, rows)
        with patch.object(D.time, 'perf_counter_ns', side_effect=[100, 90000100]), patch.object(D.time, 'thread_time_ns', side_effect=[1000, 201000]):
            timer.wait()
        timer.close()
        self.assertEqual(rows, [{'start_ns': 100, 'end_ns': 90000100, 'thread_cpu_ns': 200000,
                                'actual_expirations': 9, 'error_type': None}])
        inner.wait.assert_called_once_with()
        inner.close.assert_called_once_with()

    def test_native_error_is_retained_and_never_retried(self):
        inner = Mock(backend='original', parameters={}, expirations=None)
        inner.wait.side_effect = OSError('synthetic original wait error')
        rows = []
        timer = D.DiagnosticTicker(inner, rows)
        with self.assertRaises(OSError): timer.wait()
        self.assertEqual(rows[0]['error_type'], 'OSError')
        self.assertIsNone(rows[0]['actual_expirations'])
        inner.wait.assert_called_once_with()

    def test_wait_overflow_is_error_without_calling_native_or_dropping_prefix(self):
        inner = Mock(backend='original', parameters={})
        rows = [{'retained': True}]
        with patch.object(D, 'LIMIT', 1), self.assertRaises(RuntimeError):
            D.DiagnosticTicker(inner, rows).wait()
        self.assertEqual(rows, [{'retained': True}])
        inner.wait.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, 'GC diagnostic bound'):
            D.DiagnosticTicker(inner, [], lambda: True).wait()
        inner.wait.assert_not_called()


if __name__ == '__main__':
    unittest.main()
