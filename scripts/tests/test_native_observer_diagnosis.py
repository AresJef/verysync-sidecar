"""Wait diagnosis preserves actual counts/errors and cannot claim frozen identity."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('diagnostic', Path(__file__).resolve().parents[1]/'diagnose-native-observer.py')
D = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)


class NativeObserverDiagnosisContracts(unittest.TestCase):
    def test_timer_backend_is_bound_without_changing_other_source_inputs(self):
        original = {'sampler_sha256': 'original', 'rust_sources_sha256': 'unchanged'}
        rows = [D.source_binding(original, b'runner', b'sampler', activity_mode='on',
                    activity_bytes=b'helper', timer_backend=backend)
                for backend in [None, 'mach', 'critical-kqueue']]
        self.assertEqual(len({row['sampler_sha256'] for row in rows}), 3)
        for row, backend in zip(rows, [None, 'mach', 'critical-kqueue']):
            self.assertEqual(row['timer_backend'], backend)
            self.assertEqual(row['rust_sources_sha256'], 'unchanged')
            self.assertFalse(row['eligible_for_frozen_preparation_or_formal'])
        with self.assertRaises(ValueError):
            D.source_binding(original, b'runner', b'sampler', timer_backend='unknown')

    def test_timer_comparison_runs_four_fresh_pilots_with_balanced_order_and_same_activity(self):
        with tempfile.TemporaryDirectory() as parent:
            destination = Path(parent) / 'fresh'
            commands = []
            def run(command, **kwargs):
                commands.append(command)
                return SimpleNamespace(returncode=[0, 2, 2, 0][len(commands)-1])
            with patch.object(D.sys, 'platform', 'darwin'), patch.object(D.sys, 'argv',
                    ['diagnose', '--cargo', str(Path(parent)/'cargo'), '--timer-abba',
                     '--evidence-dir', str(destination)]), patch.object(D.subprocess, 'run', side_effect=run):
                self.assertEqual(D.main(), 0)
            result = json.loads((destination/'diagnosis-result.json').read_text())
            self.assertEqual(result['timer_backends'], ['critical-kqueue', 'mach', 'mach', 'critical-kqueue'])
            self.assertEqual(result['activity_modes'], ['on']*4)
            self.assertEqual([c['scenario'] for c in result['cases']], ['many-small']*4)
            self.assertEqual([c['exit_code'] for c in result['cases']], [0, 2, 2, 0])
            self.assertFalse(result['formal_sample'])
            self.assertEqual(len({c[c.index('--evidence-dir')+1] for c in commands}), 4)
            for command, backend in zip(commands, result['timer_backends']):
                self.assertEqual(command[command.index('--timer-backend')+1], backend)
                self.assertEqual(command[command.index('--activity-mode')+1], 'on')

    def test_bootstrap_changes_effective_identity_and_explicitly_refuses_frozen_roles(self):
        original = {'sampler_sha256': hashlib.sha256(b'original sampler').hexdigest(), 'rust_sources_sha256': 'unchanged'}
        result = D.source_binding(original, b'diagnostic runner', b'original sampler')
        self.assertNotEqual(result['sampler_sha256'], original['sampler_sha256'])
        self.assertEqual(result['unmodified_sampler_file_sha256'], original['sampler_sha256'])
        self.assertEqual(result['rust_sources_sha256'], 'unchanged')
        self.assertTrue(result['diagnostic_only'])
        self.assertFalse(result['eligible_for_frozen_preparation_or_formal'])
        self.assertEqual(original.keys(), {'sampler_sha256', 'rust_sources_sha256'})

    def test_activity_variants_and_helper_are_part_of_composite_identity(self):
        original={'sampler_sha256':'original','rust_sources_sha256':'unchanged'}
        off=D.source_binding(original,b'runner',b'sampler',activity_mode='off',activity_bytes=b'helper')
        on=D.source_binding(original,b'runner',b'sampler',activity_mode='on',activity_bytes=b'helper')
        changed=D.source_binding(original,b'runner',b'sampler',activity_mode='on',activity_bytes=b'changed')
        self.assertEqual(len({off['sampler_sha256'],on['sampler_sha256'],changed['sampler_sha256']}),3)
        for row in [off,on,changed]:
            self.assertTrue(row['diagnostic_only']);self.assertFalse(row['eligible_for_frozen_preparation_or_formal'])
            self.assertEqual(row['rust_sources_sha256'],'unchanged')

    def test_activity_starts_after_original_thread_policy_and_off_never_starts(self):
        events=[];activity=Mock()
        def original(*,worker_started):events.append(('original',worker_started));return {'observed':33}
        activity.begin.side_effect=lambda **kwargs:events.append(('activity',kwargs['worker_started'])) or {'started':True}
        result=D.activity_policy(original,'on',activity,worker_started=True)
        self.assertEqual(events,[('original',True),('activity',True)])
        self.assertEqual(result['observed'],33)
        events.clear();activity.reset_mock()
        self.assertFalse(D.activity_policy(original,'off',activity,worker_started=True)['process_activity']['started'])
        activity.begin.assert_not_called()

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
