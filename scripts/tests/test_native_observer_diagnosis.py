"""Wait diagnosis preserves actual counts/errors and cannot claim frozen identity."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('diagnostic', Path(__file__).resolve().parents[1]/'diagnose-native-observer.py')
D = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)


class NativeObserverDiagnosisContracts(unittest.TestCase):
    def test_controlled_intel_preparation_is_owned_guarded_and_keeps_full_v27_work(self):
        root = Path(__file__).resolve().parents[2]
        branch = 'ci/intel-v27-preparation-window-20261118-01a1ca9b'
        engine = (root / '.github/workflows/engine-tests.yml').read_text()
        guarded = [x[len('    if: '):] for x in engine.splitlines()
                   if x.startswith('    if: ') and branch in x]
        self.assertEqual(len(guarded), 10)
        for file in ['resource-collection.yml', 'native-observer-activity.yml']:
            text = (root / '.github/workflows' / file).read_text()
            guarded.append(next(x[len('    if: '):] for x in text.splitlines()
                                if x.startswith('    if: ') and branch in x))
        workflow = (root / '.github/workflows/native-observer-diagnosis.yml').read_text()
        steps = []
        for name in ['Retain original counter and timer calibration for the controlled supplement',
                     'Require both predetermined Kqueue short windows before complete preparation',
                     'Run all eight unchanged v27 preparation members in both original orders']:
            block = workflow.split('      - name: ' + name + '\n', 1)[1].split('\n      - ', 1)[0]
            condition = next(x[len('        if: '):] for x in block.splitlines()
                             if x.startswith('        if: '))
            self.assertNotIn('always()', condition)
            self.assertNotIn('continue-on-error', block)
            steps.append((condition, block))
        self.assertIn('for index in (0, 3):', steps[1][1])
        self.assertIn("quality['status'] == 'VALID'", steps[1][1])
        self.assertIn('scripts/preflight-native-resources.py', steps[2][1])
        self.assertIn('--protocol tests/fixtures/resource-protocol.json', steps[2][1])
        self.assertIn('--toolchain 1.85.0', steps[2][1])
        self.assertNotIn('collect-native-resources.py', workflow)
        self.assertIn('vs-intel-preparation-window/**/pretrial-result.json', workflow)
        for event, draft, repo, head in [
            ('pull_request', True, 'AresJef/verysync-sidecar', branch),
            ('pull_request', False, 'AresJef/verysync-sidecar', branch),
            ('pull_request', True, 'external/fork', branch),
            ('workflow_dispatch', True, 'AresJef/verysync-sidecar', branch),
            ('pull_request', True, 'AresJef/verysync-sidecar', 'unrelated')]:
            github = SimpleNamespace(event_name=event, head_ref=head,
                repository='AresJef/verysync-sidecar', event=SimpleNamespace(action='synchronize',
                    pull_request=SimpleNamespace(draft=draft,
                        head=SimpleNamespace(repo=SimpleNamespace(full_name=repo)))))
            owned = event == 'pull_request' and draft and repo == github.repository and head == branch
            def evaluate(condition):
                expression = re.sub(r'!(?!=)', 'not ', condition.replace('&&', ' and ').replace('||', ' or '))
                return bool(eval(expression, {'__builtins__': {}}, {'github': github, 'false': False, 'true': True}))
            for condition in guarded:
                actual = evaluate(condition)
                if owned:
                    self.assertFalse(actual)
                else:
                    github.head_ref = 'unrelated'
                    self.assertEqual(actual, evaluate(condition))
                    github.head_ref = head
            for condition, _ in steps:
                self.assertEqual(evaluate(condition), owned)

    def test_intel_wait_draft_scopes_other_jobs_and_preserves_ready_manual_and_forks(self):
        root = Path(__file__).resolve().parents[2]
        branch = 'ci/intel-native-wait-diagnosis-20261118-01a1ca9b'
        engine = (root / '.github/workflows/engine-tests.yml').read_text()
        conditions = [x[len('    if: '):] for x in engine.splitlines()
                      if x.startswith('    if: ') and branch in x]
        self.assertEqual(len(conditions), 10)
        resource = (root / '.github/workflows/resource-collection.yml').read_text()
        conditions.append(next(x[len('    if: '):] for x in resource.splitlines()
                               if x.startswith('    if: ')))
        for event, draft, repo in [('pull_request', True, 'AresJef/verysync-sidecar'),
                                  ('pull_request', False, 'AresJef/verysync-sidecar'),
                                  ('pull_request', True, 'external/fork'),
                                  ('workflow_dispatch', True, 'AresJef/verysync-sidecar')]:
            github = SimpleNamespace(event_name=event, head_ref=branch,
                repository='AresJef/verysync-sidecar', event=SimpleNamespace(
                    action='synchronize', pull_request=SimpleNamespace(draft=draft,
                        head=SimpleNamespace(repo=SimpleNamespace(full_name=repo)))))
            for condition in conditions:
                expression = re.sub(r'!(?!=)', 'not ', condition.replace('&&', ' and ').replace('||', ' or '))
                def evaluate():
                    return bool(eval(expression, {'__builtins__': {}}, {'github': github, 'false': False, 'true': True}))
                actual = evaluate()
                if event == 'pull_request' and draft and repo == github.repository:
                    self.assertFalse(actual)
                else:
                    github.head_ref = 'unrelated'
                    self.assertEqual(actual, evaluate())
                    github.head_ref = branch

    def test_arm_owned_draft_selects_matching_runner_and_core_without_broadening_scope(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / '.github/workflows/native-observer-diagnosis.yml').read_text()
        runner = next(x.strip()[len('runs-on: '):] for x in workflow.splitlines()
                      if x.strip().startswith('runs-on: '))
        package = re.search(r'--package "(\$\{\{.*?\}\})"', workflow).group(1)
        branch = 'ci/arm-native-wait-diagnosis-20261118-01a1ca9b'
        for event, draft, head, repo, expected in [
            ('pull_request', True, branch, 'AresJef/verysync-sidecar', ('macos-15', 'macos-arm64-standard')),
            ('pull_request', False, branch, 'AresJef/verysync-sidecar', ('macos-15-intel', 'macos-amd64-standard')),
            ('pull_request', True, branch, 'external/fork', ('macos-15-intel', 'macos-amd64-standard')),
            ('workflow_dispatch', True, branch, 'AresJef/verysync-sidecar', ('macos-15-intel', 'macos-amd64-standard')),
            ('pull_request', True, 'unrelated', 'AresJef/verysync-sidecar', ('macos-15-intel', 'macos-amd64-standard')),
        ]:
            github = SimpleNamespace(event_name=event, head_ref=head,
                repository='AresJef/verysync-sidecar', event=SimpleNamespace(pull_request=SimpleNamespace(
                    draft=draft, head=SimpleNamespace(repo=SimpleNamespace(full_name=repo)))))
            def evaluate(expression):
                expression = expression.removeprefix('${{').removesuffix('}}')
                expression = expression.replace('&&', ' and ').replace('||', ' or ')
                expression = re.sub(r'!(?!=)', 'not ', expression)
                return eval(expression.strip(), {'__builtins__': {}},
                            {'github': github, 'false': False, 'true': True})
            self.assertEqual((evaluate(runner), evaluate(package)), expected)
            engine = (root / '.github/workflows/engine-tests.yml').read_text()
            conditions = [line[len('    if: '):] for line in engine.splitlines()
                          if line.startswith('    if: ') and branch in line]
            self.assertEqual(len(conditions), 10)
            for expression in conditions:
                actual = evaluate(expression)
                if expected[0] == 'macos-15':
                    self.assertFalse(actual)
                else:
                    github.head_ref = 'unrelated'
                    self.assertEqual(actual, evaluate(expression))
                    github.head_ref = head

    def test_diagnostic_draft_never_launches_a_second_frozen_acquisition(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / '.github/workflows/resource-collection.yml').read_text()
        expression = next(x[len('    if: '):] for x in workflow.splitlines() if x.startswith('    if: '))
        expression = re.sub(r'!(?!=)', 'not ', expression.replace('&&', ' and ').replace('||', ' or '))
        branch = 'ci/arm-native-wait-diagnosis-20261118-01a1ca9b'
        for event, draft, head, repo in [
            ('pull_request', True, branch, 'AresJef/verysync-sidecar'),
            ('pull_request', False, branch, 'AresJef/verysync-sidecar'),
            ('pull_request', True, branch, 'external/fork'),
            ('workflow_dispatch', True, branch, 'AresJef/verysync-sidecar'),
            ('pull_request', True, 'unrelated', 'AresJef/verysync-sidecar'),
        ]:
            for action, label in [('synchronize', 'none'), ('labeled', 'resource-formal'), ('labeled', 'other')]:
                github = SimpleNamespace(event_name=event, head_ref=head, repository='AresJef/verysync-sidecar',
                    event=SimpleNamespace(action=action, label=SimpleNamespace(name=label),
                        pull_request=SimpleNamespace(draft=draft, head=SimpleNamespace(repo=SimpleNamespace(full_name=repo)))))
                original = event != 'pull_request' or action != 'labeled' or label == 'resource-formal'
                owned_draft = event == 'pull_request' and draft and head == branch and repo == github.repository
                self.assertEqual(bool(eval(expression, {'__builtins__': {}}, {'github': github})),
                                 original and not owned_draft)

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
