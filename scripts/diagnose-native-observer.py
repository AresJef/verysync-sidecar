#!/usr/bin/env python3
"""Bounded wall/thread-CPU/GC diagnosis; never frozen resource members."""
import argparse
import gc
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time

LIMIT = 32768
ORDER = ['stream-small', 'many-small', 'many-small', 'stream-small']


def sampler_module():
    spec = importlib.util.spec_from_file_location('diagnostic_sampler', Path(__file__).with_name('measure-native-resources.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_binding(original, runner_bytes, sampler_bytes, *, activity_mode=None, activity_bytes=b"", timer_backend=None):
    if activity_mode not in (None, "off", "on"):
        raise ValueError("explicit activity comparison mode required")
    if timer_backend not in (None, "mach", "critical-kqueue"):
        raise ValueError("explicit native timer comparison backend required")
    extra = b"" if activity_mode is None else b"\0"+activity_mode.encode()+b"\0"+activity_bytes
    if timer_backend is not None:
        extra += b"\0timer\0"+timer_backend.encode()
    return {**original, 'unmodified_sampler_file_sha256': hashlib.sha256(sampler_bytes).hexdigest(),
            'diagnostic_runner_sha256': hashlib.sha256(runner_bytes).hexdigest(),
            'sampler_sha256': hashlib.sha256(runner_bytes+b'\0'+sampler_bytes+extra).hexdigest(),
            'diagnostic_only': True, 'eligible_for_frozen_preparation_or_formal': False,
            'activity_mode': activity_mode,
            'timer_backend': timer_backend,
            'activity_helper_sha256': hashlib.sha256(activity_bytes).hexdigest() if activity_mode else None}


def activity_policy(original, mode, activity, *, worker_started):
    result = original(worker_started=worker_started)
    if mode == "on":
        return {**result, "process_activity": activity.begin(worker_started=worker_started)}
    if mode == "off":
        return {**result, "process_activity": {"started": False, "mode": "off", "diagnostic_only": True}}
    return result


class DiagnosticTicker:
    def __init__(self, inner, waits, gc_overflow=lambda: False):
        self.inner, self.waits = inner, waits
        self.gc_overflow = gc_overflow
        self.backend, self.parameters = inner.backend, inner.parameters

    @property
    def expirations(self):
        return self.inner.expirations

    def wait(self):
        if self.gc_overflow():
            raise RuntimeError('GC diagnostic bound exceeded; retained prefix is insufficient')
        if len(self.waits) >= LIMIT:
            raise RuntimeError('diagnostic wait bound exceeded; no observations dropped')
        wall = time.perf_counter_ns()
        cpu = time.thread_time_ns()
        error = None
        try:
            self.inner.wait()
        except BaseException as caught:
            error = type(caught).__name__
            raise
        finally:
            self.waits.append({'start_ns': wall, 'end_ns': time.perf_counter_ns(),
                'thread_cpu_ns': time.thread_time_ns()-cpu, 'actual_expirations': self.inner.expirations,
                'error_type': error})

    def close(self):
        self.inner.close()


def worker(args):
    module = sampler_module()
    protocol = json.loads(Path(__file__).resolve().parents[1].joinpath('tests/fixtures/resource-protocol.json').read_text())
    waits, events = [], []
    original_ticker, original_source = module.SamplerTicker, module.source_identity
    original_policy = module.observer_thread_policy
    original_activity_factory = getattr(module, "observer_process_activity", None)
    activity_mode = getattr(args, 'activity_mode', None)
    timer_backend = getattr(args, 'timer_backend', None)
    if activity_mode is not None and original_activity_factory is not None:
        # Explicit diagnostic variants own this setting themselves; never let
        # the canonical default turn an off control into an on measurement.
        module.observer_process_activity = lambda worker_started=False: None
    activity_bytes = Path(__file__).with_name('macos-observer-activity.py').read_bytes() if activity_mode else b''
    activity = None
    if activity_mode == 'on':
        spec = importlib.util.spec_from_file_location('observer_activity', Path(__file__).with_name('macos-observer-activity.py'))
        native_activity = importlib.util.module_from_spec(spec); spec.loader.exec_module(native_activity)
        activity = native_activity.ObserverActivity()
    module.observer_thread_policy = lambda worker_started=False: activity_policy(original_policy, activity_mode, activity, worker_started=worker_started)
    runner_bytes, sampler_bytes = Path(__file__).read_bytes(), Path(module.__file__).read_bytes()
    overflow = False

    def on_gc(phase, info):
        nonlocal overflow
        if len(events) >= LIMIT:
            overflow = True
            return
        events.append({'phase': phase, 'generation': info['generation'],
                       'at_ns': time.perf_counter_ns(), 'thread_cpu_ns': time.thread_time_ns()})

    def ticker(*a, **k):
        if overflow:
            raise RuntimeError('GC diagnostic bound exceeded; retained prefix is insufficient')
        if timer_backend is not None:
            k['darwin_backend'] = timer_backend
        return DiagnosticTicker(original_ticker(*a, **k), waits, lambda: overflow)

    module.SamplerTicker = ticker
    module.source_identity = lambda *a, **k: source_binding(original_source(*a, **k), runner_bytes, sampler_bytes, activity_mode=activity_mode, activity_bytes=activity_bytes, timer_backend=timer_backend)
    original_argv = sys.argv
    gc.callbacks.append(on_gc)
    started = time.monotonic()
    code = None
    error_type = None
    try:
        sys.argv = [module.__file__, '--stage', 'pilot', '--cargo', str(args.cargo),
            '--toolchain', args.toolchain, '--scenario', args.worker,
            '--repeats', str(protocol['scenarios'][args.worker]['repeats']),
            '--interval-ms', str(protocol['interval_ms']), '--evidence-dir', str(args.evidence_dir)]
        code = module.main()
        if overflow:
            raise RuntimeError('GC diagnostic bound exceeded; retained prefix is insufficient')
        return code
    except BaseException as error:
        error_type = type(error).__name__
        raise
    finally:
        gc.callbacks.remove(on_gc)
        sys.argv = original_argv
        module.SamplerTicker, module.source_identity = original_ticker, original_source
        module.observer_thread_policy = original_policy
        if original_activity_factory is not None:
            module.observer_process_activity = original_activity_factory
        cleanup_error = None
        if activity is not None:
            try:
                activity.close()
            except BaseException as error:
                cleanup_error = error
        args.evidence_dir.mkdir(parents=True, exist_ok=True)
        report = {'role': 'diagnosis only; not frozen preparation or formal evidence',
                  'formal_sample': False, 'native_pilot_exit_code': code, 'gc_overflow': overflow,
                  'diagnostic_error_type': error_type,
                  'activity_mode': activity_mode,
                  'timer_backend': timer_backend,
                  'process_activity': activity.report() if activity is not None else None,
                  'activity_cleanup_error_type': type(cleanup_error).__name__ if cleanup_error is not None else None,
                  'elapsed_s': time.monotonic()-started,
                  'diagnostic_runner_sha256': hashlib.sha256(runner_bytes).hexdigest(),
                  'unmodified_sampler_file_sha256': hashlib.sha256(sampler_bytes).hexdigest(),
                  'waits': waits, 'gc_events': events}
        (args.evidence_dir/'wait-diagnostics.json').write_bytes((json.dumps(report, indent=2)+'\n').encode())
        if cleanup_error is not None:
            raise cleanup_error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cargo', type=Path, required=True)
    parser.add_argument('--toolchain', default='1.85.0')
    parser.add_argument('--evidence-dir', type=Path, required=True)
    parser.add_argument('--worker', choices=sorted(set(ORDER)))
    parser.add_argument('--activity-mode', choices=['off', 'on'])
    parser.add_argument('--activity-abba', action='store_true')
    parser.add_argument('--timer-backend', choices=['mach', 'critical-kqueue'],
                        help='explicit worker-only native timer variant; diagnosis only')
    parser.add_argument('--timer-abba', action='store_true',
                        help='four fresh many-small pilots comparing native timers with activity on')
    args = parser.parse_args()
    if sys.platform != 'darwin' or not args.evidence_dir.is_absolute() or args.evidence_dir.exists():
        raise ValueError('explicit fresh absolute macOS diagnostic directory required')
    if args.worker:
        if args.activity_abba or args.timer_abba:
            raise ValueError('ABBA selection belongs to the bounded parent only')
        return worker(args)
    if args.activity_mode is not None or args.timer_backend is not None:
        raise ValueError('single diagnostic variant requires an explicit worker')
    if args.activity_abba and args.timer_abba:
        raise ValueError('activity and timer comparisons must remain separate')
    selected_order = ['many-small']*4 if args.activity_abba or args.timer_abba else ORDER
    activity_modes = (['on']*4 if args.timer_abba else
                      ['off', 'on', 'on', 'off'] if args.activity_abba else [None]*4)
    timer_backends = ['critical-kqueue', 'mach', 'mach', 'critical-kqueue'] if args.timer_abba else [None]*4
    args.evidence_dir.mkdir(mode=0o700)
    started = time.monotonic()
    result = {'formal_sample': False, 'role': 'bounded native observer diagnosis only',
              'original_budget_s': 600, 'original_order': ORDER, 'selected_order': selected_order,
              'activity_modes': activity_modes, 'timer_backends': timer_backends, 'cases': []}
    try:
        for index, scenario in enumerate(selected_order):
            if time.monotonic()-started+150 > 600:
                result['status'] = 'INSUFFICIENT_DIAGNOSTIC_TIME'
                return 2
            destination = args.evidence_dir/f'case-{index}-{scenario}'
            command = [sys.executable, '-B', str(Path(__file__).resolve()), '--cargo', str(args.cargo),
                       '--toolchain', args.toolchain, '--evidence-dir', str(destination), '--worker', scenario]
            if activity_modes[index] is not None:
                command += ['--activity-mode', activity_modes[index]]
            if timer_backends[index] is not None:
                command += ['--timer-backend', timer_backends[index]]
            with (args.evidence_dir/f'case-{index}.console.log').open('wb') as output:
                code = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, check=False).returncode
            result['cases'].append({'scenario': scenario, 'activity_mode': activity_modes[index],
                'timer_backend': timer_backends[index], 'exit_code': code, 'directory': destination.name})
            if code not in {0, 2}:
                result['status'] = 'ERROR'
                return code
        result['status'] = 'DIAGNOSIS_COMPLETE_ONLY'
        return 0
    finally:
        result['elapsed_s'] = time.monotonic()-started
        (args.evidence_dir/'diagnosis-result.json').write_bytes((json.dumps(result, indent=2)+'\n').encode())
        print(json.dumps(result))


if __name__ == '__main__':
    sys.exit(main())
