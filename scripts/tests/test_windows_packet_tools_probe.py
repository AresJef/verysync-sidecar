"""Read-only discovery never starts capture or establishes native class acceptance."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('packet_tools_probe', ROOT / 'scripts/probe-windows-packet-tools.py')
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class PacketToolDiscovery(unittest.TestCase):
    def test_every_discovery_command_is_help_or_status_not_a_mutation(self):
        self.assertEqual(len(PROBE.COMMANDS), 5)
        self.assertTrue(all(args[0] in {'help', 'status'} for _, args in PROBE.COMMANDS))
        self.assertNotIn(['start'], [args for _, args in PROBE.COMMANDS])

    def test_non_actions_invocation_is_rejected_before_a_system_command(self):
        with patch.object(PROBE.sys, 'argv', ['probe', '--github-actions-metadata-only']), \
                patch.dict(PROBE.os.environ, {'GITHUB_ACTIONS': 'false'}), \
                patch.object(PROBE.subprocess, 'run') as command:
            with self.assertRaises(RuntimeError):
                PROBE.main()
            command.assert_not_called()

    def test_diagnostic_report_is_bounded_and_never_native_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'System32').mkdir()
            (root / 'System32/pktmon.exe').write_bytes(b'unit fixture, never executed')
            result = SimpleNamespace(returncode=0, stdout='help text' * 2000)
            output = io.StringIO()
            with patch.object(PROBE.sys, 'argv', ['probe', '--github-actions-metadata-only']), \
                    patch.object(PROBE.sys, 'platform', 'win32'), \
                    patch.dict(PROBE.os.environ, {'GITHUB_ACTIONS': 'true', 'SystemRoot': temporary}), \
                    patch.object(PROBE.ctypes, 'windll', SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda: 1)), create=True), \
                    patch.object(PROBE.subprocess, 'run', return_value=result) as command, \
                    contextlib.redirect_stdout(output):
                self.assertEqual(PROBE.main(), 0)
            report = json.loads(output.getvalue().split(': ', 1)[1])
            self.assertTrue(report['read_only_diagnostic'])
            self.assertFalse(report['native_packet_class_accepted'])
            self.assertFalse(report['capture_or_filter_mutation_started'])
            self.assertFalse(report['VerySync_started'])
            self.assertEqual(command.call_count, 5)
            self.assertTrue(all(len(x['output']) == 12000 and x['output_truncated'] for x in report['observations']))
            self.assertTrue(all(call.args[0][1] in {'help', 'status'} and call.kwargs['timeout'] == 10 for call in command.call_args_list))


if __name__ == '__main__':
    unittest.main()
