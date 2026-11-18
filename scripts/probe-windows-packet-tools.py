#!/usr/bin/env python3
"""Read-only Windows CI packet-tool discovery; never native packet-class acceptance."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys

COMMANDS = [
    ('help', ['help']),
    ('status', ['status']),
    ('capture_help', ['help', 'start']),
    ('conversion_help', ['help', 'etl2pcap']),
    ('filter_help', ['help', 'filter']),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--github-actions-metadata-only', action='store_true', required=True)
    args = parser.parse_args()
    if not args.github_actions_metadata_only or sys.platform != 'win32' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('metadata probe is restricted to an explicit fresh Windows Actions VM')
    root = Path(os.environ['SystemRoot'])
    if not root.is_absolute():
        raise ValueError('absolute Windows system root required')
    tool = root / 'System32' / 'pktmon.exe'
    if not tool.is_file() or tool.is_symlink():
        raise RuntimeError('in-box packet monitor unavailable')
    observations = []
    for label, arguments in COMMANDS:
        result = subprocess.run([str(tool), *arguments], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=10, text=True, encoding='utf-8', errors='replace')
        observations.append({'command': label, 'exit_code': result.returncode,
                             'output': result.stdout[:12000], 'output_truncated': len(result.stdout) > 12000})
    print('Windows packet observer read-only metadata: ' + json.dumps({
        'read_only_diagnostic': True, 'native_packet_class_accepted': False,
        'capture_or_filter_mutation_started': False, 'VerySync_started': False,
        'administrator': bool(ctypes.windll.shell32.IsUserAnAdmin()),
        'system_tool_explicitly_selected': True, 'observations': observations,
    }, sort_keys=True), flush=True)
    return 0 if observations[0]['exit_code'] == 0 and observations[1]['exit_code'] == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
