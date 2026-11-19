"""Trace only the owned Linux receiver's file-copy calls during its Rust test."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


CASE = "native_copy_range_methods_reuse_old_blocks_and_preserve_bytes"
TRANSFER = "native copy range transfer effects: "
PAYLOAD = "copy-range-fixture.bin"
COPY = re.compile(r"^copy_file_range\(\d+<([^>]+)>.*?, \d+<([^>]+)>.*\)\s+= (-?\d+)")
THREAD = re.compile(r"^clone3?\(.*CLONE_THREAD.*\)\s+= (\d+)$")
RENAME = re.compile(r"^rename(?:at2?)?\(.*\)\s+= 0$")
STAGING_FILE = re.compile(r"[0-9a-fA-F]{32}\.tmp")


def owned_calls(trace, root_pid):
    """Yield traced calls originating from the exact owned PID and its threads."""
    pending = [root_pid]
    visited = set()
    while pending:
        tid = pending.pop()
        if tid in visited:
            continue
        visited.add(tid)
        for line in trace(tid):
            thread = THREAD.match(line)
            if thread:
                pending.append(int(thread[1]))
            yield tid, line


def copies(trace, root_pid, source, target):
    return [
        int(call[3])
        for _, line in owned_calls(trace, root_pid)
        if (call := COPY.match(line)) and Path(call[1]) == source and target(Path(call[2]))
    ]


def trace_lines(prefix):
    def lines(tid):
        trace = prefix.with_suffix(f".{tid}")
        return trace.read_text(encoding="utf-8").splitlines() if trace.is_file() else []
    return lines


def run_traced(strace, prefix, command, env):
    subprocess.run(
        [strace, "-ff", "-qq", "-yy", "-s", "0", "-e",
         "trace=clone,clone3,copy_file_range,rename,renameat,renameat2",
         "-o", str(prefix), *command], env=env, check=True,
    )


def preflight(strace, root, env):
    source = root / "oracle-source"
    dest = root / "oracle-destination"
    process_id = root / "oracle-pid"
    script = """
import os, pathlib, sys, threading
source, dest, process_id = map(pathlib.Path, sys.argv[1:])
data = b'independent range oracle' * 512
source.write_bytes(data)
process_id.write_text(str(os.getpid()))
print('copy oracle bytes:', len(data), flush=True)
def copy():
    with source.open('rb') as old, dest.open('wb') as new:
        assert os.copy_file_range(old.fileno(), new.fileno(), len(data)) == len(data)
worker = threading.Thread(target=copy)
worker.start()
worker.join()
assert dest.read_bytes() == data
"""
    prefix = root / "oracle"
    run_traced(strace, prefix, [sys.executable, "-c", script, str(source), str(dest), str(process_id)], env)
    observed = copies(trace_lines(prefix), int(process_id.read_text()), source, dest.__eq__)
    if observed != [source.stat().st_size]:
        raise RuntimeError("the unprivileged copy and decoded descriptor oracle did not agree")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    root = args.evidence_dir
    if not sys.platform.startswith("linux") or not root.is_absolute():
        parser.error("an absolute private Linux evidence directory is required")
    strace = shutil.which("strace")
    if not strace:
        parser.error("the hosted runner needs its explicit strace tool")
    root.mkdir(mode=0o700)
    scratch = (root / "scratch").resolve()
    scratch.mkdir(mode=0o700)
    env = dict(os.environ, TMPDIR=str(scratch), CARGO_NET_OFFLINE="true")
    preflight(strace, scratch, env)
    print("native copy range tracing preflight: owned same-filesystem copy and path decoder passed", flush=True)
    run_traced(strace, root / "receiver", [
        sys.executable, str(Path(__file__).with_name("run-isolated-engine-tests.py")),
        "--toolchain", args.toolchain, "--test-target", "configuration_engine",
        "--test-filter", CASE, "--evidence-dir", str(root / "engine"),
    ], env)
    log = (root / "engine" / "configuration-engine.log").read_text(encoding="utf-8")
    markers = [line.split(TRANSFER, 1)[1] for line in log.splitlines() if TRANSFER in line]
    if len(markers) != 1:
        raise RuntimeError("one Rust transfer receipt is required")
    data = json.loads(markers[0])
    fixture = Path(data["fixture_root"])
    if data["receiver_pid"] <= 1 or fixture.parent != scratch:
        raise RuntimeError("the Rust fixture identity must belong to the explicit trace root")
    trace = trace_lines(root / "receiver")
    receiver_calls = list(owned_calls(trace, data["receiver_pid"]))
    owned_threads = {tid for tid, _ in receiver_calls}
    traces = {}
    all_fixture_range_calls = 0
    for file in root.glob("receiver.*"):
        if file.suffix[1:].isdigit():
            owned = int(file.suffix[1:]) in owned_threads
            for line in file.read_text(encoding="utf-8").splitlines():
                if str(fixture) not in line:
                    continue
                operation = line.split("(", 1)[0]
                if operation not in ("copy_file_range", "rename", "renameat", "renameat2"):
                    continue
                if operation == "copy_file_range":
                    all_fixture_range_calls += 1
                relative = line.replace(str(fixture), "<fixture>")
                arm = next((arm for arm in ("standard", "copy-file-range") if f"/receiver-{arm}/" in line),
                           "other owned fixture path")
                key = (operation, arm, owned)
                entry = traces.setdefault(key, {"operation": operation, "fixture_arm": arm,
                                               "receiver_thread": owned, "count": 0,
                                               "first_owned_fixture_path_example": relative[:600]})
                entry["count"] += 1
    rows = []
    for arm in ("standard", "copy-file-range"):
        folder = fixture / f"receiver-{arm}"
        installed = folder / PAYLOAD
        stages = []
        for _, line in receiver_calls:
            if RENAME.match(line):
                paths = re.findall(r'"([^"]+)"', line)
                if len(paths) == 2 and Path(paths[1]) == installed:
                    source = Path(paths[0])
                    if source.parent == folder / ".verysync" and STAGING_FILE.fullmatch(source.name):
                        stages.append(source)
        results = copies(trace, data["receiver_pid"], installed, set(stages).__contains__)
        rows.append({"strategy": arm, "attempts": len(results),
                     "copied_bytes": sum(value for value in results if value > 0),
                     "errors": sum(value < 0 for value in results), "receiver_installs": len(stages)})
    print("native copy range observation scope: " + json.dumps({
        "calls_attributed_to_receiver_and_threads": len(receiver_calls),
        "all_fixture_copy_file_range_calls": all_fixture_range_calls,
        "threaded_copy_oracle_passed": True,
    }), flush=True)
    print("native copy range syscall effects: " + json.dumps(rows), flush=True)
    print("native traced fixture path samples: " + json.dumps(list(traces.values())), flush=True)
    if any(row["receiver_installs"] < 2 for row in rows):
        raise RuntimeError("did not attribute both actual file installs to owned receiver threads")
    if rows[0]["attempts"] != 0 or rows[1]["copied_bytes"] < data["file_bytes"] // 2 or rows[1]["errors"]:
        raise RuntimeError("the exact old-file to new-temp syscalls did not distinguish the two strategies")


if __name__ == "__main__":
    main()
