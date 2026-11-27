"""Cargo test runner for recording independent native process creation events."""
import argparse
from decimal import Decimal
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

DTRACE = r"""
dtrace:::BEGIN { printf("ready\n"); }
proc:::create { printf("%lld %d %d create\n", walltimestamp, args[0]->pr_pid, pid); }
proc:::exec-success { printf("%lld %d %d exec\n", walltimestamp, pid, ppid); }
"""


def record_linux(command, root):
    strace = shutil.which("strace")
    if not strace:
        return subprocess.call(command), [], "strace missing"
    completed = subprocess.call([
        strace, "-ff", "-s", "0", "-ttt", "-o", str(root / "calls"),
        "-e", "trace=execve,execveat,clone,clone3,fork,vfork", "--", *command,
    ])
    events = []
    for path in sorted(root.glob("calls.*")):
        pid = int(path.suffix[1:])
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            fields = re.match(r"^(\d+\.\d+) (.+?)\s+=\s+(\d+)\s*$", line)
            if not fields:
                continue
            clock, call, returned = fields.groups()
            stamp = int(Decimal(clock) * 1_000_000_000)
            if call.startswith(("execve(", "execveat(")) and returned == "0":
                events.append({"time": stamp, "pid": pid, "parent": None, "event": "exec"})
            elif call.startswith(("clone(", "clone3(", "fork(", "vfork(")) and "CLONE_THREAD" not in call:
                events.append({"time": stamp, "pid": int(returned), "parent": pid, "event": "create"})
        path.unlink()
    return completed, events, None if events else "no strace process events"


def wait_for(predicate, process, timeout=8):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if predicate():
            return True
        if process.poll() is not None:
            return False
        time.sleep(0.05)
    return False


def record_macos(command, root):
    source = root / "observe.d"
    source.write_text(DTRACE, encoding="utf-8")
    console = root / "observer.stderr"
    rows = root / "observer.local"
    with console.open("wb") as errors:
        command_line = ["/usr/bin/sudo", "-n", "/usr/sbin/dtrace", "-q", "-x", "switchrate=10hz", "-s", str(source),
                        "-o", str(rows)]
        observer = subprocess.Popen(command_line, stdout=subprocess.DEVNULL, stderr=errors, start_new_session=True)
        ready = wait_for(lambda: rows.exists() and rows.stat().st_size >= 6, observer)
        try:
            status = subprocess.call(command)
        finally:
            if observer.poll() is None:
                os.killpg(observer.pid, signal.SIGINT)
            try:
                observer.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(observer.pid, signal.SIGTERM)
                observer.wait(timeout=8)
                ready = False
    events = []
    if rows.exists():
        for line in rows.read_text(encoding="utf-8").splitlines():
            match = re.fullmatch(r"(\d+) (\d+) (\d+) (create|exec)", line.strip())
            if match:
                stamp, child, parent, event = match.groups()
                events.append({"time": int(stamp), "pid": int(child), "parent": int(parent), "event": event})
        rows.unlink()
    diagnostics = console.read_text(encoding="utf-8", errors="replace").lower()
    error = None
    if not ready or not events or re.search(r"\bdrop(?:s|ped)?\b|error|cannot|failed", diagnostics):
        error = "DTrace not ready, failed or reported missed events"
    return status, events, error


def record_windows(command, root):
    powershell = shutil.which("powershell")
    if not powershell:
        return subprocess.call(command), [], "Windows process event subscriber missing"
    script = Path(__file__).with_suffix(".ps1")
    console = root / "observer.stderr"
    with console.open("wb") as errors:
        observer = subprocess.Popen(
            [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script), str(root)],
            stdout=errors, stderr=subprocess.STDOUT,
        )
        ready = wait_for((root / "ready").exists, observer, timeout=15)
        try:
            status = subprocess.call(command)
        finally:
            (root / "stop").touch()
            try:
                observer.wait(timeout=8)
            except subprocess.TimeoutExpired:
                observer.kill()
                observer.wait(timeout=5)
                ready = False
    raw = root / "observer.local.json"
    events = []
    error = "Windows process subscriber did not complete"
    if ready and raw.exists():
        result = json.loads(raw.read_text(encoding="utf-8"))
        raw.unlink()
        if not result["error"] and not result["omitted"] and result["closed"]:
            events = result["events"]
            error = None if events else "no Windows process start events"
    return status, events, error


def start(command):
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("the native process observers require an isolated GitHub runner")
    root = Path(os.environ["VERYSYNC_S29_TRACE_DIR"])
    root.mkdir(mode=0o700)
    method = {"linux": record_linux, "darwin": record_macos, "win32": record_windows}[sys.platform]
    status, events, diagnostic = method(command, root)
    # This intermediate contains only IDs, timestamps and event classes. The
    # verifier later retains only test lineage and removes the unfiltered file.
    (root / "intermediate.json").write_text(json.dumps({
        "test_exit": status,
        "observer": method.__name__,
        "diagnostic": diagnostic,
        "events": events,
    }), encoding="utf-8")
    return status


def read_test_rows(path):
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "s29-upgrade {" in line:
            rows.append(json.loads(line.split("s29-upgrade ", 1)[1]))
    return rows


def check_case(name, rows, events):
    case = [row for row in rows if row["case"] == name]
    stages = {row["stage"]: row for row in case if row["stage"] in {
        "calibration-child", "begin-recovery", "end-recovery", "calibration-after", "original-receipt",
    }}
    if len(stages) != 5 or len({row["pid"] for row in case}) != 1:
        raise ValueError(f"{name}: missing same-attempt calibration or recovery boundaries")
    original, before, begin, end, after = (stages[key] for key in [
        "original-receipt", "calibration-child", "begin-recovery", "end-recovery", "calibration-after"
    ])
    op = original["detail"]["receipt"]["operation_id"]
    if begin["detail"]["operation_id"] != op or end["detail"]["operation_id"] != op:
        raise ValueError(f"{name}: recovery used a receipt from a different attempt")
    if begin["detail"]["requests_seen"] != end["detail"]["requests_seen"]:
        raise ValueError(f"{name}: recovery sent at least one new request")
    if not before["unix_ns"] <= begin["unix_ns"] < end["unix_ns"] <= after["unix_ns"]:
        raise ValueError(f"{name}: invalid recovery clock")
    lineage = {begin["pid"]}
    for item in sorted(events, key=lambda event: event["time"]):
        if item["parent"] in lineage or item["parent"] is None:
            lineage.add(item["pid"])
    for control, minimum, maximum in [
        (before, original["unix_ns"], begin["unix_ns"]),
        (after, end["unix_ns"], after["unix_ns"]),
    ]:
        child = control["detail"]["pid"]
        if child not in lineage or not any(
            item["pid"] == child and minimum <= item["time"] <= maximum for item in events
        ):
            raise ValueError(f"{name}: observer did not capture the short-lived calibration child {child}")
    during = [item for item in events if item["pid"] in lineage and
              begin["unix_ns"] - 1_000 <= item["time"] <= end["unix_ns"] + 1_000]
    if during:
        raise ValueError(f"{name}: recovery started a program or child process: {during}")
    return {
        "case": name,
        "operation_id": op,
        "begin_unix_ns": begin["unix_ns"],
        "end_unix_ns": end["unix_ns"],
        "additional_upgrade_requests": 0,
        "additional_started_processes": 0,
        "calibration_pids": [before["detail"]["pid"], after["detail"]["pid"]],
        "calibration_events": [item for item in events if item["pid"] in {
            before["detail"]["pid"], after["detail"]["pid"]
        }],
    }


def verify(args):
    if not args.trace.is_file():
        raise ValueError("native runner did not produce a process witness")
    evidence = json.loads(args.trace.read_text(encoding="utf-8"))
    args.trace.unlink()
    reason = evidence["diagnostic"]
    if reason or evidence["test_exit"] != 0:
        report = {"coverage": "blocked", "observer": evidence["observer"],
                  "reason": reason or "native product operation did not pass",
                  "test_exit": evidence["test_exit"]}
    else:
        try:
            rows = read_test_rows(args.log)
            cases = [check_case(name, rows, evidence["events"]) for name in ["cli-partial", "upload-drop"]]
            report = {"coverage": "passed", "observer": evidence["observer"], "cases": cases}
        except ValueError as error:
            report = {"coverage": "blocked", "observer": evidence["observer"], "reason": str(error)}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))
    return 0 if report["coverage"] == "passed" else 1


if __name__ == "__main__":
    if sys.argv[1:2] == ["--verify"]:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--trace", type=Path, required=True)
        parser.add_argument("--log", type=Path, required=True)
        parser.add_argument("--output", type=Path, required=True)
        raise SystemExit(verify(parser.parse_args(sys.argv[2:])))
    raise SystemExit(start(sys.argv[1:]))
