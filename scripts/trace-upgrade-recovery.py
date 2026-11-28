"""Cargo test runner for recording independent native process creation events."""
import argparse
from decimal import Decimal
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

PHASES = ("before-control", "begin", "end", "after-control")
CASES = ("cli-partial", "upload-drop")
BUSINESS_CASE = "s30-install-drop"


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


class DarwinForkObserver:
    def __init__(self, pid):
        import select
        self.select = select
        self.queue = select.kqueue()
        self.control = select.KQ_NOTE_FORK | select.KQ_NOTE_EXEC
        self.queue.control([select.kevent(
            pid, select.KQ_FILTER_PROC, select.KQ_EV_ADD | select.KQ_EV_CLEAR, self.control,
        )], 0, 0)

    def snapshot(self):
        flags = 0
        for event in self.queue.control(None, 8, 0):
            if event.flags & self.select.KQ_EV_ERROR:
                raise OSError("the owned process kevent returned an error")
            flags |= event.fflags
        return {
            "fork": bool(flags & self.select.KQ_NOTE_FORK),
            "root_exec": bool(flags & self.select.KQ_NOTE_EXEC),
        }

    def close(self):
        self.queue.close()


class WindowsJobObserver:
    def __init__(self, pid):
        import ctypes
        from ctypes import wintypes

        class Accounting(ctypes.Structure):
            _fields_ = [
                (name, ctypes.c_int64) for name in ("user", "kernel", "period_user", "period_kernel")
            ] + [(name, wintypes.DWORD) for name in ("faults", "total", "active", "terminated")]

        self.ctypes = ctypes
        self.accounting = Accounting
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel = kernel
        for name, output, inputs in [
            ("CreateJobObjectW", wintypes.HANDLE, [ctypes.c_void_p, wintypes.LPCWSTR]),
            ("OpenProcess", wintypes.HANDLE, [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]),
            ("AssignProcessToJobObject", wintypes.BOOL, [wintypes.HANDLE, wintypes.HANDLE]),
            ("QueryInformationJobObject", wintypes.BOOL, [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]),
            ("CloseHandle", wintypes.BOOL, [wintypes.HANDLE]),
        ]:
            method = getattr(kernel, name)
            method.restype = output
            method.argtypes = inputs
        self.job = kernel.CreateJobObjectW(None, None)
        if not self.job:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            # The Job API requires SET_QUOTA and TERMINATE rights for admission.
            # The observer owns only this disposable test process and queries
            # counts after admission. The Job has no limits or kill-on-close.
            child = kernel.OpenProcess(0x0101, False, pid)
            if not child:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                if not kernel.AssignProcessToJobObject(self.job, child):
                    raise ctypes.WinError(ctypes.get_last_error())
            finally:
                kernel.CloseHandle(child)
        except BaseException:
            self.close()
            raise

    def snapshot(self):
        record = self.accounting()
        if not self.kernel.QueryInformationJobObject(
            self.job, 1, self.ctypes.byref(record), self.ctypes.sizeof(record), None,
        ):
            raise self.ctypes.WinError(self.ctypes.get_last_error())
        return {"total": record.total, "active": record.active}

    def close(self):
        self.kernel.CloseHandle(self.job)


def record_bracketed(command, root, cases=CASES):
    observer_class = {"darwin": DarwinForkObserver, "win32": WindowsJobObserver}[sys.platform]
    env = dict(os.environ, VERYSYNC_S29_PHASE_DIR=str(root))
    process = subprocess.Popen(command, env=env)
    frames = []
    failure = None
    observer = None
    try:
        observer = observer_class(process.pid)
        (root / "attached").touch()
        expected = {(name, phase) for name in cases for phase in PHASES}
        while process.poll() is None and expected:
            for name, phase in sorted(expected):
                stem = root / f"{name}-{phase}"
                if stem.with_suffix(".request").is_file():
                    frame = {"case": name, "phase": phase, "pid": process.pid,
                             "observed": observer.snapshot(), "unix_ns": time.time_ns()}
                    frames.append(frame)
                    stem.with_suffix(".response").touch()
                    expected.remove((name, phase))
            time.sleep(0.01)
    except OSError as error:
        failure = f"kernel process observation failed: {error}"
        (root / "unavailable").touch()
    finally:
        if observer:
            observer.close()
    return process.wait(), frames, failure


def start(command):
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("the native process observers require an isolated GitHub runner")
    root = Path(os.environ["VERYSYNC_S29_TRACE_DIR"])
    root.mkdir(mode=0o700)
    business = os.environ.get("VERYSYNC_S30_TRACE") == "1"
    if sys.platform == "linux":
        method = "strace"
        status, events, diagnostic = record_linux(command, root)
        brackets = []
    else:
        method = {"darwin": "darwin_kqueue", "win32": "windows_job_total"}[sys.platform]
        status, brackets, diagnostic = record_bracketed(
            command, root, (BUSINESS_CASE,) if business else CASES
        )
        events = []
    (root / "intermediate.json").write_text(json.dumps({
        "test_exit": status,
        "observer": method,
        "diagnostic": diagnostic,
        "events": events,
        "brackets": brackets,
        "business": business,
    }), encoding="utf-8")
    return status


def read_test_rows(path, business=False):
    rows = []
    marker = "s30-upgrade " if business else "s29-upgrade "
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if marker + "{" in line:
            rows.append(json.loads(line.split(marker, 1)[1]))
    return rows


def scoped_events(rows, events):
    lineage = {row["pid"] for row in rows}
    owned = []
    for item in sorted(events, key=lambda event: event["time"]):
        if item["pid"] in lineage or item["parent"] in lineage or item["parent"] is None:
            lineage.add(item["pid"])
            owned.append(item)
    return owned


def check_case(name, rows, events, method="strace", brackets=()):
    case = [row for row in rows if row["case"] == name]
    stages = {row["stage"]: row for row in case if row["stage"] in {
        "calibration-child", "begin-recovery", "end-recovery", "calibration-after", "original-receipt", "before-dispatch",
    }}
    if len(stages) != 6 or len({row["pid"] for row in case}) != 1 or any(
        sum(row["stage"] == stage for row in case) != 1 for stage in stages
    ):
        raise ValueError(f"{name}: missing same-attempt calibration or recovery boundaries")
    original, before, begin, end, after = (stages[key] for key in [
        "original-receipt", "calibration-child", "begin-recovery", "end-recovery", "calibration-after"
    ])
    receipt = original["detail"]["receipt"]
    op = receipt["operation_id"]
    if begin["detail"]["operation_id"] != op or end["detail"]["operation_id"] != op:
        raise ValueError(f"{name}: recovery used a receipt from a different attempt")
    if receipt["outcome"] != "unknown" or end["detail"]["original_outcome"] != "Unknown":
        raise ValueError(f"{name}: original unknown outcome was not preserved")
    expected = {"cli-partial": ("Previous", "old_sha256", "previous_program_sha256"),
                "upload-drop": ("Target", "target_sha256", "target_program_sha256")}
    desired, true_key, receipt_key = expected[name]
    final = end["detail"]
    digest = stages["before-dispatch"]["detail"][true_key]
    if final["comparison"] != desired or final["sdk_sha256"] != digest or final["true_sha256"] != digest or bytes(receipt[receipt_key]).hex() != digest:
        raise ValueError(f"{name}: outcome or program digest differs from the original case")
    if begin["detail"]["requests_seen"] != 1 or end["detail"]["requests_seen"] != 1:
        raise ValueError(f"{name}: recovery sent at least one new request")
    if not before["unix_ns"] <= begin["unix_ns"] < end["unix_ns"] <= after["unix_ns"]:
        raise ValueError(f"{name}: invalid recovery clock")
    if method == "strace":
        for control, minimum, maximum in [
            (before, original["unix_ns"], begin["unix_ns"]),
            (after, end["unix_ns"], after["unix_ns"]),
        ]:
            child = control["detail"]["pid"]
            if not any(
                item["pid"] == child and minimum <= item["time"] <= maximum for item in events
            ):
                raise ValueError(f"{name}: observer did not capture the short-lived calibration child {child}")
        during = [item for item in events if
                  begin["unix_ns"] - 1_000 <= item["time"] <= end["unix_ns"] + 1_000]
        if during:
            raise ValueError(f"{name}: recovery started a program or child process: {during}")
    else:
        verify_bracket(name, method, brackets, begin, end)
    return {
        "case": name,
        "operation_id": op,
        "begin_unix_ns": begin["unix_ns"],
        "end_unix_ns": end["unix_ns"],
        "additional_upgrade_requests": 0,
        "additional_started_processes": 0,
        "kernel_brackets": [row for row in brackets if row["case"] == name],
        "calibration_pids": [before["detail"]["pid"], after["detail"]["pid"]],
        "calibration_events": [item for item in events if item["pid"] in {
            before["detail"]["pid"], after["detail"]["pid"]
        }],
    }


def verify_bracket(name, method, brackets, begin, end, *, original_program_running=False):
    frames = sorted((row for row in brackets if row["case"] == name), key=lambda row: row["unix_ns"])
    if [row["phase"] for row in frames] != list(PHASES) or any(row["pid"] != begin["pid"] for row in frames):
        raise ValueError(f"{name}: missing independent kernel counter frames for the caller")
    if not frames[1]["unix_ns"] <= begin["unix_ns"] < end["unix_ns"] <= frames[2]["unix_ns"]:
        raise ValueError(f"{name}: independent kernel counters did not bracket the full operation")
    a, b, c, d = [row["observed"] for row in frames]
    if method == "darwin_kqueue":
        good = b["fork"] and not c["fork"] and d["fork"] and not any(
            row["root_exec"] for row in [b, c, d]
        )
    elif method == "windows_job_total":
        active_coverage = (
            1 <= c["active"] <= b["active"] == a["active"] and c["active"] == d["active"]
            if original_program_running else all(row["active"] == 1 for row in [a, b, c, d])
        )
        good = active_coverage and (
            b["total"] - a["total"], c["total"] - b["total"], d["total"] - c["total"]
        ) == (1, 0, 1)
    else:
        raise ValueError(f"unknown independent observer method: {method}")
    if not good:
        raise ValueError(f"{name}: kernel accounting did not prove short-child controls and zero creation: {frames}")


def verify_business_case(rows, events, method, brackets):
    name = BUSINESS_CASE
    case = [row for row in rows if row["case"] == name]
    required = ("calibration-child", "begin-business-operation", "native-response-withheld",
                "end-business-operation", "calibration-after", "verified-within-original-call")
    stages = {row["stage"]: row for row in case if row["stage"] in required}
    if set(stages) != set(required) or len({row["pid"] for row in case}) != 1 or any(
        sum(row["stage"] == stage for row in case) != 1 for stage in required
    ):
        raise ValueError(f"{name}: missing unique calibrated business-operation evidence")
    before, begin, upstream, end, after, final = (stages[key] for key in required)
    if not before["unix_ns"] <= begin["unix_ns"] < upstream["unix_ns"] < end["unix_ns"] <= after["unix_ns"]:
        raise ValueError(f"{name}: upload response and observer windows do not agree")
    observed = final["detail"]
    if (end["detail"]["operation_id"] != observed["operation_id"]
            or not observed["payload_preserved"] or not observed["original_reply_unknown"]
            or observed["observed_disk_sha256"] != observed["target_sha256"]
            or observed["previous_sha256"] == observed["target_sha256"]
            or observed["routes"] != [["GET", "/rest/system/version"],
                                      ["GET", "/rest/system/version"],
                                      ["GET", "/rest/system/status"],
                                      ["POST", "/rest/system/upgrade/upload"]]
            or upstream["detail"]["upstream_status"] != 200
            or upstream["detail"]["downstream_bytes"] != 0):
        raise ValueError(f"{name}: installation/response/verification evidence is inconsistent")
    if method == "strace":
        for control, lower, upper in (
            (before, before["unix_ns"] - 5_000_000_000, begin["unix_ns"]),
            (after, end["unix_ns"], after["unix_ns"]),
        ):
            if not any(item["pid"] == control["detail"]["pid"]
                       and lower <= item["time"] <= upper for item in events):
                raise ValueError(f"{name}: short-lived process calibration was missed")
        direct_creations = [
            item for item in events if begin["unix_ns"] <= item["time"] <= end["unix_ns"]
            and (item["parent"] == begin["pid"] or item["pid"] == begin["pid"])
        ]
        if direct_creations:
            raise ValueError(f"{name}: the SDK caller created a process or executed another image in the observed window")
    else:
        verify_bracket(name, method, brackets, begin, end, original_program_running=True)
    return {
        "case": name, "operation_id": end["detail"]["operation_id"],
        "begin_unix_ns": begin["unix_ns"], "end_unix_ns": end["unix_ns"],
        "upload_submissions": 1, "sdk_process_creations": 0,
        "scope": "observed caller activity; native response and exit are separate evidence",
        "calibration_pids": [before["detail"]["pid"], after["detail"]["pid"]],
        "kernel_brackets": [row for row in brackets if row["case"] == name],
    }


def verify(args):
    if not args.trace.is_file():
        raise ValueError("native runner did not produce a process witness")
    evidence = json.loads(args.trace.read_text(encoding="utf-8"))
    reason = evidence["diagnostic"]
    business = evidence.get("business", False)
    rows = read_test_rows(args.log, business)
    events = scoped_events(rows, evidence["events"])
    if args.scoped_trace:
        args.scoped_trace.write_text(json.dumps({
            **evidence, "events": events,
        }, indent=2) + "\n", encoding="utf-8")
    if reason or evidence["test_exit"] != 0:
        report = {"coverage": "blocked", "observer": evidence["observer"],
                  "reason": reason or "native product operation did not pass",
                  "test_exit": evidence["test_exit"]}
    else:
        try:
            cases = [verify_business_case(rows, events, evidence["observer"], evidence.get("brackets", []))] if business else [
                check_case(name, rows, events, evidence["observer"], evidence.get("brackets", []))
                for name in CASES
            ]
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
        parser.add_argument("--scoped-trace", type=Path)
        raise SystemExit(verify(parser.parse_args(sys.argv[2:])))
    raise SystemExit(start(sys.argv[1:]))
