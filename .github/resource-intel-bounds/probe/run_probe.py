import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import struct
import subprocess
import time


MIB = 1024 * 1024
TOLERANCE = 4 * MIB
PEAK_KEYS = ("basic_peak_bytes", "vm_peak_bytes")


def now_ns():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)


def require(ok, explanation):
    if not ok:
        raise RuntimeError(explanation)


def command_output(*args):
    proc = subprocess.run(args, capture_output=True, text=True, check=False)
    return proc.stdout.strip() if proc.returncode == 0 else None


class Worker:
    def __init__(self, program, logfile, case):
        self.program = program
        self.logfile = logfile
        self.case = case
        self.messages = bytearray()
        self.transcript = case["worker_transcript"] = []

    def __enter__(self):
        self.log = self.logfile.open("wb")
        try:
            self.child = subprocess.Popen(
                [str(self.program)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=self.log, bufsize=0,
            )
        except BaseException:
            self.log.close()
            raise
        return self

    def send(self, command):
        self.transcript.append({"sent": command, "parent_time_ns": now_ns()})
        self.child.stdin.write((command + "\n").encode("ascii"))

    def read(self, event, *, deadline_ns=None):
        deadline = now_ns() + 6_000_000_000 if deadline_ns is None else deadline_ns
        while b"\n" not in self.messages:
            remaining = (deadline - now_ns()) / 1e9
            if remaining <= 0 or not select.select([self.child.stdout], [], [], remaining)[0]:
                raise RuntimeError(f"worker response {event} timed out")
            incoming = os.read(self.child.stdout.fileno(), 4096)
            if not incoming:
                raise RuntimeError(f"worker stdout ended while waiting for {event}")
            self.messages.extend(incoming)
        row, _, remainder = self.messages.partition(b"\n")
        self.messages = remainder
        received = json.loads(row)
        self.transcript.append({"received": received, "parent_time_ns": now_ns()})
        require(received["event"] == event, f"unexpected worker event {received}")
        return received

    def request(self, command, event):
        self.send(command)
        return self.read(event)

    def __exit__(self, exc_type, exc, traceback):
        forced = False
        try:
            if self.child.poll() is None:
                try:
                    self.send("stop")
                except BrokenPipeError:
                    pass
            try:
                status = self.child.wait(timeout=7)
            except subprocess.TimeoutExpired:
                forced = True
                self.child.kill()
                status = self.child.wait()
            self.case["exit"] = {"code": status, "forced": forced}
        finally:
            self.child.stdin.close()
            self.child.stdout.close()
            self.log.close()
        if exc_type is None:
            require(status == 0 and not forced, "worker did not stop normally")


class ExternalRss:
    def __init__(self, hello):
        self.pid = hello["pid"]
        self.flavor = hello["proc_task_flavor"]
        self.size = hello["proc_task_size"]
        self.offset = hello["proc_rss_offset"]
        require(0 <= self.offset <= self.size - 8 and self.size <= 4096, "bad proc_taskinfo layout")
        self.buffer = ctypes.create_string_buffer(self.size)
        self.libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self.read_info = self.libproc.proc_pidinfo
        self.read_info.argtypes = (
            ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int,
        )
        self.read_info.restype = ctypes.c_int

    def sample(self):
        start = now_ns()
        count = self.read_info(self.pid, self.flavor, 0, self.buffer, self.size)
        end = now_ns()
        require(count == self.size, f"proc_pidinfo size {count}, errno {ctypes.get_errno()}")
        (rss,) = struct.unpack_from("=Q", self.buffer, self.offset)
        require(rss > 0, "proc_pidinfo returned zero RSS")
        return {"read_begin_ns": start, "read_end_ns": end, "rss_bytes": rss}

    def series(self, quantity):
        values = [self.sample()]
        for _ in range(quantity - 1):
            time.sleep(0.020)
            values.append(self.sample())
        return values


def snapshot(worker):
    row = worker.request("snapshot", "snapshot")
    require(
        row["basic_status"] == 0 and row["vm_status"] == 0 and
        row["begin_ns"] <= row["end_ns"] and
        row["basic_peak_bytes"] >= row["basic_rss_bytes"] > 0 and
        row["vm_peak_bytes"] >= row["vm_rss_bytes"] > 0,
        f"task_info returned unexpected status or bytes {row}",
    )
    return row


def wait_until(deadline_ns):
    while (remaining := deadline_ns - now_ns()) > 0:
        time.sleep(remaining / 1e9)


def gap_case(worker, reader, case, mib, maximum_pause_ns=1_300_000_000):
    case["baseline"] = snapshot(worker)
    pre = case["ordinary_before"] = reader.series(7)
    pause_begin = pre[-1]["read_end_ns"]
    worker.send(f"pulse {mib}")
    # No ordinary RSS reads are allowed until the child confirms unmapping.
    pulse = case["pulse"] = worker.read("pulse", deadline_ns=pause_begin + maximum_pause_ns)
    wait_until(pause_begin + 1_000_000_000)
    first_after = reader.sample()
    case["ordinary_after"] = [first_after] + reader.series(6)
    case["after"] = snapshot(worker)
    pause_end = first_after["read_begin_ns"]
    case["pause_ns"] = pause_end - pause_begin
    case["pulse_entirely_in_pause"] = (
        pause_begin < pulse["mapping_begin_ns"] <= pulse["touch_done_ns"] <=
        pulse["mincore_done_ns"] <= pulse["unmap_begin_ns"] <= pulse["unmapped_ns"] < pause_end
    )
    case["ordinary_baseline_max_bytes"] = max(x["rss_bytes"] for x in pre)
    case["ordinary_total_max_bytes"] = max(
        x["rss_bytes"] for x in pre + case["ordinary_after"]
    )
    require(950_000_000 <= case["pause_ns"] <= maximum_pause_ns, "actual pause exceeded the calibration window")
    require(case["pulse_entirely_in_pause"], "pulse did not fit inside the read gap")
    require(pulse["requested_bytes"] == pulse["mapped_resident_bytes"] == mib * MIB, "pulse not resident")
    increase = case["lifetime_peak_increase_bytes"] = {
        key: case["after"][key] - case["baseline"][key] for key in PEAK_KEYS
    }
    observed_increase = case["ordinary_total_max_bytes"] - case["ordinary_baseline_max_bytes"]
    case["ordinary_increase_bytes"] = observed_increase
    if mib:
        expected = case["ordinary_baseline_max_bytes"] + mib * MIB
        case["peak_agrees_with_touched_size"] = {
            key: abs(case["after"][key] - expected) <= TOLERANCE for key in PEAK_KEYS
        }
        case["ordinary_samples_missed_pulse"] = observed_increase <= TOLERANCE
    else:
        case["control_remained_near_baseline"] = (
            observed_increase <= TOLERANCE and all(0 <= value <= TOLERANCE for value in increase.values())
        )


def phase_case(worker, reader, case, sizes):
    case["stages"] = []
    for name, mib in zip(("startup", "transfer"), sizes):
        stage = {"name": name, "baseline": snapshot(worker), "external_baseline": reader.sample()}
        case["stages"].append(stage)
        hold = stage["hold"] = worker.request(f"hold {mib}", "hold")
        stage["held_rss_samples"] = reader.series(3)
        # This read is inside the marked plateau for the phase countercheck only.
        stage["while_held"] = snapshot(worker)
        stage["release"] = worker.request("release", "release")
        stage["after_release"] = snapshot(worker)
        stage["ordinary_peak_bytes"] = max(x["rss_bytes"] for x in stage["held_rss_samples"])
        stage["ordinary_increase_bytes"] = (
            stage["ordinary_peak_bytes"] - stage["external_baseline"]["rss_bytes"]
        )
        require(hold["requested_bytes"] == hold["mapped_resident_bytes"] == mib * MIB, "phase not resident")
        require(
            all(hold["mincore_done_ns"] <= x["read_begin_ns"] <= x["read_end_ns"] <=
                stage["release"]["unmap_begin_ns"] for x in stage["held_rss_samples"]),
            "phase samples outside the touched plateau",
        )
        require(
            abs(stage["ordinary_increase_bytes"] - mib * MIB) <= TOLERANCE,
            "ordinary phase observations disagree with the touched mapping",
        )
    startup, transfer = case["stages"]
    case["after_release_peak_delta_second_minus_first_bytes"] = {
        key: transfer["after_release"][key] - startup["after_release"][key] for key in PEAK_KEYS
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("worker", type=Path)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--require-intel", action="store_true")
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    machine = {
        "architecture": platform.machine(),
        "cpu_vendor": command_output("/usr/sbin/sysctl", "-n", "machdep.cpu.vendor"),
        "cpu_brand": command_output("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"),
        "translated": command_output("/usr/sbin/sysctl", "-n", "sysctl.proc_translated"),
        "macos": command_output("/usr/bin/sw_vers", "-productVersion"),
        "macos_build": command_output("/usr/bin/sw_vers", "-buildVersion"),
        "worker_executable_archs": command_output("/usr/bin/lipo", "-archs", str(args.worker)),
        "worker_sha256": hashlib.sha256(args.worker.read_bytes()).hexdigest(),
        "runner": {name: os.environ.get(name) for name in (
            "RUNNER_ARCH", "RUNNER_ENVIRONMENT", "ImageOS", "ImageVersion",
            "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
        )},
    }
    report = {"machine": machine, "cases": [], "measurement_kind": "synthetic-method-probe"}
    cases = (
        ("gap_pulse", gap_case, 96), ("gap_control", gap_case, 0),
        ("startup_high", phase_case, (96, 32)), ("transfer_high", phase_case, (32, 96)),
    )
    try:
        if args.require_intel:
            require(
                machine["architecture"] == machine["worker_executable_archs"] == "x86_64" and
                machine["cpu_vendor"] == "GenuineIntel" and machine["translated"] in (None, "0") and
                machine["runner"]["RUNNER_ARCH"] == "X64",
                f"runner did not establish native Intel identity {machine}",
            )
        for name, function, setting in cases:
            case = {"name": name}
            report["cases"].append(case)
            with Worker(args.worker.resolve(), args.evidence / (name + ".stderr.log"), case) as worker:
                hello = case["worker"] = worker.read("hello")
                require(
                    hello["pid"] == worker.child.pid and hello["architecture"] == machine["architecture"],
                    f"unexpected worker identity {hello}",
                )
                function(worker, ExternalRss(hello), case, setting)
        require(len({case["worker"]["pid"] for case in report["cases"]}) == len(cases), "reused case PID")
    except Exception as error:
        report["error"] = repr(error)
        raise
    finally:
        (args.evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print("INTEL_RSS_METHOD_RAW " + json.dumps(report, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
