"""Bounded Mac-only diagnostic; never a formal resource observation."""

import argparse
import ctypes as ct
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import selectors
import statistics
import subprocess
import sys
import tempfile
import time

import psutil


class Sample(ct.Structure):
    _fields_ = [(key, ct.c_uint64) for key in ("birth_us", "rss_bytes", "user_ns", "system_ns")]


CHILD = """
import sys
print('ready', flush=True)
for command in sys.stdin:
    assert command.strip() == 'grow'
    data = bytearray(32 * 1024 * 1024)
    for offset in range(0, len(data), 4096):
        data[offset] = offset % 251
    work = sum(i % 251 for i in range(3_000_000))
    assert work > 0 and len(data) == 32 * 1024 * 1024
    print('grown', flush=True)
"""


def await_line(child, expected):
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        if not selector.select(6) or child.stdout.readline().strip() != expected:
            raise RuntimeError("owned test workload did not acknowledge its phase")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sampler", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--expected-architecture", choices=("arm64", "x86_64"), required=True)
    args = parser.parse_args()
    if (sys.platform != "darwin" or platform.machine() != args.expected_architecture
            or args.result.exists()):
        raise ValueError("Matching native Mac architecture and a new diagnostic output required")
    spec = importlib.util.spec_from_file_location("frozen_sampler", args.sampler)
    original = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(original)
    source = Path(__file__).with_name("owned-snapshot.c")
    with tempfile.TemporaryDirectory(prefix="vss-owned-metrics-") as temporary:
        library = Path(temporary) / "read.dylib"
        subprocess.run(["xcrun", "clang", "-O2", "-Wall", "-Wextra", "-Werror", "-dynamiclib",
                        str(source), "-o", str(library)], check=True, timeout=30)
        module = ct.CDLL(str(library))
        module.prepare_owned_reader.argtypes = []
        module.prepare_owned_reader.restype = ct.c_int
        if module.prepare_owned_reader() != 0:
            raise RuntimeError("native timebase preparation failed")
        read = module.read_owned_sample
        read.argtypes = [ct.c_int, ct.c_uint64, ct.POINTER(Sample)]
        read.restype = ct.c_int
        child = subprocess.Popen([sys.executable, "-u", "-c", CHILD], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:
            await_line(child, "ready")
            process = psutil.Process(child.pid)
            def native(birth):
                value = Sample()
                status = read(child.pid, birth, ct.byref(value))
                if status:
                    raise RuntimeError(f"native ownership read refused with status {status}")
                return value

            before = native(0)
            birth = before.birth_us
            if read(child.pid, birth + 1, ct.byref(Sample())) != 2:
                raise RuntimeError("mismatched birth was accepted")
            child.stdin.write("grow\n")
            child.stdin.flush()
            await_line(child, "grown")
            after = native(birth)
            if after.rss_bytes - before.rss_bytes < 16 * 1024 * 1024 or after.user_ns <= before.user_ns:
                raise RuntimeError("owned memory/CPU workload was not observed")
            elapsed = {"psutil": [], "combined": []}
            for index in range(256):
                first = original.snapshot(process)
                if abs(round(first["creation_time"] * 1_000_000) - birth) > 1:
                    raise RuntimeError("creation time units differ")
                pair = (("psutil", lambda: original.snapshot(process)), ("combined", lambda: native(birth)))
                for name, func in pair if index % 2 == 0 else reversed(pair):
                    start = time.perf_counter_ns()
                    reading = func()
                    elapsed[name].append(time.perf_counter_ns() - start)
                    if name == "combined":
                        combined = reading
                last = original.snapshot(process)
                for field, key in [("user_ns", "cpu_user_s"), ("system_ns", "cpu_system_s")]:
                    value = getattr(combined, field)
                    if not round(first[key] * 1_000_000_000) - 1000 <= value <= round(last[key] * 1_000_000_000) + 1000:
                        raise RuntimeError("CPU counter meaning differs from the current reader")
                if not min(first["rss_bytes"], last["rss_bytes"]) <= combined.rss_bytes <= max(first["rss_bytes"], last["rss_bytes"]):
                    raise RuntimeError("RSS differs from reads bracketing the same owned child")
        finally:
            child.stdin.close()
            try:
                if child.wait(timeout=6) != 0:
                    raise RuntimeError("owned workload did not exit normally")
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
                raise
        if read(child.pid, birth, ct.byref(Sample())) == 0:
            raise RuntimeError("already exited owned workload was accepted")
        result = {"candidate_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
                  "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                  "current_sampler_sha256": hashlib.sha256(args.sampler.read_bytes()).hexdigest(),
                  "architecture": platform.machine(), "psutil_version": psutil.__version__,
                  "status": "diagnostic_pass", "validated_pairs": 256,
                  "actual_wrong_birth_and_ended_child_rejected": True,
                  "actual_rss_growth_bytes": after.rss_bytes - before.rss_bytes,
                  "actual_user_cpu_growth_ns": after.user_ns - before.user_ns,
                  "read_cost_ns": {key: {"median": statistics.median(values),
                                          "p95": sorted(values)[int(len(values) * .95)], "values": values}
                                   for key, values in elapsed.items()},
                  "formal_samples": 0, "engine_executed": False, "frozen_protocol_changed": False}
        args.result.write_text(json.dumps(result, indent=2) + "\n")
        print("Darwin owned read diagnostic: " + json.dumps({
            **result, "read_cost_ns": {k: {x: y for x, y in v.items() if x != "values"}
                                      for k, v in result["read_cost_ns"].items()},
        }))


if __name__ == "__main__":
    main()
