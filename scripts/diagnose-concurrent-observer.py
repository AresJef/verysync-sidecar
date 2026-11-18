#!/usr/bin/env python3
"""Compare a separate native timer with a frozen sampler during private pilots."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ORDER = (False, True, True, False)
MAX_WITNESS_SECONDS = 180
TREE = "ef7818b39e4510557a906d62fdd8c2c838cc3627"
PROTOCOL_SHA = "cae69b1e559c3cf9d93522c98f32dc44f8084a5d0e47a311e864a522491e528d"


def load_reporter(source):
    spec = importlib.util.spec_from_file_location("frozen_reporter", source / "scripts/report-native-resources.py")
    reporter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reporter)
    return reporter


def witness(source, case_dir, interval_ms):
    reporter = load_reporter(source)
    metrics = reporter.module("frozen_clock", "measure-native-resources.py")
    clock = time.get_clock_info("perf_counter")
    assert clock.monotonic and not clock.adjustable and clock.implementation == "mach_absolute_time()"
    policy = metrics.observer_thread_policy()
    timer = metrics.CriticalKqueueTicker(interval_ms)
    stopping = False

    def stop(_number, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    try:
        before = time.perf_counter_ns()
        deadline = before + MAX_WITNESS_SECONDS * 1_000_000_000
        cpu_before = time.process_time_ns()
        ready = {"pid": os.getpid(), "start_ns": before, "clock": clock.implementation,
                 "thread_policy": policy, "timer": timer.parameters}
        (case_dir / "witness-ready.json").write_text(json.dumps(ready) + "\n")
        rows = []
        while not stopping and before < deadline:
            timer.wait()
            after, cpu_after = time.perf_counter_ns(), time.process_time_ns()
            rows.append({"start_ns": before, "end_ns": after, "expirations": timer.expirations,
                         "process_cpu_ns": cpu_after - cpu_before})
            before, cpu_before = after, cpu_after
            if len(rows) > 25_000:
                raise RuntimeError("independent timer row bound was exceeded")
        if not stopping:
            raise RuntimeError("independent timer reached its time bound")
        (case_dir / "witness.json").write_text(json.dumps({"ready": ready, "rows": rows}) + "\n")
    finally:
        timer.close()


def run_cases(args, protocol):
    profile = protocol["scenarios"][args.scenario]
    interval_ms = protocol["interval_ms"]
    args.evidence_dir.mkdir(mode=0o700)
    for index, enabled in enumerate(ORDER):
        case = args.evidence_dir / str(index)
        case.mkdir(mode=0o700)
        observer = None
        with (case / "witness-console.log").open("wb") as observer_log, (case / "native-console.log").open("wb") as native_log:
            try:
                if enabled:
                    observer = subprocess.Popen(
                        [sys.executable, "-B", __file__, "witness", str(args.source), str(case), str(interval_ms)],
                        cwd=args.source, stdout=observer_log, stderr=subprocess.STDOUT)
                    wait_until = time.monotonic() + 15
                    ready = case / "witness-ready.json"
                    while not ready.is_file():
                        if observer.poll() is not None or time.monotonic() >= wait_until:
                            raise RuntimeError("independent timer did not become ready")
                        time.sleep(0.025)
                command = [sys.executable, "-B", str(args.source / "scripts/measure-native-resources.py"),
                           "--stage", "pilot", "--protocol", str(args.source / "tests/fixtures/resource-protocol.json"),
                           "--cargo", str(args.cargo), "--toolchain", args.toolchain,
                           "--scenario", args.scenario, "--repeats", str(profile["repeats"]),
                           "--interval-ms", str(interval_ms), "--evidence-dir", str(case / "pilot")]
                native = subprocess.run(command, cwd=args.source, stdout=native_log,
                                        stderr=subprocess.STDOUT, check=False)
                (case / "native-exit.json").write_text(json.dumps(native.returncode) + "\n")
                if native.returncode not in {0, 2}:
                    raise RuntimeError("frozen native workload failed")
            finally:
                if observer is not None:
                    if observer.poll() is None:
                        observer.terminate()
                    try:
                        ended = observer.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        observer.kill()
                        observer.wait()
                        raise RuntimeError("independent timer did not exit normally")
                    if ended:
                        raise RuntimeError("independent timer failed")


def correlate(raw, trace, positions, limit):
    clock = raw["calibration"]["clock"]
    if trace["ready"]["clock"] != clock["implementation"]:
        raise ValueError("observers use different clock implementations")
    timer = trace["ready"]["timer"]
    if timer != raw["timer_parameters"] or trace["ready"]["thread_policy"]["observed"] != raw["observer_thread_policy"]["observed"]:
        raise ValueError("independent timer or QoS settings differ")
    rows = trace["rows"]
    if not rows or not rows[0]["start_ns"] <= positions[0] <= positions[-1] <= rows[-1]["end_ns"]:
        raise ValueError("independent timer does not cover the full observation window")
    assert rows[0]["start_ns"] == trace["ready"]["start_ns"]
    assert all(x["end_ns"] > x["start_ns"] and x["expirations"] >= 1 and x["process_cpu_ns"] >= 0 for x in rows)
    assert all(a["end_ns"] == b["start_ns"] for a, b in zip(rows, rows[1:]))
    native_gaps = [(a, b) for a, b in zip(positions, positions[1:]) if b - a > limit]
    reference_gaps = [x for x in rows if x["end_ns"] - x["start_ns"] > limit]
    correlated = []
    for start, end in native_gaps:
        overlapping = [x for x in reference_gaps if x["start_ns"] < end and x["end_ns"] > start]
        shared = max((min(end, x["end_ns"]) - max(start, x["start_ns"]) for x in overlapping), default=0)
        ticks = sum(start < x["end_ns"] < end for x in rows)
        if shared >= limit:
            observation = "concurrent_gap"
        elif not overlapping and ticks:
            observation = "reference_timer_continued"
        else:
            observation = "uncertain_alignment"
        correlated.append({"start_ns": start, "end_ns": end, "native_gap_ns": end-start,
                           "max_overlapping_late_interval_ns": shared, "reference_ticks_inside": ticks,
                           "observation": observation})
    active_rows = [x for x in rows if x["start_ns"] < positions[-1] and x["end_ns"] > positions[0]]
    return {"coverage_rows": len(active_rows), "total_rows": len(rows),
            "process_cpu_ns_including_boundary_rows": sum(x["process_cpu_ns"] for x in active_rows),
            "largest_reference_gap_ns": max(x["end_ns"] - x["start_ns"] for x in active_rows),
            "native_gaps": correlated}


def verify(args, reporter, protocol, commit):
    metrics = reporter.module("frozen_metrics", "measure-native-resources.py")
    result = {"role": "diagnostic only", "formal_sample": False, "eligible_for_frozen_preparation": False,
              "source_commit": commit, "source_tree": TREE, "protocol_sha256": PROTOCOL_SHA,
              "scenario": args.scenario, "cases": []}
    identities, binaries = set(), set()
    for index, enabled in enumerate(ORDER):
        case = args.evidence_dir / str(index)
        pilot = case / "pilot"
        raw, quality = reporter.check_attempt(pilot, protocol, "pilot", metrics)
        target = protocol["scenarios"][args.scenario]
        assert raw["scenario"] == args.scenario and raw["repeats"] == target["repeats"]
        assert raw["source"]["source_commit"] == commit and raw["source"]["source_tree"] == TREE
        assert reporter.read(case / "native-exit.json") == (0 if quality["status"] == "VALID" else 2)
        for entry in raw["identities"]:
            identity = entry["pid"], entry["creation_time"]
            assert identity not in identities
            identities.add(identity)
        ready, _, ending, _ = raw["events"]
        binaries.add((bytes(ready["controller_sha256"]).hex(), ready["engine_sha256"]))
        rows = [json.loads(line) for line in (pilot / "samples.jsonl").read_text().splitlines()]
        positions = [raw["before"][0]["read_start_ns"]] + [x["start_ns"] for x in rows if x["phase"] == "measure"] + [raw["after"][-1]["read_end_ns"]]
        assert max(b - a for a, b in zip(positions, positions[1:])) == quality["max_sample_gap_ns"]
        assert not quality["errors"]
        reference_file = case / "witness.json"
        assert reference_file.is_file() == enabled
        reference = correlate(raw, reporter.read(reference_file), positions,
                              protocol["quality"]["maximum_sample_gap_ns"]) if enabled else None
        result["cases"].append({"independent_timer": enabled, "quality": quality["status"],
                                 "max_gap_ns": quality["max_sample_gap_ns"], "quality_limits": quality["insufficient"],
                                 "elapsed_ns": ending["elapsed_ns"], "actual_calls": ending["completed_calls"],
                                 "actual_bytes": ending["transferred_bytes"], "witness": reference})
    assert len(identities) == 8 and len(binaries) == 1
    result["actual_fresh_identities"] = len(identities)
    result["binary_digests"] = sorted(binaries)
    (args.evidence_dir / "concurrent-observer-summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "witness":
        witness(Path(sys.argv[2]), Path(sys.argv[3]), float(sys.argv[4]))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--scenario", choices=["many-small", "stream-large"], required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    assert args.source.is_absolute() and args.cargo.is_absolute() and args.evidence_dir.is_absolute()
    assert sys.platform == "darwin" or args.replay
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=args.source, text=True).strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=args.source, text=True).strip()
    assert tree == TREE
    assert not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=args.source, text=True)
    reporter = load_reporter(args.source)
    protocol_path = args.source / "tests/fixtures/resource-protocol.json"
    assert reporter.digest(protocol_path) == PROTOCOL_SHA
    protocol = reporter.read(protocol_path)
    if not args.replay:
        run_cases(args, protocol)
    verify(args, reporter, protocol, commit)


if __name__ == "__main__":
    main()
