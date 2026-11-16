#!/usr/bin/env python3
"""Sample only the explicit native resource fixture's controller and owned engine.

Requires psutil==7.2.2 in the caller's isolated test environment. Sampled RSS is
not an instantaneous high-water mark. This script never discovers or controls
other VerySync processes and never runs as part of a Cargo build.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import subprocess
import sys
import time

SCENARIOS = {"idle": (8192, 1), "stream-small": (8388608, 1),
             "stream-large": (134217728, 1), "many-small": (8192, 256)}
QUALITY = {"minimum_elapsed_ns": 500000000, "minimum_measured_snapshots": 25,
           "maximum_sample_gap_ns": 50000000, "maximum_boundary_overspan_fraction": 0.05,
           "maximum_metric_read_fraction": 0.05}


def dependency():
    import psutil
    if psutil.__version__ != "7.2.2":
        raise ValueError("fixed measurement dependency required")
    return psutil


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as source:
        while chunk := source.read(65536):
            result.update(chunk)
    return result.hexdigest()


def snapshot(process):
    start = time.perf_counter_ns()
    if not process.is_running():
        raise RuntimeError("explicit process identity ended or was reused")
    memory = process.memory_info()
    cpu = process.cpu_times()
    return {"pid": process.pid, "creation_time": process.create_time(),
            "rss_bytes": memory.rss, "cpu_user_s": cpu.user, "cpu_system_s": cpu.system,
            "read_start_ns": start, "read_end_ns": time.perf_counter_ns()}


def owned_processes(ready):
    psutil = dependency()
    controller = psutil.Process(ready["controller_pid"])
    engine = psutil.Process(ready["engine_pid"])
    if controller not in engine.parents():
        raise RuntimeError("engine is not a descendant of the explicit controller")
    if not os.path.samefile(controller.exe(), ready["controller_executable"]):
        raise RuntimeError("loaded controller image differs")
    if digest(controller.exe()) != bytes(ready["controller_sha256"]).hex():
        raise RuntimeError("loaded controller digest differs")
    if not os.path.samefile(engine.exe(), os.environ["VERYSYNC_TEST_BINARY"]):
        raise RuntimeError("loaded engine image differs")
    if digest(engine.exe()) != ready["engine_sha256"]:
        raise RuntimeError("loaded engine digest differs")
    return controller, engine


def calibrate():
    psutil = dependency()
    clock = time.get_clock_info("perf_counter")
    ticks = [time.perf_counter_ns() for _ in range(10000)]
    if any(a > b for a, b in zip(ticks, ticks[1:])):
        raise RuntimeError("non-monotonic measurement clock")
    positive = [b - a for a, b in zip(ticks, ticks[1:]) if b > a]
    process = psutil.Process()
    before = snapshot(process)
    reads = [snapshot(process) for _ in range(1000)]
    after = snapshot(process)
    if any(r["rss_bytes"] <= 0 or r["cpu_user_s"] < 0 or r["cpu_system_s"] < 0 for r in reads):
        raise RuntimeError("invalid process metric units")
    cpu = [r["cpu_user_s"] + r["cpu_system_s"] for r in reads]
    if any(a > b for a, b in zip(cpu, cpu[1:])) or cpu[-1] <= cpu[0]:
        raise RuntimeError("process CPU counter did not advance monotonically")
    positive_cpu = [b - a for a, b in zip(cpu, cpu[1:]) if b > a]
    allocation_before = snapshot(process)
    touched = bytearray(16 * 1024 * 1024)
    for offset in range(0, len(touched), 4096):
        touched[offset] = 1
    allocation_after = snapshot(process)
    rss_growth = allocation_after["rss_bytes"] - allocation_before["rss_bytes"]
    if not len(touched) // 2 <= rss_growth <= len(touched) * 2:
        raise RuntimeError("touched-memory RSS byte-unit calibration is inconclusive")
    del touched
    return {"clock": {"monotonic": clock.monotonic, "adjustable": clock.adjustable,
                      "resolution_s": clock.resolution, "implementation": clock.implementation},
            "clock_min_positive_step_ns": min(positive),
            "clock_10000_reads_span_ns": ticks[-1] - ticks[0],
            "metric_reads": len(reads), "metric_total_span_ns": after["read_end_ns"] - before["read_end_ns"],
            "metric_max_read_ns": max(r["read_end_ns"] - r["read_start_ns"] for r in reads),
            "metric_first": before, "metric_last": after,
            "cpu_min_observed_positive_step_s": min(positive_cpu),
            "cpu_observed_span_s": cpu[-1] - cpu[0],
            "cpu_counter_step_is_empirical_not_an_error_bound": True,
            "rss_touched_bytes": 16 * 1024 * 1024, "rss_growth_bytes": rss_growth,
            "psutil": psutil.__version__, "python": sys.version, "platform": platform.platform()}


def source_identity(cargo, toolchain):
    root = Path(__file__).resolve().parents[1]
    paths = [root / "Cargo.toml", root / "Cargo.lock", root / "tests/resource_usage_engine.rs"]
    paths += sorted((root / "src").rglob("*.rs"))
    paths += [root / "tests/common" / name for name in
              ["managed_fixture.rs", "resource_faults.rs", "resource_fixture.rs"]]
    source_hash = hashlib.sha256()
    for path in paths:
        source_hash.update(str(path.relative_to(root)).replace(os.sep, "/").encode() + b"\0")
        source_hash.update(path.read_bytes())
    def git(ref):
        return subprocess.check_output(["git", "rev-parse", ref], cwd=root, text=True).strip()
    return {"source_commit": git("HEAD"), "source_tree": git("HEAD^{tree}"),
            "rust_sources_sha256": source_hash.hexdigest(), "cargo_lock_sha256": digest(root / "Cargo.lock"),
            "sampler_sha256": digest(__file__),
            "wrapper_sha256": digest(Path(__file__).with_name("run-isolated-engine-tests.py")),
            "toolchain": toolchain, "cargo_version": subprocess.check_output(
                [str(cargo), "+" + toolchain, "--version"], text=True).strip(),
            "rustc_version": subprocess.check_output([str(cargo.parent / "rustc"), "+" + toolchain,
                                                       "--version"], text=True).strip(),
            "build_environment_sha256": {key: hashlib.sha256(os.environ.get(key, "").encode()).hexdigest()
                for key in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTC_WRAPPER", "CARGO_PROFILE_RELEASE_OPT_LEVEL"]},
            "profile": "release"}


def summarize(report, rows, quality=QUALITY):
    import math
    import statistics
    errors, insufficient = [], []
    events = report.get("events", [])
    if report.get("exit_code") != 0 or [x.get("kind") for x in events] != ["ready", "begin", "end", "complete"]:
        return {"status": "ERROR", "errors": ["native outcome or correctness journal incomplete"]}
    ready, _, ending, complete = events
    if not all(complete.get(key) is True for key in ["all_actual_bytes_verified", "source_config_identity_unchanged", "normal_owned_tree_exit"]):
        errors.append("native correctness or cleanup did not pass")
    size, files = SCENARIOS[report["scenario"]]
    n = report["repeats"]
    calls = 0 if report["scenario"] == "idle" else files * n
    if (ready["scenario"], ready["repeats"], ready["bytes_each"], ready["files"]) != (report["scenario"], n, size, files):
        errors.append("registered workload identity differs")
    if ending["completed_calls"] != calls or ending["transferred_bytes"] != size * calls:
        errors.append("registered workload was not completed")
    measured = [x for x in rows if x["phase"] == "measure"]
    baseline = [x for x in rows if x["phase"] == "baseline"]
    elapsed = ending["elapsed_ns"]
    if not isinstance(elapsed, int) or elapsed <= 0:
        return {"status": "ERROR", "errors": ["invalid operation clock interval"]}
    if elapsed < quality["minimum_elapsed_ns"]:
        insufficient.append("batch too short")
    if len(measured) < quality["minimum_measured_snapshots"] or not baseline:
        insufficient.append("insufficient measured or baseline observations")
    positions = [report["before"][0]["read_start_ns"]] + [x["start_ns"] for x in measured] + [report["after"][-1]["read_end_ns"]]
    if any(a > b for a, b in zip(positions, positions[1:])):
        errors.append("sample clock moved backwards")
    gap = max((b-a for a, b in zip(positions, positions[1:])), default=0)
    if gap > quality["maximum_sample_gap_ns"]:
        insufficient.append("sampling gap exceeded coverage limit")
    overspan = (positions[-1] - positions[0] - elapsed) / elapsed
    if not 0 <= overspan <= quality["maximum_boundary_overspan_fraction"]:
        insufficient.append("boundary observation span insufficient")
    overhead = 0
    roles = {}
    for index, role in enumerate(["controller", "engine"]):
        before, after = report["before"][index], report["after"][index]
        identity = report["identities"][index]
        points = [before] + [x[role] for x in measured] + [after]
        for point in points:
            if (point["pid"], point["creation_time"]) != (identity["pid"], identity["creation_time"]):
                errors.append(role + " process identity changed")
            if point["read_end_ns"] < point["read_start_ns"] or point["rss_bytes"] <= 0:
                errors.append(role + " invalid metric interval or RSS")
            if not all(math.isfinite(point[key]) and point[key] >= 0 for key in ["cpu_user_s", "cpu_system_s"]):
                errors.append(role + " invalid CPU counter")
        for a, b in zip(points, points[1:]):
            if any(a[key] > b[key] for key in ["cpu_user_s", "cpu_system_s"]):
                errors.append(role + " CPU counter decreased")
        overhead += sum(p["read_end_ns"] - p["read_start_ns"] for p in points)
        baseline_rss = statistics.median(x[role]["rss_bytes"] for x in baseline[-10:]) if baseline else None
        peak = max(p["rss_bytes"] for p in points)
        roles[role] = {"sampled_peak_rss_bytes": peak, "baseline_rss_bytes": baseline_rss,
                       "sampled_rss_increment_bytes": peak - baseline_rss if baseline_rss is not None else None,
                       "cpu_user_s": after["cpu_user_s"] - before["cpu_user_s"],
                       "cpu_system_s": after["cpu_system_s"] - before["cpu_system_s"]}
    overhead /= elapsed
    if overhead > quality["maximum_metric_read_fraction"]:
        insufficient.append("metric read overhead exceeded limit")
    return {"status": "ERROR" if errors else ("INSUFFICIENT" if insufficient else "VALID"),
            "errors": sorted(set(errors)), "insufficient": insufficient, "elapsed_ns": elapsed,
            "n": n, "normalized_ns": elapsed/n, "samples": len(measured), "max_sample_gap_ns": gap,
            "boundary_overspan_fraction": overspan, "metric_read_fraction": overhead, **roles}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--toolchain", default="1.85.0")
    parser.add_argument("--cargo", type=Path)
    parser.add_argument("--scenario", choices=["idle", "stream-small", "stream-large", "many-small"])
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--interval-ms", type=float, default=10)
    parser.add_argument("--stage", choices=["calibration", "pilot", "formal", "independent"], required=True)
    parser.add_argument("--protocol", type=Path)
    args = parser.parse_args()
    if not args.evidence_dir.is_absolute() or args.evidence_dir.exists():
        raise ValueError("fresh absolute evidence directory required")
    if not 1 <= args.repeats <= 32 or not 1 <= args.interval_ms <= 100:
        raise ValueError("outside the explicit preparation parameter bounds")
    dependency()
    if args.stage != "calibration" and (args.cargo is None or not args.cargo.is_absolute() or not args.cargo.is_file()):
        raise ValueError("native measurement requires an explicit absolute Cargo executable")
    args.evidence_dir.mkdir(parents=True, mode=0o700)
    report = {"stage": args.stage, "calibration": calibrate(), "formal_sample": False}
    if args.stage == "calibration":
        (args.evidence_dir / "calibration.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report))
        return 0
    if not args.scenario:
        raise ValueError("pilot requires an explicit registered scenario")
    nonce = secrets.token_hex(32)
    events = args.evidence_dir / "events.jsonl"
    env = os.environ.copy()
    env.update(VERYSYNC_RESOURCE_SCENARIO=args.scenario, VERYSYNC_RESOURCE_REPEATS=str(args.repeats),
               VERYSYNC_RESOURCE_EVENTS=str(events), VERYSYNC_RESOURCE_NONCE=nonce)
    command = [sys.executable, str(Path(__file__).with_name("run-isolated-engine-tests.py")),
               "--cargo", str(args.cargo),
               "--toolchain", args.toolchain, "--release", "--test-target", "resource_usage_engine",
               "--evidence-dir", str(args.evidence_dir / "native")]
    journal_offset = 0
    processes = None
    phase = "prepare"
    report.update(scenario=args.scenario, repeats=args.repeats, interval_ms=args.interval_ms,
                  events=[], identities=None, source=source_identity(args.cargo, args.toolchain))
    if args.stage in {"formal", "independent"}:
        if args.protocol is None:
            raise ValueError("formal attempts require the frozen protocol")
        protocol = json.loads(args.protocol.read_text())
        if (protocol["scenarios"][args.scenario]["repeats"] != args.repeats
                or protocol["interval_ms"] != args.interval_ms or protocol["quality"] != QUALITY):
            raise ValueError("attempt differs from frozen measurement parameters")
        for key, value in protocol["source_inputs"].items():
            if report["source"].get(key) != value:
                raise ValueError("frozen source input differs: "+key)
        if not report["source"]["rustc_version"].startswith("rustc "+protocol["rust_release"]+" "):
            raise ValueError("actual compiler differs from frozen release")
        report.update(protocol_sha256=digest(args.protocol), formal_sample=True,
                      acceptance="raw attempt only; requires a complete accepted group manifest")
    with (args.evidence_dir / "console.log").open("wb") as console, (args.evidence_dir / "samples.jsonl").open("w") as samples:
        child = subprocess.Popen(command, env=env, stdout=console, stderr=subprocess.STDOUT)
        try:
            while True:
                if events.exists():
                    with events.open("rb") as journal:
                        journal.seek(journal_offset)
                        for line in journal:
                            if not line.endswith(b"\n"):
                                break
                            value = json.loads(line)
                            if value["nonce"] != nonce:
                                raise RuntimeError("resource journal identity mismatch")
                            journal_offset += len(line)
                            value["observed_ns"] = time.perf_counter_ns()
                            report["events"].append(value)
                            kind = value["kind"]
                            if kind == "ready":
                                if args.stage in {"formal", "independent"} and value["engine_version"].lstrip("v") != protocol["engine_version"].lstrip("v"):
                                    raise ValueError("actual engine version differs from frozen baseline")
                                processes = owned_processes(value)
                                report["identities"] = [snapshot(p) for p in processes]
                                phase = "baseline"
                                events.with_suffix(".ack").write_text(nonce)
                            elif kind == "begin":
                                phase = "measure"
                                report["before"] = [snapshot(p) for p in processes]
                                events.with_suffix(".begin-ack").write_text(nonce)
                            elif kind == "end":
                                report["after"] = [snapshot(p) for p in processes]
                                events.with_suffix(".end-ack").write_text(nonce)
                                phase = "after"
                            elif kind == "complete":
                                phase = "complete"
                if processes is not None and phase in {"baseline", "measure"}:
                    row = {"phase": phase, "start_ns": time.perf_counter_ns(),
                           "controller": snapshot(processes[0]), "engine": snapshot(processes[1]),
                           "end_ns": time.perf_counter_ns()}
                    samples.write(json.dumps(row) + "\n")
                if child.poll() is not None:
                    break
                time.sleep(args.interval_ms / 1000)
            report["exit_code"] = child.wait()
        finally:
            if child.poll() is None:
                # A fixture failure still reaches its normal bounded SDK cleanup.
                # Never kill by name or signal unrelated native processes.
                child.wait(timeout=150)
            (args.evidence_dir / "preparation-result.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["exit_code"] != 0:
        print(json.dumps({"exit_code": report["exit_code"], "evidence": str(args.evidence_dir)}))
        return report["exit_code"]
    if [e["kind"] for e in report["events"]] != ["ready", "begin", "end", "complete"]:
        raise RuntimeError("incomplete native correctness journal")
    rows = [json.loads(line) for line in (args.evidence_dir / "samples.jsonl").read_text().splitlines()]
    result = summarize(report, rows)
    (args.evidence_dir / "quality-result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"exit_code": 0, "quality": result["status"], "scenario": args.scenario, "evidence": str(args.evidence_dir), "formal_sample": report["formal_sample"]}))
    return 0 if result["status"] == "VALID" else 2


if __name__ == "__main__":
    sys.exit(main())
