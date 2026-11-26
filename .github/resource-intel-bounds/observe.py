"""Pilot observer for the exact released v33 workload and owned process counters."""
import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import sys
from time import perf_counter_ns

ROLES = ("controller", "engine")
MIB = 1024 * 1024
CLOCK_GUARD_NS = 100_000


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


class Peak(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "birth_us", "basic_rss_bytes", "basic_peak_bytes", "vm_rss_bytes", "vm_peak_bytes",
    )] + [(name, ctypes.c_uint32) for name in ("basic_count", "vm_count")] + [
        (name, ctypes.c_int32) for name in (
            "acquire_status", "basic_status", "vm_status", "deallocate_status", "identity_errno",
        )
    ]


class OwnedPeakReader:
    def __init__(self, library):
        self.library = ctypes.CDLL(str(library))
        if self.library.prepare_owned_reader() != 0:
            raise RuntimeError("native reader timebase could not initialize")
        self.ordinary = self.library.read_owned_sample
        self.ordinary.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                  ctypes.POINTER(ctypes.c_uint64)]
        self.ordinary.restype = ctypes.c_int
        self.peak = self.library.read_owned_peak
        self.peak.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.POINTER(Peak)]
        self.peak.restype = ctypes.c_int

    def bind(self, pid, parent):
        fields = (ctypes.c_uint64 * 4)()
        if self.ordinary(pid, parent, 0, fields) != 0:
            raise RuntimeError("owned process birth read failed")
        if self.ordinary(pid, parent, fields[0] + 1, fields) != 2:
            raise RuntimeError("reader accepted a different process birth")
        return (pid, parent, fields[0])

    def read(self, identity):
        pid, parent, birth = identity
        ordinary = (ctypes.c_uint64 * 4)()
        peak = Peak()
        started = perf_counter_ns()
        status = self.ordinary(pid, parent, birth, ordinary)
        ordinary_finished = perf_counter_ns()
        peak_status = self.peak(pid, parent, birth, ctypes.byref(peak))
        finished = perf_counter_ns()
        if status or peak_status or ordinary[0] != birth or peak.birth_us != birth:
            raise RuntimeError("owned identity changed or disappeared at a boundary")
        return {
            "identity": {"pid": pid, "parent": parent, "birth_us": birth},
            "start_ns": started, "ordinary_end_ns": ordinary_finished, "end_ns": finished,
            "rss_bytes": ordinary[1], "cpu_user_ns": ordinary[2], "cpu_system_ns": ordinary[3],
            "peak": {name: getattr(peak, name) for name, _ in Peak._fields_},
        }


def upper_value(read):
    peak = read["peak"]
    if any(peak[name] != 0 for name in (
        "acquire_status", "basic_status", "vm_status", "deallocate_status", "identity_errno",
    )):
        return None
    if (peak["basic_count"] < 12 or peak["vm_count"] < 10
            or peak["basic_rss_bytes"] <= 0 or peak["vm_rss_bytes"] <= 0
            or peak["basic_rss_bytes"] > peak["basic_peak_bytes"]
            or peak["vm_rss_bytes"] > peak["vm_peak_bytes"]
            or peak["basic_peak_bytes"] != peak["vm_peak_bytes"]
            or peak["basic_peak_bytes"] < read["rss_bytes"]):
        raise RuntimeError("native RSS and peak fields disagree at an owned boundary")
    return peak["basic_peak_bytes"]


def reproduce_bounds(folder):
    original = json.loads((folder / "preparation-result.json").read_text())
    quality = json.loads((folder / "quality-result.json").read_text())
    witness = json.loads((folder / "peak-boundaries.json").read_text())
    rows = [json.loads(line) for line in (folder / "samples.jsonl").read_text().splitlines()]
    start, stop = witness["begin"], witness["end"]
    ready, begin, ending, complete = original["events"]
    elapsed = ending["elapsed_ns"]
    earliest_start = start["ack_write_start_ns"]
    latest_end = ending["observed_ns"]
    # The fixture waits for the begin ack. Its elapsed clock stops before
    # publishing the end event. These observations enclose both real edges.
    latest_start = latest_end - elapsed + CLOCK_GUARD_NS
    earliest_end = earliest_start + elapsed - CLOCK_GUARD_NS
    if earliest_start > latest_start or latest_start >= earliest_end:
        raise RuntimeError("elapsed clock did not enclose a definite measured interval")
    if not begin["observed_ns"] < start["ack_write_start_ns"] <= start["ack_write_end_ns"]:
        raise RuntimeError("invalid begin acknowledgement time")
    if not latest_end < stop["ack_write_start_ns"] <= stop["ack_write_end_ns"] < complete["observed_ns"]:
        raise RuntimeError("invalid end acknowledgement time")
    result = {
        "scenario": original["scenario"], "repeats": original["repeats"],
        "registered_elapsed_ns": elapsed, "transferred_bytes": ending["transferred_bytes"],
        "completed_calls": ending["completed_calls"], "v33_quality": quality,
        "boundaries": {"earliest_start_ns": earliest_start, "latest_start_ns": latest_start,
                       "earliest_end_ns": earliest_end, "latest_end_ns": latest_end},
        "boundary_observer_span_ns": latest_end - earliest_start - elapsed,
        "peak_read_overspan_ns": max(stop["reads"][r]["end_ns"] for r in ROLES)
            - min(start["reads"][r]["start_ns"] for r in ROLES) - elapsed,
        "native_outcome": {name: value for name, value in complete.items() if name not in {"nonce", "kind"}},
        "roles": {},
    }
    for role in ROLES:
        before, after = start["reads"][role], stop["reads"][role]
        if before["identity"] != after["identity"] or before["identity"]["pid"] != ready[role + "_pid"]:
            raise RuntimeError("before and after describe different processes")
        if not before["end_ns"] <= earliest_start <= latest_end < after["start_ns"]:
            raise RuntimeError("peak reads do not conservatively bracket the operation")
        if after["end_ns"] > stop["ack_write_start_ns"]:
            raise RuntimeError("peak read may have happened during post-transfer verification")
        index = ROLES.index(role)
        identity = original["identities"][index]
        if abs(before["identity"]["birth_us"] - round(identity["creation_time"] * 1_000_000)) > 1:
            raise RuntimeError("frozen reader and peak reader identify different processes")
        eligible = [row[role] for row in rows if row["phase"] == "measure"
                    and latest_start <= row[role]["read_start_ns"] <= row[role]["read_end_ns"] <= earliest_end]
        low = max((point["rss_bytes"] for point in eligible), default=None)
        old, high = upper_value(before), upper_value(after)
        if high is not None and ((low is not None and high < low) or (old is not None and high < old)):
            raise RuntimeError("process lifetime peak decreased or fell below an in-window RSS read")
        cpu_delta = {}
        for counter in ("cpu_user_ns", "cpu_system_ns"):
            delta = after[counter] - before[counter]
            if delta < 0:
                raise RuntimeError("process CPU counters went backwards")
            cpu_delta[counter] = delta
        result["roles"][role] = {
            "identity": before["identity"], "confirmed_in_window_samples": len(eligible),
            "lower_rss_bytes": low, "upper_rss_bytes": high, "prior_lifetime_rss_bytes": old,
            "new_lifetime_record_may_include_edge_work": None if old is None or high is None else high > old,
            "cpu_boundary_delta_ns": cpu_delta,
            "boundary_read_duration_ns": sum(x["end_ns"] - x["start_ns"] for x in (before, after)),
            "peak_query_status_begin": before["peak"],
            "peak_query_status_end": after["peak"],
        }
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--peak-library", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--stage", choices=("pilot", "formal", "independent"), default="pilot")
    parser.add_argument("--repeats", type=int, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--toolchain", required=True)
    args = parser.parse_args()
    scripts = args.source / "scripts"
    sys.path.insert(0, str(scripts))
    sampler_file = scripts / "measure-native-resources.py"
    spec = importlib.util.spec_from_file_location("frozen_v33_observer", sampler_file)
    metrics = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(metrics)
    reader = OwnedPeakReader(args.peak_library)
    original_bind = metrics.bind_metric_processes
    witness = {"method": "same-process macOS name-port lifetime RSS; only definite-window samples can lift lower bound",
               "clock_guard_ns": CLOCK_GUARD_NS, "stage": args.stage}
    identities = {}

    def bind(ordinary_reader, processes, parent):
        ordinary_read = original_bind(ordinary_reader, processes, parent)
        for name, process in zip(ROLES, processes, strict=True):
            identities[name] = reader.bind(process.pid, process.ppid())
        return ordinary_read

    class BoundaryPath(type(Path())):
        def write_text(self, data, *pos, **kw):
            name = {"events.begin-ack": "begin", "events.end-ack": "end"}.get(self.name)
            if name is None or self.parent != args.evidence_dir:
                return super().write_text(data, *pos, **kw)
            reads = {key: reader.read(identities[key]) for key in ROLES}
            start = perf_counter_ns()
            written = super().write_text(data, *pos, **kw)
            witness[name] = {"reads": reads, "ack_write_start_ns": start, "ack_write_end_ns": perf_counter_ns()}
            return written

    metrics.Path = BoundaryPath
    metrics.bind_metric_processes = bind
    sys.argv = [str(sampler_file), "--stage", args.stage, "--protocol",
                str(args.source / "tests/fixtures/resource-protocol.json"), "--interval-ms", "10",
                "--evidence-dir", str(args.evidence_dir), "--scenario", args.scenario, "--repeats",
                str(args.repeats), "--cargo", str(args.cargo), "--toolchain", args.toolchain]
    try:
        code = metrics.main()
    finally:
        if args.evidence_dir.exists():
            write_json(args.evidence_dir / "peak-boundaries.json", witness)
    if code in {0, 2}:
        result = reproduce_bounds(args.evidence_dir)
        write_json(args.evidence_dir / "rss-bounds.json", result)
        print(json.dumps(result, separators=(",", ":")), flush=True)
        return 0
    return code


if __name__ == "__main__":
    sys.exit(main())
