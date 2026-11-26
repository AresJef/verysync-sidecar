"""External-versus-self RSS calibration on a known native fixture."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import time

from observe import OwnedPeakReader, upper_value
from run_probe import ExternalRss, Worker, gap_case

MAXIMUM_SYNTHETIC_PAUSE_NS = 3_000_000_000


def verify_clock():
    libsystem = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    libsystem.clock_gettime_nsec_np.argtypes = [ctypes.c_int]
    libsystem.clock_gettime_nsec_np.restype = ctypes.c_uint64
    samples = []
    for index in range(8):
        before = time.perf_counter_ns()
        # Darwin CLOCK_UPTIME_RAW (8), the unadjusted awake-time clock.
        uptime = libsystem.clock_gettime_nsec_np(8)
        after = time.perf_counter_ns()
        samples.append([before, uptime, after])
        if index != 7:
            time.sleep(0.057)
    # The rate agrees when the offset intervals share an intersection, with a
    # conservative 100 us run-to-run bracket for measured point inclusion.
    lo = max(before - uptime for before, uptime, _ in samples)
    hi = min(after - uptime for _, uptime, after in samples)
    if lo - hi > 100_000:
        raise RuntimeError("Rust and Python clock-rate crosscheck exceeded the pretrial guard")
    return {"perf_counter": time.get_clock_info("perf_counter").implementation, "samples_ns": samples,
            "offset_intersection_low_ns": lo, "offset_intersection_high_ns": hi}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("worker", type=Path)
    p.add_argument("peak_library", type=Path)
    p.add_argument("out", type=Path)
    args = p.parse_args()
    out = args.out
    out.mkdir()
    reader = OwnedPeakReader(args.peak_library)
    payload = {"clock": verify_clock(), "maximum_synthetic_pause_ns": MAXIMUM_SYNTHETIC_PAUSE_NS, "controls": []}
    try:
        for name, phase_start_mib, pulse_mib in (
            ("zero_increment", 0, 0), ("missed_96_mib", 0, 96), ("startup_masks_transfer", 96, 32),
        ):
            case = {"name": name, "startup_mib": phase_start_mib, "pulse_mib": pulse_mib}
            payload["controls"].append(case)
            with Worker(args.worker, out / (name + ".stderr.log"), case) as worker:
                hello = case["worker"] = worker.read("hello")
                identity = reader.bind(hello["pid"], os.getpid())
                if phase_start_mib:
                    case["startup"] = worker.request(f"hold {phase_start_mib}", "hold")
                    case["startup_inside"] = reader.read(identity)
                    case["startup_release"] = worker.request("release", "release")
                case["external_begin"] = reader.read(identity)
                gap_case(worker, ExternalRss(hello), case, pulse_mib, MAXIMUM_SYNTHETIC_PAUSE_NS)
                case["external_end"] = reader.read(identity)
                b, a = case["external_begin"], case["external_end"]
                start, finish = upper_value(b), upper_value(a)
                if (start is None) != (finish is None):
                    raise RuntimeError("external task-name access changed during the control")
                if finish is not None:
                    if abs(finish - case["after"]["basic_peak_bytes"]) > 1024**2:
                        raise RuntimeError("external and self RSS peak controls differ")
                    if finish < start or a["cpu_user_ns"] < b["cpu_user_ns"] or a["cpu_system_ns"] < b["cpu_system_ns"]:
                        raise RuntimeError("nonmonotonic lifetime counter")
                case["external_lifetime_rss_before_bytes"] = start
                case["external_lifetime_rss_after_bytes"] = finish
                case["observed_current_rss_before_bytes"] = b["rss_bytes"]
                case["observed_current_rss_after_bytes"] = a["rss_bytes"]
    finally:
        path = out / "calibration.json"
        path.write_text(json.dumps(payload, indent=2) + "\n")
        print(path)


if __name__ == "__main__":
    main()
