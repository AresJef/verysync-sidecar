"""Verify live calibration, missed spikes, and known threshold violations."""
import argparse
import json
from pathlib import Path

from observe import upper_value
from rss_limits import arithmetic_controls, file_envelope, repeat_span

MIB = 1024**2


def prove_controls(data):
    arithmetic_controls()
    clock = data["clock"]
    assert clock["perf_counter"] == "mach_absolute_time()"
    assert clock["offset_intersection_low_ns"] <= clock["offset_intersection_high_ns"] + 100_000
    assert data["maximum_synthetic_pause_ns"] == 3_000_000_000
    cases = {case["name"]: case for case in data["controls"]}
    assert set(cases) == {"zero_increment", "missed_96_mib", "startup_masks_transfer"}
    intervals = {}
    for name, case in cases.items():
        assert case["exit"] == {"code": 0, "forced": False}
        assert case["worker"]["architecture"] == "x86_64"
        assert case["pulse_entirely_in_pause"]
        assert 950_000_000 <= case["pause_ns"] <= data["maximum_synthetic_pause_ns"]
        released = next(x for x in case["worker_transcript"]
                        if x.get("received", {}).get("event") == "pulse")
        assert case["pulse"]["unmapped_ns"] <= released["parent_time_ns"]
        assert released["parent_time_ns"] < case["ordinary_after"][0]["read_begin_ns"]
        assert case["pulse"]["mapped_resident_bytes"] == case["pulse_mib"] * MIB
        begin, end = case["external_begin"], case["external_end"]
        assert begin["identity"] == end["identity"]
        ub, ue = upper_value(begin), upper_value(end)
        assert ub is not None and ue is not None and ub <= ue
        assert abs(ue - case["after"]["basic_peak_bytes"]) <= MIB
        for key in ("cpu_user_ns", "cpu_system_ns"):
            assert end[key] >= begin[key]
        intervals[name] = (case["ordinary_total_max_bytes"], ue)
    zero, spike, startup_late = (intervals[n] for n in (
        "zero_increment", "missed_96_mib", "startup_masks_transfer"))
    assert spike[0] - zero[0] < MIB and 95*MIB < spike[1] - zero[1] < 97*MIB
    startup = cases["startup_masks_transfer"]
    assert startup["startup"]["mapped_resident_bytes"] == 96*MIB
    assert startup["pulse"]["mapped_resident_bytes"] == 32*MIB
    sticky_before = startup["external_lifetime_rss_before_bytes"]
    assert 0 <= startup_late[1] - sticky_before < MIB

    visible = startup["startup_inside"]
    visible_peak = (visible["rss_bytes"], upper_value(visible))
    verdict = {
        "zero_increment_control": file_envelope([zero], [zero], 16*MIB),
        "missed_spike_16_mib_control": file_envelope([spike], [zero], 16*MIB),
        "missed_spike_8_mib_control": repeat_span([spike, zero], 8*MIB),
        "visible_overshoot_16_mib_control": file_envelope([visible_peak], [zero], 16*MIB),
        "visible_overshoot_8_mib_control": repeat_span([visible_peak, zero], 8*MIB),
    }
    assert [x["status"] for x in verdict.values()] == [
        "PASS", "INCONCLUSIVE", "INCONCLUSIVE", "ABOVE_LIMIT", "ABOVE_LIMIT"]
    return {"status": "CALIBRATED", "synthetic_rss_intervals_bytes": intervals,
            "visible_known_peak_bytes": visible_peak, "threshold_checks": verdict}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = prove_controls(json.loads(args.input.read_text()))
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
