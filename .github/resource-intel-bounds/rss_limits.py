"""Conservative resource verdicts from independently replayable RSS intervals."""
from collections import Counter


def validate_intervals(intervals):
    return bool(intervals) and all(
        low is not None and high is not None and 0 < low <= high for low, high in intervals
    )


def decision(low, high, ceiling):
    if low is None or high is None:
        status = "UNRESOLVED"
    elif high <= ceiling:
        status = "PASS"
    elif low > ceiling:
        status = "ABOVE_LIMIT"
    else:
        status = "INCONCLUSIVE"
    return {"lower_bytes": low, "upper_bytes": high, "limit_bytes": ceiling, "status": status}


def repeat_span(intervals, ceiling):
    if not validate_intervals(intervals):
        return decision(None, None, ceiling)
    lower = max(0, max(lo for lo, _ in intervals) - min(hi for _, hi in intervals))
    upper = max(hi for _, hi in intervals) - min(lo for lo, _ in intervals)
    return decision(lower, upper, ceiling)


def file_envelope(large, small, ceiling):
    if not validate_intervals(large) or not validate_intervals(small):
        return decision(None, None, ceiling)
    lower = max(lo for lo, _ in large) - min(hi for _, hi in small)
    upper = max(hi for _, hi in large) - min(lo for lo, _ in small)
    return decision(lower, upper, ceiling)


def summarize_limits(cases, protocol):
    contract = protocol["resource_contract"]
    by_scenario = {}
    for scenario in protocol["scenarios"]:
        by_scenario[scenario] = [
            (controller["lower_rss_bytes"], controller["upper_rss_bytes"])
            for case in cases if case["scenario"] == scenario
            for controller in (case["roles"]["controller"],)
        ]
    repeats = {scenario: repeat_span(rows, contract["controller_rss_repeat_span_limit_bytes"])
               for scenario, rows in by_scenario.items()}
    counts = Counter(case["scenario"] for case in cases)
    return {
        "case_counts": dict(counts),
        "six_cycle_minimum_not_a_pilot_result": all(counts[scenario] == 6 for scenario in by_scenario),
        "repetition_stability": repeats,
        "large_minus_small_envelope": file_envelope(
            by_scenario["stream-large"], by_scenario["stream-small"],
            contract["controller_peak_large_minus_small_envelope_limit_bytes"],
        ),
    }


def arithmetic_controls():
    mib = 2**20
    # Each case describes the same RSS scope as the frozen reader, in bytes.
    baseline = [(4*mib, 4*mib)]
    masked = [(4*mib, 32*mib)]
    visible = [(32*mib, 32*mib)]
    narrow = [(4*mib, 8*mib)]
    assert file_envelope(masked, baseline, 16*mib)["status"] == "INCONCLUSIVE"
    assert repeat_span(masked + baseline, 8*mib)["status"] == "INCONCLUSIVE"
    assert file_envelope(visible, baseline, 16*mib)["status"] == "ABOVE_LIMIT"
    assert repeat_span(visible + baseline, 8*mib)["status"] == "ABOVE_LIMIT"
    assert file_envelope(narrow, baseline, 16*mib)["status"] == "PASS"
    assert repeat_span(narrow + baseline, 8*mib)["status"] == "PASS"
    assert file_envelope([(4*mib, None)], baseline, 16*mib)["status"] == "UNRESOLVED"
    assert repeat_span([(4*mib, 12*mib)], 8*mib)["status"] == "PASS"


if __name__ == "__main__":
    arithmetic_controls()
