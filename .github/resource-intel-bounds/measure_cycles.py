"""Serial Intel qualification, bounded collection, and immutable complete groups."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from observe import reproduce_bounds
from rss_limits import summarize_limits, arithmetic_controls

REQUIRED_FILES = (
    "preparation-result.json", "events.jsonl", "samples.jsonl",
    "quality-result.json", "peak-boundaries.json", "rss-bounds.json", "console.log",
)


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def load(path):
    return json.loads(path.read_text())


def save(path, record):
    pending = path.with_name(path.name + ".writing")
    with pending.open("x") as output:
        json.dump(record, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    pending.replace(path)


def qualify(original, case, v33, identity):
    source, tree, protocol, engine = identity
    quality = case["v33_quality"]
    expected = v33["scenarios"][case["scenario"]]
    fields = original["source"]
    if (fields["source_commit"], fields["source_tree"]) != (source, tree):
        raise RuntimeError("actual source differs from the fixed release")
    if not all(fields.get(key) == value for key, value in v33["source_inputs"].items()):
        raise RuntimeError("a frozen measurement or compilation input differs")
    if original.get("protocol_sha256", protocol if original.get("stage") == "pilot" else None) != protocol:
        raise RuntimeError("actual resource protocol differs")
    if original["events"][0]["engine_sha256"] != engine:
        raise RuntimeError("actual engine image differs")
    if original["interval_ms"] != 10 or case["repeats"] != expected["repeats"]:
        raise RuntimeError("actual sampling period or workload differs")
    if quality["status"] not in ("VALID", "INSUFFICIENT") or quality["errors"] or not all(
        case["native_outcome"].get(key) is True for key in (
            "all_actual_bytes_verified", "normal_owned_tree_exit", "source_config_identity_unchanged")
    ):
        raise RuntimeError("frozen native correctness or process cleanup failed")
    if case["roles"].keys() != {"controller", "engine"}:
        raise RuntimeError("both observed process roles are required")
    eligible = {role: row["confirmed_in_window_samples"] for role, row in case["roles"].items()}
    reads = sum(row["boundary_read_duration_ns"] for row in case["roles"].values())
    elapsed = case["registered_elapsed_ns"]
    existing_issues = quality["insufficient"]
    remaining = [message for message in existing_issues if message != "sampling gap exceeded coverage limit"]
    if min(eligible.values()) < v33["quality"]["minimum_measured_snapshots"]:
        remaining.append("fewer than the frozen minimum of definitely in-window RSS reads")
    if any(row["lower_rss_bytes"] is None or row["upper_rss_bytes"] is None
           or row["prior_lifetime_rss_bytes"] is None for row in case["roles"].values()):
        remaining.append("missing same-process lifecycle RSS bounds")
    combined_metric_read_fraction = quality["metric_read_fraction"] + reads / elapsed
    if combined_metric_read_fraction > v33["quality"]["maximum_metric_read_fraction"]:
        remaining.append("combined observed metric-read cost exceeds the frozen limit")
    coverage = case["peak_read_overspan_ns"] / elapsed
    if not 0 <= coverage <= v33["quality"]["maximum_boundary_overspan_fraction"]:
        remaining.append("boundary witness exceeds the frozen overspan limit")
    return {
        "status": "INSUFFICIENT" if remaining else "VALID_BOUNDED_RSS",
        "original_v33_result": quality["status"],
        "original_gap_limit_exceeded": quality["max_sample_gap_ns"] > v33["quality"]["maximum_sample_gap_ns"],
        "boundary_witness_overspan": coverage, "combined_metric_read_fraction": combined_metric_read_fraction,
        "confirmed_in_window_reads": eligible, "remaining_issues": remaining,
    }


def read_case(folder, v33, stage, identity, metrics):
    case = reproduce_bounds(folder)
    if case != load(folder / "rss-bounds.json"):
        raise RuntimeError("replaying raw boundaries differs from the observation")
    original = load(folder / "preparation-result.json")
    if original["stage"] != stage or original["formal_sample"] != (stage != "pilot"):
        raise RuntimeError("attempt stage or formal sample identity differs")
    raw_points = [json.loads(line) for line in (folder / "samples.jsonl").read_text().splitlines()]
    recalculated = metrics.summarize(original, raw_points, v33["quality"])
    if recalculated != case["v33_quality"]:
        raise RuntimeError("the original periodic sampling verdict differs from raw observations")
    metrics.check_metric_reader(original, v33)
    quality = qualify(original, case, v33, identity)
    return {
        "case": case,
        "quality": quality,
        "files_sha256": {filename: digest(folder / filename) for filename in REQUIRED_FILES},
        "controller_sha256": bytes(original["events"][0]["controller_sha256"]).hex(),
        "frozen_native_reader_sha256": original["source"]["darwin_reader_library_sha256"],
        "nonce": original["events"][0]["nonce"],
    }


def capture_case(args, folder, stage, scenario, v33):
    info = v33["scenarios"][scenario]
    command = [sys.executable, "-B", str(Path(__file__).with_name("observe.py")),
               "--source", str(args.source), "--peak-library", str(args.peak_library),
               "--evidence-dir", str(folder), "--scenario", scenario, "--repeats", str(info["repeats"]),
               "--cargo", str(args.cargo), "--toolchain", args.toolchain, "--stage", stage]
    console_path = folder.with_suffix(".console.log")
    with console_path.open("xb") as stream:
        status = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT).returncode
    if status:
        raise RuntimeError(f"actual {stage} acquisition error {status} for {folder.name}")
    result = read_case(folder, v33, stage, args.identity, args.metrics)
    print(json.dumps({"stage": stage, "case": folder.name, "quality": result["quality"],
                      "bounds": {role: (v["lower_rss_bytes"], v["upper_rss_bytes"])
                                 for role, v in result["case"]["roles"].items()}}), flush=True)
    return result


def ensure_identity(cases):
    processes = {(role["identity"]["pid"], role["identity"]["birth_us"])
                 for case in cases for role in case["case"]["roles"].values()}
    if len(processes) != 2 * len(cases) or len({case["nonce"] for case in cases}) != len(cases):
        raise RuntimeError("a controller, engine or random run identity was reused")
    for key in ("controller_sha256", "frozen_native_reader_sha256"):
        if len({case[key] for case in cases}) != 1:
            raise RuntimeError("an actual loaded artifact changed during the work")


def check_preparation(root, protocol, args):
    prep = root / "preparation"
    groups = []
    for cycle, order in enumerate(protocol["formal_orders"][:2]):
        folder = prep / f"order-{cycle}"
        group = [
            read_case(folder / f"slot-{slot}-{scenario}", protocol, "pilot",
                      args.identity, args.metrics)
            for slot, scenario in enumerate(order)
        ]
        if group != load(folder / "group.json"):
            raise RuntimeError("preparation group differs from raw data")
        groups.append(group)
    cases = [case for group in groups for case in group]
    ensure_identity(cases)
    readiness = {
        "ready": any(all(case["quality"]["status"] == "VALID_BOUNDED_RSS" for case in group)
                     for group in groups),
        "complete_orders": len(groups),
        "fresh_native_cases": len(cases),
        "preview_limits": summarize_limits([row["case"] for row in cases], protocol),
    }
    return readiness, cases


def prepare(args, protocol):
    root = args.evidence
    root.mkdir(mode=0o700)
    (root / "intel-contract.json").write_bytes(args.contract.read_bytes())
    (root / "frozen-protocol.json").write_bytes(args.protocol.read_bytes())
    prep = root / "preparation"
    prep.mkdir(mode=0o700)
    for cycle, order in enumerate(protocol["formal_orders"][:2]):
        folder = prep / f"order-{cycle}"
        folder.mkdir(mode=0o700)
        group = [
            capture_case(args, folder / f"slot-{slot}-{scenario}", "pilot", scenario, protocol)
            for slot, scenario in enumerate(order)
        ]
        save(folder / "group.json", group)
    readiness, _ = check_preparation(root, protocol, args)
    save(prep / "readiness.json", readiness)
    print(json.dumps(readiness), flush=True)
    return 0 if readiness["ready"] else 2


def collect(args, v33, prep_cases):
    root = args.evidence
    begun = time.monotonic()
    deadline = begun + v33["acquisition_window_s"]
    state = {"contract_sha256": digest(args.contract), "protocol_sha256": args.identity[2],
             "run_id": args.run_id, "run_attempt": args.run_attempt,
             "source": args.identity[0], "tree": args.identity[1], "engine_sha256": args.identity[3],
             "started_unix": time.time(), "window_seconds": v33["acquisition_window_s"],
             "accepted": {"formal": [], "independent": []}, "attempts": [], "status": "INCOMPLETE"}
    save(root / "collection-state.json", state)
    accepted = []
    observed = []
    try:
        for stage in ("formal", "independent"):
            for cycle, order in enumerate(v33[f"{stage}_orders"]):
                for attempt in range(1, v33["maximum_group_attempts"] + 1):
                    if time.monotonic() + v33["estimated_complete_group_s"] + v33["save_reserve_s"] > deadline:
                        return 2
                    relative = Path(stage) / f"cycle-{cycle}-attempt-{attempt}"
                    folder = root / relative
                    folder.mkdir(parents=True, mode=0o700)
                    entry = {"stage": stage, "cycle": cycle, "attempt": attempt,
                             "folder": relative.as_posix(), "order": order,
                             "started_ns_from_window": int((time.monotonic()-begun)*1e9)}
                    state["attempts"].append(entry)
                    save(root / "collection-state.json", state)
                    measurements = [
                        capture_case(args, folder / f"slot-{slot}-{scenario}", stage, scenario, v33)
                        for slot, scenario in enumerate(order)
                    ]
                    finish = time.monotonic()
                    entry["ended_ns_from_window"] = int((finish-begun)*1e9)
                    within = (entry["ended_ns_from_window"] - entry["started_ns_from_window"]
                              <= v33["maximum_group_span_s"] * 10**9 and finish <= deadline)
                    group_ok = within and all(m["quality"]["status"] == "VALID_BOUNDED_RSS" for m in measurements)
                    manifest = folder / "accepted-group.json" if group_ok else folder / "rejected-group.json"
                    save(manifest, {"attempt": entry, "cases": measurements, "complete_group": group_ok})
                    entry["manifest_sha256"] = digest(manifest)
                    ensure_identity(prep_cases + observed + measurements)
                    observed.extend(measurements)
                    if group_ok:
                        accepted.extend(measurements)
                        state["accepted"][stage].append(manifest.relative_to(root).as_posix())
                    save(root / "collection-state.json", state)
                    if group_ok:
                        break
                else:
                    return 2

        limits = summarize_limits([row["case"] for row in accepted], v33)
        if not limits["six_cycle_minimum_not_a_pilot_result"]:
            raise RuntimeError("formal or independent original-order coverage is incomplete")
        state["status"] = "COMPLETE"
        state["limits"] = limits
        stable = all(row["status"] == "PASS" for row in limits["repetition_stability"].values())
        state["conservative_stability"] = "PASS" if stable else "INCONCLUSIVE"
        envelope = limits["large_minus_small_envelope"]["status"]
        state["conservative_resource_verdict"] = (
            {"PASS": "PASS", "ABOVE_LIMIT": "FAIL"}.get(envelope, "INCONCLUSIVE")
            if stable else "INCONCLUSIVE"
        )
        print(json.dumps({"intel_formal": state}, separators=(",", ":")), flush=True)
        return 0 if state["conservative_resource_verdict"] == "PASS" else 2
    except Exception:
        state["status"] = "ERROR"
        raise
    finally:
        state["ended_unix"] = time.time()
        save(root / "collection-state.json", state)


def verify_collection(args, protocol, prep_cases):
    root = args.evidence
    state = load(root / "collection-state.json")
    source, tree, protocol_hash, engine = args.identity
    if (state["source"], state["tree"], state["protocol_sha256"], state["engine_sha256"]) != args.identity:
        raise RuntimeError("collection source identity differs")
    if (state["run_id"], state["run_attempt"], state["contract_sha256"]) != (
            args.run_id, args.run_attempt, digest(args.contract)):
        raise RuntimeError("collection run, attempt or contract differs")
    if state["status"] != "COMPLETE" or state["conservative_resource_verdict"] != "PASS":
        raise RuntimeError("the collector did not pass the complete resource gate")
    if state["window_seconds"] != protocol["acquisition_window_s"]:
        raise RuntimeError("collection window differs")

    accepted, all_attempts = [], []
    accepted_paths = {"formal": [], "independent": []}
    expected_cycles = [
        (phase, cycle) for phase in ("formal", "independent")
        for cycle in range(len(protocol[phase + "_orders"]))
    ]
    completed = []
    attempt_number = 0
    previous_end = 0
    for entry in state["attempts"]:
        phase, cycle = entry["stage"], entry["cycle"]
        if len(completed) >= len(expected_cycles) or (phase, cycle) != expected_cycles[len(completed)]:
            raise RuntimeError("collection did not retain the original formal and independent cycle order")
        attempt_number += 1
        if entry["attempt"] != attempt_number or attempt_number > protocol["maximum_group_attempts"]:
            raise RuntimeError("collection did not retain the original attempt limits")
        order = protocol[phase + "_orders"][cycle]
        location = Path(phase) / f"cycle-{cycle}-attempt-{attempt_number}"
        if entry["order"] != order or entry["folder"] != location.as_posix():
            raise RuntimeError("cycle paths or workload order differ")
        start, end = entry["started_ns_from_window"], entry["ended_ns_from_window"]
        reserve = protocol["estimated_complete_group_s"] + protocol["save_reserve_s"]
        if not previous_end <= start < end or start > (state["window_seconds"] - reserve) * 10**9:
            raise RuntimeError("cycle start or end offsets differ from the registered window")
        previous_end = end
        rows = [
            read_case(root / location / f"slot-{slot}-{scenario}", protocol, phase, args.identity, args.metrics)
            for slot, scenario in enumerate(order)
        ]
        all_attempts.extend(rows)
        accepted_group = end <= state["window_seconds"] * 10**9 and end-start <= protocol["maximum_group_span_s"] * 10**9
        accepted_group = accepted_group and all(row["quality"]["status"] == "VALID_BOUNDED_RSS" for row in rows)
        manifest = location / ("accepted-group.json" if accepted_group else "rejected-group.json")
        expected = {"attempt": {k: v for k, v in entry.items() if k != "manifest_sha256"},
                    "cases": rows, "complete_group": accepted_group}
        if digest(root / manifest) != entry["manifest_sha256"] or load(root / manifest) != expected:
            raise RuntimeError("stored group differs from raw data")
        if accepted_group:
            accepted.extend(rows)
            accepted_paths[phase].append(manifest.as_posix())
            completed.append((phase, cycle))
            attempt_number = 0
    if completed != expected_cycles or state["accepted"] != accepted_paths:
        raise RuntimeError("complete cycle evidence is missing or incorrectly linked")
    ensure_identity(prep_cases + all_attempts)
    limits = summarize_limits([row["case"] for row in accepted], protocol)
    if (limits != state["limits"] or not limits["six_cycle_minimum_not_a_pilot_result"]
            or limits["large_minus_small_envelope"]["status"] != "PASS"
            or any(row["status"] != "PASS" for row in limits["repetition_stability"].values())):
        raise RuntimeError("the conservative memory limits are not independently proven")
    report = {
        "performance": "PASS", "profile": "macos-amd64-standard",
        "source": source, "tree": tree, "protocol_sha256": protocol_hash, "engine_sha256": engine,
        "contract_sha256": state["contract_sha256"],
        "run_id": args.run_id, "run_attempt": args.run_attempt,
        "accepted_cycles": {phase: len(paths) for phase, paths in accepted_paths.items()},
        "accepted_native_cases": len(accepted),
        "fresh_formal_and_independent_processes": 2 * len(accepted),
        "maximum_original_gap_ns": max(row["case"]["v33_quality"]["max_sample_gap_ns"] for row in accepted),
        "original_quality_rejected_cases": sum(row["quality"]["original_gap_limit_exceeded"] for row in accepted),
        "limits": limits,
    }
    save(args.report, report)
    print(json.dumps(report), flush=True)
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for flag in ("source", "evidence", "contract"):
        p.add_argument("--" + flag, type=Path, required=True)
    p.add_argument("--stage", choices=("prepare", "collect", "verify"), required=True)
    p.add_argument("--expected-source", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--run-attempt", type=int, required=True)
    p.add_argument("--peak-library", type=Path)
    p.add_argument("--cargo", type=Path)
    p.add_argument("--toolchain")
    p.add_argument("--report", type=Path)
    args = p.parse_args()
    if args.stage in ("prepare", "collect") and (
            args.run_attempt != 1 or not all((args.peak_library, args.cargo, args.toolchain))):
        p.error("live collection needs the initial run attempt, compiled helper and fixed Cargo/toolchain")
    if args.stage == "verify" and (not args.report or args.report.exists()):
        p.error("verification requires a fresh output file")

    def git(*command):
        return subprocess.check_output(["git", "-C", str(args.source), *command], text=True).strip()

    source, tree = git("rev-parse", "HEAD", "HEAD^{tree}").splitlines()
    if source != args.expected_source or git("status", "--porcelain"):
        raise RuntimeError("clean candidate identity differs")
    args.protocol = args.source / "tests/fixtures/resource-protocol.json"
    protocol_digest = digest(args.protocol)
    contract = load(args.contract)
    if contract["resource_protocol_sha256"] != protocol_digest:
        raise RuntimeError("the frozen periodic resource protocol differs")
    if any(digest(args.contract.parent / name) != expected
           for name, expected in contract["observer_inputs"].items()):
        raise RuntimeError("the frozen observer inputs differ")
    catalog = load(args.source / "releases/verysync-v2.33.2-standard-binaries.json")
    image, = (row for row in catalog["packages"] if row["id"] == "macos-amd64-standard")
    engine = image["binary_sha256"]
    if engine != contract["engine_sha256"]:
        raise RuntimeError("the frozen Intel executable differs")
    metrics_file = args.source / "scripts/measure-native-resources.py"
    sys.path.insert(0, str(metrics_file.parent))
    spec = importlib.util.spec_from_file_location("periodic_resource_metrics", metrics_file)
    args.metrics = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(args.metrics)
    args.identity = (source, tree, protocol_digest, engine)
    arithmetic_controls()
    protocol = load(args.protocol)
    if args.stage == "prepare":
        return prepare(args, protocol)

    root = args.evidence
    if (digest(root / "intel-contract.json") != digest(args.contract)
            or digest(root / "frozen-protocol.json") != protocol_digest):
        raise RuntimeError("saved contract or resource protocol differs")
    readiness, prep = check_preparation(root, protocol, args)
    if not readiness["ready"] or readiness != load(root / "preparation/readiness.json"):
        raise RuntimeError("required preparation orders did not qualify")
    if args.stage == "collect":
        return collect(args, protocol, prep)
    return verify_collection(args, protocol, prep)


if __name__ == "__main__":
    sys.exit(main())
