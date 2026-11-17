#!/usr/bin/env python3
"""Revalidate frozen native evidence offline; coverage alone never means PASS."""
import argparse
import copy
import hashlib
import importlib.util
import json
import math
from pathlib import Path, PurePosixPath
import statistics
import sys

PREPARATION_READINESS = {"mode": "one_complete_valid_order", "orders": 2,
                         "minimum_valid_orders": 1, "retain_quality_rejections": True,
                         "formal_samples_from_preparation": 0}


def preparation_policy(protocol):
    policy = protocol.get("preparation_readiness")
    if policy is not None and policy != PREPARATION_READINESS:
        raise ValueError("unrecognized preparation readiness policy")
    return policy


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def record_path(root, relative):
    # Windows-generated manifests must remain verifiable on other hosts.
    path = PurePosixPath(relative.replace("\\", "/"))
    if path.is_absolute() or not path.parts or ".." in path.parts or ":" in relative:
        raise ValueError("record path escapes its evidence root")
    candidate = root.joinpath(*path.parts)
    if not candidate.resolve().is_relative_to(root.resolve()):
        raise ValueError("record link escapes its evidence root")
    return candidate


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def describe(values):
    if not values or any(not math.isfinite(v) for v in values):
        raise ValueError("finite complete observations required")
    median = statistics.median(values)
    mad = statistics.median(abs(v-median) for v in values)
    return {"count": len(values), "median": median, "mean": statistics.mean(values),
            "minimum": min(values), "maximum": max(values), "range": max(values)-min(values),
            "MAD": mad, "relative_MAD": mad/abs(median) if median else (0 if not mad else None)}


def conclude(scenarios, protocol):
    contract = protocol["resource_contract"]
    spans = {name: describe([x["controller"]["sampled_peak_rss_bytes"] for x in rows])["range"]
             for name, rows in scenarios.items()}
    stable = all(x <= contract["controller_rss_repeat_span_limit_bytes"] for x in spans.values())
    envelope = (max(x["controller"]["sampled_peak_rss_bytes"] for x in scenarios["stream-large"])
                - min(x["controller"]["sampled_peak_rss_bytes"] for x in scenarios["stream-small"]))
    within = envelope <= contract["controller_peak_large_minus_small_envelope_limit_bytes"]
    return {"stability": "PASS" if stable else "INCONCLUSIVE", "rss_repeat_spans_bytes": spans,
            "conservative_large_minus_small_bytes": envelope, "memory_limit_met": within,
            "performance": ("PASS" if within else "FAIL") if stable else "INCONCLUSIVE"}


def check_observer_activity(report, protocol):
    policy = protocol.get("observer_process_activity")
    if policy is None:
        return  # Historical protocols retain their original source and rules.
    before = report.get("observer_process_activity", {})
    if report["calibration"]["platform"].startswith("macOS"):
        after = report.get("observer_process_activity_after", {})
        for receipt in (before, after):
            if (receipt.get("scope") != "observer-process-only"
                    or receipt.get("worker_started_before_begin") is not True
                    or receipt.get("requested_options") != policy["darwin_options"]
                    or receipt.get("started") is not True
                    or receipt.get("usage_role") != "measurement"
                    or receipt.get("diagnostic_only") is not False
                    or receipt.get("idle_sleep_disabled") is not False
                    or receipt.get("display_sleep_disabled") is not False
                    or receipt.get("system_settings_changed") is not False):
                raise ValueError("Darwin observer process activity differs")
        if before.get("ended") is not False or after.get("ended") is not True or report.get("activity_cleanup_error"):
            raise ValueError("Darwin observer process activity cleanup incomplete")
    elif before.get("scope") != "not-applicable" or before.get("started") is not False:
        raise ValueError("non-Darwin observer process activity changed")


def check_attempt(folder, protocol, stage, metrics):
    report = read(folder / "preparation-result.json")
    rows = [json.loads(line) for line in (folder / "samples.jsonl").read_text().splitlines()]
    quality = metrics.summarize(report, rows, protocol["quality"])
    allowed = {"VALID"}
    if stage == "pilot" and preparation_policy(protocol) is not None:
        allowed.add("INSUFFICIENT")
    if quality != read(folder / "quality-result.json") or quality["status"] not in allowed:
        raise ValueError("accepted raw metrics differ or no longer validate")
    if report["stage"] != stage or report["formal_sample"] != (stage != "pilot"):
        raise ValueError("preparation and formal roles must not be mixed")
    if any(report["source"].get(k) != v for k, v in protocol["source_inputs"].items()):
        raise ValueError("frozen source dependency differs")
    raw_events = [json.loads(line) for line in (folder / "events.jsonl").read_text().splitlines()]
    observed = [{k: v for k, v in event.items() if k != "observed_ns"} for event in report["events"]]
    if raw_events != observed:
        raise ValueError("raw correctness journal differs from observed events")
    ready = report["events"][0]
    if ready["engine_version"].lstrip("v") != protocol["engine_version"].lstrip("v"):
        raise ValueError("fixed native version differs")
    engine_hash = ready["engine_sha256"]
    if len(engine_hash) != 64 or any(c not in "0123456789abcdef" for c in engine_hash):
        raise ValueError("native executable digest is missing")
    calibration = report["calibration"]
    if (calibration["psutil"] != "7.2.2" or not calibration["clock"]["monotonic"]
            or calibration["clock"]["adjustable"] or calibration["metric_reads"] != 1000
            or calibration["cpu_observed_span_s"] <= 0 or calibration["rss_touched_bytes"] != 16777216
            or calibration["rss_growth_bytes"] <= 0):
        raise ValueError("required actual counter calibration is incomplete")
    if "observer_policy" in protocol:
        observer = report["observer_thread_policy"]
        if observer["scope"] != "observer-thread-only":
            raise ValueError("observer policy scope differs")
        if calibration["platform"].startswith("macOS"):
            expected = protocol["observer_policy"].get("darwin_qos_class", 0x19)
            if type(expected) is not int or expected not in {0x19, 0x21}:
                raise ValueError("unrecognized Darwin observer scheduling policy")
            policy = "darwin-user-interactive" if expected == 0x21 else "darwin-user-initiated"
            if (observer.get("observed") != expected or observer.get("requested") != expected
                    or observer.get("policy") != policy
                    or observer.get("worker_started_before_assignment") is not True):
                raise ValueError("Darwin observer scheduling policy differs")
        elif observer["policy"] != "unchanged":
            raise ValueError("non-Darwin observer scheduling changed")
    check_observer_activity(report, protocol)
    source = report["source"]
    if source["profile"] != "release" or not source["rustc_version"].startswith("rustc "+protocol["rust_release"]+" "):
        raise ValueError("frozen compiler/profile differs")
    return report, quality


def check_preparation_orders(root, attempts, protocol, metrics):
    policy = preparation_policy(protocol)
    orders = protocol["formal_orders"][:2]
    if (len(orders) != 2 or orders[1] != list(reversed(orders[0]))
            or any(len(o) != len(protocol["scenarios"]) or set(o) != set(protocol["scenarios"]) for o in orders)):
        raise ValueError("two complete opposite preparation orders required")
    expected = [(c, s, name) for c, order in enumerate(orders) for s, name in enumerate(order)]
    if [(a["cycle"], a["slot"], a["scenario"]) for a in attempts] != expected:
        raise ValueError("opposite-order native preparation incomplete or changed")
    reports, identities, binaries, sources, statuses = [], [], set(), [], {}
    counts = {"VALID": 0, "INSUFFICIENT": 0}
    for attempt, (cycle, slot, scenario) in zip(attempts, expected):
        report, quality = check_attempt(root / f"cycle-{cycle}-slot-{slot}-{scenario}", protocol, "pilot", metrics)
        if (report["scenario"] != scenario or report["repeats"] != protocol["scenarios"][scenario]["repeats"]
                or attempt["exit_code"] != (0 if quality["status"] == "VALID" else 2)):
            raise ValueError("preparation workload or exit classification differs")
        reports.append(report); sources.append(report["source"])
        identities.extend((v["pid"], v["creation_time"]) for v in report["identities"])
        binaries.add((bytes(report["events"][0]["controller_sha256"]).hex(), report["events"][0]["engine_sha256"]))
        statuses[(cycle, slot)] = quality["status"]; counts[quality["status"]] += 1
    if len(set(identities)) != len(identities) or len(binaries) != 1 or any(s != sources[0] for s in sources):
        raise ValueError("preparation reused processes or changed artifacts/source")
    valid = [c for c, order in enumerate(orders) if all(statuses[(c, s)] == "VALID" for s in range(len(order)))]
    summary = {"ready": len(valid) >= (1 if policy else 2), "complete_native_cases": len(reports),
               "complete_valid_orders": valid, "quality_counts": counts}
    return reports, summary


def find_collection(root, fingerprint):
    candidates = [p.parent for p in root.rglob("collection-state.json")
                  if read(p).get("stage") == "all" and read(p).get("protocol_sha256") == fingerprint]
    if len(candidates) != 1:
        raise ValueError("one exact all-stage collection required")
    return candidates[0]


def profile_report(label, root, protocol, fingerprint, collector, metrics, preparation=None):
    directory = find_collection(root, fingerprint)
    whole = read(directory / "collection-state.json")
    if whole["status"] != "COMPLETE":
        return {"profile": label, "coverage": "INCOMPLETE", "performance": "INCONCLUSIVE"}
    identities, artifacts, engine_hashes, sources, observations = [], set(), set(), [], []
    accepted, attempts = {}, []
    for stage in ["formal", "independent"]:
        phase = directory / stage
        state = read(phase / "collection-state.json")
        expected = protocol[stage+"_orders"]
        if (state["status"] != "COMPLETE" or state["protocol_sha256"] != fingerprint
                or set(state["accepted"]) != {str(i) for i in range(len(expected))}):
            raise ValueError("required original-order cycles are incomplete")
        accepted[stage] = len(expected)
        for i, order in enumerate(expected):
            entry = state["accepted"][str(i)]
            path = record_path(phase, entry["manifest"])
            if digest(path) != entry["sha256"]:
                raise ValueError("immutable group manifest changed")
            manifest = read(path)
            if (manifest["cycle"] != i or manifest["order"] != order
                    or manifest["end_unix"]-manifest["start_unix"] > protocol["maximum_group_span_s"]):
                raise ValueError("frozen group order/span differs")
            normalized = copy.deepcopy(manifest)
            for slot in normalized["slots"]:
                slot["directory"] = record_path(phase, slot["directory"]).relative_to(phase).as_posix()
            fresh, binaries = collector.verify_group(normalized, phase, fingerprint, stage, metrics)
            identities.extend(fresh); artifacts.update(binaries)
            for slot in manifest["slots"]:
                report, quality = check_attempt(record_path(phase, slot["directory"]), protocol, stage, metrics)
                if slot["quality"] != quality or slot["exit_code"] != 0:
                    raise ValueError("saved accepted outcome differs")
                sources.append(report["source"]); engine_hashes.add(report["events"][0]["engine_sha256"])
                observations.append({"stage": stage, "cycle": i, "scenario": slot["scenario"],
                                     "raw": slot["directory"], "raw_sha256": slot["sha256"], **quality})
        attempts.extend({"stage": stage, "path": str(p.relative_to(phase)), **read(p)}
                        for p in sorted(phase.glob("cycle-*-attempt-*/attempt.json")))
    if len(set(identities)) != len(identities) or len(artifacts) != 1 or len(engine_hashes) != 1:
        raise ValueError("fresh processes or executable consistency differs")
    if any(source != sources[0] for source in sources):
        raise ValueError("compiler, source or build environment changed within this profile")
    prep_root = preparation or root
    pretrials = list(prep_root.rglob("pretrial-result.json"))
    prepared = False
    prep_summary = None
    if len(pretrials) > 1:
        raise ValueError("ambiguous preparation evidence")
    if len(pretrials) == 1:
        p = pretrials[0]; trial = read(p)
        states = {"PREPARATION_COMPLETE"}
        if preparation_policy(protocol):
            states.add("PREPARATION_INSUFFICIENT")
        if trial.get("status") not in states or trial["protocol_sha256"] != fingerprint:
            raise ValueError("opposite-order native preparation incomplete or changed")
        reports, prep_summary = check_preparation_orders(p.parent, trial["attempts"], protocol, metrics)
        if (trial["status"] == "PREPARATION_COMPLETE") != prep_summary["ready"] or trial.get("readiness", prep_summary) != prep_summary:
            raise ValueError("preparation readiness differs from its complete raw orders")
        for report in reports:
            identities.extend((v["pid"], v["creation_time"]) for v in report["identities"])
            if (bytes(report["events"][0]["controller_sha256"]).hex() not in artifacts
                    or report["events"][0]["engine_sha256"] not in engine_hashes):
                raise ValueError("preparation executed different binaries")
        if len(set(identities)) != len(identities):
            raise ValueError("preparation reused an accepted process")
        prepared = prep_summary["ready"]
    scenarios = {name: [x for x in observations if x["scenario"] == name] for name in protocol["scenarios"]}
    if any(len(rows) != 6 for rows in scenarios.values()):
        raise ValueError("four formal and two independent observations per scenario required")
    conclusion = conclude(scenarios, protocol)
    summaries = {}
    for name, rows in scenarios.items():
        summaries[name] = {"registered_repeats_per_process": rows[0]["n"],
            "latency_ns_per_registered_repeat": describe([x["normalized_ns"] for x in rows]),
            "formal_ns_per_repeat": describe([x["normalized_ns"] for x in rows if x["stage"] == "formal"]),
            "independent_ns_per_repeat": describe([x["normalized_ns"] for x in rows if x["stage"] == "independent"]),
            "weighted_ns_per_repeat": sum(x["elapsed_ns"] for x in rows)/sum(x["n"] for x in rows),
            **{role: {metric: describe([x[role][metric] for x in rows]) for metric in
                       ["sampled_peak_rss_bytes", "sampled_rss_increment_bytes", "cpu_user_s", "cpu_system_s"]}
               for role in ["controller", "engine"]}}
        for role in ["controller", "engine"]:
            summaries[name][role]["cpu_ns_per_registered_repeat"] = describe([
                (x[role]["cpu_user_s"]+x[role]["cpu_system_s"])*1e9/x["n"] for x in rows])
        summaries[name]["latency_stability"] = ("PASS" if
            summaries[name]["latency_ns_per_registered_repeat"]["relative_MAD"] <= protocol["latency"]["relative_MAD_stability_screen"]
            else "INCONCLUSIVE")
    denominator = [slot for attempt in attempts for slot in attempt["slots"]]
    return {"profile": label, "coverage": "COMPLETE", "quality": "VALID", "accepted_cycles": accepted,
            "accepted_native_cases": len(observations), "fresh_formal_and_independent_processes": len(observations)*2,
            "preparation": "COMPLETE" if prepared else "INCOMPLETE", "preparation_readiness": prep_summary, "source": sources[0],
            "controller_artifact_sha256": sorted(artifacts), "engine_sha256": sorted(engine_hashes),
            "attempted_cases": len(denominator), "attempt_quality_counts":
                {s: sum(x["quality"]["status"] == s for x in denominator) for s in ["VALID", "INSUFFICIENT", "ERROR"]},
            "retained_attempts": [{"stage": a["stage"], "path": a["path"], "status": a.get("status", "INTERRUPTED"),
                                   "executed_cases": len(a["slots"])} for a in attempts],
            "scenarios": summaries, "observations": observations,
            **conclusion, "performance": conclusion["performance"] if prepared else "INCONCLUSIVE"}


def markdown(report):
    lines = ["# Native resource report", "", f"Protocol SHA-256: `{report['protocol_sha256']}`.", "",
             f"Overall resource conclusion: **{report['performance']}**.", "",
             "RSS is sampled resident memory of the controller and the engine root, not instantaneous high-water",
             "memory or the entire engine descendant tree. CPU is cumulative process time, not a single-thread",
             "off-CPU proxy. Latency is descriptive, with no baseline speedup or latency pass target.", "",
             "| Profile | Coverage | Preparation | RSS stability | Memory envelope (bytes) | Conclusion |",
             "| --- | --- | --- | --- | ---: | --- |"]
    for p in report["profiles"]:
        preparation = p.get("preparation", "MISSING")
        if p.get("preparation_readiness"):
            counts = p["preparation_readiness"]["quality_counts"]
            preparation += f" ({counts['VALID']} valid / {counts['INSUFFICIENT']} insufficient)"
        lines.append(f"| {p['profile']} | {p['coverage']} | {preparation} | "
                     f"{p.get('stability', 'UNRESOLVED')} | {p.get('conservative_large_minus_small_bytes', '')} | {p['performance']} |")
    for p in report["profiles"]:
        lines += ["", "## "+p["profile"], ""]
        if p.get("errors"):
            lines += ["Evidence validation error: "+"; ".join(p["errors"]), ""]
            continue
        if "scenarios" not in p:
            lines += ["Original collection is incomplete.", ""]
            continue
        lines += [f"Source `{p['source']['source_commit']}`; compiler `{p['source']['rustc_version']}`; release profile.", "",
                  f"Accepted {p['accepted_native_cases']} cases / {p['fresh_formal_and_independent_processes']} fresh processes; "
                  f"attempted {p['attempted_cases']} cases, quality counts `{p['attempt_quality_counts']}`.", "",
                  "| Scenario | n | Latency median (ms/repeat) | Relative MAD | Controller RSS min..max (MiB) | Engine-root RSS min..max (MiB) | Controller CPU median (ms/repeat) | Engine-root CPU median (ms/repeat) |",
                  "| --- | ---: | ---: | ---: | --- | --- | ---: | ---: |"]
        for scenario, values in p["scenarios"].items():
            def rss(role):
                v = values[role]["sampled_peak_rss_bytes"]
                return f"{v['minimum']/1048576:.3f}..{v['maximum']/1048576:.3f}"
            latency = values["latency_ns_per_registered_repeat"]
            lines.append(f"| {scenario} | {values['registered_repeats_per_process']} | {latency['median']/1e6:.3f} | "
                         f"{latency['relative_MAD']:.4f} | {rss('controller')} | {rss('engine')} | "
                         f"{values['controller']['cpu_ns_per_registered_repeat']['median']/1e6:.3f} | "
                         f"{values['engine']['cpu_ns_per_registered_repeat']['median']/1e6:.3f} |")
    lines += ["", "All six registered profiles, complete raw quality, separate fresh-process independent cycles,",
              "preparation and frozen RSS repeatability are required. Missing or unstable evidence remains",
              "INCONCLUSIVE. No stability exception has been applied. Full observations, source/artifact hashes,",
              "raw-record hashes, attempt denominators and statistics are in resource-report.json.", "",
              "Per-repeat latency uses one registered repeat: many-small includes all 256 files in that repeat.",
              "The 20% relative-MAD latency screen is descriptive; the resource acceptance stability condition",
              "is the frozen 8 MiB controller RSS repeat span. No confidence interval is claimed.", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--profile", action="append", required=True, help="registered-profile=evidence-root")
    parser.add_argument("--preparation", action="append", default=[], help="profile=separate-pretrial-root")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    protocol, fingerprint = read(args.protocol), digest(args.protocol)
    collector, metrics = module("resource_collector", "collect-native-resources.py"), module("resource_metrics", "measure-native-resources.py")
    if (digest(Path(collector.__file__)) != protocol["collector_sha256"]
            or digest(Path(metrics.__file__)) != protocol["source_inputs"]["sampler_sha256"]
            or ("reporter_sha256" in protocol and digest(__file__) != protocol["reporter_sha256"])):
        raise ValueError("use the exact frozen offline validation helpers")
    def inputs(values):
        result = {}
        for value in values:
            name, path = value.split("=", 1)
            if name not in protocol["profiles"] or name in result:
                raise ValueError("unique registered profile labels required")
            result[name] = Path(path)
        return result
    profiles, preparation = inputs(args.profile), inputs(args.preparation)
    results = []
    for name, root in profiles.items():
        try:
            results.append(profile_report(name, root, protocol, fingerprint, collector, metrics, preparation.get(name)))
        except (ValueError, KeyError, TypeError, OSError) as error:
            results.append({"profile": name, "coverage": "ERROR", "quality": "ERROR",
                            "performance": "ERROR", "errors": [str(error)]})
    missing = sorted(set(protocol["profiles"])-set(profiles))
    statuses = [p["performance"] for p in results]
    overall = ("ERROR" if "ERROR" in statuses else ("FAIL" if "FAIL" in statuses else
               ("INCONCLUSIVE" if missing or "INCONCLUSIVE" in statuses else "PASS")))
    report = {"protocol_sha256": fingerprint, "protocol_id": protocol["protocol_id"],
              "performance": overall, "missing_profiles": missing, "profiles": results,
              "coverage": "COMPLETE" if not missing and all(p["coverage"] == "COMPLETE" for p in results) else "INCOMPLETE",
              "quality": "ERROR" if "ERROR" in statuses else ("VALID" if all(p.get("quality") == "VALID" for p in results) else "UNRESOLVED"),
              "stability": "PASS" if not missing and all(p.get("stability") == "PASS" for p in results) else "INCONCLUSIVE",
              "reporter_sha256": digest(__file__), "frozen_criteria": protocol["resource_contract"]}
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "resource-report.json").write_text(json.dumps(report, indent=2, allow_nan=False)+"\n")
    (args.output / "resource-report.md").write_text(markdown(report))
    print(json.dumps({"performance": overall, "profiles": len(results), "missing_profiles": missing}))
    return 0 if overall == "PASS" else (2 if overall == "INCONCLUSIVE" else 1)


if __name__ == "__main__":
    sys.exit(main())
