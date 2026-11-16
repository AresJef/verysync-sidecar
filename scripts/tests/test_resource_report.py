"""Synthetic offline contracts are not native runtime evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from test_resource_measurement_quality import fixture

SPEC = importlib.util.spec_from_file_location("resource_report", Path(__file__).resolve().parents[1] / "report-native-resources.py")
REPORT = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(REPORT)
COLLECT = REPORT.module("report_test_collector", "collect-native-resources.py")
METRICS = REPORT.module("report_test_metrics", "measure-native-resources.py")
PROTOCOL = Path(__file__).resolve().parents[2] / "tests/fixtures/resource-protocol.json"


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2)+"\n")


def dataset(root, *, windows_paths=False, changed_source=False, reused_process=False):
    protocol = REPORT.read(PROTOCOL)
    fingerprint = REPORT.digest(PROTOCOL)
    source = {**protocol["source_inputs"], "profile": "release", "rustc_version": "rustc 1.85.0 (synthetic)",
              "source_commit": "SYNTHETIC-TEST-ONLY", "source_tree": "SYNTHETIC-TEST-ONLY"}
    next_case = 0

    def attempt(folder, stage, scenario, *, changed=False, reused=False):
        nonlocal next_case
        report, rows = fixture()
        case = 0 if reused else next_case
        next_case += 1
        report.update(stage=stage, formal_sample=stage != "pilot", scenario=scenario,
                      repeats=protocol["scenarios"][scenario]["repeats"], source=copy.deepcopy(source),
                      protocol_sha256=fingerprint,
                      calibration={"psutil": "7.2.2", "clock": {"monotonic": True, "adjustable": False},
                                   "metric_reads": 1000, "cpu_observed_span_s": .1,
                                   "rss_touched_bytes": 16777216, "rss_growth_bytes": 16777216})
        if changed:
            report["source"]["sampler_sha256"] = "wrong"
        report["identities"] = copy.deepcopy(report["before"])
        for points in [report["identities"], report["before"], report["after"]] + [[r["controller"], r["engine"]] for r in rows]:
            for index, point in enumerate(points):
                point.update(pid=100+case*2+index, creation_time=100+case)
        config = protocol["scenarios"][scenario]
        report["events"][0].update(scenario=scenario, repeats=config["repeats"], bytes_each=config["bytes_each"], files=config["files"],
                                   controller_sha256=[1]*32, engine_sha256="a"*64, engine_version="v2.33.2")
        calls = 0 if scenario == "idle" else config["files"]*config["repeats"]
        report["events"][2].update(completed_calls=calls, transferred_bytes=calls*config["bytes_each"])
        quality = METRICS.summarize(report, rows)
        save(folder / "preparation-result.json", report); save(folder / "quality-result.json", quality)
        for filename, values in [("samples.jsonl", rows), ("events.jsonl", report["events"])]:
            (folder / filename).write_text("".join(json.dumps(v)+"\n" for v in values))
        return quality, {p.name: REPORT.digest(p) for p in folder.iterdir()}

    for stage in ["formal", "independent"]:
        directory = root / stage; save(directory / "frozen-protocol.json", protocol)
        state = {"status": "COMPLETE", "protocol_sha256": fingerprint, "accepted": {}}
        for cycle, order in enumerate(protocol[stage+"_orders"]):
            group = {"cycle": cycle, "attempt": 1, "order": order, "slots": [], "status": "VALID", "start_unix": 0, "end_unix": 120}
            for slot, scenario in enumerate(order):
                path = directory / f"cycle-{cycle}-attempt-1/slot-{slot}-{scenario}"
                last = stage == "independent" and cycle == 1 and slot == 3
                quality, hashes = attempt(path, stage, scenario, changed=changed_source and last, reused=reused_process and last)
                relative = path.relative_to(directory).as_posix()
                group["slots"].append({"scenario": scenario, "directory": relative.replace("/", "\\") if windows_paths else relative,
                                       "exit_code": 0, "quality": quality, "sha256": hashes})
            target = directory / f"cycle-{cycle}-attempt-1/accepted-group.json"
            save(target, group); save(target.with_name("attempt.json"), group)
            relative = target.relative_to(directory).as_posix()
            state["accepted"][str(cycle)] = {"manifest": relative.replace("/", "\\") if windows_paths else relative, "sha256": REPORT.digest(target)}
        save(directory / "collection-state.json", state)
    save(root / "collection-state.json", {"stage": "all", "status": "COMPLETE", "protocol_sha256": fingerprint})
    preparation = root / "preparation"
    trials = []
    for cycle, order in enumerate(protocol["formal_orders"][:2]):
        for slot, scenario in enumerate(order):
            attempt(preparation / f"cycle-{cycle}-slot-{slot}-{scenario}", "pilot", scenario)
            trials.append({"cycle": cycle, "slot": slot, "scenario": scenario, "exit_code": 0})
    save(preparation / "pretrial-result.json", {"status": "PREPARATION_COMPLETE", "protocol_sha256": fingerprint, "attempts": trials})
    return protocol, fingerprint


class ResourceReportContracts(unittest.TestCase):
    def report(self, root, protocol, fingerprint):
        return REPORT.profile_report("macos-arm64-standard", root, protocol, fingerprint, COLLECT, METRICS)

    def test_all_registered_cycles_and_windows_manifest_paths_validate_offline(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); protocol, fingerprint = dataset(root, windows_paths=True)
            result = self.report(root, protocol, fingerprint)
            self.assertEqual(result["performance"], "PASS")
            self.assertEqual(result["accepted_native_cases"], 24)
            self.assertEqual(result["fresh_formal_and_independent_processes"], 48)
            self.assertEqual(result["attempted_cases"], 24)

    def test_changed_raw_bytes_are_never_accepted(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); protocol, fingerprint = dataset(root)
            path = next((root / "formal").rglob("samples.jsonl")); path.write_text("{}\n")
            with self.assertRaisesRegex(ValueError, "raw record"):
                self.report(root, protocol, fingerprint)

    def test_changed_source_and_reused_independent_process_are_rejected(self):
        for option, message in [("changed_source", "source"), ("reused_process", "fresh processes")]:
            with self.subTest(option=option), tempfile.TemporaryDirectory() as name:
                root = Path(name); protocol, fingerprint = dataset(root, **{option: True})
                with self.assertRaisesRegex(ValueError, message):
                    self.report(root, protocol, fingerprint)

    def test_missing_cycle_or_preparation_never_becomes_pass(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); protocol, fingerprint = dataset(root)
            prep = root / "preparation/pretrial-result.json"; prep.unlink()
            self.assertEqual(self.report(root, protocol, fingerprint)["performance"], "INCONCLUSIVE")
            state_path = root / "independent/collection-state.json"; state = REPORT.read(state_path)
            del state["accepted"]["1"]; save(state_path, state)
            with self.assertRaisesRegex(ValueError, "incomplete"):
                self.report(root, protocol, fingerprint)

    def test_record_paths_cannot_escape_on_either_host_syntax(self):
        for path in ["../outside", "..\\outside", "/absolute", "C:\\outside", "\\\\host\\share"]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                REPORT.record_path(Path("/synthetic"), path)

    def test_memory_stability_failure_and_insufficiency_remain_separate(self):
        protocol = REPORT.read(PROTOCOL)
        def cases(small, large):
            return {name: [{"controller": {"sampled_peak_rss_bytes": value}} for value in
                           (large if name == "stream-large" else small)] for name in protocol["scenarios"]}
        self.assertEqual(REPORT.conclude(cases([10]*6, [20]*6), protocol)["performance"], "PASS")
        self.assertEqual(REPORT.conclude(cases([10]*6, [20000000]*6), protocol)["performance"], "FAIL")
        self.assertEqual(REPORT.conclude(cases([10]*6, [20]*5+[10000000]), protocol)["performance"], "INCONCLUSIVE")
        self.assertEqual(REPORT.describe([1, 2, 100])["maximum"], 100)
        self.assertEqual(REPORT.describe([1, 2, 100])["mean"], 103/3)


if __name__ == "__main__":
    unittest.main()
