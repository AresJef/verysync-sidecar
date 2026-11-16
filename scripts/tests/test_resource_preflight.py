"""Preparation rejection is retained; no rejected row becomes formal evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from test_resource_report import dataset, REPORT, COLLECT, METRICS, save

POLICY = {"mode": "one_complete_valid_order", "orders": 2, "minimum_valid_orders": 1,
          "retain_quality_rejections": True, "formal_samples_from_preparation": 0}
SPEC = importlib.util.spec_from_file_location("resource_preflight", Path(__file__).resolve().parents[1] / "preflight-native-resources.py")
PREFLIGHT = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(PREFLIGHT)


def reject(folder):
    rows = [json.loads(line) for line in (folder / "samples.jsonl").read_text().splitlines()]
    rows = rows[:15] + rows[25:]
    (folder / "samples.jsonl").write_text("".join(json.dumps(v)+"\n" for v in rows))
    quality = METRICS.summarize(REPORT.read(folder / "preparation-result.json"), rows)
    assert quality["status"] == "INSUFFICIENT"
    save(folder / "quality-result.json", quality)


def noisy(root, cycles=(0,)):
    trial = REPORT.read(root / "preparation/pretrial-result.json")
    for cycle in cycles:
        row = next(r for r in trial["attempts"] if r["cycle"] == cycle and r["slot"] == 0)
        reject(root / "preparation" / f"cycle-{cycle}-slot-0-{row['scenario']}")
        row["exit_code"] = 2
    save(root / "preparation/pretrial-result.json", trial)


class ResourcePreparationContracts(unittest.TestCase):
    def test_one_complete_valid_pretrial_order_allows_only_the_original_complete_formal_data(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); protocol, fingerprint = dataset(root, readiness=POLICY)
            noisy(root)
            result = REPORT.profile_report("macos-arm64-standard", root, protocol, fingerprint, COLLECT, METRICS)
            self.assertEqual(result["performance"], "PASS")
            self.assertEqual(result["accepted_native_cases"], 24)
            self.assertEqual(result["attempted_cases"], 24)
            self.assertEqual(result["preparation_readiness"]["complete_valid_orders"], [1])
            self.assertEqual(result["preparation_readiness"]["quality_counts"], {"VALID": 7, "INSUFFICIENT": 1})

    def test_two_rejected_orders_do_not_make_readiness_and_legacy_policy_stays_strict(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); protocol, fingerprint = dataset(root, readiness=POLICY)
            noisy(root, (0, 1))
            trial = REPORT.read(root / "preparation/pretrial-result.json")
            trial["status"] = "PREPARATION_INSUFFICIENT"
            save(root / "preparation/pretrial-result.json", trial)
            result = REPORT.profile_report("macos-arm64-standard", root, protocol, fingerprint, COLLECT, METRICS)
            self.assertEqual(result["performance"], "INCONCLUSIVE")
            self.assertEqual(result["preparation"], "INCOMPLETE")
            legacy = copy.deepcopy(protocol); legacy.pop("preparation_readiness")
            folder = next((root / "preparation").glob("cycle-0-slot-0-*"))
            with self.assertRaises(ValueError):
                REPORT.check_attempt(folder, legacy, "pilot", METRICS)

    def test_quality_rejection_is_never_permitted_for_a_formal_member_or_native_error(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); protocol, _ = dataset(root, readiness=POLICY)
            folder = next((root / "formal").glob("cycle-0-attempt-1/slot-0-*"))
            reject(folder)
            with self.assertRaises(ValueError):
                REPORT.check_attempt(folder, protocol, "formal", METRICS)
            pilot = next((root / "preparation").glob("cycle-0-slot-0-*"))
            report = REPORT.read(pilot / "preparation-result.json"); report["exit_code"] = 101
            save(pilot / "preparation-result.json", report)
            with self.assertRaises(ValueError):
                REPORT.check_attempt(pilot, protocol, "pilot", METRICS)

    def test_runner_executes_both_original_orders_after_the_first_coverage_rejection(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); protocol, _ = dataset(root / "source", readiness=POLICY)
            noisy(root / "source")
            protocol["preflight_sha256"] = REPORT.digest(SPEC.origin)
            protocol["reporter_sha256"] = REPORT.digest(REPORT.__file__)
            save(root / "protocol.json", protocol)
            def execute(command, **_):
                target = Path(command[command.index("--evidence-dir")+1])
                source = root / "source/preparation" / target.name
                shutil.copytree(source, target)
                return SimpleNamespace(returncode=0 if REPORT.read(target / "quality-result.json")["status"] == "VALID" else 2)
            argv = [str(SPEC.origin), "--protocol", str(root / "protocol.json"), "--cargo", "/synthetic/not-executed",
                    "--toolchain", "1.85.0", "--evidence-dir", str(root / "output")]
            with patch.object(PREFLIGHT.sys, "argv", argv), patch.object(PREFLIGHT.subprocess, "run", side_effect=execute) as run:
                self.assertEqual(PREFLIGHT.main(), 0)
            saved = REPORT.read(root / "output/pretrial-result.json")
            self.assertEqual(run.call_count, 8)
            self.assertEqual(len(saved["attempts"]), 8)
            self.assertEqual(saved["attempts"][0]["exit_code"], 2)
            self.assertEqual(saved["readiness"]["complete_valid_orders"], [1])
            self.assertFalse(saved["formal_sample"])

    def test_native_error_with_exit_two_stops_instead_of_becoming_a_quality_rejection(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); protocol, _ = dataset(root / "source", readiness=POLICY)
            first = next((root / "source/preparation").glob("cycle-0-slot-0-*"))
            report = REPORT.read(first / "preparation-result.json"); report["exit_code"] = 101
            save(first / "preparation-result.json", report)
            rows = [json.loads(line) for line in (first / "samples.jsonl").read_text().splitlines()]
            save(first / "quality-result.json", METRICS.summarize(report, rows))
            protocol["preflight_sha256"] = REPORT.digest(SPEC.origin)
            protocol["reporter_sha256"] = REPORT.digest(REPORT.__file__)
            save(root / "protocol.json", protocol)
            def execute(command, **_):
                target = Path(command[command.index("--evidence-dir")+1])
                shutil.copytree(first, target)
                return SimpleNamespace(returncode=2)
            argv = [str(SPEC.origin), "--protocol", str(root / "protocol.json"), "--cargo", "/synthetic/not-executed",
                    "--toolchain", "1.85.0", "--evidence-dir", str(root / "output")]
            with patch.object(PREFLIGHT.sys, "argv", argv), patch.object(PREFLIGHT.subprocess, "run", side_effect=execute) as run:
                with self.assertRaises(ValueError):
                    PREFLIGHT.main()
            saved = REPORT.read(root / "output/pretrial-result.json")
            self.assertEqual(run.call_count, 1)
            self.assertEqual(saved["status"], "ERROR")
            self.assertNotIn("readiness", saved)


if __name__ == "__main__":
    unittest.main()
