import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "upgrade_witness", Path(__file__).resolve().parents[1] / "trace-upgrade-recovery.py"
)
witness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(witness)


def inputs():
    name, owner, op = "cli-partial", 50, [1, 2, 3]
    rows = [
        {"case": name, "stage": name_of_stage, "pid": owner, "unix_ns": stamp, "detail": detail}
        for name_of_stage, stamp, detail in [
            ("original-receipt", 10_000, {"receipt": {"operation_id": op}}),
            ("calibration-child", 16_000, {"pid": 51}),
            ("begin-recovery", 20_000, {"operation_id": op, "requests_seen": 1}),
            ("end-recovery", 30_000, {"operation_id": op, "requests_seen": 1}),
            ("calibration-after", 40_000, {"pid": 52}),
        ]
    ]
    events = [
        {"event": "create", "time": stamp, "parent": parent, "pid": pid}
        for stamp, parent, pid in [(13_000, owner, 51), (32_000, owner, 52), (25_000, 9, 10)]
    ]
    return name, rows, events


class UpgradeProcessWitnessTests(unittest.TestCase):
    def test_accepts_calibrated_empty_interval(self):
        name, rows, events = inputs()
        evidence = witness.check_case(name, rows, witness.scoped_events(rows, events))
        self.assertEqual(evidence["additional_started_processes"], 0)
        self.assertEqual(evidence["additional_upgrade_requests"], 0)

    def test_rejects_missing_short_child(self):
        name, rows, events = inputs()
        with self.assertRaisesRegex(ValueError, "short-lived calibration"):
            witness.check_case(name, rows, events[1:])

    def test_rejects_extra_exec(self):
        name, rows, events = inputs()
        events.append({"event": "exec", "time": 26_000, "parent": 50, "pid": 53})
        with self.assertRaisesRegex(ValueError, "started a program"):
            witness.check_case(name, rows, witness.scoped_events(rows, events))

    def test_rejects_new_request_and_wrong_receipt(self):
        name, rows, events = inputs()
        rows[3]["detail"]["requests_seen"] = 2
        with self.assertRaisesRegex(ValueError, "new request"):
            witness.check_case(name, rows, events)
        rows[3]["detail"].update(requests_seen=1, operation_id=[4])
        with self.assertRaisesRegex(ValueError, "different attempt"):
            witness.check_case(name, rows, events)


if __name__ == "__main__":
    unittest.main()
