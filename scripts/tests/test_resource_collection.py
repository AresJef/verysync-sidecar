"""Frozen-cycle evidence is complete, immutable and bounded on resume."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("resource_collection", Path(__file__).resolve().parents[1] / "collect-native-resources.py")
COLLECT = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(COLLECT)


class ResourceCollectionContracts(unittest.TestCase):
    def test_host_text_newlines_cannot_change_durable_record_bytes(self):
        original = COLLECT.tempfile.NamedTemporaryFile
        def windows_text_default(*args, **kwargs):
            if "b" not in kwargs.get("mode", "w+b"):
                kwargs.setdefault("newline", "\r\n")
            return original(*args, **kwargs)
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "record.json"
            value = {"frozen": "identity", "attempt": 1}
            with patch.object(COLLECT.tempfile, "NamedTemporaryFile", side_effect=windows_text_default):
                COLLECT.save(path, value)
            self.assertEqual(path.read_bytes(), (json.dumps(value, indent=2)+"\n").encode())

    def test_frozen_bytes_are_copied_without_reserializing_the_protocol(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "frozen.json"
            original = b'{"frozen":"identity"}\r\n'
            COLLECT.save_bytes(path, original)
            self.assertEqual(path.read_bytes(), original)

    def test_missing_or_wrong_original_order_never_reaches_metric_acceptance(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); order = ["idle", "stream-small", "stream-large", "many-small"]
            COLLECT.save(root / "frozen-protocol.json", {"formal_orders": [order]})
            fingerprint = COLLECT.digest(root / "frozen-protocol.json")
            metrics = Mock()
            for supplied in [order[:-1], list(reversed(order))]:
                manifest = {"cycle": 0, "order": order, "slots": [{"scenario": s} for s in supplied]}
                with self.assertRaisesRegex(ValueError, "coverage"):
                    COLLECT.verify_group(manifest, root, fingerprint, "formal", metrics)
            metrics.summarize.assert_not_called()

    def test_raw_hash_or_frozen_source_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); order = ["idle"]
            COLLECT.save(root / "frozen-protocol.json", {"formal_orders": [order], "source_inputs": {"sampler_sha256": "expected"}})
            folder = root / "slot"; folder.mkdir()
            for filename in ["preparation-result.json", "samples.jsonl", "events.jsonl", "quality-result.json"]:
                COLLECT.save(folder / filename, {})
            COLLECT.save(folder / "preparation-result.json", {"stage": "formal", "protocol_sha256": COLLECT.digest(root / "frozen-protocol.json"), "source": {"sampler_sha256": "changed"}})
            hashes = {p.name: COLLECT.digest(p) for p in folder.iterdir()}
            manifest = {"cycle": 0, "order": order, "slots": [{"scenario": "idle", "directory": "slot", "sha256": hashes}]}
            metrics = Mock()
            with self.assertRaisesRegex(ValueError, "source"):
                COLLECT.verify_group(manifest, root, COLLECT.digest(root / "frozen-protocol.json"), "formal", metrics)
            (folder / "samples.jsonl").write_text("changed\n")
            with self.assertRaisesRegex(ValueError, "raw record"):
                COLLECT.verify_group(manifest, root, COLLECT.digest(root / "frozen-protocol.json"), "formal", metrics)
            metrics.summarize.assert_not_called()

    def test_expired_resume_preserves_deadline_and_starts_no_new_group(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); protocol = root / "protocol.json"
            config = {"collector_sha256": COLLECT.digest(SPEC.origin), "source_inputs": {},
                      "formal_orders": [["idle"]], "maximum_group_attempts": 3,
                      "estimated_complete_group_s": 120, "save_reserve_s": 30}
            COLLECT.save(protocol, config)
            original = time.time()-1
            state = {"protocol_sha256": COLLECT.digest(protocol), "stage": "formal", "deadline_unix": original,
                     "accepted": {}, "attempts": {}, "status": "INCOMPLETE"}
            COLLECT.save(root / "collection-state.json", state)
            metrics = Mock(); metrics.source_identity.return_value = {}
            argv = [str(SPEC.origin), "--stage", "formal", "--resume", "--protocol", str(protocol),
                    "--evidence-dir", str(root), "--cargo", "/synthetic/not-executed"]
            with patch.object(sys, "argv", argv), patch.object(COLLECT, "metrics_module", return_value=metrics), patch.object(COLLECT.subprocess, "run") as run:
                self.assertEqual(COLLECT.main(), 2)
                run.assert_not_called()
            saved = json.loads((root / "collection-state.json").read_text())
            self.assertEqual(saved["deadline_unix"], original)
            self.assertEqual(saved["attempts"], {})

    def test_committed_protocol_binds_actual_collector_and_sampler_sources(self):
        root = Path(__file__).resolve().parents[2]
        config = json.loads((root / "tests/fixtures/resource-protocol.json").read_text())
        self.assertEqual(config["collector_sha256"], COLLECT.digest(SPEC.origin))
        self.assertEqual(config["source_inputs"]["sampler_sha256"], COLLECT.digest(root / "scripts/measure-native-resources.py"))
        self.assertEqual(config["source_inputs"]["wrapper_sha256"], COLLECT.digest(root / "scripts/run-isolated-engine-tests.py"))
        self.assertEqual(len(config["formal_orders"]), 4)
        self.assertEqual(len(config["independent_orders"]), 2)


if __name__ == "__main__":
    unittest.main()
