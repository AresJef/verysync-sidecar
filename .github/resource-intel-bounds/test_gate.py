"""Reject claims that cannot meet the Intel-only bounded-evidence gate."""
import copy
import unittest

from measure_cycles import qualify
from rss_limits import arithmetic_controls


class IntelEvidence(unittest.TestCase):
    def setUp(self):
        sha = "1" * 40
        tree = "2" * 40
        engine = "3" * 64
        protocol = "4" * 64
        self.identity = (sha, tree, protocol, engine)
        self.policy = {
            "source_inputs": {"rust_sources_sha256": "5" * 64},
            "scenarios": {"idle": {"repeats": 1}},
            "quality": {
                "minimum_measured_snapshots": 25, "maximum_sample_gap_ns": 50_000_000,
                "maximum_metric_read_fraction": 0.05, "maximum_boundary_overspan_fraction": 0.05,
            },
        }
        self.original = {
            "source": {"source_commit": sha, "source_tree": tree, **self.policy["source_inputs"]},
            "protocol_sha256": protocol, "events": [{"engine_sha256": engine}], "interval_ms": 10,
        }
        bound = {
            "confirmed_in_window_samples": 29, "lower_rss_bytes": 4_194_304,
            "upper_rss_bytes": 4_198_400, "prior_lifetime_rss_bytes": 4_198_400,
            "boundary_read_duration_ns": 2000,
        }
        self.case = {
            "scenario": "idle", "repeats": 1, "registered_elapsed_ns": 2_000_000_000,
            "peak_read_overspan_ns": 3_000_000,
            "native_outcome": dict.fromkeys((
                "all_actual_bytes_verified", "normal_owned_tree_exit", "source_config_identity_unchanged",
            ), True),
            "v33_quality": {"status": "INSUFFICIENT", "errors": [],
                "insufficient": ["sampling gap exceeded coverage limit"], "max_sample_gap_ns": 100_000_000,
                "metric_read_fraction": 0.02},
            "roles": {"controller": bound, "engine": copy.deepcopy(bound)},
        }

    def verdict(self):
        return qualify(self.original, self.case, self.policy, self.identity)["status"]

    def test_a_gap_alone_still_needs_both_process_bounds(self):
        self.assertEqual(self.verdict(), "VALID_BOUNDED_RSS")
        self.case["roles"]["controller"]["upper_rss_bytes"] = None
        self.assertEqual(self.verdict(), "INSUFFICIENT")
        self.case["roles"].pop("controller")
        with self.assertRaisesRegex(RuntimeError, "roles"):
            self.verdict()

    def test_retains_non_gap_coverage_failures(self):
        self.case["v33_quality"]["insufficient"].append("insufficient measured or baseline observations")
        self.assertEqual(self.verdict(), "INSUFFICIENT")

    def test_requires_the_exact_source_engine_and_protocol(self):
        for field, update in (
            ("protocol_sha256", "0" * 64), ("events", [{"engine_sha256": "0" * 64}]),
            ("source", dict(self.original["source"], source_commit="0" * 40)),
        ):
            with self.subTest(field=field):
                saved = self.original[field]
                self.original[field] = update
                with self.assertRaisesRegex(RuntimeError, "differs"):
                    self.verdict()
                self.original[field] = saved

    def test_failed_native_exit_cannot_qualify(self):
        self.case["native_outcome"]["normal_owned_tree_exit"] = False
        with self.assertRaisesRegex(RuntimeError, "cleanup"):
            self.verdict()

    def test_controls_refuse_hidden_and_visible_overshoots(self):
        arithmetic_controls()


if __name__ == "__main__":
    unittest.main()
