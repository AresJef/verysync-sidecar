"""Draft diagnosis is scoped; ready/dispatch coverage and refusals are strict."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("diagnostic_plan", ROOT / "scripts/select-native-diagnostics.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class DiagnosticSelection(unittest.TestCase):
    def setUp(self):
        self.rows = json.loads((ROOT / ".github/native-diagnostic-matrix.json").read_text())
        self.selection = {"draft_labels": ["remote-version-archives", "thumbnail-cache"]}

    def test_draft_includes_all_profiles_for_both_pending_features(self):
        actual = HELPER.select(self.rows, self.selection, draft=True)
        self.assertEqual(len(actual), 12)
        for label in self.selection["draft_labels"]:
            self.assertEqual(len([r for r in actual if r.get("label") == label]), 6)
        self.assertTrue(all(r in self.rows for r in actual))

    def test_ready_and_dispatch_preserve_every_original_row(self):
        self.assertEqual(HELPER.select(self.rows, self.selection, draft=False), self.rows)
        self.assertEqual(len(self.rows), 72)
        self.assertEqual(HELPER.select(self.rows, None, draft=True), self.rows)

    def test_unknown_empty_duplicate_and_malformed_selection_refused(self):
        for value in [{"draft_labels": []}, {"draft_labels": ["unknown"]},
                      {"draft_labels": ["thumbnail-cache", "thumbnail-cache"]},
                      {"draft_labels": "thumbnail-cache"}, {}, {"draft_labels": None}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                HELPER.select(self.rows, value, draft=True)

    def test_catalog_injection_unknown_runner_duplicates_and_unbounded_input_refused(self):
        for field, value in [("target", "files_engine; echo bad"), ("filter", "$(bad)"),
                             ("runner", "self-hosted"), ("rust", "wrong-target"),
                             ("trace", "anything"), ("package", "unrelated")]:
            changed = copy.deepcopy(self.rows); changed[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                HELPER.select(changed, self.selection, draft=False)
        for changed in [[], self.rows + [self.rows[0]], self.rows * 20]:
            with self.assertRaises(ValueError):
                HELPER.select(changed, self.selection, draft=True)

    def test_only_owned_drafts_are_scoped_and_missing_event_state_refuses(self):
        repo = "AresJef/verysync-sidecar"
        event = {"pull_request": {"draft": True, "head": {"repo": {"full_name": repo}}}}
        self.assertTrue(HELPER.draft_mode("pull_request", event, repo))
        event["pull_request"]["draft"] = False
        self.assertFalse(HELPER.draft_mode("pull_request", event, repo))
        event["pull_request"]["draft"] = True
        event["pull_request"]["head"]["repo"] = {"full_name": "fork/verysync-sidecar"}
        self.assertFalse(HELPER.draft_mode("pull_request", event, repo))
        event["pull_request"]["head"]["repo"] = None
        self.assertFalse(HELPER.draft_mode("pull_request", event, repo))
        self.assertFalse(HELPER.draft_mode("workflow_dispatch", {}, repo))
        for malformed in [{}, {"pull_request": {"draft": "true"}}, None]:
            with self.assertRaises(ValueError):
                HELPER.draft_mode("pull_request", malformed, repo)
        with self.assertRaises(ValueError):
            HELPER.draft_mode("push", {}, repo)

    def test_planning_does_not_mutate_the_catalog(self):
        before = copy.deepcopy(self.rows)
        HELPER.select(self.rows, self.selection, draft=True)
        self.assertEqual(self.rows, before)


if __name__ == "__main__":
    unittest.main()
