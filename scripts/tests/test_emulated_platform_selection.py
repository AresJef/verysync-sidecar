"""Emulation diagnosis keeps every original ready/manual target and safe inputs."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("emulated_selection", ROOT / "scripts/select-emulated-platforms.py")
SELECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SELECTOR)


class EmulatedPlatformSelection(unittest.TestCase):
    def setUp(self):
        self.rows = json.loads((ROOT / ".github/other-emulated-matrix.json").read_text())
        self.repo = "AresJef/verysync-sidecar"
        self.event = {"pull_request": {"draft": True, "head": {
            "ref": "ci/native-stop-diagnostics-20261117-01a1ca9b",
            "repo": {"full_name": self.repo}}}}

    def test_only_the_exact_owned_diagnostic_draft_selects_one_mips_profile(self):
        before = copy.deepcopy(self.rows)
        selected = SELECTOR.select(self.rows, "pull_request", self.event, self.repo)
        self.assertEqual(selected, [row for row in self.rows if row["package"] == "linux-mips-standard"])
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["rust"], "mips-unknown-linux-gnu")
        self.assertEqual(self.rows, before)

    def test_ready_and_manual_keep_all_eight_original_profiles(self):
        self.event["pull_request"]["draft"] = False
        self.assertEqual(SELECTOR.select(self.rows, "pull_request", self.event, self.repo), self.rows)
        self.assertEqual(SELECTOR.select(self.rows, "workflow_dispatch", {}, self.repo), self.rows)
        self.assertEqual(len(self.rows), 8)

    def test_only_an_owned_formal_candidate_push_runs_the_complete_matrix(self):
        event = {"ref": "refs/heads/ci/formal-candidate/rc1",
                 "deleted": False, "repository": {"full_name": self.repo}}
        self.assertEqual(SELECTOR.select(self.rows, "push", event, self.repo), self.rows)
        self.assertEqual(SELECTOR.select(self.rows, "push", event | {"created": True}, self.repo), self.rows)
        for invalid in (event | {"ref": "refs/heads/ci/normal-work"},
                        event | {"ref": "refs/heads/ci/formal-candidate/"},
                        event | {"deleted": True},
                        event | {"repository": {"full_name": "fork/verysync-sidecar"}}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                SELECTOR.select(self.rows, "push", invalid, self.repo)
        with self.assertRaises(ValueError):
            SELECTOR.select(self.rows, "push", event, "fork/verysync-sidecar")

    def test_other_or_fork_drafts_cannot_enable_emulation(self):
        self.event["pull_request"]["head"]["repo"]["full_name"] = "fork/other"
        self.assertEqual(SELECTOR.select(self.rows, "pull_request", self.event, self.repo), [])
        self.event["pull_request"]["head"]["repo"]["full_name"] = self.repo
        self.event["pull_request"]["head"]["ref"] = "another-draft"
        self.assertEqual(SELECTOR.select(self.rows, "pull_request", self.event, self.repo), [])

    def test_incomplete_duplicate_or_shell_like_catalog_is_refused(self):
        variants = [self.rows[:-1], [*self.rows[:-1], self.rows[0]]]
        for key, value in [("package", "unknown"), ("cc", "gcc;false"),
                           ("apt", "$(false)"), ("custom_std", 1)]:
            rows = copy.deepcopy(self.rows)
            rows[0][key] = value
            variants.append(rows)
        for rows in variants:
            with self.assertRaises(ValueError):
                SELECTOR.select(rows, "workflow_dispatch", {}, self.repo)

    def test_event_state_must_be_explicit(self):
        for event in [{}, {"pull_request": {"draft": "false"}}]:
            with self.assertRaises(ValueError):
                SELECTOR.select(self.rows, "pull_request", event, self.repo)
        with self.assertRaises(ValueError):
            SELECTOR.select(self.rows, "push", {}, self.repo)

    def test_actual_actions_output_contains_one_typed_mips_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event = root / "event.json"
            output = root / "output.txt"
            event.write_text(json.dumps(self.event))
            with patch.dict(SELECTOR.os.environ, {
                "GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(event),
                "GITHUB_REPOSITORY": self.repo, "GITHUB_OUTPUT": str(output),
            }):
                SELECTOR.main()
            line = output.read_text().strip()
            self.assertTrue(line.startswith("matrix="))
            rows = json.loads(line.removeprefix("matrix="))["include"]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["package"], "linux-mips-standard")
            self.assertIs(rows[0]["custom_std"], True)
            self.assertIs(rows[0]["manual_registration"], True)


if __name__ == "__main__":
    unittest.main()
