"""Only obsolete owned draft ancestors may be cancelled."""
import copy
import importlib.util
import json
import io
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("retire_ci", Path(__file__).resolve().parents[1] / "cancel-superseded-draft-ci.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class RetirementContracts(unittest.TestCase):
    def test_preservation_returns_before_credential_or_api_access(self):
        repo = "AresJef/verysync-sidecar"
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            event.write_text(json.dumps({"pull_request": {"draft": True,
                "head": {"sha": "b" * 40, "repo": {"full_name": repo}}}}))
            environment = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": repo,
                "GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(event),
                "GITHUB_RUN_ID": "2"}
            output = io.StringIO()
            with patch.dict(HELPER.os.environ, environment, clear=True), \
                    patch.object(HELPER, "preserve_ancestor_drafts", return_value=True), \
                    patch.object(HELPER.urllib.request, "urlopen") as request, \
                    patch.object(HELPER.subprocess, "run") as command, redirect_stdout(output):
                HELPER.main()
            request.assert_not_called()
            command.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())["cancellation_requests"], 0)

    def test_explicit_preservation_and_malformed_settings_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertFalse(HELPER.preserve_ancestor_drafts(root))
            (root / ".github").mkdir()
            path = root / ".github/native-diagnostic-preservation.json"
            for selected in [True, False]:
                path.write_text(json.dumps({"preserve_ancestor_drafts": selected}))
                self.assertEqual(HELPER.preserve_ancestor_drafts(root), selected)
            for value in [{}, {"preserve_ancestor_drafts": "false"},
                          {"preserve_ancestor_drafts": 0},
                          {"preserve_ancestor_drafts": True, "other": True}]:
                path.write_text(json.dumps(value))
                with self.subTest(value=value), self.assertRaises(ValueError):
                    HELPER.preserve_ancestor_drafts(root)

    def test_ready_release_unrelated_current_and_nonancestor_runs_are_preserved(self):
        run = {"id": 1, "event": "pull_request", "name": "Engine fixture", "status": "queued", "head_sha": "a"*40}
        pull = {"draft": True, "state": "open", "head": {"sha": "a"*40, "repo": {"full_name": "AresJef/verysync-sidecar"}}}
        self.assertTrue(HELPER.eligible(run, pull, 2, "b"*40, lambda _: True))
        for key, value in [("name", "Release"), ("name", "Quality"), ("event", "push"), ("id", 2), ("status", "completed"), ("head_sha", "b"*40)]:
            changed = dict(run); changed[key] = value
            self.assertFalse(HELPER.eligible(changed, pull, 2, "b"*40, lambda _: True))
        for key, value in [("draft", False), ("state", "closed")]:
            changed = copy.deepcopy(pull); changed[key] = value
            self.assertFalse(HELPER.eligible(run, changed, 2, "b"*40, lambda _: True))
        self.assertFalse(HELPER.eligible(run, pull, 2, "b"*40, lambda _: False))
        changed = copy.deepcopy(pull); changed["head"]["repo"]["full_name"] = "someone/another-repository"
        self.assertFalse(HELPER.eligible(run, changed, 2, "b"*40, lambda _: True))


if __name__ == "__main__":
    unittest.main()
