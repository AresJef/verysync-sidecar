"""Only obsolete owned draft ancestors may be cancelled."""
import copy
import importlib.util
import json
import io
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("retire_ci", Path(__file__).resolve().parents[1] / "cancel-superseded-draft-ci.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class RetirementContracts(unittest.TestCase):
    def exact_fixture(self):
        row = {"run_id": 1, "pr": 7, "head_sha": "a"*40, "equivalent_head_sha": "c"*40,
               "expected_files": {"scripts/probe-macos-timers.py": "d"*40}}
        run = {"id": 1, "workflow_id": 415510507, "event": "pull_request", "name": "Engine fixture",
               "status": "queued", "head_sha": "a"*40,
               "repository": {"full_name": "AresJef/verysync-sidecar"}, "pull_requests": [{"number": 7}]}
        pull = {"draft": True, "state": "open", "head": {"sha": "a"*40,
                "repo": {"full_name": "AresJef/verysync-sidecar"}}}
        diff = {"status": "ahead", "base_commit": {"sha": "c"*40}, "total_commits": 1,
                "commits": [{"sha": "a"*40}], "files": [{"filename": "scripts/probe-macos-timers.py",
                "sha": "d"*40, "status": "modified"}]}
        def response(path, method="GET"):
            if method == "POST": return None
            if path == "/actions/runs/1": return copy.deepcopy(run)
            if path == "/pulls/7": return copy.deepcopy(pull)
            if path.startswith("/compare/"): return copy.deepcopy(diff)
            raise AssertionError(path)
        return row, run, pull, diff, response

    def test_exact_duplicate_checks_full_diff_before_only_pinned_cancellation(self):
        row, _, _, _, response = self.exact_fixture()
        api = Mock(side_effect=response)
        result = HELPER.retire_exact([row], api, 2, "b"*40, lambda _: True)
        self.assertEqual(result[0]["id"], 1)
        self.assertTrue(result[0]["cancel_requested"])
        self.assertFalse(result[0]["accepted"])
        self.assertEqual(api.call_args_list[-1].args, ("/actions/runs/1/cancel", "POST"))
        self.assertEqual(sum(call.args[-1:] == ("POST",) for call in api.call_args_list), 1)

    def test_exact_identity_scope_or_changed_native_diff_never_cancels(self):
        for kind in ["quality", "ready", "repo", "head", "diff", "blob", "incomplete", "ancestor"]:
            row, run, pull, diff, response = self.exact_fixture()
            if kind == "quality": run["name"] = "Quality"
            if kind == "ready": pull["draft"] = False
            if kind == "repo": run["repository"]["full_name"] = "someone/else"
            if kind == "head": run["head_sha"] = "e"*40
            if kind == "diff": diff["files"][0]["filename"] = "src/client.rs"
            if kind == "blob": diff["files"][0]["sha"] = "e"*40
            if kind == "incomplete": diff["total_commits"] = 2
            api = Mock(side_effect=response)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                HELPER.retire_exact([row], api, 2, "b"*40, lambda _: kind != "ancestor")
            self.assertFalse(any(call.args[-1:] == ("POST",) for call in api.call_args_list))

    def test_terminal_or_newly_ready_run_remains_preserved_and_unaccepted(self):
        row, run, pull, _, response = self.exact_fixture()
        run["status"] = "completed"
        api = Mock(side_effect=response)
        result = HELPER.retire_exact([row], api, 2, "b"*40, lambda _: True)
        self.assertEqual(len(api.call_args_list), 1)
        self.assertFalse(result[0]["accepted"])
        run["status"] = "queued"
        count = 0
        def race(path, method="GET"):
            nonlocal count
            if path == "/pulls/7":
                count += 1
                if count == 2: pull["draft"] = False
            return response(path, method)
        api = Mock(side_effect=race)
        result = HELPER.retire_exact([row], api, 2, "b"*40, lambda _: True)
        self.assertEqual(result[0]["skip"], "no longer eligible")
        self.assertFalse(any(call.args[-1:] == ("POST",) for call in api.call_args_list))

    def test_retirement_schema_rejects_native_inputs_unpinned_or_duplicate_targets(self):
        row, _, _, _, _ = self.exact_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / ".github").mkdir()
            path = root / ".github/exact-native-retirements.json"
            self.assertEqual(HELPER.exact_retirements(root), [])
            path.write_text(json.dumps({"runs": [row]}))
            self.assertEqual(HELPER.exact_retirements(root), [row])
            for changed in [{**row, "expected_files": {"src/client.rs": "d"*40}},
                            {**row, "head_sha": "main"}, {**row, "run_id": True}]:
                path.write_text(json.dumps({"runs": [changed]}))
                with self.assertRaises(ValueError): HELPER.exact_retirements(root)
            path.write_text(json.dumps({"runs": [row, row]}))
            with self.assertRaises(ValueError): HELPER.exact_retirements(root)

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
                    patch.object(HELPER, "exact_retirements", return_value=[]), \
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
