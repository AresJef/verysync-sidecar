"""Only obsolete owned draft ancestors may be cancelled."""
import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("retire_ci", Path(__file__).resolve().parents[1] / "cancel-superseded-draft-ci.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class RetirementContracts(unittest.TestCase):
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
