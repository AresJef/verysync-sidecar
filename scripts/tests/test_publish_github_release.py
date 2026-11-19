"""Release identity failures must reject before creating a tag or release."""

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_helper", ROOT / "scripts/publish-github-release.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class ReleaseIdentityTests(unittest.TestCase):
    def setUp(self):
        self.metadata = json.loads(ROOT.joinpath("releases/crates-io-release.json").read_text())

    def package(self, entries=(), source=None, omitted=()):
        manifest = '[package]\nname="verysync-sidecar"\nversion="0.1.0-alpha.1"\n'
        contents = {
            ".cargo_vcs_info.json": json.dumps({"git": {"sha1": source or self.metadata["source"]}}),
            "Cargo.toml": manifest,
            "Cargo.toml.orig": manifest,
            "Cargo.lock": "# locked",
            "README.md": "# Synthetic package",
            "LICENSE-MIT": "Synthetic license fixture",
            "LICENSE-APACHE": "Synthetic license fixture",
            "src/lib.rs": "// synthetic public crate",
            "docs/public/guide.md": "# Synthetic guide",
        }
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, payload in (*contents.items(), *entries):
                if name in omitted:
                    continue
                data = payload.encode() if isinstance(payload, str) else payload
                info = tarfile.TarInfo(f'verysync-sidecar-{self.metadata["version"]}/{name}')
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        candidate = copy.deepcopy(self.metadata)
        content = buffer.getvalue()
        candidate["package_sha256"] = hashlib.sha256(content).hexdigest()
        return candidate, content

    def test_exact_metadata_is_accepted(self):
        HELPER.validate_metadata(self.metadata)

    def test_wrong_repository_source_or_publisher_rejected(self):
        for key, value in (("repository", "elsewhere/repo"), ("source", "main"),
                           ("publisher_id", 1), ("package_sha256", "invalid")):
            candidate = copy.deepcopy(self.metadata)
            candidate[key] = value
            with self.assertRaises(ValueError):
                HELPER.validate_metadata(candidate)

    def test_registry_identity_must_match_checksum_and_publisher(self):
        version = {"num": self.metadata["version"], "checksum": self.metadata["package_sha256"],
                   "published_by": {"login": "AresJef", "id": 448021}}
        HELPER.validate_registry(self.metadata, version)
        for key, value in (("checksum", "0" * 64), ("num", "0.0.0"),
                           ("published_by", {"login": "someone", "id": 1})):
            candidate = copy.deepcopy(version)
            candidate[key] = value
            with self.assertRaises(ValueError):
                HELPER.validate_registry(self.metadata, candidate)

    def test_actual_archive_vcs_source_is_checked_after_checksum(self):
        self.assertIn("src/lib.rs", HELPER.validate_package(*self.package()))
        with self.assertRaisesRegex(ValueError, "archive source differs"):
            HELPER.validate_package(*self.package(source="0" * 40))

    def test_unpublished_inputs_and_binary_content_fail_even_with_the_correct_digest(self):
        for name, data, error in (
            ("docs/internal/work.md", "private", "outside the public package"),
            ("tasks/raw/result.json", "{}", "outside the public package"),
            ("src/embedded.rs", b"\x7fELF\0", "binary data"),
            ("examples/pair.rs", b"\xff\xff", "not UTF-8"),
        ):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, error):
                HELPER.validate_package(*self.package(((name, data),)))

    def test_duplicate_alias_and_missing_license_fail_before_upload(self):
        for name, message in (("README.md", "duplicate"), ("readme.md", "nonportable"),
                              ("docs//public/guide.md", "unexpected"), ("docs/../README.md", "unexpected"),
                              ("src/payload.rs:stream", "unexpected")):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, message):
                HELPER.validate_package(*self.package(((name, "data"),)))
        with self.assertRaisesRegex(ValueError, "license is missing"):
            HELPER.validate_package(*self.package(omitted=("LICENSE-APACHE",)))

    def test_missing_or_failed_native_target_is_rejected(self):
        jobs = [{"name": name, "status": "completed", "conclusion": "success"}
                for name in HELPER.NATIVE_TARGETS]
        HELPER.validate_jobs(jobs, HELPER.NATIVE_TARGETS)
        with self.assertRaises(ValueError):
            HELPER.validate_jobs(jobs[:-1], HELPER.NATIVE_TARGETS)
        jobs[0]["conclusion"] = "failure"
        with self.assertRaises(ValueError):
            HELPER.validate_jobs(jobs, HELPER.NATIVE_TARGETS)

    def test_formal_release_does_not_reuse_the_alpha_acceptance_contract(self):
        self.metadata["version"] = "0.1.0"
        with self.assertRaisesRegex(ValueError, "alpha"):
            HELPER.validate_metadata(self.metadata)

    def test_candidate_runs_require_distinct_nonzero_run_and_attempts(self):
        candidate = copy.deepcopy(self.metadata)
        candidate["candidate_runs"] = {
            key: {"id": index, "attempt": 1}
            for index, key in enumerate(("quality", "engine", "platforms", "resources"), 1)
        }
        HELPER.validate_candidate_runs(candidate)
        for correction in ({}, {"id": True, "attempt": 1}, {"id": 2, "attempt": 1},
                           {"id": 9, "attempt": 0}):
            with self.subTest(correction=correction):
                invalid = copy.deepcopy(candidate)
                invalid["candidate_runs"]["quality"] = correction
                with self.assertRaises(ValueError):
                    HELPER.validate_candidate_runs(invalid)

    def test_authenticated_candidate_run_identity(self):
        repository = self.metadata["repository"]
        run_path = ".github/workflows/engine-tests.yml"
        run = {"id": 30, "workflow_id": 9, "path": run_path, "event": "workflow_dispatch",
               "head_sha": self.metadata["source"], "run_attempt": 2,
               "status": "completed", "conclusion": "success",
               "repository": {"full_name": repository}, "head_repository": {"full_name": repository}}
        lookup = {"id": 9, "path": run_path}
        reference = {"id": 30, "attempt": 2}
        HELPER.validate_candidate_run(self.metadata, run_path, lookup, reference, run)
        for key, value in (("id", 31), ("workflow_id", 8), ("path", ".github/workflows/other.yml"),
                           ("event", "pull_request"), ("head_sha", "a" * 40), ("run_attempt", 1),
                           ("status", "in_progress"), ("conclusion", "failure"),
                           ("head_repository", {"full_name": "elsewhere/verysync-sidecar"})):
            with self.subTest(key=key), self.assertRaises(ValueError):
                HELPER.validate_candidate_run(self.metadata, run_path, lookup, reference, run | {key: value})

    def candidate_job(self, name, job_id, steps=("acceptance", "cleanup")):
        return {"id": job_id, "name": name, "run_id": 51, "run_attempt": 2, "runner_id": 4,
                "head_sha": self.metadata["source"], "status": "completed", "conclusion": "success",
                "steps": [{"name": step, "status": "completed", "conclusion": "success"} for step in steps]}

    def test_required_jobs_and_steps_cannot_be_skipped_renamed_or_repeated(self):
        first, second = self.candidate_job("native-one", 11), self.candidate_job("native-two", 12)
        expected = {name: {"acceptance", "cleanup"} for name in ("native-one", "native-two")}
        HELPER.validate_candidate_jobs(self.metadata["source"], 51, 2, [first, second], expected)
        for roster in ([first], [first, second | {"name": "other"}],
                       [first, second, second | {"id": 13}], [first, second | {"id": 11}],
                       [first, second | {"run_attempt": 1}], [first, second | {"runner_id": 0}],
                       [first, second | {"head_sha": "e" * 40}], [first, second | {"conclusion": "skipped"}],
                       [first, self.candidate_job("native-two", 12, ("acceptance",))],
                       [first, second | {"steps": [second["steps"][0], second["steps"][1] | {"conclusion": "skipped"}]}]):
            with self.subTest(roster=roster), self.assertRaises(ValueError):
                HELPER.validate_candidate_jobs(self.metadata["source"], 51, 2, roster, expected)

    def test_candidate_job_pagination_rejects_partial_or_changing_rosters(self):
        pages = [{"total_count": 101, "jobs": [{"id": job} for job in range(1, 101)]},
                 {"total_count": 101, "jobs": [{"id": 101}]}]
        endpoint = "repos/AresJef/verysync-sidecar/actions/runs/51"
        with patch.object(HELPER, "github", side_effect=pages) as lookup:
            self.assertEqual(len(HELPER.candidate_attempt_jobs(endpoint, 2)), 101)
            self.assertEqual([call.args[0] for call in lookup.call_args_list],
                             [endpoint + f"/attempts/2/jobs?per_page=100&page={page}" for page in (1, 2)])
        for invalid in ({"total_count": 101, "jobs": []}, {"total_count": 102, "jobs": [{"id": 101}]}):
            with patch.object(HELPER, "github", side_effect=[pages[0], invalid]):
                with self.assertRaises(ValueError):
                    HELPER.candidate_attempt_jobs(endpoint, 2)

    def test_candidate_action_verification_reads_the_full_registered_attempts(self):
        candidate = copy.deepcopy(self.metadata)
        context = f'repos/{candidate["repository"]}'
        references = {
            key: {"id": index + 60, "attempt": 2}
            for index, key in enumerate(HELPER.ACTION_WORKFLOWS, 1)
        }
        candidate["candidate_runs"] = references
        commit = f'{context}/git/commits/{candidate["source"]}'
        replies = {commit: {"sha": candidate["source"], "tree": {"sha": candidate["tree"]}}}
        expected = {}
        for lane, filename in HELPER.ACTION_WORKFLOWS.items():
            run_id = references[lane]["id"]
            path = f".github/workflows/{filename}"
            workflow = {"path": path, "id": run_id + 100}
            key = f"{context}/actions/runs/{run_id}"
            repo = {"full_name": candidate["repository"]}
            replies[f"{context}/actions/workflows/{filename}"] = workflow
            replies[key] = {"id": run_id, "workflow_id": workflow["id"], "path": path,
                            "event": "workflow_dispatch", "head_sha": candidate["source"], "run_attempt": 2,
                            "status": "completed", "conclusion": "success", "repository": repo,
                            "head_repository": repo}
            jobs = [self.candidate_job(name, index, steps) | {"run_id": run_id}
                    for index, (name, steps) in enumerate(HELPER.CANDIDATE_ACTION_JOBS[lane].items(), 1)]
            endpoint = f"{key}/attempts/2/jobs?per_page=100&page=1"
            replies[endpoint] = {"total_count": len(jobs), "jobs": jobs}
            expected[lane] = {"id": run_id, "attempt": 2,
                              "required_jobs": len(jobs), "listed_jobs": len(jobs)}
        with patch.object(HELPER, "github", side_effect=replies.__getitem__) as github:
            self.assertEqual(HELPER.verify_candidate_actions(candidate), expected)
            self.assertNotIn("publish", [call.args[0] for call in github.call_args_list])
        # A successful resource job without the formal measurement step is only preparation.
        resource_attempt = f'{context}/actions/runs/{references["resources"]["id"]}/attempts/2/jobs?per_page=100&page=1'
        job = replies[resource_attempt]["jobs"][0]
        formal = next(step for step in job["steps"] if "formal" in step["name"])
        formal["conclusion"] = "skipped"
        with patch.object(HELPER, "github", side_effect=replies.__getitem__):
            with self.assertRaisesRegex(ValueError, "required step.*formal"):
                HELPER.verify_candidate_actions(candidate)

    def test_publication_outside_trusted_main_context_cannot_call_github(self):
        with patch.dict(HELPER.os.environ, {"GITHUB_REPOSITORY": "AresJef/verysync-sidecar",
                                          "GITHUB_REF": "refs/pull/14/merge",
                                          "GITHUB_EVENT_NAME": "pull_request"}, clear=True):
            with patch.object(HELPER, "github") as api:
                with self.assertRaises(ValueError):
                    HELPER.publish(self.metadata)
                api.assert_not_called()

    def test_existing_tag_with_other_source_is_never_moved(self):
        with patch.dict(HELPER.os.environ, {"GITHUB_REPOSITORY": "AresJef/verysync-sidecar",
                                          "GITHUB_REF": "refs/heads/main",
                                          "GITHUB_EVENT_NAME": "push"}, clear=True):
            with patch.object(HELPER, "tag_target", return_value="0" * 40):
                with patch.object(HELPER, "github") as api:
                    with self.assertRaises(ValueError):
                        HELPER.publish(self.metadata)
                    api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
