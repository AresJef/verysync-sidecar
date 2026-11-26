"""Release identity failures must reject before creating a tag or release."""

import base64
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_helper", ROOT / "scripts/publish-github-release.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


def diagnostic_catalog_reply(rows):
    content = json.dumps(rows).encode()
    header = f"blob {len(content)}\0".encode()
    return {
        "type": "file", "path": HELPER.ENGINE_DIAGNOSTIC_MANIFEST, "encoding": "base64",
        "size": len(content), "sha": hashlib.sha1(header + content).hexdigest(),
        "content": base64.encodebytes(content).decode(),
    }


class ReleaseIdentityTests(unittest.TestCase):
    def setUp(self):
        self.metadata = json.loads(ROOT.joinpath("releases/crates-io-release.json").read_text())

    def package(self, entries=(), source=None, omitted=()):
        manifest = f'[package]\nname="verysync-sidecar"\nversion="{self.metadata["version"]}"\n'
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

    def test_only_named_windows_permissions_script_is_public(self):
        name = "scripts/run-windows-managed-permissions.ps1"
        original = (ROOT / name).read_bytes()
        self.assertEqual(HELPER.validate_package(*self.package(((name, original),)))[name], original)
        for unregistered in ("scripts/other-windows-permissions.ps1",
                             "scripts/nested/run-windows-managed-permissions.ps1"):
            with self.subTest(unregistered=unregistered), self.assertRaisesRegex(
                ValueError, "outside the public package"
            ):
                HELPER.validate_package(*self.package(((unregistered, original),)))

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
            for index, key in enumerate(HELPER.ACTION_WORKFLOWS, 1)
        }
        HELPER.validate_candidate_runs(candidate)
        for lane in ("windows_amd64_packets", "windows_arm64_packets"):
            with self.subTest(lane=lane):
                missing_packets = copy.deepcopy(candidate)
                del missing_packets["candidate_runs"][lane]
                with self.assertRaisesRegex(ValueError, "Windows AMD64 and ARM64 packet runs"):
                    HELPER.validate_candidate_runs(missing_packets)
        for correction in ({}, {"id": True, "attempt": 1}, {"id": 2, "attempt": 1},
                           {"id": 9, "attempt": 0}):
            with self.subTest(correction=correction):
                invalid = copy.deepcopy(candidate)
                invalid["candidate_runs"]["quality"] = correction
                with self.assertRaises(ValueError):
                    HELPER.validate_candidate_runs(invalid)
        for invalid in (None, True, ["macos-amd64-standard"], "linux-amd64-standard"):
            with self.subTest(deferred=invalid), self.assertRaisesRegex(ValueError, "approved R23"):
                HELPER.validate_candidate_runs(candidate | {"deferred_formal_resource_profile": invalid})

    def test_r23_resource_deferral_requires_the_exact_owned_candidate_push(self):
        repo = {"full_name": self.metadata["repository"]}
        reference = {"id": 30, "attempt": 1}
        path = ".github/workflows/resource-collection.yml"
        workflow = {"id": 55, "path": path}
        run = {"id": 30, "workflow_id": 55, "path": path, "event": "push",
               "head_sha": self.metadata["source"], "run_attempt": 1,
               "head_branch": HELPER.R23_RESOURCE_BRANCH + "first-stable",
               "status": "completed", "conclusion": "success",
               "repository": repo, "head_repository": repo}
        scoped = self.metadata | {"deferred_formal_resource_profile": "macos-amd64-standard"}
        HELPER.validate_candidate_run(scoped, path, workflow, reference, run)
        for declaration, actual in (
            (self.metadata, run),
            (scoped, run | {"event": "workflow_dispatch"}),
            (scoped, run | {"head_branch": "ci/formal-candidate/regular"}),
            (scoped, run | {"head_branch": HELPER.R23_RESOURCE_BRANCH}),
            (scoped, run | {"head_repository": {"full_name": "fork/verysync-sidecar"}}),
        ):
            with self.subTest(declaration=declaration, run=actual), self.assertRaises(ValueError):
                HELPER.validate_candidate_run(declaration, path, workflow, reference, actual)

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

    def test_owned_candidate_push_is_valid_for_all_required_workflows(self):
        repository = {"full_name": self.metadata["repository"]}
        reference = {"id": 30, "attempt": 1}
        branch = "ci/formal-candidate/rc1"
        for lane in HELPER.ACTION_WORKFLOWS.values():
            path = f".github/workflows/{lane}"
            workflow = {"id": 55, "path": path}
            run = {"id": 30, "workflow_id": 55, "path": path, "event": "push",
                   "head_sha": self.metadata["source"], "run_attempt": 1, "head_branch": branch,
                   "status": "completed", "conclusion": "success",
                   "repository": repository, "head_repository": repository}
            with self.subTest(workflow=lane):
                HELPER.validate_candidate_run(self.metadata, path, workflow, reference, run)
            for wrong in ("main", "ci/normal", "ci/formal-candidate/", "verify/r24/windows-amd64-packet-boundary"):
                with self.subTest(workflow=lane, branch=wrong), self.assertRaises(ValueError):
                    HELPER.validate_candidate_run(self.metadata, path, workflow, reference, run | {"head_branch": wrong})
            with self.assertRaises(ValueError):
                HELPER.validate_candidate_run(self.metadata, path, workflow, reference,
                                              run | {"head_repository": {"full_name": "fork/verysync-sidecar"}})

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
        native_diagnostics = [
            {"package": name, "target": "network", "label": "peer-example", "filter": "native_case"}
            for name in sorted(HELPER.NATIVE_TARGETS)
        ]
        native_steps = {
            f"Native helper diagnosis ({row['package']} / peer-example)": (
                "Explicitly prepare the matching fixed private core",
                "Preserve original native effects, strict predicates and deadlines",
                "Require exact owned-executable cleanup after the original result",
            ) for row in native_diagnostics
        }
        manifest = f'{context}/contents/{HELPER.ENGINE_DIAGNOSTIC_MANIFEST}?ref={candidate["source"]}'
        replies[manifest] = diagnostic_catalog_reply(native_diagnostics)
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
            required = HELPER.CANDIDATE_ACTION_JOBS[lane]
            if lane == "engine":
                required = required | native_steps
            jobs = [self.candidate_job(name, index, steps) | {"run_id": run_id}
                    for index, (name, steps) in enumerate(required.items(), 1)]
            endpoint = f"{key}/attempts/2/jobs?per_page=100&page=1"
            replies[endpoint] = {"total_count": len(jobs), "jobs": jobs}
            expected[lane] = {"id": run_id, "attempt": 2,
                              "required_jobs": len(jobs), "listed_jobs": len(jobs)}
        with patch.object(HELPER, "github", side_effect=replies.__getitem__) as github:
            self.assertEqual(HELPER.verify_candidate_actions(candidate), expected)
            self.assertNotIn("publish", [call.args[0] for call in github.call_args_list])
        engine_id = references["engine"]["id"]
        engine_attempt = f"{context}/actions/runs/{engine_id}/attempts/2/jobs?per_page=100&page=1"
        engine_jobs = replies[engine_attempt]["jobs"]
        mac_case = next(job for job in engine_jobs if job["name"] ==
                        "Native helper diagnosis (macos-arm64-standard / peer-example)")
        case_index = engine_jobs.index(mac_case)
        for bad_job, message in (
            (mac_case | {"runner_id": 0, "conclusion": "cancelled", "steps": []}, "did not complete successfully"),
            (mac_case | {"conclusion": "skipped"}, "did not complete successfully"),
            (mac_case | {"steps": mac_case["steps"][:-1]}, "required step"),
        ):
            with self.subTest(message=message), patch.object(HELPER, "github", side_effect=replies.__getitem__):
                engine_jobs[case_index] = bad_job
                try:
                    with self.assertRaisesRegex(ValueError, message):
                        HELPER.verify_candidate_actions(candidate)
                finally:
                    engine_jobs[case_index] = mac_case
        engine_jobs.remove(mac_case)
        replies[engine_attempt]["total_count"] -= 1
        with patch.object(HELPER, "github", side_effect=replies.__getitem__):
            with self.assertRaisesRegex(ValueError, "native diagnostic job roster"):
                HELPER.verify_candidate_actions(candidate)
        engine_jobs.append(mac_case)
        replies[engine_attempt]["total_count"] += 1
        packet_run = references["windows_amd64_packets"]["id"]
        packet_attempt = f"{context}/actions/runs/{packet_run}/attempts/2/jobs?per_page=100&page=1"
        packet_step = next(
            step for job in replies[packet_attempt]["jobs"] for step in job["steps"]
            if "all six scoped AMD64 packet cases" in step["name"]
        )
        packet_step["conclusion"] = "skipped"
        with patch.object(HELPER, "github", side_effect=replies.__getitem__):
            with self.assertRaisesRegex(ValueError, "required step.*AMD64 packet cases"):
                HELPER.verify_candidate_actions(candidate)
        packet_step["conclusion"] = "success"

        arm64_run = references["windows_arm64_packets"]["id"]
        arm64_attempt = f"{context}/actions/runs/{arm64_run}/attempts/2/jobs?per_page=100&page=1"
        arm64_job = replies[arm64_attempt]["jobs"][0]
        for step in arm64_job["steps"]:
            with self.subTest(arm64_step=step["name"]):
                step["conclusion"] = "skipped"
                with patch.object(HELPER, "github", side_effect=replies.__getitem__):
                    with self.assertRaisesRegex(ValueError, "required step.*owned Windows ARM64 link"):
                        HELPER.verify_candidate_actions(candidate)
                step["conclusion"] = "success"

        # A successful resource job without the formal measurement step is only preparation.
        resource_attempt = f'{context}/actions/runs/{references["resources"]["id"]}/attempts/2/jobs?per_page=100&page=1'
        job = replies[resource_attempt]["jobs"][0]
        formal = next(step for step in job["steps"] if "formal" in step["name"])
        formal["conclusion"] = "skipped"
        with patch.object(HELPER, "github", side_effect=replies.__getitem__):
            with self.assertRaisesRegex(ValueError, "required step.*formal"):
                HELPER.verify_candidate_actions(candidate)
        formal["conclusion"] = "success"
        job["steps"] = [step for step in job["steps"]
                        if step["name"] != "Require frozen resource limits and exact candidate identity"]
        with patch.object(HELPER, "github", side_effect=replies.__getitem__):
            with self.assertRaisesRegex(ValueError, "required step.*resource limits"):
                HELPER.verify_candidate_actions(candidate)

        # Restore the complete measurement step before switching to the recorded R23 scope.
        job["steps"] += [{"name": "Require frozen resource limits and exact candidate identity",
                          "status": "completed", "conclusion": "success"}]
        resource_id = references["resources"]["id"]
        resource_run = f"{context}/actions/runs/{resource_id}"
        replies[resource_run].update(event="push", head_branch=HELPER.R23_RESOURCE_BRANCH + "validated")
        intel_resource = "Resource coverage (macos-amd64-standard)"
        jobs = [entry for entry in replies[resource_attempt]["jobs"] if entry["name"] != intel_resource]
        plan = next(entry for entry in jobs if entry["name"] == HELPER.RESOURCE_PLAN)
        record = {"name": HELPER.R23_RESOURCE_RECORD, "status": "completed", "conclusion": "success"}
        plan["steps"].append(record)
        replies[resource_attempt] = {"total_count": len(jobs), "jobs": jobs}
        scoped = candidate | {"deferred_formal_resource_profile": "macos-amd64-standard"}
        with patch.object(HELPER, "github", side_effect=replies.__getitem__):
            verified = HELPER.verify_candidate_actions(scoped)
            self.assertEqual(verified["resources"], {"id": resource_id, "attempt": 2, "required_jobs": 6,
                             "listed_jobs": 6, "deferred_formal_resource_profiles": ["macos-amd64-standard"]})
            record["conclusion"] = "skipped"
            with self.assertRaisesRegex(ValueError, "required step.*R23 Intel"):
                HELPER.verify_candidate_actions(scoped)
            record["conclusion"] = "success"
            remaining_measurement = next(entry for entry in jobs if entry["name"] != HELPER.RESOURCE_PLAN)
            measured = next(step for step in remaining_measurement["steps"] if "formal and two" in step["name"])
            measured["conclusion"] = "skipped"
            with self.assertRaisesRegex(ValueError, "required step.*formal and two"):
                HELPER.verify_candidate_actions(scoped)
            measured["conclusion"] = "success"
            engine_id = references["engine"]["id"]
            engine_attempt = f"{context}/actions/runs/{engine_id}/attempts/2/jobs?per_page=100&page=1"
            engine_jobs = [entry for entry in replies[engine_attempt]["jobs"]
                           if entry["name"] != "macos-amd64-standard"]
            replies[engine_attempt] = {"total_count": len(engine_jobs), "jobs": engine_jobs}
            with self.assertRaisesRegex(ValueError, "omitted a required job"):
                HELPER.verify_candidate_actions(scoped)

    def test_exact_native_catalog_rejects_bad_identity_profile_and_duplicate_job(self):
        package = "macos-arm64-standard"
        rows = [{"package": name, "target": "network", "label": "peer-example", "filter": "native_case"}
                for name in sorted(HELPER.NATIVE_TARGETS)]
        rows += [{"package": package, "target": "upgrade_engine", "filter": "native_upgrade"}]
        endpoint = self.metadata["repository"]
        source = self.metadata["source"]
        manifest = diagnostic_catalog_reply(rows)
        with patch.object(HELPER, "github", return_value=manifest) as get:
            resolved = HELPER.candidate_engine_diagnostics(endpoint, source)
            self.assertIn("Require exact older owned-executable cleanup",
                          resolved[f"Native helper diagnosis ({package} / upgrade_engine)"])
            get.assert_called_once_with(f"{endpoint}/contents/{HELPER.ENGINE_DIAGNOSTIC_MANIFEST}?ref={source}")
        for catalog, message in (
            (manifest | {"sha": "0" * 40}, "identity differs"),
            (diagnostic_catalog_reply(rows[:-2]), "omitted a standard profile"),
            (diagnostic_catalog_reply(rows + [rows[0]]), "repeated a case"),
        ):
            with self.subTest(message=message), patch.object(HELPER, "github", return_value=catalog):
                with self.assertRaisesRegex(ValueError, message):
                    HELPER.candidate_engine_diagnostics(endpoint, source)

    def test_candidate_preflight_records_one_package_and_hosted_identity(self):
        candidate = self.metadata | {
            "version": "0.1.0",
            "candidate_runs": {
                lane: {"id": index, "attempt": 1}
                for index, lane in enumerate(HELPER.ACTION_WORKFLOWS, 1)
            },
        }
        with tempfile.TemporaryDirectory() as root:
            package = Path(root) / "verysync-sidecar-0.1.0.crate"
            metadata = Path(root) / "candidate.json"
            metadata.write_text(json.dumps(candidate), encoding="utf-8")
            output = io.StringIO()
            with (
                patch("sys.argv", ["release-helper", "--metadata", str(metadata), "--check-candidate", str(package)]),
                patch("sys.stdout", output),
                patch.object(HELPER, "verify_local_package", return_value=9) as local,
                patch.object(HELPER, "verify_candidate_actions", return_value=candidate["candidate_runs"]) as hosted,
                patch.object(HELPER, "verify") as registry,
                patch.object(HELPER, "publish") as publish,
            ):
                HELPER.main()
            local.assert_called_once_with(candidate, package)
            hosted.assert_called_once_with(candidate)
            registry.assert_not_called()
            publish.assert_not_called()
        self.assertEqual(json.loads(output.getvalue()), {
            "local_package_verified": True, "candidate_actions_verified": True,
            "source": candidate["source"], "tree": candidate["tree"],
            "package_sha256": candidate["package_sha256"], "packaged_files": 9,
            "runs": candidate["candidate_runs"],
        })

    def test_candidate_preflight_rejects_either_side_of_the_binding(self):
        candidate = self.metadata | {
            "candidate_runs": {
                lane: {"id": index, "attempt": 1}
                for index, lane in enumerate(HELPER.ACTION_WORKFLOWS, 1)
            },
        }
        package = Path("private-candidate.crate")
        with (
            patch.object(HELPER, "verify_local_package", side_effect=ValueError("checkout source or tree differs")),
            patch.object(HELPER, "verify_candidate_actions") as hosted,
        ):
            with self.assertRaisesRegex(ValueError, "checkout source or tree differs"):
                HELPER.verify_candidate_preflight(candidate, package)
            hosted.assert_not_called()
        with (
            patch.object(HELPER, "verify_local_package", return_value=9),
            patch.object(HELPER, "verify_candidate_actions", side_effect=ValueError("candidate run source differs")),
        ):
            with self.assertRaisesRegex(ValueError, "candidate run source differs"):
                HELPER.verify_candidate_preflight(candidate, package)

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

    def stable_package(self):
        self.metadata["version"] = "0.1.0"
        return self.package()

    def test_stable_registry_checks_exact_download_and_cargo_sparse_index(self):
        metadata, content = self.stable_package()
        crate, version = metadata["crate"], metadata["version"]
        api = f"https://crates.io/api/v1/crates/{crate}"
        index = f"https://index.crates.io/ve/ry/{crate}"
        publisher = {"login": metadata["publisher"], "id": metadata["publisher_id"]}
        version_row = {"num": version, "checksum": metadata["package_sha256"],
                       "published_by": publisher, "yanked": False}
        index_row = {"name": crate, "vers": version, "cksum": metadata["package_sha256"], "yanked": False}
        replies = {
            f"{api}/{version}": json.dumps({"version": version_row}).encode(),
            f"{api}/owners": json.dumps({"users": [publisher]}).encode(),
            f"https://static.crates.io/crates/{crate}/{crate}-{version}.crate": content,
            index: json.dumps(index_row).encode() + b"\n",
        }
        with (
            patch.object(HELPER, "verify_candidate_preflight", return_value={"local_package_verified": True}) as preflight,
            patch.object(HELPER, "public_bytes", side_effect=replies.__getitem__) as reads,
            patch.object(HELPER, "github") as github,
        ):
            path = Path("stable-fixture.crate")
            self.assertEqual(HELPER.verify_stable_registry(metadata, path), {
                "local_package_verified": True, "registry_verified": True,
                "sparse_index_verified": True, "version": version,
            })
            preflight.assert_called_once_with(metadata, path)
            github.assert_not_called()
            self.assertEqual([call.args[0] for call in reads.call_args_list], list(replies))
            for bad_index in (b"", replies[index] * 2,
                              json.dumps(index_row | {"cksum": "0" * 64}).encode(),
                              json.dumps(index_row | {"yanked": True}).encode()):
                with self.subTest(index=bad_index), self.assertRaisesRegex(ValueError, "sparse index"):
                    replies[index] = bad_index
                    HELPER.verify_stable_registry(metadata, path)
            replies[f"{api}/{version}"] = json.dumps({"version": version_row | {"yanked": True}}).encode()
            with self.assertRaisesRegex(ValueError, "yanked"):
                HELPER.verify_stable_registry(metadata, path)

    def test_stable_registry_rejects_prerelease_and_wrong_publisher_before_reads(self):
        for change in ({"version": "0.1.0-alpha.2"}, {"version": "01.0.0"}, {"publisher_id": 1}):
            candidate = self.metadata | {"version": "0.1.0"} | change
            with (
                self.subTest(change=change),
                patch.object(HELPER, "verify_candidate_preflight") as preflight,
                patch.object(HELPER, "public_bytes") as registry,
            ):
                with self.assertRaisesRegex(ValueError, "stable version|publisher"):
                    HELPER.verify_stable_registry(candidate, Path("stable-fixture.crate"))
                preflight.assert_not_called()
                registry.assert_not_called()

    def test_stable_registry_stops_after_failed_candidate_gate(self):
        candidate, _ = self.stable_package()
        with (
            patch.object(HELPER, "verify_candidate_preflight", side_effect=ValueError("candidate run source differs")),
            patch.object(HELPER, "public_bytes") as registry,
        ):
            with self.assertRaisesRegex(ValueError, "candidate run source differs"):
                HELPER.verify_stable_registry(candidate, Path("stable-fixture.crate"))
            registry.assert_not_called()

    def test_stable_release_checks_actual_tag_and_visible_release_by_read_only_calls(self):
        candidate, _ = self.stable_package()
        tag = "v0.1.0"
        repository = candidate["repository"]
        base = f"repos/{repository}"
        tag_path = f"{base}/git/ref/tags/{tag}"
        release_path = f"{base}/releases/tags/{tag}"
        tag_payload = {"object": {"type": "commit", "sha": candidate["source"]}}
        release_payload = {"tag_name": tag, "draft": False, "prerelease": False,
                           "published_at": "2026-11-19T00:00:00Z",
                           "html_url": f"https://github.com/{repository}/releases/tag/{tag}"}
        replies = {tag_path: tag_payload, release_path: release_payload}

        def read(path, payload=None, optional=False):
            self.assertIsNone(payload)
            return replies[path]

        with (
            patch.object(HELPER, "verify_stable_registry", return_value={"registry_verified": True}) as registry,
            patch.object(HELPER, "github", side_effect=read),
        ):
            path = Path("stable-fixture.crate")
            self.assertEqual(HELPER.verify_stable_release(candidate, path), {
                "registry_verified": True, "release": release_payload["html_url"], "tag": tag,
            })
            registry.assert_called_once_with(candidate, path)
            for field, bad in (("draft", True), ("prerelease", True), ("tag_name", "v0.1.1"),
                               ("published_at", None), ("html_url", "https://elsewhere.example")):
                replies[release_path] = release_payload | {field: bad}
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, "published GitHub release"):
                    HELPER.verify_stable_release(candidate, path)
            replies[release_path] = release_payload
            replies[tag_path] = {"object": {"type": "tag", "sha": "1" * 40}}
            replies[f"{base}/git/tags/" + "1" * 40] = tag_payload
            self.assertEqual(HELPER.verify_stable_release(candidate, path)["tag"], tag)
            replies[release_path] = None
            with self.assertRaisesRegex(ValueError, "published GitHub release"):
                HELPER.verify_stable_release(candidate, path)
            replies[tag_path] = {"object": {"type": "commit", "sha": "0" * 40}}
            with self.assertRaisesRegex(ValueError, "tag source differs"):
                HELPER.verify_stable_release(candidate, path)

    def test_stable_cli_wires_registry_and_release_modes_without_publication(self):
        candidate, _ = self.stable_package()
        with tempfile.TemporaryDirectory() as root:
            metadata = Path(root) / "metadata.json"
            metadata.write_text(json.dumps(candidate), encoding="utf-8")
            path = Path(root) / "stable-fixture.crate"
            for flag, name in (("--verify-stable-registry", "verify_stable_registry"),
                               ("--verify-stable-release", "verify_stable_release")):
                with (
                    self.subTest(flag=flag),
                    patch("sys.argv", ["release-helper", "--metadata", str(metadata), flag, str(path)]),
                    patch("sys.stdout", io.StringIO()) as output,
                    patch.object(HELPER, name, return_value={"verified": True}) as check,
                    patch.object(HELPER, "publish") as publish,
                ):
                    HELPER.main()
                    check.assert_called_once_with(candidate, path)
                    publish.assert_not_called()
                    self.assertEqual(json.loads(output.getvalue()), {"verified": True})


if __name__ == "__main__":
    unittest.main()
