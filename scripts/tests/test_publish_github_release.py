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
        for source in (self.metadata["source"], "0" * 40):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                for name, payload in ((".cargo_vcs_info.json", json.dumps({"git": {"sha1": source}})),
                                      ("Cargo.toml", '[package]\nname="verysync-sidecar"\nversion="0.1.0-alpha.1"\n')):
                    data = payload.encode()
                    info = tarfile.TarInfo(f'verysync-sidecar-{self.metadata["version"]}/{name}')
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            content = buffer.getvalue()
            candidate = copy.deepcopy(self.metadata)
            candidate["package_sha256"] = hashlib.sha256(content).hexdigest()
            if source == self.metadata["source"]:
                HELPER.validate_package(candidate, content)
            else:
                with self.assertRaises(ValueError):
                    HELPER.validate_package(candidate, content)

    def test_missing_or_failed_native_target_is_rejected(self):
        jobs = [{"name": name, "status": "completed", "conclusion": "success"}
                for name in HELPER.NATIVE_TARGETS]
        HELPER.validate_jobs(jobs, HELPER.NATIVE_TARGETS)
        with self.assertRaises(ValueError):
            HELPER.validate_jobs(jobs[:-1], HELPER.NATIVE_TARGETS)
        jobs[0]["conclusion"] = "failure"
        with self.assertRaises(ValueError):
            HELPER.validate_jobs(jobs, HELPER.NATIVE_TARGETS)

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
