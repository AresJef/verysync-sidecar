"""The trust helper must reject local and unowned paths before native commands."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "ephemeral_ci_trust", Path(__file__).resolve().parents[1] / "ephemeral-ci-trust.py")
TRUST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRUST)


class EphemeralTrustScopeTests(unittest.TestCase):
    def test_unselected_local_or_self_hosted_execution_cannot_reach_native_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            directory = root / "vs-ldap-trusted-synthetic"
            directory.mkdir()
            certificate = directory / "synthetic-ldap-ca.pem"
            certificate.write_text("deliberately not a certificate")
            environment = {"CI": "true", "GITHUB_ACTIONS": "true",
                           "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_TEMP": str(root)}
            for enabled, changes in [(False, {}), (True, {"CI": "false"}),
                                     (True, {"GITHUB_ACTIONS": "false"}),
                                     (True, {"RUNNER_ENVIRONMENT": "self-hosted"})]:
                with self.subTest(enabled=enabled, changes=changes):
                    with mock.patch.dict(os.environ, {**environment, **changes}, clear=True):
                        with mock.patch.object(TRUST, "run", side_effect=AssertionError("native command attempted")):
                            with mock.patch.object(TRUST, "certificate_identity", side_effect=AssertionError("scope bypassed")):
                                with self.assertRaises(ValueError):
                                    TRUST.main(["install", "--certificate", str(certificate)] +
                                               (["--allow-ephemeral-runner-system-trust"] if enabled else []))

    def test_certificate_must_be_bounded_and_in_its_dedicated_runner_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            environment = {"CI": "true", "GITHUB_ACTIONS": "true",
                           "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_TEMP": str(root)}
            unrelated = root / "unrelated"
            unrelated.mkdir()
            certificate = unrelated / "synthetic-ldap-ca.pem"
            certificate.write_text("synthetic")
            selected = root / "vs-ldap-trusted-synthetic"
            selected.mkdir()
            oversized = selected / "synthetic-ldap-ca.pem"
            oversized.write_bytes(b"x" * 16385)
            with mock.patch.dict(os.environ, environment, clear=True):
                for path in [certificate, oversized, Path("synthetic-ldap-ca.pem")]:
                    with self.subTest(path=path):
                        with mock.patch.object(TRUST, "certificate_identity", side_effect=AssertionError("scope bypassed")):
                            with self.assertRaises(ValueError):
                                TRUST.main(["install", "--certificate", str(path), "--allow-ephemeral-runner-system-trust"])


if __name__ == "__main__":
    unittest.main()
