"""The trust helper must reject local and unowned paths before native commands."""
import importlib.util
import json
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
    def test_macos_removal_uses_exact_sha256_and_requires_independent_trust_absence(self):
        path = Path("/synthetic/vs-ldap-trusted-owned/synthetic-ldap-ca.pem")
        identity = {"sha256": "a" * 64, "sha1": "b" * 40, "common_name": "synthetic"}
        with mock.patch.object(TRUST.sys, "platform", "darwin"):
            with mock.patch.object(TRUST, "macos_certificate_absent", return_value=False):
                with mock.patch.object(TRUST, "run", return_value=0) as run:
                    with mock.patch.object(TRUST, "probe_macos_admin_trust", return_value=0) as probe:
                        TRUST.mutate("remove", path, identity)
            self.assertEqual(run.call_args_list, [
                mock.call(["sudo", "-n", "security", "delete-certificate", "-t", "-Z", "a" * 64,
                           "/Library/Keychains/System.keychain"], path),
            ])
            self.assertEqual(probe.call_count, 1)

    def test_macos_already_absent_keychain_and_trust_need_no_mutating_command(self):
        with mock.patch.object(TRUST.sys, "platform", "darwin"):
            with mock.patch.object(TRUST, "macos_certificate_absent", return_value=True):
                with mock.patch.object(TRUST, "probe_macos_admin_trust", return_value=0):
                    with mock.patch.object(TRUST, "run", side_effect=AssertionError("already absent state modified")):
                        TRUST.mutate("remove", Path("/synthetic"), {"sha256": "a" * 64})

    def test_macos_stale_or_unobservable_admin_trust_is_a_cleanup_failure(self):
        with mock.patch.object(TRUST.sys, "platform", "darwin"):
            for status in [3, 1]:
                with self.subTest(status=status), mock.patch.object(TRUST, "run", return_value=0):
                    with mock.patch.object(TRUST, "macos_certificate_absent", return_value=True):
                        with mock.patch.object(TRUST, "probe_macos_admin_trust", return_value=status):
                            with self.assertRaises(RuntimeError):
                                TRUST.mutate("remove", Path("/synthetic"), {"sha256": "a" * 64})

    def test_failed_cleanup_keeps_exact_owned_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic-ldap-ca.pem"
            path.write_text("synthetic")
            identity = {"sha256": "a" * 64}
            lease = path.parent / ".ephemeral-ci-ca-lease.json"
            lease.write_text(json.dumps(identity))
            with mock.patch.object(TRUST, "require_scope", return_value=path):
                with mock.patch.object(TRUST, "certificate_identity", return_value=identity):
                    with mock.patch.object(TRUST, "mutate", side_effect=RuntimeError("stale trust")):
                        with self.assertRaises(RuntimeError):
                            TRUST.main(["remove", "--certificate", str(path), "--allow-ephemeral-runner-system-trust"])
            self.assertEqual(json.loads(lease.read_text()), identity)

    def test_probe_never_calls_a_mutation_and_distinguishes_present_empty_settings(self):
        for native, expected in [(0, 3), (-25300, 0)]:
            with self.subTest(status=native), mock.patch.object(TRUST.sys, "platform", "darwin"):
                with mock.patch.object(TRUST, "require_scope", return_value=Path("/synthetic")):
                    with mock.patch.object(TRUST, "certificate_identity", return_value={"sha256": "a" * 64}):
                        with mock.patch.object(TRUST, "macos_admin_trust_status", return_value=native):
                            with mock.patch.object(TRUST, "mutate", side_effect=AssertionError("probe mutated trust")):
                                self.assertEqual(TRUST.main(["probe-admin-trust", "--certificate", "/synthetic",
                                                             "--allow-ephemeral-runner-system-trust"]), expected)

    def test_unrecognized_native_trust_read_status_is_not_absence(self):
        with mock.patch.object(TRUST.sys, "platform", "darwin"):
            with mock.patch.object(TRUST, "require_scope", return_value=Path("/synthetic")):
                with mock.patch.object(TRUST, "certificate_identity", return_value={"sha256": "a" * 64}):
                    with mock.patch.object(TRUST, "macos_admin_trust_status", return_value=-1):
                        with self.assertRaises(RuntimeError):
                            TRUST.main(["probe-admin-trust", "--certificate", "/synthetic",
                                        "--allow-ephemeral-runner-system-trust"])

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
