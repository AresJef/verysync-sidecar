"""Boundary contracts for an explicit private fixture, without network or trust writes."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "ldap_tls_fixture", Path(__file__).resolve().parents[1] / "ldap_tls_fixture.py")
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class PrivateTlsFixtureTests(unittest.TestCase):
    def test_only_the_explicit_public_ca_section_supplies_the_password(self):
        source = ("### <ins>A. Self-Signed Certificate</ins>\nPassword: unrelated\n"
                  "### <ins>B. Public CA Certificate</ins> warning\nPassword: **synthetic value**\n"
                  "### <ins>C. Cert Bundle by Request</ins>\nPassword: unrelated\n")
        self.assertEqual(FIXTURE.publisher_password(source), b"synthetic value")
        with self.assertRaises(ValueError):
            FIXTURE.publisher_password(source.replace("B. Public CA Certificate", "other"))

    def test_dns_requires_every_result_to_be_loopback(self):
        FIXTURE.require_loopback(["127.0.0.1", "::1"])
        for addresses in [[], ["198.18.6.219"], ["127.0.0.1", "192.0.2.1"], ["invalid"]]:
            with self.subTest(addresses=addresses), self.assertRaises(ValueError):
                FIXTURE.require_loopback(addresses)

    def test_resolver_is_bounded_and_requires_ipv4_loopback(self):
        for content, accepted in [(b'["127.0.0.1"]', True), (b'["::1"]', False),
                                  (b'["127.0.0.1","198.18.6.219"]', False),
                                  (b" " * 4097, False)]:
            result = mock.Mock(stdout=content)
            with mock.patch.object(FIXTURE.subprocess, "run", return_value=result) as run:
                if accepted:
                    FIXTURE.check_dns()
                else:
                    with self.assertRaises(ValueError):
                        FIXTURE.check_dns()
                self.assertEqual(run.call_args.kwargs["timeout"], 8)

    def test_private_reads_refuse_oversize_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owned"
            path.write_bytes(b"private")
            self.assertEqual(FIXTURE.read_bounded(path, 7), b"private")
            with self.assertRaises(ValueError):
                FIXTURE.read_bounded(path, 6)
            with mock.patch.object(Path, "is_symlink", return_value=True):
                with self.assertRaises(ValueError):
                    FIXTURE.read_bounded(path, 7)

    def test_manifest_cannot_select_other_hosts_keys_or_parent_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            base = {"hostname": FIXTURE.HOSTNAME, "certificate": "certificate-chain.pem",
                    "private_key": "private-key.pem", "leaf_sha256": FIXTURE.LEAF_SHA256,
                    "bundle_sha256": FIXTURE.BUNDLE_SHA256, "source": FIXTURE.SOURCE}
            for key, value in [("hostname", "example.com"), ("certificate", "../unowned"),
                               ("private_key", "/unowned"), ("leaf_sha256", "a" * 64)]:
                changed = dict(base, **{key: value})
                path.write_text(json.dumps(changed))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    FIXTURE.load_manifest(path)

    def test_download_refuses_changed_or_oversized_pinned_content(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"changed"
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(FIXTURE.urllib.request, "build_opener", return_value=opener):
            for limit in [2, 128]:
                with self.assertRaises(ValueError):
                    FIXTURE.download(FIXTURE.BUNDLE_URL, "a" * 64, limit)

    def test_cleanup_refuses_unowned_paths_without_reading_or_deleting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unrelated = root / "user-data"
            unrelated.mkdir()
            path = unrelated / "manifest.json"
            path.write_text("must remain")
            with mock.patch.object(FIXTURE, "load_manifest", side_effect=AssertionError("unowned file read")):
                with self.assertRaises(ValueError):
                    FIXTURE.cleanup(path, root)
            self.assertEqual(path.read_text(), "must remain")

    def test_private_files_are_exclusive_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-key.pem"
            FIXTURE.write_private(path, b"synthetic test value")
            with self.assertRaises(FileExistsError):
                FIXTURE.write_private(path, b"replacement")
            self.assertEqual(path.read_bytes(), b"synthetic test value")


if __name__ == "__main__":
    unittest.main()
