"""Exercise the visible fields and trust lookup with a private OpenSSH database."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

RUNTIME = Path(__file__).resolve().parents[1] / "runtime-next"
sys.path.insert(0,str(RUNTIME))
from r33_cases import TWO_CORE_SCOPES
from r33_single import linux_destination, show_confirmation, update_profile
from r33_ssh import Destination, SSHConfigurationError, host_key_identity, saved_host_pin


class SixInputs(unittest.TestCase):
    def setUp(self):
        self.sandbox = tempfile.TemporaryDirectory()
        self.addCleanup(self.sandbox.cleanup)
        self.base = Path(self.sandbox.name)
        ssh = self.base/".ssh"
        ssh.mkdir(mode=0o700)
        self.known = ssh/"known_hosts"
        keyfile = self.base/"host"
        subprocess.run(["/usr/bin/ssh-keygen","-q","-t","ed25519","-N","","-f",str(keyfile)],
                       check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        keyline = keyfile.with_suffix(".pub").read_text().split()
        self.key, self.fingerprint = host_key_identity(" ".join(keyline[:2]))

    def test_three_visible_values_restore_hashed_saved_identity(self):
        self.known.write_text(f"[127.0.0.1]:32425 {self.key}\n")
        subprocess.run(["/usr/bin/ssh-keygen","-q","-H","-f",str(self.known)],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        assert self.known.read_text().startswith("|1|")
        with patch("r33_ssh.Path.home",return_value=self.base), \
             patch("builtins.input",side_effect=["127.0.0.1","32425","root"]) as ui, \
             patch("r33_single.first_host_pin",side_effect=AssertionError("Saved identity must take precedence")):
            profile = linux_destination()
        self.assertEqual(ui.call_count,3)
        self.assertEqual(profile["trust_source"],"saved")
        self.assertEqual(profile["fingerprint"],self.fingerprint)
        with patch("r33_ssh.Path.home",return_value=self.base):
            self.assertIsNone(saved_host_pin("127.0.0.1",32426))

    def test_unseen_address_is_explained_in_existing_start_confirmation(self):
        with patch("r33_ssh.Path.home",return_value=self.base), \
             patch("r33_ssh.presented_host_keys",return_value=iter([(self.key,self.fingerprint)])) as scan, \
             patch("builtins.input",side_effect=["127.0.0.1","",""]) as ui:
            profile = linux_destination()
        self.assertEqual(ui.call_count,3)
        self.assertEqual((profile["port"],profile["user"],profile["trust_source"]),(22,"root","first-use"))
        scan.assert_called_once_with("127.0.0.1",22)
        review = io.StringIO()
        with redirect_stdout(review):
            show_confirmation("0"*32,2_000_000_000,{"linux":((),profile),"pro":((),{})})
        self.assertIn("START also accepts the displayed new server identity",review.getvalue())
        self.assertIn(self.fingerprint,review.getvalue())
        destination=Destination.parse(profile,allow_root=True)
        argv=destination.command(self.base,remote_entry="fixed test entry")
        self.assertIn("StrictHostKeyChecking=yes",argv)
        self.assertIn("NumberOfPasswordPrompts=1",argv)
        self.assertIn("PreferredAuthentications=password",argv)
        self.assertIn(self.key,(self.base/"pinned-host-key").read_text())

    def test_revoked_entry_refused_before_contact(self):
        self.known.write_text(f"@revoked 127.0.0.1 {self.key}\n")
        with patch("r33_ssh.Path.home",return_value=self.base), \
             patch("r33_ssh.presented_host_keys",side_effect=AssertionError("revocation must stop")), \
             self.assertRaisesRegex(SSHConfigurationError,"revoked"):
            saved_host_pin("127.0.0.1",22)

    def test_preserve_linux_first_then_pro_order(self):
        profile = self.base/"operator.json"
        profile.write_text(json.dumps({
            "pro": {"allow": ["observe","refresh-paid",*TWO_CORE_SCOPES["pro-cases"]],
                    "connection":{"two_core_scope":"pro-cases"}}
        }))
        update_profile(profile,{"host":"127.0.0.1"})
        self.assertEqual(list(json.loads(profile.read_text())),["linux","pro"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
