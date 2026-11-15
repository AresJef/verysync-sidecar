import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "host-test-cargo.py"
SPEC = importlib.util.spec_from_file_location("host_cargo", SOURCE)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)

class HostTestElevationContracts(unittest.TestCase):
    def fixture(self, root):
        artifact = root / "owned test executable"
        artifact.write_bytes(b"synthetic artifact; never executed")
        envfile = root / "github-env"
        args = SimpleNamespace(cargo="explicit-cargo", toolchain="1.85.0",
                               parent=root, github_env=envfile)
        row = {"reason":"compiler-artifact","target":{"name":HELPER.TARGET,"kind":["test"]},
               "profile":{"test":True},"executable":str(artifact)}
        result = SimpleNamespace(returncode=0, stderr="", stdout=json.dumps(row))
        with patch.object(HELPER.subprocess, "run", return_value=result) as build:
            values = HELPER.prepare(args)
        self.assertEqual(build.call_args.args[0][0], "explicit-cargo")
        self.assertNotIn("sudo", build.call_args.args[0])
        env = {**values,"GITHUB_ACTIONS":"true","VERYSYNC_TEST_ALLOW_HOST_CONFIGURATION":HELPER.SCOPE}
        argv = ["+1.85.0","test","--features","engine-tests","--test",HELPER.TARGET,
                "--offline","--locked",HELPER.CASE,"--","--test-threads=1","--nocapture"]
        return artifact, env, argv

    def test_only_prebuilt_pinned_exact_case_is_elevated_and_secrets_are_not_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            artifact, env, argv = self.fixture(Path(folder))
            env["GITHUB_TOKEN"] = "synthetic-private-token"
            with patch.object(HELPER.sys, "platform", "linux"):
                command = HELPER.root_command(argv, env)
            self.assertEqual(command[0], "/usr/bin/sudo")
            self.assertIn(str(artifact), command)
            self.assertIn("--exact", command)
            self.assertNotIn("GITHUB_TOKEN", " ".join(command))
            self.assertNotIn("synthetic-private-token", " ".join(command))
            self.assertEqual(command[-4], HELPER.CASE)

    def test_missing_scope_or_wrong_filter_is_refused_without_invoking_sudo(self):
        with tempfile.TemporaryDirectory() as folder:
            _, env, argv = self.fixture(Path(folder))
            for replacement in [{**env,"GITHUB_ACTIONS":"false"},
                                {**env,"VERYSYNC_TEST_ALLOW_HOST_CONFIGURATION":"missing"}]:
                with patch.object(HELPER.sys,"platform","linux"), self.assertRaises(ValueError):
                    HELPER.root_command(argv,replacement)
            with patch.object(HELPER.sys,"platform","linux"), self.assertRaises(ValueError):
                HELPER.root_command(argv[:8]+["other-case"]+argv[9:],env)

    def test_changed_artifact_or_non_linux_host_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            artifact, env, argv = self.fixture(Path(folder))
            with patch.object(HELPER.sys,"platform","darwin"), self.assertRaises(ValueError):
                HELPER.root_command(argv,env)
            artifact.write_bytes(b"changed synthetic artifact")
            with patch.object(HELPER.sys,"platform","linux"), self.assertRaises(ValueError):
                HELPER.root_command(argv,env)
