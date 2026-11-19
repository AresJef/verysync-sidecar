import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import yaml

SOURCE = Path(__file__).resolve().parents[1] / "host-test-cargo.py"
SPEC = importlib.util.spec_from_file_location("host_cargo", SOURCE)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)

class HostTestElevationContracts(unittest.TestCase):
    def test_packet_case_keeps_the_native_process_unelevated_and_requires_its_scope(self):
        with tempfile.TemporaryDirectory() as folder:
            artifact, env, argv = self.fixture(Path(folder))
            receipt = Path(env["VERYSYNC_HOST_TEST_RECEIPT"])
            row = json.loads(receipt.read_text()); row["case"] = HELPER.PACKET_CASE
            receipt.write_text(json.dumps(row))
            argv = [HELPER.PACKET_CASE if x == HELPER.CASE else x for x in argv]
            with patch.object(HELPER.sys, "platform", "darwin"), self.assertRaises(ValueError):
                HELPER.packet_command(argv, env)
            env["VERYSYNC_TEST_ALLOW_PACKET_CAPTURE"] = "github-actions-owned-loopback-headers"
            for host in ["darwin", "linux"]:
                with patch.object(HELPER.sys, "platform", host):
                    command = HELPER.packet_command(argv, env)
                self.assertEqual(command, [str(artifact), HELPER.PACKET_CASE, "--exact", "--test-threads=1", "--nocapture"])
                self.assertNotIn("sudo", " ".join(command))
            with patch.object(HELPER.sys, "platform", "darwin"), self.assertRaises(ValueError):
                HELPER.packet_command(argv + ["--ignored"], env)
            artifact.write_bytes(b"changed synthetic artifact")
            with patch.object(HELPER.sys, "platform", "linux"), self.assertRaises(ValueError):
                HELPER.packet_command(argv, env)

    def test_ipv6_packet_case_is_exact_pinned_unelevated_and_not_a_host_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            artifact, env, argv=self.fixture(Path(folder))
            receipt=Path(env["VERYSYNC_HOST_TEST_RECEIPT"])
            row=json.loads(receipt.read_text());row["case"]=HELPER.PACKET_IPV6_CASE
            receipt.write_text(json.dumps(row))
            argv=[HELPER.PACKET_IPV6_CASE if x==HELPER.CASE else x for x in argv]
            env["VERYSYNC_TEST_ALLOW_PACKET_CAPTURE"]="github-actions-owned-loopback-headers"
            for host in ["darwin","linux"]:
                with patch.object(HELPER.sys,"platform",host):
                    self.assertEqual(HELPER.packet_command(argv,env),[str(artifact),HELPER.PACKET_IPV6_CASE,"--exact","--test-threads=1","--nocapture"])
                    with self.assertRaises(ValueError):
                        HELPER.packet_command([HELPER.PACKET_CASE if x==HELPER.PACKET_IPV6_CASE else x for x in argv],env)
            with patch.object(HELPER.sys,"platform","linux"),self.assertRaises(ValueError):
                HELPER.root_command(argv,env)

    def test_privileged_effect_uses_both_native_linux_architectures(self):
        workflow = SOURCE.parents[1] / ".github/workflows/engine-tests.yml"
        job = yaml.safe_load(workflow.read_text())["jobs"]["host-watch-limit-positive"]
        self.assertEqual(job["runs-on"], "${{ matrix.runner }}")
        self.assertEqual(job["strategy"]["matrix"]["include"], [
            {"runner": "ubuntu-24.04", "package": "linux-amd64-standard"},
            {"runner": "ubuntu-24.04-arm", "package": "linux-arm64-standard"},
        ])
        self.assertFalse(job["strategy"]["fail-fast"])
        self.assertEqual(job["env"]["VERYSYNC_TEST_ALLOW_HOST_CONFIGURATION"], HELPER.SCOPE)
        commands = "\n".join(step.get("run", "") for step in job["steps"])
        self.assertIn('--package "${{ matrix.package }}"', commands)
        self.assertIn("host-test-cargo.py prepare", commands)
        self.assertIn("--test-filter " + HELPER.CASE, commands)
        self.assertIn("prepare-test-engine.py check-cleanup", commands)

    def test_sleep_case_needs_its_own_scope_and_keeps_exact_artifact_elevation(self):
        case = "linux_sleep_inhibitor_cases::native::privileged_native_linux_sleep_inhibitor_tracks_transfer_and_releases"
        with tempfile.TemporaryDirectory() as folder:
            artifact, env, argv = self.fixture(Path(folder))
            receipt = Path(env["VERYSYNC_HOST_TEST_RECEIPT"])
            row = json.loads(receipt.read_text()); row["case"] = case
            receipt.write_text(json.dumps(row))
            argv = [case if arg == HELPER.CASE else arg for arg in argv]
            with patch.object(HELPER.sys, "platform", "linux"), self.assertRaises(ValueError):
                HELPER.root_command(argv, env)
            env["VERYSYNC_TEST_ALLOW_SLEEP_INHIBITOR"] = HELPER.SCOPE
            with patch.object(HELPER.sys, "platform", "linux"):
                command = HELPER.root_command(argv, env)
            self.assertEqual(command[0], "/usr/bin/sudo")
            self.assertIn(str(artifact), command)
            self.assertEqual(command[-4], case)
            self.assertIn("--exact", command)
            self.assertNotIn("GITHUB_TOKEN", " ".join(command))

    def test_linux_sleep_effect_gate_has_both_native_profiles_and_separate_scope(self):
        workflow = SOURCE.parents[1] / ".github/workflows/engine-tests.yml"
        job = yaml.safe_load(workflow.read_text())["jobs"]["linux-sleep-inhibitor-positive"]
        self.assertEqual(job["runs-on"], "$"+"{{ matrix.runner }}")
        self.assertEqual(job["strategy"]["matrix"]["include"], [
            {"runner": "ubuntu-24.04", "package": "linux-amd64-standard"},
            {"runner": "ubuntu-24.04-arm", "package": "linux-arm64-standard"},
        ])
        self.assertEqual(job["env"]["VERYSYNC_TEST_ALLOW_SLEEP_INHIBITOR"], HELPER.SCOPE)
        commands = "\n".join(step.get("run", "") for step in job["steps"])
        self.assertIn("--case " + HELPER.SLEEP_CASE, commands)
        self.assertIn("--test-filter " + HELPER.SLEEP_CASE, commands)
        self.assertIn("prepare-test-engine.py check-cleanup", commands)
        self.assertNotIn("/requestsoverride", commands)
        self.assertNotIn("systemctl start", commands)

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
