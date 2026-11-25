"""Regression for qualification and native test dispatch in one foreground."""

import asyncio
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import time
import unittest
from unittest.mock import AsyncMock, patch

import r33_licensed_validation as entry
from r33_gateway_crossnetwork import ContinuousMac, LinuxGateway
from test_crossnetwork_commands import FIXTURE, RUN, Source, Target


class SyntheticNamedCases:
    def __init__(self, source):
        self.source = source
        self.active = None

    async def execute(self, work, before_send):
        before_send()
        name = work.request.operation
        self.source.trace.append("case:" + name)
        if name == "observe":
            return await self.source.execute("inspect") | {"ok": True}
        family, action = name.rsplit("-", 1)
        if action == "prepare":
            assert self.active is None
            self.active = family
        if action == "finish":
            assert self.active == family
            self.active = None
        return {"ok": True, "device": self.source.initial["device"]}

    async def stop(self, unknown, journal):
        self.active = None
        return await self.source.stop()


class PaidSource(Source):
    def __init__(self, trace):
        super().__init__(trace)
        self.initial = self.initial | {"version": "2.33.2"}
        self.named_cases = SyntheticNamedCases(self)

    async def execute(self, action, fields=None):
        if action in ("login", "inspect", "gateway-qualify"):
            self.trace.append("source:" + action)
            return self.initial | {
                "account": "logged-in", "login_acknowledged": action == "login",
                "pro_observations": [{"reported_trial": False, "expiry_observation": "perpetual"}],
            }
        if action == "gateway-finish":
            self.trace.append("source:gateway-finish")
            return {"ok": True, "same_device": True}
        return await super().execute(action, fields)

    async def stop(self):
        self.trace.append("source:stop")
        return {"normal": True}


class LinuxRole:
    initial = {"device": "synthetic-local-api-core", "version": "2.33.2"}

    def __init__(self, trace, qualification=None, unconfirmed=False, file_uncertain=False,
                 peer_uncertain=False):
        self.trace = trace
        self.qualification = qualification or {"state": "license-required", "code": 3001}
        self.unconfirmed = unconfirmed
        self.file_uncertain = file_uncertain
        self.peer_uncertain = peer_uncertain

    async def execute(self, action, fields=None, timeout=50, *, operator_stop=None):
        self.trace.append("local-api:" + action)
        if action == "local-api-qualify":
            return self.qualification
        if action == "local-api-file-verify":
            if self.file_uncertain:
                raise TimeoutError("The synthetic index case did not return a cleanup receipt.")
            return {"ok": True, "device": self.initial["device"], "fixture_unregistered": True,
                    "checks": {"SYM-090": {"state": "observed"}}}
        if action == "local-api-peer-verify":
            if self.peer_uncertain:
                raise TimeoutError("The synthetic peer case did not return its restoration receipt.")
            return {"ok": True, "device": self.initial["device"], "fixture_unregistered": True,
                    "device_restored": True, "secondary_normal_owned_exit": True}
        if action == "local-api-config-verify":
            if self.unconfirmed:
                raise TimeoutError("Synthetic readback unavailable.")
            return {"ok": True, "device": self.initial["device"], "checks": {"LA-010": True}}
        return self.initial | {
            "account": "logged-in", "login_acknowledged": action == "login",
            "pro_observations": [{"reported_trial": False, "expiry_observation": "perpetual"}],
        }

    async def stop(self):
        self.trace.append("local-api:stop")
        return {"normal": True}


class ForegroundRegression(unittest.IsolatedAsyncioTestCase):
    async def exercise_foreground(self, qualification=None, unconfirmed=False, ssh_available=True,
                                  file_uncertain=False, peer_uncertain=False):
        trace = []
        source = PaidSource(trace)
        role = LinuxRole(trace, qualification, unconfirmed, file_uncertain, peer_uncertain)
        target = Target(trace)
        results = {}
        inputs = AsyncMock(return_value={"username": "synthetic-only", "password": "synthetic-only"})
        gateway_done = asyncio.Event()
        target.stop = AsyncMock(return_value={"role_stopped": True})
        ssh = SimpleNamespace(begin=AsyncMock(), stop=AsyncMock(return_value={"ssh_exit": 0}))

        async def begin(worker, _stop):
            if worker is entry.LinuxQualification:
                trace.append("ssh:local-api")
                return (role, {"instance": role.initial})
            self.assertIs(worker, LinuxGateway)
            self.assertIn("local-api:stop", trace)
            trace.append("ssh:gateway")
            return (target, FIXTURE)

        ssh.begin.side_effect = begin

        async def operator_stop(stop, deadline, revoke):
            await gateway_done.wait()
            revoke()

        def publish(_, key, receipt):
            results[key] = receipt
            if key == "cases-ready" or (key == "ready" and "socket" in receipt):
                gateway_done.set()

        with TemporaryDirectory() as directory:
            args = SimpleNamespace(exchange=Path(directory), expires_at=int(time.time()) + 30)
            boundary = SimpleNamespace(private=Path(directory).resolve(), group=os.getgid())
            linux_open = AsyncMock(return_value=(ssh, {}) if ssh_available else None)
            with (
                patch.object(ContinuousMac, "start", AsyncMock(return_value=source)),
                patch.object(entry.LinuxForeground, "open", linux_open),
                patch.object(entry, "hash_file", return_value="a" * 64),
                patch.object(entry, "verify_native_boundary", AsyncMock()),
                patch.object(entry, "read_credentials", inputs),
                patch.object(entry, "await_operator_stop", operator_stop),
                patch.object(entry, "publish", side_effect=publish),
            ):
                await entry.execute(args, boundary, Path("unused-engine"), Path("unused-driver"), RUN,
                                    {"host": "192.0.2.1"}, os.getgid())

        inputs.assert_awaited_once()
        linux_open.assert_awaited_once()
        self.assertEqual(trace.count("source:login"), 1)
        self.assertEqual(set(results["ready"]), {"run", "socket"})
        self.assertEqual(results["ready"]["run"], RUN)
        self.assertTrue(results["native-ready"]["mac_signed_out"])
        self.assertFalse(Path(results["ready"]["socket"]).parent.exists())
        if ssh_available:
            ssh.stop.assert_awaited_once()
            target.stop.assert_awaited_once()
            self.assertEqual(trace.count("local-api:login"), 1)
            self.assertEqual(trace.count("source:gateway-write"), 1)
            self.assertLess(trace.index("source:gateway-write"), trace.index("source:gateway-finish"))
            self.assertLess(trace.index("source:gateway-finish"), trace.index("source:stop"))
            self.assertTrue(results["cross-network"]["result"]["target_files_preserved"])
        else:
            ssh.begin.assert_not_awaited()
            self.assertEqual(results["qualification"]["result"]["local_api"]["state"], "linux-preflight-unavailable")
            self.assertEqual(results["cross-network"]["result"]["state"], "linux-gateway-preflight-unavailable")
        return trace, results

    async def test_missing_ssh_does_not_disable_cases_in_the_original_foreground(self):
        await self.exercise_foreground(ssh_available=False)

    async def test_failed_native_isolation_precedes_both_hidden_prompts(self):
        with TemporaryDirectory() as directory:
            args = SimpleNamespace(exchange=Path(directory), expires_at=int(time.time()) + 10)
            boundary = SimpleNamespace(private=Path(directory).resolve(), group=os.getgid())
            source = PaidSource([])
            with (
                patch.object(ContinuousMac, "start", AsyncMock(return_value=source)),
                patch.object(entry.LinuxForeground, "open", AsyncMock(return_value=None)) as ssh,
                patch.object(entry,"hash_file", return_value="a"*64),
                patch.object(entry,"verify_native_boundary", AsyncMock(side_effect=ValueError("fixture rejection"))),
                patch.object(entry,"read_credentials", AsyncMock()) as pro,
                patch.object(entry,"publish"),
            ):
                with self.assertRaisesRegex(ValueError, "fixture rejection"):
                    await entry.execute(args,boundary,Path("unused-engine"),Path("unused-driver"),RUN,
                                        {"host":"192.0.2.1"},os.getgid())
            ssh.assert_not_awaited()
            pro.assert_not_awaited()
            self.assertEqual(source.trace, ["source:stop"])

    async def test_qualified_pro_source_continues_with_same_objects_before_stop(self):
        trace, results = await self.exercise_foreground()
        self.assertEqual(results["qualification"]["result"]["local_api"]["qualification"]["code"], 3001)
        self.assertNotIn("local-api:local-api-config-verify", trace)

    @staticmethod
    def qualified_receipt():
        return {"ok": True, "fixed_native_account_observation": {
                    "device": LinuxRole.initial["device"], "version": "2.33.2"},
                "protected_read_routes": [{"route": "LA-012", "state": "exact-folder-readback",
                                           "exact_id": True, "exact_path": True}],
                "same_paid_device_after_read": True, "protected_writes": 0}

    async def test_exact_local_api_qualification_continues_before_role_cleanup(self):
        trace, results = await self.exercise_foreground(self.qualified_receipt())
        file_case = "local-api:local-api-file-verify"
        peer_case = "local-api:local-api-peer-verify"
        attempt = "local-api:local-api-config-verify"
        self.assertEqual(trace.count(file_case), 1)
        self.assertEqual(trace.count(peer_case), 1)
        self.assertLess(trace.index(file_case), trace.index(peer_case))
        self.assertLess(trace.index(peer_case), trace.index(attempt))
        self.assertTrue(results["local-api-files"]["result"]["fixture_unregistered"])
        self.assertEqual(trace.count(attempt), 1)
        self.assertLess(trace.index(attempt), trace.index("local-api:stop"))
        self.assertEqual(results["local-api-config"]["result"]["checks"], {"LA-010": True})

    async def test_wrong_path_or_core_refuses_config_verification_while_gateway_continues(self):
        for field in ("exact_path", "device"):
            receipt = self.qualified_receipt()
            if field == "device":
                receipt["fixed_native_account_observation"]["device"] = "another-core"
            else:
                receipt["protected_read_routes"][0]["exact_path"] = False
            trace, _ = await self.exercise_foreground(receipt)
            self.assertNotIn("local-api:local-api-config-verify", trace)

    async def test_wrong_id_returns_a_different_folder_and_only_the_linux_config_is_skipped(self):
        receipt = self.qualified_receipt()
        receipt["wrong_id_control"] = {"state": "unexpected-configuration", "returned_requested_id": False}
        trace, results = await self.exercise_foreground(receipt)
        self.assertNotIn("local-api:local-api-file-verify", trace)
        self.assertNotIn("local-api:local-api-config-verify", trace)
        self.assertEqual(
            results["local-api-config"]["result"]["state"],
            "qualification-returned-config-for-absent-folder",
        )
        self.assertLess(trace.index("local-api:stop"), trace.index("ssh:gateway"))
        self.assertEqual(trace.count("source:login"), 1)

    async def test_unconfirmed_file_case_does_not_queue_a_write_on_that_role(self):
        trace, results = await self.exercise_foreground(self.qualified_receipt(), file_uncertain=True)
        self.assertEqual(trace.count("local-api:local-api-file-verify"), 1)
        self.assertNotIn("local-api:local-api-peer-verify", trace)
        self.assertNotIn("local-api:local-api-config-verify", trace)
        self.assertEqual(results["local-api-files"]["result"]["state"], "file-verification-unconfirmed")
        self.assertLess(trace.index("local-api:stop"), trace.index("ssh:gateway"))

    async def test_unconfirmed_peer_receipt_stops_only_its_own_role_and_never_retries(self):
        trace, results = await self.exercise_foreground(self.qualified_receipt(), peer_uncertain=True)
        self.assertEqual(trace.count("local-api:local-api-peer-verify"), 1)
        self.assertNotIn("local-api:local-api-config-verify", trace)
        self.assertEqual(results["local-api-peers"]["result"]["state"], "peer-verification-unconfirmed")
        self.assertLess(trace.index("local-api:stop"), trace.index("ssh:gateway"))

    async def test_wrong_id_transient_failure_is_reported_and_not_retried(self):
        receipt = self.qualified_receipt()
        receipt["wrong_id_control"] = {"state": "http-failure", "http": 503}
        trace, results = await self.exercise_foreground(receipt)
        self.assertEqual(trace.count("local-api:local-api-qualify"), 1)
        self.assertEqual(trace.count("local-api:local-api-config-verify"), 1)
        self.assertEqual(
            results["qualification"]["result"]["local_api"]["qualification"]["wrong_id_control"],
            {"state": "http-failure", "http": 503},
        )

    async def test_unconfirmed_config_result_is_preserved_and_never_retried(self):
        trace, results = await self.exercise_foreground(self.qualified_receipt(), unconfirmed=True)
        self.assertEqual(trace.count("local-api:local-api-config-verify"), 1)
        self.assertEqual(results["local-api-config"]["result"]["state"], "configuration-result-unconfirmed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
