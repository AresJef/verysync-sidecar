"""Check the one-terminal routing rules before launching the real PTY fixtures."""

import asyncio
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time
import unittest
from zipfile import ZipFile


SOURCE = Path(__file__).resolve().parents[1] / "runtime-next"
sys.path.insert(0, str(SOURCE))

from r33_cases import TWO_CORE_SCOPES
from r33_handoff import Journal, Scope, Supervisor
from r33_linux_worker import Guardian, secure_initial
from r33_protocol import DENIED, ProtocolError, Request, encode_frame
from r33_remote_peer import bundle
from r33_simulated_cases import SimulatedCases


class Routing(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        os.umask(0o077)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.run = secrets.token_hex(16)

    def test_peer_archive_is_reproducible(self):
        command, digest, wire = bundle(SOURCE)
        again = bundle(SOURCE)
        self.assertEqual((command, digest, wire), again)
        payload = wire[4:]
        self.assertEqual(len(payload), int.from_bytes(wire[:4], "big"))
        self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)
        self.assertIn(digest, command)
        with ZipFile(io.BytesIO(payload)) as archive:
            self.assertEqual(set(archive.namelist()), {"r33_linux_worker.py", "r33_protocol.py"})
            for name in archive.namelist():
                self.assertEqual(archive.read(name), (SOURCE / name).read_bytes())

    def test_bootstrap_rejects_unknown_scope_and_bad_deadline(self):
        epoch = int(time.time())+30
        self.assertEqual(secure_initial(encode_frame({"kind":"start","run":self.run,"absolute_epoch":epoch})),
                         ("start",self.run,epoch))
        for item in ({"kind":"start","run":self.run,"absolute_epoch":epoch-60},
                     {"kind":"recover","run":self.run,"absolute_epoch":epoch},
                     {"kind":"start","run":self.run,"command":"ungranted"}):
            with self.assertRaises(ProtocolError):
                secure_initial(encode_frame(item))

    def test_same_account_switches_owned_case_and_rejects_wrong_steps(self):
        scenarios = SimulatedCases(self.root)
        self.assertEqual(scenarios.run_case("audit-reset"),DENIED)
        self.assertEqual(scenarios.run_case("enterprise-execute"),DENIED)
        order = (["schedule-watch-prepare","schedule-watch-seed","schedule-watch-observe","schedule-watch-finish"],
                 list(op for op in TWO_CORE_SCOPES["pro-cases"] if op.startswith("selection-")),
                 ["audit-prepare","audit-record","audit-observe","audit-reset","audit-finish"])
        for commands in order:
            self.assertTrue(scenarios.run_case(commands[0])["ok"])
            self.assertEqual(scenarios.run_case("audit-prepare" if not commands[0].startswith("audit")
                                                else "selection-prepare"),DENIED)
            for command in commands[1:]:
                reply = scenarios.run_case(command)
                self.assertTrue(reply["ok"],command)
                if command.endswith(("-observe","-select-root")):
                    expected = (self.root.name+"/"+reply["fixture"]).encode()
                    self.assertEqual(reply["sha256"],hashlib.sha256(expected).hexdigest())
                    self.assertEqual(reply["bytes"],len(expected))
            self.assertEqual(list(self.root.iterdir()),[])
        self.assertEqual(scenarios.effects, ["schedule-watch","selection","audit"])

    async def test_absolute_deadline_wins_over_renewal(self):
        guard = Guardian(self.root, int(time.time()) + 3)
        self.assertTrue(guard.permits())
        guard.absolute_limit = time.monotonic()-1
        self.assertEqual(await guard.respond({"kind":"renew"},False),DENIED)
        await guard.stop("verification")
        self.assertEqual(json.loads((self.root/"receipt.json").read_text())["reason"],"absolute-expired")

    async def test_seal_removes_queued_writes_and_keeps_scope_alive(self):
        release = asyncio.Event()
        started = asyncio.Event()
        calls = []

        class Backend:
            async def execute(_, work, before_send):
                before_send()
                calls.append(work.request.operation)
                if work.request.operation == "write-sample":
                    started.set()
                    await release.wait()
                return {"ok":True}

            async def stop(_, unknown, journal):
                return {"state":"stopped"}

        journal = Journal(self.root/"journal",self.run)
        supervisor = Supervisor(self.run, os.getuid(), journal, expires_at=int(time.time())+30)
        supervisor.scopes["linux"] = Scope("linux",Backend(),("observe","write-sample"),journal)

        def req(target, operation):
            return Request(self.run,target,operation,secrets.token_hex(16))

        first = asyncio.create_task(supervisor.route(os.getuid(),req("linux","write-sample")))
        await asyncio.wait_for(started.wait(), 1)
        second = asyncio.create_task(supervisor.route(os.getuid(),req("linux","write-sample")))
        await asyncio.sleep(0)
        self.assertEqual(supervisor.scopes["linux"].queue.qsize(),1)
        result = await supervisor.route(os.getuid(),req("handoff","seal"))
        self.assertEqual(result["local"],"active")
        self.assertTrue(result["business_queue_sealed"])
        self.assertEqual(await asyncio.wait_for(second, 1),DENIED)
        self.assertEqual(await supervisor.route(os.getuid(),req("linux","write-sample")),DENIED)
        release.set()
        self.assertTrue((await first)["ok"])
        self.assertTrue((await supervisor.route(os.getuid(),req("linux","observe")))["ok"])
        self.assertEqual(calls,["write-sample","observe"])
        self.assertEqual((await supervisor.route(os.getuid(),req("handoff","stop")))["local"],"revoked")
        await asyncio.gather(*supervisor.stopping.values())


if __name__ == "__main__":
    unittest.main(verbosity=2)

