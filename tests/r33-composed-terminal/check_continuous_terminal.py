"""Drive the corrected foreground through a real PTY with synthetic account inputs."""

import asyncio
from base64 import b64encode
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import pty
import select
import secrets
import signal
import sys
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import r33_licensed_validation as entry
from r33_gateway_crossnetwork import ContinuousMac, LinuxGateway
from r33_handoff import query
from r33_protocol import DENIED, Request
from r33_rendezvous import TMP, confirmed_status
from r33_single import confirm_combined
from r33_ssh import host_key_identity
from test_continuous_foreground import LinuxRole, PaidSource
from test_crossnetwork_commands import FIXTURE, RUN, Target

USERNAME = b"fixture-account-r33"
PASSWORD = b"fixture-password-r33"
HERE = Path(__file__).resolve()


async def fixture(root):
    trace = []
    mac = PaidSource(trace)
    local = LinuxRole(trace)
    target = Target(trace)
    target.stop = AsyncMock(return_value={"role_stopped": True})

    async def begin(worker, stop):
        if stop.is_set():
            return None
        if worker is entry.LinuxQualification:
            return local, {"instance": local.initial}
        if worker is LinuxGateway:
            return target, FIXTURE
        raise AssertionError("Unexpected fixture role.")

    ssh = SimpleNamespace(begin=begin, stop=AsyncMock(return_value={"ssh_exit": 0}))
    args = SimpleNamespace(exchange=root, expires_at=int(time.time()) + 22)
    boundary = SimpleNamespace(private=root, group=os.getgid())
    encoded = b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))).decode("ascii")
    public, fingerprint = host_key_identity("ssh-ed25519 " + encoded)
    destination = {"host": "192.0.2.1", "port": 22, "user": "root", "public_key": public,
                   "fingerprint": fingerprint, "trust_source": "saved"}
    if not confirm_combined(RUN, args.expires_at, destination=destination, state_root=root / "synthetic-state",
                            bundle_digest="b" * 64, driver_digest="c" * 64, linux_payload_digest="a" * 64,
                            gateway_port=58611, synthetic=True):
        return
    with ExitStack() as context:
        for obj, method, replacement in (
            (ContinuousMac, "start", AsyncMock(return_value=mac)),
            (entry.LinuxForeground, "open", AsyncMock(return_value=(ssh, {}))),
            (entry, "hash_file", lambda _: "a" * 64),
            (entry, "verify_native_boundary", AsyncMock()),
        ):
            context.enter_context(patch.object(obj, method, replacement))
        await entry.execute(args, boundary, Path("unused-engine"), Path("unused-driver"), RUN,
                            destination, os.getgid(), linux_payload_digest="a" * 64)
        assert entry.LinuxForeground.open.await_count == 1
        assert ssh.stop.await_count == target.stop.await_count == 1
    (root / "synthetic-trace.json").write_text(json.dumps(trace))


async def exercise_named_cases(ready):
    address = Path(ready["socket"])
    assert set(ready) == {"run", "socket"}
    status = await confirmed_status(address, ready["run"], os.getuid(), os.getgid())
    assert status["pro"]["state"] == "active"

    async def send(target, name):
        return await query(address, Request(ready["run"], target, name, secrets.token_hex(16)))

    state = await send("pro", "observe")
    for case in ("schedule-watch", "selection", "audit"):
        for step in ("prepare", "finish"):
            result = await send("pro", f"{case}-{step}")
            assert result == {"ok": True, "device": state["device"]}
    assert await send("pro", "enterprise-write") == DENIED
    assert (await send("handoff", "seal"))["business_queue_sealed"] is True
    assert await send("pro", "audit-prepare") == DENIED


def terminal(root, command):
    pid, descriptor = pty.fork()
    if pid == 0:
        os.execv(sys.executable, [sys.executable, "-B", str(HERE), "--fixture", str(root)])
    history = bytearray()
    reaped = False

    def wait_for(text):
        deadline = time.monotonic() + 8
        while text not in history:
            ready = select.select([descriptor], [], [], max(0, deadline - time.monotonic()))[0]
            if not ready:
                raise AssertionError(f"The foreground did not reach {text!r}.")
            try:
                read = os.read(descriptor, 4096)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                read = b""
            if not read:
                safe = bytes(history).replace(USERNAME, b"[redacted]").replace(PASSWORD, b"[redacted]")
                raise AssertionError(f"The foreground stopped before reaching {text!r}: {safe[-1200:]!r}.")
            history.extend(read)

    try:
        wait_for(b"Type START to authorize these test operations:")
        assert b"(hidden)" not in history and b"OpenSSH prompt" not in history
        for identifier in (b"VS-041-W", b"VS-033-S5", b"VS-040", b"VS-042-P", b"VS-042-R", b"VS-042-L", b"VS-042-E"):
            assert identifier in history
        assert b"TCP 58611" in history and b"SSH identity SHA256:" in history
        assert b"Trial redemption is deferred" in history and b"Access expires at" in history
        for digest in (b"b" * 64, b"c" * 64, b"a" * 64):
            assert digest in history
        os.write(descriptor, b"START\n")
        wait_for(b"VerySync account (hidden) ")
        os.write(descriptor, USERNAME + b"\n")
        wait_for(b"VerySync password (hidden) ")
        os.write(descriptor, PASSWORD + b"\n")
        wait_for(b"R33_READY ")
        assert (root / "cross-network.json").is_file()
        assert not (root / "stopped.json").exists()
        ready = json.loads((root / "ready.json").read_text())
        private_receipts = root / "v" / ready["run"] / "owned-case-receipts.jsonl"
        announced = json.loads(private_receipts.read_bytes().splitlines()[0])
        assert announced["event"] == "owner-transport-paths" and announced["run"] == ready["run"]
        entry_address = Path(ready["socket"]).parent
        assert announced["public"] == str(entry_address)
        assert announced["public_device"] == entry_address.stat().st_dev
        assert announced["public_inode"] == entry_address.stat().st_ino
        asyncio.run(exercise_named_cases(ready))
        start = time.monotonic()
        os.write(descriptor, command)
        wait_for(b"R33_QUALIFICATION_STOPPED ")
        elapsed = time.monotonic() - start
        _, status = os.waitpid(pid, 0)
        reaped = True
        assert os.waitstatus_to_exitcode(status) == 0
        assert USERNAME not in history and PASSWORD not in history
        assert history.count(b"VerySync account (hidden) ") == 1
        assert history.count(b"VerySync password (hidden) ") == 1
        assert history.count(b"Enter the Linux SSH password at the OpenSSH prompt.") == 1
        assert history.count(b"Type START to authorize these test operations:") == 1
        assert history.count(b"R33_READY ") == 1
        trace = json.loads((root / "synthetic-trace.json").read_text())
        assert trace.count("source:login") == trace.count("local-api:login") == 1
        assert trace.count("source:gateway-write") == 1
        applied = [item.removeprefix("case:") for item in trace if item.startswith("case:")]
        assert applied == ["observe", "schedule-watch-prepare", "schedule-watch-finish",
                           "selection-prepare", "selection-finish", "audit-prepare", "audit-finish"], applied
        assert trace.index("source:gateway-finish") < trace.index("case:observe") < trace.index("source:stop")
        assert not Path(ready["socket"]).parent.exists()
        return {
            "stop": "Ctrl+C" if command == b"\x03" else "STOP",
            "credential_echoes": 0,
            "very_sync_account_prompts": 1,
            "very_sync_password_prompts": 1,
            "ssh_adapter_opens": 1,
            "scope_confirmations": 1,
            "observer_automatically_verified_ready_endpoint": True,
            "owned_cleanup_address_bound": True,
            "gateway_write_calls": 1,
            "same_run_named_cases": applied[1:],
            "business_queue_sealed_before_stop": True,
            "normal_fixture_stop_seconds": round(elapsed, 6),
            "synthetic_adapters": True,
            "real_terminal": True,
        }
    finally:
        if not reaped:
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)
        os.close(descriptor)


if __name__ == "__main__":
    if sys.argv[1:2] == ["--fixture"]:
        asyncio.run(fixture(Path(sys.argv[2])))
    else:
        for command in (b"STOP\n", b"\x03"):
            with TemporaryDirectory(prefix="r33-exchange-", dir=TMP) as directory:
                result = terminal(Path(directory), command)
            assert not Path(directory).exists()
            print(json.dumps(result | {"root_removed": True}, sort_keys=True))
