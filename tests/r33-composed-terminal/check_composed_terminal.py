"""Exercise the exact foreground dispatcher over a disposable password SSH connection."""

import asyncio
import errno
import json
import os
from pathlib import Path
import pty
import secrets
import select
import shutil
import signal
import sys
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import check_password_transport as ssh_fixture
import r33_licensed_validation as entry
from check_continuous_terminal import exercise_named_cases
from r33_gateway_crossnetwork import ContinuousMac
from r33_single import confirm_combined
from test_continuous_foreground import PaidSource


HERE = Path(__file__).resolve()
USERNAME = b"combined-terminal-synthetic-user"
PASSWORD = b"combined-terminal-synthetic-password"
LINUX_DEVICE = "synthetic-licensed-linux"
OPERATIONS = ["login", "inspect", "local-api-qualify", "local-api-file-verify",
              "local-api-peer-verify", "local-api-config-verify"]
CASES = ["observe", "schedule-watch-prepare", "schedule-watch-finish",
         "selection-prepare", "selection-finish", "audit-prepare", "audit-finish"]
START = b"Type START to authorize these test operations:"
SSH_PASSWORD = b"'s password:"
PRO_ACCOUNT = b"VerySync account (hidden) "
PRO_PASSWORD = b"VerySync password (hidden) "
READY = b"R33_READY "
STOPPED = b"R33_QUALIFICATION_STOPPED "


def fixture_role():
    prefix, marker, _ = ssh_fixture.ROLE_PROGRAM.partition(b"\npublish(ready,")
    assert marker
    return prefix + b'''
owned = {"device":"synthetic-licensed-linux","version":"2.33.2"}
paid = {"account":"logged-in","pro_observations":[{"reported_trial":False,"expiry_observation":"perpetual"}]}
observed = []
publish(ready, deadline=expires, role_pid=os.getpid(), instance=owned)
for line in sys.stdin:
    request = json.loads(line)
    assert request["run"] == run
    kind = request["kind"]
    if kind == "renew":
        continue
    if kind == "stop":
        publish("local-api-foreground-stopped", operations=observed, credentials_checked=observed.count("login"))
        publish("local-api-cleanup", private_state_removed=True)
        break
    assert kind == "execute"
    action = request["operation"]
    observed.append(action)
    assert observed.count(action) == 1
    result = {"ok":True,"device":owned["device"]}
    if role == "native-target":
        assert action == "inspect"
        result = {"role":role,"role_pid":os.getpid()}
    elif action == "login":
        assert request["input"]["username"] == "combined-terminal-synthetic-user"
        assert request["input"]["password"] == "combined-terminal-synthetic-password"
        result.update(owned, **paid, login_acknowledged=True)
    elif action == "inspect":
        result.update(owned, **paid)
    elif action == "local-api-qualify":
        result.update(fixed_native_account_observation=owned, same_paid_device_after_read=True,
                      protected_writes=0, protected_read_routes=[
                          {"route":"LA-012","state":"exact-folder-readback","exact_id":True,"exact_path":True}
                      ])
    elif action == "local-api-file-verify":
        result["fixture_unregistered"] = True
    elif action == "local-api-peer-verify":
        result.update(fixture_unregistered=True, device_restored=True, secondary_normal_owned_exit=True)
    else:
        assert action == "local-api-config-verify"
    publish("operation-observed", request=request["request"], native=result)
'''


async def worker(root, spec):
    run = secrets.token_hex(16)
    expires = int(time.time()) + 105
    payload = root / "payload"
    exchange = root / "exchange"
    payload.mkdir(mode=0o700)
    exchange.mkdir(mode=0o700)
    shutil.copyfile(root / "synthetic-stage.zip", payload / "linux-scope.zip")
    shutil.copyfile(HERE.with_name("r33_linux_qualification_bootstrap.py"),
                    payload / "r33_linux_qualification_bootstrap.py")
    digest = entry.hash_file(payload / "linux-scope.zip")
    destination = dict(spec, trust_source="saved")
    trace = []
    mac = PaidSource(trace)
    original_open = entry.LinuxForeground.open
    connection = {}
    standby = {}

    async def open_and_measure(*arguments):
        assert not connection
        session, ready = await original_open(*arguments)
        connection["session"] = session
        connection["process"] = session.session.child
        before = ssh_fixture.listening_endpoints()
        assert any(kind == "tcp" and address.endswith(f":{spec['port']:04X}") for kind, address, _ in before)
        started = time.monotonic()
        samples = 0
        try:
            while session.idle_renewals < 2:
                assert session.active is None and session.session.child.returncode is None
                assert ssh_fixture.listening_endpoints() == before and time.monotonic() - started < 39
                samples += 1
                await asyncio.sleep(.25)
        except BaseException:
            await session.stop()
            raise
        elapsed = time.monotonic() - started
        assert elapsed >= 29 and samples >= 60
        standby.update(idle_renewals=session.idle_renewals, standby_seconds=round(elapsed, 6),
                       kernel_socket_census_checks=samples, added_standby_listeners=0)
        return session, ready

    async def synthetic_gateway(source, session, qualifications, private, run_number, stopped):
        assert run_number == run and session is connection["session"] and session.active is None
        assert qualifications["local_api"]["state"] == "observed"
        active, advertised = await session.begin(ssh_fixture.FixtureGateway, stopped)
        assert active.child is connection["process"]
        try:
            result = await active.execute("inspect", operator_stop=stopped)
            assert result == {"role":"native-target","role_pid":advertised["role_pid"]}
        finally:
            final = await active.stop()
        assert final["cleanup"]["private_state_removed"] and session.active is None
        assert session.session.child.returncode is None
        standby.update(both_roles_returned_to_standby=True, fixed_bootstrap_verified=True)
        return {"state":"synthetic-gateway-returned-to-standby","same_authenticated_connection":True}

    if not confirm_combined(run, expires, destination=destination, state_root=root / "synthetic-state",
                            bundle_digest="b" * 64, driver_digest="c" * 64, linux_payload_digest=digest,
                            gateway_port=58611, synthetic=True):
        raise AssertionError("The one-window fixture did not confirm its first scope.")
    args = SimpleNamespace(exchange=exchange, expires_at=expires)
    boundary = SimpleNamespace(private=root, group=os.getgid())
    with (
        patch.object(ContinuousMac, "start", AsyncMock(return_value=mac)),
        patch.object(entry.LinuxForeground, "open", side_effect=open_and_measure),
        patch.object(entry, "verify_native_boundary", AsyncMock()),
        patch.object(entry, "gateway_peer", return_value="127.0.0.1:58611"),
        patch.object(entry, "continue_gateway", side_effect=synthetic_gateway),
        patch.object(entry, "APP", payload),
    ):
        await entry.execute(args, boundary, Path("unused-engine"), Path("unused-driver"), run,
                            destination, os.getgid(), linux_payload_digest=digest)
    cleanup = json.loads((exchange/"stopped.json").read_text())
    assert cleanup["run"] == run and cleanup["linux"]["one_authenticated_channel"] is True
    assert cleanup["linux"]["ssh_exit"] == 0 and cleanup["linux"]["staging"]["temporary_programs_removed"]
    assert trace.count("source:login") == trace.count("source:stop") == 1
    actions = [item.removeprefix("case:") for item in trace if item.startswith("case:")]
    assert actions == CASES
    for stage in ("files","peers","config","cleanup"):
        assert json.loads((exchange/f"local-api-{stage}.json").read_text())["run"] == run
    linux = json.loads((exchange/"local-api-cleanup.json").read_text())["result"]["native_scope"]
    assert linux["operations"] == OPERATIONS and linux["credentials_checked"] == 1
    standby.update(same_run_named_cases=actions, linux_role_operations=linux["operations"],
                   actual_foreground_dispatch=True, combined_window=True, mac_native_adapter="synthetic",
                   gateway_effect_adapter="synthetic")
    (root/"standby-receipt.json").write_text(json.dumps(standby))


def drive(root, spec, ssh_password, stop_command):
    pid, descriptor = pty.fork()
    if pid == 0:
        os.execv(sys.executable, [sys.executable, "-B", str(HERE), "--fixture", str(root), json.dumps(spec)])
    history = bytearray()
    reaped = False
    secrets_under_test = (ssh_password, USERNAME, PASSWORD)

    def wait_for(marker, seconds=14):
        until = time.monotonic() + seconds
        while marker not in history:
            if not select.select([descriptor], [], [], max(0, until-time.monotonic()))[0]:
                raise AssertionError(f"The terminal did not reach {marker!r}.")
            try:
                block = os.read(descriptor, 4096)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                block = b""
            if not block:
                safe = bytes(history)
                for secret in secrets_under_test:
                    safe = safe.replace(secret, b"[redacted]")
                raise AssertionError(f"The terminal exited before {marker!r}: {safe[-1800:]!r}.")
            history.extend(block)

    try:
        wait_for(START)
        assert SSH_PASSWORD not in history and PRO_ACCOUNT not in history
        os.write(descriptor, b"START\n")
        wait_for(SSH_PASSWORD)
        assert PRO_ACCOUNT not in history
        os.write(descriptor, ssh_password + b"\n")
        wait_for(PRO_ACCOUNT, 52)
        os.write(descriptor, USERNAME+b"\n")
        wait_for(PRO_PASSWORD)
        os.write(descriptor, PASSWORD+b"\n")
        wait_for(READY, 24)
        ready = json.loads((root/"exchange/ready.json").read_text())
        assert (root/"exchange/cross-network.json").is_file() and not (root/"exchange/stopped.json").exists()
        asyncio.run(exercise_named_cases(ready))
        began = time.monotonic()
        os.write(descriptor, stop_command)
        wait_for(STOPPED)
        _, status = os.waitpid(pid, 0)
        reaped = True
        assert os.waitstatus_to_exitcode(status) == 0
        elapsed = time.monotonic() - began
        assert not Path(ready["socket"]).parent.exists()
        assert all(history.count(marker) == 1 for marker in (START, SSH_PASSWORD, PRO_ACCOUNT, PRO_PASSWORD, READY))
        assert not any(secret in history for secret in secrets_under_test)
        receipt = root/"standby-receipt.json"
        result = json.loads(receipt.read_text())
        result.update(pro_account_prompts=1, pro_password_prompts=1, pro_credential_echoes=0,
                      one_scope_confirmation=True, operator_stop="Ctrl+C" if stop_command==b"\x03" else "STOP",
                      local_terminal_address_removed=True, observed_cleanup_seconds=round(elapsed,6))
        receipt.write_text(json.dumps(result))
    finally:
        if not reaped:
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)
        os.close(descriptor)


def check():
    for command in (b"STOP\n", b"\x03"):
        with TemporaryDirectory(prefix="r33-password-composed-") as directory:
            with (
                patch.object(ssh_fixture, "ROLE_PROGRAM", fixture_role()),
                patch.object(ssh_fixture, "drive_terminal",
                             lambda root, spec, password: drive(root, spec, password, command)),
            ):
                result = ssh_fixture.check(Path(directory))
        assert not Path(directory).exists()
        print("R33_COMPOSED_TERMINAL "+json.dumps(result | {"fixture_root_removed":True}, sort_keys=True),flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    if sys.argv[1:2] == ["--fixture"]:
        asyncio.run(worker(Path(sys.argv[2]), json.loads(sys.argv[3])))
    else:
        check()
