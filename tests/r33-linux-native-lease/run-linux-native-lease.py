"""Exercise the fixed signed-out Local-API core behind the R33 lease."""

import argparse
import asyncio
from contextlib import asynccontextmanager, closing
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import runpy
import secrets
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import time


HERE = Path(__file__).resolve().parent
NATIVE = runpy.run_path(str(HERE / "run-linux-native-isolation.py"))
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
QUALIFY = "local-api-qualify"
SCRIPT = str(Path(__file__).resolve())


class PrivateNative:
    def __init__(self, program, fixture, port):
        self.program, self.fixture, self.port = program, fixture, port
        self.process = None
        self.ready = None

    async def start(self, test):
        self.process = await asyncio.create_subprocess_exec(
            "/usr/bin/sudo", "-n", "/usr/bin/unshare", "--net", "/usr/bin/python3", "-B",
            SCRIPT, "--worker", str(self.port), str(os.getuid()), str(os.getgid()),
            NATIVE["namespace"](), str(test), str(self.program), str(self.fixture),
            NATIVE["sha256"](self.program), stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            limit=8192, start_new_session=True,
        )
        self.ready = await self.event("READY", 22)
        alias, pid = self.ready.get("device_alias"), self.ready.get("core_pid")
        if (type(alias) is not str or not SHA256.fullmatch(alias) or type(pid) is not int or pid <= 1
                or self.ready.get("namespace") == NATIVE["namespace"]()
                or self.ready.get("fixed_version") != "v2.33.2"
                or self.ready.get("ordinary_inside_identity_matched") is not True
                or self.ready.get("logged_out") is not True or self.ready.get("protected_read_denials") != 0):
            raise ValueError("The fixed native fixture did not confirm its signed-out private startup.")

    async def event(self, name, timeout):
        prefix = f"R33_NATIVE_PRIVATE_{name} ".encode("ascii")
        async def take():
            for _ in range(12):
                part = await self.process.stdout.readline()
                if not part:
                    break
                if prefix in part:
                    result = json.loads(part.split(prefix, 1)[1])
                    if type(result) is dict:
                        return result
            raise ValueError(f"The fixed native fixture did not report {name}.")
        return await asyncio.wait_for(take(), timeout)

    async def qualify(self):
        self.process.stdin.write(b"QUALIFY\n")
        await self.process.stdin.drain()
        reply = await self.event("QUALIFIED", 2)
        if (reply != {"protected_read_denials":3, "protected_writes":0,
                      "device_alias":self.ready["device_alias"]}):
            raise ValueError("The fixed qualification result did not match this device.")
        return reply

    async def finish(self, expected_reads):
        if self.process is None:
            return None
        if self.process.returncode is not None or self.ready is None:
            raise ValueError("Cannot verify the owned core's normal exit.")
        self.process.stdin.write(b"STOP\n")
        await self.process.stdin.drain()
        self.process.stdin.close()
        data = await self.event("DATA", 2)
        end = await self.event("EXIT", 3)
        await asyncio.wait_for(self.process.wait(), 3)
        if (self.process.returncode or Path(f"/proc/{self.ready['core_pid']}").exists()
                or end != {"normal_owned_exit":True, "exact_state_released":True}
                or data.get("read_back_after_test") is not True
                or data.get("protected_read_denials") != expected_reads
                or data.get("protected_writes") != 0):
            raise ValueError("The owned Local-API fixture could not confirm its final state.")
        byte_receipts = {}
        for label, relative in [("sample", Path("samples/sample.txt")), ("control", Path("control.txt"))]:
            value = (self.fixture / relative).read_bytes()
            digest = hashlib.sha256(value).hexdigest()
            if (digest != data.get(f"{label}_sha256") or len(value) != data.get(f"{label}_bytes")):
                raise ValueError("The raw native byte receipt could not be independently reconstructed.")
            byte_receipts[label] = {"sha256":digest, "bytes":len(value)}
        return {"native_pid_exited":True, "state_released":True, "protected_reads":expected_reads,
                "protected_writes":0, "files":byte_receipts}

    async def emergency_close(self):
        if self.process and self.process.returncode is None:
            if not self.process.stdin.is_closing():
                self.process.stdin.close()
            try:
                await asyncio.wait_for(self.process.wait(), 6)
            except asyncio.TimeoutError:
                # This is the hosted fixture's verified, newly created process group.
                cleanup = await asyncio.create_subprocess_exec(
                    "/usr/bin/sudo", "-n", "/bin/kill", "-TERM", "--", f"-{self.process.pid}",
                )
                await asyncio.wait_for(cleanup.wait(), 2)
                await asyncio.wait_for(self.process.wait(), 4)


def build_guard(handoff):
    sys.path.insert(0, str(handoff))
    from r33_linux_worker import Guardian, CONTROL
    from r33_protocol import DENIED, REQUEST_ID, peer_uid

    class LocalApiGuard(Guardian):
        """Permit one named, fixed read-only qualification in an active grant."""

        def __init__(self, directory, native):
            super().__init__(directory)
            self.native = native
            self.mutex = asyncio.Lock()
            self.qualification = None
            self.final_native = None
            self.dispatched = False
            self.cleanup_error = False

        def receipt(self):
            report = super().receipt()
            report.update({"qualification_dispatched":self.dispatched,
                           "native":self.final_native,
                           "cleanup_pending":self.cleanup_error})
            return report

        async def connection(self, reader, writer):
            try:
                allowed = peer_uid(writer.get_extra_info("socket")) == os.getuid()
            except OSError:
                allowed = False
            if allowed:
                await super().connection(reader, writer)
            else:
                writer.close()
                await writer.wait_closed()

        async def respond(self, request, recover):
            if request.get("kind") in ("status", "renew", "stop"):
                return await super().respond(request, recover)
            if (recover or set(request) != {"kind", "operation", "id"}
                    or request.get("kind") != "execute" or request.get("operation") != QUALIFY
                    or type(request["id"]) is not str or not REQUEST_ID.fullmatch(request["id"])
                    or not self.lease.permits(time.monotonic())):
                return DENIED
            async with self.mutex:
                if self.dispatched or not self.lease.permits(time.monotonic()):
                    return DENIED
                self.dispatched = True
                try:
                    self.qualification = await self.native.qualify()
                except (OSError, ValueError, asyncio.TimeoutError):
                    self.lease.revoke(time.monotonic(), "native-result-unconfirmed")
                    return {"ok":False, "code":"native-result-unconfirmed"}
                if not self.lease.permits(time.monotonic()):
                    return DENIED
                return dict(ok=True, **self.qualification)

        async def stop(self, reason):
            self.lease.revoke(time.monotonic(), reason)
            async with self.mutex:
                if self.finished is None:
                    try:
                        expected = 3 if self.qualification else 0
                        self.final_native = await self.native.finish(expected)
                    except (OSError, ValueError, asyncio.TimeoutError):
                        self.cleanup_error = True
                        await self.native.emergency_close()
                    finally:
                        await super().stop(reason)

    return LocalApiGuard, CONTROL, DENIED


class Session:
    def __init__(self):
        self.ssh = None

    async def open(self, remote, runtime, run, mode):
        destination, identity = remote
        runtime.mkdir(mode=0o700)
        self.ssh = await asyncio.create_subprocess_exec(
            *destination.command(runtime, identity), stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, limit=4096,
        )
        self.read, self.write = self.ssh.stdout, self.ssh.stdin
        initial = await self.call({"kind":mode, "run":run})
        return initial

    async def call(self, message, timeout=5):
        self.write.write(json.dumps(message, separators=(",", ":")).encode("ascii") + b"\n")
        await self.write.drain()
        data = await asyncio.wait_for(self.read.readline(), timeout)
        return json.loads(data)

    async def close(self):
        self.write.close()
        await self.write.wait_closed()
        await asyncio.wait_for(self.ssh.wait(), 5)
        if self.ssh.returncode:
            raise ValueError("The isolated SSH transport did not close normally.")

    async def disconnect(self):
        self.ssh.kill()
        await asyncio.wait_for(self.ssh.wait(), 5)
        if self.ssh.returncode != -9:
            raise ValueError("The qualified transport was not interrupted as intended.")


def generate_ssh_pair(path):
    subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=5)
    public = path.with_suffix(".pub")
    algorithm, key, *_ = public.read_text().split()
    digest = subprocess.check_output(["/usr/bin/ssh-keygen", "-lf", str(public)],
                                     text=True, timeout=4).split()[1]
    return f"{algorithm} {key}", digest


@asynccontextmanager
async def ssh_server(root, handoff, endpoint):
    from r33_ssh import Destination
    root.mkdir(mode=0o700)
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    key = root / "client"
    host = root / "host"
    host_key, fingerprint = await asyncio.to_thread(generate_ssh_pair, host)
    client_key, _ = await asyncio.to_thread(generate_ssh_pair, key)
    authorized = root / "authorized"
    authorized.write_text("restrict " + client_key + "\n")
    user = pwd.getpwuid(os.getuid()).pw_name
    settings = root / "sshd.conf"
    forced = shlex.join(["/usr/bin/python3", "-B", SCRIPT, "--stdio", str(endpoint),
                        "--handoff", str(handoff)])
    settings.write_text("\n".join((
        "AddressFamily inet", "ListenAddress 127.0.0.1", f"Port {port}", f"HostKey {host}",
        f"PidFile {root/'sshd.pid'}", f"AuthorizedKeysFile {authorized}", f"AllowUsers {user}",
        "StrictModes no", "UsePAM no", "PasswordAuthentication no", "KbdInteractiveAuthentication no",
        "AuthenticationMethods publickey", "PermitRootLogin no", "DisableForwarding yes",
        "LogLevel ERROR", "LoginGraceTime 10", f"ForceCommand {forced}",
    )) + "\n")
    subprocess.run(["/usr/sbin/sshd", "-t", "-f", str(settings)], check=True, timeout=5)
    server = await asyncio.create_subprocess_exec(
        "/usr/sbin/sshd", "-D", "-e", "-f", str(settings),
        stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
        stderr=None, start_new_session=True,
    )
    try:
        for _ in range(40):
            if server.returncode is not None:
                raise ValueError("The disposable SSH fixture exited before accepting connections.")
            try:
                _, live = await asyncio.open_connection("127.0.0.1", port)
            except OSError:
                await asyncio.sleep(0.05)
            else:
                live.close()
                await live.wait_closed()
                break
        else:
            raise TimeoutError("The disposable SSH fixture did not start.")
        yield Destination.parse({"host":"127.0.0.1", "port":port, "user":user,
                                 "public_key":host_key, "fingerprint":fingerprint}), key
    finally:
        if server.returncode is None:
            server.terminate()
        await asyncio.wait_for(server.wait(), 5)


def stdio(endpoint, handoff):
    sys.path.insert(0, str(handoff))
    from r33_linux_worker import CONTROL, exchange_stdio, private_directory
    info = endpoint.lstat()
    private_directory(endpoint.parent)
    if (endpoint.name != CONTROL or endpoint.resolve() != endpoint or not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise ValueError("The fixed owner socket is unavailable.")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.connect(str(endpoint))
        exchange_stdio(channel)


async def exercise(guard, home, remote, mode, port, denied, first, second):
    identifier = home.name
    assert (await first.open(remote, home / "a", identifier, "start"))["state"] == "active"
    assert (await second.open(remote, home / "b", identifier, "recover"))["state"] == "active"
    with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=1)) as outside:
        try:
            outside.request("GET", "/rest/localapi/system/status")
        except ConnectionRefusedError:
            pass
        else:
            raise ValueError("The ordinary outside reader reached the native endpoint.")
    req = {"kind":"execute", "operation":QUALIFY, "id":secrets.token_hex(10)}
    assert await second.call(req) == denied
    assert await first.call(dict(req, operation="write-sample")) == denied
    if mode == "operator":
        allowed = await first.call(req)
        assert allowed["ok"] and allowed["protected_read_denials"] == 3
        assert await first.call(req) == denied
        assert await first.call(dict(req, id=secrets.token_hex(10))) == denied
        sent = time.monotonic()
        stopped = await second.call({"kind":"stop"}, timeout=10)
        ended = time.monotonic()
        assert await first.call(dict(req, id=secrets.token_hex(10))) == denied
        assert (await second.call({"kind":"stop"}))["stopped"] == stopped["stopped"]
        result = {"denied_after_revoke":True, "normal_scope_stop_elapsed":ended-sent}
        await first.close()
        await second.close()
        return result, stopped
    renewal = await first.call({"kind":"renew"})
    await first.disconnect()
    lost = time.monotonic()
    await asyncio.wait_for(guard.closed.wait(), 95)
    stopped = await second.call({"kind":"status"})
    assert await second.call(req) == denied
    await second.close()
    assert stopped["reason"] == "expired"
    assert stopped["stopped"] - renewal["renewed"] <= 95
    return {"last_renewal_to_native_exit":stopped["stopped"]-renewal["renewed"],
            "disconnected_to_native_exit":stopped["stopped"]-lost,
            "post_expiry_qualification_denied":True, "ssh_transport_killed":True}, stopped


async def regress(root, binary, engine, handoff, mode):
    guard_type, control_name, denied = build_guard(handoff)
    identifier = secrets.token_hex(16)
    home = root / identifier
    home.mkdir(mode=0o700)
    fixture = home / "owned"
    fixture.mkdir(mode=0o700)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
        native = PrivateNative(engine, fixture, port)
        guard = guard_type(home, native)
        lifecycle = None
        first = Session()
        second = Session()
        try:
            await native.start(binary)
            lifecycle = asyncio.create_task(guard.run())
            endpoint = home / control_name
            for _ in range(40):
                if endpoint.is_socket():
                    break
                await asyncio.sleep(0.025)
            async with ssh_server(home / "ssh", handoff, endpoint) as remote:
                saved, stopped = await exercise(guard, home, remote, mode, port, denied, first, second)
            await asyncio.wait_for(lifecycle, 5)
            assert not endpoint.exists() and not stopped["cleanup_pending"]
            final = stopped["native"]
            assert final["native_pid_exited"] and final["protected_writes"] == 0
            assert final["protected_reads"] == (3 if mode == "operator" else 0)
            saved.update({"normal_exit":True, "outside_native_management_refused":True,
                          "pinned_real_ssh":True,
                          "closed_control_socket":True, "denied_unknown_and_recovery_work":True,
                          "native":final})
            return saved
        finally:
            for client in (first, second):
                if client.ssh is not None and client.ssh.returncode is None:
                    await client.disconnect()
            if lifecycle is not None and not lifecycle.done():
                await guard.stop("fixture-cleanup")
                await asyncio.wait_for(lifecycle, 5)
            await native.emergency_close()


async def run(source, handoff):
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="r33-nl-", dir="/tmp") as directory:
        root = Path(directory)
        binary, engine = await asyncio.to_thread(NATIVE["materialize"], root, source)
        normal, expired = await asyncio.gather(
            regress(root, binary, engine, handoff, "operator"),
            regress(root, binary, engine, handoff, "network-loss"),
        )
        report = {"operator":normal, "network_loss":expired,
                  "crate_sha256":NATIVE["CRATE_SHA"], "native_sha256":NATIVE["sha256"](engine),
                  "fixture_sha256":NATIVE["sha256"](binary), "official_credentials_used":False}
    report["owned_directory_removed"] = not root.exists()
    print("R33_LEASED_LOCAL_API " + json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", nargs=8)
    parser.add_argument("--test-source", type=Path)
    parser.add_argument("--handoff", type=Path)
    parser.add_argument("--stdio", type=Path)
    args = parser.parse_args()
    if args.worker:
        NATIVE["worker"](*args.worker, leased=True)
    elif args.stdio and args.handoff:
        stdio(args.stdio, args.handoff)
    else:
        if (sys.platform != "linux" or os.uname().machine != "x86_64" or os.geteuid() == 0
                or os.environ.get("GITHUB_ACTIONS") != "true" or not args.test_source or not args.handoff):
            parser.error("Run the signed-out fixture from an ordinary account on the disposable Linux runner.")
        asyncio.run(run(args.test_source.resolve(strict=True), args.handoff.resolve(strict=True)))
