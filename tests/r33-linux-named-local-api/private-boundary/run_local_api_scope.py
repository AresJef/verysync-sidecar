"""Run one leased Local-API qualification with a private Linux core."""

import argparse
import asyncio
from contextlib import suppress
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

from linux_account_connector import NativeAccountConnector, UnixOfficialProxy, namespace_peer_allowed
from linux_private_boundary import launch_arguments, namespace, open_boundary, relinquish_admin
from r33_protocol import FRAME_MAX, Lease, RUN, decode_frame, encode_frame


NATIVE = "770324d3411bf6ff7d18109ba5fa1e5057056b5e93441f29185b50895f55693a"
DRIVER = "d29b9f8fae4a8b7b844e0cd12fcdeb1c56f1fc2cd6c70024b43823943985e555"
PROVIDER_GATED_OPERATIONS = frozenset(("login", "refresh-paid", "local-api-qualify", "inspect"))
HERE = Path(__file__).resolve()


def publish(observation):
    sys.stdout.buffer.write(encode_frame(observation))
    sys.stdout.buffer.flush()


def verified_copy(source, destination, expected, group):
    with source.open("rb") as original, destination.open("xb") as copied:
        shutil.copyfileobj(original, copied)
    if hashlib.sha256(destination.read_bytes()).hexdigest() != expected:
        raise ValueError("The private executable does not match the frozen identity.")
    os.chown(destination, 0, group)
    destination.chmod(0o550)


async def send(child, data):
    child.stdin.write(encode_frame(data))
    await child.stdin.drain()


async def observe(child, timeout):
    return decode_frame(await asyncio.wait_for(child.stdout.readline(), timeout))


async def inside(base, uid, gid, before_net, before_mount, run, management_port):
    root = Path(base) / "state"
    boundary = open_boundary(root, int(uid), int(gid), int(before_net), int(before_mount))
    relinquish_admin(int(uid), int(gid))
    proxy = NativeAccountConnector(Path(base) / "authorization.sock", 0)
    addr = f"http://127.0.0.1:{proxy.server_address[1]}"
    variables = {"HOME":str(root),"TMPDIR":str(root),"PATH":"/usr/bin:/bin",
                 "R33_LOCAL_API_PORT":management_port,"R33_OUTER_NETWORK_INODE":before_net,
                 "https_proxy":addr,"http_proxy":addr,"HTTPS_PROXY":addr,"HTTP_PROXY":addr,
                 "no_proxy":"localhost,127.0.0.1","NO_PROXY":"localhost,127.0.0.1"}
    loop = asyncio.get_running_loop()
    a_stop = asyncio.Event()

    def revoked():
        (root / "local-grant-revoked").touch(exist_ok=True)
        a_stop.set()

    for name in (signal.SIGUSR1, signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        loop.add_signal_handler(name, revoked)
    child = None
    try:
        publish({"event":"private-linux-worker","boundary":boundary,"runtime_uid":os.getuid(),
                 "local_api_port":int(management_port),"provider_proxy_bound":True})
        child = await asyncio.create_subprocess_exec(
            str(Path(base) / "driver"), "serve-local-api", str(Path(base) / "engine"),
            str(root), run, cwd=root, env=variables, stderr=asyncio.subprocess.DEVNULL,
        )
        running = asyncio.create_task(child.wait())
        revoke_request = asyncio.create_task(a_stop.wait())
        await asyncio.wait((running, revoke_request), return_when=asyncio.FIRST_COMPLETED)
        if revoke_request.done() and not running.done():
            try:
                await asyncio.wait_for(asyncio.shield(running), 45)
            except asyncio.TimeoutError:
                child.terminate()
                await asyncio.wait_for(running, 5)
        revoke_request.cancel()
        await asyncio.gather(revoke_request, return_exceptions=True)
        return child.returncode or 0
    finally:
        proxy.close()


def validate(scope, message, login_sent, synthetic):
    operation = message.get("kind")
    if type(operation) is not str or scope != operation:
        return False
    if operation == "login":
        if synthetic or login_sent or set(message) != {"kind","username","password"}:
            return False
        return (type(message["username"]) is str and 1 <= len(message["username"].encode()) <= 512
                and type(message["password"]) is str and 1 <= len(message["password"].encode()) <= 2300)
    if operation not in PROVIDER_GATED_OPERATIONS or set(message) != {"kind"}:
        return False
    return synthetic or login_sent or operation == "inspect"


async def owned_stdin():
    pipe = asyncio.StreamReader(limit=FRAME_MAX)
    await asyncio.get_running_loop().connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(pipe), sys.stdin.buffer,
    )
    return pipe


async def enveloped_requests(child, proxy, synthetic, expires, run, minimum_receipt):
    loop = asyncio.get_running_loop()
    stopped = asyncio.Event()
    stop_reason = "external-stop"
    for name in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        loop.add_signal_handler(name, stopped.set)
    frames = await owned_stdin()
    lease = Lease(lifetime=40)
    lifetime_limit = time.monotonic() + max(0, expires-time.time())
    login_sent = False
    pending = None
    operation_ids = set()

    def refuse(code, identifier=None):
        publish({"ok":False,"code":code,"request":identifier})

    async def dispatch(identifier, value):
        try:
            if stopped.is_set() or not lease.permits(time.monotonic()):
                refuse("lease-closed",identifier)
                return
            await send(child, value)
            value.clear()
            native = await observe(child, 42)
            publish({"ok":True,"event":"operation-observed","request":identifier,"native":native})
        except (OSError, ValueError, asyncio.TimeoutError):
            refuse("native-result-unconfirmed",identifier)
            stopped.set()
        finally:
            value.clear()

    publish({"event":"local-api-foreground-ready","run":run, "deadline":expires, **minimum_receipt})
    try:
        while not stopped.is_set():
            now = time.monotonic()
            if not lease.permits(now) or now >= lifetime_limit or time.time() >= expires:
                stop_reason = "lease-expired"
                break
            try:
                data = await asyncio.wait_for(frames.readline(), 0.25)
            except asyncio.TimeoutError:
                continue
            if not data:
                stop_reason = "channel-closed"
                break
            request = decode_frame(data)
            del data
            kind = request.get("kind")
            if request == {"kind":"renew","run":run}:
                lease.renew(time.monotonic())
                continue
            if request == {"kind":"stop","run":run}:
                stop_reason = "user-stop"
                break
            identifier = request.get("request")
            if (kind != "execute" or request.get("run") != run
                    or type(identifier) is not str or not re.fullmatch(r"[0-9a-f]{32}", identifier)
                    or set(request) != {"kind","run","request","operation","input"}
                    or type(request["input"]) is not dict):
                refuse("outside-scope")
                continue
            if len(operation_ids) == 20 or identifier in operation_ids or (pending and not pending.done()):
                refuse("duplicate-or-busy",identifier)
                continue
            if not validate(request["operation"], request["input"], login_sent, synthetic):
                refuse("outside-scope",identifier)
                continue
            operation_ids.add(identifier)
            if stopped.is_set() or not lease.permits(time.monotonic()):
                refuse("lease-closed",identifier)
                break
            if request["operation"] == "login":
                login_sent = True
                proxy.activate()
            pending = asyncio.create_task(dispatch(identifier, request["input"]))
    finally:
        lease.revoke(time.monotonic(),stop_reason)
        cleanup_limit = time.monotonic()+44
        with suppress(ProcessLookupError):
            child.send_signal(signal.SIGUSR1)
        if pending is not None:
            try:
                await asyncio.wait_for(asyncio.shield(pending), 12)
            except asyncio.TimeoutError:
                pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)
        try:
            await send(child, {"kind":"end"})
            last = await observe(child, max(0.01, cleanup_limit-time.monotonic()-4))
            await asyncio.wait_for(child.wait(), max(0.01, cleanup_limit-time.monotonic()))
        except (OSError, ValueError, asyncio.TimeoutError):
            last = {"ok":False,"normal_owned_exit":False}
        publish({"event":"local-api-foreground-stopped","run":run,"reason":stop_reason,
                 "last_renewal_age":round(time.monotonic()-lease.last_renewed,3),
                 "provider_network":proxy.receipt(),"native":last})
    return child.returncode == 0 and last.get("normal_owned_exit") is True


async def supervisor(engine, driver, run, expires, synthetic):
    if os.getresuid() != (0,0,0) or not RUN.fullmatch(run) or not 0 < expires-time.time() <= 48*3600:
        raise ValueError("The owned Linux start request is invalid.")
    account = pwd.getpwnam("nobody")
    expectation = {}
    with tempfile.TemporaryDirectory(prefix="r33-local-api-", dir="/tmp") as work:
        base = Path(work).resolve()
        os.chown(base, 0, account.pw_gid)
        base.chmod(0o710)
        (base / "state").mkdir(mode=0o700)
        verified_copy(engine, base/"engine", NATIVE, account.pw_gid)
        verified_copy(driver, base/"driver", DRIVER, account.pw_gid)
        operator_socket = base/"authorization.sock"
        proxy = UnixOfficialProxy(
            operator_socket, lambda stream: expectation.get("net") is not None
            and namespace_peer_allowed(stream, expectation["net"], account.pw_uid),
        )
        child = None
        ready = False
        try:
            os.chown(operator_socket, 0, account.pw_gid)
            operator_socket.chmod(0o660)
            net, mount = namespace("net"), namespace("mnt")
            with socket.socket() as reserved:
                reserved.bind(("127.0.0.1",0))
                port = reserved.getsockname()[1]
                if port == 18886:
                    raise ValueError("The shared default address is outside the fixture.")
                argv = ["/usr/bin/python3","-B",str(HERE),"--inside",
                        *map(str,(base,account.pw_uid,account.pw_gid,net,mount,run,port))]
                child = await asyncio.create_subprocess_exec(
                    *launch_arguments(argv),stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,
                    start_new_session=True,
                )
                entry = await observe(child, 15)
                actual = entry["boundary"]
                if (entry.get("event") != "private-linux-worker" or entry.get("runtime_uid") != account.pw_uid
                        or actual["network_namespace"] == net or actual["mount_namespace"] == mount
                        or not actual["only_loopback"] or not actual["volatile_private_state"]):
                    raise ValueError("The expected namespaces are unavailable.")
                expectation["net"] = actual["network_namespace"]
                initial = await observe(child, 25)
                if initial.get("account") != "logged-out" or initial.get("pro_observations") != []:
                    if synthetic:
                        print("Signed-out startup reply: " + json.dumps(initial), file=sys.stderr)
                    raise ValueError("The new isolation instance is not signed out.")
                ready = True
                probe = subprocess.run(
                    ["/usr/bin/python3","-B",str(HERE.with_name("check_worker_boundary.py")),
                     "--drop-observer",str(base),str(port),str(account.pw_uid),str(account.pw_gid)],
                    capture_output=True, timeout=8,
                )
                if probe.returncode:
                    if synthetic:
                        print("Outside observer failure: " + probe.stderr.decode(errors="replace"),
                              file=sys.stderr)
                    raise ValueError("The ordinary identity could not complete the isolation check.")
                outside = json.loads(probe.stdout)
                if (outside["same_runtime_uid"] != account.pw_uid or not outside["loopback_port_refused"]
                        or not outside["authorization_socket_refused"] or outside["state_read"] not in ("EACCES","ENOENT")):
                    raise ValueError("An outside process can reach the private state or listener.")
            good = await enveloped_requests(child, proxy, synthetic, expires, run,
                                            {"isolation":entry,"outside_check":outside,"instance":initial})
        finally:
            if ready and child and child.returncode is None:
                with suppress(OSError, ValueError, asyncio.TimeoutError, ProcessLookupError):
                    child.send_signal(signal.SIGUSR1)
                    await send(child, {"kind":"end"})
                    await observe(child,8)
            proxy.close()
            if child and child.returncode is None:
                with suppress(ProcessLookupError):
                    os.killpg(child.pid,signal.SIGTERM)
                try:
                    await asyncio.wait_for(child.wait(),4)
                except asyncio.TimeoutError:
                    with suppress(ProcessLookupError):
                        os.killpg(child.pid,signal.SIGKILL)
                    await asyncio.wait_for(child.wait(),4)
    publish({"event":"local-api-cleanup","run":run,"private_state_removed":not base.exists(),
             "driver_sha256":DRIVER,"native_sha256":NATIVE,"normal_scope_exit":good})
    return 0 if good else 2


if __name__ == "__main__":
    os.umask(0o077)
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--inside",nargs=7)
    cli.add_argument("--engine",type=Path)
    cli.add_argument("--driver",type=Path)
    cli.add_argument("--run")
    cli.add_argument("--expires",type=int)
    cli.add_argument("--synthetic",action="store_true")
    args=cli.parse_args()
    try:
        if args.inside:
            raise SystemExit(asyncio.run(inside(*args.inside)))
        if not all((args.engine,args.driver,args.run,args.expires)):
            cli.error("Supply the verified executable pair and one bounded grant.")
        raise SystemExit(asyncio.run(supervisor(args.engine,args.driver,args.run,args.expires,args.synthetic)))
    except (OSError, ValueError, asyncio.TimeoutError, subprocess.SubprocessError) as error:
        if args.synthetic:
            print(f"Synthetic scope fixture failed: {type(error).__name__}: {error}", file=sys.stderr)
        publish({"ok":False,"code":"owned-local-api-start-or-cleanup-unconfirmed"})
        raise SystemExit(2) from None
