#!/usr/bin/python3
"""Operate a bounded R33 handoff from a foreground terminal."""

import argparse
import asyncio
from dataclasses import dataclass
import json
import os
from pathlib import Path
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time

from r33_protocol import (
    DENIED, FRAME_MAX, HEARTBEAT_SECONDS, RUN, OperatorCancelled, ProtocolError, Request, decode_frame,
    encode_frame, peer_uid,
)
from r33_ssh import Destination


BUNDLE = Path(__file__).resolve().parent
TMP = Path("/private/tmp") if sys.platform == "darwin" else Path("/tmp")
PUBLIC_OPERATIONS = {
    "linux": frozenset(("observe", "start-observer", "write-sample")),
    "pro": frozenset(("observe",)),
    "github": frozenset(("observe",)),
}
PENDING = {"ok": False, "code": "result-pending"}
UNAVAILABLE = {"ok": False, "code": "unavailable"}


class Withdrawn(Exception):
    pass


def private_file(path):
    info = path.lstat()
    if path.resolve() != path or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Use a file owned exclusively by the operator.")
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Choose a regular operator file.")
    return path


class Journal:
    def __init__(self, path, run):
        base = path.parent
        if not path.is_absolute() or base.resolve() != base or base.stat().st_uid != os.getuid():
            raise ValueError("Choose an absolute evidence path in an operator-owned directory.")
        if base.stat().st_mode & 0o022:
            raise ValueError("Choose an evidence directory that only the operator can change.")
        self.path, self.run = path, run
        with path.open("xb"):
            pass

    def record(self, event, **data):
        receipt = {"run": self.run, "event": event, "monotonic": time.monotonic(), **data}
        with self.path.open("ab", buffering=0) as log:
            log.write(encode_frame(receipt))
            os.fsync(log.fileno())


class Channel:
    def __init__(self, process):
        self.process = process
        self.lock = asyncio.Lock()
        self.broken = False

    async def call(self, item, before_send=None, deadline=8):
        async with self.lock:
            if self.broken or self.process.returncode is not None:
                raise ConnectionError("The private channel has closed.")
            if before_send:
                before_send()
            self.process.stdin.write(encode_frame(item))
            try:
                await asyncio.wait_for(self.process.stdin.drain(), deadline)
                reply = await asyncio.wait_for(self.process.stdout.readline(), deadline)
                return decode_frame(reply)
            except (OSError, ValueError, asyncio.TimeoutError, asyncio.CancelledError):
                self.broken = True
                raise

    async def close(self):
        self.process.stdin.close()
        try:
            await asyncio.wait_for(self.process.wait(), 2)
        except asyncio.TimeoutError:
            try:
                self.process.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(self.process.wait(), 2)
            except asyncio.TimeoutError:
                try:
                    self.process.kill()
                except ProcessLookupError:
                    pass
                await self.process.wait()


class Linux:
    def __init__(self, channel):
        self.channel = channel

    @classmethod
    async def open(cls, profile, runtime, run, mode="start"):
        data = profile.copy()
        identity = data.pop("identity", None)
        command = Destination.parse(data).command(runtime, Path(identity) if identity else None)
        # OpenSSH prompts on the operator's controlling terminal. Its stdin is
        # reserved for the fixed peer protocol. No parent environment is passed.
        child = await asyncio.create_subprocess_exec(
            sys.executable, "-B", str(BUNDLE/"r33_ssh_exec.py"), *command,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=None,
            limit=FRAME_MAX, env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home())},
        )
        channel = Channel(child)
        try:
            reply = await channel.call({"kind": mode, "run": run}, deadline=80)
            if reply.get("ok") is not True or reply.get("state") not in ("active", "revoked"):
                raise ConnectionError("The fixed SSH peer did not accept the session.")
        except BaseException:
            await channel.close()
            raise
        return cls(channel)

    async def execute(self, work, before_send):
        if work.request.operation == "observe":
            reply = await self.channel.call({"kind": "status"}, before_send)
            return self.redact(reply)
        message = {"kind": "execute", "id": work.request.request, "operation": work.request.operation}
        reply = await self.channel.call(message, before_send)
        if reply.get("ok") is not True:
            return DENIED
        return {"ok": True, "committed": reply.get("committed") is True,
                "running": reply.get("running") is True}

    async def renew(self, before_send):
        reply = await self.channel.call({"kind": "renew"}, before_send)
        if reply.get("ok") is not True or reply.get("state") != "active":
            raise ConnectionError("The Linux lease is no longer active.")

    @staticmethod
    def redact(reply):
        if reply.get("ok") is not True:
            return UNAVAILABLE
        state = reply.get("state")
        if state not in ("active", "revoked"):
            return UNAVAILABLE
        return {"ok": True, "state": state,
                "tasks": reply.get("tasks") if type(reply.get("tasks")) is int else None,
                "writes": reply.get("writes") if type(reply.get("writes")) is int else None,
                "stopped": type(reply.get("stopped")) in (float, int)}

    async def stop(self, unknown, journal):
        try:
            terminal = self.redact(await self.channel.call({"kind": "stop"}, deadline=5))
            if terminal.get("state") != "revoked" or terminal.get("tasks") != 0 or not terminal.get("stopped"):
                return {"state": "pending-confirmation"}
            for identifier in unknown:
                result = await self.channel.call({"kind": "readback", "id": identifier}, deadline=5)
                observed = result.get("observed")
                journal.record("write-readback", target="linux", request=identifier,
                               verified=result.get("ok") is True, sample_present=(
                                   type(observed) is dict and observed.get("sample_present") is True))
            return {"state": "stopped", "writes": terminal["writes"]}
        except (OSError, ValueError, asyncio.TimeoutError):
            return {"state": "pending-confirmation"}
        finally:
            await self.channel.close()


@dataclass
class Work:
    request: Request
    response: asyncio.Future
    dispatched: bool = False


class Scope:
    def __init__(self, name, backend, allowed, journal):
        self.name = name
        self.backend = backend
        self.allowed = frozenset(allowed)
        self.journal = journal
        self.revoked = False
        self.queue = asyncio.Queue(maxsize=8)
        self.seen = set()
        self.possible_writes = set()
        self.worker = asyncio.create_task(self.execute())
        self.ended = asyncio.Event()
        self.final = None

    def guard(self, work):
        if self.revoked:
            raise Withdrawn
        work.dispatched = True
        ident = work.request.request
        if work.request.operation == "write-sample":
            self.possible_writes.add(ident)
            self.journal.record("write-submitted", target=self.name, request=ident)

    async def execute(self):
        try:
            while not self.revoked:
                work = await self.queue.get()
                if work is None:
                    break
                request = work.request
                try:
                    if self.revoked:
                        raise Withdrawn
                    result = await self.backend.execute(work, lambda: self.guard(work))
                    if request.request in self.possible_writes:
                        if self.revoked:
                            result = PENDING
                        elif result.get("ok") is True:
                            self.journal.record("write-acknowledged", target=self.name, request=request.request)
                            self.possible_writes.discard(request.request)
                except Withdrawn:
                    result = DENIED
                except (OSError, ValueError, asyncio.TimeoutError):
                    result = PENDING if work.dispatched else UNAVAILABLE
                if not work.response.done():
                    work.response.set_result(result)
        finally:
            self.ended.set()

    async def submit(self, request):
        if self.revoked or request.operation not in self.allowed or request.request in self.seen:
            return DENIED
        if self.queue.full() or len(self.seen) >= 256:
            return {"ok": False, "code": "busy"}
        result = asyncio.get_running_loop().create_future()
        work = Work(request, result)
        self.seen.add(request.request)
        self.journal.record("queued", target=self.name, request=request.request)
        self.queue.put_nowait(work)
        return await asyncio.shield(result)

    def withdraw(self):
        if self.revoked:
            return
        self.revoked = True
        self.journal.record("scope-revoked", target=self.name)
        while not self.queue.empty():
            work = self.queue.get_nowait()
            if not work.response.done():
                work.response.set_result(DENIED)
        # Wake the one dispatcher if it is waiting on an empty queue.
        self.queue.put_nowait(None)

    async def finish(self):
        self.withdraw()
        try:
            await asyncio.wait_for(self.ended.wait(), 18)
            self.final = await self.backend.stop(sorted(self.possible_writes), self.journal)
        except (OSError, ValueError, asyncio.TimeoutError):
            self.final = {"state": "pending-confirmation"}
        self.journal.record("scope-terminal", target=self.name, result=self.final)
        return self.final


class Supervisor:
    def __init__(self, run, executor_uid, journal):
        self.run, self.executor_uid, self.journal = run, executor_uid, journal
        self.status = "active"
        self.scopes = {}
        self.done = asyncio.Event()
        self.clients = set()
        self.stopping = {}

    def snapshot(self):
        result = {"ok": True, "local": self.status}
        for name in PUBLIC_OPERATIONS:
            scope = self.scopes.get(name)
            result[name] = scope.final if scope and scope.final else {
                "state": "revoked" if scope.revoked else "active"} if scope else {"state": "not-enabled"}
        return result

    def revoke(self, reason):
        if self.status != "active":
            return
        self.status = "revoked"
        self.journal.record("local-revoked", reason=reason)
        for name, scope in self.scopes.items():
            self.stop_scope(name, scope)
        self.done.set()

    def stop_scope(self, name, scope):
        scope.withdraw()
        if name not in self.stopping:
            self.stopping[name] = asyncio.create_task(scope.finish())

    async def renew_linux(self):
        scope = self.scopes.get("linux")
        if scope is None:
            return
        while self.status == "active" and not scope.revoked:
            try:
                await asyncio.wait_for(self.done.wait(), HEARTBEAT_SECONDS)
                return
            except asyncio.TimeoutError:
                pass
            try:
                def live():
                    if self.status != "active" or scope.revoked:
                        raise Withdrawn
                await scope.backend.renew(live)
            except (OSError, ValueError, asyncio.TimeoutError, Withdrawn):
                self.stop_scope("linux", scope)
                break

    async def connection(self, reader, writer):
        if len(self.clients) >= 16:
            writer.close()
            return
        self.clients.add(writer)
        try:
            uid = peer_uid(writer.get_extra_info("socket"))
            if uid not in (os.getuid(), self.executor_uid):
                writer.write(encode_frame(DENIED))
                await writer.drain()
                return
            while line := await asyncio.wait_for(reader.readline(), 60):
                try:
                    request = Request.parse(decode_frame(line))
                except ProtocolError:
                    result = DENIED
                else:
                    result = await self.route(uid, request)
                writer.write(encode_frame(result))
                await asyncio.wait_for(writer.drain(), 2)
        except (OSError, ValueError, asyncio.TimeoutError):
            pass
        finally:
            self.clients.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def route(self, uid, request):
        if request.run != self.run:
            return DENIED
        if request.target == "handoff":
            if request.operation == "status":
                return self.snapshot()
            if request.operation == "stop" and uid == os.getuid():
                self.revoke("operator-stop")
                return self.snapshot()
            return DENIED
        scope = self.scopes.get(request.target)
        if request.operation == "withdraw" and scope and uid == os.getuid():
            self.stop_scope(request.target, scope)
            return self.snapshot()
        if self.status != "active" or scope is None:
            return DENIED
        return await scope.submit(request)


async def query(socket_path, request):
    reader, writer = await asyncio.open_unix_connection(str(socket_path), limit=FRAME_MAX)
    try:
        writer.write(encode_frame(request.__dict__))
        await writer.drain()
        return decode_frame(await asyncio.wait_for(reader.readline(), 20))
    finally:
        writer.close()
        await writer.wait_closed()


def run_profile(path, synthetic):
    value = json.loads(private_file(path).read_text())
    if type(value) is not dict or not value or not set(value) <= set(PUBLIC_OPERATIONS):
        raise ValueError("Choose at least one supported target.")
    result = {}
    for name, data in value.items():
        if type(data) is not dict or set(data) != {"allow", "connection"}:
            raise ValueError("The target profile has unexpected fields.")
        allowed = data["allow"]
        if type(allowed) is not list or not allowed or any(type(a) is not str for a in allowed):
            raise ValueError("Choose named operations for the target.")
        expected = PUBLIC_OPERATIONS[name] if synthetic else frozenset(("observe",))
        if not set(allowed) <= expected:
            raise ValueError("The target profile contains an unapproved operation.")
        result[name] = frozenset(allowed), data["connection"]
    return result


def watch_operator_terminal(supervisor):
    """End the foreground grant on terminal EOF or an explicit STOP line."""
    fd = sys.stdin.fileno()
    loop = asyncio.get_running_loop()

    def receive():
        try:
            value = os.read(fd, 512)
        except OSError:
            value = b""
        if not value:
            supervisor.revoke("operator-eof")
            loop.remove_reader(fd)
        elif value.strip() == b"STOP":
            supervisor.revoke("operator-quit")
            loop.remove_reader(fd)

    loop.add_reader(fd, receive)
    return lambda: loop.remove_reader(fd)


async def start(args):
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValueError("Start the handoff in a private operator terminal.")
    if not 0 < args.executor_uid < 2**32 or os.getuid() == 0:
        raise ValueError("Use unprivileged operator and executor system accounts.")
    if not args.synthetic and args.executor_uid == os.getuid():
        raise ValueError("Use separate unprivileged operator and executor system accounts.")
    profile = run_profile(args.profile, args.synthetic)
    print(f"VerySync R33 acceptance. Access expires after {args.minutes} minutes.", flush=True)
    for name, (allowed, connection) in profile.items():
        target = f" at {Destination.parse({k:v for k,v in connection.items() if k != 'identity'}).host}" if name=="linux" else ""
        print(f"{name}{target} ({', '.join(sorted(allowed))})", flush=True)
    if input("Type START to grant these operations. ") != "START":
        raise ValueError("The operator did not start this handoff.")
    run = secrets.token_hex(16)
    with tempfile.TemporaryDirectory(prefix="r33-owned-", dir=TMP) as private, \
            tempfile.TemporaryDirectory(prefix="r33-client-", dir=TMP) as public:
        runtime, entrance = Path(private).resolve(), Path(public).resolve()
        # Owner access only until the socket is bound and permissions are set.
        journal = Journal(args.evidence, run)
        supervisor = Supervisor(run, args.executor_uid, journal)
        journal.record("owner-transport-paths", private=str(runtime), public=str(entrance))
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            loop.add_signal_handler(sig, supervisor.revoke, signal.Signals(sig).name)
        socket_path = entrance/"b.sock"
        server = None
        renewal = None
        try:
            for name, (allowed, connection) in profile.items():
                if supervisor.status != "active":
                    break
                if name == "linux":
                    backend = await Linux.open(connection, runtime, run)
                else:
                    from r33_accounts import open_backend
                    backend = await open_backend(name, connection, runtime, run, args.synthetic, supervisor.done)
                scope = Scope(name, backend, allowed, journal)
                supervisor.scopes[name] = scope
                if supervisor.status != "active":
                    supervisor.stop_scope(name, scope)
            if supervisor.status != "active":
                return 1
            server = await asyncio.start_unix_server(supervisor.connection, str(socket_path),
                                                      limit=FRAME_MAX, backlog=16)
            socket_path.chmod(0o666)
            entrance.chmod(0o711)
            journal.record("local-ready")
            print("R33_READY "+json.dumps({"run":run, "socket":str(socket_path)}), flush=True)
            renewal = asyncio.create_task(supervisor.renew_linux())
            expiry = loop.call_later(args.minutes*60, supervisor.revoke, "authorization-expired")
            stop_watching = watch_operator_terminal(supervisor)
            try:
                await supervisor.done.wait()
            finally:
                stop_watching()
                expiry.cancel()
        except OperatorCancelled:
            return 1
        finally:
            supervisor.revoke("normal-exit")
            if renewal:
                await asyncio.gather(renewal, return_exceptions=True)
            await asyncio.gather(*supervisor.stopping.values())
            if server:
                await asyncio.sleep(1.1)
                server.close()
                await server.wait_closed()
            for connection in supervisor.clients:
                connection.close()
            final = supervisor.snapshot()
            print("R33_STOPPED "+json.dumps(final), flush=True)
            journal.record("terminal", result=final)
    return 0


async def recover(args):
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValueError("Open the pending handoff from a private operator terminal.")
    if not RUN.fullmatch(args.run):
        raise ValueError("Enter the previous run identifier.")
    profile = run_profile(args.profile, args.synthetic)
    if args.target not in profile:
        raise ValueError("Choose a target in the private profile for that run.")
    print(f"Check and stop the previous {args.target} session.", flush=True)
    if input("Type RECOVER to continue. ") != "RECOVER":
        raise ValueError("No recovery request was sent.")
    _, connection = profile[args.target]
    if args.target == "pro" and args.synthetic:
        from r33_accounts import recover_synthetic_account
        outcome = await recover_synthetic_account(connection, args.run)
    elif args.target == "linux":
        with tempfile.TemporaryDirectory(prefix="r33-recover-", dir=TMP) as directory:
            backend = await Linux.open(connection, Path(directory).resolve(), args.run, mode="recover")
            outcome = await backend.stop((), None)
    else:
        raise ValueError("The requested private recovery service has not been prepared.")
    response = {"local": "no-new-grant", args.target: outcome}
    print("R33_RECOVERY " + json.dumps(response), flush=True)
    return 1 if outcome["state"] == "pending-confirmation" else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    handle = commands.add_parser("start", help="Start a foreground, time-limited handoff.")
    handle.add_argument("--profile", type=Path, required=True)
    handle.add_argument("--executor-uid", type=int, required=True)
    handle.add_argument("--minutes", type=int, required=True)
    handle.add_argument("--evidence", type=Path, required=True)
    handle.add_argument("--synthetic", action="store_true")
    for name in ("status", "stop", "request", "withdraw"):
        action = commands.add_parser(name)
        action.add_argument("--socket", type=Path, required=True)
        action.add_argument("--run", required=True)
        if name in ("request", "withdraw"):
            action.add_argument("--target", choices=tuple(PUBLIC_OPERATIONS), required=True)
        if name == "request":
            action.add_argument("operation")
    restore = commands.add_parser("recover", help="Check and stop a previous handoff.")
    restore.add_argument("--profile", type=Path, required=True)
    restore.add_argument("--run", required=True)
    restore.add_argument("--target", choices=("pro", "linux"), required=True)
    restore.add_argument("--synthetic", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.command == "start":
            if not 1 <= args.minutes <= 2880:
                raise ValueError("Choose one to 2880 minutes of foreground access.")
            return asyncio.run(start(args))
        if args.command == "recover":
            return asyncio.run(recover(args))
        target = getattr(args, "target", "handoff")
        request = Request.parse({"run":args.run,"target":target,
                                 "operation":getattr(args,"operation",args.command),"request":secrets.token_hex(16)})
        receipt = asyncio.run(query(args.socket, request))
        print(json.dumps(receipt, ensure_ascii=True))
        return 0 if receipt.get("ok") else 2
    except KeyboardInterrupt:
        print("The local handoff stopped.", file=sys.stderr)
        return 130
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    except (OSError, asyncio.TimeoutError):
        print("The handoff could not finish. Check the foreground status and retained receipts.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
