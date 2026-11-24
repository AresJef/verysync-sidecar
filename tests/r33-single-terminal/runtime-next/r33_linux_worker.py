#!/usr/bin/python3
"""Run the R33 test peer over one SSH channel with its own local lease."""

import argparse
import asyncio
import hashlib
import json
import os
import platform
import shutil
from pathlib import Path
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time

from r33_protocol import DENIED, FRAME_MAX, Lease, ProtocolError, REQUEST_ID, RUN, decode_frame, encode_frame


TASK_PROGRAM = """from pathlib import Path
import sys
import time
target = Path(sys.argv[1])
while True:
    with target.open("ab") as sample:
        sample.write(b"tick\\n")
    time.sleep(.20)
"""
ROOT = Path.home()/".local/share/verysync-r33/sessions"
CONTROL = "g.sock"


def private_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise OSError("The Linux session directory is not private.")
    if path.resolve() != path:
        raise OSError("The Linux session directory must use its real path.")


def save_object(path, value):
    pending = path.with_suffix(".new")
    with pending.open("w", encoding="ascii") as stream:
        json.dump(value, stream, separators=(",", ":"), allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(pending, path)


def readback(directory, identifier, *, existing):
    if type(identifier) is not str or not REQUEST_ID.fullmatch(identifier):
        return DENIED
    receipt = directory/f"readback-{identifier}"
    if existing:
        try:
            data = json.loads(receipt.read_bytes())
        except FileNotFoundError:
            return {"ok":False,"code":"no-stored-readback"}
        except ValueError:
            return {"ok":False,"code":"readback-pending"}
        return data
    try:
        with receipt.open("xb") as audit_file:
            sample = directory/f"sample-{identifier}"
            observation = None
            if sample.is_file():
                data = sample.read_bytes()
                observation = {"operation":"write-sample","sample_present":True,
                               "length":len(data),"sha256":hashlib.sha256(data).hexdigest()}
            result = {"ok":True,"observed":observation}
            audit_file.write(encode_frame(result))
            audit_file.flush()
            os.fsync(audit_file.fileno())
            return result
    except FileExistsError:
        return DENIED


def secure_initial(line):
    hello = decode_frame(line)
    kind = hello.get("kind")
    expected = {"kind", "run"}
    if set(hello) == expected | {"absolute_epoch"} and kind == "start":
        end = hello["absolute_epoch"]
        if type(end) is not int or not 0 < end - time.time() <= 48 * 3600:
            raise ProtocolError("The approved standby deadline is invalid.")
    elif set(hello) == expected and kind in ("start", "recover"):
        end = None
    else:
        raise ProtocolError("A lease handshake is required.")
    run = hello["run"]
    if type(run) is not str or not RUN.fullmatch(run):
        raise ProtocolError("The run identifier is invalid.")
    return kind, run, end


class Guardian:
    def __init__(self, directory, absolute_epoch=None):
        self.directory = directory
        self.lease = Lease()
        self.absolute_epoch = absolute_epoch
        self.absolute_limit = time.monotonic() + (absolute_epoch - time.time()) if absolute_epoch else None
        self.renewals = 0
        self.cleaned = asyncio.Event()
        self.started = False
        self.operations = {}
        self.lifecycle = asyncio.Lock()
        self.tasks = {}
        self.closed = asyncio.Event()
        self.finished = None

    def permits(self):
        now = time.monotonic()
        if self.absolute_epoch and (now >= self.absolute_limit or time.time() >= self.absolute_epoch):
            self.lease.revoke(now, "absolute-expired")
        return self.lease.permits(now)

    def receipt(self):
        return {
            "ok": True,
            "state": "active" if self.lease.revoked_at is None else "revoked",
            "renewed": self.lease.last_renewed,
            "deadline": self.lease.deadline,
            "reason": self.lease.reason,
            "stopped": self.finished,
            "writes": sum(case["operation"] == "write-sample" for case in self.operations.values()),
            "tasks": len(self.tasks),
            "readbacks": sum(1 for _ in self.directory.glob("readback-*")),
            "renewals": self.renewals,
            "standby": self.lease.revoked_at is None and not self.tasks,
            "native_test_listeners": 0,
            "architecture": platform.machine(),
            "absolute_epoch": self.absolute_epoch,
        }

    async def end_task(self, task):
        if task.returncode is None:
            try:
                os.killpg(task.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            await asyncio.wait_for(task.wait(), 1.5)
        except asyncio.TimeoutError:
            try:
                os.killpg(task.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await asyncio.wait_for(task.wait(), 1.5)
        return task.returncode == 0

    async def stop(self, reason):
        self.lease.revoke(time.monotonic(), reason)
        async with self.lifecycle:
            if self.finished is not None:
                return
            normal = True
            for task in self.tasks.values():
                normal = await self.end_task(task) and normal
            self.tasks.clear()
            self.finished = time.monotonic()
            save_object(self.directory/"receipt.json", self.receipt() | {"normal_task_exit": normal})
            self.closed.set()

    async def finish_observer(self, identifier):
        async with self.lifecycle:
            if not self.permits() or len(self.tasks) != 1:
                return DENIED
            prior, task = next(iter(self.tasks.items()))
            normal = await self.end_task(task)
            del self.tasks[prior]
            sample = self.directory/"observer-sample"
            data = sample.read_bytes()
            if not data or data != b"tick\n" * (len(data)//5):
                return DENIED
            result = {"ok": normal, "standby": True, "normal_task_exit": normal,
                      "sample_bytes": len(data), "sample_sha256": hashlib.sha256(data).hexdigest(),
                      "native_test_listeners": 0}
            save_object(self.directory/f"observer-{prior}.json", result)
            sample.unlink()
            self.operations[identifier] = {"operation": "finish-observer", "committed": True}
            return result

    async def monitor(self):
        while not self.closed.is_set():
            if not self.permits():
                await self.stop(self.lease.reason or "expired")
                return
            await asyncio.sleep(.1)

    async def respond(self, request, recover):
        kind = request.get("kind")
        if kind == "status" and set(request) == {"kind"}:
            return self.receipt()
        if kind == "stop" and set(request) == {"kind"}:
            await self.stop("operator")
            return self.receipt()
        if kind in ("readback","stored-readback") and set(request) == {"kind", "id"}:
            if self.finished is None:
                return DENIED
            observed = readback(self.directory, request["id"], existing=kind=="stored-readback")
            if kind=="readback":
                save_object(self.directory/"receipt.json", self.receipt())
            return observed
        if kind == "purge" and set(request) == {"kind"} and self.absolute_epoch and self.finished is not None:
            shutil.rmtree(self.directory)
            self.cleaned.set()
            return {"ok": True, "owned_worker_directory_removed": not self.directory.exists()}
        if recover or self.closed.is_set() or not self.permits():
            return DENIED
        if kind == "renew" and set(request) == {"kind"}:
            if self.lease.renew(time.monotonic()):
                self.renewals += 1
                return self.receipt()
            return DENIED
        if kind != "execute" or set(request) != {"kind", "id", "operation"}:
            return DENIED
        identifier, operation = request["id"], request["operation"]
        if type(identifier) is not str or not REQUEST_ID.fullmatch(identifier) or identifier in self.operations:
            return DENIED
        if operation == "finish-observer" and self.absolute_epoch:
            return await self.finish_observer(identifier)
        if operation == "write-sample":
            with (self.directory/f"sample-{identifier}").open("xb") as sample:
                sample.write(b"R33 synthetic sample\n")
                sample.flush()
                os.fsync(sample.fileno())
            self.operations[identifier] = {"operation": operation, "committed": True}
            save_object(self.directory/"receipt.json", self.receipt())
            return {"ok": True, "committed": True}
        if operation == "start-observer":
            async with self.lifecycle:
                if not self.permits() or self.tasks:
                    return DENIED
                task = await asyncio.create_subprocess_exec(
                    sys.executable, "-B", "-c", TASK_PROGRAM, str(self.directory/"observer-sample"),
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                )
                self.tasks[identifier] = task
                self.operations[identifier] = {"operation": operation, "committed": True}
            if not self.permits():
                await self.stop(self.lease.reason)
                return DENIED
            return {"ok": True, "running": True}
        return DENIED

    async def connection(self, reader, writer):
        try:
            greeting = await asyncio.wait_for(reader.readline(), 5)
            mode, run, end = secure_initial(greeting)
            if (run != self.directory.name
                    or mode == "start" and (self.started or end != self.absolute_epoch)):
                writer.write(encode_frame(DENIED))
                await writer.drain()
                return
            recover = mode == "recover"
            if not recover:
                self.started = True
            writer.write(encode_frame(self.receipt()))
            await writer.drain()
            while True:
                line = await reader.readline()
                if not line:
                    break
                result = await self.respond(decode_frame(line), recover)
                writer.write(encode_frame(result))
                await writer.drain()
        except (OSError, ValueError, asyncio.TimeoutError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def run(self):
        server = await asyncio.start_unix_server(self.connection, str(self.directory/CONTROL),
                                                limit=FRAME_MAX)
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            asyncio.get_running_loop().add_signal_handler(
                sig, lambda: asyncio.create_task(self.stop("peer-signal")),
            )
        watcher = asyncio.create_task(self.monitor())
        try:
            await self.closed.wait()
            try:
                await asyncio.wait_for(self.cleaned.wait(), 2)
            except asyncio.TimeoutError:
                pass
            else:
                # Let the already-connected stdio relay send the final receipt.
                await asyncio.sleep(.1)
        finally:
            server.close()
            await server.wait_closed()
            watcher.cancel()
            await self.stop("process-exit")
            (self.directory/CONTROL).unlink(missing_ok=True)


def exchange_stdio(channel):
    with selectors.DefaultSelector() as poll:
        poll.register(sys.stdin.fileno(), selectors.EVENT_READ, "client")
        poll.register(channel, selectors.EVENT_READ, "guard")
        while True:
            for key, _ in poll.select():
                if key.data == "client":
                    data = os.read(sys.stdin.fileno(), FRAME_MAX)
                    if not data:
                        return
                    channel.sendall(data)
                else:
                    data = channel.recv(FRAME_MAX)
                    if not data:
                        return
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()


def transport(root):
    first = sys.stdin.buffer.raw.readline(FRAME_MAX+1)
    mode, run, absolute_epoch = secure_initial(first)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_directory(root)
    directory = root/run
    guard = None
    if mode == "start":
        directory.mkdir(mode=0o700)
        command = [sys.executable, "-B", str(Path(__file__).resolve()), "guard", "--root", str(directory)]
        if absolute_epoch:
            command += ["--absolute-epoch", str(absolute_epoch)]
        guard = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True,
        )
    private_directory(directory)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        for _ in range(40 if mode == "start" else 1):
            try:
                channel.connect(str(directory/CONTROL))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(.05)
        else:
            receipt = directory/"receipt.json"
            if mode == "recover" and receipt.is_file():
                report = json.loads(receipt.read_bytes())
                if report.get("state") == "revoked" and report.get("stopped") is not None:
                    sys.stdout.buffer.write(encode_frame(report))
                    sys.stdout.buffer.flush()
                    while True:
                        line = sys.stdin.buffer.readline(FRAME_MAX+1)
                        if not line:
                            break
                        request = decode_frame(line)
                        if request == {"kind": "stop"} or request == {"kind": "status"}:
                            response = report | {"readbacks": sum(1 for _ in directory.glob("readback-*"))}
                        elif request.get("kind") in ("readback","stored-readback") and set(request) == {"kind","id"}:
                            response = readback(directory, request["id"], existing=request["kind"]=="stored-readback")
                        else:
                            response = DENIED
                        sys.stdout.buffer.write(encode_frame(response))
                        sys.stdout.buffer.flush()
                    return
            raise OSError("The independent peer is unavailable.")
        channel.sendall(first)
        exchange_stdio(channel)
    if guard is not None and not directory.exists():
        guard.wait(timeout=4)


async def launch_guard(directory, absolute_epoch):
    await Guardian(directory, absolute_epoch).run()


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("operation", choices=("stdio", "guard"))
    args.add_argument("--root", type=Path, default=ROOT)
    args.add_argument("--absolute-epoch", type=int)
    options = args.parse_args()
    os.umask(0o077)
    try:
        if options.operation == "stdio":
            transport(options.root)
        else:
            private_directory(options.root)
            asyncio.run(launch_guard(options.root, options.absolute_epoch))
    except (OSError, ValueError, asyncio.TimeoutError):
        print("The restricted peer session did not complete.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
