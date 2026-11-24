#!/usr/bin/python3
"""Run the R33 test peer over one SSH channel with its own local lease."""

import argparse
import asyncio
import hashlib
import json
import os
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
    if set(hello) != {"kind", "run"} or hello["kind"] not in {"start", "recover"}:
        raise ProtocolError("A lease handshake is required.")
    run = hello["run"]
    if type(run) is not str or not RUN.fullmatch(run):
        raise ProtocolError("The run identifier is invalid.")
    return hello["kind"], run


class Guardian:
    def __init__(self, directory):
        self.directory = directory
        self.lease = Lease()
        self.started = False
        self.operations = {}
        self.lifecycle = asyncio.Lock()
        self.tasks = {}
        self.closed = asyncio.Event()
        self.finished = None

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
        }

    async def stop(self, reason):
        self.lease.revoke(time.monotonic(), reason)
        async with self.lifecycle:
            if self.finished is not None:
                return
            for task in self.tasks.values():
                if task.returncode is None:
                    try:
                        os.killpg(task.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
            for task in self.tasks.values():
                try:
                    await asyncio.wait_for(task.wait(), 1.5)
                except asyncio.TimeoutError:
                    try:
                        os.killpg(task.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    await asyncio.wait_for(task.wait(), 1.5)
            self.tasks.clear()
            self.finished = time.monotonic()
            save_object(self.directory/"receipt.json", self.receipt())
            self.closed.set()

    async def monitor(self):
        while not self.closed.is_set():
            if not self.lease.permits(time.monotonic()):
                await self.stop("expired")
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
        if recover or self.closed.is_set() or not self.lease.permits(time.monotonic()):
            return DENIED
        if kind == "renew" and set(request) == {"kind"}:
            if self.lease.renew(time.monotonic()):
                return self.receipt()
            return DENIED
        if kind != "execute" or set(request) != {"kind", "id", "operation"}:
            return DENIED
        identifier, operation = request["id"], request["operation"]
        if type(identifier) is not str or not REQUEST_ID.fullmatch(identifier) or identifier in self.operations:
            return DENIED
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
                if not self.lease.permits(time.monotonic()) or self.tasks:
                    return DENIED
                task = await asyncio.create_subprocess_exec(
                    sys.executable, "-B", "-c", TASK_PROGRAM, str(self.directory/"observer-sample"),
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                )
                self.tasks[identifier] = task
                self.operations[identifier] = {"operation": operation, "committed": True}
            if not self.lease.permits(time.monotonic()):
                await self.stop(self.lease.reason)
                return DENIED
            return {"ok": True, "running": True}
        return DENIED

    async def connection(self, reader, writer):
        try:
            greeting = await asyncio.wait_for(reader.readline(), 5)
            mode, run = secure_initial(greeting)
            if run != self.directory.name or mode == "start" and self.started:
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
            await asyncio.sleep(2)
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
    mode, run = secure_initial(first)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_directory(root)
    directory = root/run
    if mode == "start":
        directory.mkdir(mode=0o700)
        subprocess.Popen(
            [sys.executable, "-B", str(Path(__file__).resolve()), "guard", "--root", str(directory)],
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


async def launch_guard(directory):
    await Guardian(directory).run()


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("operation", choices=("stdio", "guard"))
    args.add_argument("--root", type=Path, default=ROOT)
    options = args.parse_args()
    os.umask(0o077)
    try:
        if options.operation == "stdio":
            transport(options.root)
        else:
            private_directory(options.root)
            asyncio.run(launch_guard(options.root))
    except (OSError, ValueError, asyncio.TimeoutError):
        print("The restricted peer session did not complete.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
