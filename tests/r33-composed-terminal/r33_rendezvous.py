"""Pass the public challenge and confirmed broker address to the named observer."""

import argparse
import asyncio
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import sys
import tempfile
import time

from r33_isolation import agent, socket_denial
from r33_protocol import FRAME_MAX, RUN, Request, decode_frame, encode_frame, peer_identity


TMP = Path("/private/tmp").resolve() if sys.platform == "darwin" else Path("/tmp").resolve()


def exchange_path(path):
    info = path.lstat()
    if (path.parent != TMP or not re.fullmatch(r"r33-exchange-[a-z0-9_]{8}", path.name)
            or path.resolve() != path or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise ValueError("The private handoff notification folder is unavailable.")
    return path


def publish(path, stage, value):
    exchange = exchange_path(path)
    destination = exchange / (stage + ".json")
    temporary = exchange / (".notice-" + secrets.token_hex(8))
    try:
        with temporary.open("xb") as handle:
            handle.write(encode_frame(value))
        os.link(temporary, destination, follow_symlinks=False)
    finally:
        temporary.unlink(missing_ok=True)


def await_notice(path, stage, deadline):
    directory = exchange_path(path)
    document = directory / (stage + ".json")
    while time.monotonic() < deadline:
        try:
            with os.fdopen(os.open(document, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                    raise ValueError("The foreground notification has an unexpected identity.")
                return decode_frame(stream.read(FRAME_MAX + 1))
        except FileNotFoundError:
            time.sleep(0.10)
    raise TimeoutError("The current foreground notification did not arrive.")


def owned_socket(path, owner_uid):
    parent = path.parent
    endpoint, directory = path.lstat(), parent.lstat()
    if (parent.parent != TMP or not re.fullmatch(r"r33-client-[a-z0-9_]{8}", parent.name)
            or path.name != "b.sock" or path.resolve() != path
            or not stat.S_ISDIR(directory.st_mode) or not stat.S_ISSOCK(endpoint.st_mode)
            or endpoint.st_uid != owner_uid or directory.st_uid != owner_uid):
        raise ValueError("The broker address is outside the known foreground boundary.")
    return path


async def confirmed_status(path, run, owner_uid, owner_gid):
    reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(str(owned_socket(path, owner_uid))), 5)
    try:
        if peer_identity(writer.get_extra_info("socket")) != (owner_uid, owner_gid):
            raise ValueError("The broker belongs to a different foreground process identity.")
        query = Request(run, "handoff", "status", secrets.token_hex(16))
        writer.write(encode_frame(query.__dict__))
        await writer.drain()
        result = decode_frame(await asyncio.wait_for(reader.readline(), 5))
        if result.get("ok") is not True or result.get("local") != "active":
            raise ValueError("The current foreground grant is unavailable.")
        return result
    finally:
        writer.close()
        await writer.wait_closed()


async def verify_native_boundary(exchange, run, arena, executor_uid, executor_gid, stopped):
    native = arena / "state" / "gui.sock"
    actual = native.lstat()
    if (native.resolve() != native or not stat.S_ISSOCK(actual.st_mode)
            or actual.st_uid != os.getuid()):
        raise ValueError("The fixed engine did not start its private management socket.")
    with tempfile.TemporaryDirectory(prefix="r33-native-proof-", dir=TMP) as folder:
        public = Path(folder).resolve()
        entrance = public / "n.sock"
        completed = asyncio.Event()

        async def acknowledge(reader, writer):
            reply = {"ok": False}
            try:
                identity = peer_identity(writer.get_extra_info("socket"))
                result = decode_frame(await asyncio.wait_for(reader.readline(), 4))
                if (identity == (executor_uid, executor_gid) and not completed.is_set()
                        and result == {"run": run, "native_management_denied": True}):
                    reply = {"ok": True, "native_management_denied": True}
                    completed.set()
                writer.write(encode_frame(reply))
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_unix_server(acknowledge, str(entrance), limit=FRAME_MAX)
        pending = [asyncio.create_task(flag.wait()) for flag in (completed, stopped)]
        try:
            entrance.chmod(0o666)
            public.chmod(0o711)
            publish(exchange, "native", {"run": run, "native": str(native), "check": str(entrance)})
            await asyncio.wait(pending, timeout=80, return_when=asyncio.FIRST_COMPLETED)
            if not completed.is_set() or stopped.is_set():
                raise ValueError("The fixed engine's management isolation check did not pass.")
        finally:
            server.close()
            await server.wait_closed()
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)


def native_probe(notice, details):
    if set(notice) != {"run", "native", "check"} or notice["run"] != details["run"]:
        raise ValueError("The native probe belongs to a different run.")
    fake_root = Path(details["fake_file"]).parent.parent
    native = Path(notice["native"])
    if native != fake_root / "v" / details["run"] / "state" / "gui.sock":
        raise ValueError("The native probe does not identify the owned fixed engine.")
    check = Path(notice["check"])
    if (check.parent.parent != TMP or check.name != "n.sock"
            or not re.fullmatch(r"r33-native-proof-[a-z0-9_]{8}", check.parent.name)):
        raise ValueError("The native proof endpoint is outside the owned test scope.")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(check))
        if peer_identity(client) != (details["owner_uid"], details["owner_group"]):
            raise ValueError("The native proof handler has an unexpected identity.")
        denied = socket_denial(str(native))
        client.sendall(encode_frame({"run": details["run"], "native_management_denied": denied}))
        with client.makefile("rb") as stream:
            if decode_frame(stream.readline(FRAME_MAX+1)) != {"ok":True, "native_management_denied":True}:
                raise ValueError("Ordinary execution could reach the actual native management endpoint.")
    print("R33_NATIVE_ISOLATION " + encode_frame({"ok": True, "native_management_denied": True}).decode().strip(),
          flush=True)


def watch(path, seconds, require_native=False):
    from r33_isolation import public_challenge

    deadline = time.monotonic() + seconds
    challenge = await_notice(path, "challenge", deadline)
    if set(challenge) != {"run", "challenge"} or not RUN.fullmatch(challenge["run"]):
        raise ValueError("The foreground notification is incomplete.")
    challenge_path = Path(challenge["challenge"])
    details = public_challenge(challenge_path)
    if details["run"] != challenge["run"] or "owner_group" not in details:
        raise ValueError("The challenge belongs to a different run.")
    if agent(challenge_path) != 0:
        raise ValueError("The current ordinary executor failed the isolation challenge.")
    if require_native:
        native_probe(await_notice(path, "native", deadline), details)
    ready = await_notice(path, "ready", deadline)
    if set(ready) != {"run", "socket"} or ready["run"] != challenge["run"]:
        raise ValueError("The ready endpoint belongs to a different run.")
    status = asyncio.run(confirmed_status(Path(ready["socket"]), ready["run"],
                                          details["owner_uid"], details["owner_group"]))
    return ready | {"status": status}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exchange", type=Path, required=True)
    parser.add_argument("--wait", type=int, default=600)
    parser.add_argument("--require-native",action="store_true")
    args = parser.parse_args()
    try:
        result = watch(args.exchange, args.wait, args.require_native)
        print("R33_EXECUTOR_READY " + encode_frame(result).decode().strip(), flush=True)
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)
