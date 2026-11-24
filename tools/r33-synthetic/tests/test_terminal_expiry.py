"""Exercise foreground exit and independent expiry over real loopback SSH."""

import asyncio
from contextlib import contextmanager
from dataclasses import replace
import errno
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time

from r33_handoff import Linux
from r33_protocol import DENIED, decode_frame, encode_frame
from ssh_fixture import daemon
from test_terminal import TMP, Terminal, connect, profile_file, request
from test_terminal_active import until


def guarded_status(directory, run, stop=False):
    path = directory / "g.sock"
    with connect(path) as client, client.makefile("rb") as replies:
        client.sendall(encode_frame({"kind": "recover", "run": run}))
        result = decode_frame(replies.readline())
        if stop:
            client.sendall(encode_frame({"kind": "stop"}))
            result = decode_frame(replies.readline())
        return result


@contextmanager
def relay(peer, disconnect):
    with subprocess.Popen(
        [sys.executable, "-B", str(Path(__file__).with_name("loopback_link.py")),
         str(peer.port), str(disconnect)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    ) as worker:
        try:
            assert select.select([worker.stdout], [], [], 5)[0]
            yield replace(peer, port=int(worker.stdout.readline()))
        finally:
            worker.terminate()
            worker.wait(5)


def still_running(path):
    paths = subprocess.check_output(
        ["/bin/ps" if sys.platform == "darwin" else "/usr/bin/ps", "-ww", "-axo", "pid=,command="],
        text=True,
    )
    return any(row.rsplit(maxsplit=1)[-1:] == [str(path)] for row in paths.splitlines())


async def recovered(peer, key, run, root):
    runtime = root / "recover"
    runtime.mkdir(mode=0o700)
    backend = await Linux.open(peer.__dict__ | {"identity": str(key)}, runtime, run, mode="recover")
    try:
        assert await backend.channel.call({"kind": "renew"}) == DENIED
        attempt = {"kind": "execute", "id": "oldlease-12345678".replace("-", ""),
                   "operation": "write-sample"}
        assert await backend.channel.call(attempt) == DENIED
        status = await backend.channel.call({"kind": "status"})
        assert status["state"] == "revoked" and status["tasks"] == status["writes"] == 0
        assert (await backend.channel.call({"kind": "stop"}))["stopped"] == status["stopped"]
        return status
    finally:
        await backend.channel.close()


def run_case(root, mode, peer, key, remote, drop):
    profile = root / "profile.json"
    profile_file(profile, peer, key)
    journal = root / "audit.jsonl"
    user = Terminal(["start", "--synthetic", "--executor-uid", str(os.getuid()),
                     "--minutes", "5", "--profile", str(profile), "--evidence", str(journal)])
    run, entry, directory = None, None, None
    try:
        user.feed(b"START\n")
        owner = user.response(b"R33_READY ", 12)
        run, entry = owner["run"], Path(owner["socket"])
        directory = remote / run
        marker = directory / "observer-sample"
        with connect(entry) as client:
            assert request(client, run, "linux", "start-observer")["running"]
        until(lambda: marker.exists() and marker.stat().st_size >= 10)
        assert still_running(marker)
        initial = guarded_status(directory, run)
        scope_report = None

        if mode in ("loss", "kill"):
            # The production heartbeat must reach the actual remote process before
            # we interrupt the foreground or remove its data path.
            granted = until(lambda: (value if (value := guarded_status(directory, run))["renewed"]
                                     > initial["renewed"] else None), timeout=19)
            assert 90 == round(granted["deadline"] - granted["renewed"])
            last_action = time.monotonic()
            if mode == "loss":
                drop.touch()
            else:
                os.kill(user.pid, signal.SIGKILL)
                assert user.wait(4) == -signal.SIGKILL
                try:
                    connect(entry)
                except OSError as exc:
                    assert exc.errno in (errno.ENOENT, errno.ECONNREFUSED), exc
                else:
                    raise AssertionError("A client could still reach the killed foreground.")

            # Loss of the launcher or SSH alone does not stop the observation.
            size = marker.stat().st_size
            until(lambda: marker.stat().st_size > size, timeout=3)
            assert still_running(marker)
            receipt = directory / "receipt.json"
            terminal = until(lambda: receipt.is_file() and json.loads(receipt.read_bytes()), timeout=96)
            assert terminal["reason"] == "expired", terminal
            assert terminal["renewed"] == granted["renewed"], terminal
            assert 89.95 <= terminal["stopped"] - terminal["renewed"] <= 95, terminal
            observed = time.monotonic()
            assert 89 <= observed - last_action <= 95, terminal
            until(lambda: not (directory/"g.sock").exists())
            assert not still_running(marker)
            before = marker.read_bytes()
            time.sleep(.5)
            assert marker.read_bytes() == before
            if mode == "loss":
                drop.unlink()
                with connect(entry) as client:
                    assert request(client, run, "linux", "write-sample") == DENIED
                user.feed(b"\x03")
                scope_report = user.response(b"R33_STOPPED ", 15)
                assert scope_report["local"] == "revoked"
                assert scope_report["linux"]["state"] == "pending-confirmation"
                assert user.wait(5) == 0
            recovery = asyncio.run(recovered(peer, key, run, root))
            assert recovery["stopped"] == terminal["stopped"]
        else:
            last_action = time.monotonic()
            if mode == "eof":
                user.feed(b"\x04")
            elif mode == "operator-stop":
                with connect(entry) as client:
                    assert request(client, run, "handoff", "stop")["local"] == "revoked"
            else:
                os.kill(user.pid, {"term": signal.SIGTERM, "hup": signal.SIGHUP}[mode])
            scope_report = user.response(b"R33_STOPPED ", 12)
            assert scope_report["local"] == "revoked"
            assert scope_report["linux"] == {"state": "stopped", "writes": 0}
            assert user.wait(8) == 0
            terminal = json.loads((directory/"receipt.json").read_bytes())
            assert terminal["reason"] == "operator"
            observed = time.monotonic()
            assert 0 <= observed - last_action < 5
            until(lambda: not (directory/"g.sock").exists())
            assert not still_running(marker)
            recovery = asyncio.run(recovered(peer, key, run, root))
            assert recovery["stopped"] == terminal["stopped"]

        assert terminal["tasks"] == terminal["writes"] == 0
        assert not entry.exists() or mode == "kill"
        return {
            "scenario": mode, "run": run, "terminal": terminal,
            "actual_foreground_exit": user.exit, "remote_task_no_longer_in_process_table": True,
            "remote_socket_absent": True, "recovery_only_rejected_execute_and_renew": True,
            "local_sec_to_observe_remote_stop": observed-last_action,
            "sec_from_last_renewal_to_remote_stop": terminal["stopped"]-terminal["renewed"],
            "foreground_receipt": scope_report,
        }
    finally:
        user.close()
        if directory and (directory/"g.sock").exists():
            guarded_status(directory, run, stop=True)
            until(lambda: not (directory/"g.sock").exists())
        if entry and entry.exists():
            assert entry.is_socket() and entry.parent.name.startswith("r33-client-")
            assert entry.parent.stat().st_uid == os.getuid()
            entry.unlink()
            entry.parent.rmdir()
        if user.exit == -signal.SIGKILL:
            owner_record = next(event for event in map(json.loads, journal.read_text().splitlines())
                                if event["event"] == "owner-transport-paths")
            private = Path(owner_record["private"])
            assert private.parent == TMP and private.name.startswith("r33-owned-")
            assert private.stat().st_uid == os.getuid() and not private.stat().st_mode & 0o077
            assert {member.name for member in private.iterdir()} == {"pinned-host-key"}
            (private/"pinned-host-key").unlink()
            private.rmdir()


def main(mode, output):
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="r33-h4-", dir=TMP) as work:
        root = Path(work).resolve()
        with daemon(root/"ssh") as (peer, _, key, remote):
            drop = root/"link-off"
            if mode == "loss":
                with relay(peer, drop) as routed:
                    result = run_case(root, mode, routed, key, remote, drop)
            else:
                result = run_case(root, mode, peer, key, remote, drop)
    result["synthetic_fixture_directory_absent"] = not root.exists()
    output.write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main(sys.argv[1], Path(sys.argv[2]))
