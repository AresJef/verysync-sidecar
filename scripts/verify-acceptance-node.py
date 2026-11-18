#!/usr/bin/env python3
"""Verify a compiled finite node against an explicitly selected isolated core."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import stat
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request

import psutil


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def event(lines, deadline):
    line = lines.get(timeout=max(0.01, deadline - time.monotonic()))
    require(bool(line), "node exited before required event")
    return json.loads(line)


def verify(args, mode, parent):
    root = parent / mode
    ttl = 2 if mode == "ttl" else 60
    started = time.monotonic()
    child = subprocess.Popen(
        [str(args.example), str(args.program), args.sha256, str(root), str(ttl)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, encoding="utf-8",
    )
    lines = queue.Queue(maxsize=4)

    def read():
        for _ in range(3):
            lines.put(child.stdout.readline(8193))

    threading.Thread(target=read, daemon=True).start()
    try:
        ready = event(lines, started + 45)
        require(ready["event"] == "ready", "missing readiness event")
        pid = ready["process_id"]
        process = psutil.Process(pid)
        born = process.create_time()
        require(Path(process.exe()).resolve() == args.program.resolve(), "wrong owned image")
        state = root / "state"
        receipt_path = state / "acceptance-connection.json"
        receipt = json.loads(receipt_path.read_text())
        require("api_key" not in ready, "credential leaked in readiness")
        require(receipt["device_id"] == ready["device_id"], "receipt identity differs")
        url = urllib.parse.urlparse(receipt["endpoint"])
        require(url.hostname == "127.0.0.1" and url.port != 18886, "unsafe management endpoint")
        if os.name != "nt":
            require(stat.S_IMODE(state.stat().st_mode) == 0o700, "state not private")
            require(stat.S_IMODE(receipt_path.stat().st_mode) == 0o600, "receipt not private")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def get(path):
            request = urllib.request.Request(
                receipt["endpoint"] + path, headers={"X-API-Key": receipt["api_key"]}
            )
            with opener.open(request, timeout=5) as response:
                return json.load(response)

        require(get("rest/system/status")["myID"] == ready["device_id"], "authenticated identity differs")
        configuration = get("rest/config")
        require(configuration["folders"] == [], "unexpected selected folders")
        options = configuration["options"]
        for field in ["globalAnnounceEnabled", "localAnnounceEnabled", "natEnabled", "relaysEnabled"]:
            require(options[field] is False, "unrequested discovery/NAT/relay enabled")
        require(options["listenAddresses"] == ["tcp://127.0.0.1:0"], "non-loopback peer listener enabled")
        files = [state / "key.pem", state / "cert.pem", state / ".verysync-sidecar-identity"]
        before = {path.name: sha(path) for path in files}
        sample = state / "synthetic-retained-sample.bin"
        sample.write_bytes(bytes(range(256)) * 8)
        sample_hash = sha(sample)
        if mode == "stop":
            child.stdin.write("stop\n")
            child.stdin.flush()
        elif mode == "eof":
            child.stdin.close()
        stopped = event(lines, started + 80)
        require(stopped == {"event": "stopped", "code": 0, "forced": False,
                            "tree_stopped": True, "state_released": True}, "normal exit not confirmed")
        require(child.wait(timeout=10) == 0, "example failed after core exit")
        require(not psutil.pid_exists(pid) or psutil.Process(pid).create_time() != born,
                "owned core remains alive")
        require(before == {path.name: sha(path) for path in files}, "private identity changed")
        require(sha(sample) == sample_hash, "synthetic bytes changed or removed")
        return {"mode": mode, "normal_exit": True, "private_identity_retained": True,
                "synthetic_bytes_retained": 2048, "management_authenticated": True,
                "network_isolated": True, "elapsed_seconds": round(time.monotonic() - started, 3)}
    finally:
        if child.poll() is None:
            if not child.stdin.closed:
                try:
                    child.stdin.write("stop\n")
                    child.stdin.flush()
                except BrokenPipeError:
                    pass
            try:
                child.wait(timeout=40)
            except subprocess.TimeoutExpired:
                # This exact example owns only the newly created test core.
                # A forced harness cleanup is never a passing normal-exit result.
                child.kill()
                child.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--example", type=Path, required=True)
    parser.add_argument("--program", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    require(args.program.is_absolute() and args.example.is_absolute(), "explicit absolute programs required")
    require(len(args.sha256) == 64 and sha(args.program) == args.sha256, "core digest differs")
    require(not args.evidence.exists(), "evidence output already exists")
    parent = Path(tempfile.mkdtemp(prefix="verysync-acceptance-node-"))
    report = {"core_sha256": args.sha256, "example_sha256": sha(args.example),
              "private_test_root": str(parent), "cases": [], "negative_cases": []}
    try:
        for mode in ["stop", "eof", "ttl"]:
            report["cases"].append(verify(args, mode, parent))
        # No program execution is needed for these rejected input boundaries.
        for name, digest in [("wrong-hash", "0" * 64), ("unicode-hash", "é" * 32)]:
            root = parent / name
            output = subprocess.run([str(args.example), str(args.program), digest, str(root), "1"],
                                    input="", capture_output=True, text=True, timeout=45)
            require(output.returncode != 0 and not output.stdout, "invalid digest accepted")
            report["negative_cases"].append(name)
        existing = parent / "already-present"
        existing.mkdir()
        sentinel = existing / "original.txt"
        sentinel.write_bytes(b"existing caller data\n")
        output = subprocess.run([str(args.example), str(args.program), args.sha256, str(existing), "1"],
                                input="", capture_output=True, text=True, timeout=10)
        require(output.returncode != 0 and sentinel.read_bytes() == b"existing caller data\n"
                and sorted(p.name for p in existing.iterdir()) == ["original.txt"], "existing root altered")
        report["negative_cases"].append("existing-root-preserved")
        report["status"] = "passed"
    except BaseException:
        report["status"] = "failed"
        raise
    finally:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        with args.evidence.open("x", encoding="utf-8") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
        print(json.dumps(report))


if __name__ == "__main__":
    main()
