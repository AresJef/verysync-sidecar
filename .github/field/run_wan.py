"""Run one private Mac/hosted-Linux TCP acceptance pair."""
import argparse
import contextlib
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import secrets
import socket
import ssl
import subprocess
import tempfile
import time

import psutil

READY = {"event": "stopped", "code": 0, "forced": False, "tree_stopped": True, "state_released": True}
SIZE = 262181
DEVICE = re.compile(r"[A-Z2-7]{7}(?:-[A-Z2-7]{7}){7}")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_private(path, data):
    with open(path, "x", encoding="utf-8", opener=lambda p, f: os.open(p, f, 0o600)) as output:
        json.dump(data, output)


def read_event(stream, wait):
    with selectors.DefaultSelector() as selector:
        selector.register(stream, selectors.EVENT_READ)
        require(selector.select(wait), "owned example event timeout")
        line = stream.readline(8193)
    require(0 < len(line) <= 8192, "missing owned example event")
    return json.loads(line)


def bounded(function, seconds):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        result = function()
        if result:
            return result
        time.sleep(0.35)
    raise TimeoutError("required observation timed out")


@contextlib.contextmanager
def node(args, runtime, report):
    root = runtime / "node"
    env = {"PATH": os.environ["PATH"], "TMPDIR": str(runtime), "HOME": str(runtime),
           "NO_PROXY": "127.0.0.1,localhost,::1", "no_proxy": "127.0.0.1,localhost,::1"}
    if "RUNNER_TRACKING_ID" in os.environ:
        env["RUNNER_TRACKING_ID"] = os.environ["RUNNER_TRACKING_ID"]
    policy = []
    if args.mode == "mac":
        profile = runtime / "isolated-daemon.sb"
        profile.write_text(
            '(version 1)(allow default)'
            '(deny network-outbound (remote ip))(allow network-outbound (remote ip "localhost:*"))'
            f'(deny file-write* (require-not (require-any (subpath {json.dumps(str(runtime))}) '
            '(literal "/dev/null") (literal "/dev/ptmx") (regex #"^/dev/ttys[0-9]+$"))))\n')
        policy = ["/usr/bin/sandbox-exec", "-f", str(profile)]
    proc = subprocess.Popen(
        [*policy, str(args.example), str(args.engine), args.sha, str(root), "1080"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
    )
    native = None
    try:
        event = read_event(proc.stdout, 45)
        require(event["event"] == "ready" and event["program_version"] == "v2.33.2", "wrong readiness")
        require("api_key" not in event and event["program_sha256"] == args.sha, "wrong digest or key leak")
        native = psutil.Process(event["process_id"])
        require(Path(native.exe()).resolve() == args.engine, "wrong native image")
        report["native_core_sha256"] = args.sha
        report["native_version"] = event["program_version"]

        def control(action):
            result = subprocess.run([*policy, str(args.control), action, str(root)], env=env,
                                    capture_output=True, timeout=40, check=False)
            require(result.returncode == 0, "SDK " + action + " failed")
            return json.loads(result.stdout)

        yield root, event["device_id"], control
    finally:
        try:
            if proc.poll() is None:
                proc.stdin.write(b"stop\n")
                proc.stdin.flush()
            if native is not None:
                report["normal_exit"] = read_event(proc.stdout, 40) == READY and proc.wait(5) == 0
                report["exact_engine_gone"] = not native.is_running()
                require(report["normal_exit"] and report["exact_engine_gone"], "owned core stop failed")
            else:
                proc.wait(45)
        finally:
            if proc.poll() is None:
                proc.kill()  # Exact example process created above. The cleanup is a failure.
                proc.wait(10)
            for pipe in [proc.stdin, proc.stdout, proc.stderr]:
                pipe.close()


def recv_record(conn):
    conn.settimeout(3)
    line = bytearray()
    while len(line) < 4096:
        data = conn.recv(1)
        if data == b"\n":
            return json.loads(line)
        if not data:
            break
        line.extend(data)
    raise ValueError("invalid bounded private message")


def send_record(conn, value):
    conn.sendall(json.dumps(value, separators=(",", ":")).encode() + b"\n")


def mac_handshake(args, runtime, identity, receive_share, sample_hashes):
    cert, key = runtime / "server.pem", runtime / "server.key"
    cert_command = ["/usr/bin/openssl", "req", "-new", "-x509", "-newkey", "rsa:2048",
                    "-nodes", "-days", "1", "-subj", "/CN=verysync-isolated-test",
                    "-keyout", str(key), "-out", str(cert)]
    subprocess.run(cert_command, check=True, capture_output=True, timeout=12)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    nonce = secrets.token_hex(32)
    request = {"host": args.public, "port": args.port, "nonce": nonce,
               "fingerprint": digest(ssl.PEM_cert_to_DER_cert(cert.read_text()))}
    # Public address and nonce remain private. Only this one CI job receives them.
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.lan, args.port))
        listener.listen(4)
        listener.settimeout(1)
        write_private(args.handoff, request)
        until = time.monotonic() + 390
        while time.monotonic() < until and not args.stop.exists():
            try:
                stream, source = listener.accept()
                with stream:
                    stream.settimeout(3)
                    with context.wrap_socket(stream, server_side=True) as conn:
                        hello = recv_record(conn)
                        if not hmac.compare_digest(str(hello["nonce"]), nonce):
                            continue
                        peer = hello["device"]
                        if not (isinstance(peer, str) and DEVICE.fullmatch(peer) and
                                peer != identity and ipaddress.IPv4Address(source[0]).is_global):
                            continue
                        send_record(conn, {"device": identity, "share": receive_share, "hashes": sample_hashes})
                        return peer, source[0], digest(nonce.encode())
            except (OSError, ValueError, KeyError, TypeError):
                continue
    raise TimeoutError("no authenticated outside node on selected port")


def linux_handshake(identity, report):
    request = json.loads(os.environ.pop("FIELD_SESSION"))
    host = str(ipaddress.IPv4Address(request["host"]))
    port = request["port"]
    require(ipaddress.IPv4Address(host).is_global and type(port) is int and 49152 <= port <= 65535,
            "invalid field target")
    for key in ("nonce", "fingerprint"):
        require(re.fullmatch(r"[0-9a-f]{64}", request[key]), "invalid transient session material")
    report["tcp_probe"] = "connecting"
    try:
        with socket.create_connection((host, port), timeout=7) as stream:
            report["tcp_probe"] = "connected_before_authentication"
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(stream) as conn:
                require(hmac.compare_digest(digest(conn.getpeercert(binary_form=True)), request["fingerprint"]),
                        "test listener fingerprint differs")
                send_record(conn, {"nonce": request["nonce"], "device": identity})
                result = recv_record(conn)
    except TimeoutError:
        if report["tcp_probe"] == "connecting":
            report["tcp_probe"] = "connect_timeout"
        raise
    except ConnectionRefusedError:
        report["tcp_probe"] = "connection_refused"
        raise
    require(DEVICE.fullmatch(result["device"]) and result["device"] != identity, "invalid peer identity")
    require(len(result["hashes"]) == 2 and
            all(re.fullmatch(r"[0-9a-f]{64}", sha) for sha in result["hashes"]), "invalid sample description")
    report.update(tcp_probe="owned_tls_listener_matched", session_fingerprint=digest(request["nonce"].encode()))
    return host, port, result


def observe(control, expected_direction, expected, remote_match=True):
    state = control("observe")
    if state.get("connected") is False and remote_match is False:
        return True
    if state.get("connected") is not True:
        return False
    if remote_match is False:
        return False
    require(state["direction"] == expected_direction, "wrong native peer transport or direction")
    raw = state["address"] or ""
    ip, _, port = raw.removeprefix("tcp://").rpartition(":")
    reported = ipaddress.IPv4Address(ip)
    require(reported.is_global and reported == ipaddress.IPv4Address(expected[0]), "wrong native public peer")
    if expected[1] is not None:
        require(int(port) == expected[1], "wrong native peer port")
    return {"authenticated_direct_tcp": True, "expected_public_address_matched": True}


def matched_file(path, expected):
    return path.is_file() and path.stat().st_size == SIZE and digest(path.read_bytes()) == expected


def local_command(args):
    result = subprocess.run(args, capture_output=True, check=False, timeout=12)
    require(result.returncode == 0, "isolated runner packet control command failed")
    return result.stdout


@contextlib.contextmanager
def cut_runner_link(host, port, session):
    rule = ["-p", "tcp", "-d", host + "/32", "--dport", str(port), "--syn",
            "-m", "comment", "--comment", "vs-field-" + session[:16], "-j", "REJECT", "--reject-with", "tcp-reset"]
    firewall = ["sudo", "-n", "iptables", "-w", "3"]
    match = ["dst", host, "dport", "=", ":" + str(port)]
    before = local_command(["ss", "-Htn", "state", "established", *match]).splitlines()
    require(len(before) == 1, "need exactly one established test socket")
    local_command([*firewall, "-I", "OUTPUT", "1", *rule])
    try:
        local_command(["sudo", "-n", "ss", "-K", "state", "established", *match])
        require(not local_command(["ss", "-Htn", "state", "established", *match]).strip(),
                "test socket was not closed")
        yield
    finally:
        local_command([*firewall, "-D", "OUTPUT", *rule])


def run_mac(args, runtime, report, root, identity, control):
    samples = [os.urandom(SIZE), os.urandom(SIZE)]
    hashes = [digest(sample) for sample in samples]
    receive_share = control("source")["receive_share"]
    (root / "synthetic/first.bin").write_bytes(samples[0])
    peer, egress, session = mac_handshake(args, runtime, identity, receive_share, hashes)
    report.update(tcp_probe="owned_tls_listener_matched", session_fingerprint=session)
    write_private(root / "field-plan.json", {"peer": peer, "listen": f"{args.lan}:{args.port}"})
    control("prepare")
    report["initial_connection"] = bounded(lambda: observe(control, "tcp_server", (egress, None)), 75)
    report["disconnect"] = bounded(lambda: observe(control, "", None, False), 100)
    (root / "synthetic/second.bin").write_bytes(samples[1])
    control("scan")
    require(matched_file(root / "synthetic/first.bin", hashes[0]), "sender first file changed")
    report["recovered_connection"] = bounded(lambda: observe(control, "tcp_server", (egress, None)), 90)
    report["generated_bytes"] = SIZE
    report["digests"] = hashes
    bounded(lambda: args.stop.exists(), 120)


def run_linux(report, root, identity, control):
    host, port, plan = linux_handshake(identity, report)
    write_private(root / "field-plan.json", {"peer": plan["device"], "dial": f"{host}:{port}",
                                           "read_key": plan["share"]})
    first, second = [root / "synthetic" / name for name in ("first.bin", "second.bin")]
    require(not first.exists() and not second.exists(), "receiver was not initially empty")
    report["receiver_initially_empty"] = True
    control("prepare")
    report["initial_connection"] = bounded(lambda: observe(control, "tcp_client", (host, port)), 75)
    bounded(lambda: matched_file(first, plan["hashes"][0]), 65)
    report["first_file"] = {"bytes": SIZE, "sha256": digest(first.read_bytes())}
    with cut_runner_link(host, port, report["session_fingerprint"]):
        report["disconnect"] = bounded(lambda: observe(control, "", None, False), 20)
        for _ in range(12):
            require(matched_file(first, plan["hashes"][0]) and not second.exists(),
                    "file protection or packet cutoff did not hold")
            time.sleep(1)
        report["retained_first_and_second_absent_during_cut"] = True
    report["runner_rule_removed"] = True
    report["recovered_connection"] = bounded(lambda: observe(control, "tcp_client", (host, port)), 90)
    bounded(lambda: matched_file(second, plan["hashes"][1]), 65)
    report["second_file"] = {"bytes": SIZE, "sha256": digest(second.read_bytes())}
    require(matched_file(first, plan["hashes"][0]), "first file was not retained after recovery")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["mac", "linux"])
    for name in ("example", "control", "engine", "receipt"):
        parser.add_argument("--"+name, type=Path, required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--lan")
    parser.add_argument("--public")
    parser.add_argument("--port", type=int)
    parser.add_argument("--handoff", type=Path)
    parser.add_argument("--stop", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    args.engine = args.engine.resolve(strict=True)
    require(digest(args.engine.read_bytes()) == args.sha, "owned binary digest differs")
    if args.mode == "mac":
        require(ipaddress.IPv4Address(args.lan).is_private and ipaddress.IPv4Address(args.public).is_global
                and 49152 <= args.port <= 65535 and args.handoff.is_absolute() and args.stop.is_absolute(),
                "invalid exact field parameters")
    else:
        require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_OS") == "Linux",
                "packet cutoff requires a dedicated hosted Linux GitHub runner")
    report = {"role": args.mode, "stable_source": "99ee1036b70b9b115df26ca76c57559e7dc038a3",
              "harness_sha256": digest(Path(__file__).read_bytes()), "status": "failed"}
    try:
        with tempfile.TemporaryDirectory(prefix="vsw.", dir="/private/tmp" if args.mode == "mac" else None) as path:
            runtime = Path(path)
            with node(args, runtime, report) as (root, identity, control):
                if args.mode == "mac":
                    run_mac(args, runtime, report, root, identity, control)
                else:
                    run_linux(report, root, identity, control)
        report["private_scratch_removed"] = not runtime.exists()
        report["status"] = "passed"
    except Exception as exc:
        report["failure_class"] = type(exc).__name__
        if isinstance(exc, RuntimeError) and not isinstance(exc, subprocess.SubprocessError):
            report["failure_reason"] = str(exc)
    finally:
        write_private(args.receipt, report)
        print(json.dumps(report))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
