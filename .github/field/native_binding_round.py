"""Run bounded native STUN against the one approved service."""
import argparse
from contextlib import contextmanager, ExitStack
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlsplit


ROLE_HOST = "stun.cloudflare.com"
ROLE_PORT = 3478
SOURCE = "99ee1036b70b9b115df26ca76c57559e7dc038a3"


def run_checked(*args):
    result = subprocess.run(args, capture_output=True, timeout=15)
    if result.returncode != 0:
        raise RuntimeError("owned runner preparation or release failed")
    return result.stdout.decode().strip()


@contextmanager
def hosted_scope(root, engine, controller, target):
    ident = secrets.token_hex(5)
    name = "vsudp" + ident
    chain = "VSUDP" + ident
    assert os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_OS") == "Linux"
    profile = ["-w", "3"]
    with ExitStack() as teardown:
        run_checked("sudo", "-n", "useradd", "--no-create-home", "--shell", "/usr/sbin/nologin", name)
        teardown.callback(run_checked, "sudo", "-n", "userdel", name)
        user = pwd.getpwnam(name)
        for family in ("iptables", "ip6tables"):
            cmd = ["sudo", "-n", family, *profile]
            run_checked(*cmd, "-N", chain)
            teardown.callback(run_checked, *cmd, "-X", chain)
            teardown.callback(run_checked, *cmd, "-F", chain)
            run_checked(*cmd, "-A", chain, "-o", "lo", "-j", "RETURN")
            if family == "iptables":
                run_checked(*cmd, "-A", chain, "-p", "udp", "-d", target + "/32",
                            "--dport", str(ROLE_PORT), "-m", "time", "--datestop",
                            (datetime.now(timezone.utc)+timedelta(seconds=90)).strftime("%Y-%m-%dT%H:%M:%S"),
                            "-j", "RETURN")
            run_checked(*cmd, "-A", chain, "-j", "REJECT")
            rule = ["-m", "owner", "--uid-owner", str(user.pw_uid), "-j", chain]
            run_checked(*cmd, "-I", "OUTPUT", "1", *rule)
            teardown.callback(run_checked, *cmd, "-D", "OUTPUT", *rule)
        native, driver = [root / name for name in ("core", "driver")]
        for source, target_file in ((engine, native), (controller, driver)):
            shutil.copyfile(source, target_file)
            target_file.chmod(0o755)
        state_store = root / "work"
        state_store.mkdir(mode=0o700)
        run_checked("sudo", "-n", "chown", f"{user.pw_uid}:{user.pw_gid}", str(state_store))
        root.chmod(0o755)
        # Restore caller ownership before removing the precise disposable fixture.
        teardown.callback(run_checked, "sudo", "-n", "chown", "-R", f"{os.getuid()}:{os.getgid()}", str(state_store))
        yield ["sudo", "-n", "-u", name, "env", f"HOME={state_store}", f"TMPDIR={state_store}"], native, driver, state_store


@contextmanager
def mac_scope(root, engine, driver):
    profile = root / "private-egress.sb"
    profile.write_text(
        '(version 1)(allow default)(deny network-outbound)'
        '(allow network-outbound (remote ip "localhost:*") (remote unix-socket))'
        '(allow network-outbound (remote udp "*:3478"))'
        f'(deny file-write* (require-not (require-any (subpath {json.dumps(str(root))}) '
        '(literal "/dev/null") (literal "/dev/ptmx") (regex #"^/dev/ttys[0-9]+$"))))\n')
    private_engine = root / "owned-core"
    shutil.copyfile(engine, private_engine)
    private_engine.chmod(0o700)
    yield ["/usr/bin/sandbox-exec", "-f", str(profile)], private_engine, driver, root


def verify_ipv4(value):
    host = ipaddress.IPv4Address(value)
    if not host.is_global:
        raise ValueError("selected STUN address is not public")
    return str(host)


def candidate_addresses(raw):
    public = []
    for entry in raw:
        parsed = urlsplit(entry)
        if parsed.scheme not in ("udp", "quic") or not parsed.hostname:
            continue
        try:
            address = verify_ipv4(parsed.hostname)
        except ValueError:
            continue
        if parsed.port is not None and 1024 < parsed.port <= 65535:
            public.append((address, parsed.port))
    return public


def owned_processes(path):
    import re
    result = subprocess.run(["pgrep", "-f", "^" + re.escape(str(path)) + r"( |$)"],
                            capture_output=True, timeout=8)
    if result.returncode not in (0,1):
        raise RuntimeError("cannot inventory the exact native test image")
    return result.stdout.split()


def main():
    p=argparse.ArgumentParser()
    p.add_argument("role",choices=["mac","linux"])
    for name in ("engine","driver","receipt"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--sha",required=True)
    args=p.parse_args()
    os.umask(0o077)
    native = args.engine.resolve(strict=True)
    driver = args.driver.resolve(strict=True)
    assert hashlib.sha256(native.read_bytes()).hexdigest() == args.sha
    report={"role":args.role,"official_version":"v2.33.2","stable_source":SOURCE,
            "allowed_stun_host":ROLE_HOST,"allowed_stun_port":ROLE_PORT,
            "allowed_native_window_seconds":90,"native_route_opening_request_blocked":True,
            "private_addresses_published":False,"peer_data_sent":False,"result":"failed"}
    try:
        destination=socket.getaddrinfo(ROLE_HOST,ROLE_PORT,socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)[0][4][0]
        destination=verify_ipv4(destination)
        with tempfile.TemporaryDirectory(prefix="vsudp.",dir="/private/tmp" if args.role=="mac" else "/tmp") as scratch:
            root=Path(scratch)
            plan=mac_scope(root,native,driver) if args.role=="mac" else hosted_scope(root,native,driver,destination)
            with plan as (launcher, exact_image, control, state):
                assert owned_processes(exact_image)==[]
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as reserve:
                    reserve.bind(("127.0.0.1",0))
                    port=reserve.getsockname()[1]
                env={"PATH":os.environ["PATH"],"HOME":str(state),"TMPDIR":str(state)}
                run=[*launcher,str(control),str(exact_image),args.sha,str(state/"core-state"),
                     f"{destination}:{ROLE_PORT}",str(port),"public-stun-only"]
                clock=time.monotonic()
                with subprocess.Popen(run,stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      env=env,cwd=state,start_new_session=True) as process:
                    try:
                        stdout, stderr=process.communicate(timeout=79)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(process.pid,signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        try:
                            process.wait(3)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid,signal.SIGKILL)
                            process.wait(2)
                        for field in owned_processes(exact_image):
                            pid = int(field)
                            if args.role == "linux":
                                run_checked("sudo", "-n", "kill", "-TERM", str(pid))
                            else:
                                os.kill(pid, signal.SIGTERM)
                        raise RuntimeError("native STUN window exhausted")
                    report["native_elapsed_seconds"]=round(time.monotonic()-clock,3)
                    report["driver_exit"]=process.returncode
                    if process.returncode!=0:
                        raise RuntimeError("native STUN helper failed, addresses suppressed")
                    raw=json.loads(stdout)
                    public=candidate_addresses(raw["reported_addresses"])
                    report["reported_udp_public_candidate_count"]=len(public)
                    for key in ("final_native_nat_type","initial_native_nat_type"):
                        value = raw[key]
                        report[key] = value if value.replace(" ","").replace("-","").isalnum() else "unrecognized"
                    for key in ("exact_private_stun_settings_observed","restart_identity_preserved","native_exit"):
                        report[key]=raw[key] is True
                    report["listener_address_count"]=len(raw["reported_addresses"])
                assert owned_processes(exact_image)==[]
                report["exact_engine_cleanup"]=True
            report["policy_released"]=True
        report["result"]="observed"
    except (OSError, RuntimeError, ValueError, AssertionError, subprocess.SubprocessError) as exc:
        report["failure_type"]=type(exc).__name__
        if type(exc) is RuntimeError:
            report["failure_reason"]=str(exc)
    finally:
        with args.receipt.open("x",encoding="utf-8") as out:
            json.dump(report,out,indent=2)
            out.write("\n")
        print(json.dumps(report))
    return 0 if report["result"]=="observed" else 1


if __name__=="__main__":
    raise SystemExit(main())
