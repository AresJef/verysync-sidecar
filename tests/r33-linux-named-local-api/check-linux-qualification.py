"""Verify the named Local-API driver in a disposable, signed-out Linux VM."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import select
import shutil
import signal
import socket
import subprocess
import tempfile


CRATE_SHA = "1d1e7d0d3ef4ac4dcf063b8e4d3ac336bd823fd056e5aae84c5dbaaf24d6cbfe"
ARCHIVE_SHA = "8a4b347669cd33def98b3bf1888576c8dc786ed77485080901bba0101c4413bd"
NATIVE_SHA = "770324d3411bf6ff7d18109ba5fa1e5057056b5e93441f29185b50895f55693a"
DRIVER_FILES = {
    "Cargo.toml": "674193245a41efc1570319a40c3fd461479974512a865f30177a1fabf0cfb0f7",
    "Cargo.lock": "282b62eebe8bba2f7ff8aaa497981254bddaf482642f3964e29891dca799a93e",
}
ARTIFACTS = (
    ("https://static.crates.io/crates/verysync-sidecar/verysync-sidecar-0.1.0.crate", CRATE_SHA),
    ("https://dl-cn.verysync.com/releases/v2.33.2/verysync-linux-amd64-v2.33.2.tar.gz", ARCHIVE_SHA),
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pinned_download(url, expected, destination):
    subprocess.run(["/usr/bin/curl", "--fail", "--silent", "--show-error", "--proto", "=https",
                    "--connect-timeout", "10", "--max-time", "60", "-o", str(destination), url],
                   check=True, timeout=65)
    if digest(destination) != expected:
        raise ValueError("A frozen artifact digest did not match.")


def namespace():
    return os.stat("/proc/self/ns/net").st_ino


def ask(child, request=None):
    if request:
        child.stdin.write(json.dumps({"kind":request}).encode("ascii") + b"\n")
        child.stdin.flush()
    if not select.select([child.stdout], [], [], 30)[0]:
        raise TimeoutError("The owned worker did not return a bounded response.")
    return json.loads(child.stdout.readline(8193))


def enter(outer, identity, group, program, driver, root, port):
    if os.geteuid() != 0 or namespace() == int(outer) or int(identity) <= 0:
        raise ValueError("The signed-out check requires a separate Linux network.")
    subprocess.run(["/usr/sbin/ip", "link", "set", "lo", "up"], check=True, timeout=5)
    if {name for _, name in socket.if_nameindex()} != {"lo"}:
        raise ValueError("An unexpected interface exists in this fixture.")
    os.setgroups([])
    os.setgid(int(group))
    os.setuid(int(identity))
    if os.getresuid() != (int(identity),) * 3 or os.getgroups():
        raise ValueError("Ordinary fixture identity verification failed.")
    environment = {"HOME": root, "TMPDIR": root, "PATH": "/usr/bin:/bin",
                   "R33_LOCAL_API_PORT": port, "R33_OUTER_NETWORK_INODE": outer}
    print(json.dumps({"namespace":namespace(),"uid":os.getuid(),"loopback_only":True}), flush=True)
    os.execve(driver, [driver, "serve-local-api", program, root, "bafc891375a940a5aebb306728499dfd"],
              environment)


def check_boundary(shell, root, program, driver, evidence):
    with socket.socket() as hold:
        hold.bind(("127.0.0.1",0))
        port = hold.getsockname()[1]
    assert port != 18886
    outer = namespace()
    env = {"HOME":str(root),"TMPDIR":str(root),"PATH":"/usr/bin:/bin",
           "R33_LOCAL_API_PORT":str(port),"R33_OUTER_NETWORK_INODE":str(outer)}
    argv = [str(driver), "serve-local-api", str(program), str(root), "94f0b2f3aa2d441a99ff0083183b60aa"]
    outside = subprocess.run(argv, env=env, cwd=root, capture_output=True, timeout=8)
    assert outside.returncode == 2
    assert json.loads(outside.stdout)["code"] == "licensed-local-api-needs-private-linux-loopback"
    assert not (root / "state").exists()
    with (evidence / "driver.stderr").open("xb") as stderr:
        child = subprocess.Popen(
            [*shell, "/usr/bin/unshare", "--net", "/usr/bin/python3", "-B", __file__,
             "--inside", *map(str, (outer, os.getuid(), os.getgid(), program, driver, root, port))],
            cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr,
            start_new_session=True, bufsize=0,
        )
        try:
            sandbox = ask(child)
            assert sandbox["loopback_only"] and sandbox["uid"] == os.getuid()
            assert sandbox["namespace"] != outer
            first = ask(child)
            assert first["account"] == "logged-out" and first["pro_observations"] == []
            with socket.socket() as observer:
                observer.settimeout(3)
                try:
                    observer.connect(("127.0.0.1", port))
                except ConnectionRefusedError:
                    refused_outside = True
                else:
                    raise ValueError("A caller outside the namespace reached private management.")
            refusal = ask(child, "local-api-qualify")
            assert refusal == {"ok":False,"reason":"dedicated-official-session-not-confirmed"}
            locked = {"ok":False,"reason":"operation-outside-the-licensed-local-api-scope"}
            assert ask(child, "local-api-qualify") == locked
            assert ask(child, "refresh-paid") == locked
            last = ask(child, "inspect")
            assert last["device"] == first["device"] and last["account"] == "logged-out"
            stopped = ask(child, "end")
            child.stdin.close()
            assert stopped == {"ok":True,"login_submitted":False,"native_logout":None,
                               "qualification_consumed":True,"normal_owned_exit":True}
            assert child.wait(timeout=15) == 0
        finally:
            if child.poll() is None:
                subprocess.run([*shell,"/bin/kill","-TERM","--",f"-{child.pid}"],
                               check=False, timeout=5)
                child.wait(timeout=12)
    return {"outside_launch_denied":True,"outside_same_uid_connection_refused":refused_outside,
            "actual_worker_identity":sandbox,"outer_namespace":outer,
            "before":first,"after":last,"first_qualification":refusal,
            "duplicate_and_refresh_refused":True,"normal_exit":stopped}


def verification(driver_source, evidence, scope_driver):
    if os.geteuid() == 0 or os.uname().machine != "x86_64" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("This case requires the opted-in standard AMD64 Linux job.")
    evidence.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="r33-la-ci-") as stage:
        root = Path(stage)
        archive, engine = root / "release.crate", root / "core.tar.gz"
        for (url, sha), destination in zip(ARTIFACTS, (archive, engine)):
            pinned_download(url, sha, destination)
        subprocess.run(["/usr/bin/tar","-xzf",str(archive),"-C",stage], check=True, timeout=10)
        crate = root / "verysync-sidecar-0.1.0"
        release = json.loads((crate / ".cargo_vcs_info.json").read_bytes())
        assert release["git"]["sha1"] == "99ee1036b70b9b115df26ca76c57559e7dc038a3"
        scripts = runpy.run_path(str(crate / "scripts" / "prepare-test-engine.py"))
        program = scripts["extract_executable"](
            engine, root, "verysync-linux-amd64-v2.33.2", "verysync", "tar.gz",
        )
        if digest(program) != NATIVE_SHA:
            raise ValueError("The expected official Linux binary did not match.")
        program.chmod(0o700)
        selected = root / "driver"
        shutil.copytree(driver_source / "src", selected / "src")
        existing = driver_source.parent.parent / "r33-single-terminal" / "native-driver"
        for name, expected in DRIVER_FILES.items():
            pinned = existing / name
            if digest(pinned) != expected:
                raise ValueError("The existing driver dependency lock changed.")
            shutil.copy2(pinned, selected / name)
        target = root / "target"
        command = ["cargo","+1.85.0","build","--locked","--target-dir",str(target),
                   "--config", f'patch.crates-io.verysync-sidecar.path="{crate}"']
        subprocess.run(command, cwd=selected, check=True, timeout=300)
        driver = target / "debug" / "verysync-r33-operator"
        record = check_boundary(["/usr/bin/sudo","-n"], root, program, driver, evidence)
        if scope_driver:
            phases = driver_source.parent / "private-boundary" / "check_scope_lifetimes.py"
            subprocess.run(
                ["/usr/bin/python3","-B",str(phases),"--engine",str(program),
                 "--driver",str(scope_driver.resolve(strict=True))],
                check=True, timeout=200,
            )
            staged = phases.with_name("check_staging.py")
            subprocess.run(
                ["/usr/bin/python3","-B",str(staged),str(program),str(scope_driver.resolve(strict=True))],
                check=True, timeout=125,
            )
        record.update({"crate_sha256":CRATE_SHA,"native_binary_sha256":NATIVE_SHA,
                       "driver_sha256":digest(driver),"lock_sha256":digest(selected / "Cargo.lock")})
        shutil.copy2(driver, evidence / driver.name)
    record["exact_fixture_removed"] = not root.exists()
    (evidence / "receipt.json").write_text(json.dumps(record,indent=2) + "\n")
    print("R33_LINUX_QUALIFICATION " + json.dumps(record,sort_keys=True))


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside",nargs=7)
    parser.add_argument("--source",type=Path)
    parser.add_argument("--evidence",type=Path)
    parser.add_argument("--scope-driver",type=Path)
    args = parser.parse_args()
    if args.inside:
        enter(*args.inside)
    else:
        verification(args.source.resolve(strict=True), args.evidence.resolve(), args.scope_driver)
