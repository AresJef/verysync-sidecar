"""Run the exact released SDK and owned native core in a disposable private network."""

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
from queue import Empty, Queue
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time


CRATE = "https://static.crates.io/crates/verysync-sidecar/verysync-sidecar-0.1.0.crate"
CRATE_SHA = "1d1e7d0d3ef4ac4dcf063b8e4d3ac336bd823fd056e5aae84c5dbaaf24d6cbfe"
RELEASE = "99ee1036b70b9b115df26ca76c57559e7dc038a3"
ENGINE = "https://dl-cn.verysync.com/releases/v2.33.2/verysync-linux-amd64-v2.33.2.tar.gz"
ENGINE_SHA = "8a4b347669cd33def98b3bf1888576c8dc786ed77485080901bba0101c4413bd"
TEST = "r33_private_namespace::r33_native_private_local_api"


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def materialize(root, source):
    archive, native = root / "release.crate", root / "core.tar.gz"
    for artifact, url, digest in ((archive, CRATE, CRATE_SHA), (native, ENGINE, ENGINE_SHA)):
        subprocess.run(["/usr/bin/curl", "--fail", "--location", "--proto", "=https",
                        "--connect-timeout", "15", "--max-time", "70", "--silent", "--show-error",
                        "--output", str(artifact), url], check=True, timeout=75)
        if sha256(artifact) != digest:
            raise ValueError("A pinned release archive does not match its checksum.")
    with tarfile.open(archive, "r:gz") as package:
        for member in package.getmembers():
            relative = Path(member.name)
            if (relative.is_absolute() or ".." in relative.parts
                    or not relative.parts or relative.parts[0] != "verysync-sidecar-0.1.0"
                    or not (member.isdir() or member.isfile())):
                raise ValueError("The pinned SDK contains an unexpected member.")
        package.extractall(root)
    crate = root / "verysync-sidecar-0.1.0"
    if json.loads((crate / ".cargo_vcs_info.json").read_text())["git"]["sha1"] != RELEASE:
        raise ValueError("The pinned crate does not report the selected release commit.")
    library = {str(file.relative_to(crate)): sha256(file) for file in (crate / "src").rglob("*") if file.is_file()}
    tests = crate / "tests"
    shutil.copyfile(source, tests / "r33_private_namespace.rs")
    with (tests / "authentication_engine.rs").open("a", encoding="utf-8") as module:
        module.write('\n#[path = "r33_private_namespace.rs"]\nmod r33_private_namespace;\n')
    cargo = shutil.which("cargo")
    if cargo is None:
        raise ValueError("The disposable runner has no Cargo command.")
    build_log = root / "build-messages.jsonl"
    with build_log.open("x") as artifact:
        build = subprocess.run([cargo, "+1.85.0", "test", "--locked", "--features", "engine-tests",
                                "--test", "authentication_engine",
                                "--no-run", "--message-format=json"], cwd=crate, timeout=440, stdout=artifact)
    with build_log.open() as artifact:
        messages = [json.loads(line) for line in artifact]
    if build.returncode:
        for row in messages:
            if row.get("reason") == "compiler-message" and row["message"].get("level") == "error":
                print(row["message"]["rendered"], file=sys.stderr)
        raise ValueError("The pinned SDK test build failed.")
    binary = next(Path(row["executable"]) for row in messages if row.get("reason") == "compiler-artifact"
                  and row.get("target", {}).get("name") == "authentication_engine" and row.get("executable"))
    if library != {str(file.relative_to(crate)): sha256(file) for file in (crate / "src").rglob("*") if file.is_file()}:
        raise ValueError("Library source bytes changed during the private test build.")
    program = root / "fixed-native-core"
    with tarfile.open(native, "r:gz") as package:
        candidates = [entry for entry in package.getmembers() if Path(entry.name).name == "verysync"]
        if len(candidates) != 1 or not candidates[0].isfile():
            raise ValueError("Cannot identify the executable member in the fixed native archive.")
        with package.extractfile(candidates[0]) as source_bytes, program.open("xb") as output:
            shutil.copyfileobj(source_bytes, output)
    program.chmod(0o700)
    return binary, program


def namespace():
    return str(os.stat("/proc/self/ns/net").st_ino)


def worker(port, uid, gid, outer, test, program, fixture, digest):
    if os.geteuid() != 0 or int(uid) <= 0 or namespace() == outer:
        raise ValueError("The worker needs a separate network and an ordinary runtime UID.")
    subprocess.run(["/usr/sbin/ip", "link", "set", "lo", "up"], check=True, timeout=5)
    if {name for _, name in socket.if_nameindex()} != {"lo"}:
        raise ValueError("The private native worker has an unexpected network interface.")
    internal = namespace()
    os.setgroups([])
    os.setgid(int(gid))
    os.setuid(int(uid))
    if os.geteuid() != int(uid) or os.getegid() != int(gid):
        raise ValueError("The fixture did not drop to the intended ordinary identity.")
    env = {
        "HOME": fixture, "TMPDIR": fixture, "PATH": "/usr/bin:/bin",
        "R33_LOOPBACK_ENGINE": program, "R33_LOOPBACK_ENGINE_SHA256": digest,
        "R33_LOOPBACK_STATE": fixture, "R33_LOOPBACK_PORT": port, "R33_LOOPBACK_NAMESPACE": internal,
    }
    os.chdir(fixture)
    os.execve(test, [test, TEST, "--exact", "--nocapture", "--test-threads=1"], env)


def observe(test, program, fixture):
    executable_digest = sha256(program)
    outside = namespace()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        child = subprocess.Popen(
            ["/usr/bin/sudo", "-n", "/usr/bin/unshare", "--net", "/usr/bin/python3", "-B",
             str(Path(__file__).resolve()), "--worker", str(port), str(os.getuid()), str(os.getgid()),
             outside, str(test), str(program), str(fixture), executable_digest],
            text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        lines = Queue()

        def read():
            for line in child.stdout:
                lines.put(line)
            lines.put(None)
        receiver = threading.Thread(target=read, daemon=True)
        receiver.start()
        notes = {}
        refused = False
        try:
            end = time.monotonic() + 55
            while True:
                line = lines.get(timeout=max(0.1, end-time.monotonic()))
                if line is None:
                    break
                print(line, end="", flush=True)
                for marker in ("READY", "DATA", "EXIT"):
                    prefix = f"R33_NATIVE_PRIVATE_{marker} "
                    if prefix in line:
                        if marker in notes:
                            raise ValueError("Duplicate native fixture event.")
                        notes[marker] = json.loads(line.split(prefix, 1)[1])
                if "READY" in notes and not refused:
                    ready = notes["READY"]
                    if ready["namespace"] == outside or ready["logged_out"] is not True or child.poll() is not None:
                        raise ValueError("The native owned loopback observation is not live and exclusive.")
                    peer = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                    try:
                        peer.request("GET", "/rest/localapi/system/status")
                    except ConnectionRefusedError:
                        refused = True
                    else:
                        raise ValueError("The outside ordinary actor connected to the private native endpoint.")
                    finally:
                        peer.close()
                    child.stdin.write("STOP\n")
                    child.stdin.flush()
                if time.monotonic() > end:
                    raise TimeoutError("The private native receipt exceeded its window.")
        except Empty as exc:
            raise TimeoutError("The private native runtime did not report its next state.") from exc
        finally:
            try:
                child.wait(timeout=8)
            except subprocess.TimeoutExpired:
                subprocess.run(["/usr/bin/sudo", "-n", "/bin/kill", "-TERM", "--", f"-{child.pid}"],
                               timeout=4, check=False)
                child.wait(timeout=5)
            receiver.join(timeout=2)
        if (child.returncode != 0 or not refused or set(notes) != {"READY", "DATA", "EXIT"}
                or Path(f"/proc/{notes['READY']['core_pid']}").exists()
                or not notes["DATA"]["read_back_after_test"] or not notes["EXIT"]["normal_owned_exit"]):
            raise ValueError("Native isolation, file witnesses or exact normal exit did not verify.")
    return {"inside": notes, "outside_namespace": outside, "outside_ordinary_uid": os.getuid(),
            "outside_same_uid_refused": refused, "only_private_loopback": True,
            "crate_sha256": CRATE_SHA, "release_commit": RELEASE, "native_archive_sha256": ENGINE_SHA,
            "native_binary_sha256": executable_digest, "test_sha256": sha256(test)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", nargs=8)
    parser.add_argument("--test-source", type=Path)
    args = parser.parse_args()
    if args.worker is not None:
        worker(*args.worker)
        return
    if (args.test_source is None or sys.platform != "linux" or os.uname().machine != "x86_64"
            or os.geteuid() == 0 or os.environ.get("GITHUB_ACTIONS") != "true"):
        parser.error("Use this control as an ordinary user of the disposable AMD64 Actions runner.")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="r33-nl-", dir="/tmp") as scratch:
        root = Path(scratch)
        binary, program = materialize(root, args.test_source.resolve(strict=True))
        fixture = root / "owned"
        fixture.mkdir(mode=0o700)
        report = observe(binary, program, fixture)
    report["owned_directory_removed"] = not root.exists()
    print("R33_NATIVE_PRIVATE_BOUNDARY " + json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
