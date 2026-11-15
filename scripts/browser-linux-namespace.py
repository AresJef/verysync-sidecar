#!/usr/bin/env python3
"""Test-only private mount setup; drop privileges before Cargo or native SDK code."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

CANDIDATES = (
    "/usr/bin/google-chrome-stable", "/usr/bin/google-chrome",
    "/usr/bin/chromium", "/usr/bin/chromium-browser", "/snap/bin/chromium",
)
INVALID = b"owned invalid browser executable; deliberately no executable header\n"


def validate_plan(plan, owner):
    uid, gid = plan["uid"], plan["gid"]
    if type(uid) is not int or type(gid) is not int or uid <= 0 or gid <= 0 or owner != uid:
        raise ValueError("explicit unprivileged runner identity required")
    if any(type(group) is not int or group <= 0 for group in plan["groups"]):
        raise ValueError("unprivileged original supplementary groups required")
    source = Path(plan["invalid_source"])
    if not source.is_absolute() or source.is_symlink() or not source.is_file():
        raise ValueError("owned regular invalid-browser source required")
    if source.stat().st_uid != uid or source.read_bytes() != INVALID:
        raise ValueError("owned exact invalid-browser bytes required")
    if not isinstance(plan["command"], list) or not plan["command"] or any(
            not isinstance(arg, str) or "\0" in arg for arg in plan["command"]):
        raise ValueError("explicit structured test command required")
    if plan["env"].get("GITHUB_ACTIONS") != "true" or plan["env"].get("RUNNER_OS") != "Linux":
        raise ValueError("explicit isolated GitHub Linux VM required")
    return source


def verify_caller(plan):
    caller = plan["caller_pid"]
    if type(caller) is not int or caller <= 1:
        raise ValueError("live original wrapper PID required")
    current = os.getppid()
    for _ in range(32):
        if current == caller:
            break
        if current <= 1:
            raise ValueError("original wrapper must be an actual ancestor")
        fields = dict(line.split(":", 1) for line in Path(f"/proc/{current}/status").read_text().splitlines() if ":" in line)
        current = int(fields["PPid"].strip())
    else:
        raise ValueError("bounded original wrapper ancestry required")
    fields = dict(line.split(":", 1) for line in Path(f"/proc/{caller}/status").read_text().splitlines() if ":" in line)
    if int(fields["Uid"].split()[0]) != plan["uid"] or int(fields["Gid"].split()[0]) != plan["gid"]:
        raise ValueError("wrapper kernel identity differs from plan")
    if sorted(map(int, fields["Groups"].split())) != sorted(plan["groups"]):
        raise ValueError("original kernel supplementary groups required")
    parent = os.readlink(f"/proc/{caller}/ns/mnt")
    if parent != plan["parent_namespace"] or os.readlink("/proc/self/ns/mnt") == parent:
        raise ValueError("kernel-observed private child mount namespace required")


def main():
    if sys.platform != "linux" or os.geteuid() != 0 or len(sys.argv) != 2:
        raise ValueError("privileged private Linux mount setup only")
    payload = Path(sys.argv[1])
    metadata = payload.lstat()
    if payload.is_symlink() or metadata.st_mode & 0o077:
        raise ValueError("private regular namespace plan required")
    plan = json.loads(payload.read_text())
    source = validate_plan(plan, metadata.st_uid)
    verify_caller(plan)
    subprocess.run(["/bin/mount", "--make-rprivate", "/"], check=True,
                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, timeout=10)
    targets = set()
    for candidate in CANDIDATES:
        path = Path(candidate)
        if path.exists():
            target = path.resolve(strict=True)
            if not target.is_file():
                raise ValueError("native browser candidate is not a regular file")
            targets.add(target)
    for target in sorted(targets):
        subprocess.run(["/bin/mount", "--bind", str(source), str(target)],
                       check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=10)
    # Every native candidate now either remains absent or fails its exact exec;
    # the pinned CLI falls back to the PATH-owned xdg-open fixture.
    os.setgroups(plan["groups"])
    os.setgid(plan["gid"])
    os.setuid(plan["uid"])
    if os.getuid() != plan["uid"] or os.geteuid() == 0:
        raise ValueError("runner privilege restoration failed")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if any(int(status[key].strip(), 16) for key in ("CapEff", "CapPrm", "CapAmb")):
        raise ValueError("Cargo and SDK must not retain setup capabilities")
    receipt = {"private_mount_namespace": True, "namespace_differs_from_parent": True,
               "bound_native_candidate_targets": len(targets),
               "invalid_source_sha256": hashlib.sha256(INVALID).hexdigest(),
               "cargo_and_sdk_run_as_original_unprivileged_uid": True,
               "host_files_written": False}
    with open(plan["receipt"], "x", encoding="utf-8", opener=lambda p, f: os.open(p, f, 0o600)) as output:
        json.dump(receipt, output)
    os.chdir(plan["cwd"])
    os.execvpe(plan["command"][0], plan["command"], plan["env"])


if __name__ == "__main__":
    main()
