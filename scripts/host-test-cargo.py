#!/usr/bin/env python3
"""Explicit CI adapter: build as the runner, elevate only one pinned test binary."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

CASE = "privileged_native_watch_limit_is_raised_then_independently_restored"
TARGET = "host_control_engine"
SCOPE = "github-actions-isolated-linux-vm"
PRESERVE = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
            "http_proxy", "https_proxy", "all_proxy", "no_proxy",
            "VERYSYNC_TEST_BINARY", "VERYSYNC_TEST_BINARY_SHA256",
            "VERYSYNC_TEST_ALLOW_HOST_CONFIGURATION", "GITHUB_ACTIONS",
            "CARGO_NET_OFFLINE")

def prepare(args):
    command = [args.cargo, "+" + args.toolchain, "test", "--no-run", "--locked",
               "--features", "host-configuration-tests", "--test", TARGET,
               "--message-format=json"]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.stderr:
        sys.stderr.write(result.stderr)
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, command)
    candidates = []
    for line in result.stdout.splitlines():
        row = json.loads(line)
        if (row.get("reason") == "compiler-artifact"
                and row.get("target", {}).get("name") == TARGET
                and row.get("target", {}).get("kind") == ["test"]
                and row.get("profile", {}).get("test") is True
                and row.get("executable")):
            candidates.append(Path(row["executable"]))
    if len(candidates) != 1:
        raise ValueError("Cargo must identify exactly one native test executable")
    artifact = candidates[0]
    if not artifact.is_absolute() or not artifact.is_file() or artifact.is_symlink():
        raise ValueError("host test artifact must be an exact regular absolute path")
    directory = Path(tempfile.mkdtemp(prefix="verysync-host-test-", dir=args.parent))
    receipt = directory / "receipt.json"
    receipt.write_text(json.dumps({"executable": str(artifact),
                                  "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                                  "toolchain": args.toolchain}), encoding="utf-8")
    adapter = directory / "cargo"
    adapter.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " " +
                       shlex.quote(str(Path(__file__).resolve())) + ' "$@"\n', encoding="utf-8")
    adapter.chmod(0o700)
    values = {"VERYSYNC_HOST_TEST_CARGO_SHIM": str(adapter),
              "VERYSYNC_HOST_TEST_RECEIPT": str(receipt)}
    if any("\n" in value or "\r" in value for value in values.values()):
        raise ValueError("unsafe GitHub environment value")
    with args.github_env.open("a", encoding="utf-8") as output:
        for key, value in values.items():
            output.write(key + "=" + value + "\n")
    return values

def root_command(argv, env):
    if sys.platform != "linux":
        raise ValueError("host test elevation is supported only in the Linux CI job")
    if env.get("GITHUB_ACTIONS") != "true" or env.get("VERYSYNC_TEST_ALLOW_HOST_CONFIGURATION") != SCOPE:
        raise ValueError("host mutations require the explicit isolated GitHub VM scope")
    receipt = Path(env["VERYSYNC_HOST_TEST_RECEIPT"])
    if not receipt.is_absolute() or not receipt.is_file() or receipt.is_symlink() or receipt.stat().st_size > 65536:
        raise ValueError("an explicit regular receipt is required")
    row = json.loads(receipt.read_text(encoding="utf-8"))
    expected = ["+" + row["toolchain"], "test", "--features", "engine-tests",
                "--test", TARGET, "--offline", "--locked", CASE,
                "--", "--test-threads=1", "--nocapture"]
    if argv != expected:
        raise ValueError("only the exact prebuilt privileged case may be elevated")
    executable = Path(row["executable"])
    if not executable.is_absolute() or not executable.is_file() or executable.is_symlink():
        raise ValueError("invalid privileged test artifact")
    if hashlib.sha256(executable.read_bytes()).hexdigest() != row["sha256"]:
        raise ValueError("privileged test artifact changed since compilation")
    return ["/usr/bin/sudo", "--non-interactive",
            "--preserve-env=" + ",".join(PRESERVE), str(executable), CASE,
            "--exact", "--test-threads=1", "--nocapture"]

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "prepare":
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--cargo", default="cargo")
        parser.add_argument("--toolchain", required=True)
        parser.add_argument("--parent", required=True, type=Path)
        parser.add_argument("--github-env", required=True, type=Path)
        print(json.dumps(prepare(parser.parse_args(sys.argv[2:]))))
        return 0
    return subprocess.run(root_command(sys.argv[1:], os.environ)).returncode

if __name__ == "__main__":
    raise SystemExit(main())
