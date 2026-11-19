"""Inspect current native CLI handling of the historical LAN-admission option."""

import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

EXPECTED = {
    "linux": "770324d3411bf6ff7d18109ba5fa1e5057056b5e93441f29185b50895f55693a",
    "win32": "b1455da891a0723404c8c025ca77dc5ee8bc73632979edf4542c45d57fc73ea7",
}


def observe(binary, root, label, factory):
    work = root / label
    work.mkdir()
    state = work / "state"
    state.mkdir()
    args = factory(state)
    out = subprocess.run(
        [binary, *args], cwd=work, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=8, check=False,
    )
    untouched = set(work.iterdir()) == {state} and not list(state.iterdir())
    row = {
        "label": label, "returncode": out.returncode, "private_paths_untouched": untouched,
        "output_bytes": len(out.stdout), "output_sha256": hashlib.sha256(out.stdout).hexdigest(),
        "output": out.stdout[:12000].decode("utf-8", "replace"),
    }
    print("NATIVE_ADMISSION_CLI " + json.dumps(row, ensure_ascii=True), flush=True)
    if not untouched:
        raise RuntimeError("Informational CLI invocation wrote to its fresh private state")
    return row


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise RuntimeError("The probe requires the disposable native AMD64 runner")
    if sys.platform == "linux":
        outer = os.environ.get("VS_SIDE_CAR_BASE_NET_NAMESPACE")
        if not outer or outer == os.readlink("/proc/self/ns/net"):
            raise RuntimeError("The isolated Linux network namespace is required")
    binary = Path(os.environ["VERYSYNC_TEST_BINARY"]).resolve(strict=True)
    owned_parent = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if owned_parent not in binary.parents or not binary.is_file():
        raise RuntimeError("Use the private prepared executable under this runner's temp root")
    with binary.open("rb") as entry:
        digest = hashlib.file_digest(entry, "sha256").hexdigest()
    if digest != EXPECTED[sys.platform] or digest != os.environ["VERYSYNC_TEST_BINARY_SHA256"]:
        raise RuntimeError("Unexpected official VerySync v2.33.2 executable")
    print(f"NATIVE_ADMISSION_IMAGE platform={sys.platform} architecture={platform.machine()} sha256={digest}")
    missing = "--vs-sidecar-known-absent-control"
    with tempfile.TemporaryDirectory(prefix="vs-admission-cli-", dir=owned_parent) as parent:
        root = Path(parent)
        observe(binary, root, "general_help", lambda _: ["--help"])
        observe(binary, root, "serve_help", lambda state: ["serve", "--home", state, "--help"])
        observe(binary, root, "serve_negative_control",
                lambda state: ["serve", "--home", state, missing, "--help"])
        observe(binary, root, "legacy_negative_control",
                lambda state: [missing, "--help", "--home", state])
        for spelling, flag in (("long", "--trust-devices"), ("single_dash", "-trust-devices")):
            observe(binary, root, f"serve_{spelling}",
                    lambda state: ["serve", "--home", state, flag, "--help"])
            observe(binary, root, f"legacy_{spelling}",
                    lambda state: [flag, "--help", "--home", state])
    print("NATIVE_ADMISSION_CLI_CLEAN owned_state_removed=true", flush=True)


if __name__ == "__main__":
    main()
