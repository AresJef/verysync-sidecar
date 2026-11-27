#!/usr/bin/env python3
"""Compare the candidate archive with the exact published 0.1.1 API in three profiles."""
import argparse
from hashlib import file_digest
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib

BASELINE_SHA = "3b72ddcd6f28dbdfee7fd3153c318321a645efdb5aa76cd4957c5765834638bb"
BASELINE_COMMIT = "1918028860f710f67e5e1ae5266eefe408ff6519"
BASELINE_VERSION = "0.1.1"
RUSTUP_TOOLCHAIN = "1.99.1"
CHECKER_VERSION = "cargo-semver-checks 0.51.0"
CHECKER_PROFILES = {
    "minimal": "--only-explicit-features",
    "default": "--default-features",
    "all": "--all-features",
}


def sha256(path):
    with path.open("rb") as contents:
        return file_digest(contents, "sha256").hexdigest()


def unpack(archive, dest, version, commit):
    dest.mkdir()
    with tarfile.open(archive, "r:gz") as package:
        package.extractall(dest, filter="data")
    source = dest / f"verysync-sidecar-{version}"
    stamp = json.loads((source / ".cargo_vcs_info.json").read_text(encoding="utf8"))["git"]
    manifest = tomllib.loads((source / "Cargo.toml").read_text(encoding="utf8"))["package"]
    if stamp["sha1"] != commit or stamp.get("dirty", False) or manifest["version"] != version:
        raise ValueError("unpacked crate identity does not match the checked package")
    return source


def check(args):
    candidate = json.loads(args.identity.read_text(encoding="utf8"))
    baseline_hash = sha256(args.baseline)
    candidate_hash = sha256(args.candidate)
    if baseline_hash != BASELINE_SHA or candidate_hash != candidate["candidate_crate_sha256"]:
        raise ValueError("candidate or official 0.1.1 package checksum differs")
    args.evidence.mkdir(mode=0o700, parents=True)
    version = subprocess.check_output([args.checker, "--version"], text=True, timeout=15).strip()
    if version != CHECKER_VERSION:
        raise ValueError("explicit pinned cargo-semver-checks 0.51.0 required")
    rustc = subprocess.check_output(
        ["rustup", "run", RUSTUP_TOOLCHAIN, "rustc", "-vV"], text=True, timeout=20,
    ).strip()

    results = []
    with tempfile.TemporaryDirectory(prefix="control-api-comparison-", dir=args.parent) as directory:
        scratch = Path(directory)
        published = unpack(args.baseline, scratch / "baseline", BASELINE_VERSION, BASELINE_COMMIT)
        current = unpack(args.candidate, scratch / "candidate", candidate["version"], candidate["source"])
        env = dict(os.environ, RUSTUP_TOOLCHAIN=RUSTUP_TOOLCHAIN, CARGO_NET_OFFLINE="true",
                   PATH=str(args.cargo.parent) + os.pathsep + os.environ.get("PATH", ""))
        for profile, flag in CHECKER_PROFILES.items():
            log = args.evidence / f"{profile}.log"
            env["CARGO_TARGET_DIR"] = str(scratch / ("target-" + profile))
            command = [args.checker, "--manifest-path", current / "Cargo.toml",
                       "--baseline-root", published, "--release-type", "patch", "--color", "never", flag]
            with log.open("xb") as output:
                exit_code = subprocess.run(command, cwd=scratch, env=env, stdout=output,
                                           stderr=subprocess.STDOUT, timeout=360, check=False).returncode
            results.append({"profile": profile, "flags": [flag], "exit": exit_code,
                            "log": log.name, "log_sha256": sha256(log)})
    report = {
        "candidate_commit": candidate["source"], "candidate_tree": candidate["tree"],
        "candidate_crate_sha256": candidate_hash, "baseline_commit": BASELINE_COMMIT,
        "baseline_crate_sha256": baseline_hash, "checker": version,
        "checker_sha256": sha256(args.checker), "rustc": rustc, "profiles": results,
        "isolated_materials_removed": not scratch.exists(),
    }
    (args.evidence / "api-compatibility.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf8",
    )
    print(json.dumps(report))
    if any(result["exit"] != 0 for result in results):
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("identity", "baseline", "candidate", "checker", "cargo", "parent", "evidence"):
        parser.add_argument("--" + name, required=True, type=Path)
    check(parser.parse_args())
