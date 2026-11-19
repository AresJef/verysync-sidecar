#!/usr/bin/env python3
"""Prove a pinned semver checker detects real API removal and feature coverage."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checker", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if not args.checker.is_absolute() or not args.cargo.is_absolute() or args.evidence.exists():
        raise ValueError("explicit absolute tools and a new evidence directory are required")
    version = subprocess.check_output([str(args.checker), "--version"], text=True, timeout=10).strip()
    if version != "cargo-semver-checks 0.51.0":
        raise ValueError("the explicitly pinned checker version is required")
    args.evidence.mkdir(parents=True)
    root = Path(tempfile.mkdtemp(prefix="vss-api-tool-selftest-"))
    common = 'pub fn stable_call() -> u8 { 1 }\n'
    optional = '#[cfg(feature = "optional")]\npub fn optional_call() -> u8 { 2 }\n'
    for name, source in [("baseline", common + optional), ("unchanged", common + optional),
                         ("breaking", optional), ("feature-breaking", common)]:
        crate = root / name
        (crate / "src").mkdir(parents=True)
        (crate / "Cargo.toml").write_text(
            '[package]\nname="vss-api-tool-fixture"\nversion="1.0.0"\nedition="2021"\n'
            '[features]\ndefault=[]\noptional=[]\n', encoding="utf-8")
        (crate / "src" / "lib.rs").write_text(source, encoding="utf-8")
    env = dict(os.environ)
    env.update({"RUSTUP_TOOLCHAIN": "1.99.1", "CARGO_NET_OFFLINE": "true",
                "CARGO_TARGET_DIR": str(root / "target"),
                "PATH": str(args.cargo.parent) + os.pathsep + env.get("PATH", "")})
    records = []
    for name, current, features, expected in [
        ("unchanged", "unchanged", ["--default-features"], 0),
        ("public-function-removal", "breaking", ["--default-features"], 100),
        ("optional-removal-outside-default", "feature-breaking", ["--default-features"], 0),
        ("optional-removal-with-all-features", "feature-breaking", ["--all-features"], 100),
    ]:
        command = [str(args.checker), "--manifest-path", str(root / current / "Cargo.toml"),
                   "--baseline-root", str(root / "baseline"), "--release-type", "patch",
                   "--color", "never", *features]
        result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=120)
        text = result.stdout + result.stderr
        log = args.evidence / (name + ".log")
        log.write_text(text, encoding="utf-8")
        if result.returncode != expected:
            raise RuntimeError(f"{name}: expected checker exit {expected}, got {result.returncode}; see {log}")
        if expected == 100 and "function_missing" not in text:
            raise RuntimeError("noncompatibility exit did not report the actual removed function")
        records.append({"name": name, "exit": result.returncode, "expected_exit": expected,
                        "actual_removed_function_reported": expected == 100,
                        "features": features, "log": log.name,
                        "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()})
    report = {"checker_version": version, "checker_sha256": hashlib.sha256(args.checker.read_bytes()).hexdigest(),
              "toolchain": "1.99.1", "cases": records, "offline": True,
              "SDK_formal_baseline_selected": False, "SDK_compatibility_claimed": False,
              "alpha_compatibility_required": False, "status": "passed"}
    (args.evidence / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
