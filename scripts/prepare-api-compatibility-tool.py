#!/usr/bin/env python3
"""Explicit CI-only download of one fixed, checksum-verified semver tool."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent", type=Path, required=True)
    parser.add_argument("--github-env", type=Path, required=True)
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix="vss-semver-0.51.0-", dir=args.parent.resolve(strict=True)))
    archive = directory / "tool.tar.gz"
    url = ("https://github.com/obi1kenobi/cargo-semver-checks/releases/download/v0.51.0/"
           "cargo-semver-checks-x86_64-unknown-linux-gnu.tar.gz")
    expected = "cacadafaa5cd27ae6d05a74a103266917ebab4c5e43c898360e177d4fbf06a65"
    count = 0
    started = time.monotonic()
    with urllib.request.urlopen(url, timeout=30) as response, archive.open("xb") as output:
        while chunk := response.read(65536):
            count += len(chunk)
            if count > 8397378 or time.monotonic() - started > 120:
                raise ValueError("fixed tool download exceeded its bounded size or time")
            output.write(chunk)
    if count != 8397378 or hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise ValueError("official semver tool archive size/SHA-256 differs")
    # Reuse the existing bounded regular-member extractor; never unpack the
    # whole archive or install any tool into the global Cargo directory.
    spec = importlib.util.spec_from_file_location("fixed_extractor", Path(__file__).with_name("prepare-test-engine.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    binary = module.extract_executable(archive, directory, "", "cargo-semver-checks", "tar.gz")
    value = str(binary)
    if "\n" in value or "\r" in value:
        raise ValueError("tool path cannot be represented in a GitHub environment file")
    with args.github_env.open("a", encoding="utf-8") as output:
        output.write(f"VERYSYNC_SEMVER_CHECKER={value}\n")
    print(json.dumps({"version": "0.51.0", "url": url, "archive_sha256": expected,
                      "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}))


if __name__ == "__main__":
    main()
