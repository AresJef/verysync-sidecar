#!/usr/bin/env python3
"""Explicit release/CI audit with a fixed RustSec tool and fresh advisory data."""

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--toolchain", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="verysync-rustsec-", dir=os.environ.get("RUNNER_TEMP")) as temporary:
        root = Path(temporary)
        tool = root.joinpath("tool")
        environment = os.environ.copy()
        environment["CARGO_TARGET_DIR"] = str(root.joinpath("build"))
        subprocess.run([
            args.cargo, f"+{args.toolchain}", "install", "cargo-audit",
            "--version", "0.23.0", "--locked", "--root", str(tool),
        ], env=environment, check=True)
        executable = tool.joinpath("bin", "cargo-audit")
        if os.name == "nt":
            executable = executable.with_suffix(".exe")
        result = subprocess.run([
            str(executable), "audit", "--db", str(root.joinpath("advisory-db")),
            "--json", "--deny", "warnings",
        ], check=False)
        return result.returncode


if __name__ == "__main__":
    sys.exit(main())
