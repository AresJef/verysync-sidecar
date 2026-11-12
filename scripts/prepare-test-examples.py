#!/usr/bin/env python3
"""Explicitly build and identify this checkout's example executables."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--github-env", type=Path)
    args = parser.parse_args()
    cargo = [args.cargo, f"+{args.toolchain}"]
    subprocess.run([*cargo, "build", "--examples", "--locked"], check=True)
    metadata = json.loads(subprocess.check_output(
        [*cargo, "metadata", "--no-deps", "--format-version", "1"], text=True
    ))
    directory = Path(metadata["target_directory"]).joinpath("debug", "examples")
    records = []
    for name in ("connect_existing", "create_folder", "manage_existing"):
        executable = directory.joinpath(name)
        if os.name == "nt":
            executable = executable.with_suffix(".exe")
        if not executable.is_file() or executable.is_symlink():
            raise ValueError("expected regular compiled example is missing")
        records.append({"name": name, "sha256": hashlib.sha256(executable.read_bytes()).hexdigest()})
    if args.github_env:
        value = str(directory)
        if "\n" in value or "\r" in value:
            raise ValueError("example directory cannot be written to GitHub environment")
        with args.github_env.open("a", encoding="utf-8") as output:
            output.write(f"VERYSYNC_TEST_EXAMPLE_DIR={value}\n")
    print(json.dumps({"example_directory": str(directory), "compiled_examples": records}))


if __name__ == "__main__":
    main()
