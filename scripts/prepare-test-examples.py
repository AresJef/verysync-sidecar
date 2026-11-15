#!/usr/bin/env python3
"""Explicitly build and identify this checkout's example executables."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def build_artifacts(cargo, selection):
    """Use Cargo's actual executable paths, including explicit cross targets."""
    command = [*cargo, "build", *selection, "--locked", "--message-format=json"]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.stderr:
        sys.stderr.write(result.stderr)
    artifacts = {}
    for line in result.stdout.splitlines():
        message = json.loads(line)
        if message.get("reason") == "compiler-message":
            rendered = message.get("message", {}).get("rendered")
            if rendered:
                sys.stderr.write(rendered)
        if (message.get("reason") == "compiler-artifact"
                and "example" in message.get("target", {}).get("kind", [])
                and message.get("executable")):
            artifacts[message["target"]["name"]] = Path(message["executable"])
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, command)
    return artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--github-env", type=Path)
    args = parser.parse_args()
    cargo = [args.cargo, f"+{args.toolchain}"]
    artifacts = build_artifacts(cargo, ["--examples"])
    artifacts.update(build_artifacts(cargo, ["--example", "cache_program", "--features", "download"]))
    names = ("connect_existing", "create_folder", "manage_existing", "manage_owned", "cache_program")
    if any(name not in artifacts for name in names):
        raise ValueError("Cargo did not identify every required compiled example")
    directories = {artifacts[name].parent for name in names}
    if len(directories) != 1:
        raise ValueError("compiled examples must have one explicitly identified directory")
    directory = directories.pop()
    records = []
    for name in names:
        executable = artifacts[name]
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
