#!/usr/bin/env python3
"""Explicitly prepare private protocol-peer tools, separate from SDK execution."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent", required=True, type=Path)
    parser.add_argument("--github-env", required=True, type=Path)
    parser.add_argument("--base-python", default=os.environ.get("VERYSYNC_STORAGE_BASE_PYTHON") or sys.executable)
    args = parser.parse_args()
    parent = args.parent.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix="vs-storage-tools-", dir=parent))
    # Preserve the interpreter's venv path: resolving its symlink can select the
    # base interpreter and lose the private environment's installed packages.
    subprocess.run([args.base_python, "-m", "venv", str(root)], check=True, timeout=120)
    interpreter = root / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")
    requirements = Path(__file__).with_name("storage-test-requirements.txt")
    command = [str(interpreter), "-m", "pip", "--isolated", "install",
               "--index-url", "https://pypi.org/simple", "--disable-pip-version-check",
               "--cache-dir", str(root / "pip-cache"), "--report", str(root / "install-report.json"),
               "-r", str(requirements)]
    with (root / "install.log").open("wb") as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=600)
    if result.returncode:
        print("Explicit private storage-tool installation failed; retained bounded diagnostics:")
        print("\n".join((root / "install.log").read_text(errors="replace").splitlines()[-20:]))
        raise SystemExit(result.returncode)
    code = ("import json,sys,sysconfig,struct;import pyftpdlib,paramiko,wsgidav,impacket,cheroot;"
            "print(json.dumps({'python':sys.version.split()[0],'python_platform':sysconfig.get_platform(),"
            "'pointer_bits':struct.calcsize('P')*8}))")
    record = json.loads(subprocess.check_output([str(interpreter), "-c", code], text=True, timeout=30))
    frozen = subprocess.check_output([str(interpreter), "-m", "pip", "freeze"], text=True, timeout=30)
    (root / "installed-requirements.txt").write_text(frozen, encoding="utf8")
    record.update(role="protocol peer tools only; SDK/core architecture is verified separately",
                  installed_distributions=len(frozen.splitlines()))
    (root / "runtime-identity.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf8")
    value = str(interpreter)
    if "\n" in value or "\r" in value:
        raise ValueError("private interpreter path cannot contain environment-record separators")
    with args.github_env.open("a", encoding="utf8") as output:
        output.write("VERYSYNC_STORAGE_TEST_PYTHON=" + value + "\n")
    print("Prepared explicit protocol peer runtime: " + json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
