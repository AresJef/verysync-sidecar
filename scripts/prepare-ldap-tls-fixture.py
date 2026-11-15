#!/usr/bin/env python3
"""Explicit runtime preparation/cleanup for the strict native LDAP CI fixture."""
import argparse
import os
from pathlib import Path
import subprocess
import sys


def main():
    # Use the already explicitly prepared private protocol-tool environment.
    selected = os.environ.get("VERYSYNC_STORAGE_TEST_PYTHON")
    if selected and os.path.normcase(os.path.abspath(selected)) != os.path.normcase(os.path.abspath(sys.executable)):
        return subprocess.run([selected, __file__, *sys.argv[1:]], timeout=100).returncode
    import ldap_tls_fixture as fixture
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "cleanup"])
    parser.add_argument("--parent", type=Path, required=True)
    parser.add_argument("--github-env", type=Path)
    args = parser.parse_args()
    if args.action == "cleanup":
        path = os.environ.get("VERYSYNC_TEST_LDAP_TLS_MANIFEST")
        if path is not None:
            fixture.cleanup(path, args.parent)
        print("Private LDAP TLS fixture cleanup complete; system trust was never modified")
        return 0
    if args.github_env is None:
        raise ValueError("explicit environment output required")
    path = fixture.prepare(args.parent)
    if "\n" in str(path) or "\r" in str(path):
        fixture.cleanup(path, args.parent)
        raise ValueError("fixture path cannot contain environment separators")
    try:
        with args.github_env.open("a", encoding="utf-8") as output:
            output.write("VERYSYNC_TEST_LDAP_TLS_MANIFEST=" + str(path) + "\n")
    except BaseException:
        fixture.cleanup(path, args.parent)
        raise
    print("Prepared pinned public-CA loopback TLS fixture; keys remain private; system trust unchanged")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        # Provider ZIP exceptions and URLs must not disclose private inputs.
        print("Private LDAP TLS fixture failed: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
