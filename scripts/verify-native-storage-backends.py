#!/usr/bin/env python3
"""Require all existing ordinary storage suites on one isolated native source."""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


SUITES = {
    "local_sync_engine": 1,
    "local_sync_advanced_engine": 5,
    "local_sync_protocol_engine": 11,
    "local_sync_protocol_advanced_engine": 4,
    "local_sync_runtime_engine": 11,
}


def expected_summaries(target):
    count = SUITES[target]
    outer = ("ok", str(count), "0", "0", "0", "0")
    if target == "local_sync_protocol_engine":
        # The SFTP host-policy case runs the same test binary in a fresh
        # child environment. Its one exact test filters the other ten.
        return [("ok", "1", "0", "0", "0", str(count - 1)), outer]
    return [outer]


def read_summaries(output):
    return re.findall(
        r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; "
        r"(\d+) ignored; (\d+) measured; (\d+) filtered out;", output, re.MULTILINE,
    )


def accepts_suite(target, output, exit_code, exact_image_cleanup):
    return (exit_code == 0 and exact_image_cleanup
            and read_summaries(output) == expected_summaries(target))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.evidence_dir.is_absolute():
        raise ValueError("an explicit absolute evidence directory is required")
    args.evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    scripts = Path(__file__).resolve().parent
    failed = False
    for target, count in SUITES.items():
        directory = args.evidence_dir / target
        result = subprocess.run(
            [sys.executable, str(scripts / "run-isolated-engine-tests.py"),
             "--toolchain", args.toolchain, "--test-target", target,
             "--evidence-dir", str(directory)], check=False,
        )
        log = directory / (target.replace("_", "-") + ".log")
        output = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
        clean = subprocess.run([sys.executable, str(scripts / "prepare-test-engine.py"),
                                "check-cleanup"], check=False).returncode == 0
        passed = accepts_suite(target, output, result.returncode, clean)
        print("native storage backend suite receipt: " + json.dumps({
            "target": target, "expected_cases": count, "wrapper_exit_code": result.returncode,
            "rust_summaries": read_summaries(output), "exact_image_cleanup": clean, "passed": passed,
        }), flush=True)
        failed |= not passed
        if not clean:
            # A remaining instance shares this prepared image. Stop rather than
            # contaminate the later suite or send an unowned termination request.
            raise RuntimeError("prepared-image cleanup failed before the next suite")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
