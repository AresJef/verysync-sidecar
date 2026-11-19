#!/usr/bin/env python3
"""Require the frozen raw-data verdict for one exact hosted resource profile."""

import argparse
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--protocol", required=True)
    parser.add_argument("--collection", required=True)
    parser.add_argument("--preparation", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--engine-sha256", required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be a fresh report directory")

    reporter = Path(__file__).with_name("report-native-resources.py")
    completed = subprocess.run([
        sys.executable, str(reporter), "--protocol", args.protocol,
        "--profile", f"{args.profile}={args.collection}",
        "--preparation", f"{args.profile}={args.preparation}", "--output", str(args.output),
    ], stdout=subprocess.DEVNULL)
    report_path = args.output / "resource-report.json"
    if completed.returncode not in (0, 1, 2) or not report_path.is_file():
        sys.exit("Frozen resource reporter did not produce a verdict")

    # The aggregate reports missing platforms when CI checks one matrix job.
    profile, = json.loads(report_path.read_text(encoding="utf-8"))["profiles"]
    performance = profile["performance"]
    if profile["profile"] != args.profile or performance != "PASS" or completed.returncode == 1:
        sys.exit(f"{args.profile}: frozen resource verdict performance={performance}")
    source = profile["source"]
    if ((source["source_commit"], source["source_tree"]) != (args.source, args.tree)
            or profile["engine_sha256"] != [args.engine_sha256]):
        sys.exit(f"{args.profile}: resource source or engine identity differs")
    print(json.dumps({"profile": args.profile, "performance": performance,
                      "source": args.source, "tree": args.tree, "engine_sha256": args.engine_sha256}))


if __name__ == "__main__":
    main()
