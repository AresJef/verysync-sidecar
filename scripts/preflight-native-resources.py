#!/usr/bin/env python3
"""Require full opposite-order native preparation on each actual CI profile."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--protocol", type=Path, required=True)
    p.add_argument("--cargo", type=Path, required=True)
    p.add_argument("--toolchain", required=True)
    p.add_argument("--evidence-dir", type=Path, required=True)
    args = p.parse_args()
    protocol = json.loads(args.protocol.read_text())
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != protocol["preflight_sha256"]:
        raise ValueError("preflight source differs from frozen preparation")
    args.evidence_dir.mkdir(parents=True, exist_ok=False)
    result = {"stage": "pretrial", "formal_sample": False, "start_unix": time.time(),
              "protocol_sha256": hashlib.sha256(args.protocol.read_bytes()).hexdigest(), "attempts": []}
    try:
        for cycle, order in enumerate(protocol["formal_orders"][:2]):
            for slot, scenario in enumerate(order):
                target = args.evidence_dir / f"cycle-{cycle}-slot-{slot}-{scenario}"
                command = [sys.executable, "-B", str(Path(__file__).with_name("measure-native-resources.py")),
                           "--stage", "pilot", "--cargo", str(args.cargo), "--toolchain", args.toolchain,
                           "--scenario", scenario, "--repeats", str(protocol["scenarios"][scenario]["repeats"]),
                           "--interval-ms", str(protocol["interval_ms"]), "--evidence-dir", str(target)]
                code = subprocess.run(command, check=False).returncode
                result["attempts"].append({"cycle": cycle, "slot": slot, "scenario": scenario, "exit_code": code})
                if code:
                    return code
                report = json.loads((target / "preparation-result.json").read_text())
                if any(report["source"].get(key) != value for key, value in protocol["source_inputs"].items()):
                    raise ValueError("actual preparation source differs")
        result["status"] = "PREPARATION_COMPLETE"
        return 0
    finally:
        result["end_unix"] = time.time()
        (args.evidence_dir / "pretrial-result.json").write_text(json.dumps(result, indent=2)+"\n")
        print(json.dumps(result))


if __name__ == "__main__":
    sys.exit(main())
