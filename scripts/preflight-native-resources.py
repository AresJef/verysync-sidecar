#!/usr/bin/env python3
"""Require full opposite-order native preparation on each actual CI profile."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time


def check_frozen_source(metrics, protocol, cargo, toolchain):
    source = metrics.source_identity(cargo, toolchain)
    changed = [field for field, expected in protocol["source_inputs"].items()
               if source.get(field) != expected]
    if changed:
        raise ValueError("frozen preparation input differs: " + ", ".join(changed))
    if not source["rustc_version"].startswith(f"rustc {protocol['rust_release']} "):
        raise ValueError("actual compiler differs from frozen release")
    return source


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--protocol", type=Path, required=True)
    p.add_argument("--cargo", type=Path, required=True)
    p.add_argument("--toolchain", required=True)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--evidence-dir", type=Path)
    mode.add_argument("--check-source", action="store_true",
                      help="check the frozen source and compiler before running preparation")
    args = p.parse_args()
    protocol_bytes = args.protocol.read_bytes()
    protocol = json.loads(protocol_bytes)
    protocol_sha256 = hashlib.sha256(protocol_bytes).hexdigest()
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != protocol["preflight_sha256"]:
        raise ValueError("preflight source differs from frozen preparation")
    spec = importlib.util.spec_from_file_location("preflight_validator", Path(__file__).with_name("report-native-resources.py"))
    validator = importlib.util.module_from_spec(spec); spec.loader.exec_module(validator)
    if "reporter_sha256" in protocol and validator.digest(validator.__file__) != protocol["reporter_sha256"]:
        raise ValueError("preflight validator differs from frozen preparation")
    validator.preparation_policy(protocol)
    metrics = validator.module("preflight_metrics", "measure-native-resources.py")
    if args.check_source:
        source = check_frozen_source(metrics, protocol, args.cargo, args.toolchain)
        print(json.dumps({"status": "SOURCE_READY", "protocol_sha256": protocol_sha256,
                          "source": source}))
        return 0
    args.evidence_dir.mkdir(parents=True, exist_ok=False)
    result = {"stage": "pretrial", "formal_sample": False, "start_unix": time.time(),
              "protocol_sha256": protocol_sha256, "attempts": []}
    try:
        check_frozen_source(metrics, protocol, args.cargo, args.toolchain)
        for cycle, order in enumerate(protocol["formal_orders"][:2]):
            for slot, scenario in enumerate(order):
                target = args.evidence_dir / f"cycle-{cycle}-slot-{slot}-{scenario}"
                command = [sys.executable, "-B", str(Path(__file__).with_name("measure-native-resources.py")),
                           "--stage", "pilot", "--cargo", str(args.cargo), "--toolchain", args.toolchain,
                           "--scenario", scenario, "--repeats", str(protocol["scenarios"][scenario]["repeats"]),
                           "--interval-ms", str(protocol["interval_ms"]), "--evidence-dir", str(target)]
                started = time.monotonic()
                code = subprocess.run(command, check=False).returncode
                attempt = {"cycle": cycle, "slot": slot, "scenario": scenario, "exit_code": code,
                           "elapsed_s": time.monotonic()-started}
                result["attempts"].append(attempt)
                if code not in {0, 2}:
                    result["status"] = "ERROR"
                    return code
                _, quality = validator.check_attempt(target, protocol, "pilot", metrics)
                if code != (0 if quality["status"] == "VALID" else 2):
                    raise ValueError("native exit and preparation quality differ")
                attempt["quality_status"] = quality["status"]
        _, readiness = validator.check_preparation_orders(args.evidence_dir, result["attempts"], protocol, metrics)
        result["readiness"] = readiness
        result["status"] = "PREPARATION_COMPLETE" if readiness["ready"] else "PREPARATION_INSUFFICIENT"
        return 0 if readiness["ready"] else 2
    except Exception as error:
        result["status"] = "ERROR"
        result["error_type"] = type(error).__name__
        raise
    finally:
        result["end_unix"] = time.time()
        (args.evidence_dir / "pretrial-result.json").write_text(json.dumps(result, indent=2)+"\n")
        print(json.dumps(result))


if __name__ == "__main__":
    sys.exit(main())
