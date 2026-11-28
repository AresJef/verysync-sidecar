#!/usr/bin/env python3
"""Bind each SDK operation to named test results from a verified external crate."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RUN_NATIVE = ROOT / "scripts" / "run-isolated-engine-tests.py"
RUN_DOWNLOAD_FEATURES = {
    "download_engine", "cache_engine", "file_transfer_engine", "maintenance_engine",
}
ISOLATED_CASES = {
    ("network", "actual_builtin_discovery_client_uses_isolated_service_and_populates_cache"):
        ("--allow-private-discovery",),
    ("upgrade_engine", "stopped_owner_cli_detailed_records_check_provider_and_url_exits"):
        ("--allow-upgrade-metadata", "--serve-pinned-upgrade-archive"),
}
STARTED = re.compile(r"^test ([A-Za-z0-9_:]+) \.\.\.")
TOTAL = re.compile(r"^test result: ok\. (\d+) passed; 0 failed; 0 ignored;")
VALID_NAME = re.compile(r"[A-Za-z0-9_:]+\Z")


def sha256(path):
    with path.open("rb") as artifact:
        return hashlib.file_digest(artifact, "sha256").hexdigest()


def read_contract(path):
    with path.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source, delimiter="\t"))
    if [row["id"] for row in rows] != [f"{i:02}" for i in range(1, 75)]:
        raise ValueError("the SDK proof contract must cover all 74 ordered operation IDs")
    result = {}
    for row in rows:
        selectors = []
        for kind in ("native", "controlled"):
            for value in filter(None, row[f"{kind}_case_selectors"].split(";")):
                suite, selector = value.split(":", 1)
                if not re.fullmatch(r"[a-z0-9_]+", suite) or not VALID_NAME.fullmatch(selector):
                    raise ValueError(f"invalid {kind} test selector for operation {row['id']}: {value}")
                selectors.append((kind, suite, selector))
        if not any(kind == "native" for kind, _, _ in selectors):
            raise ValueError(f"no native observation for operation {row['id']}")
        result[row["id"]] = (selectors, row["additional_scope"])
    return result


def capture(command, cwd, log_path):
    with log_path.open("w", encoding="utf-8") as log:
        with subprocess.Popen(command, cwd=cwd, text=True, encoding="utf-8", errors="replace",
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as child:
            for line in child.stdout:
                log.write(line)
                print(line, end="", flush=True)
            return child.wait()


def listed_cases(toolchain, consumer, suite, kind, log):
    features = ("engine-tests,download" if suite in RUN_DOWNLOAD_FEATURES else "engine-tests")
    command = ["cargo", "+" + toolchain, "test", "--locked", "--offline", "--test", suite]
    if kind == "native":
        command.extend(["--features", features])
    command.extend(["--", "--list"])
    code = capture(command, consumer, log)
    if code:
        raise ValueError(f"could not list {kind} test suite {suite}, exit {code}; see {log.name}")
    return [line.removesuffix(": test") for line in log.read_text(encoding="utf-8").splitlines()
            if line.endswith(": test") and VALID_NAME.fullmatch(line.removesuffix(": test"))]


def verified_lines(log, expected, exit_code):
    if exit_code:
        raise ValueError(f"{log.name} exited with {exit_code}")
    started = {}
    totals = []
    for number, line in enumerate(log.read_text(encoding="utf-8").splitlines(), start=1):
        if match := STARTED.match(line):
            name = match.group(1)
            if name in started:
                raise ValueError(f"repeated test {name} in {log.name}")
            started[name] = number
        if match := TOTAL.match(line):
            totals.append(int(match.group(1)))
    if set(started) != set(expected) or totals != [len(expected)] or not expected:
        missing = sorted(set(expected) - set(started))
        unexpected = sorted(set(started) - set(expected))
        raise ValueError(f"{log.name}: missing={missing}, unexpected={unexpected}, totals={totals}")
    return started


def measure_suite(args, kind, suite, cases, fixture_set):
    root = args.output / suite / fixture_set
    log_path = root / (suite.replace("_", "-") + ".log")
    if kind == "native":
        command = [
            sys.executable, str(RUN_NATIVE), "--toolchain", args.toolchain, "--test-target", suite,
            "--sdk-completion-consumer", str(args.consumer), "--evidence-dir", str(root),
        ]
        for name in cases:
            command.extend(["--exact-case", name])
        if fixture_set != "ordinary":
            command.extend(ISOLATED_CASES[(suite, fixture_set)])
        root.parent.mkdir(parents=True, exist_ok=True)
        code = capture(command, ROOT, root.parent / (fixture_set + "-runner.log"))
        proxy = json.loads((root / "proxy-observations.json").read_text(encoding="utf-8"))
        if (not proxy["package_consumer"] or proxy["test_target"] != suite
                or proxy["exact_cases"] != cases or proxy["test_exit_code"] != code
                or not proxy["listener_loopback_only"]):
            raise ValueError(f"isolated launcher did not bind {suite}/{fixture_set} to these tests")
    else:
        root.mkdir(parents=True)
        command = ["cargo", "+" + args.toolchain, "test", "--locked", "--offline", "--test",
                   suite, "--", "--test-threads=1", "--nocapture", "--exact", *cases]
        code = capture(command, args.consumer, log_path)
    positions = verified_lines(log_path, cases, code)
    digest = sha256(log_path)
    return {name: {"log": log_path.relative_to(args.output).as_posix(),
                   "line": line, "sha256": digest} for name, line in positions.items()}


def bind_consumer(args):
    consumer_record = json.loads(args.consumer_identity.read_text(encoding="utf-8"))
    package_record = json.loads(args.package_identity.read_text(encoding="utf-8"))
    checkout = subprocess.check_output(["git", "rev-parse", "HEAD", "HEAD^{tree}"],
                                       cwd=ROOT, text=True, timeout=15).splitlines()
    if (checkout != [package_record["source"], package_record["tree"]]
            or sha256(args.crate) != package_record["candidate_crate_sha256"]
            or sha256(args.consumer / "Cargo.lock") != consumer_record["consumer_lock_sha256"]
            or not consumer_record["consumer_uses_separately_unpacked_package"]
            or any(consumer_record[name] != package_record[key] for name, key in (
                ("source", "source"), ("tree", "tree"), ("crate_sha256", "candidate_crate_sha256")))):
        raise ValueError("checkout, verified crate and independent consumer do not share the same identity")
    package = args.consumer.parent / f"verysync-sidecar-{package_record['version']}"
    expected = package / "scripts" / "sdk-completion-cases.tsv"
    present = ROOT / "scripts" / "sdk-completion-cases.tsv"
    if sha256(expected) != sha256(present):
        raise ValueError("the packaged matrix contract differs from checkout")
    for name, expected in consumer_record["consumer_test_sources_sha256"].items():
        relative = Path("tests") / name
        if sha256(args.consumer / relative) != expected or sha256(package / relative) != expected:
            raise ValueError(f"test fixture is not identical to the unpacked candidate: {relative}")
    return present, package_record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", required=True)
    for flag in ("output", "consumer", "package-identity", "consumer-identity", "crate"):
        parser.add_argument("--" + flag, required=True, type=Path)
    parser.add_argument("--only", action="append", default=[], metavar="TEST_TARGET",
                        help="restrict a diagnostic run to named test targets")
    args = parser.parse_args()
    for name in ("output", "consumer", "package_identity", "consumer_identity", "crate"):
        setattr(args, name, getattr(args, name).resolve())
    contract_path, identity = bind_consumer(args)
    contract = read_contract(contract_path)
    args.output.mkdir(mode=0o700, parents=True)
    listings = args.output / "listings"
    listings.mkdir()
    shutil.copyfile(contract_path, args.output / contract_path.name)
    grouped = {}
    requested = {}
    suites = {}
    for selectors, _scope in contract.values():
        for kind, suite, selector in selectors:
            if not args.only or suite in args.only:
                grouped.setdefault((kind, suite), set()).add(selector)
    errors = {}
    observed = {}
    for (kind, suite), selectors in sorted(grouped.items()):
        try:
            listing = listed_cases(args.toolchain, args.consumer, suite, kind, listings / (suite + ".log"))
            for selector in sorted(selectors):
                matches = sorted(name for name in listing if selector in name)
                if matches:
                    requested[(kind, suite, selector)] = matches
                    for name in matches:
                        fixture = name if (suite, name) in ISOLATED_CASES else "ordinary"
                        suites.setdefault((kind, suite, fixture), set()).add(name)
                else:
                    errors[f"{suite}:{selector}"] = "selector resolved to zero test cases"
        except (OSError, ValueError) as exc:
            errors[suite] = str(exc)

    for (kind, suite, fixture), names in sorted(suites.items()):
        label = f"{suite}/{fixture}"
        print(f"SDK named evidence {kind} {label} ({len(names)} cases)", flush=True)
        try:
            for name, receipt in measure_suite(args, kind, suite, sorted(names), fixture).items():
                observed[(kind, suite, name)] = receipt
        except (OSError, ValueError, KeyError) as exc:
            errors[label] = str(exc)
            print(f"SDK named evidence failed for {label}: {exc}", flush=True)

    records = []
    for id_, (selectors, scope) in contract.items():
        receipts = []
        for kind, suite, selector in selectors:
            names = requested.get((kind, suite, selector), [])
            matches = [
                {"name": name, **observed[(kind, suite, name)]}
                for name in names if (kind, suite, name) in observed
            ]
            receipts.append({"kind": kind, "suite": suite, "selector": selector, "listed": names,
                             "observed": matches, "complete": bool(names) and len(names) == len(matches)})
        records.append({"id": id_, "scope": scope, "tests": receipts,
                        "complete": all(receipt["complete"] for receipt in receipts)})
    complete = sum(record["complete"] for record in records)
    report = {
        "source": identity["source"], "tree": identity["tree"], "version": identity["version"],
        "crate_sha256": identity["candidate_crate_sha256"], "contract_sha256": sha256(contract_path),
        "toolchain": args.toolchain, "job_sha": os.environ.get("GITHUB_SHA"),
        "run_id": os.environ.get("GITHUB_RUN_ID"), "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "selected_targets": args.only, "complete_groups": complete, "errors": errors,
        "named_tests_passed": len(observed), "operation_groups": records,
    }
    (args.output / "operation-results.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"SDK operation proof: {complete}/74 complete groups, {len(observed)} passed tests, "
          f"{len(errors)} errors; see operation-results.json", flush=True)
    return int(bool(errors) or (not args.only and complete != 74) or not observed)


if __name__ == "__main__":
    raise SystemExit(main())
