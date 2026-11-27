#!/usr/bin/env python3
"""Collect first observations from the unchanged native test runner."""
from datetime import datetime, timezone
from hashlib import file_digest
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
PLAN = json.loads((HERE / "plan.json").read_text(encoding="utf-8"))
LIMIT = 2 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")
SECRET = (
    re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer|basic)\s+)[^,\s]+"),
    re.compile(r'''(?i)(["']?(?:X-API-Key|api[_-]?key|cookie|credential|share[_-]?key|private[_-]?key|password)["']?\s*[:=]\s*["'])(?!\[)[^"'\r\n]+'''),
    re.compile(r"(?i)((?:set-cookie|cookie|x-api-key)\s*:\s*)[^\r\n]+"),
    re.compile(r"(?<![\w])(?:gh[pousr]_[A-Za-z0-9]{25,}|github_pat_[A-Za-z0-9_]{40,})(?![\w])"),
)
PEM = re.compile(r"-----((?:BEGIN)|(?:END)) [A-Z ]*PRIVATE KEY-----")


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as file:
        file.write(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def sha(path):
    with path.open("rb") as contents:
        return file_digest(contents, "sha256").hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def event(directory, key, **details):
    row = json.dumps({"kind": key, "observed_at": now(), **details}, ensure_ascii=False)
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "timeline.jsonl").open("a", encoding="utf-8", newline="\n") as log:
        log.write(row + "\n")
        log.flush()
    print("R1_CAPTURE " + row, flush=True)


class Redactor:
    def __init__(self):
        self.key = False

    def __call__(self, line):
        marker = PEM.search(line)
        if marker:
            self.key = marker[1] == "BEGIN"
            return "[private key material omitted]\n"
        if self.key:
            return "[private key material omitted]\n"
        for expression in SECRET:
            line = expression.sub(lambda m: (m[1] if expression.groups else "") + "[redacted]", line)
        return line


def capture(command, cwd, env, log):
    """Retain a bounded, line-preserving mirror and the upstream process exit."""
    redact = Redactor()
    kept = 0
    dropped = 0
    start = time.monotonic_ns()
    with log.open("x", encoding="utf-8", newline="\n") as output:
        with subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                              errors="replace") as child:
            for raw in child.stdout:
                line = redact(raw)
                size = len(line.encode("utf-8"))
                if kept + size > LIMIT:
                    dropped += 1
                    continue
                # A native process can print strings beginning with Actions command delimiters.
                print(line if not line.startswith("::") else " " + line, end="", flush=True)
                output.write(line)
                output.flush()
                kept += size
            code = child.wait()
    return {"exit": code, "elapsed_ms": (time.monotonic_ns() - start) // 1_000_000,
            "preserved_bytes": kept, "discarded_lines": dropped, "log_sha256": sha(log)}


def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args], text=True).strip()


def product_guard(source):
    want = PLAN["product"]
    fields = {"source": git(source, "rev-parse", "HEAD"),
              "tree": git(source, "rev-parse", "HEAD^{tree}"),
              "locked_source_dependencies_sha256": sha(source / "Cargo.lock")}
    for key, got in fields.items():
        if got != want[key]:
            raise ValueError(f"frozen product {key} differs")
    if git(source, "status", "--porcelain"):
        raise ValueError("frozen product checkout must be clean")
    return fields


def artifact_guard(package):
    identity = read_json(package / "package.json")
    crate = package / "candidate.crate"
    expected = PLAN["product"]
    if (any(identity[k] != v for k, v in expected.items())
        or sha(crate) != expected["candidate_crate_sha256"]
        or crate.stat().st_size != expected["candidate_crate_bytes"]):
        raise ValueError("frozen package differs")
    return identity


def natural_cases(platform):
    return [x for x in PLAN["natural"] if x["id"] != "N03-M" or platform == "macos-arm64-standard"]


def case_result(path, selector, exit_code):
    if not path.is_file():
        return {"status": "missing_log", "started": False, "running_lines": [], "result_lines": []}
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    running = [n for n, s in enumerate(lines, 1) if re.fullmatch(r"running 1 test", s.strip())]
    zero = [n for n, s in enumerate(lines, 1) if s.strip() == "running 0 tests"]
    start = [n for n, s in enumerate(lines, 1) if s.startswith(f"test {selector} ...")]
    end = [n for n, s in enumerate(lines, 1)
           if s.startswith(("test result: ok.", "test result: FAILED."))]
    fault = [n for n, s in enumerate(lines, 1)
             if any(s.startswith(x) for x in ("Error:", "error:", "thread ", "Caused by:", "failures:"))]
    observed = bool(running and start)
    if zero:
        status = "zero_cases"
    elif not observed:
        status = "dispatch_or_build_error" if exit_code else "missing_start"
    elif not end:
        status = "interrupted_or_missing_result"
    elif exit_code == 0 and any("1 passed; 0 failed" in lines[n-1] for n in end):
        status = "passed"
    elif exit_code != 0 and any("0 passed; 1 failed" in lines[n-1] for n in end):
        status = "test_failed"
    else:
        status = "result_inconsistent"
    return {"status": status, "started": observed, "running_lines": running + zero,
            "selector_lines": start, "result_lines": end, "failure_lines": fault}


def preparation_environment(file, environment):
    for row in file.read_text(encoding="utf-8").splitlines():
        key, value = row.split("=", 1)
        if not key.startswith("VERYSYNC_TEST_") or "\x00" in value:
            raise ValueError("fixture supplied an unexpected environment entry")
        environment[key] = value


def guard_engine(source, receipt, slot, root):
    actual = read_json(receipt)
    catalog_name = ("verysync-v2.33.2.json" if slot == "current"
                    else "verysync-upgrade-test-source-v2.33.1.json")
    catalog = read_json(source / "releases" / catalog_name)
    entry = next(x for x in catalog["packages"] if x["id"] == actual["package"])
    binary = Path(actual["binary"]).resolve(strict=True)
    if (actual["version"] != catalog["version"] or actual["archive_sha256"] != entry["sha256"]
            or not binary.is_relative_to(root) or actual["binary_sha256"] != sha(binary)):
        raise ValueError(f"engine {slot} differs from the fixed catalog")
    if slot == "current":
        pins = read_json(source / "releases/verysync-v2.33.2-standard-binaries.json")
        pin = next(x for x in pins["packages"] if x["id"] == actual["package"])
        if pin["binary_sha256"] != actual["binary_sha256"] or pin["archive_sha256"] != actual["archive_sha256"]:
            raise ValueError("current extracted engine digest is not the pinned standard binary")
    return actual


def select_receipt(log):
    for line in log.read_text(encoding="utf-8").splitlines():
        if line.startswith('{"package": '):
            return json.loads(line)
    raise ValueError("official engine setup did not report an identity")


def cleanup(source, env, out, name):
    rows = {}
    for key, arguments in (("current", []), ("upgrade_source", ["--upgrade-source"])):
        var = "VERYSYNC_TEST_BINARY" if key == "current" else "VERYSYNC_TEST_UPGRADE_SOURCE_BINARY"
        if not env.get(var):
            rows[key] = {"status": "not_prepared"}
            continue
        log = out / f"{name}-{key}.log"
        row = capture([sys.executable, "scripts/prepare-test-engine.py", "check-cleanup", *arguments],
                      source, env, log)
        good = row["exit"] == 0 and "No process remains for the exact task-owned test executable." in log.read_text()
        rows[key] = {**row, "status": "passed" if good else "failed", "log": log.name}
    return rows


def prepare(args, out, root, base_env, platform):
    product = product_guard(args.product)
    if git(HERE, "rev-parse", "HEAD") != os.environ["GITHUB_SHA"]:
        raise ValueError("collector checkout does not match workflow SHA")
    manifest = artifact_guard(args.package)
    toolchain = "1.85.0-" + platform["host"]
    rust = subprocess.check_output(["rustc", "+" + toolchain, "-vV"], text=True)
    if ("host: " + platform["host"]) not in rust.splitlines() or "release: 1.85.0" not in rust.splitlines():
        raise ValueError("unexpected Rust build host or release")
    identity = {"product": product, "package": manifest, "collector": os.environ["GITHUB_SHA"],
                "rustc": rust, "runner_os": os.environ.get("RUNNER_OS"),
                "runner_arch": os.environ.get("RUNNER_ARCH"), "runner_label": platform["runner"],
                "runner_name": os.environ.get("RUNNER_NAME"), "image_os": os.environ.get("ImageOS"),
                "image_version": os.environ.get("ImageVersion"), "native_workspace": str(root),
                "run": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
                "workflow_job_label": f'{args.batch} ({args.platform})'}
    write_json(out / "identity.json", identity)
    scopes = ("current", "upgrade_source") if args.batch in ("N1", "N2") else ("current",)
    engines = {}
    for scope in scopes:
        prepare_log = out / f"prepare-{scope}.log"
        flags = ["--upgrade-source"] if scope == "upgrade_source" else []
        env_file = root / f"engine-{scope}.env"
        result = capture([sys.executable, "scripts/prepare-test-engine.py", "prepare", *flags,
                          "--package", args.platform, "--parent", str(root), "--github-env", str(env_file)],
                         args.product, base_env, prepare_log)
        if result["exit"] != 0:
            if scope == "current":
                raise ValueError("fixed current engine preparation failed")
            event(out, "upgrade_fixture_unavailable", detail=result)
            continue
        preparation_environment(env_file, base_env)
        receipt = out / f"engine-{scope}.json"
        write_json(receipt, select_receipt(prepare_log))
        engines[scope] = guard_engine(args.product, receipt, scope, root)
    if args.batch == "I":
        env_file = root / "consumer.env"
        build_path = out / "consumer"
        result = capture([sys.executable, "scripts/prepare-control-reliability-consumer.py",
                          "--toolchain", toolchain,
                          "--candidate", str(args.package / "candidate.crate"),
                          "--candidate-identity", str(args.package / "package.json"),
                          "--work", str(root / "consumer-build"), "--evidence", str(build_path),
                          "--github-env", str(env_file)],
                         args.product, base_env, out / "prepare-package-consumer.log")
        if result["exit"] != 0:
            raise ValueError("fixed package consumer preparation failed")
        preparation_environment(env_file, base_env)
    return toolchain, engines


def copy_proxy_receipt(raw_root, case_dir):
    receipt = raw_root / "proxy-observations.json"
    if receipt.is_file() and receipt.stat().st_size <= LIMIT:
        # Only the upstream runner's aggregate proxy receipt is carried forward.
        write_json(case_dir / receipt.name, read_json(receipt))


def run_case(args, entry, toolchain, env, root, out):
    case_id = entry["id"]
    case_dir = out / case_id
    case_dir.mkdir()
    runtime = root / case_id
    runtime.mkdir()
    scratch = runtime / "private-runtime"
    scratch.mkdir()
    local = {**env, "CARGO_TERM_COLOR": "never"}
    if args.batch != "D":
        local.update(TMPDIR=str(scratch), TMP=str(scratch), TEMP=str(scratch))
    raw = runtime / "research"
    capture_log = case_dir / "process.log"
    event(out, "case_dispatch", case=case_id, target=entry["target"], selector=entry["selector"],
          sample=f"{args.batch}-{args.platform}-{case_id}",
          tested_runtime_temp=(tempfile.gettempdir() if args.batch == "D" else str(scratch)),
          temp_override_active=args.batch != "D")
    result = capture([sys.executable, "scripts/run-isolated-engine-tests.py",
                      "--toolchain", toolchain, "--test-target", entry["target"],
                      "--test-filter", entry["selector"], "--evidence-dir", str(raw),
                      *(["--allow-upgrade-metadata", "--serve-pinned-upgrade-archive"]
                        if case_id in ("N04a", "N04b") else [])],
                     args.product, local, capture_log)
    copy_proxy_receipt(raw, case_dir)
    row = {**entry, **result, **case_result(capture_log, entry["selector"], result["exit"]),
           "sample_id": f"{args.batch}-{args.platform}-{case_id}", "private_root": str(runtime),
           "operation_observability": "See same-case log and proxy receipt. A missing count, response stage, PID or file effect is unknown.",
           "process_log": f"{case_id}/process.log"}
    # Save the result before doing any ownership inventory or cleanup.
    write_json(case_dir / "first-result.json", row)
    event(out, "case_first_result", **row)
    case_cleanup = cleanup(args.product, env, case_dir, "cleanup")
    write_json(case_dir / "cleanup.json", case_cleanup)
    row["cleanup"] = case_cleanup
    event(out, "case_cleanup", case=case_id,
          results={key: cell["status"] for key, cell in case_cleanup.items()})
    return row


def run_controls(args, env, root, out):
    entry = out / "I-public-caller.log"
    command = [sys.executable, "scripts/check-control-corrections-output.py",
               "--listener", env["VERYSYNC_TEST_RECOVERY_EXAMPLE"],
               "--preview", env["VERYSYNC_TEST_PREVIEW_EXAMPLE"], "--only", "B"]
    local = {**env, "TMPDIR": str(root), "TMP": str(root), "TEMP": str(root)}
    event(out, "controlled_group_dispatch", group="I-public-caller")
    results = capture(command, args.product, local, entry)
    fields = []
    for number, line in enumerate(entry.read_text(encoding="utf-8").splitlines(), 1):
        if line.startswith('{"case":'):
            row = json.loads(line)
            if row["case"] in PLAN["public_illustrations"]:
                fields.append({"case": row["case"], "line": number,
                               "assertion_passed": not row["unmet_assertions"]})
    complete = ([item["case"] for item in fields] == PLAN["public_illustrations"]
                and all(item["assertion_passed"] for item in fields)
                and results["discarded_lines"] == 0)
    event(out, "controlled_group_first_result", group="I-public-caller", complete=complete,
          controls=fields, **results)
    write_json(out / "I-public-caller.json", {**results, "complete": complete, "controls": fields})
    return complete and results["exit"] == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--batch", choices=("D",), required=True)
    args = parser.parse_args()
    for name in ("product", "package", "root", "out"):
        setattr(args, name, getattr(args, name).resolve())
    args.out.mkdir(parents=True, exist_ok=False)
    args.root.mkdir(mode=0o700, parents=True, exist_ok=False)
    platform = next(x for x in PLAN["platforms"] if x["package_id"] == args.platform)
    direction = read_json(HERE / "direction-plan.json")[args.platform]
    cases = [r for r in natural_cases(args.platform) + PLAN["controlled"] if r["id"] in direction]
    if set(direction) != {r["id"] for r in cases}:
        raise ValueError("directional authorization and case roster differ")
    event(args.out, "job_entered", batch=args.batch, platform=args.platform, private_root=str(args.root))
    base_env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", CARGO_TERM_COLOR="never")
    base_env.pop("VERYSYNC_TEST_GUI_RESTORE_LOST_REPLY", None)
    # Existing tests own these paths. Do not admit an inherited instance.
    for name in ("VERYSYNC_TEST_BINARY", "VERYSYNC_TEST_BINARY_SHA256", "VERYSYNC_TEST_ARCHIVE",
                 "VERYSYNC_TEST_UPGRADE_SOURCE_BINARY", "VERYSYNC_TEST_UPGRADE_SOURCE_SHA256"):
        base_env.pop(name, None)
    cases_seen = []
    broken = False
    controls_passed = None
    preparation_reason = None
    try:
        toolchain, engines = prepare(args, args.out, args.root, base_env, platform)
        if args.batch == "I":
            controls_passed = run_controls(args, base_env, args.root, args.out)
        for entry in cases:
            if broken:
                cases_seen.append({**entry, "status": "not_run_after_cleanup_error", "started": False})
                continue
            if entry["id"] in ("N04a", "N04b") and "upgrade_source" not in engines:
                cases_seen.append({**entry, "status": "not_run_without_pinned_upgrade_source", "started": False})
                continue
            row = run_case(args, entry, toolchain, base_env, args.root, args.out)
            cases_seen.append(row)
            broken = any(x["status"] == "failed" for x in row["cleanup"].values())
        if args.batch == "I" and not broken:
            from controls import run as supplemental
            controls_passed = supplemental(args.out, args.root) and controls_passed
    except (KeyError, OSError, ValueError, subprocess.SubprocessError, StopIteration) as error:
        preparation_reason = Redactor()(str(error))
        event(args.out, "collector_exception", reason=preparation_reason, type=type(error).__name__)
    finally:
        final_cleanup = cleanup(args.product, base_env, args.out, "final-cleanup")
        safe = all(x["status"] != "failed" for x in final_cleanup.values()) and not broken
        if safe:
            shutil.rmtree(args.root)
        for case in cases:
            if all(existing["id"] != case["id"] for existing in cases_seen):
                skipped = "not_run_after_collector_exception" if cases_seen else "not_run_preparation_failed"
                cases_seen.append({**case, "status": skipped, "started": False})
        final = {"batch": args.batch, "platform": args.platform, "cases": cases_seen,
                 "fixture_outcome": controls_passed, "collector_exception": preparation_reason,
                 "final_cleanup": final_cleanup, "private_root": str(args.root),
                 "private_root_removed": not args.root.exists()}
        write_json(args.out / "job-result.json", final)
        event(args.out, "job_receipt", removed=final["private_root_removed"],
              cleanup={key: value["status"] for key, value in final_cleanup.items()})
    return int(bool(preparation_reason or not safe or controls_passed is False
                    or any(x["status"] != "passed" or x.get("discarded_lines") for x in cases_seen)))


if __name__ == "__main__":
    raise SystemExit(main())
