#!/usr/bin/env python3
"""Explicit native Windows Job investigations; never run by Cargo build/import."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

CASES = ("normal", "forced-host", "last-handle", "persistent", "early",
         "auth-failure", "startup-failure")
KILL_ON_CLOSE = 0x2000


def verify(case: str, report: dict) -> None:
    assert report["case"] == case
    assert report["observer_holds_inner_job_handle"] is False
    assert report["identity_key_unchanged"]
    assert not report["host_exact_child_fallback_used"]
    if case == "startup-failure":
        result = report["startup_failure"]
        assert result["success"] is False and result["code"] != 0
        assert result["job"]["active_processes"] == 0
        assert report["host_exit"]["success"]
        return
    job = report["job"]
    assert job["root_in_job"]
    assert not job["handle_inheritable"]
    assert job["process_ids"]
    assert job["active_processes"] > 0
    assert report["outer_containment"]["root_in_job"]
    assert report["host_pid"] in report["outer_containment"]["process_ids"]
    assert set(job["process_ids"]).issubset(report["outer_containment"]["process_ids"])
    assert report["host_pid"] not in job["process_ids"]
    assert report["all_recorded_process_handles_signalled_before_fallback"]
    assert report["outer_job_empty_before_fallback"]
    assert not report["external_fallback_needed"]
    assert report["host_exit"]["success"] == (case in ("normal", "last-handle"))
    if case == "persistent":
        assert job["limit_flags"] & KILL_ON_CLOSE == 0
        assert report["authenticated_after_host_termination"]
        assert report["live_after_host_termination"] > 0
        assert report["explicit_shutdown_acknowledged"]
    else:
        assert job["limit_flags"] & KILL_ON_CLOSE
    if case == "last-handle":
        duplicate = report["retained_duplicate_job"]
        assert duplicate["process_ids"]
        assert not duplicate["handle_inheritable"]
        assert duplicate["root_in_job"]
        assert report["authenticated_after_primary_close"]
    if case in ("early", "auth-failure"):
        assert report["authenticated_expected_identity"] is None
    else:
        assert report["authenticated_expected_identity"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "win32":
        raise RuntimeError("explicit Windows lifetime investigation requires native Windows")
    if not args.evidence_dir.is_absolute():
        raise ValueError("absolute private evidence directory required")
    args.evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    failures = []
    for case in CASES:
        evidence = args.evidence_dir / f"{case}.json"
        env = dict(os.environ, VERYSYNC_LIFETIME_CASE=case,
                   VERYSYNC_LIFETIME_EVIDENCE=str(evidence))
        try:
            subprocess.run(["cargo", f"+{args.toolchain}", "test", "--locked", "--features",
                            "engine-tests", "--test", "windows_lifetime_probes",
                            "windows_lifetime_case", "--", "--test-threads=1"],
                           env=env, check=True)
            report = json.loads(evidence.read_text())
            print(json.dumps(report, sort_keys=True), flush=True)
            verify(case, report)
        except (AssertionError, subprocess.CalledProcessError) as failure:
            failures.append(case)
            print(f"Investigation case {case} failed: {type(failure).__name__}", flush=True)
        finally:
            subprocess.run([sys.executable, str(Path(__file__).with_name("prepare-test-engine.py")),
                            "check-cleanup"], env=env, check=True)
    if failures:
        raise RuntimeError("Native Windows investigation failed cases: " + ", ".join(failures))
    print("All explicit Windows mechanism cases verified; not product runtime acceptance.")


if __name__ == "__main__":
    main()
