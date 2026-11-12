#!/usr/bin/env python3
"""Explicit native investigations; never invoked by Cargo build/import."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

CASES = ("normal", "conflict", "forced-base", "forced-pty", "close-pty",
         "early-pty", "auth-failure-pty", "inherited-pty")


def verify(case: str, report: dict) -> None:
    if report.get("case") != case or report.get("identity_key_unchanged") is not True:
        raise RuntimeError("investigation identity/case evidence is incomplete")
    if case == "normal":
        assert report["normal_rust_guard_child_stopped"]
        assert report["normal_rust_guard_live_group_members"] == []
        assert report["same_state_identity_reused"]
        assert report["explicit_shutdown_acknowledged"]
        assert report["explicit_shutdown_child_exit"]["code"] == 0
        assert report["explicit_shutdown_live_group_members"] == []
    elif case == "conflict":
        assert report["second_failed_without_probe_timeout"]
        assert not report["address_conflict_message_observed"]
        assert any("failed to acquire lock" in text.lower()
                   for text in report["bounded_rejection_context"])
        assert report["first_process_group_still_live"]
        assert report["first_authenticated_endpoint_still_ready"]
        assert report["first_child_exit"]["code"] == 0
    elif case != "forced-base":
        assert report["native_entire_group_stopped_before_any_fallback"]
        assert not report["external_fallback_needed"]
        assert not report["probe_host_fallback_timeout"]
        assert report["native_live_group_members_before_cleanup"] == []
        assert report["host_descriptor_and_signal_state"]["master_cloexec"]
        fields = report["before"].split()
        assert fields[0] == fields[2] == fields[3] and fields[4] != "??"
    if case == "early-pty":
        assert report["readiness_not_requested"]
        assert report["authenticated_expected_identity"] is None
    elif case == "auth-failure-pty":
        assert report["expected_authentication_rejection"]
        assert report["authenticated_expected_identity"] is None
    else:
        assert report["authenticated_expected_identity"]
    if case == "inherited-pty":
        assert report["host_descriptor_and_signal_state"]["host_hup_ignored_and_blocked"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "darwin":
        raise RuntimeError("explicit macOS lifetime investigation requires native macOS")
    if not args.evidence_dir.is_absolute():
        raise ValueError("absolute private evidence directory required")
    args.evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    compiler = subprocess.check_output(
        ["rustup", "which", "rustc", "--toolchain", args.toolchain], text=True).strip()
    for case in CASES:
        output = args.evidence_dir / f"{case}.json"
        env = dict(os.environ, VERYSYNC_PROBE_RUSTC=compiler,
                   VERYSYNC_LIFETIME_CASE=case, VERYSYNC_LIFETIME_EVIDENCE=str(output))
        subprocess.run(["cargo", f"+{args.toolchain}", "test", "--locked", "--features",
                        "engine-tests", "--test", "lifetime_probes", "macos_lifetime_case",
                        "--", "--test-threads=1"], env=env, check=True)
        report = json.loads(output.read_text())
        verify(case, report)
        # Only bounded, credential-free investigation results enter CI logs.
        print(json.dumps(report, sort_keys=True), flush=True)
        subprocess.run([sys.executable, str(Path(__file__).with_name("prepare-test-engine.py")),
                        "check-cleanup"], env=env, check=True)
    print("All explicit macOS mechanism cases verified; not product lifecycle acceptance.")


if __name__ == "__main__":
    main()
