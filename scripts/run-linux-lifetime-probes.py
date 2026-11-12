#!/usr/bin/env python3
"""Explicit native investigations; never invoked by Cargo build/import."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil

CASES = ("normal", "conflict", "forced-base", "pdeath-hup", "pdeath-kill",
         "thread-pdeath", "forced-pty", "close-pty", "early-pty",
         "auth-failure-pty", "inherited-pty", "thread-pty", "install-race", "exec-fork")


def verify(case: str, report: dict) -> None:
    assert report.get("case") == case
    if case == "exec-fork":
        assert report["primitive"] == {"pdeathsig_after_exec": 1, "pdeathsig_after_fork": 0}
        return
    if case == "install-race":
        assert report["parent_changed_rejected_before_exec"]
        assert report["child_stopped_before_external_cleanup"]
        assert report["live_group_before_cleanup"] == []
        return
    assert report["identity_key_unchanged"]
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
        assert any("failed to acquire lock" in text.lower() for text in report["bounded_rejection_context"])
        assert report["first_process_group_still_live"]
        assert report["first_authenticated_endpoint_still_ready"]
        assert report["first_child_exit"]["code"] == 0
    elif "pty" in case:
        assert report["native_entire_group_stopped_before_any_fallback"]
        assert not report["external_fallback_needed"]
        assert not report["probe_host_fallback_timeout"]
        assert report["native_live_group_members_before_cleanup"] == []
        assert report["host_descriptor_and_signal_state"]["master_cloexec"]
        fields = report["before"].split()
        assert fields[0] == fields[2] == fields[3] and fields[4] != "?"
    elif case.startswith("pdeath") or case == "thread-pdeath":
        # Root termination is distinct from termination of its descendants.
        # Preserve either whole-group outcome for the investigation decision.
        assert report["native_child_stopped_before_external_cleanup"]
    elif case == "forced-base":
        assert report["external_fallback_needed"]
        assert not report["native_entire_group_stopped_before_any_fallback"]
    if case in ("early-pty", "auth-failure-pty"):
        assert report["authenticated_expected_identity"] is None
    else:
        assert report["authenticated_expected_identity"]
    if case == "early-pty":
        assert report["readiness_not_requested"]
    if case == "auth-failure-pty":
        assert report["expected_authentication_rejection"]
    if case == "inherited-pty":
        assert report["host_descriptor_and_signal_state"]["host_hup_ignored_and_blocked"]
    if case.startswith("thread-"):
        meta = report["host_descriptor_and_signal_state"]
        assert meta["creator_tid"] != meta["host_pid"]
        assert report["creator_thread_exited"]
    if case == "thread-pdeath":
        assert report["host_recorded_after_creator_thread_exit"]
    if case == "thread-pty":
        assert report["host_still_live_after_creator_thread_exit"]
        assert report["engine_still_authenticated_after_creator_thread_exit"]


def verify_native_abi(evidence_dir: Path) -> None:
    source = r'''#define _GNU_SOURCE
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <stdio.h>
int main(void) {
 printf("{\"sigset_size\":%zu,\"setmask\":%d,\"block\":%d,\"ctty\":%lu,\"getfd\":%d,\"setfd\":%d,\"cloexec\":%d,\"open_cloexec\":%d,\"set_pdeath\":%d,\"get_pdeath\":%d}\n",
 sizeof(sigset_t), SIG_SETMASK, SIG_BLOCK, (unsigned long)TIOCSCTTY,
 F_GETFD, F_SETFD, FD_CLOEXEC, O_CLOEXEC, PR_SET_PDEATHSIG, PR_GET_PDEATHSIG);
 return 0;
}
'''
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("native C compiler required to validate standalone FFI ABI")
    with tempfile.TemporaryDirectory(prefix="vs-abi-") as private:
        executable = Path(private) / "native-abi"
        subprocess.run([compiler, "-x", "c", "-std=c11", "-Werror", "-o", str(executable), "-"],
                       input=source, text=True, check=True)
        report = json.loads(subprocess.check_output([str(executable)], text=True))
    assert report == {"sigset_size": 128, "setmask": 2, "block": 0, "ctty": 0x540e,
                      "getfd": 1, "setfd": 2, "cloexec": 1, "open_cloexec": 0o2000000,
                      "set_pdeath": 1, "get_pdeath": 2}
    (evidence_dir / "native-abi.json").write_text(json.dumps(report, sort_keys=True) + "\n")
    print("Native Linux FFI ABI verified: " + json.dumps(report, sort_keys=True), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        raise RuntimeError("explicit Linux lifetime investigation requires native Linux")
    if not args.evidence_dir.is_absolute():
        raise ValueError("absolute private evidence directory required")
    args.evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    verify_native_abi(args.evidence_dir)
    compiler = subprocess.check_output(
        ["rustup", "which", "rustc", "--toolchain", args.toolchain], text=True).strip()
    for case in CASES:
        output = args.evidence_dir / f"{case}.json"
        env = dict(os.environ, VERYSYNC_PROBE_RUSTC=compiler,
                   VERYSYNC_LIFETIME_CASE=case, VERYSYNC_LIFETIME_EVIDENCE=str(output))
        subprocess.run(["cargo", f"+{args.toolchain}", "test", "--locked", "--features",
                        "engine-tests", "--test", "lifetime_probes", "linux_lifetime_case",
                        "--", "--test-threads=1"], env=env, check=True)
        report = json.loads(output.read_text())
        verify(case, report)
        # Only bounded, credential-free investigation results enter CI logs.
        print(json.dumps(report, sort_keys=True), flush=True)
        subprocess.run([sys.executable, str(Path(__file__).with_name("prepare-test-engine.py")),
                        "check-cleanup"], env=env, check=True)
    print("All explicit Linux mechanism cases verified; not product lifecycle acceptance.")


if __name__ == "__main__":
    main()
