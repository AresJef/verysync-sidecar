#!/usr/bin/env python3
"""Require actual step outcomes, including failures hidden by continue-on-error."""
import json
import os
import sys
from pathlib import Path

COMMON = frozenset(['native_files_engine', 'native_file_mutation_engine', 'native_local_sync_engine', 'native_local_sync_protocol_engine', 'native_local_sync_protocol_advanced_engine', 'native_local_sync_advanced_engine', 'native_local_sync_runtime_engine', 'native_local_sync_automation_engine', 'native_local_sync_repair_engine', 'native_local_sync_configuration_engine', 'native_configuration_engine', 'native_authentication_engine', 'native_ldap_trusted_ca_engine', 'storage_environment', 'native_file_transfer_engine', 'native_disk_full_engine', 'native_file_history_engine', 'native_maintenance_engine', 'native_managed_lifetime', 'native_managed_instance', 'native_p2p_isolation', 'native_devices', 'native_invitations', 'native_network', 'native_sync_observation', 'native_p2p_three_nodes', 'native_upgrade_engine', 'native_engine_control', 'native_host_watch_limit', 'native_wallpaper_denied', 'native_wallpaper_resource', 'native_events', 'native_example_control', 'native_operations', 'native_sharing', 'native_download_engine', 'native_cache_engine', 'native_cleanup_baseline', 'native_cleanup_upgrade'])


def failures(package, steps):
    family = package.split("-", 1)[0]
    if family not in {"macos", "linux", "windows"}:
        return ["unknown native matrix family"]
    required = set(COMMON)
    required.add("native_mechanism_" + family)
    if family == "windows":
        required.add("native_windows_ui")
    if family in {"macos", "linux"}:
        required.add("native_browser_engine")
    # New native steps are required too, except explicitly inapplicable ones.
    inapplicable = {"native_mechanism_" + other for other in {"macos", "linux", "windows"} if other != family}
    if family != "windows":
        inapplicable.add("native_windows_ui")
    if family not in {"macos", "linux"}:
        inapplicable.add("native_browser_engine")
    if package == "windows-amd64-standard":
        required.add("native_windows_gui_lost_reply")
    else:
        inapplicable.add("native_windows_gui_lost_reply")
    required.update(key for key in steps if key.startswith("native_") and key not in inapplicable)
    return [key for key in sorted(required) if steps.get(key, {}).get("outcome") != "success"]


def main():
    failed = failures(os.environ["NATIVE_MATRIX_PACKAGE"], json.loads(os.environ["NATIVE_STEP_RESULTS"]))
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        message = (
            "Some required native tests or cleanup checks did not pass. "
            "Open the failing steps in this job to see what ran and whether the test processes stopped."
            if failed else
            "The required native tests passed on this runner. "
            "The process checks confirmed that neither test program is still running."
        )
        try:
            with Path(path).open("a", encoding="utf-8") as summary:
                print(f"### Native test results\n\n{message}\n", file=summary)
        except OSError:
            print("Could not write the job summary. The test result is in the log.", file=sys.stderr)
    if failed:
        print("Required native outcomes did not pass: " + ", ".join(failed), file=sys.stderr)
        return 1
    print("All applicable native suites and both exact-executable cleanup checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
