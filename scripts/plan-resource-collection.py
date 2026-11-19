#!/usr/bin/env python3
"""Select frozen resource profiles from a trusted Actions event."""

import json
import os
from pathlib import Path

REPOSITORY = "AresJef/verysync-sidecar"
R23_REF = "refs/heads/ci/formal-candidate/r23-intel-deferred/"
INTEL_PROFILE = "macos-amd64-standard"
CHECKOUT_REPAIR = "ci/compiled-input-resources-v27-20261118-01a1ca9b"
PROFILES = (
    (INTEL_PROFILE, "macos-15-intel", "x86_64-apple-darwin"),
    ("macos-arm64-standard", "macos-15", "aarch64-apple-darwin"),
    ("linux-amd64-standard", "ubuntu-24.04", "x86_64-unknown-linux-gnu"),
    ("linux-arm64-standard", "ubuntu-24.04-arm", "aarch64-unknown-linux-gnu"),
    ("windows-amd64-standard", "windows-2022", "x86_64-pc-windows-msvc"),
    ("windows-arm64-standard", "windows-11-arm", "aarch64-pc-windows-msvc"),
)


def select_profiles(event_name, repository, ref, event):
    deferred = (
        event_name == "push" and repository == REPOSITORY
        and ref.startswith(R23_REF) and ref != R23_REF
        and event.get("ref") == ref and event.get("deleted") is False
        and (event.get("repository") or {}).get("full_name") == REPOSITORY
    )
    pull = event.get("pull_request") or {}
    head = pull.get("head") or {}
    checkout_repair = (
        event_name == "pull_request" and pull.get("draft") is True
        and head.get("ref") == CHECKOUT_REPAIR
        and (head.get("repo") or {}).get("full_name") == repository
        and all(label.get("name") != "resource-formal" for label in pull.get("labels", []))
    )
    profiles = [
        {"package": package, "runner": runner, "rust": rust}
        for package, runner, rust in PROFILES
        if (not deferred or package != INTEL_PROFILE)
        and (not checkout_repair or package.startswith("windows-"))
    ]
    return profiles, INTEL_PROFILE if deferred else ""


def main():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    profiles, deferred = select_profiles(
        os.environ["GITHUB_EVENT_NAME"], os.environ["GITHUB_REPOSITORY"],
        os.environ["GITHUB_REF"], event,
    )
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write(f"profiles={json.dumps(profiles)}\n")
        output.write(f"deferred_profile={deferred}\n")
    print(json.dumps({"required_resource_profiles": [row["package"] for row in profiles],
                      "deferred_formal_resource_profile": deferred or None}))


if __name__ == "__main__":
    main()
