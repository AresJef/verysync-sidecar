#!/usr/bin/env python3
"""Plan bounded draft diagnostics and preserve complete candidate coverage.

This schedules evidence collection only. A selected or superseded diagnosis is
never acceptance; the independent complete native gates remain required.
An owned draft may select known labels or run explicit test filters on the six
standard native profiles without expanding the release matrix.
"""
import json
import os
from pathlib import Path
import re

PROFILES = {
    "macos-amd64-standard": ("macos-15-intel", "x86_64-apple-darwin"),
    "macos-arm64-standard": ("macos-15", "aarch64-apple-darwin"),
    "linux-amd64-standard": ("ubuntu-24.04", "x86_64-unknown-linux-gnu"),
    "linux-arm64-standard": ("ubuntu-24.04-arm", "aarch64-unknown-linux-gnu"),
    "windows-amd64-standard": ("windows-2022", "x86_64-pc-windows-msvc"),
    "windows-arm64-standard": ("windows-11-arm", "aarch64-pc-windows-msvc"),
    "windows-386-standard": ("windows-2022", "i686-pc-windows-msvc"),
}


def draft_mode(event_name, event, repository):
    if event_name == "workflow_dispatch":
        return False
    if event_name == "push":
        source = event.get("repository") if isinstance(event, dict) else None
        branch = event.get("ref") if isinstance(event, dict) else None
        if (repository != "AresJef/verysync-sidecar" or not isinstance(source, dict)
                or source.get("full_name") != repository or event.get("deleted") is not False
                or not isinstance(branch, str)
                or not re.fullmatch(r"refs/heads/ci/formal-candidate/.+", branch)):
            raise ValueError("owned formal candidate push required")
        return False
    if event_name != "pull_request":
        raise ValueError("explicit pull-request, candidate push or manual event required")
    pull = event.get("pull_request") if isinstance(event, dict) else None
    if (not isinstance(pull, dict) or type(pull.get("draft")) is not bool
            or not isinstance(repository, str) or not repository):
        raise ValueError("explicit pull-request draft state and repository required")
    head = pull.get("head") or {}
    repo = head.get("repo") or {}
    # Forks retain the complete catalog; no input can select a private runner.
    return pull["draft"] and repo.get("full_name") == repository


def validate_catalog(catalog):
    if not isinstance(catalog, list) or not 0 < len(catalog) <= 256:
        raise ValueError("bounded nonempty diagnostic catalog required")
    seen = set()
    labels = set()
    for row in catalog:
        required = {"package", "runner", "rust", "target", "filter", "trace"}
        if (not isinstance(row, dict) or not required <= row.keys()
                or not row.keys() <= required | {"label"}
                or any(not isinstance(v, str) for v in row.values())):
            raise ValueError("exact string-valued diagnostic schema required")
        if PROFILES.get(row["package"]) != (row["runner"], row["rust"]):
            raise ValueError("diagnostic runner and target must match a known profile")
        if (row["trace"] not in {"0", "1"}
                or not re.fullmatch(r"[A-Za-z0-9_:]+", row["target"])
                or not re.fullmatch(r"[A-Za-z0-9_:]+", row["filter"])
                or ("label" in row and not re.fullmatch(r"[a-z0-9-]+", row["label"]))):
            raise ValueError("unsafe diagnostic command selection")
        key = tuple(sorted(row.items()))
        if key in seen:
            raise ValueError("duplicate diagnostic row")
        seen.add(key)
        labels.add(row.get("label", row["target"]))
    return labels


def standard_draft_rows(cases):
    if not isinstance(cases, list) or not 0 < len(cases) <= 32:
        raise ValueError("bounded nonempty draft test cases required")
    if any(not isinstance(case, dict) or set(case) != {"target", "filter"} for case in cases):
        raise ValueError("draft test cases require exactly a target and filter")
    rows = [
        {**case, "package": package, "runner": runner, "rust": rust, "trace": "0"}
        for case in cases
        for package, (runner, rust) in PROFILES.items()
        if package != "windows-386-standard"
    ]
    validate_catalog(rows)
    return rows


def select(catalog, selection, *, draft):
    labels = validate_catalog(catalog)
    requested = None
    if selection is not None:
        if not isinstance(selection, dict):
            raise ValueError("exact draft diagnostic selection schema required")
        if set(selection) == {"draft_cases"}:
            rows = standard_draft_rows(selection["draft_cases"])
            return rows if draft else [dict(row) for row in catalog]
        if set(selection) != {"draft_labels"}:
            raise ValueError("exact draft diagnostic selection schema required")
        requested = selection["draft_labels"]
        if (not isinstance(requested, list) or not 0 < len(requested) <= 32
                or any(not isinstance(label, str) for label in requested)
                or len(set(requested)) != len(requested) or not set(requested) <= labels):
            raise ValueError("unique nonempty known draft labels required")
    return [dict(row) for row in catalog if not draft or requested is None
            or row.get("label", row["target"]) in requested]


def main():
    root = Path(__file__).resolve().parents[1]
    event_name = os.environ.get("GITHUB_EVENT_NAME", "workflow_dispatch")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    event = json.loads(Path(event_path).read_text()) if event_path else {}
    draft = draft_mode(event_name, event, os.environ.get("GITHUB_REPOSITORY", ""))
    catalog = json.loads((root / ".github/native-diagnostic-matrix.json").read_text())
    selection_path = root / ".github/native-diagnostic-selection.json"
    selection = json.loads(selection_path.read_text()) if selection_path.exists() else None
    rows = select(catalog, selection, draft=draft)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with Path(output).open("a", encoding="utf-8") as stream:
            stream.write("matrix=" + json.dumps({"include": rows}, separators=(",", ":")) + "\n")
    print(json.dumps({"draft_diagnosis": draft, "selected_cases": len(rows),
                      "catalog_cases": len(catalog), "selection_is_not_acceptance": True}))


if __name__ == "__main__":
    main()
