#!/usr/bin/env python3
"""Select a bounded MIPS diagnostic without changing ready/manual emulation."""
import json
import os
from pathlib import Path
import re

PACKAGES = {f"linux-{name}-standard" for name in
            ["loong64", "ppc64le", "riscv64", "s390x", "mips", "mipsle", "mips64", "mips64le"]}
BRANCH = "ci/native-stop-diagnostics-20261117-01a1ca9b"


def select(catalog, event_name, event, repository):
    required = {"package", "rust", "platform", "emulator", "compiler", "cc", "cxx", "apt", "cpu"}
    if not isinstance(catalog, list) or len(catalog) != len(PACKAGES):
        raise ValueError("all eight frozen emulated profiles are required")
    seen = set()
    for row in catalog:
        if (not isinstance(row, dict) or not required <= row.keys()
                or not row.keys() <= required | {"custom_std", "manual_registration"}):
            raise ValueError("exact emulated profile schema required")
        for key, value in row.items():
            if key in {"custom_std", "manual_registration"}:
                if type(value) is not bool:
                    raise ValueError("emulated mode flags must be booleans")
            elif (not isinstance(value, str) or not re.fullmatch(
                    r"[A-Za-z0-9+._-]+(?: [A-Za-z0-9+._-]+)*" if key == "apt"
                    else r"[A-Za-z0-9+._-]+", value)):
                raise ValueError("bounded literal emulation selections required")
        if row["package"] not in PACKAGES or row["package"] in seen:
            raise ValueError("unique known emulated packages required")
        seen.add(row["package"])
    if event_name == "workflow_dispatch":
        return [dict(row) for row in catalog]
    if event_name == "push":
        if (not isinstance(event, dict) or repository != "AresJef/verysync-sidecar"
                or (event.get("repository") or {}).get("full_name") != repository
                or event.get("deleted") is not False
                or not re.fullmatch(r"refs/heads/ci/formal-candidate/.+", event.get("ref", ""))):
            raise ValueError("owned formal candidate push required")
        return [dict(row) for row in catalog]
    if event_name != "pull_request":
        raise ValueError("explicit pull-request, candidate push or manual event required")
    pull = event.get("pull_request") if isinstance(event, dict) else None
    if (not isinstance(pull, dict) or type(pull.get("draft")) is not bool
            or not isinstance(repository, str) or not repository):
        raise ValueError("explicit pull-request state and repository required")
    if not pull["draft"]:
        return [dict(row) for row in catalog]
    head = pull.get("head") or {}
    if (head.get("ref") == BRANCH
            and (head.get("repo") or {}).get("full_name") == repository):
        return [dict(row) for row in catalog if row["package"] == "linux-mips-standard"]
    return []


def main():
    root = Path(__file__).resolve().parents[1]
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    event = json.loads(Path(event_path).read_text()) if event_path else {}
    catalog = json.loads((root / ".github/other-emulated-matrix.json").read_text())
    rows = select(catalog, os.environ.get("GITHUB_EVENT_NAME", "workflow_dispatch"),
                  event, os.environ.get("GITHUB_REPOSITORY", ""))
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with Path(output).open("a", encoding="utf-8") as stream:
            stream.write("matrix=" + json.dumps({"include": rows}, separators=(",", ":")) + "\n")
    print(json.dumps({"catalog_profiles": len(catalog), "selected_profiles": len(rows),
                      "diagnosis_is_not_complete_platform_acceptance": len(rows) != len(catalog)}))


if __name__ == "__main__":
    main()
