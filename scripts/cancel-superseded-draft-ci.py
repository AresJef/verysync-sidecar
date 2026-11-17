#!/usr/bin/env python3
"""Cancel only older draft native runs whose source is in this candidate.

The explicit CI job uses its Actions token, never a developer credential. Release,
quality, ready-for-review, unrelated and non-ancestor runs are preserved. A
cancelled run remains unaccepted; its completed job logs retain their identities.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.request

NON_NATIVE_INPUTS = {
    ".github/workflows/macos-timer-diagnostics.yml", ".github/workflows/resource-collection.yml",
    "docs/public/platform-validation.md", "docs/public/resource-measurements.md",
    "scripts/measure-native-resources.py", "scripts/probe-macos-timers.py",
    "scripts/tests/test_macos_timer_probe.py", "scripts/tests/test_resource_measurement_quality.py",
    "tests/fixtures/resource-protocol.json",
}


def exact_retirements(root):
    path = root / ".github/exact-native-retirements.json"
    if not path.exists():
        return []
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or set(value) != {"runs"} or not isinstance(value["runs"], list) or len(value["runs"]) > 4:
        raise ValueError("bounded explicit native retirement list required")
    seen = set()
    for row in value["runs"]:
        if (not isinstance(row, dict) or set(row) != {"run_id", "pr", "head_sha", "equivalent_head_sha", "expected_files"}
                or type(row["run_id"]) is not int or row["run_id"] <= 0 or row["run_id"] in seen
                or type(row["pr"]) is not int or row["pr"] <= 0
                or any(not isinstance(row[k], str) or not re.fullmatch(r"[0-9a-f]{40}", row[k]) for k in ["head_sha", "equivalent_head_sha"])
                or not isinstance(row["expected_files"], dict) or not row["expected_files"]
                or not set(row["expected_files"]) <= NON_NATIVE_INPUTS
                or any(not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{40}", v) for v in row["expected_files"].values())):
            raise ValueError("exact pinned non-native-only retirement proof required")
        seen.add(row["run_id"])
    return value["runs"]


def retire_exact(rows, api, current_run, current_sha, ancestor):
    prepared, outcomes = [], []
    for row in rows:
        run = api(f'/actions/runs/{row["run_id"]}')
        if (run["id"] != row["run_id"] or run["workflow_id"] != 415510507
                or run["name"] != "Engine fixture" or run["event"] != "pull_request"
                or run["head_sha"] != row["head_sha"]
                or run["repository"]["full_name"] != "AresJef/verysync-sidecar"
                or [p["number"] for p in run["pull_requests"]] != [row["pr"]]
                or run["id"] == current_run or run["head_sha"] == current_sha):
            raise ValueError("explicit native run identity differs")
        if run["status"] == "completed":
            outcomes.append({"id": run["id"], "accepted": False, "skip": "already completed"})
            continue
        pull = api(f'/pulls/{row["pr"]}')
        if not eligible(run, pull, current_run, current_sha, ancestor) or not ancestor(row["equivalent_head_sha"]):
            raise ValueError("explicit native retirement is no longer an owned draft ancestor")
        comparison = api(f'/compare/{row["equivalent_head_sha"]}...{row["head_sha"]}')
        if (comparison["status"] != "ahead" or comparison["base_commit"]["sha"] != row["equivalent_head_sha"]
                or not 1 <= comparison["total_commits"] <= 4
                or len(comparison["commits"]) != comparison["total_commits"]
                or comparison["commits"][-1]["sha"] != row["head_sha"]
                or len(comparison["files"]) != len(row["expected_files"])
                or any(f["status"] not in {"modified", "added"} for f in comparison["files"])
                or {f["filename"]: f["sha"] for f in comparison["files"]} != row["expected_files"]):
            raise ValueError("native consumer equivalence proof differs")
        prepared.append(row)
    # Validate every identity and complete exact diff before the first mutation.
    for row in prepared:
        fresh = api(f'/actions/runs/{row["run_id"]}')
        pull = api(f'/pulls/{row["pr"]}')
        if (not eligible(fresh, pull, current_run, current_sha, ancestor)
                or fresh["head_sha"] != row["head_sha"] or fresh["id"] != row["run_id"]
                or fresh["name"] != "Engine fixture" or fresh["workflow_id"] != 415510507
                or fresh["repository"]["full_name"] != "AresJef/verysync-sidecar"
                or [p["number"] for p in fresh["pull_requests"]] != [row["pr"]]):
            outcomes.append({"id": row["run_id"], "accepted": False, "skip": "no longer eligible"})
            continue
        outcome = {"id": row["run_id"], "pr": row["pr"], "head_sha": row["head_sha"],
                   "equivalent_head_sha": row["equivalent_head_sha"], "accepted": False}
        try:
            api(f'/actions/runs/{row["run_id"]}/cancel', "POST")
            outcome["cancel_requested"] = True
        except urllib.error.HTTPError as error:
            if error.code != 409:
                raise RuntimeError(f'explicit cancellation failed for run {row["run_id"]}: HTTP {error.code}') from None
            outcome["cancel_requested"] = False
            outcome["already_finished_or_uncancellable"] = True
        outcomes.append(outcome)
    return outcomes


def eligible(run, pull, current_run, current_sha, is_ancestor):
    return (run["id"] != current_run and run["event"] == "pull_request"
            and run["name"] in {"Engine fixture", "Additional platform acceptance"}
            and run["status"] in {"queued", "in_progress", "waiting", "pending", "requested"}
            and run["head_sha"] != current_sha
            and bool(re.fullmatch(r"[0-9a-f]{40}", run["head_sha"]))
            and pull.get("draft") is True and pull.get("state") == "open"
            and (pull["head"].get("repo") or {}).get("full_name") == "AresJef/verysync-sidecar"
            and pull["head"]["sha"] == run["head_sha"]
            and is_ancestor(run["head_sha"]))


def preserve_ancestor_drafts(root):
    path = root / ".github/native-diagnostic-preservation.json"
    if not path.exists():
        return False
    value = json.loads(path.read_text())
    if (not isinstance(value, dict) or set(value) != {"preserve_ancestor_drafts"}
            or type(value["preserve_ancestor_drafts"]) is not bool):
        raise ValueError("exact boolean diagnostic-preservation setting required")
    return value["preserve_ancestor_drafts"]


def main():
    if (os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REPOSITORY") != "AresJef/verysync-sidecar"
            or os.environ.get("GITHUB_EVENT_NAME") != "pull_request"):
        raise ValueError("explicit owned-repository pull-request CI required")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    current_pull = event["pull_request"]
    if not current_pull["draft"] or current_pull["head"]["repo"]["full_name"] != os.environ["GITHUB_REPOSITORY"]:
        raise ValueError("only an owned draft candidate may retire ancestor drafts")
    current_sha = current_pull["head"]["sha"]
    current_run = int(os.environ["GITHUB_RUN_ID"])
    base = "https://api.github.com/repos/AresJef/verysync-sidecar"
    root = Path(__file__).resolve().parents[1]
    preserve = preserve_ancestor_drafts(root)
    exact = exact_retirements(root)
    if preserve and not exact:
        print(json.dumps({"preserve_ancestor_drafts": True,
                          "reason": "distinct pending evidence remains required",
                          "cancellation_requests": 0}))
        return
    token = os.environ["GH_TOKEN"]

    def api(path, method="GET"):
        request = urllib.request.Request(base+path, method=method,
            headers={"Authorization": "Bearer "+token, "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28"}, data=b"" if method == "POST" else None)
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read()
            return json.loads(body) if body else None

    def ancestor(sha):
        result = subprocess.run(["git", "merge-base", "--is-ancestor", sha, current_sha], cwd=root,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode not in {0, 1}:
            raise RuntimeError("source ancestry is unavailable; refuse cancellation")
        return result.returncode == 0

    if exact:
        print(json.dumps({"exact_non_native_duplicates": retire_exact(exact, api, current_run, current_sha, ancestor),
                          "cancellation_never_establishes_acceptance": True}), flush=True)
    if preserve:
        print(json.dumps({"preserve_ancestor_drafts": True,
                          "reason": "all runs outside the explicit proven duplicate list remain preserved"}))
        return

    outcomes = []
    for page in range(1, 4):
        runs = api(f"/actions/runs?per_page=100&page={page}")["workflow_runs"]
        for run in runs:
            pulls = run.get("pull_requests", [])
            if len(pulls) != 1 or run["status"] not in {"queued", "in_progress", "waiting", "pending", "requested"}:
                continue
            if run["event"] != "pull_request" or run["name"] not in {"Engine fixture", "Additional platform acceptance"}:
                continue
            pull = api(f'/pulls/{pulls[0]["number"]}')
            if not eligible(run, pull, current_run, current_sha, ancestor):
                continue
            fresh = api(f'/actions/runs/{run["id"]}')
            if not eligible(fresh, pull, current_run, current_sha, ancestor):
                continue
            row = {"id": run["id"], "pr": pulls[0]["number"], "head_sha": run["head_sha"],
                   "name": run["name"], "before": fresh["status"], "accepted": False}
            try:
                api(f'/actions/runs/{run["id"]}/cancel', "POST")
                row["cancel_requested"] = True
            except urllib.error.HTTPError as error:
                if error.code != 409:
                    raise RuntimeError(f'bounded cancellation failed for run {run["id"]}: HTTP {error.code}') from None
                row["cancel_requested"] = False
                row["already_finished_or_uncancellable"] = True
            outcomes.append(row)
            print(json.dumps(row), flush=True)
        if len(runs) < 100:
            break
    print(json.dumps({"candidate": current_sha, "runs_considered_for_retirement": len(outcomes),
                      "cancellation_never_establishes_acceptance": True}))


if __name__ == "__main__":
    main()
