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
    if preserve_ancestor_drafts(root):
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
