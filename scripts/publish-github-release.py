#!/usr/bin/env python3
"""Verify an uploaded crate and accepted source before an explicit GitHub release."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
import tomllib
import urllib.request

NATIVE_TARGETS = frozenset(f"{system}-{arch}-standard" for system in ("macos", "windows", "linux")
                           for arch in ("amd64", "arm64"))
QUALITY_JOBS = frozenset(("Minimum Rust 1.85", "Format, build, lint and docs"))
ACTION_WORKFLOWS = {
    "quality": "quality.yml",
    "engine": "engine-tests.yml",
    "platforms": "platform-matrix.yml",
    "resources": "resource-collection.yml",
}
PLATFORM_CLEANUP_STEP = "Require exact owned-executable cleanup"
CANDIDATE_ACTION_JOBS = {
    "quality": {
        "Minimum Rust 1.85": ("Install MSRV",),
        "Format, build, lint and docs": ("Audit locked dependencies against current RustSec advisories",),
    },
    "engine": {
        **{name: ("Require every applicable native suite and exact cleanup",) for name in NATIVE_TARGETS},
        "Fixed archive catalog (static, no engine execution)": (),
    },
    "platforms": {
        **{f"Link legacy Windows Rust examples ({target}-win7-windows-msvc)":
           ("Record the linked architecture and bytes without executing the examples",)
           for target in ("i686", "x86_64")},
        **{name: (PLATFORM_CLEANUP_STEP, "Require every compatibility execution outcome")
           for name in ("linux-386-standard (x86 on x64 Linux)", "windows-386-standard (WOW64)")},
        **{f"linux-{arch}-standard (QEMU user emulation)":
           (PLATFORM_CLEANUP_STEP, "Require all selected emulated outcomes and positive-inventory cases")
           for arch in ("arm", "armv6", "armhf", "loong64", "ppc64le", "riscv64", "s390x",
                        "mips", "mipsle", "mips64", "mips64le")},
        "Plan complete emulation or the exact owned MIPS diagnosis": (),
    },
    "resources": {
        f"Resource coverage ({name})": (
            "Require complete fresh-process preparation on this actual profile",
            "Collect four formal and two independent original-order cycles",
            "Require exact owned-program cleanup",
            "Preserve sanitized raw measurements and immutable group records",
        ) for name in NATIVE_TARGETS
    },
}
PACKAGE_LIMIT = 2 * 1024 * 1024
PACKAGE_ROOT_FILES = frozenset((
    ".cargo_vcs_info.json", "Cargo.toml", "Cargo.toml.orig", "Cargo.lock",
    "README.md", "CHANGELOG.md", "CONTRIBUTING.md", "LICENSE-MIT", "LICENSE-APACHE",
))
PACKAGE_REQUIRED = frozenset((
    ".cargo_vcs_info.json", "Cargo.toml", "Cargo.toml.orig", "Cargo.lock",
    "README.md", "LICENSE-MIT", "LICENSE-APACHE", "src/lib.rs",
))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_package_binding(metadata):
    require(metadata["repository"] == "AresJef/verysync-sidecar", "unexpected repository")
    require(metadata["crate"] == "verysync-sidecar", "unexpected crate")
    require(re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", metadata["version"]), "invalid version")
    for field, length in (("source", 40), ("tree", 40), ("package_sha256", 64)):
        require(re.fullmatch(f"[0-9a-f]{{{length}}}", metadata[field]), f"invalid {field}")


def validate_metadata(metadata):
    validate_package_binding(metadata)
    require(metadata["version"] == "0.1.0-alpha.1",
            "the historical alpha acceptance contract cannot authorize another release")
    require(metadata["publisher"] == "AresJef" and metadata["publisher_id"] == 448021,
            "unexpected publisher")
    for field in ("native_run", "quality_run"):
        require(type(metadata[field]) is int and metadata[field] > 0, f"invalid {field}")
    require(isinstance(metadata["notes"], str) and 0 < len(metadata["notes"]) < 8000, "invalid notes")


def validate_registry(metadata, version):
    require(version["num"] == metadata["version"], "registry version differs")
    require(version["checksum"] == metadata["package_sha256"], "registry checksum differs")
    publisher = version.get("published_by") or {}
    require(publisher.get("login") == metadata["publisher"]
            and publisher.get("id") == metadata["publisher_id"], "registry publisher differs")


def public_package_member(relative):
    if len(relative.parts) == 1:
        return relative.name in PACKAGE_ROOT_FILES
    if any(part.startswith(".") for part in relative.parts):
        return False
    root = relative.parts[0]
    name = relative.as_posix()
    if root in ("src", "examples", "tests"):
        return relative.suffix == ".rs" or name == "tests/fixtures/resource-protocol.json"
    if root == "scripts":
        return relative.suffix == ".py" or name in (
            "scripts/trace-native-folder-opener.ps1", "scripts/storage-test-requirements.txt",
        )
    if root == "docs":
        return (relative.parts[1] == "public" and len(relative.parts) > 2 and relative.suffix == ".md"
                or name in ("docs/capabilities.csv", "docs/platforms.csv"))
    return root == "releases" and len(relative.parts) == 2 and relative.suffix == ".json"


def validate_package(metadata, content):
    require(len(content) <= PACKAGE_LIMIT, "archive input exceeds limit")
    require(hashlib.sha256(content).hexdigest() == metadata["package_sha256"], "archive checksum differs")
    prefix = f'{metadata["crate"]}-{metadata["version"]}/'
    files = {}
    seen = set()
    total_size = 0
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
        for member in archive:
            total_size += member.size
            require(len(files) < 1000 and total_size <= 8 * 1024 * 1024,
                    "unpacked archive exceeds limit")
            filename = PurePosixPath(member.name)
            require(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                    and member.name.startswith(prefix) and filename.as_posix() == member.name
                    and ".." not in filename.parts and "\\" not in member.name
                    and ":" not in member.name and not any(ord(ch) < 32 for ch in member.name),
                    "unexpected archive member")
            raw = member.name.removeprefix(prefix)
            folded = raw.casefold()
            require(folded not in seen, "duplicate or nonportable archive path")
            require(public_package_member(PurePosixPath(raw)), "archive member is outside the public package")
            seen.add(folded)
            with archive.extractfile(member) as file:
                data = file.read()
            require(b"\0" not in data, "archive member contains binary data")
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError("archive member is not UTF-8 public source or documentation") from None
            files[raw] = data
    require(PACKAGE_REQUIRED <= files.keys(), "required source, manifest or license is missing from the archive")
    vcs = json.loads(files[".cargo_vcs_info.json"])
    require(vcs["git"]["sha1"] == metadata["source"] and not vcs["git"].get("dirty", False),
            "archive source differs or is dirty")
    manifest = tomllib.loads(files["Cargo.toml"].decode())
    require(manifest["package"]["name"] == metadata["crate"]
            and manifest["package"]["version"] == metadata["version"], "archive manifest differs")
    return files


def verify_local_package(metadata, path):
    # Cargo rewrites Cargo.toml; Cargo.toml.orig and every other source input
    # retain the exact bytes checked into the candidate tree.
    def git(*arguments):
        return subprocess.check_output(("git", *arguments), timeout=30)

    root = Path(git("rev-parse", "--show-toplevel").decode().rstrip("\r\n"))
    require(Path.cwd() == root, "verify the local archive from the exact candidate checkout root")
    source, tree = git("rev-parse", "HEAD", "HEAD^{tree}").decode().splitlines()
    require((source, tree) == (metadata["source"], metadata["tree"]), "checkout source or tree differs")
    require(not git("status", "--porcelain"), "candidate checkout is dirty")
    with path.open("rb") as local:
        files = validate_package(metadata, local.read(PACKAGE_LIMIT + 1))
    package_name = f'{metadata["crate"]}-{metadata["version"]}'
    with tempfile.TemporaryDirectory(prefix="verysync-package-reference-") as target:
        subprocess.run(
            ("cargo", "package", "--no-verify", "--locked", "--offline", "--target-dir", target),
            timeout=60, check=True,
        )
        reference = Path(target) / "package" / (package_name + ".crate")
        with tarfile.open(reference, mode="r:gz") as generated:
            prefix = package_name + "/"
            names = [name.removeprefix(prefix) for name in generated.getnames()]
            manifest = generated.extractfile(prefix + "Cargo.toml").read()
    require(len(names) == len(set(names)) and files.keys() == set(names),
            "archive members differ from the candidate's Cargo package list")
    require(files["Cargo.toml"] == manifest, "packaged manifest differs from Cargo's normalized candidate")
    tracked = {}
    for record in git("ls-tree", "-r", "-z", source).split(b"\0"):
        if record:
            header, name = record.split(b"\t", 1)
            mode, kind, digest = header.split()
            if kind == b"blob" and mode in (b"100644", b"100755"):
                tracked[name.decode("utf-8")] = digest.decode("ascii")
    for name, data in files.items():
        if name in (".cargo_vcs_info.json", "Cargo.toml"):
            continue
        lookup = "Cargo.toml" if name == "Cargo.toml.orig" else name
        blob = hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
        require(tracked.get(lookup) == blob, "packaged file differs from the candidate Git blob")
    original = tomllib.loads(files["Cargo.toml.orig"].decode())
    normalized = tomllib.loads(files["Cargo.toml"].decode())
    require(normalized.get("features", {}) == original.get("features", {}), "packaged feature policy differs")
    require(normalized["package"].get("license") == original["package"].get("license"),
            "packaged license differs")
    require(normalized["package"].get("publish") == original["package"].get("publish") == ["crates-io"],
            "packaged registry policy differs")
    return len(files)


def validate_jobs(jobs, expected):
    require(len(jobs) == len(expected) and {job["name"] for job in jobs} == expected,
            "required job matrix differs")
    require(all(job["status"] == "completed" and job["conclusion"] == "success" for job in jobs),
            "required job is incomplete or unsuccessful")


def validate_candidate_runs(metadata):
    validate_package_binding(metadata)
    runs = metadata.get("candidate_runs")
    require(isinstance(runs, dict) and runs.keys() == ACTION_WORKFLOWS.keys(),
            "candidate requires quality, engine, platform and formal resource runs")
    for reference in runs.values():
        require(isinstance(reference, dict) and reference.keys() == {"id", "attempt"}
                and all(type(value) is int and value > 0 for value in reference.values()),
                "candidate run requires a positive run ID and attempt number")
    require(len({reference["id"] for reference in runs.values()}) == len(runs),
            "candidate workflow run IDs must be distinct")
    return runs


def validate_candidate_run(metadata, workflow_path, workflow, reference, run):
    repository = metadata["repository"]
    require(workflow["path"] == workflow_path and run["workflow_id"] == workflow["id"]
            and run["path"].split("@", 1)[0] == workflow_path,
            "candidate run does not use the registered workflow")
    candidate_push = (
        run["event"] == "push" and workflow_path in (
            ".github/workflows/platform-matrix.yml", ".github/workflows/resource-collection.yml",
        ) and re.fullmatch(r"ci/formal-candidate/.+", run.get("head_branch") or "")
    )
    require(run["id"] == reference["id"] and run["run_attempt"] == reference["attempt"]
            and run["head_sha"] == metadata["source"]
            and (run["event"] == "workflow_dispatch" or candidate_push)
            and (run.get("repository") or {}).get("full_name") == repository
            and (run.get("head_repository") or {}).get("full_name") == repository,
            "candidate run source, repository, event or attempt differs")
    require(run["status"] == "completed" and run["conclusion"] == "success",
            "candidate workflow did not complete successfully")


def candidate_attempt_jobs(run_path, attempt):
    jobs = []
    total = None
    page = 1
    while total is None or len(jobs) < total:
        response = github(f"{run_path}/attempts/{attempt}/jobs?per_page=100&page={page}")
        if total is None:
            total = response["total_count"]
            require(type(total) is int and total > 0, "candidate workflow returned no jobs")
        members = response["jobs"]
        require(response["total_count"] == total and len(members) == min(100, total - len(jobs)),
                "candidate workflow job list is incomplete or changed during retrieval")
        jobs.extend(members)
        page += 1
    return jobs


def validate_candidate_jobs(source, run_id, attempt, jobs, expected):
    require(len({job["id"] for job in jobs}) == len(jobs), "candidate workflow repeated a job ID")
    required = {}
    for job in jobs:
        name = job["name"]
        if name in expected:
            require(name not in required, "candidate workflow repeated a required job")
            required[name] = job
    require(required.keys() == expected.keys(), "candidate workflow omitted a required job")
    for name, job in required.items():
        require(job["status"] == "completed" and job["conclusion"] == "success",
                f"candidate job did not complete successfully: {name}")
        require(job["run_id"] == run_id and job["run_attempt"] == attempt and job["head_sha"] == source
                and type(job["runner_id"]) is int and job["runner_id"] > 0,
                f"candidate job source, attempt or runner differs: {name}")
        for step in expected[name]:
            matching = [entry for entry in job["steps"] if entry["name"] == step]
            require(len(matching) == 1 and matching[0]["status"] == "completed"
                    and matching[0]["conclusion"] == "success",
                    f"candidate job did not complete a required step: {name} / {step}")


def verify_candidate_actions(metadata):
    runs = validate_candidate_runs(metadata)
    repository = f'repos/{metadata["repository"]}'
    commit = github(f'{repository}/git/commits/{metadata["source"]}')
    require(commit["sha"] == metadata["source"] and commit["tree"]["sha"] == metadata["tree"],
            "repository source or tree differs")
    counts = {}
    for lane, filename in ACTION_WORKFLOWS.items():
        reference = runs[lane]
        workflow = github(f"{repository}/actions/workflows/{filename}")
        run_path = f'{repository}/actions/runs/{reference["id"]}'
        workflow_path = f".github/workflows/{filename}"
        validate_candidate_run(metadata, workflow_path, workflow, reference, github(run_path))
        jobs = candidate_attempt_jobs(run_path, reference["attempt"])
        required = CANDIDATE_ACTION_JOBS[lane]
        validate_candidate_jobs(metadata["source"], reference["id"], reference["attempt"], jobs, required)
        validate_candidate_run(metadata, workflow_path, workflow, reference, github(run_path))
        counts[lane] = {"id": reference["id"], "attempt": reference["attempt"],
                        "required_jobs": len(required), "listed_jobs": len(jobs)}
    return counts


def verify_candidate_preflight(metadata, package):
    """Bind a local Cargo archive and hosted validation to one candidate."""
    validate_candidate_runs(metadata)
    count = verify_local_package(metadata, package)
    checked = verify_candidate_actions(metadata)
    return {
        "local_package_verified": True,
        "candidate_actions_verified": True,
        "source": metadata["source"],
        "tree": metadata["tree"],
        "package_sha256": metadata["package_sha256"],
        "packaged_files": count,
        "runs": checked,
    }


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def public_bytes(url):
    request = urllib.request.Request(url, headers={
        "User-Agent": "verysync-sidecar release verifier (https://github.com/AresJef/verysync-sidecar)"
    })
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
        data = response.read(2 * 1024 * 1024 + 1)
    require(len(data) <= 2 * 1024 * 1024, "public response exceeds limit")
    return data


def github(path, payload=None, optional=False):
    args = ["gh", "api", "--method", "POST" if payload is not None else "GET", path]
    if payload is not None:
        args.extend(("--input", "-"))
    result = subprocess.run(args, input=json.dumps(payload) if payload is not None else None,
                            capture_output=True, text=True, timeout=45, check=False)
    if result.returncode:
        if optional and "HTTP 404" in result.stderr:
            return None
        raise RuntimeError(f"GitHub API request failed for {path}; no automatic mutation retry")
    return json.loads(result.stdout)


def verify(metadata):
    crate, version, repository = (metadata[field] for field in ("crate", "version", "repository"))
    observed = json.loads(public_bytes(f"https://crates.io/api/v1/crates/{crate}/{version}"))["version"]
    validate_registry(metadata, observed)
    owners = json.loads(public_bytes(f"https://crates.io/api/v1/crates/{crate}/owners"))["users"]
    require(any(owner.get("login") == metadata["publisher"] and owner.get("id") == metadata["publisher_id"]
                for owner in owners), "intended publisher is not a current crate owner")
    validate_package(metadata, public_bytes(f"https://static.crates.io/crates/{crate}/{crate}-{version}.crate"))
    commit = github(f'repos/{repository}/git/commits/{metadata["source"]}')
    require(commit["tree"]["sha"] == metadata["tree"], "repository tree differs")
    for field, expected in (("native_run", NATIVE_TARGETS), ("quality_run", QUALITY_JOBS)):
        path = f'repos/{repository}/actions/runs/{metadata[field]}'
        run = github(path)
        require(run["head_sha"] == metadata["source"] and run["status"] == "completed"
                and run["conclusion"] == "success" and run["repository"]["full_name"] == repository,
                "accepted workflow source or outcome differs")
        response = github(path + "/jobs?per_page=100")
        require(response["total_count"] == len(response["jobs"]), "job list is incomplete")
        validate_jobs(response["jobs"], expected)


def tag_target(repository, tag):
    ref = github(f"repos/{repository}/git/ref/tags/{tag}", optional=True)
    if ref is None:
        return None
    target = ref["object"]
    for _ in range(4):
        if target["type"] == "commit":
            return target["sha"]
        require(target["type"] == "tag", "unexpected tag target type")
        target = github(f'repos/{repository}/git/tags/{target["sha"]}')["object"]
    raise ValueError("tag nesting exceeds limit")


def publish(metadata):
    repository, source = metadata["repository"], metadata["source"]
    require(os.environ.get("GITHUB_REPOSITORY") == repository
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_EVENT_NAME") in ("push", "workflow_dispatch"),
            "publication requires the explicit trusted main-branch workflow")
    tag = "v" + metadata["version"]
    target = tag_target(repository, tag)
    require(target in (None, source), "existing tag points to another source; never move it")
    if target is None:
        github(f"repos/{repository}/git/refs", {"ref": "refs/tags/" + tag, "sha": source})
    require(tag_target(repository, tag) == source, "tag source verification failed")
    notes = (metadata["notes"] + f'\n\nSource: `{source}`\n\n'
             f'Package SHA-256: `{metadata["package_sha256"]}`\n\n'
             f'[crates.io](https://crates.io/crates/{metadata["crate"]}/{metadata["version"]}) | '
             f'[Native validation](https://github.com/{repository}/actions/runs/{metadata["native_run"]}) | '
             f'[Quality validation](https://github.com/{repository}/actions/runs/{metadata["quality_run"]})')
    desired = {"tag_name": tag, "target_commitish": source, "name": tag, "body": notes,
               "draft": False, "prerelease": "-" in metadata["version"], "make_latest": "false"}
    release = github(f"repos/{repository}/releases/tags/{tag}", optional=True)
    if release is None:
        release = github(f"repos/{repository}/releases", desired)
    require(all(release[key] == desired[key] for key in ("tag_name", "body", "draft", "prerelease")),
            "release differs; never overwrite an existing release")
    print(json.dumps({"release": release["html_url"], "tag": tag, "source": source}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, default=Path("releases/crates-io-release.json"))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-metadata", action="store_true")
    mode.add_argument("--check-package", type=Path, metavar="LOCAL_CRATE")
    mode.add_argument("--check-actions", action="store_true")
    mode.add_argument("--check-candidate", type=Path, metavar="LOCAL_CRATE",
                      help="check the local package and hosted runs for one candidate")
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    metadata = json.loads(args.metadata.read_text())
    if args.check_package is not None:
        validate_package_binding(metadata)
        count = verify_local_package(metadata, args.check_package)
        print(json.dumps({"local_package_verified": True, "source": metadata["source"],
                          "tree": metadata["tree"], "package_sha256": metadata["package_sha256"],
                          "packaged_files": count}))
        return
    if args.check_actions:
        checked = verify_candidate_actions(metadata)
        print(json.dumps({"candidate_actions_verified": True, "source": metadata["source"],
                          "tree": metadata["tree"], "runs": checked}))
        return
    if args.check_candidate is not None:
        print(json.dumps(verify_candidate_preflight(metadata, args.check_candidate)))
        return
    validate_metadata(metadata)
    if args.check_metadata:
        print("Release metadata shape checked; registry/effect/publication gates have not run.")
        return
    verify(metadata)
    print(json.dumps({"registry_and_source_verified": True, "source": metadata["source"],
                      "package_sha256": metadata["package_sha256"]}))
    if args.publish:
        publish(metadata)


if __name__ == "__main__":
    main()
