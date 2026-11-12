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
import tomllib
import urllib.request

NATIVE_TARGETS = frozenset(f"{system}-{arch}-standard" for system in ("macos", "windows", "linux")
                           for arch in ("amd64", "arm64"))
QUALITY_JOBS = frozenset(("Minimum Rust 1.85", "Format, build, lint and docs"))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_metadata(metadata):
    require(metadata["repository"] == "AresJef/verysync-sidecar", "unexpected repository")
    require(metadata["crate"] == "verysync-sidecar", "unexpected crate")
    require(metadata["publisher"] == "AresJef" and metadata["publisher_id"] == 448021,
            "unexpected publisher")
    require(re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", metadata["version"]), "invalid version")
    for field, length in (("source", 40), ("tree", 40), ("package_sha256", 64)):
        require(re.fullmatch(f"[0-9a-f]{{{length}}}", metadata[field]), f"invalid {field}")
    for field in ("native_run", "quality_run"):
        require(type(metadata[field]) is int and metadata[field] > 0, f"invalid {field}")
    require(isinstance(metadata["notes"], str) and 0 < len(metadata["notes"]) < 8000, "invalid notes")


def validate_registry(metadata, version):
    require(version["num"] == metadata["version"], "registry version differs")
    require(version["checksum"] == metadata["package_sha256"], "registry checksum differs")
    publisher = version.get("published_by") or {}
    require(publisher.get("login") == metadata["publisher"]
            and publisher.get("id") == metadata["publisher_id"], "registry publisher differs")


def validate_package(metadata, content):
    require(hashlib.sha256(content).hexdigest() == metadata["package_sha256"], "archive checksum differs")
    prefix = f'{metadata["crate"]}-{metadata["version"]}/'
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
        members = archive.getmembers()
        require(2 <= len(members) <= 1000, "unexpected archive size")
        require(sum(member.size for member in members) <= 8 * 1024 * 1024,
                "unpacked archive exceeds limit")
        require(all(member.isfile() and member.name.startswith(prefix)
                    and ".." not in PurePosixPath(member.name).parts for member in members),
                "unexpected archive member")
        vcs = json.load(archive.extractfile(prefix + ".cargo_vcs_info.json"))
        require(vcs["git"]["sha1"] == metadata["source"] and not vcs["git"].get("dirty", False),
                "archive source differs or is dirty")
        manifest = tomllib.loads(archive.extractfile(prefix + "Cargo.toml").read().decode())
        require(manifest["package"]["name"] == metadata["crate"]
                and manifest["package"]["version"] == metadata["version"], "archive manifest differs")


def validate_jobs(jobs, expected):
    require(len(jobs) == len(expected) and {job["name"] for job in jobs} == expected,
            "required job matrix differs")
    require(all(job["status"] == "completed" and job["conclusion"] == "success" for job in jobs),
            "required job is incomplete or unsuccessful")


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
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    metadata = json.loads(args.metadata.read_text())
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
