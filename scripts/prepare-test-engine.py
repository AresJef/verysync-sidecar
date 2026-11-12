#!/usr/bin/env python3
"""Explicitly prepare a fixed official engine for isolated integration tests.

This helper is never invoked by Cargo. It copies only the executable from a
verified archive into a new private test directory; service samples stay inside
the archive. It does not launch the program or change host configuration.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile

MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 10_000
OFFICIAL_HOSTS = {"dl-cn.verysync.com"}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validated_members(members, get_name):
    if len(members) > MAX_MEMBERS:
        raise ValueError("archive member count exceeds the test setup limit")
    seen = set()
    result = []
    for member in members:
        name = get_name(member)
        path = PurePosixPath(name)
        if ("\\" in name or "\0" in name or path.is_absolute()
                or ".." in path.parts or (path.parts and ":" in path.parts[0])):
            raise ValueError("unsafe archive member path")
        normalized = path.as_posix()
        if normalized in seen:
            raise ValueError("duplicate archive member path")
        seen.add(normalized)
        result.append((member, normalized))
    return result


def copy_bounded(source, target, size):
    if size <= 0 or size > MAX_EXECUTABLE_BYTES:
        raise ValueError("unexpected executable size")
    written = 0
    with target.open("xb") as destination:
        while True:
            chunk = source.read(64 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > size or written > MAX_EXECUTABLE_BYTES:
                raise ValueError("executable expanded beyond its declared limit")
            destination.write(chunk)
    if written != size:
        raise ValueError("incomplete executable in archive")
    target.chmod(0o700)


def extract_executable(archive_path, destination, root, executable_name, archive_format):
    expected = (PurePosixPath(root) / executable_name).as_posix()
    target = destination / executable_name
    if archive_format == "zip":
        with zipfile.ZipFile(archive_path) as archive:
            members = validated_members(archive.infolist(), lambda i: i.filename)
            selected = [m for m, name in members if name == expected]
            if len(selected) != 1:
                raise ValueError("expected version-root executable is missing or ambiguous")
            member = selected[0]
            file_type = stat.S_IFMT(member.external_attr >> 16)
            if member.is_dir() or file_type not in (0, stat.S_IFREG):
                raise ValueError("selected executable is not a regular file")
            with archive.open(member) as source:
                copy_bounded(source, target, member.file_size)
    elif archive_format == "tar.gz":
        with tarfile.open(archive_path, "r:gz") as archive:
            members = validated_members(archive.getmembers(), lambda i: i.name)
            selected = [m for m, name in members if name == expected]
            if len(selected) != 1 or not selected[0].isfile():
                raise ValueError("expected regular version-root executable is missing or ambiguous")
            member = selected[0]
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("selected executable cannot be read")
            with source:
                copy_bounded(source, target, member.size)
    else:
        raise ValueError("unknown fixed-catalog archive format")
    return target


def validate_official_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in OFFICIAL_HOSTS
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("test download must use the fixed official HTTPS source")


class OfficialRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        validate_official_url(new_url)
        return super().redirect_request(request, fp, code, message, headers, new_url)


def download(package, path):
    validate_official_url(package["url"])
    request = urllib.request.Request(package["url"], headers={"User-Agent": "verysync-sidecar-test-setup/0.1"})
    deadline = time.monotonic() + 120
    count = 0
    opener = urllib.request.build_opener(OfficialRedirect())
    with opener.open(request, timeout=30) as response, path.open("xb") as output:
        for chunk in iter(lambda: response.read(64 * 1024), b""):
            count += len(chunk)
            if count > package["bytes"] or time.monotonic() > deadline:
                raise ValueError("official test archive exceeded its size or time limit")
            output.write(chunk)


def prepare(args):
    manifest_path = Path(__file__).resolve().parents[1] / "releases" / "verysync-v2.33.2.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["version"] != "v2.33.2":
        raise ValueError("test setup is pinned to v2.33.2")
    packages = [p for p in manifest["packages"] if p["id"] == args.package]
    if len(packages) != 1 or not packages[0]["alpha_target"]:
        raise ValueError("this fixture setup currently covers the six alpha package mappings only")
    package = packages[0]
    root = "-".join(["verysync", package["os"], package["upstream_arch"], manifest["version"]])
    parent = Path(args.parent).resolve(strict=True)
    if not parent.is_dir():
        raise ValueError("explicit test parent must be a directory")
    # A fresh task-owned directory is the only destination ever written here.
    directory = Path(tempfile.mkdtemp(prefix="verysync-test-engine-", dir=parent))
    directory.chmod(0o700)
    try:
        archive = Path(args.archive).resolve(strict=True) if args.archive else directory / package["filename"]
        if not args.archive:
            download(package, archive)
        if archive.stat().st_size != package["bytes"] or sha256(archive) != package["sha256"]:
            raise ValueError("official archive size/SHA-256 mismatch; nothing will be executed")
        binary = extract_executable(archive, directory, root, package["executable_name"], package["archive_format"])
        binary_hash = sha256(binary)
        receipt = {"package": package["id"], "version": manifest["version"],
                   "url": package["url"], "archive_sha256": package["sha256"],
                   "binary": str(binary), "binary_sha256": binary_hash}
        (directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        if args.github_env:
            if any(c in str(binary) for c in "\r\n"):
                raise ValueError("test executable path cannot be represented in an environment file")
            with Path(args.github_env).open("a", encoding="utf-8", newline="\n") as output:
                output.write("VERYSYNC_TEST_BINARY=" + str(binary) + "\n")
                output.write("VERYSYNC_TEST_BINARY_SHA256=" + binary_hash + "\n")
        print(json.dumps(receipt))
    except BaseException:
        shutil.rmtree(directory)
        raise


def check_cleanup():
    binary = os.environ.get("VERYSYNC_TEST_BINARY")
    if not binary or not Path(binary).is_absolute():
        raise ValueError("explicit test executable is required for cleanup verification")
    if os.name == "nt":
        # The path is data in an environment variable, never interpolated into code.
        code = "$p=$env:VERYSYNC_TEST_BINARY; @(Get-CimInstance Win32_Process | Where-Object {$_.ExecutablePath -eq $p}).Count"
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", code],
                                check=True, capture_output=True, text=True, timeout=20)
        count = int(result.stdout.strip())
        if count:
            raise RuntimeError("task-owned test engine processes remain: " + str(count))
    else:
        result = subprocess.run(["pgrep", "-f", "^" + re.escape(binary) + "( |$)"],
                                capture_output=True, text=True, timeout=10)
        if result.returncode not in (0, 1):
            raise RuntimeError("cannot verify exact test-process ownership")
        if result.returncode == 0:
            raise RuntimeError("task-owned test engine processes remain")
    print("No process remains for the exact task-owned test executable.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--package", required=True)
    prepare_parser.add_argument("--parent", required=True)
    prepare_parser.add_argument("--archive", help="Optional existing archive; same fixed SHA-256 required")
    prepare_parser.add_argument("--github-env", help="Explicit GitHub environment file to append to")
    commands.add_parser("check-cleanup")
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args)
    else:
        check_cleanup()


if __name__ == "__main__":
    main()
