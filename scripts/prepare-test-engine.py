#!/usr/bin/env python3
"""Explicitly prepare a fixed official engine for isolated integration tests.

This helper is never invoked by Cargo. It copies only the executable from a
verified archive into a new private test directory; service samples stay inside
the archive. It does not launch the program or change host configuration.
"""
import argparse
import hashlib
import json
import ntpath
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
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
            if any(c in str(binary) + str(archive) for c in "\r\n"):
                raise ValueError("test executable path cannot be represented in an environment file")
            with Path(args.github_env).open("a", encoding="utf-8", newline="\n") as output:
                output.write("VERYSYNC_TEST_BINARY=" + str(binary) + "\n")
                output.write("VERYSYNC_TEST_BINARY_SHA256=" + binary_hash + "\n")
                output.write("VERYSYNC_TEST_ARCHIVE=" + str(archive) + "\n")
        print(json.dumps(receipt))
    except BaseException:
        shutil.rmtree(directory)
        raise


def windows_retained_process_image(kernel, process, transition_wait_ms=0):
    """Return an image or a proven native exit; inaccessible live state fails."""
    import ctypes
    from ctypes import wintypes
    image = ctypes.create_unicode_buffer(32768)
    size = wintypes.DWORD(len(image))
    if kernel.QueryFullProcessImageNameW(process, 0, image, ctypes.byref(size)):
        return image.value
    error = ctypes.get_last_error()
    wait = kernel.WaitForSingleObject(process, 0)
    if wait == 0:  # WAIT_OBJECT_0, exact handle
        return None
    # Image metadata can become inaccessible before the retained process object
    # signals exit. Only a real signal permits exclusion; timeout still fails.
    # The caller supplies at most 250 ms from its existing inventory deadline.
    if error == 5 and wait == 258 and 0 < transition_wait_ms <= 250:
        wait = kernel.WaitForSingleObject(process, transition_wait_ms)
        if wait == 0:
            return None
    failure = ctypes.WinError(error)
    failure.native_operation = "query_full_process_image"
    failure.native_wait = wait
    failure.native_transition_wait_ms = transition_wait_ms
    raise failure


def windows_processes_for_binary(binary):
    """Query native process image paths without WMI/provider startup or a shell."""
    import ctypes
    from ctypes import wintypes

    class ProcessEntry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_void_p),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    for name in ["Process32FirstW", "Process32NextW"]:
        function = getattr(kernel, name)
        function.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
        function.restype = wintypes.BOOL
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                                wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL

    snapshot = kernel.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
    if snapshot in (None, ctypes.c_void_p(-1).value):
        raise ctypes.WinError(ctypes.get_last_error())
    entry = ProcessEntry()
    entry.dwSize = ctypes.sizeof(entry)
    expected = ntpath.normcase(ntpath.normpath(binary))
    matches = []
    deadline = time.monotonic() + 10
    try:
        available = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        while available:
            if time.monotonic() > deadline:
                raise TimeoutError("native test-process inventory exceeded its deadline")
            if ntpath.normcase(entry.szExeFile) == ntpath.basename(expected):
                process = kernel.OpenProcess(0x101000, False, entry.th32ProcessID)  # QUERY_LIMITED_INFORMATION | SYNCHRONIZE
                if not process:
                    error = ctypes.get_last_error()
                    if error != 87:  # A process may already have exited.
                        failure = ctypes.WinError(error)
                        failure.native_operation = "open_process_for_image"
                        raise failure
                else:
                    try:
                        remaining_ms = max(0, min(250, int((deadline - time.monotonic()) * 1000)))
                        image = windows_retained_process_image(kernel, process, remaining_ms)
                        if image is not None and ntpath.normcase(ntpath.normpath(image)) == expected:
                            matches.append(entry.th32ProcessID)
                    finally:
                        kernel.CloseHandle(process)
            available = kernel.Process32NextW(snapshot, ctypes.byref(entry))
        if ctypes.get_last_error() != 18:  # ERROR_NO_MORE_FILES
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.CloseHandle(snapshot)
    return matches


def owned_processes(binary=None):
    """Read exact native image/argv ownership, including filesystem aliases."""
    binary = binary or os.environ.get("VERYSYNC_TEST_BINARY")
    if not binary or not Path(binary).is_absolute():
        raise ValueError("explicit absolute test executable is required for process verification")
    # Managed startup resolves the selected executable before spawning it. The
    # inventory must compare that same native path, not an alias spelling.
    binary = str(Path(binary).resolve())
    if os.name == "nt":
        return sorted(windows_processes_for_binary(binary))
    result = subprocess.run(["pgrep", "-f", "^" + re.escape(binary) + "( |$)"],
                            capture_output=True, text=True, timeout=10)
    if result.returncode not in (0, 1):
        raise RuntimeError("cannot verify exact test-process ownership")
    if result.returncode == 1:
        return []
    matches = sorted(int(pid) for pid in result.stdout.split())
    if not matches or len(matches) > 4096 or any(pid <= 0 for pid in matches):
        raise RuntimeError("exact test-process inventory was incomplete")
    return matches


def check_cleanup():
    matches = owned_processes()
    if matches:
        raise RuntimeError("task-owned test engine processes remain: " + str(len(matches)))
    print("No process remains for the exact task-owned test executable.")


def owned_tcp_listeners():
    """Observe IPv4 LISTEN sockets for exact task-owned images; never connect."""
    pids = owned_processes()
    if not pids:
        raise RuntimeError("no exact task-owned image is available for socket observation")
    listeners = []
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        import socket
        import struct
        class Row(ctypes.Structure):
            _fields_ = [(name, wintypes.DWORD) for name in
                        ("state", "local_address", "local_port", "remote_address", "remote_port", "pid")]
        api = ctypes.WinDLL("iphlpapi", use_last_error=True).GetExtendedTcpTable
        api.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
                        wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
        api.restype = wintypes.DWORD
        size = wintypes.DWORD(0)
        result = api(None, ctypes.byref(size), False, socket.AF_INET, 5, 0)
        if result not in (0, 122) or size.value > 16 * 1024 * 1024:
            raise RuntimeError("cannot size native owned TCP table")
        table = ctypes.create_string_buffer(max(size.value, 4))
        result = api(table, ctypes.byref(size), False, socket.AF_INET, 5, 0)
        if result != 0:
            raise RuntimeError("cannot read native owned TCP table")
        count = wintypes.DWORD.from_buffer_copy(table).value
        if 4 + count * ctypes.sizeof(Row) > len(table):
            raise RuntimeError("native TCP table is incomplete")
        for index in range(count):
            row = Row.from_buffer_copy(table, 4 + index * ctypes.sizeof(Row))
            if row.pid in pids and row.state == 2:
                listeners.append({"pid": row.pid, "address": socket.inet_ntoa(struct.pack("=I", row.local_address)),
                                  "port": socket.ntohs(row.local_port & 0xffff)})
    elif sys.platform == "darwin":
        result = subprocess.run(["/usr/sbin/lsof", "-nP", "-a", "-p", ",".join(map(str, pids)),
                                 "-i4TCP", "-sTCP:LISTEN", "-Fpn"], capture_output=True, text=True, timeout=10)
        if result.returncode != 0 and not (result.returncode == 1 and not result.stdout and not result.stderr):
            raise RuntimeError("cannot read exact owned TCP listeners")
        pid = None
        for line in result.stdout.splitlines():
            if line.startswith("p"):
                pid = int(line[1:])
            elif line.startswith("n") and pid in pids:
                address, port = line[1:].rsplit(":", 1)
                listeners.append({"pid": pid, "address": address, "port": int(port)})
    elif sys.platform.startswith("linux"):
        import socket
        import struct
        for pid in pids:
            descriptors = Path(f"/proc/{pid}/fd")
            inodes = set()
            for item in descriptors.iterdir():
                try:
                    target = os.readlink(item)
                except FileNotFoundError:
                    # A single descriptor can close during this passive snapshot.
                    # Permission and process-directory failures still propagate.
                    continue
                if target.startswith("socket:["):
                    inodes.add(target[8:-1])
            for line in Path(f"/proc/{pid}/net/tcp").read_text().splitlines()[1:]:
                fields = line.split()
                if fields[3] != "0A" or fields[9] not in inodes:
                    continue
                address, port = fields[1].split(":")
                listeners.append({"pid": pid, "address": socket.inet_ntoa(struct.pack("=I", int(address, 16))),
                                  "port": int(port, 16)})
    else:
        raise RuntimeError("native owned socket observation is unavailable")
    return {"pids": pids, "tcp_listeners": listeners, "scope": "exact owned images; passive IPv4 socket observation"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--package", required=True)
    prepare_parser.add_argument("--parent", required=True)
    prepare_parser.add_argument("--archive", help="Optional existing archive; same fixed SHA-256 required")
    prepare_parser.add_argument("--github-env", help="Explicit GitHub environment file to append to")
    commands.add_parser("check-cleanup")
    commands.add_parser("list-owned-processes")
    commands.add_parser("list-owned-listeners")
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args)
    elif args.command == "list-owned-listeners":
        print(json.dumps(owned_tcp_listeners()))
    elif args.command == "list-owned-processes":
        try:
            print(json.dumps({"pids": owned_processes()}))
        except OSError as error:
            # Diagnostic classification only: never print command arguments,
            # native paths, private state or exception payloads.
            print(json.dumps({"observation_error": type(error).__name__,
                              "winerror": getattr(error, "winerror", None),
                              "native_operation": getattr(error, "native_operation", None),
                              "native_wait": getattr(error, "native_wait", None),
                              "native_transition_wait_ms": getattr(error, "native_transition_wait_ms", None),
                              "errno": error.errno}))
            raise SystemExit(1) from None
    else:
        check_cleanup()


if __name__ == "__main__":
    main()
