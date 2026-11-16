#!/usr/bin/env python3
"""Provision one small, owned CI filesystem for a real native ENOSPC case.

This is an explicit GitHub-hosted test operation, never a build hook. No physical
disk is selected, and cleanup verifies the exact mount/image before detaching.
"""
import argparse
import json
import os
from pathlib import Path
import plistlib
import secrets
import shutil
import subprocess
import sys


def require_ci(parent, evidence):
    expected = {"linux": "Linux", "darwin": "macOS", "win32": "Windows"}.get(sys.platform)
    if not expected or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != expected:
        raise ValueError("bounded filesystem provisioning requires the matching explicit GitHub CI host")
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if not parent.is_absolute() or parent.resolve(strict=True) != runner:
        raise ValueError("parent must be the exact current RUNNER_TEMP directory")
    if not evidence.is_absolute() or evidence.parent.resolve(strict=True) != runner or evidence.exists():
        raise ValueError("evidence must be a fresh direct child of RUNNER_TEMP")


class OwnedVolume:
    def __init__(self, parent, evidence):
        require_ci(parent, evidence)
        evidence.mkdir(mode=0o700)
        self.nonce = secrets.token_hex(32)
        self.root = parent / ("vs-bounded-" + self.nonce)
        self.root.mkdir(mode=0o700)
        self.mount = self.root / "volume"
        self.mount.mkdir()
        self.evidence = evidence
        self.image = self.root / ("owned.vhd" if sys.platform == "win32" else "owned.dmg")
        self.source = "verysync-owned-" + self.nonce
        self.device = None
        self.cleanup_verified = False

    def command(self, argv):
        result = subprocess.run(argv, capture_output=True, check=False)
        with (self.evidence / "filesystem-commands.log").open("ab") as log:
            log.write((json.dumps(argv) + "\n").encode())
            log.write(result.stdout + result.stderr + b"\n")
        result.check_returncode()
        return result.stdout

    def linux_mount(self):
        matches = []
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            left, right = line.split(" - ", 1)
            fields, filesystem = left.split(), right.split()
            path = fields[4]
            for old, new in [("\\040", " "), ("\\011", "\t"), ("\\134", "\\")]:
                path = path.replace(old, new)
            if Path(path) == self.mount:
                matches.append((filesystem[0], filesystem[1]))
        if not matches:
            return False
        if matches != [("tmpfs", self.source)]:
            raise RuntimeError("mount ownership differs; refuse cleanup")
        return True

    def mac_image(self):
        info = plistlib.loads(self.command(["/usr/bin/hdiutil", "info", "-plist"]))
        images = [x for x in info.get("images", []) if Path(x.get("image-path", "")) == self.image]
        if not images:
            return False
        if len(images) != 1:
            raise RuntimeError("ambiguous owned image identity")
        entities = images[0].get("system-entities", [])
        if not any(x.get("mount-point") == str(self.mount) for x in entities):
            # A partially attached image is still detachable by its exact image
            # relation. Never infer a disk number from host inventory ordering.
            if any(x.get("mount-point") for x in entities):
                raise RuntimeError("owned image mounted at an unexpected location")
        devices = [x["dev-entry"] for x in entities if x.get("dev-entry")]
        if not devices or any(not x.startswith("/dev/disk") for x in devices):
            raise RuntimeError("missing exact owned image device relation")
        self.device = devices[0]
        return True

    def diskpart(self, name, lines):
        # DiskPart has its own quoted-string grammar; reject control characters
        # instead of treating JSON encoding as command-language escaping.
        for path in (self.image, self.mount):
            if any(c in str(path) for c in '\r\n"'):
                raise ValueError("unsupported DiskPart path syntax")
        script = self.root / (name + ".txt")
        script.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return self.command([str(Path(os.environ["SystemRoot"]) / "System32" / "diskpart.exe"), "/s", str(script)])

    def windows_image(self):
        # Exact ImagePath is a data argument, not interpolated PowerShell code.
        env = os.environ.copy()
        env["VERYSYNC_OWNED_VHD_QUERY"] = str(self.image)
        result = subprocess.run([
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference='Stop'; Get-DiskImage -ImagePath $env:VERYSYNC_OWNED_VHD_QUERY | "
            "Select-Object ImagePath,Attached | ConvertTo-Json -Compress",
        ], env=env, capture_output=True, text=True, check=True)
        info = json.loads(result.stdout)
        if Path(info["ImagePath"]).resolve() != self.image.resolve():
            raise RuntimeError("queried image identity differs")
        return info["Attached"] is True

    def attach(self):
        if sys.platform == "linux":
            self.command(["sudo", "-n", "mount", "-t", "tmpfs", "-o",
                          f"size=8m,mode=0700,nodev,nosuid,noexec,uid={os.getuid()},gid={os.getgid()}",
                          self.source, str(self.mount)])
            if not self.linux_mount():
                raise RuntimeError("owned tmpfs did not attach")
        elif sys.platform == "darwin":
            self.command(["/usr/bin/hdiutil", "create", "-size", "16m", "-fs", "HFS+",
                          "-layout", "NONE", "-nospotlight", "-volname", "VerySyncOwned",
                          "-format", "UDRW", str(self.image)])
            self.command(["/usr/bin/hdiutil", "attach", "-nobrowse", "-owners", "off", "-plist",
                          "-mountpoint", str(self.mount), str(self.image)])
            if not self.mac_image():
                raise RuntimeError("owned disk image did not attach")
        else:
            self.diskpart("attach", [f'create vdisk file="{self.image}" maximum=32 type=expandable',
                                    f'select vdisk file="{self.image}"', "attach vdisk",
                                    "create partition primary", "format fs=ntfs quick label=VerySyncOwned",
                                    f'assign mount="{self.mount}"'])
            if not self.windows_image():
                raise RuntimeError("owned VHD did not attach")
        usage = shutil.disk_usage(self.mount)
        if not 4 * 1024**2 <= usage.total <= 40 * 1024**2 or usage.free < 2 * 1024**2:
            raise RuntimeError("actual capacity is not bounded; refuse payload creation")
        (self.mount / "owned-volume.txt").write_text(self.nonce, encoding="ascii")
        return {"capacity_bytes": usage.total, "free_bytes": usage.free,
                "mount": str(self.mount), "image": str(self.image) if self.image.exists() else None}

    def cleanup(self):
        if sys.platform == "linux":
            if self.linux_mount():
                self.command(["sudo", "-n", "umount", str(self.mount)])
            if self.linux_mount():
                raise RuntimeError("owned tmpfs is still mounted")
        elif sys.platform == "darwin":
            if self.mac_image():
                self.command(["/usr/bin/hdiutil", "detach", self.device])
            if self.mac_image():
                raise RuntimeError("owned disk image is still attached")
        elif self.image.exists():
            if self.windows_image():
                self.diskpart("detach", [f'select vdisk file="{self.image}"', "detach vdisk"])
            if self.windows_image():
                raise RuntimeError("owned VHD is still attached")
        # No recursive deletion across a mount point. Failure leaves evidence
        # and the owned image for diagnosis instead of touching another volume.
        if self.mount.exists():
            self.mount.rmdir()
        for child in self.root.iterdir():
            if child not in {self.image, self.root / "attach.txt", self.root / "detach.txt"} or child.is_symlink():
                raise RuntimeError("unexpected fixture child; refuse deletion")
            child.unlink()
        self.root.rmdir()
        self.cleanup_verified = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--toolchain", required=True)
    args = parser.parse_args()
    volume = OwnedVolume(args.parent, args.evidence_dir)
    report = {"actual_native_suite_exit": None, "cleanup_verified": False}
    try:
        report["filesystem"] = volume.attach()
        env = os.environ.copy()
        env["VERYSYNC_TEST_BOUNDED_FS"] = str(volume.mount)
        env["VERYSYNC_TEST_BOUNDED_FS_NONCE"] = volume.nonce
        command = [sys.executable, str(Path(__file__).with_name("run-isolated-engine-tests.py")),
                   "--cargo", str(Path(shutil.which("cargo")).absolute()),
                   "--toolchain", args.toolchain, "--test-target", "disk_full_engine",
                   "--evidence-dir", str(args.evidence_dir / "native")]
        result = subprocess.run(command, env=env, check=False)
        report["actual_native_suite_exit"] = result.returncode
        return result.returncode
    finally:
        try:
            volume.cleanup()
        finally:
            report["cleanup_verified"] = volume.cleanup_verified
            (args.evidence_dir / "bounded-filesystem-result.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(report))


if __name__ == "__main__":
    sys.exit(main())
