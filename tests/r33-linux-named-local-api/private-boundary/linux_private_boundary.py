"""Set up the owned Linux worker's network and volatile state."""

import os
from pathlib import Path
import socket
import stat
import subprocess


def namespace(kind):
    return os.stat(f"/proc/self/ns/{kind}").st_ino


def launch_arguments(argv):
    return ["/usr/bin/unshare", "--net", "--mount", "--propagation", "private", "--", *argv]


def open_boundary(state: Path, uid, gid, outer_network, outer_mount):
    if os.getresuid() != (0, 0, 0) or uid <= 0 or gid <= 0:
        raise PermissionError("The owned worker needs an ordinary runtime identity.")
    net, mount = namespace("net"), namespace("mnt")
    if net == outer_network or mount == outer_mount:
        raise PermissionError("Network and state visibility must both be private.")
    entry = state.lstat()
    if not stat.S_ISDIR(entry.st_mode) or entry.st_uid != 0 or list(state.iterdir()):
        raise ValueError("Use the new owned staging directory.")
    subprocess.run(["/usr/sbin/ip", "link", "set", "lo", "up"], timeout=5, check=True)
    if {name for _, name in socket.if_nameindex()} != {"lo"}:
        raise PermissionError("The owned network has unexpected interfaces.")
    subprocess.run(
        ["/usr/bin/mount", "-t", "tmpfs", "-o", f"size=64m,nosuid,nodev,noexec,mode=0700,uid={uid},gid={gid}",
         "r33-private-state", str(state)], timeout=5, check=True,
    )
    top = state.stat()
    if (top.st_uid, top.st_gid) != (uid, gid) or top.st_dev == entry.st_dev or top.st_mode & 0o077:
        raise PermissionError("The owned state mount is unavailable.")
    return {"network_namespace":net, "mount_namespace":mount,
            "volatile_private_state":True, "only_loopback":True}


def relinquish_admin(uid, gid):
    if uid <= 0 or gid <= 0:
        raise PermissionError("The test UID and GID must be ordinary.")
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    if os.getresuid() != (uid,) * 3 or os.getresgid() != (gid,) * 3 or os.getgroups():
        raise PermissionError("The worker retained administrator access.")
