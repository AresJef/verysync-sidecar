"""Start the reviewed R33 application as the original user inside a temporary group."""

import hashlib
import os
from pathlib import Path
import re
import stat
import sys
from zipfile import ZipFile


MODULE = re.compile(r"r33_[a-z_]{2,40}\.py\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
DRIVER = "bin/verysync-r33-operator"
ENGINE = "engine.zip"
SCOPE = "foreground-scope.txt"
PYTHON = ["/usr/bin/python3","-E","-s","-B"]


def extract(bundle, app):
    with ZipFile(bundle) as archive:
        entries = archive.infolist()
        names = {entry.filename for entry in entries}
        if len(names)!=len(entries) or len(names)>32 or not {DRIVER,ENGINE,SCOPE,"SHA256SUMS"}<=names:
            raise ValueError("The private bundle inventory did not verify.")
        manifest = archive.read("SHA256SUMS").decode("ascii").splitlines()
        checks = {}
        for row in manifest:
            digest, name = row.split("  ",1)
            if name in checks or not SHA256.fullmatch(digest):
                raise ValueError("The bundle manifest is incomplete.")
            checks[name] = digest
        if names-{"SHA256SUMS"}!=set(checks) or any(
            name not in {DRIVER,ENGINE,SCOPE} and not MODULE.fullmatch(name) for name in checks
        ):
            raise ValueError("The bundle contains an unexpected member.")
        if not {"r33_prepare.py","r33_handoff.py","r33_isolation.py"} <= checks.keys():
            raise ValueError("The foreground tool is incomplete.")
        app.mkdir()
        (app/"bin").mkdir()
        for member, digest in checks.items():
            info = archive.getinfo(member)
            if info.file_size > 80*1024**2 or info.is_dir() or not stat.S_ISREG(info.external_attr>>16):
                raise ValueError("The foreground bundle contains an invalid file.")
            hasher = hashlib.sha256()
            with archive.open(info) as source, (app/member).open("xb") as out:
                for block in iter(lambda:source.read(64*1024),b""):
                    hasher.update(block)
                    out.write(block)
            if hasher.hexdigest()!=digest:
                raise ValueError("A private program checksum did not verify.")
    return checks[DRIVER]


def verified_environment(owner):
    base = owner.parent.lstat()
    info = owner.lstat()
    gid, uid = os.getegid(), os.geteuid()
    if (base.st_uid!=0 or stat.S_IMODE(base.st_mode)!=0o710 or base.st_gid!=gid
            or uid==0 or info.st_uid!=uid or info.st_gid!=gid
            or stat.S_IMODE(info.st_mode)!=0o700):
        raise ValueError("The temporary current-login permission group is not active.")
    if not all(os.isatty(fd) for fd in (0,2)) or os.ttyname(0)!=os.ttyname(2):
        raise ValueError("Use the current foreground Terminal.")
    for fd in (0,2):
        tty = os.fstat(fd)
        if not stat.S_ISCHR(tty.st_mode) or tty.st_uid!=0 or tty.st_gid!=gid or tty.st_mode & 0o177:
            raise ValueError("The operator terminal was not isolated.")
    return uid


def call(owner, mode, value, exchange=None, digest=None):
    uid = verified_environment(owner)
    app = owner/"kit"
    if mode=="recover":
        if not re.fullmatch(r"[0-9a-f]{32}",value):
            raise ValueError("The original local native run is invalid.")
        command = [str(app/"r33_handoff.py"),"recover","--target","pro","--run",value,
                   "--profile",str(app/"operator-profile.json"),"--group-private",str(owner),"--unified"]
    else:
        if (mode not in {"check","start"} or exchange is None or digest is None
                or not value.isascii() or not value.isdigit() or not SHA256.fullmatch(digest)):
            raise ValueError("The active window was not verified.")
        driver = extract(owner/"kit.zip",app)
        command = [str(app/"r33_prepare.py"),"--group-private",str(owner),
                   "--executor-uid",str(uid),"--expires-at",value,"--exchange",exchange,"--bundle-sha256",digest,
                   "--engine-archive",str(app/ENGINE),"--driver-sha256",driver]
        if mode=="check":
            command += ["--prepare-only"]
    # Replace this bootstrap so the operator's terminal signal reaches the
    # foreground app directly. The root supervisor only handles restoration.
    os.execv(PYTHON[0],PYTHON+command)


if __name__=="__main__":
    try:
        if len(sys.argv) not in (4,6):
            raise ValueError("The local launcher received unexpected arguments.")
        call(Path(sys.argv[1]),*sys.argv[2:])
    except (OSError,ValueError,KeyboardInterrupt):
        print("The verified process group could not start the private tool.",file=sys.stderr)
        sys.exit(2)
