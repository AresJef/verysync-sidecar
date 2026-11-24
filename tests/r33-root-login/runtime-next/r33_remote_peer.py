"""Bootstrap the verified standby worker over the already authenticated SSH channel."""

import hashlib
import io
from pathlib import Path
import re
import shlex
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


MEMBERS = ("r33_protocol.py", "r33_linux_worker.py")
BOOTSTRAP = """
import hashlib, io, os, pathlib, pwd, re, runpy, signal, stat, struct, sys, tempfile, zipfile

def read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            raise EOFError("The verified peer payload ended early.")
        data.extend(chunk)
    return data

def interrupted(signum, _frame):
    raise SystemExit(128 + signum)

def directory(path, private=False):
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = path.lstat()
    if (path.resolve() != path or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & (0o077 if private else 0o022)):
        raise ValueError("The owned Linux workspace could not be verified.")
    return path

def drop_root(run, mode):
    if os.getresuid() != (0, 0, 0) or not re.fullmatch("[0-9a-f]{32}", run) or mode not in ("start", "recover"):
        raise ValueError("The root-authenticated bootstrap does not match the selected test run.")
    owner = pwd.getpwnam("nobody")
    uid, gid = owner.pw_uid, owner.pw_gid
    if uid == 0 or gid == 0:
        raise ValueError("The Linux test worker needs an unprivileged identity.")
    temporary = pathlib.Path("/tmp").resolve(strict=True)
    temp_info = temporary.stat()
    if temp_info.st_uid != 0 or not stat.S_ISDIR(temp_info.st_mode) or not temp_info.st_mode & stat.S_ISVTX:
        raise ValueError("The Linux temporary parent does not protect per-run directories.")
    home = temporary / ("r33-root-" + run)
    if mode == "start":
        home.mkdir(mode=0o700)
        try:
            os.chown(home, uid, gid, follow_symlinks=False)
        except OSError:
            home.rmdir()
            raise
    info = home.lstat()
    if not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid) != (uid, gid) or info.st_mode & 0o077:
        raise ValueError("The run directory has an unexpected identity.")
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    if os.getresuid() != (uid,)*3 or os.getresgid() != (gid,)*3 or os.getgroups():
        raise ValueError("The Linux test worker could not relinquish administrator access.")
    os.environ["HOME"] = str(home)
    os.environ["TMPDIR"] = str(home)
    return home

owned = state = None
expected = None
try:
    if not sys.platform.startswith("linux") or len(sys.argv) not in (2, 4):
        raise ValueError("Use the fixed Linux bootstrap.")
    os.umask(0o077)
    if len(sys.argv) == 4:
        run, mode = sys.argv[2:]
        owned = drop_root(run, mode)
        expected = (mode, run)
    elif os.getuid() == 0:
        raise ValueError("Root authentication needs the scoped foreground bootstrap.")
    for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    raw = sys.stdin.buffer.raw
    size, = struct.unpack("!I", read_exact(raw, 4))
    if not 0 < size <= 65536:
        raise ValueError("The verified peer payload size is invalid.")
    payload = read_exact(raw, size)
    if hashlib.sha256(payload).hexdigest() != sys.argv[1]:
        raise ValueError("The verified peer payload digest does not match.")
    if owned:
        state = directory(owned / "s", private=True)
    else:
        home = pathlib.Path.home()
        share = directory(directory(home / ".local") / "share")
        state = directory(directory(share / "verysync-r33", private=True) / "single", private=True)
    names = {"r33_protocol.py", "r33_linux_worker.py"}
    with tempfile.TemporaryDirectory(prefix="r33-peer-") as raw_root, zipfile.ZipFile(io.BytesIO(payload)) as archive:
        root = pathlib.Path(raw_root)
        if set(archive.namelist()) != names or len(archive.namelist()) != len(names):
            raise ValueError("The verified peer payload inventory does not match.")
        for name in names:
            member = archive.getinfo(name)
            if not 0 < member.file_size <= 65536:
                raise ValueError("The verified peer member size is invalid.")
            with (root / name).open("xb") as output:
                output.write(archive.read(member))
        sys.path.insert(0, str(root))
        work = runpy.run_path(str(root / "r33_linux_worker.py"))
        work["transport"](state, expected=expected)
except (OSError, ValueError, EOFError, KeyError):
    print("The verified standby peer could not start.", file=sys.stderr)
    raise SystemExit(2)
finally:
    if owned:
        try:
            if state:
                state.rmdir()
            owned.rmdir()
        except OSError:
            # A lost transport may leave its named lease and evidence intact.
            pass
""".strip()


def bundle(directory: Path, *, root_run=None, recover=False):
    stream = io.BytesIO()
    with ZipFile(stream, "w", compression=ZIP_DEFLATED, compresslevel=6) as archive:
        for name in MEMBERS:
            info = ZipInfo(name)
            info.compress_type = ZIP_DEFLATED
            archive.writestr(info, (directory / name).read_bytes())
    content = stream.getvalue()
    if not 0 < len(content) <= 65536:
        raise ValueError("The verified standby payload exceeds its limit.")
    digest = hashlib.sha256(content).hexdigest()
    command = ('exec /usr/bin/env -i HOME="$HOME" PATH=/usr/bin:/bin '
               '/usr/bin/python3 -I -S -B -c ' + shlex.quote(BOOTSTRAP) + " " + digest)
    if root_run is not None:
        if type(root_run) is not str or not re.fullmatch(r"[0-9a-f]{32}", root_run):
            raise ValueError("Bind the root login to one run identifier.")
        command += " " + root_run + (" recover" if recover else " start")
    return command, digest, len(content).to_bytes(4, "big") + content
