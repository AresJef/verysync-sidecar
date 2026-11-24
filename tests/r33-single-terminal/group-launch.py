"""Create a temporary macOS access group and start one fixed foreground R33 app."""

import argparse
from contextlib import contextmanager
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import secrets
import shutil
import signal
import stat
import sys
import tempfile
import time


TMP = Path("/private/tmp")
TTY = re.compile(r"/dev/ttys[0-9]+\Z")
DIRECTORY = re.compile(r"r33-session-[a-z0-9_]{8}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
UID = re.compile(r"[1-9][0-9]{0,8}\Z")
RUN = re.compile(r"[0-9a-f]{32}\Z")
MAX_BUNDLE = 80 * 1024**2
END_OF_STAGE = 1795663346


def account():
    uid_text = os.environ.get("SUDO_UID", "")
    if sys.platform != "darwin" or os.geteuid()!=0 or not UID.fullmatch(uid_text):
        raise ValueError("Start the one-time Mac authorization from your own Terminal.")
    return pwd.getpwuid(int(uid_text))


def next_group():
    for _ in range(60):
        gid = 280000 + secrets.randbelow(90000)
        try:
            grp.getgrgid(gid)
        except KeyError:
            return gid
    raise ValueError("The system could not reserve a temporary permission group.")


@contextmanager
def private_terminal(uid, gid):
    """Protect just the current terminal device and restore each original mode."""
    if not os.isatty(0) or not os.isatty(2) or os.ttyname(0)!=os.ttyname(2):
        raise ValueError("Open a dedicated Terminal tab first.")
    own = os.ttyname(0)
    origin = os.environ.get("SUDO_TTY", own)
    if not TTY.fullmatch(own) or not TTY.fullmatch(origin):
        raise ValueError("Use the local Mac Terminal rather than an SSH pipe.")
    handles = []
    try:
        for path in dict.fromkeys((own, origin)):
            fd = (os.dup(0) if path==own else
                  os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NOFOLLOW | os.O_NONBLOCK))
            attrs = os.fstat(fd)
            if not stat.S_ISCHR(attrs.st_mode) or attrs.st_uid not in {uid, 0}:
                os.close(fd)
                raise ValueError("The terminal does not belong to this invocation.")
            handles.append((fd,attrs))
        if os.fstat(0).st_ino!=handles[0][1].st_ino:
            raise ValueError("The controlling terminal changed.")
        for fd, _ in handles:
            # Removing access precedes the owner transition. The current
            # Terminal and sudo already hold their file descriptors.
            os.fchmod(fd, 0)
            os.fchown(fd, 0, gid)
            os.fchmod(fd, 0o600)
        yield
    finally:
        failed = None
        for fd, attrs in reversed(handles):
            try:
                os.fchown(fd, attrs.st_uid, attrs.st_gid)
                os.fchmod(fd, stat.S_IMODE(attrs.st_mode))
            except OSError as error:
                failed = error
            finally:
                os.close(fd)
        if failed is not None:
            raise failed


def verified_program(source, destination, digest, uid, gid):
    if not HEX.fullmatch(digest):
        raise ValueError("The program checksum is missing.")
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or not 0<metadata.st_size<=MAX_BUNDLE:
            raise ValueError("Use the reviewed local program bundle.")
        content = stream.read(MAX_BUNDLE+1)
    if hashlib.sha256(content).hexdigest()!=digest:
        raise ValueError("The inspected program bundle has a different checksum.")
    with destination.open("xb") as target:
        target.write(content)
        os.fchown(target.fileno(), uid, gid)


def new_session(uid, bundle, digest):
    base = Path(tempfile.mkdtemp(prefix="r33-session-", dir=TMP))
    try:
        gid = next_group()
        owner = base/"owner"
        owner.mkdir()
        verified_program(bundle,owner/"kit.zip",digest,uid,gid)
        with (base/"owner.json").open("x") as handle:
            json.dump({"uid":uid,"gid":gid,"kit_sha256":digest},handle)
        os.chown(base,0,gid)
        os.chown(owner,uid,gid)
        base.chmod(0o710)
        return base,gid
    except BaseException:
        shutil.rmtree(base)
        raise


def existing_session(base, uid, digest):
    info = base.lstat()
    if (base.parent!=TMP or not DIRECTORY.fullmatch(base.name) or base.resolve()!=base
            or not stat.S_ISDIR(info.st_mode) or info.st_uid!=0
            or stat.S_IMODE(info.st_mode)!=0o710):
        raise ValueError("Use the recovery directory printed by the original handoff.")
    record = base/"owner.json"
    info_record = record.lstat()
    if info_record.st_uid!=0 or not stat.S_ISREG(info_record.st_mode) or info_record.st_mode & 0o077:
        raise ValueError("The original local authority record is unavailable.")
    detail = json.loads(record.read_text())
    if detail!={"uid":uid,"gid":info.st_gid,"kit_sha256":digest}:
        raise ValueError("This local account or program has changed since the handoff.")
    owner = base/"owner"
    info_owner = owner.lstat()
    if (not stat.S_ISDIR(info_owner.st_mode) or info_owner.st_uid!=uid or info_owner.st_gid!=info.st_gid
            or stat.S_IMODE(info_owner.st_mode)!=0o700):
        raise ValueError("The original isolated owner directory is unavailable.")
    return base, info.st_gid


def unfinished(base):
    private = base/"owner"/"v"
    if not private.exists():
        return []
    if not stat.S_ISDIR(private.lstat().st_mode):
        raise ValueError("The native recovery directory changed.")
    return [p.name for p in private.iterdir() if RUN.fullmatch(p.name) and stat.S_ISDIR(p.lstat().st_mode)
            and (p/"login-submitted").is_file() and not (p/"native-signed-out").is_file()]


def verified_child(account, owner, gid, bootstrap, digest, arguments):
    """Drop the user and group permanently before executing any app code."""
    child = os.fork()
    if child == 0:
        try:
            os.setgroups([gid])
            os.setgid(gid)
            os.setuid(account.pw_uid)
            if (os.getgid()!=gid or os.getegid()!=gid or os.geteuid()!=account.pw_uid
                    or os.getuid()!=account.pw_uid):
                os._exit(25)
            os.chdir(owner)
            inner = (
                "import hashlib,pathlib,sys;"
                "code=pathlib.Path(sys.argv.pop(1)).read_bytes();expected=sys.argv.pop(1);"
                "sys.argv[0]='r33-current-login';"
                "assert hashlib.sha256(code).hexdigest()==expected;"
                "exec(compile(code,'<verified unprivileged launcher>','exec'),{'__name__':'__main__'})"
            )
            environment = {"PATH":"/usr/bin:/bin", "LANG":"C", "R33_UID":str(account.pw_uid)}
            os.execve("/usr/bin/python3",["/usr/bin/python3","-I","-S","-B","-c",inner,
                                         str(bootstrap),digest,str(owner),*arguments],environment)
        except BaseException:
            os._exit(25)
    return child


@contextmanager
def owned_signals(child):
    def forward(signum, _frame):
        try:
            os.kill(child, signum)
        except ProcessLookupError:
            pass

    previous = {signum:signal.signal(signum,forward)
                for signum in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP)}
    try:
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum,handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--child", type=Path, required=True)
    parser.add_argument("--child-sha256",required=True)
    parser.add_argument("--recover", type=Path)
    parser.add_argument("--check-terminal-only",action="store_true")
    parser.add_argument("--exchange",type=Path,required=True)
    args = parser.parse_args()
    operator = account()
    exchange = args.exchange
    attrs = exchange.lstat()
    if (exchange.parent != TMP or exchange.resolve() != exchange
            or not re.fullmatch(r"r33-exchange-[a-z0-9_]{8}", exchange.name)
            or not stat.S_ISDIR(attrs.st_mode) or attrs.st_uid != operator.pw_uid or attrs.st_mode & 0o077):
        raise ValueError("Use the verified single-window notification directory.")
    if args.check_terminal_only and args.recover:
        raise ValueError("Use a fresh run for the no-secret terminal check.")
    if END_OF_STAGE <= time.time() and not args.recover:
        raise ValueError("The approved foreground window has expired.")
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    base,gid = (existing_session(args.recover,operator.pw_uid,args.bundle_sha256) if args.recover
                else new_session(operator.pw_uid,args.bundle,args.bundle_sha256))
    lock = os.open(base/"active",os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW,0o600)
    acquired = False
    try:
        fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
        acquired = True
        owner=base/"owner"
        if not args.recover:
            verified_program(args.child,owner/"worker.py",args.child_sha256,operator.pw_uid,gid)
        remaining = unfinished(base) if args.recover else []
        if args.recover and len(remaining)!=1:
            raise ValueError("There must be exactly one unresolved local native run.")
        work = (["recover",remaining[0]] if args.recover else
                ["check" if args.check_terminal_only else "start", str(END_OF_STAGE), str(exchange), args.bundle_sha256])
        with private_terminal(operator.pw_uid,gid):
            child = verified_child(operator,owner,gid,owner/"worker.py",args.child_sha256,work)
            with owned_signals(child):
                code = os.waitstatus_to_exitcode(os.waitpid(child,0)[1])
        return code if code>=0 else 128-code
    finally:
        if acquired:
            if unfinished(base):
                print("The local native sign-out still needs confirmation.",flush=True)
                print("R33_RECOVER_LOCAL "+str(base),flush=True)
            else:
                shutil.rmtree(base)
        os.close(lock)


if __name__=="__main__":
    try:
        sys.exit(main())
    except (OSError,ValueError,KeyboardInterrupt):
        print("The local permission setup did not finish. Check this Terminal before entering account information.",
              file=sys.stderr)
        sys.exit(2)
