"""Prepare an operator-owned program copy and run the no-secret proof."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from zipfile import ZipFile

from r33_isolation import require_private_terminal
from r33_cases import TWO_CORE_SCOPES
from r33_group_boundary import GroupBoundary
from r33_single import linux_destination, remaining_seconds, update_profile


ENGINE_ARCHIVE = "7921321d2df082a03647388cd50e30f187d37f7af4439246797118f4f05478f4"
ENGINE_BINARY = "f8e9bd67be3fb1b45eafea794008c4dfae24aec4e177617578b268598bf12274"
ENGINE_MEMBER = "verysync-macos-arm64-v2.33.2/verysync"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
BUNDLE = Path(__file__).resolve().parent
DRIVER = "bin/verysync-r33-operator"


def hash_file(path):
    hasher=hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda:stream.read(256*1024),b""):
            hasher.update(data)
    return hasher.hexdigest()


def private_executable(path):
    info=path.lstat()
    if path.resolve()!=path or info.st_uid!=os.getuid() or not stat.S_ISREG(info.st_mode):
        raise ValueError("Use the operator-owned program files.")
    path.chmod(0o700)


def extract_engine(archive, executable):
    if hash_file(archive)!=ENGINE_ARCHIVE:
        raise ValueError("The fixed official archive does not match its expected digest.")
    with ZipFile(archive) as source:
        info=source.getinfo(ENGINE_MEMBER)
        if info.file_size!=46731408:
            raise ValueError("The fixed official executable has an unexpected length.")
        with source.open(info) as member, executable.open("xb") as target:
            shutil.copyfileobj(member,target)
    if hash_file(executable)!=ENGINE_BINARY:
        raise ValueError("The fixed official executable does not match its expected digest.")
    private_executable(executable)


def prepare(executor, archive, driver_digest, boundary=None):
    if not SHA256.fullmatch(driver_digest):
        raise ValueError("Supply the fixed operator driver digest.")
    if sys.platform!="darwin" or os.uname().machine!="arm64":
        raise ValueError("Use the Apple Silicon operator Mac for this account handoff.")
    if os.getuid()==0 or executor<1 or ((executor==os.getuid()) != (boundary is not None)):
        raise ValueError("Start the verified current-login or separate-account isolation first.")
    if boundary and BUNDLE.parent!=boundary.private:
        raise ValueError("Use this private folder for the current-login Mac account check.")
    if BUNDLE.stat().st_uid!=os.getuid() or BUNDLE.stat().st_mode & 0o077:
        raise ValueError("Extract the kit into your own private folder.")
    driver=BUNDLE/DRIVER
    private_executable(driver)
    if driver_digest!=hash_file(driver):
        raise ValueError("The operator driver does not match the verified digest.")
    fixed=BUNDLE/"official-v2.33.2"
    extract_engine(archive,fixed)
    storage = (boundary.private/"v" if boundary else
               Path(tempfile.mkdtemp(prefix="r33-vault-",dir="/private/tmp")).resolve())
    if boundary:
        storage.mkdir()
    profile=BUNDLE/"operator-profile.json"
    selected=(BUNDLE/"foreground-scope.txt").read_text(encoding="ascii").strip()
    if selected not in TWO_CORE_SCOPES:
        raise ValueError("Use a verified audit, selective-sync, or named Pro acceptance package.")
    options={
        "pro":{
            "allow":["observe","refresh-paid",*TWO_CORE_SCOPES[selected]],
            "connection":{"engine":str(fixed),"driver":str(driver),
                          "driver_sha256":driver_digest,"recovery":str(storage),
                          "two_core_scope":selected},
        },
    }
    with profile.open("x",encoding="ascii") as output:
        json.dump(options,output,indent=2)
        output.write("\n")
    return profile


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executor-uid",type=int,required=True)
    parser.add_argument("--engine-archive",type=Path,required=True)
    parser.add_argument("--driver-sha256",required=True)
    parser.add_argument("--prepare-only",action="store_true")
    expiry = parser.add_mutually_exclusive_group(required=True)
    expiry.add_argument("--minutes",type=int)
    expiry.add_argument("--expires-at",type=int)
    parser.add_argument("--exchange",type=Path)
    parser.add_argument("--bundle-sha256")
    parser.add_argument("--group-private",type=Path)
    args=parser.parse_args()
    os.umask(0o077)
    boundary=GroupBoundary.current(args.group_private) if args.group_private else None
    require_private_terminal(boundary)
    if args.minutes is not None and not 1 <= args.minutes <= 2880:
        raise ValueError("Choose a foreground lifetime within the approved stage.")
    if args.expires_at is not None:
        remaining_seconds(args.expires_at)
        if not boundary or not args.exchange or not args.bundle_sha256 or not SHA256.fullmatch(args.bundle_sha256):
            raise ValueError("The single-window bundle has no verified notification path or digest.")
    work=prepare(args.executor_uid,args.engine_archive,args.driver_sha256,boundary)
    if args.prepare_only:
        print("R33_PREPARED "+json.dumps({"profile":str(work)}),flush=True)
        return 0
    proof=BUNDLE/"isolation.json"
    log=BUNDLE/"operator-receipt.jsonl"
    base=["/usr/bin/python3","-E","-s","-B"]
    uid=str(args.executor_uid)
    mode=["--group-private",str(boundary.private)] if boundary else []
    check = base+[str(BUNDLE/"r33_isolation.py"),"operator","--executor-uid",uid,
                  "--record",str(proof)]+mode
    handoff = base+[str(BUNDLE/"r33_handoff.py"),"start","--executor-uid",uid,
                    "--isolation-record",str(proof),"--profile",str(work),"--evidence",str(log)]+mode
    if args.expires_at is not None:
        from r33_rendezvous import exchange_path
        exchange_path(args.exchange)
        run = secrets.token_hex(16)
        binding = ["--run",run,"--exchange",str(args.exchange)]
        check += binding
        handoff += binding+["--expires-at",str(args.expires_at),"--bundle-sha256",args.bundle_sha256]
    else:
        handoff += ["--minutes",str(args.minutes)]
    subprocess.run(check,check=True)
    if args.expires_at is not None:
        remaining_seconds(args.expires_at)
        update_profile(work, linux_destination())
    print("The synthetic isolation check passed. Enter private credentials only when prompted here.",flush=True)
    os.execv(base[0], handoff)


if __name__=="__main__":
    try:
        raise SystemExit(main())
    except (OSError,ValueError,EOFError,KeyboardInterrupt,subprocess.CalledProcessError):
        print("The private toolkit could not complete setup. Review this terminal before granting access.",
              file=sys.stderr)
        raise SystemExit(2)
