"""Package the private current-login toolkit and record all shipped program digests."""

import hashlib
import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import tempfile
import stat
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile, ZipInfo

BASE=Path(__file__).resolve().parent
ENGINE="7921321d2df082a03647388cd50e30f187d37f7af4439246797118f4f05478f4"


def digest(path):
    hasher=hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda:file.read(128*1024),b""):
            hasher.update(block)
    return hasher.hexdigest()


def package(binary, engine, identity, scope):
    if digest(engine)!=ENGINE:
        raise ValueError("The official fixed program archive changed.")
    if scope != "pro-cases":
        raise ValueError("Choose a known foreground test scope.")
    storage=Path(tempfile.mkdtemp(prefix=f"r33-{scope}-kit.",dir="/private/tmp"))
    exchange = Path(tempfile.mkdtemp(prefix="r33-exchange-",dir="/private/tmp")).resolve()
    archive=storage/"r33.zip"
    checks={}
    modules=sorted((BASE/"runtime-next").glob("r33_*.py"))
    with ZipFile(archive,"x",compression=ZIP_DEFLATED,compresslevel=6) as file:
        for origin,member in [(m,m.name) for m in modules]+[(binary,"bin/verysync-r33-operator"),
                                                             (engine,"engine.zip")]:
            if origin.is_symlink() or not origin.is_file():
                raise ValueError("Select only the exact fixed local source files.")
            file.write(origin,member,compress_type=ZIP_STORED if origin==engine else ZIP_DEFLATED)
            checks[member]=digest(origin)
        scope_entry=ZipInfo("foreground-scope.txt")
        scope_entry.create_system=3
        scope_entry.external_attr=(stat.S_IFREG | 0o400) << 16
        scope_data=(scope+"\n").encode("ascii")
        file.writestr(scope_entry,scope_data)
        checks[scope_entry.filename]=hashlib.sha256(scope_data).hexdigest()
        file.writestr("SHA256SUMS","".join(f"{sha}  {member}\n" for member,sha in checks.items()))
    for name in ("group-launch.py","group-worker.py"):
        shutil.copyfile(BASE/name,storage/name)
    headline,body=digest(storage/"group-launch.py"),digest(storage/"group-worker.py")
    sealed=digest(archive)
    launcher=storage/"start-in-current-terminal.sh"
    commands=f"""#!/bin/bash
set -euo pipefail
umask 077
if ! test -t 0 || ! test -t 2; then
    echo 'Open a new Terminal tab with your current Mac login.' >&2
    exit 2
fi
if [ "$#" -gt 0 ] && ! {{ [ "$#" = 1 ] && [ "$1" = --check-terminal-only ]; }} \\
    && ! {{ [ "$#" = 2 ] && [ "$1" = --recover ]; }}; then
    echo 'Run the foreground command without arguments, or use the printed recovery command.' >&2
    exit 2
fi
r33_kit="$(cd -P -- "$(dirname -- "$0")" && pwd)"
echo 'macOS may ask for local administrator authorization to prepare this temporary test session.'
exec /usr/bin/sudo -k -- /usr/bin/python3 -I -S -B -c '
import hashlib,pathlib,sys
src=pathlib.Path(sys.argv.pop(1)).read_bytes()
expected=sys.argv.pop(1)
if hashlib.sha256(src).hexdigest()!=expected:
    raise SystemExit("The local launcher checksum did not verify.")
sys.argv[0]="r33-current-login"
exec(compile(src,"<verified local launcher>","exec"),{{"__name__":"__main__"}})
' "$r33_kit/group-launch.py" {shlex.quote(headline)} --bundle "$r33_kit/r33.zip" \\
    --bundle-sha256 {shlex.quote(sealed)} --child "$r33_kit/group-worker.py" \\
    --child-sha256 {shlex.quote(body)} --exchange {shlex.quote(str(exchange))} "$@"
"""
    launcher.write_text(commands)
    launcher.chmod(0o700)
    for member in storage.iterdir():
        if member!=launcher:
            member.chmod(0o400)
    response={"directory":str(storage),"exchange":str(exchange),"status":"single-terminal-candidate","scope":scope,
              "launcher":str(launcher),"launcher_sha256":digest(launcher),"archive_sha256":sealed,
              "root_loader_sha256":headline,"unprivileged_worker_sha256":body,"archive_members":checks}
    with identity.open("x") as report:
        report.write(json.dumps(response,indent=2)+"\n")
    print(json.dumps({key:response[key] for key in ("launcher","launcher_sha256","archive_sha256","status","exchange")}))


if __name__=="__main__":
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary",type=Path)
    parser.add_argument("engine",type=Path)
    parser.add_argument("identity",type=Path)
    parser.add_argument("--scope",choices=("audit","selective","pro-cases"),required=True)
    args=parser.parse_args()
    package(args.binary,args.engine,args.identity,args.scope)
