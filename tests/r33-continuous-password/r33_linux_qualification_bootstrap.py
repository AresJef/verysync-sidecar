"""Load the exact private test programs inside the operator's SSH session."""

import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import select
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from zipfile import ZipFile


FILES = frozenset((
    "verysync-v2.33.2", "verysync-r33-operator", "run_local_api_scope.py",
    "linux_account_connector.py", "linux_private_boundary.py", "check_worker_boundary.py",
    "r33_protocol.py", "r33_official_proxy.py",
))
GATEWAY_FILES=frozenset((
    "verysync-v2.33.2","verysync-r33-operator","r33_gateway_target.py",
    "r33_wan_route.py","linux_private_boundary.py","r33_protocol.py",
))
MAX_TRANSFER = 104 * 1024 * 1024
ROLE_FILES = {"live": ("local-api", FILES), "native-target": ("gateway", GATEWAY_FILES)}


def receive(payload, expected):
    size = os.read(0, 1)
    while size and not size.endswith(b"\n") and len(size) <= 10:
        extra = os.read(0, 1)
        if not extra:
            raise ValueError("The prepared test payload ended early.")
        size += extra
    if not re.fullmatch(rb"[0-9]{1,9}\n",size) or not 0<int(size)<=MAX_TRANSFER:
        raise ValueError("The prepared test payload exceeds its allowed length.")
    remaining = int(size)
    actual = hashlib.sha256()
    with payload.open("xb") as out:
        while remaining:
            block = os.read(0,min(remaining,512*1024))
            if not block:
                raise ValueError("The prepared test payload ended early.")
            out.write(block)
            actual.update(block)
            remaining -= len(block)
    if actual.hexdigest()!=expected:
        raise ValueError("The prepared test payload does not match its checksum.")


def unpack(root, payload, roles, gid):
    os.chown(root,0,gid)
    root.chmod(0o710)
    inventory={}
    for mode, folder, files in roles:
        if folder:
            directory=root/folder
            directory.mkdir(mode=0o710)
            os.chown(directory,0,gid)
        for name in files:
            path=str(Path(folder)/name)
            executable=mode=="native-target" and name in ("verysync-v2.33.2","verysync-r33-operator")
            member=name if name=="verysync-v2.33.2" else path
            inventory.setdefault(member,[]).append((root/path,executable))
    with ZipFile(payload) as bundle:
        items=bundle.infolist()
        if len(items)!=len(inventory) or {item.filename for item in items}!=inventory.keys():
            raise ValueError("The staged test inventory does not match.")
        for fact in items:
            if fact.file_size>100*1024**2 or not stat.S_ISREG(fact.external_attr>>16):
                raise ValueError("The staged test program has an invalid file type.")
            for destination,executable in inventory[fact.filename]:
                with bundle.open(fact) as src, destination.open("xb") as out:
                    shutil.copyfileobj(src,out)
                os.chown(destination,0,gid)
                destination.chmod(0o550 if executable else 0o440)


def run_role(root, run, expires, mode):
    if mode=="native-target":
        command=["/usr/bin/python3","-B",str(root/"r33_gateway_target.py"),"serve",str(root),run,expires]
    else:
        command=["/usr/bin/python3","-B",str(root/"run_local_api_scope.py"),
                 "--engine",str(root/"verysync-v2.33.2"),"--driver",str(root/"verysync-r33-operator"),
                 "--run",run,"--expires",expires]
        if mode=="control":
            command.append("--synthetic")
    return own_process(command)


def own_process(command):
    child=subprocess.Popen(command)
    old={}
    interrupted=False
    def forward(_number,_frame):
        nonlocal interrupted
        interrupted=True
        if child.poll() is None:
            child.terminate()
    for number in (signal.SIGHUP,signal.SIGTERM,signal.SIGINT):
        old[number]=signal.signal(number,forward)
    try:
        result=child.wait()
    finally:
        for number,handler in old.items():
            signal.signal(number,handler)
    if interrupted:
        raise SystemExit(1)
    return result


def frame(value):
    return json.dumps(value,separators=(",",":")).encode("ascii")+b"\n"


def announce(value):
    sys.stdout.buffer.write(frame(value))
    sys.stdout.buffer.flush()


def idle_command(expires):
    # An active role owns stdin until its process exits. The caller waits for
    # the role-finished frame before sending the next broker-level request.
    line=bytearray()
    while len(line)<256:
        remaining=expires-time.time()
        if remaining<=0 or not select.select([0],[],[],remaining)[0]:
            return None
        value=os.read(0,1)
        if not value:
            return None
        line.extend(value)
        if value==b"\n":
            return bytes(line)
    raise ValueError("The standby command exceeds its allowed size.")


def serve_roles(root, run, expires, launch=run_role):
    cutoff=int(expires)
    close=frame({"kind":"close-foreground","run":run})
    pending={frame({"kind":"start-role","run":run,"role":role}): (role, folder)
             for role,(folder,_) in ROLE_FILES.items()}
    announce({"event":"linux-foreground-ready","run":run,"deadline":cutoff})
    while True:
        request=idle_command(cutoff)
        if request in (None,close) or time.time()>=cutoff:
            return 0
        if request not in pending:
            raise ValueError("The command is outside the selected Linux roles.")
        role,folder=pending.pop(request)
        code=launch(root/folder,run,expires,role)
        announce({"event":"linux-role-finished","run":run,"role":role,"exit_code":code})


def start(run, expires, expected, mode):
    if (os.getresuid()!=(0,0,0) or os.uname().machine!="x86_64"
            or not re.fullmatch(r"[a-f0-9]{32}",run) or not re.fullmatch(r"[a-f0-9]{64}",expected)
            or not 0<int(expires)-time.time()<=48*3600
            or mode not in ("live","control","native-target","combined")):
        raise ValueError("The selected Linux node or the test window does not match.")
    worker=pwd.getpwnam("nobody")
    if mode=="combined":
        roles=[(role,folder,files) for role,(folder,files) in ROLE_FILES.items()]
    else:
        roles=[(mode,"",GATEWAY_FILES if mode=="native-target" else FILES)]
    def revoke(_number,_frame):
        raise SystemExit(1)
    old={number:signal.signal(number,revoke) for number in (signal.SIGHUP,signal.SIGTERM,signal.SIGINT)}
    try:
        with tempfile.TemporaryDirectory(prefix="r33-la-staging-",dir="/tmp") as folder:
            root=Path(folder).resolve()
            payload=root/"test.zip"
            receive(payload,expected)
            unpack(root,payload,roles,worker.pw_gid)
            payload.unlink()
            result=serve_roles(root,run,expires) if mode=="combined" else run_role(root,run,expires,mode)
    finally:
        for number,handler in old.items():
            signal.signal(number,handler)
    print('{"event":"linux-staging-cleaned","temporary_programs_removed":true}',flush=True)
    return result


if __name__=="__main__":
    os.umask(0o077)
    try:
        raise SystemExit(start(*sys.argv[1:]))
    except (OSError,ValueError,TypeError):
        print('{"ok":false,"code":"owned-linux-staging-unconfirmed"}',flush=True)
        raise SystemExit(2) from None
