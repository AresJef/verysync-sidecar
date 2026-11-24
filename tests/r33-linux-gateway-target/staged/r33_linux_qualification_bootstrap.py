"""Load the exact private test programs inside the operator's SSH session."""

import hashlib
import os
from pathlib import Path
import pwd
import re
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


def start(run, expires, expected, synthetic):
    if (os.getresuid()!=(0,0,0) or os.uname().machine!="x86_64"
            or not re.fullmatch(r"[a-f0-9]{32}",run) or not re.fullmatch(r"[a-f0-9]{64}",expected)
            or not 0<int(expires)-time.time()<=48*3600
            or synthetic not in ("live","control","native-target")):
        raise ValueError("The selected Linux node or the test window does not match.")
    worker = pwd.getpwnam("nobody")
    scope=GATEWAY_FILES if synthetic=="native-target" else FILES
    with tempfile.TemporaryDirectory(prefix="r33-la-staging-",dir="/tmp") as folder:
        root=Path(folder).resolve()
        payload=root/"test.zip"
        receive(payload,expected)
        os.chown(root,0,worker.pw_gid)
        root.chmod(0o710)
        with ZipFile(payload) as bundle:
            items=bundle.infolist()
            if len(items)!=len(scope) or {i.filename for i in items}!=scope:
                raise ValueError("The staged test inventory does not match.")
            for fact in items:
                if fact.file_size>100*1024**2 or not stat.S_ISREG(fact.external_attr>>16):
                    raise ValueError("The staged test program has an invalid file type.")
                destination=root/fact.filename
                with bundle.open(fact) as src, destination.open("xb") as out:
                    shutil.copyfileobj(src,out)
                os.chown(destination,0,worker.pw_gid)
                destination.chmod(0o550 if synthetic=="native-target" and
                                  fact.filename in ("verysync-v2.33.2","verysync-r33-operator") else 0o440)
        payload.unlink()
        command=["/usr/bin/python3","-B",str(root/"run_local_api_scope.py"),
                 "--engine",str(root/"verysync-v2.33.2"),
                 "--driver",str(root/"verysync-r33-operator"),
                 "--run",run,"--expires",expires]
        if synthetic=="control":
            command.append("--synthetic")
        elif synthetic=="native-target":
            command=["/usr/bin/python3","-B",str(root/"r33_gateway_target.py"),"serve",str(root),run,str(expires)]
        child=subprocess.Popen(command)
        old={}
        def forward(number,_frame):
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
        for number in (signal.SIGHUP,signal.SIGTERM,signal.SIGINT):
            old[number]=signal.signal(number,forward)
        try:
            result=child.wait()
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
