"""Replay the private bootstrap on a signed-out, disposable runner."""

from hashlib import sha256
import json
from pathlib import Path
import secrets
import select
import stat
import subprocess
import sys
import tempfile
import time
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED


HERE = Path(__file__).resolve().parent
WORKER = HERE / "r33_linux_qualification_bootstrap.py"


def take(child,timeout):
    if not select.select([child.stdout],[],[],timeout)[0]:
        raise TimeoutError("The private bootstrap did not return a receipt.")
    return json.loads(child.stdout.readline(8193))


def verified_role(body, expected, control):
    run=secrets.token_hex(16)
    child=subprocess.Popen(
        ["/usr/bin/sudo","-n","/usr/bin/python3","-B",str(WORKER),
         run,str(int(time.time())+150),expected,"control"],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,bufsize=0,
    )
    try:
        child.stdin.write(str(len(body)).encode("ascii")+b"\n")
        view=memoryview(body)
        while view:
            consumed=child.stdin.write(view)
            view=view[consumed:]
        child.stdin.flush()
        ready=take(child,50)
        if not control:
            assert ready=={"ok":False,"code":"owned-linux-staging-unconfirmed"},ready
            assert child.wait(timeout=10)==2
            return
        assert ready.get("event")=="local-api-foreground-ready" and ready["run"]==run,ready
        assert ready["instance"]["account"]=="logged-out"
        child.stdin.write(json.dumps({"kind":"stop","run":run}).encode("ascii")+b"\n")
        child.stdin.flush()
        end=take(child,28)
        cleanup=take(child,8)
        staged=take(child,5)
        assert end["reason"]=="user-stop" and end["native"]["normal_owned_exit"]
        assert end["provider_network"]["permitted"]==0 and not end["native"]["login_submitted"]
        assert cleanup["private_state_removed"] and cleanup["normal_scope_exit"]
        assert staged=={"event":"linux-staging-cleaned","temporary_programs_removed":True}
        assert child.wait(timeout=10)==0
    finally:
        if child.poll() is None:
            child.stdin.close()
            child.wait(timeout=16)


def execute(engine,driver):
    before=set(Path("/tmp").glob("r33-la-staging-*"))
    with tempfile.TemporaryDirectory(prefix="r33-staging-check-") as stage:
        packed=Path(stage)/"fixture.zip"
        inputs={"verysync-v2.33.2":engine,"verysync-r33-operator":driver}
        for name in ("run_local_api_scope.py","linux_account_connector.py","linux_private_boundary.py",
                     "check_worker_boundary.py","r33_protocol.py","r33_official_proxy.py"):
            inputs[name]=HERE/name
        with ZipFile(packed,"x") as archive:
            for name,path in sorted(inputs.items()):
                entry=ZipInfo(name)
                entry.external_attr=(stat.S_IFREG|0o400)<<16
                archive.writestr(entry,path.read_bytes(),compress_type=ZIP_DEFLATED,compresslevel=4)
        content=packed.read_bytes()
        verified_role(content,sha256(content).hexdigest(),True)
        verified_role(b"unmatched synthetic bytes","0"*64,False)
    assert set(Path("/tmp").glob("r33-la-staging-*"))==before
    print("R33_LICENSE_STAGING "+json.dumps({"private_payload_verified":True,"root_lease_normal_exit":True,
          "bad_digest_refused":True,"staging_removed":True,"accounts_or_provider_requests":0}))


if __name__=="__main__":
    execute(*map(Path,sys.argv[1:]))
