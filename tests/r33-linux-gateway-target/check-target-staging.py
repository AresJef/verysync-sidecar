"""Test the mounted native target, operator stop and lease withdrawal on Ubuntu."""

from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import select
import stat
import subprocess
import sys
import time
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED


HERE=Path(__file__).resolve().parent
HELPERS=HERE/"staged"
BOOTSTRAP=HELPERS/"r33_linux_qualification_bootstrap.py"


def take(child, timeout):
    if not select.select([child.stdout],[],[],timeout)[0]:
        raise TimeoutError("The isolated target did not report its next phase.")
    line=child.stdout.readline(8193)
    return json.loads(line)


def send(child,value):
    child.stdin.write(json.dumps(value).encode("ascii")+b"\n")
    child.stdin.flush()


def run(payload, ending):
    run_id=secrets.token_hex(16)
    deadline=str(int(time.time())+170)
    documented={"SSH_CONNECTION":"192.0.2.2 41010 192.0.2.1 22","PATH":"/usr/bin:/bin"}
    argv=[sys.executable,"-B",str(BOOTSTRAP),run_id,deadline,sha256(payload).hexdigest(),"native-target"]
    child=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,bufsize=0,env=documented)
    try:
        child.stdin.write(str(len(payload)).encode("ascii")+b"\n")
        tail=memoryview(payload)
        while tail:
            consumed=child.stdin.write(tail)
            if not consumed:
                raise IOError("The staged target refused the bounded payload.")
            tail=tail[consumed:]
        child.stdin.flush()
        readiness=take(child,50)
        assert readiness.get("event")=="native-gateway-foreground-ready"
        assert readiness["run"]==run_id and readiness["deadline"]==int(deadline)
        assert readiness["target"]["engine"]=="v2.33.2"
        assert readiness["boundary"]["private_state"] and readiness["boundary"]["uid"]!=0
        assert readiness["boundary"]["network"]!=Path("/proc/self/ns/net").stat().st_ino
        assert readiness["boundary"]["mount"]!=Path("/proc/self/ns/mnt").stat().st_ino

        request=secrets.token_hex(16)
        command={"kind":"execute","run":run_id,"request":request,"operation":"state","input":{"kind":"state"}}
        send(child,command)
        state=take(child,8)
        assert state["event"]=="operation-observed" and state["request"]==request
        assert state["native"]["folder_exact"] and state["native"]["files_match"] and state["native"]["peer"] is None
        send(child,command)
        assert take(child,7)=={"event":"operation-refused","request":request}
        send(child,{"kind":"renew","run":run_id})
        start=time.monotonic()
        if ending=="user-stop":
            send(child,{"kind":"stop","run":run_id})
        elif ending=="channel-closed":
            child.stdin.close()
        result=take(child,55)
        elapsed=time.monotonic()-start
        assert result.get("reason")==ending, result.get("reason")
        assert result["native"]=={"event":"owned-target-exit","normal":True}
        assert result["exit_code"]==0 and result["dedicated_connection_count"]==0
        assert result["target_changed_restored"]["files_match"] and elapsed<95
        cleanup=take(child,9)
        assert cleanup=={"event":"native-gateway-target-cleanup","run":run_id,
                         "exact_route_removed":True,"private_state_removed":True}
        assert take(child,7)=={"event":"linux-staging-cleaned","temporary_programs_removed":True}
        assert child.wait(timeout=8)==0
        return {"ending":ending,"normal_native_exit":True,"elapsed_s":round(elapsed,3),
                "private_route_removed":True,"duplicate_refused":True}
    finally:
        if child.poll() is None:
            child.stdin.close()
            try:
                child.wait(timeout=45)
            except subprocess.TimeoutExpired:
                child.terminate()
                child.wait(timeout=12)


def main(engine,binary,archive_path):
    assert os.geteuid()==0 and Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()=="1"
    before=set(Path("/tmp").glob("r33-la-staging-*"))
    source={"verysync-v2.33.2":engine,"verysync-r33-operator":binary}
    for name in ("r33_gateway_target.py","r33_wan_route.py","linux_private_boundary.py","r33_protocol.py"):
        source[name]=HELPERS/name
    with ZipFile(archive_path,"x") as archive:
        for name,path in sorted(source.items()):
            info=ZipInfo(name)
            info.external_attr=(stat.S_IFREG|0o400)<<16
            archive.writestr(info,path.read_bytes(),compress_type=ZIP_DEFLATED,compresslevel=4)
    try:
        payload=archive_path.read_bytes()
        outcomes=[run(payload,choice) for choice in ("user-stop","channel-closed","lease-expired")]
        assert set(Path("/tmp").glob("r33-la-staging-*"))==before
    finally:
        archive_path.unlink()
    print("R33_NATIVE_GATEWAY_STAGING "+json.dumps({"cases":outcomes,"credentials":0,
           "driver_sha256":sha256(binary.read_bytes()).hexdigest(),
           "fixed_native_sha256":sha256(engine.read_bytes()).hexdigest()},sort_keys=True),flush=True)


if __name__=="__main__":
    main(*map(Path,sys.argv[1:]))
