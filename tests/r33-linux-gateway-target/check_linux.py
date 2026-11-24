"""Run the target witness on the pinned signed-out Linux program."""

import json
import os
from pathlib import Path
import runpy
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager


HERE = Path(__file__).resolve().parent
CASES = runpy.run_path(str(HERE/"gateway_target_controls.py"))
FILES = runpy.run_path(str(HERE.parent/"r33-linux-named-local-api"/"check-linux-qualification.py"))


def exact_processes(program):
    owned=[]
    for candidate in Path("/proc").iterdir():
        if candidate.name.isnumeric():
            try:
                if os.readlink(candidate/"exe")==str(program):
                    owned.append(int(candidate.name))
            except (OSError, ValueError):
                continue
    return owned


@contextmanager
def worker(engine, binary, root):
    isolated=Path(tempfile.mkdtemp(prefix="r33-gateway-target-",dir=root)).resolve()
    held=[socket.socket() for _ in range(3)]
    try:
        for listener in held:
            listener.bind(("127.0.0.1",0))
        gui,data,auxiliary=[listener.getsockname()[1] for listener in held]
    finally:
        for listener in held:
            listener.close()
    env={"HOME":str(isolated),"TMPDIR":str(isolated),"PATH":"/usr/bin:/bin"}
    run=secrets.token_hex(16)
    process=subprocess.Popen(
        [str(binary),"sealed-loopback-control",str(engine),str(isolated),run,
         str(gui),str(data),str(auxiliary)],
        env=env,cwd=isolated,stdin=subprocess.PIPE,stdout=subprocess.PIPE,start_new_session=True,
    )
    try:
        yield process,gui
    finally:
        if process.poll() is None:
            process.stdin.close()
            try:
                process.wait(timeout=16)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGTERM)
                process.wait(timeout=10)
        deadline=time.monotonic()+8
        while exact_processes(engine) and time.monotonic()<deadline:
            time.sleep(.1)
        if exact_processes(engine):
            raise ValueError("The exact synthetic target program did not stop.")


def inner(engine,binary,root,uid,gid,outer):
    if os.geteuid()!=0 or int(uid)==0 or FILES["namespace"]()==int(outer):
        raise ValueError("The test target needs a fresh native network and an ordinary UID.")
    subprocess.run(["/usr/sbin/ip","link","set","lo","up"],check=True,timeout=5)
    assert {name for _,name in socket.if_nameindex()}=={"lo"}
    os.setgroups([])
    os.setgid(int(gid))
    os.setuid(int(uid))
    with worker(engine,binary,root) as (other,_):
        allocated=CASES["ask"](other,{"synthetic_target_key":secrets.token_hex(32)})
        assert allocated["event"]=="owned-target-ready"
        final=CASES["ask"](other,{"kind":"end"})
        assert final["observation"]["files_match"]
        assert CASES["ask"](other)=={"event":"owned-target-exit","normal":True}
        assert other.wait(timeout=15)==0
    with worker(engine,binary,root) as (target,port):
        proof=CASES["test_fixture"](target,port,secrets.token_hex(32),allocated["internal_device_id"])
    proof.update({"uid":os.getuid(),"separate_loopback":True,"engine":FILES["digest"](Path(engine)),
                  "signed_out_control":True,"driver":FILES["digest"](Path(binary))})
    print("R33_LINUX_GATEWAY_TARGET "+json.dumps(proof,sort_keys=True))


def main(evidence):
    if os.geteuid()==0 or os.uname().machine!="x86_64" or os.environ.get("GITHUB_ACTIONS")!="true":
        raise ValueError("Use the standard AMD64 Linux workflow.")
    evidence.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="r33-linux-gateway-",dir="/tmp") as workspace:
        folder=Path(workspace)
        crate_archive,engine_archive=folder/"release.crate",folder/"engine.tar.gz"
        for (url,digest),path in zip(FILES["ARTIFACTS"],(crate_archive,engine_archive)):
            FILES["pinned_download"](url,digest,path)
        subprocess.run(["/usr/bin/tar","-xzf",str(crate_archive),"-C",workspace],check=True,timeout=10)
        released=folder/"verysync-sidecar-0.1.0"
        native=runpy.run_path(str(released/"scripts"/"prepare-test-engine.py"))["extract_executable"](
            engine_archive,folder,"verysync-linux-amd64-v2.33.2","verysync","tar.gz",
        )
        assert FILES["digest"](native)==FILES["NATIVE_SHA"]
        source=folder/"driver"
        (source/"src").mkdir(parents=True)
        for code in (HERE/"src").glob("*.rs"):
            (source/"src"/code.name).write_bytes(code.read_bytes())
        manifest=HERE.parent/"r33-single-terminal"/"native-driver"
        for name,digest in FILES["DRIVER_FILES"].items():
            content=manifest/name
            assert FILES["digest"](content)==digest
            (source/name).write_bytes(content.read_bytes())
        target=folder/"target"
        subprocess.run(["cargo","+1.85.0","build","--locked","--target-dir",str(target),
                        "--config",f'patch.crates-io.verysync-sidecar.path="{released}"'],
                       cwd=source,check=True,timeout=285)
        binary=target/"debug"/"verysync-r33-operator"
        subprocess.run(["/usr/bin/sudo","-n","/usr/bin/unshare","--net","/usr/bin/python3","-B",
                        __file__,"--inside",str(native),str(binary),workspace,str(os.getuid()),
                        str(os.getgid()),str(FILES["namespace"]())],
                       cwd=folder,check=True,timeout=100)
        subprocess.run(
            ["/usr/bin/sudo","-n","/usr/bin/unshare","--net","--mount","--propagation","private","--",
             "/bin/bash","-euc",
             '/usr/sbin/sysctl -w net.ipv4.ip_forward=1 && exec /usr/bin/python3 -B "$@"',
             "isolated native target",str(HERE/"check-target-staging.py"),str(native),str(binary),
             str(folder/"staging-proof.zip")],
            cwd=folder,check=True,timeout=220)
        (evidence/"verysync-r33-operator").write_bytes(binary.read_bytes())
    assert not folder.exists()
    print("R33_LINUX_GATEWAY_TARGET_CLEANUP "+json.dumps({"exact_fixture_removed":True}))


if __name__=="__main__":
    if len(sys.argv)==8 and sys.argv[1]=="--inside":
        inner(*sys.argv[2:])
    elif len(sys.argv)==2:
        main(Path(sys.argv[1]))
    else:
        raise SystemExit("Use the verified workflow invocation.")
