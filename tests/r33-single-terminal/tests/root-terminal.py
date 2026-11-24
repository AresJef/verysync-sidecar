"""Exercise the launcher group/TTY code on an owned hosted pseudo-terminal."""

import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import select
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT/"runtime-next"
sys.path.insert(0,str(RUNTIME))

from r33_group_boundary import GroupBoundary
from r33_isolation import operator
from r33_rendezvous import verify_native_boundary


TMP = Path("/private/tmp" if sys.platform == "darwin" else "/tmp")


async def isolate(uid, boundary, run, exchange, app):
    await operator(uid, app/"proof.json", boundary, run_id=run, exchange=exchange)
    arena = boundary.private/"v"/run
    (arena/"state").mkdir(parents=True)
    raw = arena/"state"/"gui.sock"

    async def unused(_reader, writer):
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_unix_server(unused, str(raw))
    try:
        await verify_native_boundary(exchange,run,arena,uid,int(os.environ["R33_OBSERVER_GID"]),
                                     asyncio.Event())
    finally:
        server.close()
        await server.wait_closed()
        raw.unlink()


def child(owner, uid, exchange, fixed):
    gid = os.getegid()
    boundary = GroupBoundary.current(owner)
    app = owner/"kit"
    app.mkdir()
    for source in RUNTIME.glob("*.py"):
        shutil.copyfile(source, app/source.name)
    run = os.urandom(16).hex()
    environment = {"PATH":"/usr/bin:/bin","PYTHONPATH":str(app),"LANG":"C"}
    with (app/"fixture-domain.json").open("x") as stream:
        json.dump(fixed["expected"],stream)
    native_state = owner/"recovery"
    native_state.mkdir()
    provider_dir = owner/"provider"
    provider_dir.mkdir()
    shutil.copyfile(app/"fixture-domain.json",provider_dir/"expect.json")
    profile = app/"profile.json"
    profile.write_text(json.dumps({
        "pro":{"connection":{"socket":str(provider_dir/"account.sock"),"recovery":str(native_state)},
               "allow":["observe","schedule-watch-prepare","schedule-watch-seed","schedule-watch-observe","schedule-watch-finish"]},
    }))
    target = Path(__file__).parent/"prior"/"fake_vendor.py"
    with subprocess.Popen([sys.executable,"-B",str(target),str(provider_dir)],env=environment,
                          stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as service:
        try:
            assert select.select([service.stdout],[],[],5)[0]
            assert service.stdout.readline()==b"ACCOUNT_FIXTURE_READY\n", service.poll()
            asyncio.run(isolate(uid,boundary,run,exchange,app))
            arguments=[sys.executable,"-B",str(app/"r33_handoff.py"),"start","--synthetic",
                       "--executor-uid",str(uid),"--profile",str(profile),"--group-private",str(owner),
                       "--isolation-record",str(app/"proof.json"),"--evidence",str(app/"journal"),
                       "--exchange",str(exchange),"--run",run,"--expires-at",str(int(time.time())+180)]
            completed=subprocess.run(arguments,env=environment,check=False)
            return completed.returncode
        finally:
            if service.poll() is None:
                service.terminate()
                service.wait(timeout=6)


def main():
    if os.getuid()!=0 or not os.environ.get("SUDO_UID","").isdigit():
        raise ValueError("Use the disposable hosted terminal fixture.")
    uid = int(os.environ["SUDO_UID"])
    exchange, config = map(Path,sys.argv[1:])
    fixed = json.loads(config.read_bytes())
    assert set(fixed)=={"expected","scope"}
    loader = runpy.run_path(str(ROOT/"group-launch.py"))
    terminal = loader["private_terminal"]
    if sys.platform.startswith("linux"):
        terminal.__globals__["TTY"] = re.compile(r"/dev/pts/[0-9]+\Z")
    gid = loader["next_group"]()
    with tempfile.TemporaryDirectory(prefix="r33-session-",dir=TMP) as work:
        vault=Path(work).resolve()
        owner=vault/"owner"
        owner.mkdir()
        os.chown(vault,0,gid)
        os.chown(owner,uid,gid)
        vault.chmod(0o710)
        print("R33_PROTECTED_VAULT "+json.dumps({"private":str(owner)}),flush=True)
        with terminal(uid,gid):
            pid=os.fork()
            if pid==0:
                try:
                    os.setgroups([gid])
                    os.setgid(gid)
                    os.setuid(uid)
                    os.umask(0o077)
                    os.environ["R33_OBSERVER_GID"]=str(fixed["scope"]["gid"])
                    result=child(owner,uid,exchange,fixed)
                except BaseException as exc:
                    print(f"The protected fixture stopped at {type(exc).__name__}: {exc}",file=sys.stderr,flush=True)
                    os._exit(2)
                os._exit(result)
            with loader["owned_signals"](pid):
                code=os.waitstatus_to_exitcode(os.waitpid(pid,0)[1])
    return code


if __name__=="__main__":
    raise SystemExit(main())

