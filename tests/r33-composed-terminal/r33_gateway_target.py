"""Own the signed-out Linux target and its bounded native TCP route."""

import asyncio
import os
from pathlib import Path
import pwd
import re
import secrets
import signal
import socket
import sys
import tempfile
import time

from linux_private_boundary import namespace, relinquish_admin
from r33_protocol import FRAME_MAX, Lease, decode_frame, encode_frame
from r33_wan_route import PORT, Route, open_owned, run


HERE = Path(__file__).resolve()
ACTIONS = frozenset(("register","allow","state","restore"))


def receipt(value):
    sys.stdout.buffer.write(encode_frame(value))
    sys.stdout.buffer.flush()


async def send(writer, value):
    writer.write(encode_frame(value))
    await writer.drain()


async def read(stream, timeout=28):
    return decode_frame(await asyncio.wait_for(stream.readline(),timeout))


def isolated_driver(stage, root, run_id, address, uid, gid, outside_net, outside_mount):
    if namespace("net")==outside_net or namespace("mnt")==outside_mount:
        raise ValueError("The target needs its own network and mount scope.")
    if {name for _,name in socket.if_nameindex()}!={"lo","r33-data"}:
        raise ValueError("The target network contains an unexpected interface.")
    original=root.stat()
    if original.st_uid!=0 or list(root.iterdir()):
        raise ValueError("The target needs a new private mount point.")
    run("/usr/bin/mount","-t","tmpfs","-o",f"size=64m,nosuid,nodev,noexec,mode=0700,uid={uid},gid={gid}",
        "r33-gateway-private",str(root))
    private=root.stat()
    if private.st_dev==original.st_dev or (private.st_uid,private.st_gid)!=(uid,gid) or private.st_mode&0o077:
        raise ValueError("The native target state is not the private mount.")
    relinquish_admin(uid,gid)
    with socket.socket() as gui, socket.socket() as auxiliary:
        for listener in (gui,auxiliary):
            listener.bind(("127.0.0.1",0))
        ports=[str(listener.getsockname()[1]) for listener in (gui,auxiliary)]
    receipt({"event":"private-native-target-network","uid":uid,"network":namespace("net"),
             "mount":namespace("mnt"),"private_state":True})
    binary=stage/"verysync-r33-operator"
    os.chdir(root)
    os.execve(binary,[str(binary),"sealed-network-target",str(stage/"verysync-v2.33.2"),
                      str(root),run_id,ports[0],f"{address}:{PORT}",ports[1]],
              {"HOME":str(root),"TMPDIR":str(root),"PATH":"/usr/bin:/bin",
               "R33_OUTER_NETWORK_INODE":str(outside_net)})


async def controller(child, route, expires, ready):
    loop=asyncio.get_running_loop()
    closed=asyncio.Event()
    for sig in (signal.SIGHUP,signal.SIGINT,signal.SIGTERM):
        loop.add_signal_handler(sig,closed.set)
    frames=asyncio.StreamReader(limit=FRAME_MAX)
    await loop.connect_read_pipe(lambda:asyncio.StreamReaderProtocol(frames),sys.stdin.buffer)
    lease=Lease(lifetime=38)
    pending=None
    used=set()
    reason="external-stop"

    async def dispatch(request_id, data):
        try:
            if closed.is_set() or not lease.permits(time.monotonic()):
                raise ValueError("The authorization is no longer active.")
            await send(child.stdin,data)
            observed=await read(child.stdout)
            receipt({"event":"operation-observed","request":request_id,"native":observed})
        except (OSError,ValueError,asyncio.TimeoutError):
            receipt({"event":"operation-unconfirmed","request":request_id})
            closed.set()

    receipt(ready)
    try:
        while not closed.is_set():
            if not lease.permits(time.monotonic()) or time.time()>=expires:
                reason="lease-expired"
                break
            try:
                frame=await asyncio.wait_for(frames.readline(),.25)
            except asyncio.TimeoutError:
                continue
            if not frame:
                reason="channel-closed"
                break
            message=decode_frame(frame)
            if message=={"kind":"renew","run":route.run_id}:
                lease.renew(time.monotonic())
                continue
            if message=={"kind":"stop","run":route.run_id}:
                reason="user-stop"
                break
            action=message.get("operation")
            operation_id=message.get("request")
            arguments=message.get("input")
            expected={"kind","peer"} if action=="register" else {"kind"}
            if (set(message)!={"kind","run","request","operation","input"} or message["kind"]!="execute"
                    or message["run"]!=route.run_id or type(action) is not str or action not in ACTIONS
                    or type(arguments) is not dict
                    or set(arguments)!=expected or arguments["kind"]!=action
                    or type(operation_id) is not str or not re.fullmatch(r"[a-f0-9]{32}",operation_id)
                    or len(used)>=18 or operation_id in used or (pending and not pending.done())):
                receipt({"event":"operation-refused","request":operation_id})
                continue
            used.add(operation_id)
            pending=asyncio.create_task(dispatch(operation_id,arguments))
    except (OSError,ValueError,asyncio.TimeoutError):
        reason="control-channel-unconfirmed"
    finally:
        lease.revoke(time.monotonic(),reason)
        if pending and not pending.done():
            try:
                await asyncio.wait_for(asyncio.shield(pending),14)
            except asyncio.TimeoutError:
                pending.cancel()
                await asyncio.gather(pending,return_exceptions=True)
    try:
        await send(child.stdin,{"kind":"end"})
        final=await read(child.stdout,12)
        finished=await read(child.stdout,16)
        child.stdin.close()
        await asyncio.wait_for(child.wait(),5)
        return {"event":"native-gateway-target-stopped","run":route.run_id,"reason":reason,
                "target_changed_restored":final.get("observation"),"native":finished,
                "exit_code":child.returncode,"dedicated_connection_count":route.packet_count()}
    except (OSError,ValueError,asyncio.TimeoutError):
        return {"event":"native-gateway-target-stopped","run":route.run_id,"reason":reason,
                "native_cleanup":"unconfirmed","exit_code":child.returncode}


async def serve(stage, run_id, expires):
    if os.getresuid()!=(0,0,0) or os.uname().machine!="x86_64":
        raise ValueError("This scope needs the approved AMD64 Linux target.")
    ssh=os.environ.get("SSH_CONNECTION","").split()
    if len(ssh)!=4 or not 0<expires-time.time()<=48*3600:
        raise ValueError("The SSH-authorized origin, endpoint or expiry is missing.")
    route=Route.for_connection(run_id,ssh[0],ssh[2])
    runtime=pwd.getpwnam("nobody")
    with tempfile.TemporaryDirectory(prefix="r33-gateway-target-",dir="/tmp") as directory:
        root=Path(directory)
        with open_owned(route):
            child=await asyncio.create_subprocess_exec(
                *route.inside("/usr/bin/unshare","--mount","--propagation","private","--",
                              "/usr/bin/python3","-B",str(HERE),"inside",str(stage),str(root),run_id,
                              str(route.target),str(runtime.pw_uid),str(runtime.pw_gid),
                              str(namespace("net")),str(namespace("mnt"))),
                stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,
            )
            try:
                boundary=await read(child.stdout,15)
                if boundary.get("event")!="private-native-target-network" or boundary.get("uid")!=runtime.pw_uid:
                    raise ValueError("The target process is outside its private runtime.")
                key=secrets.token_hex(32)
                await send(child.stdin,{"synthetic_target_key":key})
                ready=await read(child.stdout,38)
                if ready.get("event")!="owned-target-ready" or ready.get("native_p2p")!=f"{route.target}:{PORT}":
                    raise ValueError("The native target did not confirm the dedicated listener.")
                final=await controller(child,route,expires,
                    {"event":"native-gateway-foreground-ready","run":run_id,"deadline":expires,
                     "boundary":boundary,"target":ready,"synthetic_target_key":key})
            finally:
                if child.returncode is None:
                    child.stdin.close()
                    try:
                        await asyncio.wait_for(child.wait(),16)
                    except asyncio.TimeoutError:
                        child.terminate()
                        await asyncio.wait_for(child.wait(),5)
        if not route.cleared():
            raise ValueError("The dedicated test route or private network remains.")
    receipt(final)
    receipt({"event":"native-gateway-target-cleanup","run":run_id,
             "exact_route_removed":True,"private_state_removed":not root.exists()})


if __name__=="__main__":
    os.umask(0o077)
    try:
        if sys.argv[1]=="inside":
            stage,root,run_id,address,uid,gid,outnet,outmnt=sys.argv[2:]
            isolated_driver(Path(stage),Path(root),run_id,address,*map(int,(uid,gid,outnet,outmnt)))
        else:
            assert sys.argv[1]=="serve"
            stage,run_id,expiry=sys.argv[2:]
            asyncio.run(serve(Path(stage),run_id,int(expiry)))
    except (OSError,RuntimeError,ValueError,asyncio.TimeoutError):
        receipt({"ok":False,"code":"owned-gateway-target-unconfirmed"})
        raise SystemExit(2) from None
