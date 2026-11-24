#!/usr/bin/python3
"""Verify the intended Mac executor cannot reach the operator's private material."""

import argparse
import asyncio
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import sys
import tempfile
import time

from r33_protocol import DENIED, FRAME_MAX, RUN, decode_frame, encode_frame, peer_uid


TMP = Path("/private/tmp") if sys.platform == "darwin" else Path("/tmp")
FORMAT = "r33-isolation-v1"
TTL_SECONDS = 48*3600


def read_proof(path, executor):
    data_path = path.lstat()
    if (path.resolve()!=path or data_path.st_uid!=os.getuid() or not stat.S_ISREG(data_path.st_mode)
            or data_path.st_mode & 0o077):
        raise ValueError("Choose the verified private operator identity record.")
    value = decode_frame(path.read_bytes())
    if (value.get("format")!=FORMAT or value.get("operator_uid")!=os.getuid()
            or value.get("executor_uid")!=executor or executor==os.getuid()
            or value.get("private_file_unreadable") is not True or value.get("private_socket_denied") is not True
            or type(value.get("checked_epoch")) is not int
            or not 0<=time.time()-value["checked_epoch"]<=TTL_SECONDS):
        raise ValueError("Verify these two identities with the current private isolation check.")
    return value


def canary_denial(path):
    try:
        Path(path).read_bytes()
    except PermissionError:
        return True
    return False


def socket_denial(path):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        try:
            conn.connect(path)
        except PermissionError:
            return True
    return False


def public_challenge(challenge_file):
    info = challenge_file.lstat()
    if (challenge_file.resolve()!=challenge_file or challenge_file.parent.parent!=TMP
            or not challenge_file.parent.name.startswith("r33-check-public-")
            or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or info.st_size>FRAME_MAX):
        raise ValueError("Choose the temporary synthetic challenge printed by the operator.")
    value = decode_frame(challenge_file.read_bytes())
    if set(value)!={"run","executor_uid","owner_uid","fake_file","fake_socket","broker"}:
        raise ValueError("The synthetic challenge is invalid.")
    if (not RUN.fullmatch(value["run"]) or value["executor_uid"]!=os.getuid()
            or value["owner_uid"]!=info.st_uid or value["owner_uid"]==os.getuid()):
        raise ValueError("Run the check under the intended delegated identity.")
    endpoints = [Path(value[key]) for key in ("fake_file","fake_socket","broker")]
    fake_file,fake_socket,broker = endpoints
    if (any(endpoint.parent.parent!=TMP for endpoint in endpoints)
            or broker!=challenge_file.parent/"q.sock"
            or fake_file.parent!=fake_socket.parent or not fake_file.parent.name.startswith("r33-check-owned-")
            or fake_file.name!="canary" or fake_socket.name!="raw.sock"):
        raise ValueError("The challenge does not identify the temporary synthetic resources.")
    return value


def agent(challenge_file):
    item=public_challenge(challenge_file)
    result={"run":item["run"],"private_file_unreadable":canary_denial(item["fake_file"]),
            "private_socket_denied":socket_denial(item["fake_socket"])}
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        conn.settimeout(5)
        conn.connect(item["broker"])
        with conn.makefile("rb") as stream:
            conn.sendall(encode_frame(result))
            response=decode_frame(stream.readline(FRAME_MAX))
    print("R33_ISOLATION_RESULT "+json.dumps(response),flush=True)
    return 0 if response.get("ok") is True else 2


async def operator(executor, proof):
    if os.getuid() in (0,executor) or not 0<executor<2**32:
        raise ValueError("Select a distinct unprivileged executor account.")
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValueError("Open the isolation check in the operator's private terminal.")
    parent = proof.parent
    if (parent.resolve()!=parent or parent.stat().st_uid!=os.getuid()
            or parent.stat().st_mode & 0o077 or proof.exists()):
        raise ValueError("Choose a new identity record in a private operator directory.")
    with tempfile.TemporaryDirectory(prefix="r33-check-owned-",dir=TMP) as secret, \
            tempfile.TemporaryDirectory(prefix="r33-check-public-",dir=TMP) as shared:
        private,public = Path(secret).resolve(),Path(shared).resolve()
        canary,raw,entrance = private/"canary",private/"raw.sock",public/"q.sock"
        (private/"canary").write_bytes(secrets.token_bytes(32))
        run=secrets.token_hex(16)
        finished = asyncio.Event()

        async def reject_private(_reader, writer):
            writer.close()
            await writer.wait_closed()

        async def authenticate(reader, writer):
            try:
                if peer_uid(writer.get_extra_info("socket"))!=executor:
                    answer=DENIED
                else:
                    request=decode_frame(await asyncio.wait_for(reader.readline(),4))
                    expected={"run":run,"private_file_unreadable":True,"private_socket_denied":True}
                    if request!=expected or finished.is_set():
                        answer=DENIED
                    else:
                        evidence={"format":FORMAT,"run":run,"operator_uid":os.getuid(),"executor_uid":executor,
                                  "checked_epoch":int(time.time()),"private_file_unreadable":True,
                                  "private_socket_denied":True}
                        with proof.open("xb") as output:
                            output.write(encode_frame(evidence))
                        answer={"ok":True,"matches_os_identity":True,"file_denied":True,"socket_denied":True}
                        finished.set()
                writer.write(encode_frame(answer))
                await writer.drain()
            except (OSError,ValueError,asyncio.TimeoutError):
                pass
            finally:
                writer.close()
                await writer.wait_closed()

        raw_server=await asyncio.start_unix_server(reject_private,str(raw))
        gate=await asyncio.start_unix_server(authenticate,str(entrance),limit=FRAME_MAX)
        try:
            entrance.chmod(0o666)
            file=public/"challenge.json"
            file.write_bytes(encode_frame({"owner_uid":os.getuid(),"executor_uid":executor,"run":run,
                                           "fake_file":str(canary),"fake_socket":str(raw),"broker":str(entrance)}))
            file.chmod(0o644)
            public.chmod(0o711)
            print("R33_ISOLATION "+str(file),flush=True)
            await asyncio.wait_for(finished.wait(),300)
            print("The selected executor passed the private file and socket checks.",flush=True)
        finally:
            gate.close()
            raw_server.close()
            await gate.wait_closed()
            await raw_server.wait_closed()
    return 0


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    role=parser.add_subparsers(dest="role",required=True)
    owner=role.add_parser("operator")
    owner.add_argument("--executor-uid",type=int,required=True)
    owner.add_argument("--record",type=Path,required=True)
    delegate=role.add_parser("executor")
    delegate.add_argument("--challenge",type=Path,required=True)
    args=parser.parse_args()
    try:
        if args.role=="executor":
            return agent(args.challenge)
        return asyncio.run(operator(args.executor_uid,args.record))
    except (OSError,ValueError,asyncio.TimeoutError):
        print("The private identity check did not finish. Start a new synthetic challenge.",file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
