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

from r33_protocol import DENIED, FRAME_MAX, RUN, decode_frame, encode_frame, peer_identity

from r33_group_boundary import GROUP_FORMAT, VAULT, GroupBoundary


TMP = Path("/private/tmp") if sys.platform == "darwin" else Path("/tmp")
FORMAT = "r33-isolation-v1"
TTL_SECONDS = 48*3600


def require_private_terminal(boundary=None):
    """Require a terminal owned by this system login before reading input."""
    streams=(sys.stdin,sys.stderr)
    if not all(stream.isatty() for stream in streams):
        raise ValueError("Open this in a private terminal belonging to the operator.")
    descriptors=[stream.fileno() for stream in streams]
    attributes=[os.fstat(descriptor) for descriptor in descriptors]
    owns = (boundary.owns_terminal(attributes) if boundary is not None else
            all(item.st_uid==os.getuid() and not item.st_mode & 0o044 for item in attributes))
    if os.ttyname(descriptors[0])!=os.ttyname(descriptors[1]) or not owns:
        raise ValueError("Open a Terminal from the operator's own Mac login.")


def read_proof(path, executor, boundary=None):
    data_path = path.lstat()
    if (path.resolve()!=path or data_path.st_uid!=os.getuid() or not stat.S_ISREG(data_path.st_mode)
            or data_path.st_mode & 0o077):
        raise ValueError("Choose the verified private operator identity record.")
    value = decode_frame(path.read_bytes())
    matches = (value.get("format")==FORMAT and executor!=os.getuid()
               if boundary is None else
               value.get("format")==GROUP_FORMAT and executor==os.getuid()
               and value.get("operator_group")==boundary.group
               and type(value.get("executor_group")) is int
               and value["executor_group"]!=boundary.group
               and value.get("private_write_denied") is True)
    if (not matches or value.get("operator_uid")!=os.getuid()
            or value.get("executor_uid")!=executor
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


def write_denial(path):
    try:
        descriptor = os.open(path, os.O_WRONLY)
    except PermissionError:
        return True
    os.close(descriptor)
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
    repeated_login = "owner_group" in value
    keys = {"run","executor_uid","owner_uid","fake_file","fake_socket","broker"}
    if set(value)!=(keys | {"owner_group"} if repeated_login else keys):
        raise ValueError("The synthetic challenge is invalid.")
    if (not RUN.fullmatch(value["run"]) or value["executor_uid"]!=os.getuid()
            or value["owner_uid"]!=info.st_uid
            or repeated_login != (value["owner_uid"]==os.getuid())):
        raise ValueError("Run the check under the intended delegated identity.")
    endpoints = [Path(value[key]) for key in ("fake_file","fake_socket","broker")]
    fake_file,fake_socket,broker = endpoints
    if repeated_login:
        owned = fake_file.parent.parent
        root = owned.parent
        guard = root.lstat()
        shape = (root.parent == TMP and VAULT.fullmatch(root.name) and owned.name == "owner"
                 and value["owner_group"] == guard.st_gid and guard.st_uid == 0
                 and stat.S_IMODE(guard.st_mode) == 0o710 and os.getegid() != guard.st_gid)
    else:
        shape = all(endpoint.parent.parent==TMP for endpoint in (fake_file,fake_socket))
    if (not shape or broker!=challenge_file.parent/"q.sock"
            or fake_file.parent!=fake_socket.parent or not fake_file.parent.name.startswith("r33-check-owned-")
            or fake_file.name!="canary" or fake_socket.name!="raw.sock"):
        raise ValueError("The challenge does not identify the temporary synthetic resources.")
    return value


def agent(challenge_file):
    item=public_challenge(challenge_file)
    result={"run":item["run"],"private_file_unreadable":canary_denial(item["fake_file"]),
            "private_socket_denied":socket_denial(item["fake_socket"])}
    if "owner_group" in item:
        result["private_write_denied"] = write_denial(item["fake_file"])
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        conn.settimeout(5)
        conn.connect(item["broker"])
        with conn.makefile("rb") as stream:
            conn.sendall(encode_frame(result))
            response=decode_frame(stream.readline(FRAME_MAX))
    print("R33_ISOLATION_RESULT "+json.dumps(response),flush=True)
    return 0 if response.get("ok") is True else 2


async def operator(executor, proof, boundary=None, *, run_id=None, exchange=None):
    if (os.getuid()==0 or not 0<executor<2**32
            or ((executor==os.getuid()) != (boundary is not None))):
        raise ValueError("Select a distinct unprivileged executor account.")
    require_private_terminal(boundary)
    parent = proof.parent
    if (parent.resolve()!=parent or parent.stat().st_uid!=os.getuid()
            or parent.stat().st_mode & 0o077 or proof.exists()):
        raise ValueError("Choose a new identity record in a private operator directory.")
    with tempfile.TemporaryDirectory(prefix="r33-check-owned-",dir=boundary.private if boundary else TMP) as secret, \
            tempfile.TemporaryDirectory(prefix="r33-check-public-",dir=TMP) as shared:
        private,public = Path(secret).resolve(),Path(shared).resolve()
        canary,raw,entrance = private/"canary",private/"raw.sock",public/"q.sock"
        (private/"canary").write_bytes(secrets.token_bytes(32))
        run = run_id or secrets.token_hex(16)
        if not RUN.fullmatch(run):
            raise ValueError("The notification run identifier is invalid.")
        finished = asyncio.Event()

        async def reject_private(_reader, writer):
            writer.close()
            await writer.wait_closed()

        async def authenticate(reader, writer):
            try:
                uid, gid = peer_identity(writer.get_extra_info("socket"))
                if uid!=executor or (boundary and gid==boundary.group):
                    answer=DENIED
                else:
                    request=decode_frame(await asyncio.wait_for(reader.readline(),4))
                    expected={"run":run,"private_file_unreadable":True,"private_socket_denied":True}
                    if boundary:
                        expected["private_write_denied"] = True
                    if request!=expected or finished.is_set():
                        answer=DENIED
                    else:
                        evidence={"format":GROUP_FORMAT if boundary else FORMAT,"run":run,"operator_uid":os.getuid(),"executor_uid":executor,
                                  "checked_epoch":int(time.time()),"private_file_unreadable":True,
                                  "private_socket_denied":True}
                        if boundary:
                            evidence.update({"operator_group":boundary.group,"executor_group":gid,
                                             "private_write_denied":True})
                        with proof.open("xb") as output:
                            output.write(encode_frame(evidence))
                        answer={"ok":True,"matches_os_identity":True,"file_denied":True,"socket_denied":True}
                        if boundary:
                            answer["write_denied"] = True
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
            challenge = {"owner_uid":os.getuid(),"executor_uid":executor,"run":run,
                         "fake_file":str(canary),"fake_socket":str(raw),"broker":str(entrance)}
            if boundary:
                challenge["owner_group"] = boundary.group
            file.write_bytes(encode_frame(challenge))
            file.chmod(0o644)
            public.chmod(0o711)
            if exchange:
                from r33_rendezvous import publish
                publish(exchange, "challenge", {"run":run, "challenge":str(file)})
                print("Waiting for the automatic synthetic isolation check.", flush=True)
            else:
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
    owner.add_argument("--group-private",type=Path)
    owner.add_argument("--run")
    owner.add_argument("--exchange",type=Path)
    delegate=role.add_parser("executor")
    delegate.add_argument("--challenge",type=Path,required=True)
    args=parser.parse_args()
    try:
        if args.role=="executor":
            return agent(args.challenge)
        boundary=GroupBoundary.current(args.group_private) if args.group_private else None
        return asyncio.run(operator(args.executor_uid,args.record,boundary,run_id=args.run,exchange=args.exchange))
    except (OSError,ValueError,asyncio.TimeoutError):
        print("The private identity check did not finish. Start a new synthetic challenge.",file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
