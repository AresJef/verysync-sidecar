"""Check the Pro account and continue eligible tests in the same foreground."""

import argparse
import asyncio
from contextlib import ExitStack, suppress
from hashlib import sha256
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import sys
import time
from tempfile import TemporaryDirectory

from r33_accounts import read_credentials
from r33_cases import TWO_CORE_SCOPES
from r33_group_boundary import GroupBoundary
from r33_handoff import Journal, Scope, Supervisor
from r33_isolation import read_proof, require_private_terminal
from r33_linux_qualification_session import LinuxForeground, LinuxQualification
from r33_official_proxy import OfficialProxy
from r33_prepare import extract_engine, hash_file, private_executable
from r33_protocol import FRAME_MAX, OperatorCancelled, decode_frame, encode_frame
from r33_rendezvous import TMP, exchange_path, publish, verify_native_boundary
from r33_single import confirm_combined, linux_destination, remaining_seconds


APP = Path(__file__).resolve().parent


def gateway_policy(root, official_port, owned_ports):
    addresses = tuple(owned_ports)
    if len(addresses)!=5 or 18886 in addresses or len({official_port,*addresses})!=6:
        raise ValueError("The gateway case needs distinct owned loopback ports.")
    permitted_bind = "".join(f'(allow network-bind (local tcp "localhost:{port}"))\n'
                             for port in addresses)
    permitted_connect = "".join(f'(allow network-outbound (remote tcp "localhost:{port}"))\n'
                                for port in (official_port,*addresses))
    confinement = root / "owned-gateway.sb"
    confinement.write_text(
        '(version 1)\n(allow default)\n(deny network-outbound (remote ip))\n' + permitted_connect
        + '(deny network-bind (local ip))\n' + permitted_bind
        + '(deny network-inbound (local ip))\n(allow network-inbound (local tcp))\n'
        + '(deny file-write* (require-not (require-any '
        + f'(subpath {json.dumps(str(root))}) (literal "/dev/null") (literal "/dev/ptmx") '
        + '(regex #"^/dev/ttys[0-9]+$"))))\n',
        encoding="ascii",
    )
    return confinement


class MacGateway:
    def __init__(self,worker,gate,root,initial,check):
        self.worker=worker
        self.gate=gate
        self.root=root
        self.initial=initial
        self.check=check
        self.serial=asyncio.Lock()

    @classmethod
    async def open(cls,root,engine,driver,run,check=False):
        proxy=OfficialProxy()
        proxy_port=proxy.server_address[1]
        worker=None
        try:
            with ExitStack() as context:
                sockets=[context.enter_context(socket.socket()) for _ in range(5)]
                for listener in sockets:
                    listener.bind(("127.0.0.1",0))
                assigned=tuple(listener.getsockname()[1] for listener in sockets)
                config=gateway_policy(root,proxy_port,assigned)
            local=f"http://127.0.0.1:{proxy_port}"
            variables={"HOME":str(root),"TMPDIR":str(root),"PATH":"/usr/bin:/bin",
                       "HTTP_PROXY":local,"HTTPS_PROXY":local,"http_proxy":local,"https_proxy":local,
                       "NO_PROXY":"localhost,127.0.0.1","no_proxy":"localhost,127.0.0.1",
                       "R33_GATEWAY_PORTS":",".join(map(str,assigned))}
            command="check-local-gateway-scope" if check else "serve-local-gateway"
            worker=await asyncio.create_subprocess_exec(
                "/usr/bin/sandbox-exec","-f",str(config),str(driver),command,
                str(engine),str(root),run,env=variables,cwd=root,
                stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,
                stderr=None if check else asyncio.subprocess.DEVNULL,
            )
            initial=decode_frame(await asyncio.wait_for(worker.stdout.readline(),55))
            if (initial.get("account")!="logged-out" or initial.get("pro_observations")!=[]
                    or initial.get("target_signed_out") is not True):
                if check:
                    raise ValueError("Signed-out Mac startup reply: "+json.dumps(initial))
                raise ValueError("The two new native Mac cores did not confirm the signed-out state.")
            (root/"isolated-device").write_text(initial["device"],encoding="ascii")
            return cls(worker,proxy,root,initial,check)
        except BaseException:
            proxy.close()
            if worker and worker.returncode is None:
                worker.stdin.close()
                try:
                    await asyncio.wait_for(worker.wait(),12)
                except asyncio.TimeoutError:
                    worker.terminate()
                    await asyncio.wait_for(worker.wait(),6)
            raise

    async def execute(self,action,fields=None,timeout=55):
        async with self.serial:
            if action=="login" and not self.check:
                (self.root/"login-submitted").touch(exist_ok=False)
                self.gate.activate()
            self.worker.stdin.write(encode_frame({"kind":action,**(fields or {})}))
            await self.worker.stdin.drain()
            return decode_frame(await asyncio.wait_for(self.worker.stdout.readline(),timeout))

    async def stop(self):
        try:
            (self.root/"local-grant-revoked").touch(exist_ok=True)
            last=await self.execute("end",timeout=45)
            self.worker.stdin.close()
            await asyncio.wait_for(self.worker.wait(),8)
            logout=last.get("native_logout")
            if isinstance(logout,dict) and logout.get("native_logout_readback") and logout.get("persisted_after_restart"):
                (self.root/"native-signed-out").touch(exist_ok=True)
            return {"native":last,"provider_network":self.gate.receipt(),"process_exit":self.worker.returncode}
        except (OSError,ValueError,asyncio.TimeoutError):
            self.worker.stdin.close()
            try:
                await asyncio.wait_for(self.worker.wait(),9)
            except asyncio.TimeoutError:
                pass
            return {"normal_exit":"unconfirmed","process_exit":self.worker.returncode,
                    "provider_network":self.gate.receipt()}
        finally:
            self.gate.close()


def current_paid(observation,device):
    return (observation.get("device")==device and observation.get("account")=="logged-in"
            and any(item.get("reported_trial") is False
                    and item.get("expiry_observation") in ("perpetual","not-expired")
                    for item in observation.get("pro_observations",[])))


async def qualify(session, initial, login, operation, stopped):
    expected=initial["device"]
    if stopped.is_set():
        return {"state":"operator-stopped"}
    diagnostic = {"acknowledged": login.get("login_acknowledged") is True}
    failure = login.get("operation_failure")
    if failure in ("outside-scope","lease-closed","native-result-unconfirmed","duplicate-or-busy"):
        diagnostic["operation_failure"] = failure
    native=login.get("login_native_result")
    if isinstance(native,dict) and native.get("stage") in (
        "native-acknowledgment","native-rejection","outcome-unknown","management-failure","input-unavailable"
    ):
        diagnostic["native_result"]={"stage":native["stage"]}
        diagnostic["native_result"].update({
            field:native[field] for field in ("code","http")
            if type(native.get(field)) is int
        })
    counts = login.get("provider_network")
    if isinstance(counts,dict):
        diagnostic["provider_network"] = {
            field: counts[field] for field in
            ("permitted","blocked","verified_public_tls","unexpected_target","failed")
            if type(counts.get(field)) is int and counts[field] >= 0
        }
    if login.get("device") not in (None,expected):
        return {"state":"native-identity-changed","login_diagnostic":diagnostic}

    # A missing mutation acknowledgment is resolved by one state read of the
    # already-started instance. This path never sends the login again.
    license_before=await guarded(session.execute("inspect"), {})
    state=license_before.get("account")
    diagnostic["readback"]=state if state in ("logged-in","logged-out","unknown") else "unavailable"
    if license_before.get("device") not in (None,expected):
        return {"state":"native-identity-changed","login_diagnostic":diagnostic}
    if (license_before.get("device")!=expected or state!="logged-in"
            or license_before.get("version")!=initial.get("version")):
        return {"state":"native-login-unconfirmed","login_diagnostic":diagnostic}
    paid=current_paid(license_before,expected)
    if not paid:
        if stopped.is_set():
            return {"state":"operator-stopped"}
        if license_before.get("device")!=expected or license_before.get("account")!="logged-in":
            return {"state":"native-identity-changed"}
        first_refresh=await session.execute("refresh-paid")
        license_before=await session.execute("inspect")
        paid=current_paid(license_before,expected)
        if not paid:
            return {"state":"existing-paid-license-unconfirmed","license":license_before,
                    "login_diagnostic":diagnostic,
                    "refresh":first_refresh.get("refresh_acknowledged")}
    if stopped.is_set():
        return {"state":"operator-stopped"}
    result=await session.execute(operation)
    return {"state":"observed","paid_instance":license_before,"qualification":result,
            "login_diagnostic":diagnostic}


async def guarded(coro,default):
    try:
        return await coro
    except (OSError,ValueError,asyncio.TimeoutError):
        return default


async def merged_qualifications(mac, linux, linux_initial, stopped, values, mac_operation):
    try:
        mac_login=await guarded(mac.execute("login",values),{}) if not stopped.is_set() else {}
        linux_login=(await guarded(linux.execute("login",values),{})
                     if linux and not stopped.is_set() else {})
    finally:
        values.clear()
    if stopped.is_set():
        return {"operator-stopped":True}
    tasks=[guarded(qualify(mac,mac.initial,mac_login,mac_operation,stopped),
                   {"state":"mac-result-unconfirmed"})]
    if linux:
        tasks.append(guarded(qualify(linux,linux_initial["instance"],linux_login,
                                     "local-api-qualify",stopped),{"state":"linux-result-unconfirmed"}))
    outcome=await asyncio.gather(*tasks)
    return {"gateway":outcome[0],
            "local_api":outcome[1] if linux else {"state":"linux-preflight-unavailable"}}


async def await_operator_stop(stopped,deadline,revoke):
    loop=asyncio.get_running_loop()
    descriptor=sys.stdin.fileno()
    def read():
        if os.read(descriptor,128).strip() in (b"STOP",b""):
            revoke()
    loop.add_reader(descriptor,read)
    try:
        if deadline is None:
            await stopped.wait()
        else:
            await asyncio.wait_for(stopped.wait(),max(0,deadline-time.time()))
    except asyncio.TimeoutError:
        revoke()
    finally:
        loop.remove_reader(descriptor)


def gateway_peer(destination):
    if destination is None:
        return None
    try:
        address=IPv4Address(destination["host"])
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        return None
    return f"{address}:58611"


async def continue_gateway(mac, ssh, qualifications, root, run, stop):
    from r33_gateway_crossnetwork import LinuxGateway, connect, exercise

    if stop.is_set():
        return {"state":"operator-stopped"}
    paid=qualifications.get("gateway",{})
    if paid.get("state")!="observed":
        return {"state":"mac-paid-qualification-unconfirmed"}
    if ssh is None:
        return {"state":"linux-gateway-preflight-unavailable"}
    opened=await guarded(ssh.begin(LinuxGateway,stop),None)
    if opened is None:
        return {"state":"linux-gateway-preflight-unavailable"}
    target,details=opened
    witness=root/"mac-outside-sentinel"
    witness.write_bytes(b"R33 unrelated synthetic Mac data")
    before=witness.read_bytes()
    result={"state":"native-cross-network-unconfirmed"}
    try:
        lane=await guarded(connect(mac,target,details,stop),{})
        if lane.get("ok") is True and not stop.is_set():
            result=await guarded(exercise(mac,target,details,stop,run),result)
            result["paid_mac_observation"]=paid["paid_instance"]
        elif stop.is_set():
            result["state"]="operator-stopped"
        else:
            known=lane.get("code")
            if known in ("selected-native-peer-connect-timed-out","connected-peer-did-not-use-the-selected-native-path"):
                result["state"]=known
        observed=witness.read_bytes()
        result["mac_outside_file"]={"bytes":len(observed),"sha256":sha256(observed).hexdigest(),
                                    "matches":observed==before}
    finally:
        try:
            result["linux_target_cleanup"]=await target.stop()
        finally:
            result["mac_source_cleanup"]=await guarded(mac.execute("gateway-finish"), {})
    return result


async def continue_local_checks(linux, qualification, stop):
    unqualified = {"state": "qualification-required"}
    if stop.is_set() or qualification.get("state") != "observed":
        return unqualified, unqualified, unqualified
    result = qualification.get("qualification")
    if not isinstance(result, dict) or result.get("ok") is not True:
        return unqualified, unqualified, unqualified
    account = result.get("fixed_native_account_observation")
    paid = qualification["paid_instance"]
    routes = result.get("protected_read_routes")
    if (not isinstance(account, dict) or account.get("device") != paid["device"]
            or account.get("version") != paid["version"]
            or result.get("same_paid_device_after_read") is not True
            or result.get("protected_writes") != 0
            or routes != [{"route": "LA-012", "state": "exact-folder-readback",
                           "exact_id": True, "exact_path": True}]):
        return unqualified, unqualified, unqualified
    wrong_id = result.get("wrong_id_control")
    if isinstance(wrong_id, dict) and wrong_id.get("state") == "unexpected-configuration":
        mismatch = {"state": "qualification-returned-config-for-absent-folder"}
        return mismatch, mismatch, mismatch
    files = await guarded(linux.execute("local-api-file-verify", timeout=155, operator_stop=stop), None)
    if not isinstance(files, dict):
        files = {"state": "file-verification-unconfirmed"}
    if files.get("fixture_unregistered") is not True or files.get("device") != paid["device"]:
        needs_cleanup = {"state": "file-fixture-cleanup-required"}
        return files, needs_cleanup, needs_cleanup
    if stop.is_set():
        stopped = {"state": "operator-stopped"}
        return files, stopped, stopped
    peers = await guarded(linux.execute("local-api-peer-verify", timeout=155, operator_stop=stop), None)
    if not isinstance(peers, dict):
        peers = {"state": "peer-verification-unconfirmed"}
    if (peers.get("fixture_unregistered") is not True or peers.get("device") != paid["device"]
            or peers.get("device_restored") is not True or peers.get("secondary_normal_owned_exit") is not True):
        return files, peers, {"state": "peer-fixture-cleanup-required"}
    if stop.is_set():
        return files, peers, {"state": "operator-stopped"}
    observed = await guarded(linux.execute("local-api-config-verify", timeout=155, operator_stop=stop), None)
    if observed is None:
        return files, peers, {"state": "configuration-result-unconfirmed"}
    if observed.get("ok") is True and observed.get("device") != paid["device"]:
        return files, peers, {"state": "configuration-readback-identity-changed"}
    return files, peers, observed


async def execute(args,boundary,engine,driver,run,destination,ordinary_gid,*,linux_payload_digest=None,
                  transport_receipt=None):
    from r33_gateway_crossnetwork import ContinuousMac

    stop=asyncio.Event()
    loop=asyncio.get_running_loop()
    home=boundary.private/"v"/run
    home.mkdir(mode=0o700,parents=True)
    cases=None
    def revoke():
        stop.set()
        (home/"local-grant-revoked").touch(exist_ok=True)
        if cases is not None:
            cases.revoke("foreground-ended")
    for signal_number in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):
        loop.add_signal_handler(signal_number,revoke)
    expiry=loop.call_later(max(0,args.expires_at-time.time()),revoke)
    mac=None
    ssh=None
    linux=None
    linux_status=None
    listener=None
    case_server=None
    entrance=None
    try:
        peer=gateway_peer(destination)
        mac=await ContinuousMac.start(home,engine,driver,run,peer)
        if stop.is_set():
            return
        await verify_native_boundary(args.exchange,run,home,os.getuid(),ordinary_gid,stop)
        if stop.is_set():
            return
        if destination:
            descriptor=APP/"linux-scope.zip"
            payload=await guarded(asyncio.to_thread(hash_file,descriptor),None)
            opened=None
            if payload and (linux_payload_digest is None or payload==linux_payload_digest) and not stop.is_set():
                print("Enter the Linux SSH password at the OpenSSH prompt.",flush=True)
                opened=await guarded(
                    LinuxForeground.open(destination,home,APP/"r33_linux_qualification_bootstrap.py",
                                         descriptor,payload,run,args.expires_at),
                    None,
                )
            if opened:
                ssh,_=opened
                print("Linux SSH is connected for this test session.",flush=True)
                qualified=await guarded(ssh.begin(LinuxQualification,stop),None)
                if qualified:
                    linux,linux_status=qualified
            else:
                print("The selected Linux test session could not be opened.",flush=True)
        if stop.is_set():
            return
        publish(args.exchange,"native-ready",{"run":run,"mac_signed_out":True,"linux_ready":linux is not None})
        values=await read_credentials(stop)
        listener=asyncio.create_task(await_operator_stop(stop,args.expires_at,revoke))
        results=await merged_qualifications(mac,linux,linux_status,stop,values,"inspect")
        publish(args.exchange,"qualification",{"run":run,"result":results})
        if linux is not None:
            files, peers, config = await continue_local_checks(linux, results.get("local_api", {}), stop)
            publish(args.exchange, "local-api-files", {"run": run, "result": files})
            publish(args.exchange, "local-api-peers", {"run": run, "result": peers})
            publish(args.exchange, "local-api-config", {"run": run, "result": config})
            cleanup=await linux.stop()
            linux=None
            publish(args.exchange,"local-api-cleanup",{"run":run,"result":cleanup})
        if peer is not None:
            result=await continue_gateway(mac,ssh,results,home,run,stop)
            publish(args.exchange,"cross-network",{"run":run,"result":result})
        if not stop.is_set():
            entrance=TemporaryDirectory(prefix="r33-client-",dir=TMP)
            address=Path(entrance.name)/"b.sock"
            transport=address.parent.stat()
            journal=Journal(transport_receipt or home/"owned-case-receipts.jsonl",run)
            journal.record("owner-transport-paths", private=str(home), public=str(address.parent),
                           public_device=transport.st_dev, public_inode=transport.st_ino)
            cases=Supervisor(run,os.getuid(),journal,boundary.group,executor_group=ordinary_gid,
                             expires_at=args.expires_at)
            if results.get("gateway", {}).get("state") == "observed":
                cases.scopes["pro"]=Scope("pro",mac.named_cases,
                                         {"observe"} | TWO_CORE_SCOPES["pro-cases"].keys(),journal)
            case_server=await asyncio.start_unix_server(cases.connection,str(address),limit=FRAME_MAX,backlog=16)
            if not stop.is_set():
                address.chmod(0o666)
                address.parent.chmod(0o711)
                ready={"run":run,"socket":str(address)}
                publish(args.exchange,"ready",ready)
                print("R33_READY "+json.dumps(ready),flush=True)
                await cases.done.wait()
                revoke()
    finally:
        expiry.cancel()
        revoke()
        if listener is not None:
            listener.cancel()
            await asyncio.gather(listener,return_exceptions=True)
        async def stop_mac():
            if cases is not None and "pro" in cases.scopes:
                return await cases.stopping["pro"]
            return await mac.stop() if mac else {"state":"not-opened"}
        mac_done,linux_done=await asyncio.gather(
            stop_mac(),
            ssh.stop() if ssh else asyncio.sleep(0,result={"state":"not-opened"}),
        )
        if case_server is not None:
            case_server.close()
            await case_server.wait_closed()
            for client in tuple(cases.clients):
                client.close()
        if entrance is not None:
            entrance.cleanup()
        publish(args.exchange,"stopped",{"run":run,"mac":mac_done,"linux":linux_done})
        print("R33_QUALIFICATION_STOPPED "+json.dumps({"run":run,"receipt":str(args.exchange/"stopped.json")}),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group-private",required=True,type=Path)
    parser.add_argument("--expires-at",type=int)
    parser.add_argument("--exchange",type=Path)
    parser.add_argument("--driver-sha256",required=True)
    parser.add_argument("--bundle-sha256")
    parser.add_argument("--check-only",action="store_true")
    parser.add_argument("--recover-run")
    args=parser.parse_args()
    boundary=GroupBoundary.current(args.group_private)
    require_private_terminal(boundary)
    if APP.parent!=boundary.private:
        raise ValueError("The agreed test session is unavailable.")
    driver=APP/"bin"/"verysync-r33-operator"
    if hash_file(driver)!=args.driver_sha256:
        raise ValueError("The gateway test driver did not verify.")
    private_executable(driver)
    engine=APP/"official-v2.33.2"
    if args.recover_run:
        return recover(boundary,engine,driver,args.recover_run)
    if args.exchange is None:
        raise ValueError("The agreed test session is unavailable.")
    remaining_seconds(args.expires_at)
    exchange_path(args.exchange)
    extract_engine(APP/"engine.zip",engine)
    run=secrets.token_hex(16)
    if args.check_only:
        print("R33_QUALIFICATION_PREPARED "+json.dumps({"run":run,"driver_checked":True}),flush=True)
        return 0
    subprocess.run(
        ["/usr/bin/python3","-E","-s","-B",str(APP/"r33_isolation.py"),"operator",
         "--executor-uid",str(os.getuid()),"--record",str(APP/"isolation.json"),
         "--group-private",str(boundary.private),"--run",run,"--exchange",str(args.exchange)],
        check=True,
    )
    proof=read_proof(APP/"isolation.json",os.getuid(),boundary)
    if proof.get("run")!=run:
        raise ValueError("The local isolation evidence belongs to another session.")
    destination=linux_destination()
    linux_payload_digest=None
    if destination:
        try:
            linux_payload_digest=hash_file(APP/"linux-scope.zip")
        except OSError:
            print("The Linux test bundle is unavailable. The isolated Mac tests can continue.",flush=True)
            destination=None
    if not confirm_combined(run,args.expires_at,destination=destination,state_root=boundary.private/"v"/run,
                            bundle_digest=args.bundle_sha256,driver_digest=args.driver_sha256,
                            linux_payload_digest=linux_payload_digest,
                            gateway_port=58611 if gateway_peer(destination) else None):
        return 0
    remaining_seconds(args.expires_at)
    asyncio.run(execute(args,boundary,engine,driver,run,destination,proof["executor_group"],
                        linux_payload_digest=linux_payload_digest,transport_receipt=APP/"operator-receipt.jsonl"))
    return 0


def recover(boundary,engine,driver,run):
    if not re.fullmatch(r"[a-f0-9]{32}",run):
        raise ValueError("The original qualification run was not identified.")
    root=boundary.private/"v"/run
    if root.resolve()!=root or not (root/"login-submitted").is_file():
        raise ValueError("No matching private account recovery was found.")
    proxy=OfficialProxy()
    try:
        proxy_port=proxy.server_address[1]
        with ExitStack() as resources:
            sockets=[resources.enter_context(socket.socket()) for _ in range(5)]
            for listener in sockets:
                listener.bind(("127.0.0.1",0))
            config=gateway_policy(root,proxy_port,[listener.getsockname()[1] for listener in sockets])
        local=f"http://127.0.0.1:{proxy_port}"
        variables={"HOME":str(root),"TMPDIR":str(root),"PATH":"/usr/bin:/bin",
                   "HTTP_PROXY":local,"HTTPS_PROXY":local,"http_proxy":local,"https_proxy":local,
                   "NO_PROXY":"localhost,127.0.0.1","no_proxy":"localhost,127.0.0.1"}
        worker=subprocess.run(
            ["/usr/bin/sandbox-exec","-f",str(config),str(driver),"recover-gateway-signout",
             str(engine),str(root),run],
            env=variables,cwd=root,check=True,capture_output=True,timeout=65,
        )
        final=decode_frame(worker.stdout)
        if not (final.get("ok") and final.get("same_owned_device") and final.get("native_logout_readback") and final.get("normal_owned_exit")
                and (final.get("persisted_after_restart") or final.get("already_signed_out"))):
            raise ValueError("The original native account sign-out needs confirmation.")
        (root/"native-signed-out").touch(exist_ok=True)
        print("R33_QUALIFICATION_RECOVERED "+json.dumps(final),flush=True)
        return 0
    finally:
        proxy.close()


if __name__=="__main__":
    os.umask(0o077)
    try:
        raise SystemExit(main())
    except OperatorCancelled:
        print("The operator cancelled this test session.",flush=True)
        raise SystemExit(0) from None
    except (OSError,ValueError,EOFError,KeyboardInterrupt,subprocess.SubprocessError):
        print("The temporary qualification did not finish. Review its local receipt.",file=sys.stderr,flush=True)
        raise SystemExit(2) from None
