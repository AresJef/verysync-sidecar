"""Run the paid native gateway against the selected bounded Linux target."""

import asyncio
from contextlib import ExitStack
from hashlib import sha256
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import time

from r33_accounts import read_credentials
from r33_handoff import Channel
from r33_licensed_validation import MacGateway, await_operator_stop, guarded, qualify
from r33_linux_qualification_session import LinuxQualification
from r33_native import NativeAccount, environment, scoped_preflight
from r33_official_proxy import OfficialProxy
from r33_prepare import hash_file
from r33_protocol import FRAME_MAX, decode_frame
from r33_rendezvous import publish, verify_native_boundary


APP=Path(__file__).resolve().parent


def sandbox(root, proxy, ports, peer, *, case_ports=()):
    listeners = (*ports, *case_ports)
    used = (proxy, *listeners)
    if (len(ports) != (2 if peer else 0) or len(case_ports) not in (0, 2)
            or len(set(used)) != len(used) or 18886 in used):
        raise ValueError("Mac test listeners must be private and distinct.")
    egress = ""
    if peer:
        raw_peer, raw_port = peer.rsplit(":", 1)
        address, data_port = IPv4Address(raw_peer), int(raw_port)
        if data_port in used or not 1024 <= data_port <= 65535 or data_port == 18886 or (
            not address.is_loopback and data_port != 58611
        ):
            raise ValueError("The selected native peer must use the scoped test port.")
        # The driver validates the sole selected IPv4 address and native route.
        socket_rule = f"{'localhost' if address.is_loopback else '*'}:{data_port}"
        egress = f'(allow network-outbound (remote tcp {json.dumps(socket_rule)}))\n'
    binds="".join(f'(allow network-bind (local tcp "localhost:{port}"))\n' for port in listeners)
    connects="".join(f'(allow network-outbound (remote tcp "localhost:{port}"))\n'
                     for port in used)
    file=root/"selected-gateway.sb"
    file.write_text('(version 1)\n(allow default)\n'
        '(deny network-outbound (remote ip))\n' + connects
        + egress
        + '(deny network-bind (local ip))\n' + binds
        + '(deny network-inbound (local ip))\n(allow network-inbound (local tcp))\n'
        + '(deny file-write* (require-not (require-any '
        + f'(subpath {json.dumps(str(root))}) (literal "/dev/null") (literal "/dev/ptmx") '
        + '(regex #"^/dev/ttys[0-9]+$"))))\n',encoding="ascii")
    return file


class SplitGateway(MacGateway):
    include_local_cases = False

    @classmethod
    async def start(cls, root, engine, driver, run, peer, *, synthetic=False):
        if peer is None and not cls.include_local_cases:
            raise ValueError("A selected peer is required for the standalone gateway fixture.")
        proxy=OfficialProxy()
        child=None
        try:
            with ExitStack() as holders:
                gateway_count = 2 if peer else 0
                count = gateway_count + (2 if cls.include_local_cases else 0)
                sockets=[holders.enter_context(socket.socket()) for _ in range(count)]
                for listener in sockets:
                    listener.bind(("127.0.0.1",0))
                assigned = tuple(listener.getsockname()[1] for listener in sockets)
                ports, case_ports = assigned[:gateway_count], assigned[gateway_count:]
                proxy_port=proxy.server_address[1]
                profile=sandbox(root,proxy_port,ports,peer,case_ports=case_ports)
                variables=environment(root,proxy_port)
                if peer:
                    variables.update(R33_SELECTED_GATEWAY_PEER=peer,
                                     R33_SPLIT_GATEWAY_PORTS=",".join(map(str,ports)))
                if cls.include_local_cases:
                    variables["R33_AUDIT_P2P_PORTS"] = ",".join(map(str,case_ports))
                    await scoped_preflight(driver, profile, proxy_port, variables)
            if cls.include_local_cases:
                command = "serve"
                if peer:
                    command = "check-unified-gateway" if synthetic else "serve-unified-gateway"
            else:
                command="check-split-gateway" if synthetic else "serve-split-gateway"
            child=await asyncio.create_subprocess_exec(
                "/usr/bin/sandbox-exec","-f",str(profile),str(driver),command,
                str(engine),str(root),run,stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,
                stderr=None if synthetic else asyncio.subprocess.DEVNULL,env=variables,cwd=root,
                limit=FRAME_MAX,start_new_session=cls.include_local_cases)
            initial=decode_frame(await asyncio.wait_for(child.stdout.readline(),46))
            ready = initial.get("event") == "owned-source-ready" if peer else initial.get("ok") is True
            if (not ready or initial.get("account")!="logged-out"
                    or initial.get("version")!="2.33.2" or initial.get("pro_observations")!=[]):
                raise ValueError("The selected Mac source did not confirm its private start.")
            (root/"isolated-device").write_text(initial["device"],encoding="ascii")
            return cls(child,proxy,root,initial,synthetic)
        except BaseException:
            proxy.close()
            if child and child.returncode is None:
                child.stdin.close()
                try:
                    await asyncio.wait_for(child.wait(),14)
                except asyncio.TimeoutError:
                    child.terminate()
                    await asyncio.wait_for(child.wait(),5)
            raise


class ContinuousMac(SplitGateway):
    include_local_cases = True

    def __init__(self, worker, gate, root, initial, check):
        super().__init__(worker, gate, root, initial, check)
        self.channel = Channel(worker)
        self.named_cases = NativeAccount(self.channel, gate, root, initial, "pro-cases")

    async def execute(self, action, fields=None, timeout=63):
        def before_send():
            if action == "login" and not self.check:
                if (self.root / "local-grant-revoked").exists():
                    raise ValueError("The local test authorization has ended.")
                (self.root / "login-submitted").touch(exist_ok=False)
                self.gate.activate()

        return await self.channel.call({"kind": action, **(fields or {})}, before_send, deadline=timeout)

    async def stop(self):
        self.named_cases.mark_revoked()
        if (self.root / "login-submitted").exists():
            return await self.named_cases.stop((), None)
        normal = await self.named_cases.end_owned()
        return {"state": "signed-out-control", "normal_owned_exit": normal,
                "official_network": self.gate.receipt()}


class LinuxGateway(LinuxQualification):
    ready_event="native-gateway-foreground-ready"
    live_scope="native-target"

    async def stop(self):
        if self.heartbeat:
            self.heartbeat.cancel()
            await asyncio.gather(self.heartbeat,return_exceptions=True)
        try:
            await self.write({"kind":"stop","run":self.run})
            last=await self.read(54)
            cleared=await self.read(9)
            if (last.get("event")!="native-gateway-target-stopped" or last.get("run")!=self.run
                    or cleared!={"event":"native-gateway-target-cleanup","run":self.run,
                                "exact_route_removed":True,"private_state_removed":True}):
                raise ValueError("The target cleanup was not associated with this run.")
            staging=await self.finish_staging()
            # The final direct observation can include addresses for diagnostics.
            # Retain only its effect and the owned ingress packet count.
            native=last.get("native",{})
            restored=last.get("target_changed_restored") or {}
            return {"normal_native_exit":native.get("normal") is True and last.get("exit_code")==0,
                    "final_files_preserved":restored.get("files_match") is True,
                    "final_permission_revoked":(restored.get("peer") or {}).get("allowed") is False,
                    "remaining_label_baseline":restored.get("label")=="Owned gateway baseline",
                    "native_tcp_ingress_count":last.get("dedicated_connection_count"),
                    "directory_and_ingress_removed":True,
                    "staging_removed":staging.get("temporary_programs_removed") is True,
                    "role_stopped":True,"ssh_exit":self.child.returncode}
        except (OSError,ValueError,asyncio.TimeoutError):
            await self.close_unconfirmed()
            return {"lscope":"native-gateway-cleanup-unconfirmed","ssh_exit":self.child.returncode}


async def connect(source,target,details,stop=None):
    peer=details["target"]
    local_device=source.initial["internal_device_id"]
    approved_device=peer["internal_device_id"]
    if local_device==approved_device or peer.get("engine")!="v2.33.2":
        raise ValueError("The target is not the confirmed isolated peer.")
    if stop is not None and stop.is_set():
        return {"ok":False,"code":"operator-stopped"}
    seen=await target.execute("register",{"peer":local_device})
    if seen.get("folder_exact") is not True:
        raise ValueError("The signed-out target did not register this source.")
    if stop is not None and stop.is_set():
        return {"ok":False,"code":"operator-stopped"}
    registered=await source.execute("gateway-target",{"peer":approved_device,
                                                     "private_gui_port":peer["private_gui_port"]})
    if registered.get("target_registered") is not True:
        raise ValueError("The Mac could not register this target.")
    if stop is not None and stop.is_set():
        return {"ok":False,"code":"operator-stopped"}
    return await source.execute("gateway-transport")


async def exercise(source, target, details, stop, run, *, synthetic=False):
    peer=details["target"]
    known_baseline=peer["observation"]["before"]
    expected_key=details["synthetic_target_key"]
    approved_device=peer["internal_device_id"]
    result={"target_alias":sha256((run+approved_device).encode("ascii")).hexdigest(),
            "source_alias":source.initial["device"],"scope":"split-synthetic" if synthetic else "native-cross-network"}
    if stop.is_set():
        return result|{"state":"operator-stopped-before-gateway-prepare"}

    def allowed(response, fact):
        if response.get(fact) is not True:
            raise ValueError("The owned gateway action did not confirm "+fact+".")
    try:
        first=await source.execute("gateway-prepare")
        allowed(first,"denied_before_grant")
        result["denied_before_grant"]=True
        result["source_native_path"]=first["path"]
        if stop.is_set():
            return result|{"state":"operator-stopped-before-target-grant"}
        confirmed=await target.execute("allow")
        peer_state=confirmed["peer"]
        if not peer_state["connected"] or peer_state["allowed"] is not True or (
            peer_state["native_transport"]!="PeerConnectionType::TcpServer"
        ) or (not synthetic and peer_state["reported_local"] is not False):
            raise ValueError("The target did not confirm the native TCP server connection.")
        result["target_native_tcp_server"]=True
        result["target_reports_local"]=peer_state["reported_local"]
        if stop.is_set():
            return result|{"state":"operator-stopped-before-gateway-write"}
        result["gateway"]=await guarded(source.execute("gateway-write",{
            "synthetic_target_key":expected_key,"synthetic_wrong_key":secrets.token_hex(32)}),{})
        readback=await target.execute("state")
        result["independent_target_change"]=readback["label"]=="Owned gateway change"
        result["samples_before_and_observed_match"]=readback["files_match"] is True and readback["actual"]==known_baseline
        result["target_files_before"]=known_baseline
    finally:
        restored=await guarded(target.execute("restore"),{})
        result["target_independent_restore"]=restored.get("label")=="Owned gateway baseline"
        result["target_permission_revoked"]=(restored.get("peer") or {}).get("allowed") is False
        result["target_files_preserved"]=restored.get("files_match") is True and restored.get("actual")==known_baseline
        result["target_files_after"]=restored.get("actual",[])
        revoked=await guarded(source.execute("gateway-revoke"),{})
        result["denied_after_revocation"]=revoked.get("denied_after_revocation") is True
    return result


async def execute(args,boundary,engine,driver,run,destination,gid):
    target_ip=IPv4Address(destination["host"])
    if target_ip.is_loopback or target_ip.is_unspecified or target_ip.is_multicast:
        raise ValueError("Use the same verified public IPv4 Linux target.")
    root=boundary.private/"v"/"run"
    root.mkdir(mode=0o700,parents=True)
    witness=root/"mac-outside-sentinel"
    witness.write_bytes(b"R33 unrelated synthetic Mac data")
    before=witness.read_bytes()
    stop=asyncio.Event()
    loop=asyncio.get_running_loop()
    def revoke():
        stop.set()
        (root/"local-grant-revoked").touch(exist_ok=True)
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):
        loop.add_signal_handler(sig,revoke)
    expiry=loop.call_later(max(0,args.expires_at-time.time()),revoke)
    mac=linux=listener=None
    try:
        print("Enter the Linux SSH password at the OpenSSH prompt.",flush=True)
        payload=APP/"linux-scope.zip"
        linux,ready=await LinuxGateway.open(destination,root,APP/"r33_linux_qualification_bootstrap.py",
                                           payload,hash_file(payload),run,args.expires_at)
        if stop.is_set():
            return
        mac=await SplitGateway.start(root,engine,driver,run,f"{target_ip}:58611")
        await verify_native_boundary(args.exchange,run,root,os.getuid(),gid,stop)
        publish(args.exchange,"ready",{"run":run,"mac_signed_out":True,
            "linux_target":{"network_scope_verified":ready["boundary"]["private_state"],
                            "version":ready["target"]["engine"],"dedicated_tcp_ingress":58611}})
        listener=asyncio.create_task(await_operator_stop(stop,args.expires_at,revoke))
        lane=await guarded(connect(mac,linux,ready),{})
        if lane.get("ok") is not True:
            known=lane.get("code")
            if known not in ("selected-native-peer-connect-timed-out","connected-peer-did-not-use-the-selected-native-path"):
                known="selected-peer-transport-unconfirmed"
            publish(args.exchange,"cross-network",{"run":run,"result":{"state":known,"paid_login_sent":False}})
            print("The dedicated native connection was not confirmed. Type STOP or press Ctrl+C to release this test session.",flush=True)
            await stop.wait()
            return
        if stop.is_set():
            return
        listener.cancel()
        await asyncio.gather(listener,return_exceptions=True)
        credentials=await read_credentials(stop)
        listener=asyncio.create_task(await_operator_stop(stop,args.expires_at,revoke))
        try:
            first=await guarded(mac.execute("login",credentials),{})
        finally:
            credentials.clear()
        admission=await qualify(mac,mac.initial,first,"inspect",stop)
        if admission.get("state")=="observed" and not stop.is_set():
            sanitized=await guarded(exercise(mac,linux,ready,stop,run),{"state":"native-cross-network-unconfirmed"})
            sanitized["paid_mac_observation"]=admission["paid_instance"]
            after=witness.read_bytes()
            sanitized["mac_outside_file"]={"bytes":len(after),"sha256":sha256(after).hexdigest(),"matches":before==after}
        else:
            sanitized={"state":admission.get("state"),"login_diagnostic":admission.get("login_diagnostic")}
        publish(args.exchange,"cross-network",{"run":run,"result":sanitized})
        print("The cross-network result is available. Type STOP or press Ctrl+C to release this test session.",flush=True)
        await stop.wait()
    finally:
        revoke()
        expiry.cancel()
        if listener:
            listener.cancel()
            await asyncio.gather(listener,return_exceptions=True)
        a,b=await asyncio.gather(
            mac.stop() if mac else asyncio.sleep(0,result={"state":"not-opened"}),
            linux.stop() if linux else asyncio.sleep(0,result={"state":"not-opened"}),
        )
        publish(args.exchange,"stopped",{"run":run,"mac":a,"linux":b})
