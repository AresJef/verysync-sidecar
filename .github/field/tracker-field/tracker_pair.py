"""Two fresh nodes, three allowlisted TLS tracker hosts, one bounded observation."""
import argparse
from contextlib import contextmanager, ExitStack
from datetime import datetime
import grp
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit

import run_wan as w
from signal_link import Signal, local_project_token

BASELINE="99ee1036b70b9b115df26ca76c57559e7dc038a3"
HOSTS={"control.verysync.cn","control-v4.verysync.cn","control-v6.verysync.cn"}


def load_proxy(source):
    spec=importlib.util.spec_from_file_location("exact_tracker_proxy",source/"scripts/run-official-tracker-test.py")
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.HOSTS==HOSTS
    return module


@contextmanager
def isolated_process(root, args, runtime_env):
    if args.role=="mac":
        profile=root/"seated-local-only.sb"
        profile.write_text('(version 1)(allow default)(deny network-outbound)'
             '(allow network-outbound (remote ip "localhost:*") (remote unix-socket))'
             f'(deny file-write* (require-not (require-any (subpath {json.dumps(str(root))}) '
             '(literal "/dev/null") (literal "/dev/ptmx") (regex #"^/dev/ttys[0-9]+$"))))\n')
        yield ["/usr/bin/sandbox-exec","-f",str(profile)]
        return
    assert os.environ.get("GITHUB_ACTIONS")=="true" and os.environ.get("RUNNER_OS")=="Linux"
    name="vstr"+secrets.token_hex(5)
    with ExitStack() as release:
        w.local_command(["sudo","-n","groupadd",name])
        release.callback(w.local_command,["sudo","-n","groupdel",name])
        group=grp.getgrnam(name)
        for family in ("iptables","ip6tables"):
            command=["sudo","-n",family,"-w","3"]
            chain=name.upper()
            w.local_command([*command,"-N",chain])
            release.callback(w.local_command,[*command,"-X",chain])
            release.callback(w.local_command,[*command,"-F",chain])
            w.local_command([*command,"-A",chain,"-o","lo","-j","RETURN"])
            w.local_command([*command,"-A",chain,"-j","REJECT"])
            rule=["-m","owner","--gid-owner",str(group.gr_gid),"-j",chain]
            w.local_command([*command,"-I","OUTPUT","1",*rule])
            release.callback(w.local_command,[*command,"-D","OUTPUT",*rule])
        launcher=["sudo","-n","/usr/bin/setpriv","--reuid",str(os.getuid()),"--regid",
                  str(group.gr_gid),"--clear-groups","/usr/bin/env",
                  *[f"{key}={value}" for key,value in runtime_env.items()]]
        trial=w.local_command([*launcher,"/usr/bin/id","-g"])
        assert int(trial)==group.gr_gid, "owned Linux tracker group could not be observed"
        yield launcher


def public_candidates(items):
    found=[]
    for text in items:
        try:
            url=urlsplit(text)
            host=ipaddress.IPv4Address(url.hostname or "")
            port=url.port
        except ValueError:
            continue
        if url.scheme in ("tcp","udp","quic") and host.is_global and port and port>1024 and port!=18886:
            found.append({"transport":url.scheme,"host":str(host),"port":port})
    return found


def listener_ip():
    # A UDP socket connect selects the IPv4 route; no payload is sent.
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as test:
        test.connect(("192.0.2.1",9))
        source=test.getsockname()[0]
    with socket.socket() as reserved:
        reserved.bind((source,0))
        return "%s:%d" % reserved.getsockname()


def run_fixture(args, link, report):
    proxy_module=load_proxy(args.source)
    other="linux" if args.role=="mac" else "mac"
    with tempfile.TemporaryDirectory(prefix="vstf.",dir="/private/tmp" if args.role=="mac" else None) as scratch:
        root=Path(scratch)
        engine=root/"owned-tracker-core"
        shutil.copyfile(args.engine,engine)
        engine.chmod(0o700)
        assert w.digest(engine.read_bytes())==args.sha
        control=root/"cut-owned-tracker"
        token=secrets.token_hex(32)
        with proxy_module.TrackerProxy(control,token) as proxy:
            worker=threading.Thread(target=proxy.serve_forever,kwargs={"poll_interval":0.1},daemon=True)
            worker.start()
            active_at=None
            closed_at=None
            owner_exit=None
            timer=None
            def cut_proxy():
                nonlocal closed_at
                if not control.exists():
                    control.write_text(token)
                proxy.activate_fault_if_requested()
                if closed_at is None:
                    closed_at=time.monotonic()
            endpoint=f"http://127.0.0.1:{proxy.server_address[1]}"
            environment={"PATH":os.environ["PATH"],"HOME":str(root),"TMPDIR":str(root),
                         "HTTP_PROXY":endpoint,"HTTPS_PROXY":endpoint,"ALL_PROXY":endpoint,
                         "NO_PROXY":"127.0.0.1,localhost,::1"}
            if "RUNNER_TRACKING_ID" in os.environ:
                environment["RUNNER_TRACKING_ID"]=os.environ["RUNNER_TRACKING_ID"]
            try:
                with isolated_process(root,args,environment) as launcher:
                    mode="sender" if args.role=="mac" else "receiver"
                    command=[*launcher,str(args.driver),str(engine),args.sha,str(root/"node"),listener_ip(),mode]
                    owner=subprocess.Popen(command,env=environment,cwd=root,stdin=subprocess.DEVNULL,
                                           stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    try:
                        report["phase"]="native_launch"
                        ready=w.read_event(owner.stdout,40)
                        assert ready["event"]=="ready" and ready["version"]=="v2.33.2"
                        assert w.DEVICE.fullmatch(ready["device"])
                        report["phase"]="sealed_rendezvous"
                        message={"device":ready["device"],"read_only_share":ready["read_only_share"]}
                        link.put(args.role+"-ready",message)
                        remote=link.wait(other+"-ready",145)
                        assert w.DEVICE.fullmatch(remote["device"]) and remote["device"]!=ready["device"]
                        link.put(args.role+"-peer-ready",{"paired":True})
                        peer_ready=link.wait(other+"-peer-ready",35)
                        assert peer_ready["paired"] is True
                        report["phase"]="tracker_observation"
                        plan={"peer":remote["device"],"read_only_share":remote["read_only_share"]}
                        temp=root/"node/peer-plan.pending"
                        w.write_private(temp,plan)
                        active_at=time.monotonic()
                        timer=threading.Timer(83,cut_proxy)
                        timer.daemon=True
                        timer.start()
                        temp.rename(root/"node/peer-plan.json")
                        native=w.read_event(owner.stdout,95)
                        assert native["event"]=="result"
                        owner_exit=owner.wait(8)
                        report["normal_exit"]=owner_exit==0 and native["normal_exit"]
                        public=public_candidates(native["reported_candidates"])
                        report["tracker_native_registered"]=native["tracker_registered"]
                        report["tracker_only_dynamic_target"]=native["dynamic_target_configured"]
                        report["public_peer_candidates"]=len(public)
                        report["actual_peer_connection"]=native["actual_peer_connection"]
                        report["native_mapping_disabled"]=native["native_mapping_disabled"]
                        report["tracker_turned_off"]=native["tracker_turned_off"]
                        report["private_identity_retained"]=native["isolated_identity_preserved"]
                        if public:
                            link.put(args.role+"-candidate",{"matches":public,"device":ready["device"]})
                    finally:
                        if owner.poll() is not None and owner.returncode != 0:
                            error=owner.stderr.read(4096).decode("utf-8","replace")
                            categories={"PermissionDenied":"permission","Operation not permitted":"permission",
                                        "Permission denied":"permission","Address already in use":"address_in_use",
                                        "error while loading shared libraries":"loader",
                                        "not allowed to execute":"launcher_authority","Bad system call":"syscall",
                                        "No such file or directory":"missing_file","timed out":"timeout",
                                        "sudo:":"sudo","setpriv:":"setpriv"}
                            report["launch_error_categories"]=sorted({code for text,code in categories.items() if text in error})
                            report["driver_exit"]=owner.returncode
                        if owner.poll() is None:
                            owner.terminate()
                            try:
                                owner.wait(8)
                            except subprocess.TimeoutExpired:
                                owner.kill()
                                owner.wait(5)
                        for stream in (owner.stdout,owner.stderr): stream.close()
                    listing=subprocess.run(["pgrep","-f","^"+str(engine)+r"( |$)"],
                                           capture_output=True,timeout=5)
                    report["exact_engine_cleanup"]=listing.returncode==1
                    assert report["exact_engine_cleanup"]
            finally:
                cut_proxy()
                if timer:
                    timer.cancel()
                    timer.join(2)
                proxy.shutdown()
                worker.join(3)
                report["tracker_tunnel_count"]=proxy.upgrade_connections
                report["approved_scope_only_proxy"]=True
                report["proxy_rejected_requests"]=sum(proxy.observed.values())
                report["egress_window_seconds"]=round(closed_at-active_at,3) if active_at else 0
    report["private_work_removed"]=not root.exists()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("role",choices=["mac","linux"])
    for name in ("source","engine","driver","receipt"):
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--sha",required=True)
    parser.add_argument("--key-file",type=Path)
    args=parser.parse_args()
    os.umask(0o077)
    key=args.key_file.read_text().strip() if args.role=="mac" else os.environ.pop("UDP_SIGNAL_KEY")
    token=local_project_token() if args.role=="mac" else os.environ.pop("UDP_PROJECT_TOKEN")
    session=hashlib.sha256(bytes.fromhex(key)).hexdigest()[:20]
    report={"role":args.role,"session_digest":session,
            "stable_source":BASELINE,"allowed_tls_hosts":sorted(HOSTS),
            "reported_private_addresses_published":False,"native_file_transfer_attempted":False,
            "status":"failed"}
    try:
        run_fixture(args,Signal(token,key,session),report)
        report["status"]="observed" if report["normal_exit"] and report["exact_engine_cleanup"] else "failed"
    except (AssertionError,OSError,RuntimeError,subprocess.SubprocessError,ValueError) as error:
        report["failure_type"]=type(error).__name__
        if type(error)==RuntimeError:
            report["failure_reason"]=str(error)
    finally:
        w.write_private(args.receipt,report)
        print(json.dumps(report))
    return 0 if report["status"]=="observed" else 1


if __name__=="__main__":
    raise SystemExit(main())
