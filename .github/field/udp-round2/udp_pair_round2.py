"""Exercise one matched same-port UDP route with sealed, project-owned signaling."""
import argparse
import contextlib
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tempfile
import time
from urllib.error import HTTPError

import run_wan as owned
from signal_link import Signal, local_project_token
from stun_binding_observation import HOST, PORT, encode_binding, mapped_address


BASELINE = "99ee1036b70b9b115df26ca76c57559e7dc038a3"


def mapped_candidate(link, key, other, sock, role, report):
    report["stun_stage"] = "started"
    endpoint = socket.getaddrinfo(HOST, PORT, socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)[0][4]
    owned.require(ipaddress.IPv4Address(endpoint[0]).is_global, "nonpublic STUN resolver response")
    tx = secrets.token_bytes(12)
    sock.settimeout(4)
    sock.sendto(encode_binding(tx), endpoint)
    report["stun_packets_sent"] = 1
    raw, source = sock.recvfrom(1500)
    owned.require(source == endpoint, "unexpected STUN source")
    address, port = mapped_address(raw, tx)
    owned.require(address.is_global and 1024 < port <= 65535 and port not in (18886, 3478, 1900, 5351),
                  "STUN did not allocate a suitable peer endpoint")
    report["stun_stage"] = "mapping_verified"
    report["stun_advertised_alternate_attribute"] = any_stun_alternate(raw)
    link.put(role + "-mapping", {"host": str(address), "port": port})
    peer = link.wait(other + "-mapping", 35)
    remote = (str(ipaddress.IPv4Address(peer["host"])), int(peer["port"]))
    owned.require(ipaddress.IPv4Address(remote[0]).is_global and 1024 < remote[1] <= 65535
                  and remote[1] not in (18886, 3478, 1900, 5351), "unsafe sealed test-to-test address")
    sent = marker(key, role)
    expected = marker(key, other)
    sock.settimeout(0.25)
    observed = None
    window = time.monotonic() + 15
    while time.monotonic() < window:
        sock.sendto(sent, remote)
        try:
            incoming, candidate = sock.recvfrom(128)
        except TimeoutError:
            continue
        if candidate[0] == remote[0] and hmac.compare_digest(incoming, expected):
            observed = candidate
            # A short tail gives the other endpoint time to verify our marker.
            for _ in range(6):
                sock.sendto(sent, observed)
                time.sleep(0.15)
            break
    report["authenticated_inbound_udp"] = observed is not None
    link.put(role + "-probe", {"observed": observed is not None})
    peer_result = link.wait(other + "-probe", 35)
    report["authenticated_outbound_udp"] = peer_result["observed"] is True
    if observed is None or not report["authenticated_outbound_udp"]:
        return None
    owned.require(1024 < observed[1] <= 65535 and observed[1] not in (18886, 3478, 1900, 5351), "unsafe negotiated test port")
    report["authenticated_bidirectional_udp"] = True
    return observed


def any_stun_alternate(packet):
    import struct
    offset = 20
    while offset + 4 <= len(packet):
        tag, length = struct.unpack_from("!HH", packet, offset)
        if tag in (0x0005, 0x802c):
            return True
        offset = (offset + 4 + length + 3) & ~3
    return False


def marker(key, role):
    return b"VSP2" + hmac.digest(bytes.fromhex(key), b"owned-udp-control-v1|" + role.encode(), "sha256")


def state(control, peer, connected):
    info = control("observe")
    if not connected:
        return info.get("connected") is False
    if info.get("connected") is not True:
        return False
    owned.require(info["direction"] in ("quic_client", "quic_server"), "unexpected actual peer protocol")
    raw = info["address"] or ""
    ip, _, port = raw.removeprefix("udp://").removeprefix("quic://").rpartition(":")
    owned.require(str(ipaddress.IPv4Address(ip)) == peer[0] and 1024 < int(port) <= 65535,
                  "authenticated native device used another network path")
    return {"protocol": info["direction"], "global_test_peer_observed": True, "port": int(port)}


@contextlib.contextmanager
def udp_cut(peer, local_port, tag):
    owned.require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_OS") == "Linux",
                  "rule requires the dedicated hosted Linux peer")
    prefix = ["sudo", "-n", "iptables", "-w", "3"]
    outbound = ["-p", "udp", "-d", peer[0]+"/32", "--dport", str(peer[1]), "--sport", str(local_port)]
    inbound = ["-p", "udp", "-s", peer[0]+"/32", "--sport", str(peer[1]), "--dport", str(local_port)]
    finish = ["-m", "comment", "--comment", "vs-udp-field-" + tag[:14], "-j", "DROP"]
    with contextlib.ExitStack() as release:
        for direction, match in (("OUTPUT", outbound), ("INPUT", inbound)):
            command = match + finish
            owned.local_command([*prefix, "-I", direction, "1", *command])
            release.callback(owned.local_command, [*prefix, "-D", direction, *command])
        yield


def data_case(args, runtime, report, signal, peer, raw_socket, local_port):
    role = args.mode
    other = "linux" if role == "mac" else "mac"
    args.external_udp_port = peer[1]
    marker_bytes = marker(signal.key, role)
    with owned.node(args, runtime, report) as (root, identity, control):
        raw_socket.sendto(marker_bytes, peer)
        local = {"device": identity}
        if role == "mac":
            first, second = secrets.token_bytes(owned.SIZE), secrets.token_bytes(owned.SIZE)
            local["digest1"], local["digest2"] = [owned.digest(sample) for sample in (first, second)]
            local["read_only_share"] = control("source")["receive_share"]
            (root / "synthetic/first.bin").write_bytes(first)
        signal.put(role + "-native-ready", local)
        remote = signal.wait(other + "-native-ready", 55)
        owned.require(owned.DEVICE.fullmatch(remote["device"]) and remote["device"] != identity,
                      "invalid isolated remote identity")
        raw_socket.sendto(marker_bytes, peer)
        signals_ready = role + "-native-switch"
        signal.put(signals_ready, {"ready": True})
        signal.wait(other + "-native-switch", 25)
        raw_socket.close()
        plan = {"peer": remote["device"], "dial": f"{peer[0]}:{peer[1]}", "udp_port": local_port}
        if role == "linux":
            plan["read_key"] = remote["read_only_share"]
            report["receiver_initially_empty"] = not (root / "synthetic/first.bin").exists()
        owned.write_private(root / "field-plan.json", plan)
        control("prepare_udp")
        route = owned.bounded(lambda: state(control, peer, True), 70)
        report["actual_direct_quic"] = {"protocol": route["protocol"], "global_test_peer_observed": True}
        file1, file2 = [root / "synthetic" / name for name in ("first.bin", "second.bin")]
        if role == "mac":
            signal.wait("linux-cut-active", 120)
            file2.write_bytes(second)
            control("scan")
            report["first_file_retained"] = owned.matched_file(file1, local["digest1"])
            report["observed_disconnect"] = owned.bounded(lambda: state(control, peer, False), 78)
            signal.put("mac-cut-observed", {"disconnect": True})
            signal.wait("linux-cut-released", 30)
            owned.bounded(lambda: state(control, peer, True), 70)
            signal.wait("linux-native-done", 90)
            report["generated_digests"] = [local["digest1"],local["digest2"]]
        else:
            owned.bounded(lambda: owned.matched_file(file1, remote["digest1"]), 65)
            report["first_file"] = {"bytes": owned.SIZE, "sha256": owned.digest(file1.read_bytes())}
            with udp_cut((peer[0], route["port"]), local_port, owned.digest(signal.key.encode())):
                signal.put("linux-cut-active", {"active": True})
                until = time.monotonic() + 85
                observed = False
                while time.monotonic() < until:
                    owned.require(owned.matched_file(file1, remote["digest1"]) and not file2.exists(),
                                  "receiver data changed during the exact UDP cutoff")
                    observed = observed or state(control, peer, False)
                    if observed and signal.read("mac-cut-observed"):
                        break
                    time.sleep(1)
                else:
                    raise TimeoutError("native peers did not both register the approved UDP cutoff")
                report["observed_disconnect"] = True
                report["receiver_retained_first_and_second_absent_during_cut"] = True
            report["runner_rules_released"] = True
            signal.put("linux-cut-released", {"released": True})
            owned.bounded(lambda: state(control, peer, True), 70)
            owned.bounded(lambda: owned.matched_file(file2, remote["digest2"]), 65)
            report["second_file"] = {"bytes": owned.SIZE, "sha256": owned.digest(file2.read_bytes())}
            owned.require(owned.matched_file(file1, remote["digest1"]), "original file changed after recovery")
            signal.put("linux-native-done", {"first": report["first_file"], "second": report["second_file"]})


def round_two(args, link, report):
    role = args.mode
    other = "linux" if role == "mac" else "mac"
    with tempfile.TemporaryDirectory(prefix="vsudp2.", dir="/private/tmp" if role == "mac" else None) as scratch:
        runtime = Path(scratch)
        owned.require(owned.digest(args.engine.read_bytes()) == args.sha, "supplied fixed engine does not match")
        # The rendezvous and wire protocol use no local or network credentials from the real service.
        link.put(role + "-ready", {"ready": True})
        link.wait(other + "-ready", 420 if role == "mac" else 150)
        if role == "mac":
            link.put("mac-start", {"utc_epoch": int(time.time()) + 5})
        barrier = link.wait("mac-start", 20)
        seconds = barrier["utc_epoch"] - time.time()
        owned.require(-4 < seconds < 12, "expired or untrusted coordinated test window")
        time.sleep(max(seconds, 0))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as raw:
            raw.bind(("0.0.0.0", 0))
            local_port = raw.getsockname()[1]
            peer = mapped_candidate(link, link.key, other, raw, role, report)
            if peer is None:
                return
            data_case(args, runtime, report, link, peer, raw, local_port)
            report["native_public_pair_file_recovery"] = True


def main():
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["mac","linux"])
    for name in ("example","engine","control","receipt"):
        p.add_argument("--"+name, type=Path, required=True)
    p.add_argument("--sha", required=True)
    p.add_argument("--key-file", type=Path)
    args=p.parse_args()
    os.umask(0o077)
    if args.mode == "mac":
        key=args.key_file.read_text().strip()
        token=local_project_token()
    else:
        owned.require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_OS") == "Linux",
                      "native paired test requires its explicit hosted job")
        key=os.environ.pop("UDP_SIGNAL_KEY")
        token=os.environ.pop("UDP_PROJECT_TOKEN")
    session_id=hashlib.sha256(bytes.fromhex(key)).hexdigest()[:20]
    report={"role":args.mode,"session_digest":session_id,"stable_source":BASELINE,"status":"failed","native_public_pair_file_recovery":False,
            "authorization_scope":"round_two","public_test_addresses_logged":False,"router_manual_changes":False}
    try:
        round_two(args, Signal(token,key,session_id), report)
        report["status"]="observed"
    except (OSError, ValueError, RuntimeError, AssertionError, subprocess.SubprocessError) as error:
        report["failure_class"]=type(error).__name__
        if isinstance(error, HTTPError):
            report["http_status"] = error.code
        if type(error)==RuntimeError:
            report["failure_reason"]=str(error)
    finally:
        owned.write_private(args.receipt, report)
        print(json.dumps(report))
    return 0 if report["status"]=="observed" else 1


if __name__=="__main__":
    raise SystemExit(main())
