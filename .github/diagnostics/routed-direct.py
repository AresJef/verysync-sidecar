"""Run fixed native peers in runner-owned network namespaces with no default route."""
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time

FAMILIES = {
    "4": ("192.0.2.2/30", "192.0.2.1/30", "198.51.100.2/30", "198.51.100.1/30"),
    "6": ("2001:db8:1::2/64", "2001:db8:1::1/64", "2001:db8:2::2/64", "2001:db8:2::1/64"),
}


def ip(*args):
    completed = subprocess.run(
        ["sudo", "-n", "ip", *args], capture_output=True, text=True
    )
    if completed.returncode:
        raise RuntimeError(f"ip {args}: {completed.stderr.strip()}")
    return completed.stdout.strip()


def configure(names, family):
    left, router, right = names
    a, a_gateway, b, b_gateway = FAMILIES[family]
    for name in names:
        ip("-n", name, "link", "set", "lo", "up")
    for edge, gateway_device, host, gateway in (
        (left, "left", a, a_gateway),
        (right, "right", b, b_gateway),
    ):
        ip("-n", edge, "link", "add", "peer", "type", "veth", "peer", "name", gateway_device, "netns", router)
        for namespace, device, address in (
            (edge, "peer", host),
            (router, gateway_device, gateway),
        ):
            add = ["-" + family, "-n", namespace, "addr", "add", address, "dev", device]
            if family == "6":
                add.append("nodad")
            ip(*add)
            ip("-n", namespace, "link", "set", device, "up")
    forwarding = "net.ipv4.ip_forward=1" if family == "4" else "net.ipv6.conf.all.forwarding=1"
    ip("netns", "exec", router, "sysctl", "-qw", forwarding)
    for edge, host, gateway, other in ((left, a, a_gateway, b), (right, b, b_gateway, a)):
        dest = other.split("/")[0]
        next_hop = gateway.split("/")[0]
        ip("-" + family, "-n", edge, "route", "add", f"{dest}/{32 if family == '4' else 128}", "via", next_hop, "dev", "peer")
        route = json.loads(ip("-" + family, "-n", edge, "-j", "route", "get", dest))[0]
        if route.get("gateway") != next_hop or route.get("dev") != "peer":
            raise RuntimeError("the configured route did not select the isolated router")
        print(f"ROUTED_PATH family=IPv{family} src={host.split('/')[0]} dst={dest} next_hop={next_hop}", flush=True)
    for name in names:
        for version in ("-4", "-6"):
            if ip(version, "-n", name, "route", "show", "default"):
                raise RuntimeError("unexpected default route in a test namespace")
    return a.split("/")[0], b.split("/")[0]


def read_router_bytes(router):
    result = {}
    for interface in ("left", "right"):
        data = json.loads(ip("-n", router, "-j", "-s", "link", "show", "dev", interface))[0]
        result[interface] = [data["stats64"][direction]["bytes"] for direction in ("rx", "tx")]
    return result


def wait_ready(processes):
    until = time.monotonic() + 50
    while time.monotonic() < until:
        if all((root / "ready.json").is_file() for _, root, _ in processes):
            return
        if any(process.poll() is not None for process, _, _ in processes):
            raise RuntimeError("owned node stopped before publishing its private receipt")
        time.sleep(0.15)
    raise TimeoutError("owned node startup timed out")


def validate_processes(processes, names):
    core_pids = []
    for (_, root, _), namespace in zip(processes, (names[0], names[2]), strict=True):
        text = (root / "node.log").read_text(encoding="utf-8")
        match = re.search(r"^ROUTED_NODE core_pid=(\d+) ready$", text, re.MULTILINE)
        if not match:
            raise RuntimeError("managed process ID was not published")
        pid = int(match[1])
        if ip("netns", "identify", str(pid)) != namespace:
            raise RuntimeError("managed core did not start in its assigned namespace")
        core_pids.append(pid)
    if len(set(core_pids)) != 2:
        raise RuntimeError("managed process IDs were not independent")
    print("ROUTED_PROCESS distinct_namespace_core_ids=true default_route_absent_both_families=true", flush=True)


def stop_all(processes):
    for process, _, _ in processes:
        if process.stdin is not None:
            process.stdin.close()
    for process, root, log in processes:
        try:
            process.wait(timeout=32)
        except subprocess.TimeoutExpired:
            continue
        finally:
            log.close()
    for process, root, _ in processes:
        diagnostic = (root / "node.log").read_text(encoding="utf-8")
        for line in diagnostic.splitlines():
            if line.startswith(("ROUTED_NODE ", "RECEIVER_CLASS_APPLIED ", "Error: ", "thread ", "assertion ")):
                print(line, flush=True)
        if process.returncode != 0 or "ROUTED_NODE normal_exit " not in diagnostic:
            raise RuntimeError("owned process failed its normal exit condition")


def check_wire(namespace, family, addresses, processes, binary, parent, selected):
    receiver = json.loads((processes[1][1] / "ready.json").read_text())
    port = int(receiver["peer_address"].rsplit(":", 1)[1])
    tool = str(Path(__file__).with_name("receive-headers.py"))
    observer = subprocess.Popen(
        ["sudo", "-n", "ip", "netns", "exec", namespace, "env",
         "RUNNER_DISPOSABLE_RX=true", sys.executable, tool, family, *addresses, str(port)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        ready, _, _ = select.select([observer.stdout], [], [], 5)
        if not ready or observer.stdout.readline().strip() != "RECEIVER_HEADERS_READY":
            raise RuntimeError("the receiver header observer did not become ready")
        transfer = subprocess.run(
            [binary, "transfer", str(parent / "a"), str(parent / "b")],
            text=True, capture_output=True, timeout=130,
        )
        print(transfer.stdout, end="", flush=True)
        if transfer.returncode:
            print(transfer.stderr, end="", flush=True)
            transfer.check_returncode()
        first = next(line for line in transfer.stdout.splitlines()
                     if line.startswith("ROUTED_EFFECT first_bytes="))
        authenticated_source_port = int(first.rsplit(":", 1)[1])
    finally:
        snapshot, diagnostic = observer.communicate(input="", timeout=35)
        if observer.returncode:
            raise RuntimeError("receiver capture did not exit normally: " + diagnostic)
    if not snapshot.startswith("RECEIVER_HEADERS "):
        raise RuntimeError("receiver header receipt is absent")
    rows = json.loads(snapshot.removeprefix("RECEIVER_HEADERS "))
    matched = [row for row in rows if row["source_port"] == authenticated_source_port]
    selected_rows = [row for row in matched if row["class_octet"] & 0xfc == selected]
    proof = {
        "ip_version": int(family),
        "sender_policy": selected,
        "native_authenticated_source_port": authenticated_source_port,
        "receiver_destination_port": port,
        "actual_receiver_headers": matched,
        "matching_header_count": sum(row["packets"] for row in selected_rows),
        "separate_receiver_link": True,
        "observer_normal_exit": True,
    }
    print("ROUTED_HEADER_OBSERVED " + json.dumps(proof, sort_keys=True), flush=True)
    if not selected_rows or (selected == 0 and matched != selected_rows):
        raise RuntimeError("requested DSCP octet absent from the actual authenticated TCP data")


def main():
    family = sys.argv[1]
    binary = str(Path(sys.argv[2]).resolve(strict=True))
    selected = int(sys.argv[3])
    if selected not in (16, 32, 0):
        raise ValueError("explicit tested class required")
    original_namespaces = set(ip("netns", "list").splitlines())
    parent = Path(tempfile.mkdtemp(dir="/tmp", prefix="vsy-"))
    namespaces = [parent.name + "-" + side for side in ("a", "r", "b")]
    created = []
    processes = []
    try:
        for name in namespaces:
            ip("netns", "add", name)
            created.append(name)
        addresses = configure(namespaces, family)
        before = read_router_bytes(namespaces[1])
        for namespace, address, side in zip((namespaces[0], namespaces[2]), addresses, ("a", "b"), strict=True):
            root = parent / side
            root.mkdir(mode=0o700)
            log = (root / "node.log").open("w", encoding="utf-8")
            env = [f"{var}={os.environ[var]}" for var in ("VERYSYNC_TEST_BINARY", "VERYSYNC_TEST_BINARY_SHA256")]
            process = subprocess.Popen(
                ["sudo", "-n", "ip", "netns", "exec", namespace, "setpriv",
                 f"--reuid={os.getuid()}", f"--regid={os.getgid()}", "--init-groups",
                 "--", "env", *env, binary, "node", str(root), address,
                 *([str(selected)] if side == "a" else [])],
                stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT,
            )
            processes.append((process, root, log))
        wait_ready(processes)
        validate_processes(processes, namespaces)
        check_wire(namespaces[2], family, addresses, processes, binary, parent, selected)
        after = read_router_bytes(namespaces[1])
        deltas = {side: [b - a for a, b in zip(before[side], after[side], strict=True)] for side in before}
        if not all(byte_count > 0 for entry in deltas.values() for byte_count in entry):
            raise RuntimeError("the isolated router did not count traffic in both directions on both links")
        print("ROUTED_COUNTERS " + json.dumps(deltas, sort_keys=True), flush=True)
    finally:
        try:
            stop_all(processes)
        finally:
            remaining = {name: ip("netns", "pids", name) for name in created}
            for name, pids in remaining.items():
                if not pids:
                    ip("netns", "delete", name)
            if any(remaining.values()):
                raise RuntimeError("owned namespaces still had processes during cleanup")
            if set(ip("netns", "list").splitlines()) != original_namespaces:
                raise RuntimeError("the runner's namespace inventory changed outside this fixture")
            shutil.rmtree(parent)
            print(f"ROUTED_CLEANUP family=IPv{family} private_tree_removed=true namespace_inventory_restored=true", flush=True)


if __name__ == "__main__":
    main()
