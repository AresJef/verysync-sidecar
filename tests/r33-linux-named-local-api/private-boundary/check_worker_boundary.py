"""Exercise the actual Linux mount, network and account socket with no account."""

import errno
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time

from linux_account_connector import NativeAccountConnector, UnixOfficialProxy, namespace_peer_allowed
from linux_private_boundary import launch_arguments, namespace, open_boundary, relinquish_admin


HERE = Path(__file__).resolve()
SAMPLE = b"This is a synthetic isolated state marker.\n"
OFFICIAL = b"CONNECT my.verysync.com:443 HTTP/1.1\r\n\r\n"
OTHER = b"CONNECT example.invalid:443 HTTP/1.1\r\n\r\n"


def open_exchange(port, request):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as link:
        link.sendall(request)
        return link.recv(1024)


def protected_worker(folder, uid, gid, net_before, mount_before):
    base = Path(folder)
    state = base / "state"
    info = open_boundary(state, int(uid), int(gid), int(net_before), int(mount_before))
    relinquish_admin(int(uid), int(gid))
    probe = state / "sample"
    probe.write_bytes(SAMPLE)
    route = NativeAccountConnector(base / "authorization.sock", 0)
    try:
        info.update({"uid":os.getuid(), "port":route.server_address[1]})
        print(json.dumps(info), flush=True)
        if input() != "TEST":
            raise ValueError("Expected the synthetic test instruction.")
        assert open_exchange(route.server_address[1], OFFICIAL).startswith(b"HTTP/1.1 403 ")
        assert open_exchange(route.server_address[1], OTHER).startswith(b"HTTP/1.1 403 ")
        assert probe.read_bytes() == SAMPLE
        print(json.dumps({"contained_handoff":True,"original_file_preserved":True}), flush=True)
        if input() != "STOP":
            raise ValueError("Expected the synthetic STOP.")
    finally:
        route.close()
    print(json.dumps({"connector_closed":True,"normal_exit":True}), flush=True)


def outside_observer(folder, port):
    base = Path(folder)
    try:
        with (base / "state" / "sample").open("rb"):
            raise ValueError("An outside runtime identity reached private state.")
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.ENOENT):
            raise
        isolation = errno.errorcode[error.errno]
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as route:
        route.settimeout(3)
        route.connect(str(base / "authorization.sock"))
        try:
            route.sendall(OFFICIAL)
            refused = not route.recv(1024)
        except (BrokenPipeError, ConnectionResetError):
            refused = True
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=2):
            raise ValueError("The restricted connector is reachable outside its network.")
    except ConnectionRefusedError:
        refused_port = True
    print(json.dumps({"same_runtime_uid":os.getuid(),"state_read":isolation,
                      "authorization_socket_refused":refused,"loopback_port_refused":refused_port}))


def take(worker):
    if not select.select([worker.stdout], [], [], 15)[0]:
        raise TimeoutError("The owned worker did not return a bounded receipt.")
    return json.loads(worker.stdout.readline(8193))


def verify(disposable_uid, disposable_gid):
    port_denials = []
    namespace_seen = {}
    with tempfile.TemporaryDirectory(prefix="r33-licensed-boundary-", dir="/tmp") as folder:
        base = Path(folder).resolve()
        os.chown(base, 0, disposable_gid)
        base.chmod(0o710)
        state = base / "state"
        state.mkdir(mode=0o700)
        original_device = state.stat().st_dev

        def same_network_only(conn):
            approved = namespace_seen.get("network_namespace")
            result = approved is not None and namespace_peer_allowed(conn, approved, disposable_uid)
            if not result:
                port_denials.append(time.monotonic())
            return result

        address = base / "authorization.sock"
        proxy = UnixOfficialProxy(address, same_network_only)
        try:
            os.chown(address, 0, disposable_gid)
            address.chmod(0o660)
            net, mount = namespace("net"), namespace("mnt")
            entry = ["/usr/bin/python3", "-B", str(HERE), "--inside", str(base),
                     *map(str,(disposable_uid, disposable_gid, net, mount))]
            child = subprocess.Popen(launch_arguments(entry), stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, start_new_session=True)
            try:
                namespace_seen.update(take(child))
                assert namespace_seen["uid"] == disposable_uid
                assert namespace_seen["network_namespace"] != net and namespace_seen["mount_namespace"] != mount
                assert namespace_seen["only_loopback"] and namespace_seen["volatile_private_state"]
                observer = subprocess.run(
                    ["/usr/bin/setpriv", "--reuid", str(disposable_uid), "--regid", str(disposable_gid),
                     "--clear-groups", "/usr/bin/python3", "-B", str(HERE), "--outside",
                     str(base), str(namespace_seen["port"])],
                    timeout=8, check=True, capture_output=True,
                )
                outer = json.loads(observer.stdout)
                assert outer["same_runtime_uid"] == disposable_uid
                assert outer["loopback_port_refused"] and outer["authorization_socket_refused"]
                assert len(port_denials) == 1
                child.stdin.write(b"TEST\n")
                child.stdin.flush()
                fixture = take(child)
                assert fixture == {"contained_handoff":True,"original_file_preserved":True}
                expected = {"permitted":0,"blocked":1,"verified_public_tls":0,
                            "unexpected_target":1,"failed":0}
                assert proxy.receipt() == expected
                child.stdin.write(b"STOP\n")
                child.stdin.flush()
                assert take(child) == {"connector_closed":True,"normal_exit":True}
                assert child.wait(timeout=10) == 0
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=10)
            assert state.stat().st_dev == original_device and list(state.iterdir()) == []
        finally:
            proxy.close()
        assert not address.exists()
    print("R33_LINUX_ACCOUNT_BOUNDARY " + json.dumps({
        "private_worker":namespace_seen,"outside_attempt":outer,"upstream_requests":0,
        "provider_window_closed":True,"normal_exit":True,"directory_removed":not base.exists(),
    }, sort_keys=True))


if __name__ == "__main__":
    os.umask(0o077)
    args = sys.argv[1:]
    if len(args) == 6 and args[0] == "--inside":
        protected_worker(*args[1:])
    elif len(args) == 3 and args[0] == "--outside":
        outside_observer(*args[1:])
    elif len(args) == 3 and args[0] == "--synthetic-hosted" and os.getuid() == 0:
        verify(*map(int,args[1:]))
    else:
        raise SystemExit("Use the disposable signed-out workflow.")
