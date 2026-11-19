"""Exact transfer over the one-use Windows-to-Hyper-V receiver links."""
import hashlib
import json
import socket
import time

ADDR = (
    (socket.AF_INET, "192.0.2.1", "192.0.2.2"),
    (socket.AF_INET6, "2001:db8:73f:43::1", "2001:db8:73f:43::2"),
)


def tcp(family, source, target, deadline):
    last = None
    while time.monotonic() < deadline:
        net = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        try:
            net.settimeout(1.5)
            net.bind((source, 0))
            net.connect((target, 47527))
            return net
        except OSError as e:
            last = e
            net.close()
            time.sleep(0.4)
    raise TimeoutError(f"isolated TCP to {target} from {source} failed: {last}") from last


def main():
    sample = hashlib.shake_256(b"synthetic Hyper-V link bytes").digest(1_048_576)
    digest = hashlib.sha256(sample).hexdigest()
    deadline = time.monotonic() + 120
    for family, source, target in ADDR:
        with tcp(family, source, target, deadline) as net:
            if net.getsockname()[0] != source or net.getpeername()[0] != target:
                raise RuntimeError("observed TCP path differs from fixture endpoints")
            net.settimeout(12)
            net.sendall(sample)
            net.shutdown(socket.SHUT_WR)
            echoed = bytearray()
            while chunk := net.recv(65_536):
                echoed.extend(chunk)
                if len(echoed) > len(sample):
                    raise RuntimeError("echo exceeded the synthetic sample")
            if echoed != sample:
                raise RuntimeError("receiver returned different bytes")
            print("HYPERV_LINK_ACTUAL " + json.dumps({
                "ip_version": 4 if family == socket.AF_INET else 6,
                "source": source, "receiver": target, "bytes": len(echoed), "sha256": digest,
            }, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
