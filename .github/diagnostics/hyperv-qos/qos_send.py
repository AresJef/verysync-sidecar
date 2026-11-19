"""Set a native per-socket DSCP on a disposable Windows TCP sender."""

from contextlib import contextmanager
import ctypes as c
import hashlib
import json
import os
import socket
import sys
import time

from qos_payload import CLASSES, PEERS, PORT, SIZE, sample

QOS_NON_ADAPTIVE_FLOW = 2
QOS_TRAFFIC_TYPE_BEST_EFFORT = 0
QOS_SET_OUTGOING_DSCP_VALUE = 2
DWORD = c.c_uint32
HANDLE = c.c_void_p


class Version(c.Structure):
    _fields_ = [("major", c.c_ushort), ("minor", c.c_ushort)]


@contextmanager
def per_socket_qos(net, traffic_class):
    if traffic_class == 0:
        yield {"stage": "unmodified", "winerror": 0}
        return
    try:
        api = c.WinDLL("qwave.dll", use_last_error=True)
    except OSError as error:
        yield {"stage": "load", "winerror": error.winerror}
        return
    api.QOSCreateHandle.argtypes = [c.POINTER(Version), c.POINTER(HANDLE)]
    api.QOSAddSocketToFlow.argtypes = [HANDLE, c.c_size_t, c.c_void_p, c.c_int, DWORD, c.POINTER(DWORD)]
    api.QOSSetFlow.argtypes = [HANDLE, DWORD, c.c_int, DWORD, c.c_void_p, DWORD, c.c_void_p]
    api.QOSCloseHandle.argtypes = [HANDLE]
    handle = HANDLE()
    if not api.QOSCreateHandle(c.byref(Version(1, 0)), c.byref(handle)):
        yield {"stage": "create", "winerror": c.get_last_error()}
        return
    try:
        flow = DWORD()
        if not api.QOSAddSocketToFlow(
            handle, net.fileno(), None, QOS_TRAFFIC_TYPE_BEST_EFFORT,
            QOS_NON_ADAPTIVE_FLOW, c.byref(flow)
        ):
            yield {"stage": "add", "winerror": c.get_last_error()}
            return
        dscp = DWORD(traffic_class >> 2)
        applied = bool(api.QOSSetFlow(
            handle, flow, QOS_SET_OUTGOING_DSCP_VALUE, c.sizeof(dscp), c.byref(dscp), 0, None,
        ))
        yield {"stage": "set", "winerror": 0 if applied else c.get_last_error(), "dscp": dscp.value}
    finally:
        if not api.QOSCloseHandle(handle):
            raise c.WinError(c.get_last_error())


def connect(af, source, target):
    deadline = time.monotonic() + 35
    while True:
        net = socket.socket(af, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        try:
            net.settimeout(0.75)
            net.bind((source, 0))
            net.connect((target, PORT))
            net.settimeout(12)
            return net
        except OSError:
            net.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)


def main():
    if sys.platform != "win32" or os.environ.get("OWNED_HYPERV_QOS_CONTROL") != "true":
        raise RuntimeError("Use only the disposable Windows comparison runner")
    for family, af, source, target in PEERS:
        for traffic_class in CLASSES:
            data = sample(family, traffic_class)
            digest = hashlib.sha256(data).digest()
            with connect(af, source, target) as net, per_socket_qos(net, traffic_class) as qos:
                source_port = net.getsockname()[1]
                print("QOS_API " + json.dumps({
                    "family": family, "class": traffic_class, "source_port": source_port, **qos,
                }), flush=True)
                net.sendall(data)
                net.shutdown(socket.SHUT_WR)
                with net.makefile("rb") as reply:
                    if reply.read(32) != digest or reply.read(1):
                        raise ValueError("The independent receiver did not confirm the exact payload")
            print("QOS_SENT " + json.dumps({
                "family": family, "class": traffic_class, "source_port": source_port,
                "bytes": SIZE, "sha256": digest.hex(), "socket_closed": True,
            }), flush=True)
    print("QOS_CONTROL_WINDOWS_FINISH cases=6", flush=True)


if __name__ == "__main__":
    main()
