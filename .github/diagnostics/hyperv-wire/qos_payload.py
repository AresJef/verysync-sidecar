"""Shared parameters for the isolated native TCP comparison."""

import os
import socket

PEERS = (
    (4, socket.AF_INET, "192.0.2.1", "192.0.2.2"),
    (6, socket.AF_INET6, "2001:db8:73f:43::1", "2001:db8:73f:43::2"),
)
CLASSES = (0, 16, 32)
MECHANISM = os.environ.get("OWNED_HYPERV_QOS_MECHANISM", "qwave")
PORT = {"qwave": 47529, "winsock": 47531}[MECHANISM]
SIZE = 262_181


def sample(family, traffic_class):
    return bytes(((i * 73) ^ (i >> 7) ^ family ^ traffic_class ^ 0xA5) & 255 for i in range(SIZE))
