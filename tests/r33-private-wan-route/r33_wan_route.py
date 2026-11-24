"""One owned TCP ingress to a native test instance in a Linux network namespace."""

from contextlib import ExitStack
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
import os
from pathlib import Path
import re
import subprocess


IP = "/usr/sbin/ip"
FILTER = "/usr/sbin/iptables"
PORT = 58611


def run(*args, allowed=(0,)):
    result = subprocess.run(args, check=False, capture_output=True, text=True, timeout=8)
    if result.returncode not in allowed:
        raise RuntimeError(f"The isolated route operation failed ({Path(args[0]).name}).")
    return result


@dataclass(frozen=True)
class Route:
    run_id: str
    source: IPv4Address
    ingress: IPv4Address
    space: IPv4Network

    @classmethod
    def for_connection(cls, run_id, source, ingress):
        if not re.fullmatch(r"[a-f0-9]{32}", run_id):
            raise ValueError("The test route needs its existing fixed run ID.")
        source, ingress = IPv4Address(source), IPv4Address(ingress)
        if source == ingress or any(value.is_unspecified or value.is_multicast or value.is_loopback
                                    for value in (source, ingress)):
            raise ValueError("Use the verified IPv4 SSH origin and destination.")
        first = int(IPv4Address("198.18.0.0")) + 4 * int(run_id[-4:], 16) % (1 << 17)
        space = IPv4Network((first, 30))
        if source in space or ingress in space:
            raise ValueError("The selected peers overlap the private test link.")
        return cls(run_id, source, ingress, space)

    @property
    def name(self):
        return "r33gw-" + self.run_id[:8]

    @property
    def outer(self):
        return "gwo" + self.run_id[:9]

    @property
    def inner(self):
        return "gwi" + self.run_id[:9]

    @property
    def host(self):
        return self.space.network_address + 1

    @property
    def target(self):
        return self.space.network_address + 2

    def inside(self, *args):
        return (IP, "netns", "exec", self.name, *args)

    def filter(self, table, action, chain, rules):
        return (FILTER, "-w", "3", "-t", table, action, chain, *rules)

    def rules(self):
        origin = ("-s", f"{self.source}/32")
        receiver = ("-d", f"{self.target}/32")
        tag = ("-m", "comment", "--comment", self.name)
        incoming = ("-o", self.outer, *origin, *receiver, "-p", "tcp", "--dport", str(PORT))
        reply = ("-i", self.outer, "-s", f"{self.target}/32", "-d", f"{self.source}/32",
                 "-p", "tcp", "--sport", str(PORT))
        return (
            ("nat", "PREROUTING",
             (*origin, "-d", f"{self.ingress}/32", "-p", "tcp", "--dport", str(PORT),
              *tag, "-j", "DNAT", "--to-destination", f"{self.target}:{PORT}")),
            ("filter", "FORWARD",
             (*incoming, "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED", *tag, "-j", "ACCEPT")),
            ("filter", "FORWARD",
             (*reply, "-m", "conntrack", "--ctstate", "ESTABLISHED", *tag, "-j", "ACCEPT")),
        )

    def withdraw_rule(self, table, chain, rule):
        run(*self.filter(table, "-D", chain, rule))
        if run(*self.filter(table, "-C", chain, rule), allowed=(0,1)).returncode != 1:
            raise RuntimeError("The exact temporary route rule remains present.")

    def open(self, undo):
        if os.geteuid() != 0:
            raise PermissionError("Preparing the leased route needs the authorized administrator.")
        if Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() != "1":
            raise ValueError("The host does not currently route IPv4 to an isolated test network.")
        conflicts = run(IP, "-4", "route", "show", "exact", str(self.space)).stdout.strip()
        if conflicts:
            raise ValueError("The proposed isolated address range already has a route.")
        listeners = run("/usr/bin/ss", "-Hln", "sport", "=", f":{PORT}").stdout.strip()
        if listeners:
            raise ValueError("The dedicated test port already has an unrelated listener.")

        run(IP, "netns", "add", self.name)
        undo.callback(run, IP, "netns", "del", self.name)
        run(*self.inside("/usr/sbin/sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1",
                         "net.ipv6.conf.default.disable_ipv6=1"))
        run(IP, "link", "add", self.outer, "type", "veth", "peer", "name", self.inner)
        undo.callback(run, IP, "link", "del", self.outer)
        run(IP, "link", "set", self.inner, "netns", self.name)
        run(IP, "addr", "add", f"{self.host}/30", "dev", self.outer)
        run(IP, "link", "set", self.outer, "up")
        run(*self.inside(IP, "link", "set", self.inner, "name", "r33-data"))
        run(*self.inside(IP, "addr", "add", f"{self.target}/30", "dev", "r33-data"))
        run(*self.inside(IP, "link", "set", "r33-data", "up"))
        run(*self.inside(IP, "link", "set", "lo", "up"))
        run(*self.inside(IP, "-4", "route", "add", f"{self.source}/32", "via", str(self.host), "dev", "r33-data"))

        # Only replies from the one TCP listener may leave the namespace.
        run(*self.inside(FILTER, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"))
        run(*self.inside(FILTER, "-A", "OUTPUT", "-o", "r33-data", "-d", f"{self.source}/32",
                         "-p", "tcp", "--sport", str(PORT), "-m", "conntrack",
                         "--ctstate", "ESTABLISHED", "-j", "ACCEPT"))
        run(*self.inside(FILTER, "-P", "OUTPUT", "DROP"))
        run(*self.inside(FILTER, "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"))
        run(*self.inside(FILTER, "-A", "INPUT", "-i", "r33-data", "-s", f"{self.source}/32",
                         "-p", "tcp", "--dport", str(PORT), "-m", "conntrack",
                         "--ctstate", "NEW,ESTABLISHED", "-j", "ACCEPT"))
        run(*self.inside(FILTER, "-P", "INPUT", "DROP"))
        if run(*self.inside(IP, "-4", "route", "show", "default")).stdout.strip():
            raise ValueError("The isolated target unexpectedly has a general IPv4 route.")

        # The host rules are limited to this test's origin, link, destination and port.
        for table, chain, rule in self.rules():
            run(*self.filter(table, "-I", chain, rule))
            undo.callback(self.withdraw_rule, table, chain, rule)

    def packet_count(self):
        cells = run(FILTER, "-w", "3", "-t", "nat", "-L", "PREROUTING", "-nvx").stdout.splitlines()
        selected = [line.split() for line in cells if f"/* {self.name} */" in line]
        if len(selected) != 1:
            raise ValueError("The exact dedicated ingress counter was not found.")
        return int(selected[0][0])

    def cleared(self):
        if run(IP, "link", "show", self.outer, allowed=(0,1)).returncode == 0:
            return False
        if any(line.split()[0] == self.name for line in run(IP, "netns", "list").stdout.splitlines() if line):
            return False
        return all(run(*self.filter(table, "-C", chain, rule), allowed=(0,1)).returncode == 1
                   for table, chain, rule in self.rules())


def open_owned(route):
    guard = ExitStack()
    try:
        route.open(guard)
    except BaseException:
        guard.close()
        raise
    return guard
