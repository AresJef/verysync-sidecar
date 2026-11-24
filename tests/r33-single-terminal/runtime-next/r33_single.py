"""The fixed one-terminal acceptance inventory and its user confirmation text."""

from datetime import datetime
import json
from pathlib import Path
import re
import time

from r33_cases import TWO_CORE_SCOPES
from r33_ssh import Destination, private_identity


CRATE = "1d1e7d0d3ef4ac4dcf063b8e4d3ac336bd823fd056e5aae84c5dbaaf24d6cbfe"
NATIVE = "v2.33.2"
LINUX_ALLOWED = frozenset(("observe", "start-observer", "finish-observer", "write-sample"))
FIXTURES = (
    ("VS-041-W", "Prepare, seed, observe and remove watch, interval and UTC calendar tasks."),
    ("VS-033-S5", "Test file, directory and root selections, deselection and removal across the two test peers."),
    ("VS-040", "Populate and page the test audit history, reset it and verify the files and prior settings."),
    ("VS-042-P", "Read the paid entitlement and refresh it once if needed. An independent trial requires a separately confirmed eligible target."),
    ("VS-042-R", "An official gateway and named isolated target are required before testing remote management."),
    ("VS-042-L", "An isolated licensed instance is required before testing protected Local-API routes."),
    ("VS-042-E", "The official calling contract, dedicated entitlement and isolated enterprise target are required."),
)


def linux_destination():
    host = input("Dedicated Linux address, or press Enter to leave Linux disabled: ").strip()
    if not host:
        return None
    port = input("Existing SSH port [22]: ").strip() or "22"
    if not re.fullmatch(r"[0-9]{1,5}", port):
        raise ValueError("Use the existing SSH port as a number.")
    data = {"host": host, "port": int(port),
            "user": input("Dedicated non-root SSH user: ").strip(),
            "public_key": input("Server public host key (type and key from the trusted console): ").strip(),
            "fingerprint": input("Confirmed server key fingerprint (SHA256:…): ").strip()}
    Destination.parse(data)
    identity = input("Restricted private key path, or press Enter for the OpenSSH password prompt: ").strip()
    if identity:
        data["identity"] = str(private_identity(Path(identity)))
    return data


def show_confirmation(run, deadline, profile, tool_digest=None, *, synthetic=False):
    deadline_text = datetime.fromtimestamp(deadline).astimezone().isoformat(timespec="seconds")
    print(f"VerySync test session {run}. Access expires at {deadline_text}.", flush=True)
    if tool_digest:
        print(f"Verified handoff bundle SHA-256 {tool_digest}.", flush=True)
    print(f"Fixed engine {NATIVE}. Published crate SHA-256 {CRATE}.", flush=True)
    print("Use freshly generated test identities and files inside the temporary session.", flush=True)
    print("Use only the official account service at my.verysync.com:443 for the Pro login.",
          flush=True)
    print("GitHub tests run in the verified AresJef/verysync-sidecar workflows with synthetic data.",
          flush=True)
    for identifier, scope in FIXTURES:
        print(f"{identifier}  {scope}", flush=True)
    if connection := profile.get("linux"):
        settings = connection[1]
        destination = Destination.parse({key: value for key, value in settings.items() if key != "identity"})
        print(f"Linux {destination.user}@{destination.host}, SSH port {destination.port}, "
              f"confirmed key {destination.fingerprint}.", flush=True)
        print("Keep this connection ready for the named test tasks. They use a private test directory "
              "and do not open a public listener.", flush=True)
        print("A native data-port test requires its separately listed target, lease and cleanup scope.",
              flush=True)
    else:
        print("Linux is disabled for this session.", flush=True)
    if synthetic:
        print("The account and all files in this run are synthetic.", flush=True)


def update_profile(path, destination):
    data = json.loads(path.read_text())
    if data["pro"]["connection"]["two_core_scope"] != "pro-cases":
        raise ValueError("The single terminal requires the frozen multi-case native driver.")
    if set(data["pro"]["allow"]) != ({"observe", "refresh-paid"} | TWO_CORE_SCOPES["pro-cases"].keys()):
        raise ValueError("The native operation list differs from the verified grant.")
    if destination is not None:
        data["linux"] = {"allow": sorted(LINUX_ALLOWED), "connection": destination}
        temporary = path.with_suffix(".new")
        with temporary.open("x", encoding="ascii") as output:
            json.dump(data, output, indent=2)
            output.write("\n")
        temporary.replace(path)


def remaining_seconds(deadline):
    now = int(time.time())
    if type(deadline) is not int or not 0 < deadline - now <= 48 * 3600:
        raise ValueError("The approved foreground window has expired or changed.")
    return deadline - now
