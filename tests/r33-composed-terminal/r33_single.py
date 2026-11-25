"""The fixed one-terminal acceptance inventory and its user confirmation text."""

from datetime import datetime
import json
import re
import time

from r33_cases import TWO_CORE_SCOPES
from r33_ssh import Destination, SSHConfigurationError, USER, first_host_pin, saved_host_pin


CRATE = "1d1e7d0d3ef4ac4dcf063b8e4d3ac336bd823fd056e5aae84c5dbaaf24d6cbfe"
NATIVE = "v2.33.2"
LINUX_ALLOWED = frozenset(("observe", "start-observer", "finish-observer", "write-sample"))
FIXTURES = (
    ("VS-041-W", "With verified Pro access, prepare, seed, observe and remove watch, interval and UTC calendar tasks."),
    ("VS-033-S5", "With verified Pro access, test selection and removal across two temporary peers and verify their files."),
    ("VS-040", "With verified Pro access, inspect and reset only this run's test audit history, then restore its settings."),
    ("VS-042-P", "Read the existing paid entitlement, refresh it once if needed and verify it after restart. Trial redemption is deferred."),
    ("VS-042-R", "After verifying the gateway and target, read the target version, test one reversible setting and restore it."),
    ("VS-042-L", "After verifying the dedicated entitlement and exact target, test the 28 listed routes and clean up their isolated data."),
    ("VS-042-E", "Pending the official calling contract, dedicated entitlement and isolated enterprise target."),
)


def linux_destination():
    host = input("Dedicated Linux address, or press Enter to leave Linux disabled: ").strip()
    if not host:
        return None
    port = input("Existing SSH port [22]: ").strip() or "22"
    if not re.fullmatch(r"[0-9]{1,5}", port):
        raise ValueError("Use the existing SSH port as a number.")
    user = input("Linux SSH account [root]: ").strip() or "root"
    if not USER.fullmatch(user):
        raise ValueError("Enter a valid SSH account name.")
    try:
        pin = saved_host_pin(host, int(port))
        key, fingerprint = pin if pin else first_host_pin(host, int(port))
    except SSHConfigurationError as error:
        print(str(error), flush=True)
        raise
    data = {"host":host,"port":int(port),"user":user,"public_key":key,"fingerprint":fingerprint,
            "trust_source":"saved" if pin else "first-use"}
    Destination.parse(data, allow_root=True)
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
        destination = Destination.parse({key: value for key, value in settings.items() if key != "identity"},
                                        allow_root=True)
        print(f"Linux {destination.user}@{destination.host}, SSH port {destination.port}, "
              f"SSH identity {destination.fingerprint}.", flush=True)
        if destination.trust_source == "saved":
            print("This Mac already saved this server identity. OpenSSH will check it at login.", flush=True)
        if destination.trust_source == "first-use":
            print("First connection to this address and port. START also accepts the displayed new "
                  "server identity for this session. Proceed if you recognize this server.", flush=True)
        print("Keep this connection ready for the named test tasks. They use a private test directory "
              "and do not open a public listener.", flush=True)
        print("OpenSSH will ask for the Linux password first. Next, enter the VerySync account and "
              "password in the hidden prompts. The fixed remote test worker uses ordinary permissions.", flush=True)
        print("A native data-port test requires its separately listed target, lease and cleanup scope.",
              flush=True)
    else:
        print("Linux is disabled for this session.", flush=True)
    if synthetic:
        print("The account and all files in this run are synthetic.", flush=True)


def confirm_combined(run, deadline, *, destination, state_root, bundle_digest, driver_digest,
                     linux_payload_digest, gateway_port=None, synthetic=False):
    for value in (bundle_digest, driver_digest, linux_payload_digest if destination else None):
        if value is not None and not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ValueError("The verified input checksum is missing or invalid.")
    if not bundle_digest or not driver_digest or (destination and not linux_payload_digest):
        raise ValueError("The verified input checksum is missing or invalid.")
    profile = {"linux": (LINUX_ALLOWED, destination)} if destination else {}
    show_confirmation(run, deadline, profile, bundle_digest, synthetic=synthetic)
    print(f"Mac test state and files will be created in {state_root}.", flush=True)
    print(f"Verified Mac test driver SHA-256 {driver_digest}.", flush=True)
    if destination:
        print(f"Verified Linux test bundle SHA-256 {linux_payload_digest}.", flush=True)
    if gateway_port is not None:
        print(f"The dedicated gateway test uses TCP {gateway_port} on the selected Linux host. "
              "The management interface stays private.", flush=True)
    else:
        print("This session has no selected cross-network gateway target.", flush=True)
    print("Eligible tests may be retried within their listed scope until the session expires. "
          "Results are read back before any further write. STOP or Ctrl+C ends this authorization.", flush=True)
    return input("Type START to authorize these test operations: ").strip() == "START"


def update_profile(path, destination):
    data = json.loads(path.read_text())
    if data["pro"]["connection"]["two_core_scope"] != "pro-cases":
        raise ValueError("The single terminal requires the frozen multi-case native driver.")
    if set(data["pro"]["allow"]) != ({"observe", "refresh-paid"} | TWO_CORE_SCOPES["pro-cases"].keys()):
        raise ValueError("The native operation list differs from the verified grant.")
    if destination is not None:
        data = {"linux": {"allow": sorted(LINUX_ALLOWED), "connection": destination}, **data}
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
