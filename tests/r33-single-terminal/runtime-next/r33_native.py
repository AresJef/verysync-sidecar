"""Run the fixed-account adapter as an operator-owned, private child."""

import asyncio
from contextlib import closing
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import stat
import sys

from r33_accounts import private_directory, read_credentials
from r33_handoff import Channel, private_file
from r33_official_proxy import OfficialProxy, native_sandbox
from r33_cases import TWO_CORE_SCOPES, two_core_request
from r33_protocol import BackendStartupError, OperatorCancelled, FRAME_MAX, decode_frame


ENGINE_SHA256 = "f8e9bd67be3fb1b45eafea794008c4dfae24aec4e177617578b268598bf12274"


def sha256(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024*256), b""):
            result.update(chunk)
    return result.hexdigest()


@dataclass(frozen=True)
class NativeProfile:
    engine: Path
    driver: Path
    driver_sha256: str
    recovery: Path
    scope: str

    @classmethod
    def parse(cls, profile):
        if sys.platform != "darwin" or platform.machine() != "arm64":
            raise ValueError("This account adapter requires the verified Apple Silicon build.")
        if (type(profile) is not dict
                or set(profile) != {"engine","driver","driver_sha256","recovery","two_core_scope"}
                or type(profile["two_core_scope"]) is not str or profile["two_core_scope"] not in TWO_CORE_SCOPES):
            raise ValueError("Use the private profile for the fixed native account adapter.")
        engine = Path(profile["engine"])
        driver = Path(profile["driver"])
        for program in (engine, driver):
            private_file(program)
            if not program.is_absolute() or not os.access(program, os.X_OK):
                raise ValueError("Install the verified native programs as private executables.")
        if sha256(engine)!=ENGINE_SHA256 or sha256(driver)!=profile["driver_sha256"]:
            raise ValueError("A private program does not match its verified SHA-256 digest.")
        recovery = private_directory(Path(profile["recovery"]))
        if max(len(os.fsencode(recovery/("0"*32)/role/"state"/"gui.sock"))
               for role in (Path("."), Path("ap"), Path("sp"))) >= 103:
            raise ValueError("Choose a shorter private recovery directory for the native socket.")
        return cls(engine, driver, profile["driver_sha256"], recovery, profile["two_core_scope"])


def environment(root, proxy_port):
    address = f"http://127.0.0.1:{proxy_port}"
    variables = {"HOME":str(root),"TMPDIR":str(root),"PATH":"/usr/bin:/bin","GOTRACEBACK":"none",
                 "HTTPS_PROXY":address,"HTTP_PROXY":address,"https_proxy":address,"http_proxy":address,
                 "NO_PROXY":"localhost,127.0.0.1","no_proxy":"localhost,127.0.0.1"}
    return variables


async def scoped_preflight(executable, confinement, proxy_port, env):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as unused:
        unused.bind(("127.0.0.1",0))
        unused.listen()
        child = await asyncio.create_subprocess_exec(
            "/usr/bin/sandbox-exec","-f",str(confinement),str(executable),"net-check",
            str(proxy_port),str(unused.getsockname()[1]),
            env=env, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            output, _ = await asyncio.wait_for(child.communicate(),8)
        except asyncio.TimeoutError:
            child.kill()
            await child.wait()
            raise
        if child.returncode!=0 or decode_frame(output)!={"ok":True,"fixed_egress_control":True}:
            raise ValueError("The local native network isolation check failed.")


def reserve_case_port(used):
    for _ in range(8):
        candidate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            candidate.bind(("127.0.0.1", 0))
            if candidate.getsockname()[1] not in used:
                return candidate
        except BaseException:
            candidate.close()
            raise
        candidate.close()
    raise ValueError("Could not reserve the private test socket.")


class NativeAccount:
    drain_seconds = 67

    def __init__(self, channel, guard, root, initial, scope):
        self.channel, self.guard, self.root, self.initial = channel, guard, root, initial
        self.scope = scope

    @classmethod
    async def open(cls, profile, runtime, run, stopped, mode="fresh", *, before_login=None):
        settings = NativeProfile.parse(profile)
        root = settings.recovery/run
        if mode in ("fresh","preflight"):
            root.mkdir(mode=0o700)
        private_directory(root)
        proxy = OfficialProxy()
        child = None
        account = None
        try:
            port = proxy.server_address[1]
            env = environment(root, port)
            if mode in ("fresh", "preflight"):
                with closing(reserve_case_port({port, 18886})) as first:
                    send = first.getsockname()[1]
                    with closing(reserve_case_port({port, 18886, send})) as second:
                        receive = second.getsockname()[1]
                        confinement = native_sandbox(runtime, root, port, pair_ports=(send, receive))
                        env["R33_AUDIT_P2P_PORTS"] = f"{send},{receive}"
                        await scoped_preflight(settings.driver, confinement, port, env)
            else:
                confinement = native_sandbox(runtime, root, port, recovery=True)
                await scoped_preflight(settings.driver, confinement, port, env)
            if stopped.is_set():
                raise OperatorCancelled
            child = await asyncio.create_subprocess_exec(
                "/usr/bin/sandbox-exec","-f",str(confinement),str(settings.driver),"serve",
                str(settings.engine),str(root),run,env=env,
                stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL, limit=FRAME_MAX,
            )
            channel = Channel(child)
            initial = decode_frame(await asyncio.wait_for(child.stdout.readline(),25))
            if initial.get("ok") is not True or initial.get("version")!="2.33.2":
                raise ValueError("The isolated native account driver did not confirm the fixed engine.")
            account = cls(channel,proxy,root,initial,settings.scope)
            reference = root/"isolated-device"
            if mode == "recover":
                if reference.read_text()!=initial["device"]:
                    raise ValueError("The stored account belongs to another isolated device.")
                proxy.activate()
                return account
            if initial["account"]!="logged-out":
                raise ValueError("Start with a newly generated, signed-out test instance.")
            reference.write_text(initial["device"])
            if mode == "preflight":
                return account
            if stopped.is_set():
                raise OperatorCancelled
            if before_login is not None:
                await before_login(root)
            values = await read_credentials(stopped)
            try:
                # Preserve recovery information before submitting the single
                # provider operation. An interrupted reply may conceal a login.
                (root/"login-submitted").touch(exist_ok=False)
                proxy.activate()
                outcome = await channel.call({"kind":"login",**values}, deadline=36)
            finally:
                values.clear()
            if outcome.get("login_acknowledged") is not True or outcome.get("account")!="logged-in":
                raise ValueError("The native account service did not confirm a sign-in.")
            return account
        except BaseException as error:
            if account:
                if (root/"login-submitted").exists():
                    finish = await account.stop((),None)
                    raise BackendStartupError(finish) from error
                normal = await account.end_owned()
                if isinstance(error, OperatorCancelled):
                    raise BackendStartupError({"state":"stopped-before-login",
                                               "normal_owned_exit":normal,
                                               "official_network":account.guard.receipt()}) from error
            else:
                if child is not None and child.returncode is None:
                    await Channel(child).close(grace=40)
                proxy.close()
            raise

    async def execute(self, work, before_send):
        operation = work.request.operation
        if operation in TWO_CORE_SCOPES[self.scope]:
            command = two_core_request(self.scope, operation, work.request.request)
        else:
            expected = {"observe":"inspect","refresh-paid":"refresh-paid"}
            native = expected.get(operation)
            if native is None:
                return {"ok":False,"code":"operation-outside-the-foreground-scope"}
            command = {"kind":native}
        observed = await self.channel.call(command, before_send, deadline=63)
        if observed.get("ok") is False and "device" not in observed:
            return observed
        if observed.get("device")!=self.initial["device"]:
            return {"ok":False,"code":"native-identity-unverified"}
        return observed

    def mark_revoked(self):
        """Stop additional native writes from an already-dispatched fixture."""
        try:
            (self.root/"local-grant-revoked").touch(exist_ok=True)
        except OSError:
            child=self.channel.process
            if child.returncode is None:
                try:
                    child.terminate()
                except ProcessLookupError:
                    pass

    async def end_owned(self):
        normal_exit = False
        try:
            end = await self.channel.call({"kind":"end"},deadline=20)
            normal_exit = end=={"ok":True,"normal_owned_exit":True}
        except (OSError,ValueError,asyncio.TimeoutError):
            pass
        finally:
            await self.channel.close(grace=40)
            self.guard.close()
        return normal_exit

    async def stop(self, unknown, journal):
        observation = {}
        if journal is not None and unknown:
            unrecorded = []
            for identifier in unknown:
                try:
                    readback = await self.channel.call({"kind":"case-readback","request":identifier},deadline=4)
                except (OSError,ValueError,asyncio.TimeoutError):
                    readback = {"state":"readback-unavailable"}
                if readback.get("state") == "not-submitted":
                    unrecorded.append(identifier)
                    continue
                journal.record("owned-case-readback-after-withdrawal",target="pro",request=identifier,
                               observed=readback)
            if unrecorded:
                try:
                    snapshot = await self.channel.call({"kind":"inspect"},deadline=24)
                except (OSError,ValueError,asyncio.TimeoutError):
                    snapshot = {}
                for identifier in unrecorded:
                    journal.record("native-state-after-withdrawal",target="pro",request=identifier,
                                   identity_confirmed=snapshot.get("device")==self.initial["device"],
                                   license_records=snapshot.get("pro_observations",[]))
        try:
            observation = await self.channel.call({"kind":"logout"},deadline=105)
        except (OSError,ValueError,asyncio.TimeoutError):
            pass
        normal = await self.end_owned()
        isolated_cleared = observation.get("ok") is True and normal
        if isolated_cleared:
            (self.root/"native-signed-out").touch(exist_ok=True)
        return {"state":"native-instance-signed-out" if isolated_cleared else "pending-confirmation",
                "provider_session_revocation":"pending-confirmation",
                "native_logout_readback":observation.get("native_logout_readback") is True,
                "native_logged_out_after_restart":observation.get("persisted_after_restart") is True,
                "normal_owned_exit":normal,"fixture_cleanup":observation.get("fixture_cleanup","normal"),
                "official_network":self.guard.receipt()}

    @classmethod
    async def recover(cls, profile, runtime, run):
        account = await cls.open(profile, runtime, run, asyncio.Event(), mode="recover")
        return await account.stop((),None)
