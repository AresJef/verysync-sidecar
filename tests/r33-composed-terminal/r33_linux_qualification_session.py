"""Hold the one password-authenticated SSH channel for the Local-API check."""

import asyncio
from contextlib import suppress
from hashlib import sha256
import json
from pathlib import Path
import secrets
import shlex
import time

from r33_protocol import FRAME_MAX, HEARTBEAT_SECONDS, decode_frame, encode_frame
from r33_ssh import Destination


SSH_WITH_OPERATOR_INTERRUPT = (
    "import os, signal, sys\n"
    "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
    "os.execv(sys.argv[1], sys.argv[1:])\n"
)


class LinuxQualification:
    ready_event = "local-api-foreground-ready"
    live_scope = "live"
    keeps_operator_interrupt = False

    def __init__(self, child, run, foreground=None):
        self.child=child
        self.run=run
        self.foreground=foreground
        self.sender=asyncio.Lock()
        self.heartbeat=None
        self.stopping=False
        self.interrupted_request=None

    @classmethod
    async def open(cls, destination, staging: Path, bootstrap: Path, payload: Path,
                   digest: str, run: str, expires: int, synthetic=False):
        selected=Destination.parse(destination,allow_root=True)
        if selected.user!="root":
            raise ValueError("This owned Linux check uses the root SSH login you supplied.")
        with payload.open("rb") as bundle:
            observed=sha256()
            for data in iter(lambda:bundle.read(1024**2),b""):
                observed.update(data)
            if observed.hexdigest()!=digest:
                raise ValueError("The verified Linux qualification payload changed.")
            bundle.seek(0)
            command=shlex.join(["exec","/usr/bin/python3","-B","-c",
                                bootstrap.read_text(encoding="utf-8"),run,str(expires),digest,
                                "control" if synthetic else cls.live_scope])
            external=selected.command(staging,remote_entry=command)
            if cls.keeps_operator_interrupt:
                # OpenSSH honors an inherited ignored SIGINT while connected.
                # The supervisor receives Ctrl+C and requests remote cleanup first.
                external = ["/usr/bin/python3", "-I", "-B", "-S", "-c",
                            SSH_WITH_OPERATOR_INTERRUPT, *external]
            child=await asyncio.create_subprocess_exec(*external,stdin=asyncio.subprocess.PIPE,
                                                       stdout=asyncio.subprocess.PIPE,limit=FRAME_MAX)
            session=cls(child,run)
            try:
                session.child.stdin.write(str(payload.stat().st_size).encode("ascii")+b"\n")
                for block in iter(lambda:bundle.read(128*1024),b""):
                    session.child.stdin.write(block)
                    await asyncio.wait_for(session.child.stdin.drain(),25)
                initial=await session.read(85)
                if (initial.get("event")!=cls.ready_event or initial.get("run")!=run
                        or initial.get("deadline")!=expires):
                    raise ValueError("The Linux preflight did not confirm the selected session.")
                session.heartbeat=asyncio.create_task(session.renew())
                return session,initial
            except asyncio.CancelledError:
                with suppress(ProcessLookupError):
                    child.terminate()
                await session.close_unconfirmed()
                raise
            except BaseException:
                await session.close_unconfirmed()
                raise

    async def write(self,value,operator_stop=None):
        async with self.sender:
            if operator_stop is not None and operator_stop.is_set():
                raise ValueError("The Linux work was stopped before transmission.")
            self.child.stdin.write(encode_frame(value))
            await self.child.stdin.drain()

    async def read(self, timeout):
        return decode_frame(await asyncio.wait_for(self.child.stdout.readline(),timeout))

    async def renew(self):
        while self.child.returncode is None:
            await self.write({"kind":"renew","run":self.run})
            await asyncio.sleep(10)

    async def execute(self,operation,fields=None,timeout=50,*,operator_stop=None):
        if self.stopping:
            raise ValueError("The Linux role is stopping.")
        identifier=secrets.token_hex(16)
        await self.write({"kind":"execute","run":self.run,"request":identifier,
                          "operation":operation,"input":{"kind":operation,**(fields or {})}},operator_stop)
        if operator_stop is None:
            result=await self.read(timeout)
        else:
            result=await self.read_while_active(identifier,timeout,operator_stop)
        if result is None:
            return {"state":"operator-stopped","request_transmitted":True}
        if result.get("request")!=identifier:
            raise ValueError("The Linux response did not confirm the named operation.")
        if result.get("event")!="operation-observed":
            failure=result.get("code")
            if operation=="login" and failure in (
                "outside-scope","lease-closed","native-result-unconfirmed","duplicate-or-busy"
            ):
                return {"ok":False,"operation_failure":failure,
                        "provider_network":result.get("provider_network",{})}
            raise ValueError("The Linux response did not confirm the named operation.")
        return result["native"]

    async def read_while_active(self,identifier,timeout,operator_stop):
        read=asyncio.create_task(self.read(timeout))
        stopped=asyncio.create_task(operator_stop.wait())
        try:
            await asyncio.wait((read,stopped),return_when=asyncio.FIRST_COMPLETED)
            if operator_stop.is_set():
                self.interrupted_request=identifier
                read.cancel()
                await asyncio.gather(read,return_exceptions=True)
                await self.request_stop()
                return None
            return read.result()
        except asyncio.TimeoutError:
            self.interrupted_request=identifier
            raise
        finally:
            read.cancel()
            stopped.cancel()
            await asyncio.gather(read,stopped,return_exceptions=True)

    async def request_stop(self):
        if self.stopping:
            return
        self.stopping=True
        if self.heartbeat:
            self.heartbeat.cancel()
            await asyncio.gather(self.heartbeat,return_exceptions=True)
        await self.write({"kind":"stop","run":self.run})

    async def close_unconfirmed(self):
        if self.heartbeat:
            self.heartbeat.cancel()
            await asyncio.gather(self.heartbeat,return_exceptions=True)
        if self.child.stdin:
            self.child.stdin.close()
        try:
            await asyncio.wait_for(self.child.wait(),10)
        except asyncio.TimeoutError:
            with suppress(ProcessLookupError):
                self.child.terminate()
            await asyncio.wait_for(self.child.wait(),6)

    async def finish_staging(self):
        staging=await self.read(8)
        if self.foreground is not None:
            if staging != {"event":"linux-role-finished","run":self.run,
                           "role":self.live_scope,"exit_code":0}:
                raise ValueError("The owned Linux role did not confirm its exit.")
            self.foreground.active=None
        else:
            await asyncio.wait_for(self.child.wait(),8)
            if staging != {"event":"linux-staging-cleaned","temporary_programs_removed":True}:
                raise ValueError("The Linux staging cleanup needs confirmation.")
        return staging

    async def stop(self):
        try:
            await self.request_stop()
            stop=await self.read(52)
            observation=None
            if self.interrupted_request is not None and stop.get("request")==self.interrupted_request:
                observation={key:stop[key] for key in ("event","code") if isinstance(stop.get(key),str)}
                stop=await self.read(52)
            cleanup=await self.read(8)
            if (stop.get("event")!="local-api-foreground-stopped" or stop.get("run")!=self.run
                    or cleanup.get("event")!="local-api-cleanup" or cleanup.get("run")!=self.run
                    or cleanup.get("private_state_removed") is not True):
                raise ValueError("The Linux shutdown response needs a readback.")
            staging=await self.finish_staging()
            result={"native_scope":stop,"cleanup":cleanup,"staging":staging,
                    "ssh_exit":self.child.returncode}
            if observation is not None:
                result["interrupted_observation"]=observation
            return result
        except (OSError,ValueError,asyncio.TimeoutError):
            await self.close_unconfirmed()
            return {"ssh_closed":self.child.returncode is not None,"native_cleanup":"unconfirmed"}


class LinuxForeground:
    """One authenticated transport with two sequential, named native roles."""

    def __init__(self, session, expires):
        self.session=session
        self.expires=expires
        self.active=None
        self.used=set()
        self.transitions=asyncio.Lock()
        self.idle_renewals=0
        self.transport_lost=False
        self.idle_task=asyncio.create_task(self.maintain_standby())

    @classmethod
    async def open(cls, destination, staging, bootstrap, payload, digest, run, expires):
        wire, ready=await LinuxBrokerSession.open(destination,staging,bootstrap,payload,digest,run,expires)
        return cls(wire, expires), ready

    async def begin(self, worker, stop):
        async with self.transitions:
            if stop.is_set():
                return None
            if (self.active or worker.live_scope in self.used or self.transport_lost
                    or self.session.child.returncode is not None or time.time()>=self.expires):
                raise ValueError("The selected Linux role is unavailable on this SSH session.")
            self.used.add(worker.live_scope)
            self.active=worker(self.session.child,self.session.run,self)
            try:
                await self.session.write({"kind":"start-role","run":self.session.run,"role":worker.live_scope})
                initial=await self.session.read(85)
                if initial.get("ok") is False:
                    finished=await self.session.read(8)
                    if (finished.get("event")=="linux-role-finished"
                            and finished.get("run")==self.session.run and finished.get("role")==worker.live_scope
                            and type(finished.get("exit_code")) is int and finished["exit_code"]!=0):
                        self.active=None
                        return None
                if (initial.get("event")!=worker.ready_event or initial.get("run")!=self.session.run
                        or initial.get("deadline")!=self.expires):
                    raise ValueError("The selected Linux role did not confirm readiness.")
                self.active.heartbeat=asyncio.create_task(self.active.renew())
                return self.active, initial
            except BaseException:
                self.transport_lost=True
                await self.session.close_unconfirmed()
                raise

    async def maintain_standby(self):
        try:
            while True:
                await asyncio.sleep(HEARTBEAT_SECONDS)
                async with self.transitions:
                    if (self.transport_lost or self.session.child.returncode is not None
                            or time.time()>=self.expires):
                        return
                    if self.active is not None:
                        continue
                    await self.session.write({"kind":"renew-idle","run":self.session.run})
                    receipt=await self.session.read(8)
                    if receipt!={"event":"linux-idle-renewed","run":self.session.run,"deadline":self.expires}:
                        raise ValueError("The Linux standby renewal did not confirm the selected session.")
                    self.idle_renewals+=1
        except (OSError,ValueError,asyncio.TimeoutError):
            self.transport_lost=True
            await self.session.close_unconfirmed()

    async def stop(self):
        async with self.transitions:
            self.idle_task.cancel()
            await asyncio.gather(self.idle_task,return_exceptions=True)
            if self.active is not None:
                await self.active.stop()
            try:
                if self.active is not None or self.transport_lost:
                    raise ValueError("The final SSH cleanup reply is unavailable.")
                if self.session.child.returncode is None and time.time()<self.expires:
                    await self.session.write({"kind":"close-foreground","run":self.session.run})
                staging=await self.session.read(8)
                await asyncio.wait_for(self.session.child.wait(),8)
                if (staging!={"event":"linux-staging-cleaned","temporary_programs_removed":True}
                        or self.session.child.returncode!=0):
                    raise ValueError("The final SSH cleanup reply did not match.")
                return {"staging":staging,"ssh_exit":0,"one_authenticated_channel":True,
                        "idle_renewals":self.idle_renewals}
            except (OSError,ValueError,asyncio.TimeoutError):
                await self.session.close_unconfirmed()
                return {"ssh_closed":self.session.child.returncode is not None,"staging":"unconfirmed"}


class LinuxBrokerSession(LinuxQualification):
    live_scope="combined"
    ready_event="linux-foreground-ready"
    keeps_operator_interrupt = True

    async def renew(self):
        # The native role owns its lease while active. The broker reads idle
        # commands on this same stream and applies the original absolute expiry.
        return
