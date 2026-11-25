"""Hold the one password-authenticated SSH channel for the Local-API check."""

import asyncio
from contextlib import suppress
from hashlib import sha256
import json
from pathlib import Path
import secrets
import shlex

from r33_protocol import FRAME_MAX, decode_frame, encode_frame
from r33_ssh import Destination


class LinuxQualification:
    ready_event = "local-api-foreground-ready"
    live_scope = "live"

    def __init__(self, child, run, foreground=None):
        self.child=child
        self.run=run
        self.foreground=foreground
        self.sender=asyncio.Lock()
        self.heartbeat=None

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
            except BaseException:
                await session.close_unconfirmed()
                raise

    async def write(self,value):
        async with self.sender:
            self.child.stdin.write(encode_frame(value))
            await self.child.stdin.drain()

    async def read(self, timeout):
        return decode_frame(await asyncio.wait_for(self.child.stdout.readline(),timeout))

    async def renew(self):
        while self.child.returncode is None:
            await self.write({"kind":"renew","run":self.run})
            await asyncio.sleep(10)

    async def execute(self,operation,fields=None,timeout=50):
        identifier=secrets.token_hex(16)
        await self.write({"kind":"execute","run":self.run,"request":identifier,
                          "operation":operation,"input":{"kind":operation,**(fields or {})}})
        result=await self.read(timeout)
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
        if self.heartbeat:
            self.heartbeat.cancel()
            await asyncio.gather(self.heartbeat,return_exceptions=True)
        try:
            await self.write({"kind":"stop","run":self.run})
            stop=await self.read(52)
            cleanup=await self.read(8)
            if (stop.get("event")!="local-api-foreground-stopped" or stop.get("run")!=self.run
                    or cleanup.get("event")!="local-api-cleanup" or cleanup.get("run")!=self.run
                    or cleanup.get("private_state_removed") is not True):
                raise ValueError("The Linux shutdown response needs a readback.")
            staging=await self.finish_staging()
            return {"native_scope":stop,"cleanup":cleanup,"staging":staging,
                    "ssh_exit":self.child.returncode}
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

    @classmethod
    async def open(cls, destination, staging, bootstrap, payload, digest, run, expires):
        wire, ready=await LinuxBrokerSession.open(destination,staging,bootstrap,payload,digest,run,expires)
        return cls(wire, expires), ready

    async def begin(self, worker, stop):
        if stop.is_set():
            return None
        if self.active or worker.live_scope in self.used or self.session.child.returncode is not None:
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
            await self.session.close_unconfirmed()
            raise

    async def stop(self):
        if self.active is not None:
            await self.active.stop()
        try:
            if self.active is not None or self.session.child.returncode is not None:
                raise ValueError("The final SSH cleanup reply is unavailable.")
            await self.session.write({"kind":"close-foreground","run":self.session.run})
            staging=await self.session.read(8)
            await asyncio.wait_for(self.session.child.wait(),8)
            if (staging!={"event":"linux-staging-cleaned","temporary_programs_removed":True}
                    or self.session.child.returncode!=0):
                raise ValueError("The final SSH cleanup reply did not match.")
            return {"staging":staging,"ssh_exit":0,"one_authenticated_channel":True}
        except (OSError,ValueError,asyncio.TimeoutError):
            await self.session.close_unconfirmed()
            return {"ssh_closed":self.session.child.returncode is not None,"staging":"unconfirmed"}


class LinuxBrokerSession(LinuxQualification):
    live_scope="combined"
    ready_event="linux-foreground-ready"

    async def renew(self):
        # The native role owns its lease while active. The broker reads idle
        # commands on this same stream and applies the original absolute expiry.
        return
