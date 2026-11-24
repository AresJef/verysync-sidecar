"""Observe an exact synthetic hosted job through a private fixture channel."""

import asyncio
from pathlib import Path
import time

from r33_accounts import private_call, private_directory


class SyntheticActions:
    def __init__(self, socket, run, job):
        self.socket = socket
        self.run, self.job = run, job

    @classmethod
    async def open(cls, profile):
        if type(profile) is not dict or set(profile)!={"socket","run","job"}:
            raise ValueError("Use an exact synthetic Actions run and job.")
        if any(type(profile[k]) is not int or not 1 <= profile[k] < 2**63 for k in ("run","job")):
            raise ValueError("Use the run and job numbers for this synthetic fixture.")
        path=Path(profile["socket"])
        private_directory(path.parent)
        instance=cls(path, profile["run"], profile["job"])
        await instance.inspect()
        return instance

    async def call(self, kind, before_send=None):
        response = await private_call(self.socket, {"kind":kind,"run":self.run,"job":self.job},
                                      before_send=before_send)
        if response.get("run")!=self.run or response.get("job")!=self.job:
            raise ValueError("The synthetic job returned another identity.")
        return response

    async def inspect(self, before_send=None):
        reply=await self.call("status",before_send)
        if reply.get("status") not in {"active","pending","cancelled"}:
            raise ValueError("The synthetic job returned an unsupported state.")
        return {"ok":True,"state":reply["status"]}

    async def execute(self, _work, before_send):
        return await self.inspect(before_send)

    async def stop(self, _unknown, journal):
        accepted=False
        try:
            response=await self.call("cancel")
            accepted = response.get("http") == 202
            if accepted:
                journal.record("github-cancel-accepted",run_id=self.run,job_id=self.job)
            wait=time.monotonic()+1.6
            while accepted and time.monotonic()<wait:
                state=await self.inspect()
                if state["state"]=="cancelled":
                    return {"state":"synthetic-job-cancelled","request_accepted":True,
                           "run_id":self.run,"job_id":self.job}
                await asyncio.sleep(.08)
        except (OSError,ValueError,asyncio.TimeoutError):
            pass
        return {"state":"pending-confirmation","request_accepted":accepted,
                "run_id":self.run,"job_id":self.job}
