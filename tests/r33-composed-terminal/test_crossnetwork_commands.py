import asyncio
import unittest

from r33_gateway_crossnetwork import connect, exercise


SOURCE="SYNTHETIC-SOURCE-ONLY"
TARGET="SYNTHETIC-TARGET-ONLY"
RUN="a" * 32
FILES=[{"bytes":12,"sha256":"b"*64},{"bytes":10,"sha256":"c"*64}]
FIXTURE={"target":{"internal_device_id":TARGET,"engine":"v2.33.2","private_gui_port":41515,
                   "observation":{"before":FILES}},"synthetic_target_key":"random-synthetic-target-example"}


class Target:
    def __init__(self, trace):
        self.trace=trace

    async def execute(self, action, fields=None):
        self.trace.append("target:"+action)
        if action=="register":
            assert fields=={"peer":SOURCE}
            return {"folder_exact":True}
        if action=="allow":
            return {"peer":{"connected":True,"allowed":True,"native_transport":"PeerConnectionType::TcpServer",
                            "reported_local":False}}
        if action=="state":
            return {"label":"Owned gateway change","files_match":True,"actual":FILES}
        if action=="restore":
            return {"label":"Owned gateway baseline","peer":{"allowed":False},"files_match":True,"actual":FILES}
        raise AssertionError(action)


class Source:
    initial={"internal_device_id":SOURCE,"device":"d"*64}

    def __init__(self, trace, *, accept=True, stop_event=None):
        self.trace,self.accept,self.stop_event=trace,accept,stop_event

    async def execute(self,action,fields=None):
        self.trace.append("source:"+action)
        if action=="gateway-target":
            assert fields=={"peer":TARGET,"private_gui_port":41515}
            return {"target_registered":True}
        if action=="gateway-transport":
            return {"ok":True}
        if action=="gateway-prepare":
            if self.stop_event:
                self.stop_event.set()
            return {"denied_before_grant":True,"path":{"is_local":False}}
        if action=="gateway-write":
            assert fields["synthetic_target_key"]==FIXTURE["synthetic_target_key"]
            assert fields["synthetic_wrong_key"]!=fields["synthetic_target_key"]
            if not self.accept:
                raise TimeoutError("Synthetic lost write acknowledgment.")
            return {"gateway_write_requests":1}
        if action=="gateway-revoke":
            return {"denied_after_revocation":True}
        raise AssertionError(action)


class ScopedGatewayCommands(unittest.IsolatedAsyncioTestCase):
    async def test_native_transport_is_checked_before_any_paid_operation(self):
        trace=[]
        self.assertEqual(await connect(Source(trace),Target(trace),FIXTURE),{"ok":True})
        self.assertEqual(trace,["target:register","source:gateway-target","source:gateway-transport"])

    async def test_missing_acknowledgment_uses_one_target_read_and_never_repeats_a_write(self):
        trace=[]
        value=await exercise(Source(trace,accept=False),Target(trace),FIXTURE,asyncio.Event(),RUN)
        self.assertEqual(trace,["source:gateway-prepare","target:allow","source:gateway-write",
                                "target:state","target:restore","source:gateway-revoke"])
        self.assertEqual(value["gateway"],{})
        self.assertTrue(value["independent_target_change"] and value["target_independent_restore"])

    async def test_stop_before_grant_only_allows_cleanup(self):
        trace=[]
        stop=asyncio.Event()
        value=await exercise(Source(trace,stop_event=stop),Target(trace),FIXTURE,stop,RUN)
        self.assertEqual(value["state"],"operator-stopped-before-target-grant")
        self.assertEqual(trace,["source:gateway-prepare","target:restore","source:gateway-revoke"])


if __name__=="__main__":
    unittest.main()
