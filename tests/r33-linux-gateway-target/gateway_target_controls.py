"""Common target-side control assertions for the synthetic fixture."""

import http.client
import json
import select


FOLDER = "/rest/config/folders/r33-dedicated-gateway-target"


def ask(worker, request=None):
    if request is not None:
        worker.stdin.write(json.dumps(request).encode("ascii")+b"\n")
        worker.stdin.flush()
    if not select.select([worker.stdout],[],[],32)[0]:
        raise TimeoutError("The owned target did not return a bounded receipt.")
    line=worker.stdout.readline(8193)
    return json.loads(line)


def test_fixture(worker,port,key,peer):
    ready=ask(worker,{"synthetic_target_key":key})
    assert ready.get("event")=="owned-target-ready"
    raw=ready["internal_device_id"]
    denied={"ok":False,"state":"target-request-unconfirmed"}
    assert ask(worker,{"kind":"allow"})==denied
    assert ask(worker,{"kind":"register","peer":raw})==denied
    assert ask(worker,{"kind":"register","peer":"bad-id"})==denied
    registered=ask(worker,{"kind":"register","peer":peer})
    assert registered.get("folder_exact") and registered["peer"]["allowed"] is False,registered
    allowed=ask(worker,{"kind":"allow"})
    assert allowed["peer"]["allowed"] is True and allowed["files_match"]
    assert ask(worker,{"kind":"allow"})==denied

    # Change only the owned fixture through its private GUI listener. It is a
    # deterministic control for the independent target witness.
    with_control=http.client.HTTPConnection("127.0.0.1",port,timeout=5)
    try:
        with_control.request("PATCH",FOLDER,b'{"label":"Owned gateway change"}',
                             {"X-API-Key":key,"Content-Type":"application/json"})
        response=with_control.getresponse()
        assert 200<=response.status<300
        response.read(4097)
    finally:
        with_control.close()
    readback=ask(worker,{"kind":"state"})
    assert readback["label"]=="Owned gateway change" and readback["files_match"]
    restore=ask(worker,{"kind":"restore"})
    assert restore["gateway_change_seen_before_restore"]
    assert restore["label"]=="Owned gateway baseline" and restore["peer"]["allowed"] is False
    assert restore["files_match"] and restore["actual"]==ready["observation"]["before"]
    close=ask(worker,{"kind":"end"})
    exited=ask(worker)
    worker.stdin.close()
    assert close["event"]=="owned-target-final-readback" and close["observation"]["files_match"]
    assert exited=={"event":"owned-target-exit","normal":True} and worker.wait(timeout=15)==0
    return {"before_register_denied":True,"self_peer_denied":True,"bad_peer_denied":True,
            "second_grant_denied":True,"independent_read_and_restore":True,
            "permission_revoked":True,"samples_preserved":True,"local_only":True,"native_exit":True,
            "official_gateway_calls":0,"source_of_change":"direct owned GUI fixture"}
