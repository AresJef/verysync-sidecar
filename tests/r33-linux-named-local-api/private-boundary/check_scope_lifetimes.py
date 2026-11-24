"""Verify stop, EOF and lease expiry of the actual signed-out Linux scope."""

import argparse
import json
from pathlib import Path
import secrets
import select
import subprocess
import time


SCOPE = Path(__file__).resolve().with_name("run_local_api_scope.py")


def take(child, timeout=25):
    if not select.select([child.stdout], [], [], timeout)[0]:
        raise TimeoutError("A bounded scope receipt did not arrive.")
    data = child.stdout.readline(8193)
    if not data:
        raise ValueError("The scoped process stopped without a receipt.")
    return json.loads(data)


def send(child, data):
    child.stdin.write(json.dumps(data,separators=(",",":")).encode("ascii") + b"\n")
    child.stdin.flush()


def request(child, run, operation, identifier=None, args=None):
    identifier = identifier or secrets.token_hex(16)
    send(child, {"kind":"execute","run":run,"request":identifier,
                 "operation":operation,"input":{"kind":operation,**(args or {})}})
    result = take(child)
    assert result["request"] == identifier
    return result


def prepared(child, run):
    ready = take(child,45)
    assert ready.get("event") == "local-api-foreground-ready" and ready["run"] == run, ready
    assert ready["isolation"]["boundary"]["only_loopback"]
    assert ready["isolation"]["boundary"]["volatile_private_state"]
    assert ready["outside_check"]["authorization_socket_refused"]
    assert ready["outside_check"]["loopback_port_refused"]
    assert ready["instance"]["account"] == "logged-out"
    return ready


def check_behaviors(child, run, initial):
    refusal = request(child,run,"login",args={"username":"fixture-only","password":"fixture-only"})
    assert refusal["ok"] is False and refusal["code"] == "outside-scope"
    assert request(child,run,"arbitrary")["code"] == "outside-scope"
    first = request(child,run,"inspect")
    assert first["event"] == "operation-observed" and first["native"]["device"] == initial["instance"]["device"]
    duplicate = request(child,run,"inspect",identifier=first["request"])
    assert duplicate["ok"] is False and duplicate["code"] == "duplicate-or-busy"
    check = request(child,run,"local-api-qualify")
    assert check["native"] == {"ok":False,"reason":"dedicated-official-session-not-confirmed"}
    duplicate_path = request(child,run,"local-api-qualify")
    assert duplicate_path["native"] == {"ok":False,"reason":"operation-outside-the-licensed-local-api-scope"}
    return True


def scenario(program, driver, reason):
    run = secrets.token_hex(16)
    argv = ["/usr/bin/sudo","-n","/usr/bin/python3","-B",str(SCOPE),
            "--engine",str(program),"--driver",str(driver),"--run",run,
            "--expires",str(int(time.time())+180),"--synthetic"]
    worker = subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,bufsize=0,
                              start_new_session=True)
    try:
        ready = prepared(worker,run)
        cases = False
        if reason=="user-stop":
            cases = check_behaviors(worker,run,ready)
            send(worker,{"kind":"renew","run":run})
        anchor = time.monotonic()
        if reason=="user-stop":
            send(worker,{"kind":"stop","run":run})
        elif reason=="channel-closed":
            worker.stdin.close()
        done = take(worker,55)
        cleanup = take(worker,15)
        elapsed = time.monotonic()-anchor
        assert done["event"]=="local-api-foreground-stopped" and done["reason"]==reason
        assert done["provider_network"]["permitted"]==0 and done["provider_network"]["verified_public_tls"]==0
        assert done["native"]["normal_owned_exit"] and not done["native"]["login_submitted"]
        assert cleanup["event"]=="local-api-cleanup" and cleanup["run"]==run
        assert cleanup["private_state_removed"] and cleanup["normal_scope_exit"]
        assert worker.wait(timeout=12)==0
        if reason=="lease-expired":
            assert 39 <= elapsed <= 95 and 39 <= done["last_renewal_age"] <= 95, (elapsed,done)
        return {"reason":reason,"elapsed":round(elapsed,3),"actual_runtime_checks":cases,
                "ready":ready,"stopped":done,"cleanup":cleanup}
    finally:
        if worker.poll() is None:
            subprocess.run(["/usr/bin/sudo","-n","/bin/kill","-TERM","--",f"-{worker.pid}"],
                           check=False,timeout=5)
            worker.wait(timeout=9)


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine",type=Path,required=True)
    parser.add_argument("--driver",type=Path,required=True)
    args=parser.parse_args()
    results=[scenario(args.engine,args.driver,reason)
             for reason in ("user-stop","channel-closed","lease-expired")]
    aliases={case["ready"]["instance"]["device"] for case in results}
    assert len(aliases)==3
    print("R33_LOCAL_API_LEASE " + json.dumps(results,sort_keys=True))
