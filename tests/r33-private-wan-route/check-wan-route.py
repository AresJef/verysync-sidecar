"""Verify the public-side port boundary with two disposable Linux network scopes."""

from contextlib import ExitStack
import json
from pathlib import Path
import secrets
import select
import subprocess
import sys
import time

from r33_wan_route import IP, PORT, Route, open_owned, run


ACCEPT = """
import json,socket,sys
with socket.socket() as listener:
    listener.bind((sys.argv[1],int(sys.argv[2])))
    listener.listen(3)
    listener.settimeout(5)
    print('ready',flush=True)
    with listener.accept()[0] as connection:
        address=connection.getpeername()[0]
        body=connection.recv(64)
        connection.sendall(body[::-1])
        print(json.dumps({'address':address,'bytes':len(body)}),flush=True)
"""

DIAL = """
import socket,sys
with socket.socket() as sock:
    sock.settimeout(1.6)
    sock.bind((sys.argv[1],0))
    try:
        sock.connect((sys.argv[2],int(sys.argv[3])))
        data=b'r33 isolated TCP proof'
        sock.sendall(data)
        assert sock.recv(64)==data[::-1]
    except OSError:
        sys.exit(4)
"""


def start(scope, address, port):
    child=subprocess.Popen(scope.inside(sys.executable,"-B","-c",ACCEPT,str(address),str(port)),
                           stdout=subprocess.PIPE,text=True)
    if not select.select([child.stdout],[],6)[0] or child.stdout.readline().strip()!="ready":
        child.terminate()
        child.wait(timeout=4)
        raise RuntimeError("The test listener did not become ready.")
    return child


def finish(child):
    if child.poll() is None:
        child.terminate()
    child.wait(timeout=4)


def verify():
    label=secrets.token_hex(16)
    route=Route.for_connection(label,"192.0.2.2","192.0.2.1")
    source_ns="r33src-"+label[:6]
    source_link="r33s"+label[:8]
    source_peer="r33p"+label[:8]
    with ExitStack() as root:
        run(IP,"netns","add",source_ns)
        root.callback(run,IP,"netns","del",source_ns)
        run(IP,"link","add",source_link,"type","veth","peer","name",source_peer)
        root.callback(run,IP,"link","del",source_link)
        run(IP,"link","set",source_peer,"netns",source_ns)
        run(IP,"addr","add","192.0.2.1/29","dev",source_link)
        run(IP,"link","set",source_link,"up")
        prefix=(IP,"netns","exec",source_ns)
        run(*prefix,IP,"addr","add","192.0.2.2/29","dev",source_peer)
        run(*prefix,IP,"addr","add","192.0.2.3/29","dev",source_peer)
        run(*prefix,IP,"link","set",source_peer,"up")
        run(*prefix,IP,"-4","route","add",str(route.space),"via","192.0.2.1")
        with open_owned(route), ExitStack() as children:
            data=start(route,route.target,PORT)
            children.callback(finish,data)
            gui=start(route,"127.0.0.1",48612)
            children.callback(finish,gui)
            def dial(origin,destination,port):
                return run(*prefix,sys.executable,"-B","-c",DIAL,str(origin),str(destination),str(port),
                           allowed=(0,4)).returncode
            assert route.packet_count()==0
            assert dial("192.0.2.3",route.ingress,PORT)==4
            assert dial(route.source,route.target,48612)==4
            assert dial(route.source,route.ingress,PORT)==0
            assert select.select([data.stdout],[],3)[0]
            received=json.loads(data.stdout.readline())
            assert received=={"address":"192.0.2.2","bytes":22}
            assert data.wait(timeout=4)==0
            packets=route.packet_count()
            assert packets>=1
        assert route.cleared()
    return {"different_network_namespaces":True,"verified_origin_seen_by_target":True,
            "wrong_origin_denied":True,"private_management_unreachable":True,
            "cleaned_exact_kernel_rules":True,"nat_ingress_count":packets,
            "credentials_used":0,"native_very_sync":False}


if __name__=="__main__":
    print("R33_ROUTE_CONTROL "+json.dumps(verify(),sort_keys=True),flush=True)
