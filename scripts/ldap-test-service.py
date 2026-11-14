"""Private controlled LDAPv3 simple-bind peer, never SDK code or a system service."""
import json
import hmac
import sysconfig
import socketserver
import sys
import threading
from pathlib import Path
from pyasn1.codec.ber import decoder, encoder
from pyasn1.error import SubstrateUnderrunError
from impacket.ldap import ldapasn1 as ldap

raw = sys.stdin.buffer.readline(65537)
if len(raw) > 65536 or not raw.endswith(b"\n"):
    raise ValueError("bounded explicit LDAP fixture configuration required")
config = json.loads(raw)
root = Path(config["root"]).resolve(strict=True)
if not root.is_dir() or not isinstance(config["dn"], str) or not isinstance(config["password"], str) or not config["dn"] or not config["password"] or max(len(config["dn"].encode()), len(config["password"].encode())) > 4096:
    raise ValueError("explicit synthetic directory and bounded credentials required")
observations = root / "ldap-observations.jsonl"
lock = threading.Lock()


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        pending = b""
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            pending += data
            if len(pending) > 65536:
                raise ValueError("bounded LDAP request required")
            while pending:
                try:
                    message, pending_next = decoder.decode(pending, asn1Spec=ldap.LDAPMessage())
                except SubstrateUnderrunError:
                    break
                pending = pending_next
                kind = message["protocolOp"].getName()
                if kind == "unbindRequest":
                    return
                response = ldap.LDAPMessage()
                response["messageID"] = message["messageID"]
                if kind == "bindRequest":
                    request = message["protocolOp"]["bindRequest"]
                    name = bytes(request["name"]).decode("utf-8")
                    simple = request["authentication"].getName() == "simple"
                    password = bytes(request["authentication"]["simple"]) if simple else b""
                    matched_name = name == config["dn"]
                    matched_password = hmac.compare_digest(password, config["password"].encode())
                    code = 0 if simple and matched_name and matched_password else 49
                    answer = response["protocolOp"]["bindResponse"]
                    record = {"operation": kind, "dn_matches": matched_name,
                              "password_matches": matched_password, "result_code": code}
                elif kind == "searchRequest":
                    code = 2
                    answer = response["protocolOp"]["searchResDone"]
                    record = {"operation": kind, "result_code": code}
                else:
                    raise ValueError("unexpected LDAP operation")
                answer["resultCode"] = code
                answer["matchedDN"] = ""
                answer["diagnosticMessage"] = ""
                with lock:
                    with observations.open("a", encoding="utf-8") as output:
                        output.write(json.dumps(record) + "\n")
                self.request.sendall(encoder.encode(response))


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False

    def handle_error(self, request, client_address):
        # A malformed wire request remains an error and closes that connection.
        # Exceptions can carry substrate bytes; never echo LDAP passwords.
        print("private LDAP protocol failure: " + sys.exc_info()[0].__name__, file=sys.stderr)


with Server(("127.0.0.1", 0), Handler) as server:
    if server.server_address[1] == 18886:
        raise ValueError("reserved live-instance port refused")
    print(json.dumps({"ready": True, "loopback_only": True,
                      "port": server.server_address[1], "protocol": "ldap",
                      "python_platform": sysconfig.get_platform()}), flush=True)
    server.serve_forever(poll_interval=0.1)
