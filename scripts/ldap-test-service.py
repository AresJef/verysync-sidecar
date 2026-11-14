"""Private controlled LDAPv3 simple-bind peer, never SDK code or a system service."""
import json
import hmac
import os
import ssl
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
transport = config.get("transport", "plain")
if transport not in ("plain", "tls", "starttls"):
    raise ValueError("explicit supported test transport required")
tls_context = None
if transport != "plain":
    from datetime import datetime, timedelta, timezone
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic LDAP peer")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = root / "synthetic-ldap-cert.pem", root / "synthetic-ldap-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(key_path, 0o600)
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(cert_path, key_path)


def record_observation(record):
    with lock:
        with observations.open("a", encoding="utf-8") as output:
            output.write(json.dumps(record) + "\n")


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        secure, bound = False, False

        def enable_tls():
            try:
                self.request = tls_context.wrap_socket(self.request, server_side=True)
            except ssl.SSLError as error:
                record_observation({"operation": "tlsHandshakeRejected", "reason": error.reason})
                raise
            record_observation({"operation": "tlsHandshake", "encrypted": True})

        if transport == "tls":
            enable_tls()
            secure = True
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
                start_tls = False
                if kind == "bindRequest":
                    request = message["protocolOp"]["bindRequest"]
                    name = bytes(request["name"]).decode("utf-8")
                    simple = request["authentication"].getName() == "simple"
                    password = bytes(request["authentication"]["simple"]) if simple else b""
                    matched_name = name == config["dn"]
                    matched_password = hmac.compare_digest(password, config["password"].encode())
                    code = 0 if simple and matched_name and matched_password else 49
                    if transport != "plain" and not secure:
                        code = 13  # A misapplied selector must not pass in plaintext.
                    bound = code == 0
                    answer = response["protocolOp"]["bindResponse"]
                    record = {"operation": kind, "dn_matches": matched_name,
                              "password_matches": matched_password, "result_code": code,
                              "encrypted": secure}
                elif kind == "searchRequest":
                    request = message["protocolOp"]["searchRequest"]
                    base_matches = bytes(request["baseObject"]) == b"dc=example,dc=test"
                    filter = request["filter"]
                    filter_matches = (filter.getName() == "equalityMatch"
                                      and bytes(filter["equalityMatch"]["attributeDesc"]) == b"uid"
                                      and bytes(filter["equalityMatch"]["assertionValue"]) == b"ldap-test-user")
                    found = bound and base_matches and filter_matches
                    if found:
                        entry_message = ldap.LDAPMessage()
                        entry_message["messageID"] = message["messageID"]
                        entry = entry_message["protocolOp"]["searchResEntry"]
                        entry["objectName"] = config["dn"]
                        entry["attributes"][0]["type"] = "uid"
                        entry["attributes"][0]["vals"][0] = "ldap-test-user"
                        self.request.sendall(encoder.encode(entry_message))
                    code = 0 if bound else 50
                    answer = response["protocolOp"]["searchResDone"]
                    record = {"operation": kind, "result_code": code,
                              "base_matches": base_matches, "filter_matches": filter_matches,
                              "entries": int(found), "encrypted": secure}
                elif kind == "extendedReq":
                    request = message["protocolOp"]["extendedReq"]
                    if (transport != "starttls" or secure or pending
                            or bytes(request["requestName"]) != b"1.3.6.1.4.1.1466.20037"):
                        raise ValueError("unexpected LDAP extended operation")
                    code, start_tls = 0, True
                    answer = response["protocolOp"]["extendedResp"]
                    answer["responseName"] = "1.3.6.1.4.1.1466.20037"
                    record = {"operation": "startTls", "result_code": code}
                else:
                    raise ValueError("unexpected LDAP operation")
                answer["resultCode"] = code
                answer["matchedDN"] = ""
                answer["diagnosticMessage"] = ""
                record_observation(record)
                self.request.sendall(encoder.encode(response))
                if start_tls:
                    enable_tls()
                    secure = True


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
                      "port": server.server_address[1], "protocol": "ldap", "transport": transport,
                      "python_platform": sysconfig.get_platform()}), flush=True)
    server.serve_forever(poll_interval=0.1)
