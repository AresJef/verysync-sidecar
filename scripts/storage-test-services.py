#!/usr/bin/env python3
"""Explicit test-only, loopback storage servers; never used by the Rust SDK.

The parent supplies one private JSON configuration over stdin and retains this
exact process until cleanup. Credentials are never command-line arguments or
ready-output values. No system service, user account or SSH configuration changes.
"""
import argparse
import errno
import json
import logging
import os
from pathlib import Path
import socket
import sys
import sysconfig
import threading


def ready(protocol, port):
    if not 0 < port <= 65535 or port == 18886:
        raise ValueError("invalid owned test endpoint")
    print(json.dumps({"ready": True, "protocol": protocol, "port": port,
                      "loopback_only": True,
                      "python_platform": sysconfig.get_platform()}), flush=True)


def ftp(config, root):
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer

    authorizer = DummyAuthorizer()
    authorizer.add_user(config["user"], config["password"], str(root),
                        perm="elradfmwMT")
    handler = type("OwnedFTPHandler", (FTPHandler,), {"authorizer": authorizer})
    server = FTPServer(("127.0.0.1", 0), handler)
    server.max_cons = 32
    server.max_cons_per_ip = 32
    ready("ftp", server.socket.getsockname()[1])
    server.serve_forever(timeout=0.1, blocking=True, handle_exit=False)


def webdav(config, root):
    from cheroot.wsgi import Server
    from wsgidav.wsgidav_app import WsgiDAVApp

    app = WsgiDAVApp({
        "provider_mapping": {"/": str(root)},
        "simple_dc": {"user_mapping": {"*": {
            config["user"]: {"password": config["password"], "roles": []}}}},
        "http_authenticator": {"accept_basic": True, "accept_digest": False,
                               "default_to_digest": False},
        "verbose": 0, "logging": {"enable": False},
        "dir_browser": {"enable": False},
    })
    server = Server(("127.0.0.1", 0), app, numthreads=8)
    server.prepare()
    ready("webdav", server.socket.getsockname()[1])
    server.serve()


def sftp(config, root):
    import paramiko

    def retained_key(name):
        path = root.parent / name
        if path.exists():
            return paramiko.RSAKey.from_private_key_file(str(path))
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(str(path))
        os.chmod(path, 0o600)
        return key

    host_key = retained_key("synthetic-host-key.pem")
    client_key = retained_key("synthetic-client-key.pem")

    class Auth(paramiko.ServerInterface):
        def check_auth_password(self, username, password):
            return (paramiko.AUTH_SUCCESSFUL if username == config["user"]
                    and password == config["password"] else paramiko.AUTH_FAILED)

        def check_auth_publickey(self, username, key):
            return (paramiko.AUTH_SUCCESSFUL if username == config["user"]
                    and key == client_key else paramiko.AUTH_FAILED)

        def get_allowed_auths(self, username):
            return "password,publickey"

        def check_channel_request(self, kind, channel_id):
            return (paramiko.OPEN_SUCCEEDED if kind == "session"
                    else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

    def contained(path):
        candidate = (root / path.lstrip("/")).resolve()
        if not candidate.is_relative_to(root):
            raise PermissionError(errno.EACCES, "outside synthetic share")
        return candidate

    def guarded(method):
        def call(self, *args):
            try:
                return method(self, *args)
            except OSError as error:
                return paramiko.SFTPServer.convert_errno(error.errno or errno.EIO)
        return call

    class Handle(paramiko.SFTPHandle):
        def __init__(self, flags, stream, path):
            super().__init__(flags)
            self.stream, self.path = stream, path
            if not flags & os.O_WRONLY:
                self.readfile = stream
            if flags & (os.O_WRONLY | os.O_RDWR):
                self.writefile = stream

        @guarded
        def stat(self):
            return paramiko.SFTPAttributes.from_stat(os.fstat(self.stream.fileno()))

        @guarded
        def chattr(self, attributes):
            paramiko.SFTPServer.set_file_attr(str(self.path), attributes)
            return paramiko.SFTP_OK

    class Files(paramiko.SFTPServerInterface):
        @guarded
        def list_folder(self, path):
            result = []
            for item in contained(path).iterdir():
                attr = paramiko.SFTPAttributes.from_stat(item.lstat())
                attr.filename = item.name
                result.append(attr)
            return result

        @guarded
        def stat(self, path):
            return paramiko.SFTPAttributes.from_stat(contained(path).stat())

        @guarded
        def lstat(self, path):
            return paramiko.SFTPAttributes.from_stat(contained(path).lstat())

        @guarded
        def open(self, path, flags, attributes):
            path = contained(path)
            fd = os.open(path, flags, 0o600)
            mode = "r+b" if flags & os.O_RDWR else "wb" if flags & os.O_WRONLY else "rb"
            try:
                stream = os.fdopen(fd, mode)
            except BaseException:
                os.close(fd)
                raise
            return Handle(flags, stream, path)

        @guarded
        def remove(self, path):
            contained(path).unlink()
            return paramiko.SFTP_OK

        @guarded
        def rename(self, old, new):
            if contained(new).exists():
                raise FileExistsError(errno.EEXIST, "target exists")
            contained(old).rename(contained(new))
            return paramiko.SFTP_OK

        @guarded
        def posix_rename(self, old, new):
            contained(old).replace(contained(new))
            return paramiko.SFTP_OK

        @guarded
        def mkdir(self, path, attributes):
            contained(path).mkdir(mode=0o700)
            return paramiko.SFTP_OK

        @guarded
        def rmdir(self, path):
            contained(path).rmdir()
            return paramiko.SFTP_OK

        @guarded
        def chattr(self, path, attributes):
            paramiko.SFTPServer.set_file_attr(str(contained(path)), attributes)
            return paramiko.SFTP_OK

        def canonicalize(self, path):
            try:
                relative = contained(path).relative_to(root)
                return "/" if relative == Path(".") else "/" + relative.as_posix()
            except OSError:
                return "/"

    def connection(sock):
        transport = paramiko.Transport(sock)
        transport.banner_timeout = 5
        transport.auth_timeout = 5
        transport.handshake_timeout = 5
        try:
            transport.add_server_key(host_key)
            transport.set_subsystem_handler("sftp", paramiko.SFTPServer, Files)
            transport.start_server(server=Auth())
            channels = []
            while transport.is_active():
                channel = transport.accept(timeout=0.2)
                channels = [item for item in channels if not item.closed]
                if channel is not None:
                    channels.append(channel)
        except (EOFError, OSError, paramiko.SSHException):
            pass
        finally:
            transport.close()

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    ready("sftp", listener.getsockname()[1])
    while True:
        sock, _ = listener.accept()
        threading.Thread(target=connection, args=(sock,), daemon=True).start()


def smb(config, root):
    from impacket.smbserver import SimpleSMBServer, SMB2Commands
    from impacket import smb3structs as smb2
    from impacket.ntlm import compute_lmhash, compute_nthash
    server = SimpleSMBServer(listenAddress="127.0.0.1", listenPort=0)
    server.setSMB2Support(True)

    def logoff_with_session_identity(conn_id, smb_server, request):
        # MS-SMB2 3.2.5.4 requires locating the session by response SessionId:
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0936b9c0-51a3-4e7f-8fdf-de008f2675ed
        # Impacket 0.13.1 clears Uid before constructing its LOGOFF response.
        # Preserve the request session in the response header while retaining
        # the handler's actual authentication teardown and status. Otherwise
        # go-smb2 discards that zero-session response and waits indefinitely.
        commands, _, status = SMB2Commands.smb2Logoff(conn_id, smb_server, request)
        packet = smb2.SMB2Packet()
        packet["Flags"] = smb2.SMB2_FLAGS_SERVER_TO_REDIR
        packet["Status"] = status
        for field in ("Command", "CreditCharge", "MessageID", "TreeID", "SessionID"):
            packet[field] = request[field]
        packet["CreditRequestResponse"] = request["CreditRequestResponse"]
        packet["Data"] = commands[0].getData()
        return None, [packet], status

    server.getServer().hookSmb2Command(smb2.SMB2_LOGOFF, logoff_with_session_identity)

    def create_with_named_missing_status(conn_id, smb_server, request):
        commands, packets, status = SMB2Commands.smb2Create(conn_id, smb_server, request)
        # Impacket uses STATUS_NO_SUCH_FILE for an absent FILE_OPEN name.
        # MS-SMB2 CREATE uses STATUS_OBJECT_NAME_NOT_FOUND for absent names:
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/8c61e928-9242-44ed-96a0-98d1032d0d39
        # Return the SMB2 named-object absence code, never a successful open.
        # Native clients distinguish this from other failures before mkdir.
        if status == 0xC000000F:
            status = 0xC0000034  # STATUS_OBJECT_NAME_NOT_FOUND
        return commands, packets, status

    server.getServer().hookSmb2Command(smb2.SMB2_CREATE, create_with_named_missing_status)
    server.addShare("synthetic", str(root))
    server.addCredential(config["user"], 0, compute_lmhash(config["password"]),
                         compute_nthash(config["password"]))
    # Impacket's two private named-pipe RPC listeners are also loopback-only.
    # Retain these exact in-process threads until the owned fixture process exits.
    ready("smb", server.getServer().server_address[1])
    server.start()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", choices=["ftp", "sftp", "webdav", "smb"], required=True)
    args = parser.parse_args()
    raw = sys.stdin.buffer.readline(65537)
    if len(raw) > 65536 or not raw.endswith(b"\n"):
        raise ValueError("bounded private fixture configuration required")
    config = json.loads(raw)
    root = Path(config["root"]).resolve(strict=True)
    if not root.is_dir() or not config["user"] or not config["password"]:
        raise ValueError("explicit synthetic directory and credentials required")
    logging.basicConfig(level=logging.ERROR)
    {"ftp": ftp, "sftp": sftp, "webdav": webdav, "smb": smb}[args.protocol](config, root)


if __name__ == "__main__":
    main()
