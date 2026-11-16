"""Opt-in peer observations hide credentials and preserve command dispatch."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("storage_peer", Path(__file__).resolve().parents[1] / "storage-test-services.py")
PEER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PEER)


class FtpObservationContracts(unittest.TestCase):
    def test_only_fixed_command_names_are_emitted_and_arguments_are_absent(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            PEER.ftp_observation("command", "PASS")
            PEER.ftp_observation("command", "PASS synthetic-secret")
            PEER.ftp_observation("authenticated", "synthetic-user")
        rows = [json.loads(x) for x in stderr.getvalue().splitlines()]
        self.assertEqual(rows, [{"owned_ftp_event": "command", "command": "PASS"},
                                {"owned_ftp_event": "command", "command": "OTHER"},
                                {"owned_ftp_event": "authenticated"}])
        self.assertNotIn("synthetic-secret", stderr.getvalue())
        self.assertNotIn("synthetic-user", stderr.getvalue())

    def test_unknown_event_is_refused_without_output(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(ValueError):
            PEER.ftp_observation("unrecognized")
        self.assertEqual(stderr.getvalue(), "")

    def test_default_handler_is_unobserved_and_opt_in_preserves_exact_parent_call(self):
        calls = []

        class Authorizer:
            def add_user(self, *args, **kwargs):
                pass

        class Handler:
            def pre_process_command(self, line, cmd, arg):
                calls.append((line, cmd, arg))
                return "original-parent-result"

            def on_login(self, username):
                pass

        class Server:
            def __init__(self, address, handler):
                self.handler = handler
                self.socket = types.SimpleNamespace(getsockname=lambda: ("127.0.0.1", 35001))

            def serve_forever(self, **kwargs):
                instance = self.handler()
                result = instance.pre_process_command("PASS synthetic-secret", "PASS", "synthetic-secret")
                if result != "original-parent-result":
                    raise AssertionError("original protocol result changed")
                instance.on_login("synthetic-user")

        parent = types.ModuleType("pyftpdlib"); parent.__path__ = []
        modules = {"pyftpdlib": parent,
                   "pyftpdlib.authorizers": types.SimpleNamespace(DummyAuthorizer=Authorizer),
                   "pyftpdlib.handlers": types.SimpleNamespace(FTPHandler=Handler, DTPHandler=object),
                   "pyftpdlib.servers": types.SimpleNamespace(FTPServer=Server)}
        for observed in [False, True]:
            config = {"user": "synthetic-user", "password": "synthetic-secret"}
            if observed:
                config["record_ftp_events"] = True
            stderr, stdout = io.StringIO(), io.StringIO()
            with patch.dict(sys.modules, modules), contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
                PEER.ftp(config, Path("/owned-synthetic-root"))
            self.assertEqual(calls[-1], ("PASS synthetic-secret", "PASS", "synthetic-secret"))
            self.assertEqual(json.loads(stdout.getvalue())["loopback_only"], True)
            self.assertNotIn("synthetic-secret", stderr.getvalue())
            self.assertNotIn("synthetic-user", stderr.getvalue())
            self.assertEqual(bool(stderr.getvalue()), observed)


class SftpKeyOnlyContracts(unittest.TestCase):
    def test_key_only_peer_refuses_password_and_wrong_key_without_affecting_default(self):
        config = {"user": "owned-user", "password": "owned-password", "sftp_key_only": True}
        key = object()
        self.assertTrue(PEER.sftp_authentication_allowed(config, "owned-user", key, key, "publickey"))
        self.assertFalse(PEER.sftp_authentication_allowed(config, "owned-user", object(), key, "publickey"))
        self.assertFalse(PEER.sftp_authentication_allowed(config, "other-user", key, key, "publickey"))
        self.assertFalse(PEER.sftp_authentication_allowed(config, "owned-user", "owned-password", key, "password"))
        self.assertFalse(PEER.sftp_authentication_allowed(config, "owned-user", key, key, "unknown"))
        config.pop("sftp_key_only")
        self.assertTrue(PEER.sftp_authentication_allowed(config, "owned-user", "owned-password", key, "password"))
        self.assertFalse(PEER.sftp_authentication_allowed(config, "owned-user", "wrong-password", key, "password"))


if __name__ == "__main__":
    unittest.main()
