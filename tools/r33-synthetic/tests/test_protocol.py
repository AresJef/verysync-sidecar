import errno
from pathlib import Path
import socket
import tempfile
import unittest

from r33_protocol import (
    DENIED, FRAME_MAX, Lease, ProtocolError, Request, decode_frame,
    encode_frame, peer_uid,
)


class RequestTests(unittest.TestCase):
    def test_only_the_four_protocol_fields_are_accepted(self):
        frame = encode_frame({"run": "a" * 32, "target": "linux", "operation": "observe",
                              "request": "x" * 16})
        self.assertEqual(Request.parse(decode_frame(frame)).target, "linux")
        for field, value in (("command", "owned-case"), ("url", "https://example.invalid"),
                             ("path", "/tmp/task")):
            item = decode_frame(frame)
            item[field] = value
            with self.subTest(field=field), self.assertRaises(ProtocolError):
                Request.parse(item)

    def test_malformed_duplicate_and_oversized_input_refused(self):
        for raw in (b'{"run":"a","run":"b"}\n', b'{"size":NaN}\n', b'[]\n',
                    b'{' + b' ' * FRAME_MAX + b'}\n', b'{}'):
            with self.subTest(size=len(raw)), self.assertRaises(ProtocolError):
                decode_frame(raw)

    def test_request_ids_are_fixed_and_cannot_supply_a_filename(self):
        with self.assertRaises(ProtocolError):
            Request.parse(dict(run="a"*32,target="pro",operation="observe",request="../output"))

    def test_kernel_identifies_a_real_unix_peer(self):
        import os
        with tempfile.TemporaryDirectory(prefix="r33p-") as temp:
            path = Path(temp) / "p"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(path))
                listener.listen(1)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.connect(str(path))
                    conn, _ = listener.accept()
                    with conn:
                        self.assertEqual(peer_uid(conn), os.getuid())


class LeaseTests(unittest.TestCase):
    def test_expiry_refuses_late_renewal_and_remains_revoked(self):
        lease = Lease(lifetime=90, now=10)
        self.assertTrue(lease.renew(25))
        self.assertTrue(lease.permits(114.99))
        self.assertFalse(lease.renew(115))
        self.assertFalse(lease.renew(116))
        self.assertFalse(lease.permits(116))

    def test_explicit_stop_refuses_operations_and_late_renewal(self):
        lease = Lease(lifetime=90, now=10)
        self.assertTrue(lease.revoke(12,"operator"))
        self.assertFalse(lease.permits(12))
        self.assertFalse(lease.renew(13))
        self.assertFalse(lease.revoke(14,"repeat"))
        self.assertEqual(lease.reason,"operator")


if __name__ == "__main__":
    unittest.main()
