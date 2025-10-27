"""Phase 27: status-bearing errors and CLI argument handling."""
import errno
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "userspace"))
import netfw_client as client
import netfw_protocol as protocol

class NetlinkErrorsCliTests(unittest.TestCase):
    def wire(self, status=0, cmd=1, reqid=10, seq=9):
        payload = struct.pack("!BBHIi", 1, cmd, 0, reqid, status)
        return client.HEADER.pack(28, 3, 0, seq, 0) + payload

    def test_response_layout(self):
        self.assertEqual(protocol.RESPONSE_SIZE, 12)
    def test_decode_success(self):
        r = protocol.decode_response(self.wire()[16:])
        self.assertEqual((r.version,r.request_id,r.status), (1,10,0))
    def test_invalid_response_size(self):
        with self.assertRaises(ValueError): protocol.decode_response(b"a")
    def test_reserved_not_accepted(self):
        p = bytearray(self.wire()[16:]); p[2] = 1
        with self.assertRaises(ValueError): protocol.decode_response(bytes(p))
    def test_error_raises_oserror(self):
        with self.assertRaises(OSError) as e:
            client.parse_reply(self.wire(-errno.EINVAL),1,10,9)
        self.assertEqual(e.exception.errno, errno.EINVAL)
    def test_success_roundtrip(self):
        self.assertEqual(client.parse_reply(self.wire(),1,10,9).status,0)
    def test_bad_sequence_rejected(self):
        with self.assertRaises(ValueError): client.parse_reply(self.wire(),1,10,8)
    def test_cli_ping(self):
        with patch.object(client,"request",return_value=protocol.Response(1,1,42,0)):
            self.assertEqual(client.main(["ping","--request-id","42"]),0)
    def test_kernel_error_paths(self):
        k=(ROOT/"kernel/netfw_hello.c").read_text()
        h=(ROOT/"kernel/netfw_netlink.h").read_text()
        self.assertIn("-EPROTONOSUPPORT",k)
        self.assertIn("-EOPNOTSUPP",k)
        self.assertIn("cpu_to_be32((u32)status)",k)
        self.assertIn("struct netfw_nl_response",h)
        self.assertEqual(k.count("return NF_DROP;"),1)

if __name__ == "__main__": unittest.main()
