import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "userspace"))
import netfw_protocol as proto


class NetlinkProtocolTests(unittest.TestCase):
    def test_fixed_size(self):
        self.assertEqual(proto.PAYLOAD_SIZE, 8)

    def test_known_encoding(self):
        self.assertEqual(proto.encode_request(1, 0x01020304), bytes.fromhex("0101000001020304"))

    def test_roundtrip(self):
        self.assertEqual(proto.decode_request(proto.encode_request(2, 77)).request_id, 77)

    def test_bad_command(self):
        with self.assertRaises(ValueError): proto.encode_request(99, 1)

    def test_bad_id(self):
        with self.assertRaises(ValueError): proto.encode_request(1, -1)

    def test_bad_length(self):
        with self.assertRaises(ValueError): proto.decode_request(b"abc")

    def test_bad_version(self):
        with self.assertRaises(ValueError): proto.decode_request(bytes.fromhex("0201000000000001"))

    def test_reserved_rejected(self):
        with self.assertRaises(ValueError): proto.decode_request(bytes.fromhex("0101000100000001"))

    def test_kernel_schema_matches(self):
        h=(Path(__file__).resolve().parents[1]/"kernel/netfw_netlink.h").read_text()
        for token in ("NETFW_NL_VERSION 1", "NETFW_NL_CMD_PING 1", "NETFW_NL_CMD_STATUS 2", "NETFW_NL_PAYLOAD_BYTES 8", "__be32 request_id_be", "netfw_nl_valid_request"):
            self.assertIn(token,h)


if __name__ == "__main__": unittest.main()
