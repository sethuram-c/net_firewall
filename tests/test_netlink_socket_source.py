"""Phase 26: Netlink transport serialization and kernel hardening guards."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'userspace'))
import netfw_client as client


class NetlinkSocketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kernel = (ROOT / 'kernel/netfw_hello.c').read_text()

    def test_header_and_payload_length(self):
        wire = client.make_message(1, 42, 99)
        self.assertEqual(len(wire), 24)
        self.assertEqual(client.HEADER.unpack_from(wire)[0], 24)

    def test_command_and_request_id(self):
        wire = client.make_message(2, 0x01020304, 7)
        self.assertEqual(wire[-8:].hex(), '0102000001020304')

    def test_invalid_sequence(self):
        with self.assertRaises(ValueError):
            client.make_message(1, 1, -1)

    def test_reply_roundtrip(self):
        from netfw_protocol import encode_request
        payload = encode_request(1, 123)
        wire = client.HEADER.pack(24, 3, 0, 55, 0) + payload
        self.assertEqual(client.parse_reply(wire, 1, 123, 55).request_id, 123)

    def test_reject_mismatched_reply(self):
        from netfw_protocol import encode_request
        wire = client.HEADER.pack(24, 3, 0, 55, 0) + encode_request(1, 123)
        with self.assertRaises(ValueError):
            client.parse_reply(wire, 1, 999, 55)

    def test_socket_registration_and_release(self):
        self.assertIn('netlink_kernel_create(', self.kernel)
        self.assertIn('netlink_kernel_release(netfw_nl_sock)', self.kernel)

    def test_strict_length_and_version_validation(self):
        self.assertIn('nlmsg_ok(nlh, skb->len)', self.kernel)
        self.assertIn('nlh->nlmsg_len != nlmsg_msg_size', self.kernel)
        self.assertIn('netfw_nl_valid_request(&request)', self.kernel)

    def test_sender_identity_and_safe_allocation(self):
        self.assertIn('NETLINK_CB(skb).portid', self.kernel)
        self.assertIn('GFP_ATOMIC', self.kernel)
        self.assertIn('MSG_DONTWAIT', self.kernel)

    def test_hook_lifecycle_preserved(self):
        self.assertIn('nf_unregister_net_hook(&init_net, &netfw_hook)', self.kernel)
        self.assertEqual(self.kernel.count('return NF_DROP;'), 1)
        self.assertIn('goto err_free_label;', self.kernel)


if __name__ == '__main__':
    unittest.main()
