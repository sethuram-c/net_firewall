"""Phase 32 source and Python contract checks (unprivileged)."""
import pathlib
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "userspace"))
import netfw_protocol as proto
import netfw_client as cli

SAMPLE = {"version": 1, "default_action": "ACCEPT", "rules": [
    {"action": "DROP", "protocol": "UDP", "dst_port": 54321}]}

class AuthenticatedRuleUpdates(unittest.TestCase):
    def test_command(self):
        self.assertEqual(proto.CMD_REPLACE, 4)
        self.assertIn(4, proto.COMMANDS)
    def test_encodes_exact_size(self):
        wire = proto.encode_replace_request(SAMPLE, 37)
        self.assertEqual(len(wire), 16 + 44)
        self.assertEqual(wire[:8], proto.encode_request(4, 37))
    def test_network_order_fields(self):
        wire = proto.encode_replace_request(SAMPLE)
        self.assertEqual(struct.unpack_from("!I", wire, 16)[0], 24)
        self.assertEqual(struct.unpack_from("!H", wire, 16+22)[0], 54321)
    def test_empty_candidate(self):
        wire = proto.encode_replace_request({"version": 1, "default_action": "DROP", "rules": []})
        self.assertEqual(len(wire), 16)
        self.assertEqual(wire[13], 1)
    def test_reject_interface(self):
        with self.assertRaises(ValueError):
            proto.encode_replace_request({"version": 1, "default_action": "ACCEPT", "rules":
                [{"action": "DROP", "in_iface": "eth0"}]})
    def test_reject_too_many(self):
        with self.assertRaises(ValueError):
            proto.encode_replace_request({"version": 1, "default_action": "ACCEPT", "rules":
                [{"action": "ACCEPT"}] * 17})
    def test_kernel_credentials(self):
        code = (ROOT / "kernel/netfw_hello.c").read_text()
        self.assertIn("netlink_capable(skb, CAP_NET_ADMIN)", code)
        self.assertIn("netfw_manage_replace(&netfw_export_table", code)
    def test_isolated_from_packet_path(self):
        code = (ROOT / "kernel/netfw_hello.c").read_text()
        hook = code.split("static unsigned int netfw_observe", 1)[1].split("static int __init", 1)[0]
        self.assertIn("netfw_table_evaluate(&netfw_export_table", hook)
        self.assertIn("lab_rules && state && state->in", hook)
    def test_cli_apply(self):
        code = (ROOT / "userspace/netfw_client.py").read_text()
        self.assertIn('args.command == "apply"', code)
        self.assertIn("staging table only", code)

if __name__ == "__main__":
    unittest.main()
