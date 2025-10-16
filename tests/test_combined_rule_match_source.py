"""Phase 16 protocol + combined matcher source contracts."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MATCH = (ROOT / "kernel/netfw_match.h").read_text()
MODULE = (ROOT / "kernel/netfw_hello.c").read_text()

class CombinedRuleTests(unittest.TestCase):
    def test_protocol_helper(self):
        self.assertIn("bool netfw_match_protocol(", MATCH)
    def test_protocol_wildcard(self):
        self.assertIn("if (!(rule->match_flags & NETFW_MATCH_PROTOCOL))", MATCH)
    def test_protocol_exact_match(self):
        self.assertIn("rule->protocol == packet_protocol", MATCH)
    def test_combined_helper(self):
        self.assertIn("bool netfw_match_packet(", MATCH)
    def test_null_guard(self):
        self.assertIn("if (!rule)", MATCH)
    def test_source_and_destination(self):
        self.assertIn("netfw_match_src_ipv4(rule, packet_src) &&", MATCH)
        self.assertIn("netfw_match_dst_ipv4(rule, packet_dst) &&", MATCH)
    def test_protocol_and_ports(self):
        self.assertIn("netfw_match_protocol(rule, packet_protocol) &&", MATCH)
        self.assertIn("netfw_match_ports(rule, packet_protocol,", MATCH)
    def test_init_positive_and_negative(self):
        self.assertIn("netfw_match_packet(&demo_rule, 0, 0, IPPROTO_TCP", MODULE)
        self.assertIn("netfw_match_packet(&demo_rule, 0, 0, IPPROTO_UDP", MODULE)
    def test_no_runtime_policy_change(self):
        before_init = MODULE.split("static int __init")[0]
        self.assertNotIn("netfw_match_packet(", before_init)
        self.assertEqual(MODULE.count("return NF_DROP;"), 1)
        self.assertNotIn("kmalloc(", MATCH)

if __name__ == "__main__":
    unittest.main()
