"""Phase 15 source contracts: compile on Fedora with make check-build."""
import unittest
from pathlib import Path
R = Path(__file__).resolve().parents[1]
MATCH = (R / 'kernel/netfw_match.h').read_text()
MODULE = (R / 'kernel/netfw_hello.c').read_text()
RULE = (R / 'kernel/netfw_rule.h').read_text()

class PortMatchSourceTests(unittest.TestCase):
    def test_both_port_flags(self):
        self.assertIn('NETFW_MATCH_SRC_PORT', MATCH)
        self.assertIn('NETFW_MATCH_DST_PORT', MATCH)
    def test_helper_signature(self):
        self.assertIn('bool netfw_match_ports(', MATCH)
        self.assertIn('__be16 packet_src_port', MATCH)
        self.assertIn('__be16 packet_dst_port', MATCH)
    def test_wildcard(self):
        self.assertIn('if (!(rule->match_flags & port_flags))', MATCH)
    def test_only_tcp_udp(self):
        self.assertIn('protocol != IPPROTO_TCP && protocol != IPPROTO_UDP', MATCH)
    def test_network_order_conversion(self):
        self.assertIn('ntohs(packet_src_port)', MATCH)
        self.assertIn('ntohs(packet_dst_port)', MATCH)
    def test_host_order_rule_fields(self):
        self.assertIn('u16 src_port;', RULE)
        self.assertIn('u16 dst_port;', RULE)
    def test_source_and_destination_checks(self):
        self.assertIn('!= rule->src_port', MATCH)
        self.assertIn('!= rule->dst_port', MATCH)
    def test_init_smoke_and_negative_cases(self):
        self.assertIn('netfw_match_ports(&demo_ports, IPPROTO_TCP', MODULE)
        self.assertIn('netfw_match_ports(&demo_ports, IPPROTO_UDP', MODULE)
        self.assertIn('netfw_match_ports(&demo_ports, IPPROTO_ICMP', MODULE)
    def test_no_policy_change(self):
        self.assertEqual(MODULE.count('return NF_DROP;'), 1)
        self.assertNotIn('netfw_match_ports(', MODULE.split('static int __init')[0])
        self.assertNotIn('kmalloc(', MATCH)

if __name__ == '__main__': unittest.main()
