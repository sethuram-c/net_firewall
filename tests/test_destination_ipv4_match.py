"""Phase 14: static contracts; make check-build is needed for kernel compilation."""
import re
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
MATCH = (ROOT / 'kernel/netfw_match.h').read_text()
RULE = (ROOT / 'kernel/netfw_rule.h').read_text()
MODULE = (ROOT / 'kernel/netfw_hello.c').read_text()
class DestinationIPv4MatchTests(unittest.TestCase):
    def test_destination_helper_defined(self):
        self.assertIn('netfw_match_dst_ipv4(', MATCH)
    def test_destination_flag_wildcard(self):
        self.assertRegex(MATCH, r'if\s*\(!\(rule->match_flags & NETFW_MATCH_DST_IP\)\)\s*return true;')
    def test_both_masked(self):
        self.assertIn('packet_dst & rule->dst_mask', MATCH)
        self.assertIn('rule->dst_ip & rule->dst_mask', MATCH)
    def test_network_byte_order(self):
        self.assertIn('__be32 packet_dst', MATCH)
        self.assertIn('__be32 dst_ip;', RULE)
        self.assertIn('__be32 dst_mask;', RULE)
    def test_source_matcher_preserved(self):
        self.assertIn('netfw_match_src_ipv4(', MATCH)
        self.assertIn('packet_src & rule->src_mask', MATCH)
    def test_no_allocations_packet_access(self):
        self.assertNotIn('kmalloc(', MATCH)
        self.assertNotIn('skb_', MATCH)
    def test_compiler_smoke_usage(self):
        self.assertIn('netfw_match_dst_ipv4(&demo_dst, 0)', MODULE)
    def test_no_runtime_rule_evaluation_yet(self):
        self.assertNotIn('netfw_evaluate_rule(', MODULE)
    def test_lab_drop_remains_only_drop(self):
        self.assertEqual(MODULE.count('return NF_DROP;'), 1)
        self.assertIn('if (lab_drop && state && state->in', MODULE)
if __name__ == '__main__': unittest.main()
