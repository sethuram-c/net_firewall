"""Phase 13: source-level contract checks (not substitutes for Fedora Kbuild)."""
import re
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
MATCH = (ROOT / 'kernel/netfw_match.h').read_text()
RULE = (ROOT / 'kernel/netfw_rule.h').read_text()
MODULE = (ROOT / 'kernel/netfw_hello.c').read_text()

class SourceIPv4MatchTests(unittest.TestCase):
    def test_matcher_header_guard(self):
        self.assertIn('#ifndef NETFW_MATCH_H', MATCH)
    def test_matcher_uses_rule_contract(self):
        self.assertIn('#include "netfw_rule.h"', MATCH)
        self.assertIn('struct netfw_rule *rule', MATCH)
    def test_source_ip_flag_controls_wildcard(self):
        self.assertIn('rule->match_flags & NETFW_MATCH_SRC_IP', MATCH)
        self.assertRegex(MATCH, r'if\s*\(!\(rule->match_flags & NETFW_MATCH_SRC_IP\)\)\s*return true;')
    def test_mask_both_addresses(self):
        self.assertIn('packet_src & rule->src_mask', MATCH)
        self.assertIn('rule->src_ip & rule->src_mask', MATCH)
    def test_network_order_types(self):
        self.assertIn('__be32 packet_src', MATCH)
        self.assertIn('__be32 src_ip;', RULE)
        self.assertIn('__be32 src_mask;', RULE)
    def test_no_allocations_or_packet_mutations(self):
        self.assertNotIn('kmalloc(', MATCH)
        self.assertNotIn('skb_', MATCH)
    def test_integrated_compile_path(self):
        self.assertIn('#include "netfw_match.h"', MODULE)
        self.assertIn('netfw_match_src_ipv4(&demo, 0)', MODULE)
    def test_existing_lab_drop_unchanged(self):
        self.assertEqual(MODULE.count('return NF_DROP;'), 1)
        self.assertIn('if (lab_drop && state && state->in', MODULE)
    def test_no_rule_table_yet(self):
        self.assertNotIn('netfw_evaluate_rule(', MODULE)

if __name__ == '__main__':
    unittest.main()
