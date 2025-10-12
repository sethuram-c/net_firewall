"""Phase 12: rule representation only; these are source checks, not runtime checks."""
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
HEADER=(ROOT/'kernel/netfw_rule.h').read_text()
SOURCE=(ROOT/'kernel/netfw_hello.c').read_text()

class RuleStructureTests(unittest.TestCase):
    def test_header_guard(self):
        self.assertIn('#ifndef NETFW_RULE_H', HEADER)
        self.assertIn('#define NETFW_RULE_H', HEADER)
    def test_actions(self):
        self.assertIn('NETFW_RULE_ACCEPT = 0', HEADER)
        self.assertIn('NETFW_RULE_DROP = 1', HEADER)
    def test_match_presence_flags(self):
        for field in ('SRC_IP','DST_IP','SRC_PORT','DST_PORT','PROTOCOL','IN_IFACE'):
            self.assertIn('NETFW_MATCH_'+field, HEADER)
        self.assertIn('u32 match_flags;', HEADER)
    def test_addresses_and_masks_are_network_order(self):
        for field in ('src_ip','src_mask','dst_ip','dst_mask'):
            self.assertIn('__be32 '+field+';', HEADER)
    def test_port_protocol_types(self):
        self.assertIn('u16 src_port;',HEADER)
        self.assertIn('u16 dst_port;',HEADER)
        self.assertIn('u8 protocol;', HEADER)
    def test_interface_is_bounded(self):
        self.assertIn('char in_iface[IFNAMSIZ];',HEADER)
    def test_kernel_includes_descriptor(self):
        self.assertIn('#include "netfw_rule.h"', SOURCE)
        self.assertIn('sizeof(struct netfw_rule)', SOURCE)
    def test_existing_lab_policy_preserved(self):
        self.assertIn('if (lab_drop && state && state->in',SOURCE)
        self.assertEqual(SOURCE.count('return NF_DROP;'), 1)
    def test_no_early_rule_evaluation(self):
        self.assertNotIn('netfw_evaluate_rule(', SOURCE)
        self.assertIn('inactive', SOURCE)
if __name__=='__main__': unittest.main()
