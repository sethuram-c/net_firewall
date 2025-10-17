import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
POLICY = (ROOT / 'kernel/netfw_policy.h').read_text()
MODULE = (ROOT / 'kernel/netfw_hello.c').read_text()

class OrderedPolicyTests(unittest.TestCase):
    def test_helper_exists(self):
        self.assertIn('netfw_evaluate_rules(', POLICY)
    def test_iterates_in_order(self):
        self.assertIn('for (i = 0; i < count; i++)', POLICY)
    def test_first_match_returns_immediately(self):
        self.assertRegex(POLICY, r'if \(netfw_match_packet\([\s\S]+?return rule->action;')
    def test_default_fallback(self):
        self.assertIn('return default_action;', POLICY)
    def test_null_rules(self):
        self.assertIn('if (!rules)', POLICY)
    def test_action_validation(self):
        self.assertIn('rule->action != NETFW_RULE_DROP', POLICY)
    def test_no_interface_bypass(self):
        self.assertIn('rule->match_flags & NETFW_MATCH_IN_IFACE', POLICY)
    def test_no_heap_or_packet_access(self):
        self.assertNotIn('kmalloc(', POLICY)
        self.assertNotIn('skb_', POLICY)
    def test_init_smoke_and_no_live_integration(self):
        self.assertIn('#include "netfw_policy.h"', MODULE)
        self.assertIn('ARRAY_SIZE(demo_rules)', MODULE)
        self.assertEqual(MODULE.count('return NF_DROP;'), 1)
        self.assertIn('if (lab_drop && state && state->in', MODULE)

if __name__ == '__main__':
    unittest.main()
