"""Phase 33: opt-in isolated staged UDP enforcement contract checks."""
from pathlib import Path
import unittest
R=Path(__file__).resolve().parents[1]
M=(R/'kernel/netfw_hello.c').read_text()
S=(R/'scripts/test_staged_lab_rules.sh').read_text()
class Phase33Tests(unittest.TestCase):
    def test_explicit_disabled_default(self):
        self.assertIn('static bool lab_rules;',M)
        self.assertIn('module_param(lab_rules, bool, 0444)',M)
    def test_separate_legacy_lab_switch(self):
        self.assertIn('module_param(lab_drop, bool, 0444)',M)
    def test_only_single_drop_verdict(self):
        self.assertEqual(M.count('return NF_DROP;'),1)
    def test_bound_to_lab_if_and_destination(self):
        hook=M.split('static unsigned int netfw_observe',1)[1].split('static struct nf_hook_ops',1)[0]
        self.assertIn('lab_rules && state && state->in',hook)
        self.assertIn('state->in->name, NETFW_LAB_IFACE',hook)
        self.assertIn('ntohl(iph->daddr) == NETFW_LAB_IPV4',hook)
    def test_validated_udp_only(self):
        self.assertLess(M.index('ntohs(udp->len) <= transport_len'),M.index('staged_drop = lab_rules'))
        self.assertIn('IPPROTO_UDP, udp->source, udp->dest',M)
    def test_lock_safe_evaluate(self):
        t=(R/'kernel/netfw_table.h').read_text()
        self.assertIn('spin_lock_bh(&table->lock)',t)
        self.assertIn('netfw_evaluate_rules(table->rules',t)
    def test_no_packet_allocation(self):
        hook=M.split('static unsigned int netfw_observe',1)[1].split('static struct nf_hook_ops',1)[0]
        self.assertNotIn('kmalloc(',hook)
    def test_namespace_cleanup(self):
        self.assertIn('trap cleanup EXIT',S)
        self.assertIn('ip netns del',S)
        self.assertIn('rmmod netfw_hello',S)
    def test_positive_and_negative_regression(self):
        self.assertIn('lab_rules=1 lab_drop=0',S)
        self.assertIn('54321',S)
        self.assertIn('54322',S)
        self.assertIn('apply --file',S)
if __name__=='__main__':unittest.main()
