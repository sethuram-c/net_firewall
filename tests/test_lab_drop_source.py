"""Phase 10: structural guardrails; runtime namespace test verifies behavior."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CODE = (ROOT / "kernel/netfw_hello.c").read_text()
SCRIPT = (ROOT / "scripts/test_lab_drop.sh").read_text()

class LabDropTests(unittest.TestCase):
    def test_opt_in_defaults_false(self):
        self.assertIn("static bool lab_drop;", CODE)
        self.assertIn("module_param(lab_drop, bool, 0444)", CODE)
    def test_exact_interface_gate(self):
        self.assertIn('NETFW_LAB_IFACE "nfwt10h"', CODE)
        self.assertIn('state->in->name, NETFW_LAB_IFACE, IFNAMSIZ', CODE)
    def test_destination_and_port_constraints(self):
        self.assertIn('NETFW_LAB_IPV4 0xC6120002U', CODE)
        self.assertIn('NETFW_LAB_UDP_PORT 54321', CODE)
        self.assertIn('ntohl(iph->daddr) == NETFW_LAB_IPV4', CODE)
        self.assertIn('ntohs(udp->dest) == NETFW_LAB_UDP_PORT', CODE)
    def test_only_one_drop_return(self):
        self.assertEqual(CODE.count('return NF_DROP;'), 1)
    def test_fragment_guard_precedes_drop(self):
        self.assertLess(CODE.index('if (frag_offset)'), CODE.index('return NF_DROP;'))
    def test_drop_only_after_udp_length_validation(self):
        self.assertLess(CODE.index('ntohs(udp->len) <= transport_len'), CODE.index('return NF_DROP;'))
    def test_script_cleanup(self):
        self.assertIn('trap cleanup EXIT', SCRIPT)
        self.assertIn('ip netns del', SCRIPT)
        self.assertIn('rmmod netfw_hello', SCRIPT)
    def test_script_udp_negative_positive_cases(self):
        self.assertIn('54321', SCRIPT)
        self.assertIn('54322', SCRIPT)
        self.assertIn('lab_drop=1', SCRIPT)
    def test_no_packet_heap_allocation(self):
        cb = CODE.split('static unsigned int netfw_observe',1)[1].split('static struct nf_hook_ops',1)[0]
        self.assertNotIn('kmalloc(',cb)
        self.assertNotIn('kfree(',cb)
