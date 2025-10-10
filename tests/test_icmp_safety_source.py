"""Phase 9 source-level regression checks; compilation is required separately."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CODE = (ROOT / "kernel/netfw_hello.c").read_text()

class IcmpSafetySourceTests(unittest.TestCase):
    def test_icmp_header_included(self):
        self.assertIn("#include <linux/icmp.h>", CODE)
    def test_icmp_branch(self):
        self.assertIn("iph->protocol == IPPROTO_ICMP", CODE)
    def test_header_bounds(self):
        self.assertIn("transport_len >= sizeof(icmp_buf)", CODE)
    def test_nonlinear_safe_read(self):
        self.assertRegex(CODE, r"skb_header_pointer\(skb, transport_offset,\s*sizeof\(icmp_buf\), &icmp_buf\)")
    def test_type_code_logging(self):
        self.assertIn("icmp->type, icmp->code", CODE)
    def test_ipv4_length_guards(self):
        self.assertIn("wire_len < header_len", CODE)
        self.assertIn("wire_len > skb->len - offset", CODE)
    def test_noninitial_fragments_skip_l4(self):
        self.assertIn("if (frag_offset)", CODE)
        self.assertIn("return NF_ACCEPT;", CODE)
    def test_lab_opt_in_drop_only(self):
        self.assertIn("return NF_DROP;", CODE)
        self.assertIn("lab_drop && state && state->in", CODE)
        self.assertIn(".hooknum = NF_INET_PRE_ROUTING", CODE)
    def test_no_per_packet_heap_alloc(self):
        hook = CODE.split("static unsigned int netfw_observe",1)[1].split("static struct nf_hook_ops",1)[0]
        self.assertNotIn("kmalloc(", hook)

if __name__ == "__main__": unittest.main()
