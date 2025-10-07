"""Phase 7 no-root checks; runtime checks are required on Fedora."""
from pathlib import Path
import unittest
SOURCE=(Path(__file__).resolve().parents[1]/"kernel/netfw_hello.c").read_text()
CALLBACK=SOURCE.split("static unsigned int netfw_observe",1)[1].split("static struct nf_hook_ops",1)[0]

class IPv4HeaderSourceTests(unittest.TestCase):
    def test_ipv4_types(self):
        self.assertIn("#include <linux/ip.h>",SOURCE)
        self.assertIn("struct iphdr iph_buf",CALLBACK)
    def test_network_offset_bounds(self):
        self.assertIn("skb_network_offset(skb)",CALLBACK)
        self.assertIn("offset < 0",CALLBACK)
        self.assertIn("skb->len - offset < sizeof(iph_buf)",CALLBACK)
    def test_non_linear_safe_read(self):
        self.assertIn("skb_header_pointer(skb, offset, sizeof(iph_buf), &iph_buf)",CALLBACK)
        self.assertNotIn("(struct iphdr *)skb->data",CALLBACK)
    def test_header_validity(self):
        self.assertIn("iph->version != 4",CALLBACK)
        self.assertIn("iph->ihl < 5",CALLBACK)
        self.assertIn("wire_len < header_len",CALLBACK)
        self.assertIn("wire_len > skb->len - offset",CALLBACK)
    def test_observer_only(self):
        self.assertIn("return NF_ACCEPT;",CALLBACK)
        self.assertNotIn("NF_DROP",CALLBACK)
        self.assertNotIn("kmalloc(",CALLBACK)
    def test_bounded_logging(self):
        self.assertIn("pr_info_ratelimited",CALLBACK)
        self.assertIn("%pI4",CALLBACK)
    def test_lifecycle_preserved(self):
        self.assertIn("nf_unregister_net_hook(&init_net, &netfw_hook)",SOURCE)
        self.assertIn("module_param(fail_step, int, 0444)",SOURCE)

if __name__ == "__main__":
    unittest.main()
