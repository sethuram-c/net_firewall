"""Phase 6 structural regression tests; Fedora builds and runtime still required."""
from pathlib import Path
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / "kernel/netfw_hello.c").read_text()

class NetfilterHookSourceTests(unittest.TestCase):
    def test_hook_is_ipv4_prerouting(self):
        self.assertIn(".pf = NFPROTO_IPV4", SOURCE)
        self.assertIn(".hooknum = NF_INET_PRE_ROUTING", SOURCE)
    def test_hook_accepts_except_strict_lab_drop(self):
        callback = SOURCE.split("static unsigned int netfw_observe", 1)[1].split("static struct nf_hook_ops", 1)[0]
        self.assertIn("return NF_ACCEPT;", callback)
        self.assertIn("return NF_DROP;", callback)
        self.assertIn("if (lab_drop && state && state->in", callback)
        self.assertNotIn("pr_info(", callback)
    def test_registration_is_checked(self):
        self.assertIn("err = nf_register_net_hook(&init_net, &netfw_hook)", SOURCE)
        self.assertIn("if (err)", SOURCE)
        self.assertIn("goto err_free_label;", SOURCE)
    def test_unregister_before_free(self):
        exit_body = SOURCE.split("static void __exit", 1)[1].split("module_init", 1)[0]
        self.assertLess(exit_body.index("nf_unregister_net_hook"), exit_body.index("kfree(netfw_label)"))
    def test_no_per_packet_allocations(self):
        callback = SOURCE.split("static unsigned int netfw_observe", 1)[1].split("static struct nf_hook_ops", 1)[0]
        self.assertNotIn("kmalloc", callback)
        self.assertNotIn("kfree", callback)
    def test_fault_injection_still_available(self):
        self.assertIn("if (fail_step == 1)", SOURCE)
        self.assertIn("if (fail_step == 2)", SOURCE)

if __name__ == "__main__":
    unittest.main()
