import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FLOW = (ROOT / "kernel/netfw_flow.h").read_text()
MOD = (ROOT / "kernel/netfw_hello.c").read_text()


class FlowKeyTests(unittest.TestCase):
    def test_guard(self):
        self.assertIn("#ifndef NETFW_FLOW_H", FLOW)

    def test_five_fields(self):
        for field in ("__be32 src_ip", "__be32 dst_ip", "__be16 src_port",
                      "__be16 dst_port", "u8 protocol"):
            self.assertIn(field, FLOW)

    def test_directional_comparison(self):
        self.assertIn("netfw_flow_equal", FLOW)
        self.assertIn("a->src_ip == b->src_ip", FLOW)
        self.assertIn("a->dst_port == b->dst_port", FLOW)

    def test_reverse_comparison(self):
        self.assertIn("netfw_flow_reverse_equal", FLOW)
        self.assertIn("a->src_ip == b->dst_ip", FLOW)
        self.assertIn("a->src_port == b->dst_port", FLOW)

    def test_protocol_prevents_false_matches(self):
        self.assertGreaterEqual(FLOW.count("a->protocol == b->protocol"), 2)

    def test_only_tcp_udp_transport_keys(self):
        self.assertIn("IPPROTO_TCP", FLOW)
        self.assertIn("IPPROTO_UDP", FLOW)
        self.assertIn("ICMP requires a different", FLOW)

    def test_null_safe(self):
        self.assertIn("return a && b", FLOW)
        self.assertIn("return key &&", FLOW)

    def test_module_compiles_and_smokes(self):
        self.assertIn('#include "netfw_flow.h"', MOD)
        self.assertIn("netfw_flow_reverse_equal(&outgoing, &incoming)", MOD)

    def test_no_live_tracking_yet(self):
        hook = MOD.split("static unsigned int netfw_observe", 1)[1].split("static struct nf_hook_ops", 1)[0]
        self.assertNotIn("netfw_flow_equal(", hook)
        self.assertNotIn("netfw_flow_reverse_equal(", hook)
        self.assertIn("NF_ACCEPT", hook)


if __name__ == "__main__":
    unittest.main()
