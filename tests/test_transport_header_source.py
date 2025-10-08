"""Phase 8 invariant tests (not a substitute for real packet runtime tests)."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CODE = (ROOT / "kernel/netfw_hello.c").read_text()
SCRIPT = (ROOT / "scripts/test_transport_observe.sh").read_text()

class TransportSourceTests(unittest.TestCase):
    def test_transport_headers(self):
        self.assertIn("#include <linux/tcp.h>", CODE)
        self.assertIn("#include <linux/udp.h>", CODE)
    def test_tcp_and_udp_detection(self):
        self.assertIn("IPPROTO_TCP", CODE)
        self.assertIn("IPPROTO_UDP", CODE)
    def test_fragment_offset_guard(self):
        self.assertRegex(CODE, r"frag_offset\s*=\s*ntohs\(iph->frag_off\)\s*&\s*(?:IP_OFFSET|0x1[Ff]{3})\s*;")
        self.assertRegex(CODE, r"if \(frag_offset\)")
    def test_bounded_transport_reads(self):
        self.assertIn("transport_len >= sizeof(tcp_buf)", CODE)
        self.assertIn("transport_len >= sizeof(udp_buf)", CODE)
        self.assertIn("skb_header_pointer(skb, transport_offset", CODE)
    def test_tcp_header_size(self):
        self.assertIn("tcp->doff >= 5", CODE)
        self.assertIn("tcp->doff * 4 <= transport_len", CODE)
    def test_udp_length_checks(self):
        self.assertIn("ntohs(udp->len) >= sizeof(udp_buf)", CODE)
        self.assertIn("ntohs(udp->len) <= transport_len", CODE)
    def test_network_order_ports(self):
        self.assertIn("ntohs(tcp->source)", CODE)
        self.assertIn("ntohs(tcp->dest)", CODE)
        self.assertIn("ntohs(udp->source)", CODE)
        self.assertIn("ntohs(udp->dest)", CODE)
    def test_accept_only(self):
        self.assertNotIn("NF_DROP", CODE)
        self.assertGreaterEqual(CODE.count("return NF_ACCEPT;"), 3)
    def test_runtime_script_unloads(self):
        self.assertIn("trap cleanup EXIT", SCRIPT)
        self.assertIn("rmmod netfw_hello", SCRIPT)

if __name__ == "__main__": unittest.main()
