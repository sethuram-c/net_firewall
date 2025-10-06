"""Phase 2 static checks; actual loading requires a Fedora host/VM."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class ModuleSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "kernel/netfw_hello.c").read_text()
        cls.makefile = (ROOT / "Makefile").read_text()

    def test_declares_init_and_exit(self):
        self.assertIn("module_init(netfw_hello_init)", self.source)
        self.assertIn("module_exit(netfw_hello_exit)", self.source)

    def test_gpl_metadata(self):
        self.assertIn('MODULE_LICENSE("GPL")', self.source)

    def test_packet_verdict_is_accept_only(self):
        self.assertIn("nf_register_net_hook", self.source)
        self.assertNotIn("return NF_DROP", self.source)

    def test_external_kbuild(self):
        self.assertIn("obj-m += kernel/netfw_hello.o", self.makefile)
        self.assertIn("M=$(PWD) modules", self.makefile)

if __name__ == "__main__":
    unittest.main()
