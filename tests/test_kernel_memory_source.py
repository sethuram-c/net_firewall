"""Static safety checks; not a substitute for Fedora runtime checks."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "kernel/netfw_hello.c").read_text()

class KernelMemorySourceTests(unittest.TestCase):
    def test_allocation_in_init(self):
        self.assertIn("kmalloc(NETFW_MESSAGE_SIZE, GFP_KERNEL)", SOURCE)
    def test_allocation_failure(self):
        self.assertIn("if (!netfw_message)", SOURCE)
        self.assertIn("return -ENOMEM;", SOURCE)
    def test_release_in_exit(self):
        self.assertIn("kfree(netfw_message);", SOURCE)
        self.assertIn("netfw_message = NULL;", SOURCE)
    def test_copy_bounded(self):
        self.assertIn("strscpy(netfw_message,", SOURCE)
        self.assertNotIn("strcpy(", SOURCE)
    def test_observation_does_not_drop_packets(self):
        self.assertIn("return NF_ACCEPT;", SOURCE)
    def test_allocated_string_is_used(self):
        self.assertIn('pr_info("netfw_hello: %s;', SOURCE)

if __name__ == "__main__":
    unittest.main()
