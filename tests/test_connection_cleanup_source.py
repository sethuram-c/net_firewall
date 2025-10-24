"""Phase 24: synchronized connection cleanup source checks."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CODE = (ROOT / "kernel/netfw_conn.h").read_text()
MODULE = (ROOT / "kernel/netfw_hello.c").read_text()

class ConnectionCleanupTests(unittest.TestCase):
    def test_remove_api(self):
        self.assertIn("int netfw_conn_remove(", CODE)
    def test_count_snapshot_api(self):
        self.assertIn("unsigned int netfw_conn_count(", CODE)
    def test_clear_api(self):
        self.assertIn("void netfw_conn_clear(", CODE)
    def test_reverse_key_supported(self):
        self.assertIn("!netfw_flow_reverse_equal(&entry->key, key)", CODE)
    def test_removal_missing_is_enoent(self):
        self.assertIn("int result = -ENOENT;", CODE)
    def test_invalid_input_is_einval(self):
        self.assertRegex(CODE, r"netfw_conn_remove[\s\S]+?return -EINVAL;")
    def test_slot_and_count_reset(self):
        self.assertIn("memset(entry, 0, sizeof(*entry));", CODE)
        self.assertIn("--table->count;", CODE)
    def test_clear_does_not_reinitialize_lock(self):
        body = CODE.split("static inline void netfw_conn_clear(",1)[1].split("#endif",1)[0]
        self.assertIn("spin_lock_bh(&table->lock);", body)
        self.assertIn("spin_unlock_bh(&table->lock);", body)
        self.assertNotIn("spin_lock_init", body)
    def test_init_smoke_preserves_hook(self):
        self.assertIn("netfw_conn_remove(demo_conn, &incoming)", MODULE)
        self.assertIn("netfw_conn_clear(demo_conn);", MODULE)
        self.assertIn("nf_register_net_hook", MODULE)

if __name__ == "__main__":
    unittest.main()
