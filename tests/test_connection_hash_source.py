import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CODE = (ROOT / "kernel/netfw_conn.h").read_text()
MOD = (ROOT / "kernel/netfw_hello.c").read_text()


class ConnectionHashTests(unittest.TestCase):
    def test_guard_and_dependency(self):
        self.assertIn("#ifndef NETFW_CONN_H", CODE)
        self.assertIn('#include "netfw_flow.h"', CODE)

    def test_bounded_layout(self):
        for token in ("NETFW_CONN_BUCKETS 8", "NETFW_CONN_SLOTS 4",
                      "NETFW_CONN_CAPACITY", "struct netfw_conn_entry"):
            self.assertIn(token, CODE)

    def test_symmetric_hash(self):
        self.assertIn("key->src_ip ^ (__force u32)key->dst_ip", CODE)
        self.assertIn("key->src_port", CODE)
        self.assertIn("key->dst_port", CODE)

    def test_forward_and_reverse(self):
        self.assertIn("netfw_flow_equal(&entry->key, key)", CODE)
        self.assertIn("netfw_flow_reverse_equal(&entry->key, key)", CODE)

    def test_locking(self):
        self.assertIn("spin_lock_bh(&table->lock)", CODE)
        self.assertIn("spin_unlock_bh(&table->lock)", CODE)

    def test_rejects_invalid_and_duplicate(self):
        self.assertIn("netfw_flow_is_transport(key)", CODE)
        self.assertIn("-EINVAL", CODE)
        self.assertIn("-EEXIST", CODE)

    def test_bounded_overflow(self):
        self.assertIn("-ENOSPC", CODE)
        self.assertIn("++table->count", CODE)

    def test_no_per_packet_dynamic_memory(self):
        self.assertNotIn("kmalloc(", CODE)
        hook = MOD.split("static unsigned int netfw_observe", 1)[1].split("static struct nf_hook_ops", 1)[0]
        self.assertNotIn("netfw_conn_lookup(", hook)
        self.assertNotIn("netfw_conn_add(", hook)

    def test_init_only_smoke(self):
        self.assertIn('#include "netfw_conn.h"', MOD)
        self.assertIn("netfw_conn_init(demo_conn)", MOD)
        self.assertIn("netfw_conn_lookup(demo_conn, &incoming, &reverse)", MOD)
        self.assertIn("kfree(demo_conn)", MOD)


if __name__ == "__main__":
    unittest.main()
