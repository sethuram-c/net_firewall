import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = (ROOT / "kernel/netfw_conn.h").read_text()
MODULE = (ROOT / "kernel/netfw_hello.c").read_text()

class ConnectionMetadataTests(unittest.TestCase):
    def test_state_enum(self):
        self.assertIn("enum netfw_conn_state", HEADER)
        self.assertIn("NETFW_CONN_NEW", HEADER)
        self.assertIn("NETFW_CONN_REPLIED", HEADER)
    def test_direction_enum(self):
        self.assertIn("enum netfw_flow_direction", HEADER)
        self.assertIn("NETFW_FLOW_ORIGINAL", HEADER)
        self.assertIn("NETFW_FLOW_REPLY", HEADER)
    def test_snapshot_contract(self):
        self.assertIn("struct netfw_conn_info", HEADER)
        self.assertIn("netfw_conn_lookup_info", HEADER)
    def test_lock_protects_metadata(self):
        fn = HEADER.split("static inline bool netfw_conn_lookup_info", 1)[1].split("/* Compatibility wrapper", 1)[0]
        self.assertIn("spin_lock_bh(&table->lock)", fn)
        self.assertIn("spin_unlock_bh(&table->lock)", fn)
        self.assertIn("info->state = entry->state", fn)
    def test_reverse_direction(self):
        self.assertIn("backward ? NETFW_FLOW_REPLY : NETFW_FLOW_ORIGINAL", HEADER)
    def test_new_entries_start_new(self):
        self.assertIn("table->bucket[bucket][vacant].state = NETFW_CONN_NEW", HEADER)
    def test_old_api_preserved(self):
        self.assertIn("static inline bool netfw_conn_lookup(", HEADER)
        self.assertIn("info.direction == NETFW_FLOW_REPLY", HEADER)
    def test_init_smoke_direction_and_state(self):
        for token in ("original_info.direction != NETFW_FLOW_ORIGINAL", "reply_info.direction != NETFW_FLOW_REPLY", "reply_info.state != NETFW_CONN_NEW"):
            self.assertIn(token, MODULE)
    def test_no_live_tracking_or_state_transition(self):
        hook = MODULE.split("static unsigned int netfw_observe", 1)[1].split("static struct nf_hook_ops", 1)[0]
        self.assertNotIn("netfw_conn_lookup_info(", hook)
        self.assertNotIn("netfw_conn_add(", hook)
        self.assertNotIn("NETFW_CONN_REPLIED", hook)

if __name__ == "__main__":
    unittest.main()
