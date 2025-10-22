import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONN = (ROOT / "kernel/netfw_conn.h").read_text()
CODE = (ROOT / "kernel/netfw_hello.c").read_text()

class TcpStateTests(unittest.TestCase):
    def test_states(self):
        for item in ("NETFW_CONN_NEW", "NETFW_CONN_REPLIED", "NETFW_CONN_ESTABLISHED", "NETFW_CONN_CLOSING"):
            self.assertIn(item, CONN)
    def test_three_way_handshake(self):
        self.assertIn("entry->syn_seen", CONN)
        self.assertIn("NETFW_TCP_SYN", CONN)
        self.assertIn("NETFW_TCP_ACK", CONN)
    def test_direction_sensitive(self):
        self.assertIn("&& forward", CONN)
        self.assertIn("&& backward", CONN)
    def test_terminal(self):
        self.assertIn("NETFW_TCP_RST | NETFW_TCP_FIN", CONN)
        self.assertIn("entry->state != NETFW_CONN_CLOSING", CONN)
    def test_tcp_only(self):
        self.assertIn("key->protocol != IPPROTO_TCP", CONN)
    def test_locked(self):
        body = CONN.split("static inline int netfw_conn_tcp_step(")[1]
        self.assertIn("spin_lock_bh(&table->lock)", body)
        self.assertIn("spin_unlock_bh(&table->lock)", body)
    def test_snapshot(self):
        self.assertIn("info->state = entry->state", CONN)
        self.assertIn("info->direction = backward", CONN)
    def test_init_only(self):
        self.assertIn("netfw_conn_tcp_step(demo_conn", CODE)
        self.assertIn("reply_info.state != NETFW_CONN_CLOSING", CODE)
    def test_no_live_conntrack(self):
        self.assertNotIn("netfw_conn_tcp_step(", CODE.split("static unsigned int netfw_observe")[1].split("static struct nf_hook_ops")[0])

if __name__ == "__main__":
    unittest.main()
