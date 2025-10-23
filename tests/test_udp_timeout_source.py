"""Phase 23 contract checks: UDP pseudo-state and inactivity expiry."""
import pathlib
import unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
CONN = (ROOT / 'kernel/netfw_conn.h').read_text()
KERNEL = (ROOT / 'kernel/netfw_hello.c').read_text()
SCRIPT = (ROOT / 'scripts/test_verdict_regression.sh').read_text()

class UDPTimeoutSourceTests(unittest.TestCase):
    def test_udp_api(self): self.assertIn('netfw_conn_udp_step(', CONN)
    def test_udp_only(self): self.assertIn('key->protocol != IPPROTO_UDP', CONN)
    def test_direction(self): self.assertIn('netfw_flow_reverse_equal', CONN)
    def test_reply_promotion(self): self.assertIn('entry->state = NETFW_CONN_REPLIED', CONN)
    def test_last_seen(self): self.assertIn('entry->last_seen = now', CONN)
    def test_distinct_udp_timeouts(self):
        self.assertIn('NETFW_UDP_NEW_TIMEOUT', CONN)
        self.assertIn('NETFW_UDP_REPLIED_TIMEOUT', CONN)
    def test_expire_lock_and_bounds(self):
        self.assertIn('netfw_conn_expire(', CONN)
        self.assertIn('spin_lock_bh(&table->lock)', CONN)
        self.assertIn('time_after_eq(now,', CONN)
    def test_init_smoke(self):
        self.assertIn('Phase 23: UDP reply pseudo-state', KERNEL)
        self.assertIn('netfw_conn_lookup(demo_conn, &udp_out, NULL)', KERNEL)
    def test_permission_safe_nested_script(self):
        self.assertIn('LAB_DROP_MODE=0 bash ./scripts/test_lab_drop.sh', SCRIPT)
        self.assertIn('LAB_DROP_MODE=1 bash ./scripts/test_lab_drop.sh', SCRIPT)
