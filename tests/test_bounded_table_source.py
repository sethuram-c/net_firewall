import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TABLE = (ROOT / 'kernel/netfw_table.h').read_text()
MODULE = (ROOT / 'kernel/netfw_hello.c').read_text()

class TableSourceTests(unittest.TestCase):
    def test_capacity(self):
        self.assertIn('#define NETFW_MAX_RULES 16', TABLE)
    def test_spinlock(self):
        self.assertIn('spinlock_t lock;', TABLE)
        self.assertIn('spin_lock_init(&table->lock)', TABLE)
    def test_reader_writer_lock(self):
        self.assertGreaterEqual(TABLE.count('spin_lock_bh(&table->lock)'), 3)
        self.assertGreaterEqual(TABLE.count('spin_unlock_bh(&table->lock)'), 3)
    def test_bounds_error(self):
        self.assertIn('table->count == NETFW_MAX_RULES', TABLE)
        self.assertIn('-ENOSPC', TABLE)
    def test_validates_action_flags(self):
        self.assertIn('~NETFW_KNOWN_FLAGS', TABLE)
        self.assertIn('rule->action != NETFW_RULE_DROP', TABLE)
    def test_port_protocol_requirements(self):
        self.assertIn('NETFW_MATCH_SRC_PORT | NETFW_MATCH_DST_PORT', TABLE)
        self.assertIn('IPPROTO_UDP', TABLE)
    def test_ordering(self):
        self.assertLess(TABLE.index('table->rules[table->count] = *rule'), TABLE.index('table->count++'))
    def test_evaluates_existing_ordered_engine(self):
        self.assertIn('netfw_evaluate_rules(table->rules, table->count', TABLE)
    def test_init_only_integration(self):
        self.assertIn('#include "netfw_table.h"', MODULE)
        self.assertIn('netfw_table_add(demo_table, &drop)', MODULE)
        self.assertIn('kfree(demo_table)', MODULE)
        hook = MODULE.split('static unsigned int netfw_observe',1)[1].split('static struct nf_hook_ops',1)[0]
        self.assertNotIn('netfw_table_evaluate', hook)

if __name__ == '__main__':
    unittest.main()
