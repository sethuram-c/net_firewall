/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NETFW_SNAPSHOT_H
#define NETFW_SNAPSHOT_H

#include <linux/errno.h>
#include <linux/string.h>
#include "netfw_table.h"

/* Fixed-capacity, read-only COPY. No internal table pointers escape. */
struct netfw_rule_snapshot {
    size_t count;
    enum netfw_rule_action default_action;
    struct netfw_rule rules[NETFW_MAX_RULES];
};

/* Caller supplies storage; never allocate or sleep under the spinlock.
 * Copy count, policy, and ordered rules while protected by ONE lock.
 */
static inline int netfw_table_snapshot(struct netfw_table *table,
                                       struct netfw_rule_snapshot *out)
{
    size_t count;

    if (!table || !out)
        return -EINVAL;
    spin_lock_bh(&table->lock);
    count = table->count;
    if (count > NETFW_MAX_RULES) {
        spin_unlock_bh(&table->lock);
        return -EOVERFLOW;
    }
    /* Zero unused slots to avoid exposing stale data in future exports. */
    memset(out, 0, sizeof(*out));
    out->count = count;
    out->default_action = table->default_action;
    memcpy(out->rules, table->rules, count * sizeof(table->rules[0]));
    spin_unlock_bh(&table->lock);
    return 0;
}
#endif /* NETFW_SNAPSHOT_H */
