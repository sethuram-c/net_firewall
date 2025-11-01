/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NETFW_MANAGE_H
#define NETFW_MANAGE_H

#include <linux/errno.h>
#include <linux/string.h>
#include "netfw_table.h"

/* Phase 31: validate the WHOLE candidate before publishing ANY of it.
 * authorized is a trusted decision from the kernel caller, NOT a userspace
 * payload field. Future Netlink integration must check CAP_NET_ADMIN using
 * the socket sender credentials before calling this function.
 */
static inline int netfw_manage_replace(struct netfw_table *table,
                                       const struct netfw_rule *candidate,
                                       size_t count,
                                       enum netfw_rule_action default_action,
                                       bool authorized)
{
    size_t i;

    if (!authorized)
        return -EPERM;
    if (!table || count > NETFW_MAX_RULES || (count && !candidate) ||
        (default_action != NETFW_RULE_ACCEPT &&
         default_action != NETFW_RULE_DROP))
        return -EINVAL;
    for (i = 0; i < count; ++i) {
        if (!netfw_rule_valid(&candidate[i]) ||
            (candidate[i].match_flags & NETFW_MATCH_IN_IFACE))
            return -EINVAL;
    }

    /* Validate before acquiring the lock: invalid requests never mutate.
     * One short critical section publishes rule order, count and policy.
     */
    spin_lock_bh(&table->lock);
    if (count)
        memcpy(table->rules, candidate, count * sizeof(*candidate));
    table->count = count;
    table->default_action = default_action;
    spin_unlock_bh(&table->lock);
    return 0;
}

#endif /* NETFW_MANAGE_H */
