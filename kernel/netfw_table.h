/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NETFW_TABLE_H
#define NETFW_TABLE_H

#include <linux/errno.h>
#include <linux/in.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include "netfw_policy.h"

/* Tiny fixed-size table: no allocations in the packet path. */
#define NETFW_MAX_RULES 16
#define NETFW_KNOWN_FLAGS (NETFW_MATCH_SRC_IP | NETFW_MATCH_DST_IP | \
                           NETFW_MATCH_SRC_PORT | NETFW_MATCH_DST_PORT | \
                           NETFW_MATCH_PROTOCOL | NETFW_MATCH_IN_IFACE)

struct netfw_table {
    spinlock_t lock;
    size_t count;
    enum netfw_rule_action default_action;
    struct netfw_rule rules[NETFW_MAX_RULES];
};

static inline void netfw_table_init(struct netfw_table *table,
                                    enum netfw_rule_action action)
{
    spin_lock_init(&table->lock);
    table->count = 0;
    table->default_action = (action == NETFW_RULE_DROP) ?
                            NETFW_RULE_DROP : NETFW_RULE_ACCEPT;
}

static inline bool netfw_rule_valid(const struct netfw_rule *rule)
{
    if (!rule || (rule->match_flags & ~NETFW_KNOWN_FLAGS))
        return false;
    if (rule->action != NETFW_RULE_ACCEPT &&
        rule->action != NETFW_RULE_DROP)
        return false;
    if ((rule->match_flags & NETFW_MATCH_IN_IFACE) &&
        !memchr(rule->in_iface, '\0', IFNAMSIZ))
        return false;
    if ((rule->match_flags & NETFW_MATCH_PROTOCOL) &&
        rule->protocol != IPPROTO_TCP && rule->protocol != IPPROTO_UDP &&
        rule->protocol != IPPROTO_ICMP)
        return false;
    if ((rule->match_flags & (NETFW_MATCH_SRC_PORT | NETFW_MATCH_DST_PORT)) &&
        (!(rule->match_flags & NETFW_MATCH_PROTOCOL) ||
         (rule->protocol != IPPROTO_TCP && rule->protocol != IPPROTO_UDP)))
        return false;
    return true;
}

/* May be called in process context; spin_lock_bh matches the eventual
 * Netfilter reader and protects rule entries AND count as one snapshot.
 */
static inline int netfw_table_add(struct netfw_table *table,
                                   const struct netfw_rule *rule)
{
    int ret = 0;

    if (!table || !netfw_rule_valid(rule))
        return -EINVAL;
    spin_lock_bh(&table->lock);
    if (table->count == NETFW_MAX_RULES) {
        ret = -ENOSPC;
    } else {
        table->rules[table->count] = *rule;
        table->count++;
    }
    spin_unlock_bh(&table->lock);
    return ret;
}

static inline void netfw_table_clear(struct netfw_table *table)
{
    if (!table)
        return;
    spin_lock_bh(&table->lock);
    table->count = 0;
    spin_unlock_bh(&table->lock);
}

/* Evaluation is read-only and bounded; no sleeping or allocations. */
static inline enum netfw_rule_action netfw_table_evaluate(
    struct netfw_table *table, __be32 src, __be32 dst, u8 protocol,
    __be16 sport, __be16 dport)
{
    enum netfw_rule_action result;

    if (!table)
        return NETFW_RULE_ACCEPT;
    spin_lock_bh(&table->lock);
    result = netfw_evaluate_rules(table->rules, table->count,
                                  table->default_action,
                                  src, dst, protocol, sport, dport);
    spin_unlock_bh(&table->lock);
    return result;
}

#endif /* NETFW_TABLE_H */
