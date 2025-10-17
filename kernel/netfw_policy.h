/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NETFW_POLICY_H
#define NETFW_POLICY_H

#include "netfw_match.h"
#include <linux/types.h>

/* Phase 17: first matching rule wins, otherwise apply default_action.
 * Inputs must come from validated IPv4/L4 headers. This pure helper does
 * not read skb memory, allocate memory, or alter the live Netfilter hook.
 * A caller must ensure rules points to count valid entries; count==0 is
 * valid even when rules==NULL. An invalid action is rejected at this layer.
 * An interface-constrained rule is skipped until interface matching lands.
 */
static inline enum netfw_rule_action netfw_evaluate_rules(
    const struct netfw_rule *rules, size_t count,
    enum netfw_rule_action default_action,
    __be32 packet_src, __be32 packet_dst, u8 packet_protocol,
    __be16 packet_src_port, __be16 packet_dst_port)
{
    size_t i;

    /* Fail open for invalid configuration, never dereference NULL. */
    if (default_action != NETFW_RULE_ACCEPT &&
        default_action != NETFW_RULE_DROP)
        return NETFW_RULE_ACCEPT;
    if (!rules)
        return default_action;

    for (i = 0; i < count; i++) {
        const struct netfw_rule *rule = &rules[i];

        /* Interface matching is not implemented yet. Do not silently
         * ignore that predicate or allow partial matches to decide. */
        if (rule->match_flags & NETFW_MATCH_IN_IFACE)
            continue;
        if (rule->action != NETFW_RULE_ACCEPT &&
            rule->action != NETFW_RULE_DROP)
            continue;
        if (netfw_match_packet(rule, packet_src, packet_dst,
                               packet_protocol, packet_src_port,
                               packet_dst_port))
            return rule->action;
    }
    return default_action;
}

#endif /* NETFW_POLICY_H */
