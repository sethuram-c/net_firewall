/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NETFW_MATCH_H
#define NETFW_MATCH_H

#include "netfw_rule.h"

/* Match one IPv4 source address against an optional rule field.
 * All addresses and masks are __be32 (network order). Bitwise AND works
 * on identically represented operands; never mix host/network order here.
 * If the SRC_IP flag is absent, this field is a wildcard.
 * No packet memory is accessed and no allocation is performed.
 */
static inline bool netfw_match_src_ipv4(const struct netfw_rule *rule,
                                         __be32 packet_src)
{
    if (!(rule->match_flags & NETFW_MATCH_SRC_IP))
        return true;

    return (packet_src & rule->src_mask) ==
           (rule->src_ip & rule->src_mask);
}

/* Match an optional destination IPv4 network; the flag is the wildcard
 * indicator, not a zero address. Addresses and masks are network order.
 */
static inline bool netfw_match_dst_ipv4(const struct netfw_rule *rule,
                                        __be32 packet_dst)
{
    if (!(rule->match_flags & NETFW_MATCH_DST_IP))
        return true;

    return (packet_dst & rule->dst_mask) ==
           (rule->dst_ip & rule->dst_mask);
}

#endif /* NETFW_MATCH_H */
