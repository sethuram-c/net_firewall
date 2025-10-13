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

#endif /* NETFW_MATCH_H */
