/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NETFW_MATCH_H
#define NETFW_MATCH_H

#include "netfw_rule.h"
#include <linux/in.h>
#include <linux/byteorder/generic.h>

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


/* Ports in the rule are host-order u16; packet ports are __be16.
 * Port matching is only meaningful for TCP/UDP. The protocol argument
 * comes from a previously validated IPv4 header. Unknown/ICMP protocols
 * never satisfy an enabled port condition.
 */
static inline bool netfw_match_ports(const struct netfw_rule *rule,
                                      u8 protocol,
                                      __be16 packet_src_port,
                                      __be16 packet_dst_port)
{
    const u32 port_flags = NETFW_MATCH_SRC_PORT | NETFW_MATCH_DST_PORT;

    if (!(rule->match_flags & port_flags))
        return true;

    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
        return false;

    if ((rule->match_flags & NETFW_MATCH_SRC_PORT) &&
        ntohs(packet_src_port) != rule->src_port)
        return false;

    if ((rule->match_flags & NETFW_MATCH_DST_PORT) &&
        ntohs(packet_dst_port) != rule->dst_port)
        return false;

    return true;
}

#endif /* NETFW_MATCH_H */
