/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NETFW_FLOW_H
#define NETFW_FLOW_H

#include <linux/types.h>
#include <linux/in.h>

/* Phase 19: a flow identity, NOT a tracking table or a packet verdict.
 * IP addresses and ports are always in network byte order.
 * TCP/UDP flow endpoints can be compared in either direction.
 */
struct netfw_flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    u8 protocol;
};

static inline bool netfw_flow_equal(const struct netfw_flow_key *a,
                                    const struct netfw_flow_key *b)
{
    return a && b && a->protocol == b->protocol &&
           a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port && a->dst_port == b->dst_port;
}

static inline bool netfw_flow_reverse_equal(const struct netfw_flow_key *a,
                                            const struct netfw_flow_key *b)
{
    return a && b && a->protocol == b->protocol &&
           a->src_ip == b->dst_ip && a->dst_ip == b->src_ip &&
           a->src_port == b->dst_port && a->dst_port == b->src_port;
}

/* These helpers describe TCP/UDP endpoints only. ICMP requires a different
 * key model (type/code/identifier) and is intentionally out of scope.
 */
static inline bool netfw_flow_is_transport(const struct netfw_flow_key *key)
{
    return key && (key->protocol == IPPROTO_TCP || key->protocol == IPPROTO_UDP);
}

#endif /* NETFW_FLOW_H */
