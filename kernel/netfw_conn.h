/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NETFW_CONN_H
#define NETFW_CONN_H

#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include "netfw_flow.h"

/* Phase 20: fixed-capacity demo index. Each bucket has four fixed slots.
 * No allocations or state changes occur in the Netfilter packet callback.
 */
#define NETFW_CONN_BUCKETS 8
#define NETFW_CONN_SLOTS 4
#define NETFW_CONN_CAPACITY (NETFW_CONN_BUCKETS * NETFW_CONN_SLOTS)

/* Phase 21 metadata describes direction and conceptual connection progress.
 * State is only initialized; no live packet-based transitions occur yet.
 */
enum netfw_conn_state {
    NETFW_CONN_NEW = 0,
    NETFW_CONN_REPLIED = 1,
};

enum netfw_flow_direction {
    NETFW_FLOW_ORIGINAL = 0,
    NETFW_FLOW_REPLY = 1,
};

struct netfw_conn_info {
    enum netfw_conn_state state;
    enum netfw_flow_direction direction;
};

struct netfw_conn_entry {
    bool used;
    struct netfw_flow_key key;
    enum netfw_conn_state state;
};

struct netfw_conn_table {
    spinlock_t lock;
    unsigned int count;
    struct netfw_conn_entry bucket[NETFW_CONN_BUCKETS][NETFW_CONN_SLOTS];
};

/* XORing endpoints produces the SAME bucket for forward and reverse keys.
 * __be types are bit patterns: only equality and XOR are used, not arithmetic
 * on host-order IP addresses or ports. Collision resolution scans a bucket.
 */
static inline unsigned int netfw_conn_bucket(const struct netfw_flow_key *key)
{
    u32 mix = (__force u32)key->src_ip ^ (__force u32)key->dst_ip;

    mix ^= (u32)(__force u16)key->src_port;
    mix ^= (u32)(__force u16)key->dst_port;
    mix ^= key->protocol;
    mix ^= mix >> 16;
    mix ^= mix >> 8;
    return mix % NETFW_CONN_BUCKETS;
}

static inline void netfw_conn_init(struct netfw_conn_table *table)
{
    memset(table, 0, sizeof(*table));
    spin_lock_init(&table->lock);
}

/* Copy a small snapshot while locked; never expose table entry pointers.
 * A reverse-direction lookup does NOT automatically change the state.
 */
static inline bool netfw_conn_lookup_info(struct netfw_conn_table *table,
                                          const struct netfw_flow_key *key,
                                          struct netfw_conn_info *info)
{
    unsigned int bucket, slot;
    bool found = false;

    if (!table || !netfw_flow_is_transport(key))
        return false;
    bucket = netfw_conn_bucket(key);
    spin_lock_bh(&table->lock);
    for (slot = 0; slot < NETFW_CONN_SLOTS; ++slot) {
        const struct netfw_conn_entry *entry = &table->bucket[bucket][slot];
        bool forward, backward;

        if (!entry->used)
            continue;
        forward = netfw_flow_equal(&entry->key, key);
        backward = !forward && netfw_flow_reverse_equal(&entry->key, key);
        if (!forward && !backward)
            continue;
        if (info) {
            info->state = entry->state;
            info->direction = backward ? NETFW_FLOW_REPLY : NETFW_FLOW_ORIGINAL;
        }
        found = true;
        break;
    }
    spin_unlock_bh(&table->lock);
    return found;
}

/* Compatibility wrapper preserves the existing Phase 20 API. */
static inline bool netfw_conn_lookup(struct netfw_conn_table *table,
                                     const struct netfw_flow_key *key,
                                     bool *reverse)
{
    struct netfw_conn_info info;
    bool found;

    if (reverse)
        *reverse = false;
    found = netfw_conn_lookup_info(table, key, &info);
    if (found && reverse)
        *reverse = info.direction == NETFW_FLOW_REPLY;
    return found;
}

static inline int netfw_conn_add(struct netfw_conn_table *table,
                                 const struct netfw_flow_key *key)
{
    unsigned int bucket, slot;
    int vacant = -1;
    int result = 0;

    if (!table || !netfw_flow_is_transport(key))
        return -EINVAL;
    bucket = netfw_conn_bucket(key);
    spin_lock_bh(&table->lock);
    for (slot = 0; slot < NETFW_CONN_SLOTS; ++slot) {
        const struct netfw_conn_entry *entry = &table->bucket[bucket][slot];

        if (!entry->used) {
            if (vacant < 0)
                vacant = slot;
            continue;
        }
        if (netfw_flow_equal(&entry->key, key) ||
            netfw_flow_reverse_equal(&entry->key, key)) {
            result = -EEXIST;
            goto out;
        }
    }
    if (vacant < 0) {
        result = -ENOSPC; /* Bucket-local limit: may occur before 32 total. */
        goto out;
    }
    table->bucket[bucket][vacant].key = *key;
    table->bucket[bucket][vacant].state = NETFW_CONN_NEW;
    table->bucket[bucket][vacant].used = true;
    ++table->count;
out:
    spin_unlock_bh(&table->lock);
    return result;
}

#endif /* NETFW_CONN_H */
