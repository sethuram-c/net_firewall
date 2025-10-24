/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NETFW_CONN_H
#define NETFW_CONN_H

#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include "netfw_flow.h"

/* Phase 20: fixed-capacity demo index. Each bucket has four fixed slots.
 * No allocations or state changes occur in the Netfilter packet callback.
 */
#define NETFW_CONN_BUCKETS 8
#define NETFW_CONN_SLOTS 4
#define NETFW_CONN_CAPACITY (NETFW_CONN_BUCKETS * NETFW_CONN_SLOTS)

/* Phase 22: lightweight TCP handshake model, not RFC-complete tracking. */
enum netfw_conn_state {
    NETFW_CONN_NEW = 0,
    NETFW_CONN_REPLIED = 1,
    NETFW_CONN_ESTABLISHED = 2,
    NETFW_CONN_CLOSING = 3,
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
    bool syn_seen;
    unsigned long last_seen;
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
    table->bucket[bucket][vacant].syn_seen = false;
    table->bucket[bucket][vacant].last_seen = jiffies;
    table->bucket[bucket][vacant].used = true;
    ++table->count;
out:
    spin_unlock_bh(&table->lock);
    return result;
}


/* These are the low byte of TCP flags, not netfilter verdicts. */
#define NETFW_TCP_FIN 0x01
#define NETFW_TCP_SYN 0x02
#define NETFW_TCP_RST 0x04
#define NETFW_TCP_ACK 0x10

/* Update one previously inserted TCP flow using a deliberately small model.
 * Caller must have validated the TCP header and extracted its flags.
 * The five-tuple + direction are checked while holding the bucket lock.
 * Return -ENOENT for unknown flows and -EINVAL for invalid protocol/input.
 * This is NOT TCP sequence-number validation or a security-grade conntrack.
 */
static inline int netfw_conn_tcp_step(struct netfw_conn_table *table,
                                      const struct netfw_flow_key *key,
                                      u8 flags, struct netfw_conn_info *info)
{
    unsigned int bucket, slot;
    int result = -ENOENT;

    if (!table || !key || key->protocol != IPPROTO_TCP ||
        !netfw_flow_is_transport(key))
        return -EINVAL;
    bucket = netfw_conn_bucket(key);
    spin_lock_bh(&table->lock);
    for (slot = 0; slot < NETFW_CONN_SLOTS; ++slot) {
        struct netfw_conn_entry *entry = &table->bucket[bucket][slot];
        bool forward, backward;

        if (!entry->used)
            continue;
        forward = netfw_flow_equal(&entry->key, key);
        backward = !forward && netfw_flow_reverse_equal(&entry->key, key);
        if (!forward && !backward)
            continue;
        if (entry->state != NETFW_CONN_CLOSING) {
            if (flags & (NETFW_TCP_RST | NETFW_TCP_FIN)) {
                /* Simplification: FIN and RST both enter terminal CLOSING. */
                entry->state = NETFW_CONN_CLOSING;
            } else if (entry->state == NETFW_CONN_NEW && forward &&
                       (flags & NETFW_TCP_SYN) && !(flags & NETFW_TCP_ACK)) {
                entry->syn_seen = true;
            } else if (entry->state == NETFW_CONN_NEW && backward &&
                       entry->syn_seen && (flags & NETFW_TCP_SYN) &&
                       (flags & NETFW_TCP_ACK)) {
                entry->state = NETFW_CONN_REPLIED;
            } else if (entry->state == NETFW_CONN_REPLIED && forward &&
                       (flags & NETFW_TCP_ACK) && !(flags & NETFW_TCP_SYN)) {
                entry->state = NETFW_CONN_ESTABLISHED;
            }
        }
        if (info) {
            info->state = entry->state;
            info->direction = backward ? NETFW_FLOW_REPLY : NETFW_FLOW_ORIGINAL;
        }
        result = 0;
        break;
    }
    spin_unlock_bh(&table->lock);
    return result;
}


/* Phase 23: demo-only UDP pseudo-state and inactivity timeout.
 * Callers supply a monotonic jiffies timestamp; no work queues or timers run.
 * Reply traffic promotes NEW -> REPLIED; this is NOT authenticated UDP state.
 * Return -ENOENT on missing flow, -EINVAL on invalid inputs.
 */
#define NETFW_UDP_NEW_TIMEOUT (30 * HZ)
#define NETFW_UDP_REPLIED_TIMEOUT (120 * HZ)
#define NETFW_TCP_IDLE_TIMEOUT (300 * HZ)

static inline unsigned long netfw_conn_timeout(const struct netfw_conn_entry *entry)
{
    if (entry->key.protocol == IPPROTO_UDP)
        return entry->state == NETFW_CONN_REPLIED ?
               NETFW_UDP_REPLIED_TIMEOUT : NETFW_UDP_NEW_TIMEOUT;
    return NETFW_TCP_IDLE_TIMEOUT;
}

static inline int netfw_conn_udp_step(struct netfw_conn_table *table,
                                      const struct netfw_flow_key *key,
                                      unsigned long now,
                                      struct netfw_conn_info *info)
{
    unsigned int bucket, slot;
    int result = -ENOENT;

    if (!table || !key || key->protocol != IPPROTO_UDP ||
        !netfw_flow_is_transport(key))
        return -EINVAL;
    bucket = netfw_conn_bucket(key);
    spin_lock_bh(&table->lock);
    for (slot = 0; slot < NETFW_CONN_SLOTS; ++slot) {
        struct netfw_conn_entry *entry = &table->bucket[bucket][slot];
        bool forward, backward;

        if (!entry->used)
            continue;
        forward = netfw_flow_equal(&entry->key, key);
        backward = !forward && netfw_flow_reverse_equal(&entry->key, key);
        if (!forward && !backward)
            continue;
        if (backward)
            entry->state = NETFW_CONN_REPLIED;
        entry->last_seen = now;
        if (info) {
            info->state = entry->state;
            info->direction = backward ? NETFW_FLOW_REPLY : NETFW_FLOW_ORIGINAL;
        }
        result = 0;
        break;
    }
    spin_unlock_bh(&table->lock);
    return result;
}

/* Explicit bounded expiration scan. Never return pointers to deleted entries.
 * Does not mutate live Netfilter packet behavior or schedule background work.
 */
static inline unsigned int netfw_conn_expire(struct netfw_conn_table *table,
                                             unsigned long now)
{
    unsigned int b, slot, removed = 0;

    if (!table)
        return 0;
    spin_lock_bh(&table->lock);
    for (b = 0; b < NETFW_CONN_BUCKETS; ++b) {
        for (slot = 0; slot < NETFW_CONN_SLOTS; ++slot) {
            struct netfw_conn_entry *entry = &table->bucket[b][slot];

            if (!entry->used)
                continue;
            if (!time_after_eq(now, entry->last_seen +
                                   netfw_conn_timeout(entry)))
                continue;
            memset(entry, 0, sizeof(*entry));
            --table->count;
            ++removed;
        }
    }
    spin_unlock_bh(&table->lock);
    return removed;
}

/* Phase 24: explicit synchronized removal and teardown. All operations
 * keep the shared table protected, and never return entry pointers.
 * Call clear only after stopping producers when destroying a live table.
 */
static inline unsigned int netfw_conn_count(struct netfw_conn_table *table)
{
    unsigned int count;

    if (!table)
        return 0;
    spin_lock_bh(&table->lock);
    count = table->count;
    spin_unlock_bh(&table->lock);
    return count;
}

static inline int netfw_conn_remove(struct netfw_conn_table *table,
                                    const struct netfw_flow_key *key)
{
    unsigned int bucket, slot;
    int result = -ENOENT;

    if (!table || !netfw_flow_is_transport(key))
        return -EINVAL;
    bucket = netfw_conn_bucket(key);
    spin_lock_bh(&table->lock);
    for (slot = 0; slot < NETFW_CONN_SLOTS; ++slot) {
        struct netfw_conn_entry *entry = &table->bucket[bucket][slot];

        if (!entry->used)
            continue;
        if (!netfw_flow_equal(&entry->key, key) &&
            !netfw_flow_reverse_equal(&entry->key, key))
            continue;
        memset(entry, 0, sizeof(*entry));
        --table->count;
        result = 0;
        break;
    }
    spin_unlock_bh(&table->lock);
    return result;
}

static inline void netfw_conn_clear(struct netfw_conn_table *table)
{
    if (!table)
        return;
    spin_lock_bh(&table->lock);
    memset(table->bucket, 0, sizeof(table->bucket));
    table->count = 0;
    spin_unlock_bh(&table->lock);
}

#endif /* NETFW_CONN_H */
