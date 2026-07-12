#ifndef __MINECRAFT_MAPS_H__
#define __MINECRAFT_MAPS_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "stats.h"

struct ratelimit {
    __u64 tokens;
    __u64 last_refill_ns;
};

struct ip_health {
    __u32 anomalies;
    __u64 window_start_ns;
    __u64 blacklist_until_ns;
};

struct conn_limit {
    __u64 pkt_tokens;
    __u64 pkt_last_ns;
    __u64 byte_tokens;
    __u64 byte_last_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, __u64);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_established SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, __u64);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_syn_seen SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, __u64);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, struct ratelimit);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} status_ratelimit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, struct ratelimit);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} login_ratelimit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct ratelimit);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_global_ratelimit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, __u64);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_open_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, struct conn_limit);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} conn_ratelimit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, struct ratelimit);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} syn_ratelimit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, struct ip_health);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} health SEC(".maps");

#define NUM_DROP_REASONS 10

enum drop_reason_idx {
    DROP_REASON_TCP_NO_SYN              = 0,
    DROP_REASON_TCP_TOO_MANY_OPEN       = 1,
    DROP_REASON_TCP_GLOBAL_RATELIMIT    = 2,
    DROP_REASON_STATUS_RATELIMIT        = 3,
    DROP_REASON_LOGIN_RATELIMIT         = 4,
    DROP_REASON_MALFORMED_HANDSHAKE     = 5,
    DROP_REASON_UNHEALTHY               = 6,
    DROP_REASON_TCP_BAD_FLAGS           = 7,
    DROP_REASON_CONN_RATELIMIT          = 8,
    DROP_REASON_TCP_CONN_RATE           = 9,
};

struct ip_drop_history {
    __u64 first_drop_ns;
    __u64 last_drop_ns;
    __u64 counts[NUM_DROP_REASONS];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, struct ip_drop_history);
    __uint(max_entries, 100000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_drop_history SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STAT_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stats SEC(".maps");

static __always_inline void stat_bump(__u32 slot) {
    __u64 *c = bpf_map_lookup_elem(&stats, &slot);
    if (c)
        (*c)++;
}

#endif
