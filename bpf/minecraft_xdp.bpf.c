#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "shared/maps.h"

#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6

char LICENSE[] SEC("license") = "GPL";

volatile const __u16 target_port              = 25565;
volatile const __u64 whitelist_ttl_ns         = 600ULL * 1000000000ULL;
volatile const __u64 status_period_ns         = 1000000000ULL;
volatile const __u64 status_burst             = 20;
volatile const __u64 login_period_ns          = 3000000000ULL;
volatile const __u64 login_burst              = 8;
volatile const __u64 tcp_global_period_ns     = 0;
volatile const __u64 tcp_global_burst         = 0;
volatile const __u64 tcp_max_open_per_ip      = 0;
volatile const __u64 health_window_ns         = 10ULL * 1000000000ULL;
volatile const __u32 health_threshold         = 20;
volatile const __u64 health_blacklist_ns      = 300ULL * 1000000000ULL;
volatile const __u64 conn_pkt_period_ns       = 0;
volatile const __u64 conn_pkt_burst           = 0;
volatile const __u64 conn_byte_period_ns      = 0;
volatile const __u64 conn_byte_burst          = 0;
volatile const __u64 conn_new_period_ns       = 0;
volatile const __u64 conn_new_burst           = 0;

#define MC_HANDSHAKE_PACKET_ID 0x00
#define MC_NEXT_STATE_STATUS   1
#define MC_NEXT_STATE_LOGIN    2
#define MC_NEXT_STATE_TRANSFER 3
#define MC_LEGACY_PING_BYTE    0xFE
#define MC_ADDR_MAX            255
#define MC_HANDSHAKE_MAX_LEN   1024

enum hs_class { HS_NONE = 0, HS_STATUS = 1, HS_LOGIN = 2, HS_MALFORMED = 3 };

static __always_inline int load_byte(struct xdp_md *ctx, __u32 pkt_off, __u8 *out) {
    __u8 b[8];
    __builtin_memset(b, 0, sizeof(b));
    if (bpf_xdp_load_bytes(ctx, pkt_off, b, 1) < 0)
        return -1;
    *out = b[0];
    return 0;
}

static __always_inline int load_varint(struct xdp_md *ctx, __u32 pkt_off,
                                       __u32 avail, __u32 *out) {
    __u32 value = 0;
    #pragma unroll
    for (int i = 0; i < 5; i++) {
        if ((__u32)i >= avail)
            return 0;
        __u8 c;
        if (load_byte(ctx, pkt_off + (__u32)i, &c) < 0)
            return 0;
        value |= (__u32)(c & 0x7F) << (7 * i);
        if (!(c & 0x80)) {
            *out = value;
            return i + 1;
        }
    }
    return 0;
}

static __always_inline enum hs_class classify_handshake(struct xdp_md *ctx,
                                                        __u32 payload_off,
                                                        __u32 payload_len) {
    if (payload_len < 1)
        return HS_NONE;

    __u8 first;
    if (load_byte(ctx, payload_off, &first) < 0)
        return HS_NONE;
    if (first == MC_LEGACY_PING_BYTE)
        return HS_STATUS;

    __u32 off = 0;
    __u32 pkt_len;
    int k = load_varint(ctx, payload_off + off, payload_len - off, &pkt_len);
    if (k == 0)
        return HS_NONE;
    if (pkt_len < 3 || pkt_len > MC_HANDSHAKE_MAX_LEN)
        return HS_NONE;
    off += (__u32)k;

    if (off >= payload_len)
        return HS_NONE;
    __u8 id;
    if (load_byte(ctx, payload_off + off, &id) < 0)
        return HS_NONE;
    if (id != MC_HANDSHAKE_PACKET_ID)
        return HS_NONE;
    off += 1;

    if (off >= payload_len)
        return HS_NONE;
    __u32 proto_ver;
    k = load_varint(ctx, payload_off + off, payload_len - off, &proto_ver);
    if (k == 0)
        return HS_NONE;
    off += (__u32)k;

    if (off >= payload_len)
        return HS_NONE;
    __u32 addr_len;
    k = load_varint(ctx, payload_off + off, payload_len - off, &addr_len);
    if (k == 0)
        return HS_NONE;
    if (addr_len > MC_ADDR_MAX)
        return HS_MALFORMED;
    off += (__u32)k;

    __u32 ns_off = off + addr_len + 2;
    if (ns_off >= payload_len)
        return HS_NONE;
    __u32 next_state;
    k = load_varint(ctx, payload_off + ns_off, payload_len - ns_off, &next_state);
    if (k == 0)
        return HS_NONE;
    if (next_state == MC_NEXT_STATE_STATUS)
        return HS_STATUS;
    if (next_state == MC_NEXT_STATE_LOGIN || next_state == MC_NEXT_STATE_TRANSFER)
        return HS_LOGIN;
    return HS_MALFORMED;
}

static __always_inline bool health_is_blacklisted(__be32 src_ip) {
    struct ip_health *h = bpf_map_lookup_elem(&health, &src_ip);
    if (!h)
        return false;
    __u64 now = bpf_ktime_get_boot_ns();
    return h->blacklist_until_ns > now;
}

static __always_inline void record_drop(__be32 src_ip, __u32 reason_idx) {
    if (reason_idx >= NUM_DROP_REASONS)
        return;
    __u64 now = bpf_ktime_get_boot_ns();
    struct ip_drop_history *h = bpf_map_lookup_elem(&ip_drop_history, &src_ip);
    if (!h) {
        struct ip_drop_history init = {0};
        init.first_drop_ns = now;
        init.last_drop_ns  = now;
        init.counts[reason_idx] = 1;
        bpf_map_update_elem(&ip_drop_history, &src_ip, &init, BPF_ANY);
        return;
    }
    h->last_drop_ns = now;
    __sync_fetch_and_add(&h->counts[reason_idx], 1);
}

static __always_inline void health_record_anomaly(__be32 src_ip) {
    __u64 now = bpf_ktime_get_boot_ns();
    struct ip_health *h = bpf_map_lookup_elem(&health, &src_ip);
    if (!h) {
        struct ip_health init = {
            .anomalies          = 1,
            .window_start_ns    = now,
            .blacklist_until_ns = 0,
        };
        bpf_map_update_elem(&health, &src_ip, &init, BPF_ANY);
        return;
    }
    if (now - h->window_start_ns > health_window_ns) {
        h->anomalies       = 0;
        h->window_start_ns = now;
    }
    h->anomalies++;
    if (h->anomalies >= health_threshold) {
        h->blacklist_until_ns = now + health_blacklist_ns;
    }
}

static __always_inline bool tcp_global_ratelimit_take(void) {
    if (tcp_global_burst == 0 || tcp_global_period_ns == 0)
        return true;
    __u32 zero = 0;
    struct ratelimit *b = bpf_map_lookup_elem(&tcp_global_ratelimit, &zero);
    if (!b)
        return true;

    __u64 now     = bpf_ktime_get_boot_ns();
    __u64 elapsed = now - b->last_refill_ns;
    __u64 refill  = elapsed / tcp_global_period_ns;
    __u64 t       = b->tokens + refill;
    if (t > tcp_global_burst)
        t = tcp_global_burst;
    if (t == 0)
        return false;

    b->tokens          = t - 1;
    b->last_refill_ns += refill * tcp_global_period_ns;
    return true;
}

static __always_inline bool ratelimit_take(void *map, __be32 src_ip,
                                           __u64 refill_period_ns, __u64 burst) {
    struct ratelimit *b = bpf_map_lookup_elem(map, &src_ip);
    __u64 now = bpf_ktime_get_boot_ns();

    if (!b) {
        struct ratelimit init = {
            .tokens         = burst > 0 ? burst - 1 : 0,
            .last_refill_ns = now,
        };
        bpf_map_update_elem(map, &src_ip, &init, BPF_ANY);
        return true;
    }

    __u64 elapsed = now - b->last_refill_ns;
    __u64 refill  = refill_period_ns > 0 ? elapsed / refill_period_ns : 0;
    __u64 t       = b->tokens + refill;
    if (t > burst)
        t = burst;
    if (t == 0)
        return false;

    b->tokens          = t - 1;
    b->last_refill_ns += refill * refill_period_ns;
    return true;
}

static __always_inline bool tcp_flags_bogus(struct tcphdr *tcp) {
    if (!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst && !tcp->psh && !tcp->urg)
        return true;
    if (tcp->syn && tcp->fin)
        return true;
    if (tcp->syn && tcp->rst)
        return true;
    if (tcp->fin && tcp->rst)
        return true;
    if (tcp->fin && tcp->psh && tcp->urg && !tcp->ack)
        return true;
    return false;
}

static __always_inline bool conn_ratelimit_take(__be32 src_ip, __u32 pkt_bytes) {
    bool pkt_on  = conn_pkt_period_ns  > 0 && conn_pkt_burst  > 0;
    bool byte_on = conn_byte_period_ns > 0 && conn_byte_burst > 0;
    if (!pkt_on && !byte_on)
        return true;

    __u64 now = bpf_ktime_get_boot_ns();
    struct conn_limit *b = bpf_map_lookup_elem(&conn_ratelimit, &src_ip);
    if (!b) {
        struct conn_limit init = {
            .pkt_tokens   = conn_pkt_burst > 0 ? conn_pkt_burst - 1 : 0,
            .pkt_last_ns  = now,
            .byte_tokens  = conn_byte_burst,
            .byte_last_ns = now,
        };
        if (byte_on)
            init.byte_tokens = conn_byte_burst > pkt_bytes ? conn_byte_burst - pkt_bytes : 0;
        bpf_map_update_elem(&conn_ratelimit, &src_ip, &init, BPF_ANY);
        return true;
    }

    if (pkt_on) {
        __u64 elapsed = now - b->pkt_last_ns;
        __u64 refill  = elapsed / conn_pkt_period_ns;
        __u64 t       = b->pkt_tokens + refill;
        if (t > conn_pkt_burst)
            t = conn_pkt_burst;
        if (t == 0)
            return false;
        b->pkt_tokens    = t - 1;
        b->pkt_last_ns  += refill * conn_pkt_period_ns;
    }
    if (byte_on) {
        __u64 elapsed = now - b->byte_last_ns;
        __u64 refill  = elapsed / conn_byte_period_ns;
        __u64 t       = b->byte_tokens + refill;
        if (t > conn_byte_burst)
            t = conn_byte_burst;
        if (t < pkt_bytes)
            return false;
        b->byte_tokens   = t - pkt_bytes;
        b->byte_last_ns += refill * conn_byte_period_ns;
    }
    return true;
}

SEC("xdp")
int minecraft_xdp(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip))
        return XDP_PASS;
    void *l4 = (void *)ip + ihl;
    if (l4 > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    __be16 port_be = bpf_htons(target_port);
    __be32 src     = ip->saddr;

    struct tcphdr *tcp = l4;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    if (tcp->dest != port_be)
        return XDP_PASS;

    if (tcp_flags_bogus(tcp)) {
        record_drop(src, DROP_REASON_TCP_BAD_FLAGS);
        stat_bump(STAT_DROP_TCP_BAD_FLAGS);
        return XDP_DROP;
    }

    __u32 ip_tot = bpf_ntohs(ip->tot_len);

    __u64 *wl = bpf_map_lookup_elem(&tcp_whitelist, &src);
    if (wl) {
        __u64 now = bpf_ktime_get_boot_ns();
        if (whitelist_ttl_ns > 0 && now - *wl > whitelist_ttl_ns) {
            bpf_map_delete_elem(&tcp_whitelist, &src);
        } else {
            if (!conn_ratelimit_take(src, ip_tot)) {
                health_record_anomaly(src);
                if (health_is_blacklisted(src))
                    bpf_map_delete_elem(&tcp_whitelist, &src);
                record_drop(src, DROP_REASON_CONN_RATELIMIT);
                stat_bump(STAT_DROP_CONN_RATELIMIT);
                return XDP_DROP;
            }
            if (tcp->syn && tcp_max_open_per_ip > 0) {
                __u64 *open = bpf_map_lookup_elem(&tcp_open_count, &src);
                if (open && *open >= tcp_max_open_per_ip) {
                    record_drop(src, DROP_REASON_TCP_TOO_MANY_OPEN);
                    stat_bump(STAT_DROP_TCP_TOO_MANY_OPEN);
                    return XDP_DROP;
                }
            }
            *wl = now;
            stat_bump(STAT_PASS_TCP);
            return XDP_PASS;
        }
    }

    if (!tcp->syn) {
        if (!bpf_map_lookup_elem(&tcp_syn_seen, &src) &&
            !bpf_map_lookup_elem(&tcp_established, &src)) {
            record_drop(src, DROP_REASON_TCP_NO_SYN);
            stat_bump(STAT_DROP_TCP_NO_SYN);
            return XDP_DROP;
        }
    } else {
        if (tcp_max_open_per_ip > 0) {
            __u64 *open = bpf_map_lookup_elem(&tcp_open_count, &src);
            if (open && *open >= tcp_max_open_per_ip) {
                record_drop(src, DROP_REASON_TCP_TOO_MANY_OPEN);
                stat_bump(STAT_DROP_TCP_TOO_MANY_OPEN);
                return XDP_DROP;
            }
        }
        if (conn_new_period_ns > 0 && conn_new_burst > 0) {
            if (!ratelimit_take(&syn_ratelimit, src, conn_new_period_ns, conn_new_burst)) {
                record_drop(src, DROP_REASON_TCP_CONN_RATE);
                stat_bump(STAT_DROP_TCP_CONN_RATE);
                return XDP_DROP;
            }
        }
        if (!tcp_global_ratelimit_take()) {
            record_drop(src, DROP_REASON_TCP_GLOBAL_RATELIMIT);
            stat_bump(STAT_DROP_TCP_GLOBAL_RATELIMIT);
            return XDP_DROP;
        }
        __u64 now = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&tcp_syn_seen, &src, &now, BPF_ANY);
    }

    __u32 tcp_hlen = tcp->doff * 4;
    if (tcp_hlen < sizeof(*tcp))
        return XDP_PASS;
    void *payload = (void *)tcp + tcp_hlen;
    if (payload > data_end)
        return XDP_PASS;

    stat_bump(STAT_PASS_TCP);

    __u32 hdrs = ihl + tcp_hlen;
    if (ip_tot <= hdrs)
        return XDP_PASS;
    __u32 payload_off = 14 + hdrs;
    __u32 payload_len = ip_tot - hdrs;
    enum hs_class hs = classify_handshake(ctx, payload_off, payload_len);

    if (hs == HS_NONE) {
        if (bpf_map_lookup_elem(&tcp_established, &src)) {
            if (!conn_ratelimit_take(src, ip_tot)) {
                health_record_anomaly(src);
                record_drop(src, DROP_REASON_CONN_RATELIMIT);
                stat_bump(STAT_DROP_CONN_RATELIMIT);
                return XDP_DROP;
            }
        }
        return XDP_PASS;
    }

    if (hs == HS_MALFORMED) {
        health_record_anomaly(src);
        record_drop(src, DROP_REASON_MALFORMED_HANDSHAKE);
        stat_bump(STAT_DROP_MALFORMED_HANDSHAKE);
        return XDP_DROP;
    }

    if (health_is_blacklisted(src)) {
        record_drop(src, DROP_REASON_UNHEALTHY);
        stat_bump(STAT_DROP_TCP_UNHEALTHY);
        return XDP_DROP;
    }

    if (hs == HS_STATUS) {
        stat_bump(STAT_TCP_HANDSHAKE_STATUS_SEEN);
        if (!ratelimit_take(&status_ratelimit, src, status_period_ns, status_burst)) {
            record_drop(src, DROP_REASON_STATUS_RATELIMIT);
            stat_bump(STAT_DROP_STATUS_RATELIMIT);
            return XDP_DROP;
        }
        return XDP_PASS;
    }

    stat_bump(STAT_TCP_HANDSHAKE_LOGIN_SEEN);
    if (!ratelimit_take(&login_ratelimit, src, login_period_ns, login_burst)) {
        record_drop(src, DROP_REASON_LOGIN_RATELIMIT);
        stat_bump(STAT_DROP_LOGIN_RATELIMIT);
        return XDP_DROP;
    }

    __u64 *est = bpf_map_lookup_elem(&tcp_established, &src);
    if (est) {
        __u64 now = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&tcp_whitelist, &src, &now, BPF_ANY);
        stat_bump(STAT_TCP_L7_PROMOTED);
    } else {
        stat_bump(STAT_TCP_L7_MATCH_NO_EST);
    }
    return XDP_PASS;
}
