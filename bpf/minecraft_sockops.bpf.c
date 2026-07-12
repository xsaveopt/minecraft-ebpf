#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "shared/maps.h"

#define AF_INET  2
#define AF_INET6 10

char LICENSE[] SEC("license") = "GPL";

volatile const __u16 target_port = 25565;

static __always_inline void open_count_inc(__be32 src) {
    __u64 zero = 0;
    bpf_map_update_elem(&tcp_open_count, &src, &zero, BPF_NOEXIST);
    __u64 *count = bpf_map_lookup_elem(&tcp_open_count, &src);
    if (count)
        __sync_fetch_and_add(count, 1);
}

static __always_inline void open_count_dec(__be32 src) {
    __u64 *count = bpf_map_lookup_elem(&tcp_open_count, &src);
    if (count && *count > 0) {
        __u64 old = __sync_fetch_and_sub(count, 1);
        if (old == 1) {
            bpf_map_delete_elem(&tcp_established, &src);
            bpf_map_delete_elem(&tcp_whitelist, &src);
        }
    }
}

SEC("sockops")
int minecraft_sockops(struct bpf_sock_ops *skops) {
    if (skops->local_port != target_port)
        return 1;
    if (skops->family != AF_INET && skops->family != AF_INET6)
        return 1;

    __be32 src = skops->remote_ip4;
    if (src == 0)
        return 1;

    if (skops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        __u64 now = bpf_ktime_get_boot_ns();
        bpf_map_update_elem(&tcp_established, &src, &now, BPF_ANY);
        stat_bump(STAT_TCP_ESTABLISHED_INSERTS);
        open_count_inc(src);
        bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
        return 1;
    }

    if (skops->op == BPF_SOCK_OPS_STATE_CB) {
        __u32 old_state = skops->args[0];
        __u32 new_state = skops->args[1];
        if (new_state == BPF_TCP_CLOSE &&
            (old_state == BPF_TCP_ESTABLISHED ||
             old_state == BPF_TCP_FIN_WAIT1 ||
             old_state == BPF_TCP_FIN_WAIT2 ||
             old_state == BPF_TCP_CLOSE_WAIT ||
             old_state == BPF_TCP_LAST_ACK ||
             old_state == BPF_TCP_TIME_WAIT ||
             old_state == BPF_TCP_CLOSING)) {
            open_count_dec(src);
        }
        return 1;
    }

    return 1;
}
