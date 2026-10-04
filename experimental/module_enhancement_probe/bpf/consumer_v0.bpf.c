// SPDX-License-Identifier: GPL-2.0-only
/* Control consumer: attached to the same tracepoint, only counts. Isolates
 * the cost of running a BPF program from the cost of creating sk_storage. */
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
typedef __u32 dev_t;
struct sock;
volatile const __u32 mirror_events = 1;
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");
SEC("tp_btf/sbo_enhancement_socket_identity")
int BPF_PROG(on_socket_identity, struct sock *sk, dev_t dev, unsigned long ino,
             __u32 gen, const char *path, __u32 path_len, __u8 flags)
{
    __u32 key = 0;
    __u64 *v = bpf_map_lookup_elem(&stats, &key);
    if (v)
        *v += 1;
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
