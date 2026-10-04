// SPDX-License-Identifier: GPL-2.0-only
/* Experiment: snapshot in a preallocated HASH keyed by socket cookie instead
 * of sk_storage. Insert takes a preallocated element (no kmalloc, no memcg
 * charge). Deletion on socket free is not implemented here; sized so the
 * measurement never fills it. Same 64-byte value as consumer v2. */
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
typedef __u32 dev_t;
struct sock;
struct snapshot {
    __u64 cookie; __u32 pid, tid, uid, flags; __u64 ino; __u32 dev, gen, path_len, reserved;
    char comm[16];
};
volatile const __u32 mirror_events = 1;
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144);
    __type(key, __u64);
    __type(value, struct snapshot);
} by_cookie SEC(".maps");
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
    __u32 k = 0;
    __u64 *v = bpf_map_lookup_elem(&stats, &k);
    if (v)
        *v += 1;
    if (!sk)
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct snapshot st = {
        .cookie = bpf_get_socket_cookie(sk), .pid = pid_tgid >> 32, .tid = (__u32)pid_tgid,
        .uid = (__u32)bpf_get_current_uid_gid(), .flags = flags, .ino = ino, .dev = dev,
        .gen = gen, .path_len = path_len,
    };
    bpf_get_current_comm(st.comm, sizeof(st.comm));
    bpf_map_update_elem(&by_cookie, &st.cookie, &st, BPF_ANY);
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
