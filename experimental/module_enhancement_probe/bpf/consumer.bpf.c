// SPDX-License-Identifier: GPL-2.0-only
/* BPF Consumer Program for typed tracepoint sbo_enhancement_socket_identity.
 * Proves that BPF directly consumes (dev, ino, gen, path, path_len, flags)
 * from tracepoint arguments WITHOUT reading mm->exe_file pointer chain!
 */
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct identity_snapshot {
    __u64 cookie;
    __u64 dev;
    __u64 ino;
    __u32 gen;
    __u32 path_len;
    __u8 flags;
    char path[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 14); // 16 KB ringbuf
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64); // count of consumed events
} counter SEC(".maps");

SEC("raw_tracepoint/sbo_enhancement_socket_identity")
int BPF_PROG(on_socket_identity, void *sk, __u64 dev, unsigned long ino,
             __u32 gen, const char *path, __u32 path_len, __u8 flags)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&counter, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }

    struct identity_snapshot *snap = bpf_ringbuf_reserve(&events, sizeof(*snap), 0);
    if (!snap)
        return 0;

    snap->dev = dev;
    snap->ino = ino;
    snap->gen = gen;
    snap->path_len = path_len;
    snap->flags = flags;

    // Directly read path from tracepoint argument pointer without touching task->mm
    if (path && path_len > 0) {
        bpf_probe_read_kernel_str(snap->path, sizeof(snap->path), path);
    } else {
        snap->path[0] = '\0';
    }

    bpf_ringbuf_submit(snap, 0);
    return 0;
}
