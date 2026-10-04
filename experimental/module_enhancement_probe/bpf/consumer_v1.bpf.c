// SPDX-License-Identifier: GPL-2.0-only
/* Consumer of the module's typed tracepoint sbo_enhancement_socket_identity.
 *
 * Writes the per-socket snapshot purely from the tracepoint arguments: no
 * mm->exe_file / f_inode / argv reads (compare common/socketidentity/bpf/
 * creator.bpf.c, which chases that chain itself). It also mirrors every
 * event into a ring buffer so the acceptance tool can check each one against
 * /proc, and counts duplicates (a second event for a socket that already
 * has a snapshot), which must stay zero.
 */
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>
#include <bpf_tracing.h>

typedef __u32 dev_t;
struct sock;

#define PATH_LEN 256 /* must equal PATH_MAX_LEN in the module */

struct snapshot {
    __u64 cookie;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 flags;
    __u64 dev;
    __u64 ino;
    __u32 gen;
    __u32 path_len;
    char comm[16];
    char path[PATH_LEN];
};

_Static_assert(sizeof(struct snapshot) == 320, "snapshot size");

/* BPF_F_CLONE (Stage 1): sk_clone_lock() copies the listener's snapshot
 * verbatim into each accepted child (net/core/bpf_sk_storage.c:140-148, a
 * GFP_ATOMIC allocation per child). The copy keeps the listener's cookie, so
 * a reader recognises an inherited snapshot by cookie != socket cookie.
 */
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_CLONE);
    __type(key, int);
    __type(value, struct snapshot);
} snapshots SEC(".maps");

/* Set to 0 by the loader for benchmarks: production consumers keep only the
 * snapshot, so the timed state must not pay for the ring-buffer copy. */
volatile const __u32 mirror_events = 1;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23);
} events SEC(".maps");

enum stat_index {
    ST_EVENTS,
    ST_DUPLICATE,      /* socket already had a snapshot: must stay 0 */
    ST_STORAGE_FAIL,
    ST_PATH_READ_FAIL,
    ST_RINGBUF_DROP,
    ST_COUNT,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, ST_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump(__u32 index)
{
    __u64 *value = bpf_map_lookup_elem(&stats, &index);
    if (value)
        *value += 1;
}

SEC("tp_btf/sbo_enhancement_socket_identity")
int BPF_PROG(on_socket_identity, struct sock *sk, dev_t dev, unsigned long ino,
             __u32 gen, const char *path, __u32 path_len, __u8 flags)
{
    bump(ST_EVENTS);
    if (!sk)
        return 0;
    struct snapshot *st = bpf_sk_storage_get(&snapshots, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (!st) {
        bump(ST_STORAGE_FAIL);
        return 0;
    }
    if (st->cookie) {
        bump(ST_DUPLICATE);
        return 0;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    st->pid = pid_tgid >> 32;
    st->tid = (__u32)pid_tgid;
    st->uid = (__u32)bpf_get_current_uid_gid();
    st->flags = flags;
    st->dev = dev;
    st->ino = ino;
    st->gen = gen;
    st->path_len = path_len;
    bpf_get_current_comm(st->comm, sizeof(st->comm));
    if (path_len > 0 && bpf_probe_read_kernel_str(st->path, sizeof(st->path), path) < 0)
        bump(ST_PATH_READ_FAIL);
    st->cookie = bpf_get_socket_cookie(sk); /* last: marks the snapshot complete */
    if (!mirror_events)
        return 0;

    struct snapshot *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        bump(ST_RINGBUF_DROP);
        return 0;
    }
    __builtin_memcpy(ev, st, sizeof(*ev));
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
