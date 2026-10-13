// SPDX-License-Identifier: GPL-2.0-only
// Creation-time identity only: no task registration, owner table, or TC program.
// The module-free producer is creator_lsm.bpf.c; both share creator_common.h.
//
// Attached to sbo_identity_socket, the typed tracepoint of the sbo_identity
// kernel module (kernel/sbo_identity). The module has already decided:
//   - the socket is a user inet socket (AF_INET/AF_INET6, !sk_kern_sock);
//   - its creator is NOT the process its cgroup is named after (those
//     sockets fire nothing: the socket cgroup, recorded by TC, identifies
//     the creator and userspace reads the rest from /proc - device probe
//     5453/5453 app_process sockets in their creator's own cgroup);
//   - the creator's executable (dev, ino, generation) and its full path,
//     resolved in the kernel at creation (d_path), so even a process that
//     exits before userspace looks keeps its path.
// This program records the snapshot TC copies (64 bytes, ABI unchanged:
// sing-ebpf native/tc.bpf.c) and stores each executable's path once, in
// `exe_paths`, keyed by a hash of (dev, ino, generation) that the snapshot
// carries in place of the inode (CREATOR_EXE_KEY).
#include "creator_common.h"

// Mirrors SBO_EVENT_* in kernel/sbo_identity/sbo_identity_trace.h.
#define SBO_EVENT_PATH (1U << 0)
#define SBO_EVENT_TOO_LONG (1U << 1)
#define SBO_EVENT_DELETED (1U << 2)
#define SBO_EVENT_KERNEL (1U << 4)

static __always_inline void remember_path(__u64 key, __u32 dev, __u32 generation, __u64 inode,
                                          const char *path, __u32 length, __u32 flags)
{
    if (bpf_map_lookup_elem(&exe_paths, &key))
        return;
    __u32 zero = 0;
    struct exe_path *value = bpf_map_lookup_elem(&exe_path_scratch, &zero);
    if (!value)
        return;
    value->dev = dev;
    value->generation = generation;
    value->inode = inode;
    value->length = length;
    value->flags = flags & SBO_EVENT_DELETED ? CREATOR_EXE_DELETED : 0;
    if (bpf_probe_read_kernel_str(value->path, sizeof(value->path), path) < 0)
        return;
    bpf_map_update_elem(&exe_paths, &key, value, BPF_NOEXIST);
}

SEC("tp_btf/sbo_identity_socket")
int BPF_PROG(capture_creator, struct sock *sk, dev_t dev, unsigned long ino, __u32 gen,
             const char *path, __u32 path_len, __u32 event)
{
    if (!sk || bpf_sk_storage_get(&socket_creators, sk, 0, 0))
        return 0;

    struct task_struct *task = bpf_get_current_task_btf();
    struct task_struct *leader = task ? task->group_leader : 0;
    struct socket_creator creator = {};
    if (!fill_creator(sk, leader ? leader->start_boottime : 0, &creator))
        return 0;
    if (event & SBO_EVENT_KERNEL) {
        creator.flags |= CREATOR_KERNEL;
    } else {
        struct mm_struct *mm = BPF_CORE_READ(task, mm);
        if (mm) // else a kernel thread
            record_process_name(BPF_CORE_READ(mm, arg_start), BPF_CORE_READ(mm, arg_end), &creator);
    }
    if (event & (SBO_EVENT_PATH | SBO_EVENT_TOO_LONG)) {
        __u64 key = exe_key(dev, gen, ino);
        creator.exe_inode = key;
        creator.flags |= CREATOR_EXE_KEY;
        if (event & SBO_EVENT_DELETED)
            creator.flags |= CREATOR_EXE_DELETED;
        if (event & SBO_EVENT_TOO_LONG)
            creator.flags |= CREATOR_PATH_TOO_LONG;
        else if (path_len > 0)
            remember_path(key, dev, gen, ino, path, path_len, event);
    }

    store_creator(sk, &creator);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
