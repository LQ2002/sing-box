// SPDX-License-Identifier: GPL-2.0-only
// Creation-time identity only: no task registration, owner table, or TC program.
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>
#include <bpf_tracing.h>

struct task_struct {
    struct task_struct *group_leader;
    __u64 start_boottime;
} __attribute__((preserve_access_index));

struct sock_common {
    __u16 skc_family;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
    __u8 sk_kern_sock : 1;
} __attribute__((preserve_access_index));

struct socket_creator {
    __u64 cookie;
    __u64 start_time_ns;
    __u32 process_id;
    __u32 thread_id;
    __u32 user_id;
    __u32 flags;
    char comm[16];
};

_Static_assert(sizeof(struct socket_creator) == 48, "creator size");
_Static_assert(__builtin_offsetof(struct socket_creator, cookie) == 0, "cookie offset");
_Static_assert(__builtin_offsetof(struct socket_creator, start_time_ns) == 8, "birth offset");
_Static_assert(__builtin_offsetof(struct socket_creator, process_id) == 16, "pid offset");
_Static_assert(__builtin_offsetof(struct socket_creator, thread_id) == 20, "tid offset");
_Static_assert(__builtin_offsetof(struct socket_creator, user_id) == 24, "uid offset");
_Static_assert(__builtin_offsetof(struct socket_creator, flags) == 28, "flags offset");
_Static_assert(__builtin_offsetof(struct socket_creator, comm) == 32, "comm offset");

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct socket_creator);
} socket_creators SEC(".maps");

SEC("tp_btf/sbo_identity_socket_create")
int BPF_PROG(capture_creator, struct sock *sk)
{
    if (!sk || BPF_CORE_READ_BITFIELD_PROBED(sk, sk_kern_sock))
        return 0;
    __u16 family = sk->__sk_common.skc_family;
    if (family != 2 && family != 10)
        return 0;
    if (bpf_sk_storage_get(&socket_creators, sk, 0, 0))
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct socket_creator creator = {
        .cookie = bpf_get_socket_cookie(sk),
        .process_id = pid_tgid >> 32,
        .thread_id = (__u32)pid_tgid,
        .user_id = (__u32)bpf_get_current_uid_gid(),
    };
    struct task_struct *task = bpf_get_current_task_btf();
    struct task_struct *leader = task ? task->group_leader : 0;
    if (leader)
        creator.start_time_ns = leader->start_boottime;
    if (!creator.cookie || !creator.start_time_ns || !creator.process_id || !creator.thread_id)
        return 0;
    if (bpf_get_current_comm(creator.comm, sizeof(creator.comm)))
        return 0;
    creator.flags = 1;

    // The helper copies the complete initial value only when creating storage.
    // It never replaces an existing snapshot. No BPF_F_CLONE: accept is unknown.
    bpf_sk_storage_get(&socket_creators, sk, &creator, BPF_SK_STORAGE_GET_F_CREATE);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
