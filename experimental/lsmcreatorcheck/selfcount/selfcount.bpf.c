// SPDX-License-Identifier: GPL-2.0-only
// Read-only measurement for lsmcreatorcheck -selfcount: how many user inet
// sockets one process (sing-box, target_tgid) creates compared with the
// whole system, and every bpf(2) call it makes, per command, with the time
// spent in the kernel. Its self-bypass registration is one MAP_UPDATE_ELEM
// per outbound socket (sing-ebpf SelfBypass.RegisterSocket); assignment
// reads are MAP_LOOKUP_ELEM, and the UDP session cleanup
// (TCBackend.RemoveAssignmentIfMatch) is a lookup plus a MAP_DELETE_ELEM. Nothing
// here changes a socket or a decision; the LSM program always returns 0.
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_TYPE_MASK 0xf

volatile const __u32 target_tgid;

enum {
    C_ALL_INET,      // user inet sockets, every process
    C_SELF_INET,     // ... created by target_tgid
    C_SELF_TCP,
    C_SELF_UDP,
    C_SELF_OTHER,
    C_MAX,
};

#define CMD_MAX 40 // bpf commands 0..39 (enum bpf_cmd)

struct cmd_stat {
    __u64 calls;
    __u64 ns;
    __u64 fails;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, CMD_MAX);
    __type(key, __u32);
    __type(value, struct cmd_stat);
} cmds SEC(".maps");

struct call {
    __u64 start;
    __u64 cmd;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, C_MAX);
    __type(key, __u32);
    __type(value, __u64);
} counts SEC(".maps");

// sys_enter time and command per thread of target_tgid inside bpf(2).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct call);
} inflight SEC(".maps");

static __always_inline void add(__u32 index, __u64 value)
{
    __u64 *slot = bpf_map_lookup_elem(&counts, &index);
    if (slot)
        *slot += value;
}

struct socket;

SEC("lsm/socket_post_create")
int BPF_PROG(count_socket, struct socket *sock, int family, int type, int protocol, int kern)
{
    if (kern || (family != AF_INET && family != AF_INET6))
        return 0;
    add(C_ALL_INET, 1);
    if ((bpf_get_current_pid_tgid() >> 32) != target_tgid)
        return 0;
    add(C_SELF_INET, 1);
    switch (type & SOCK_TYPE_MASK) {
    case SOCK_STREAM:
        add(C_SELF_TCP, 1);
        break;
    case SOCK_DGRAM:
        add(C_SELF_UDP, 1);
        break;
    default:
        add(C_SELF_OTHER, 1);
    }
    return 0;
}

// include/trace/events/syscalls.h records, as in
// /sys/kernel/tracing/events/syscalls/sys_{enter,exit}_bpf/format.
struct sys_enter_args {
    __u64 common;
    __s32 nr;
    __s32 pad;
    __u64 args[6];
};

struct sys_exit_args {
    __u64 common;
    __s32 nr;
    __s32 pad;
    __s64 ret;
};

SEC("tracepoint/syscalls/sys_enter_bpf")
int enter_bpf(struct sys_enter_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if ((pid_tgid >> 32) != target_tgid || ctx->args[0] >= CMD_MAX)
        return 0;
    __u32 tid = (__u32)pid_tgid;
    struct call call = {.start = bpf_ktime_get_ns(), .cmd = ctx->args[0]};
    bpf_map_update_elem(&inflight, &tid, &call, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_bpf")
int exit_bpf(struct sys_exit_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if ((pid_tgid >> 32) != target_tgid)
        return 0;
    __u32 tid = (__u32)pid_tgid;
    struct call *call = bpf_map_lookup_elem(&inflight, &tid);
    if (!call)
        return 0;
    __u32 cmd = call->cmd;
    struct cmd_stat *stat = bpf_map_lookup_elem(&cmds, &cmd);
    if (stat) {
        stat->calls++;
        stat->ns += bpf_ktime_get_ns() - call->start;
        if (ctx->ret < 0)
            stat->fails++;
    }
    bpf_map_delete_elem(&inflight, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
