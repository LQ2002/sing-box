// SPDX-License-Identifier: GPL-2.0-only
// Feasibility probe for the socket creator v2 snapshot (ANDROID_ATTRIBUTION_PLAN.md,
// "Claude 目标设计"). It runs the exact reads the v2 producer would add, at the
// same hook, but reports every observation through a ring buffer instead of
// SK_STORAGE so userspace can compare each one against /proc. It never
// changes a socket, packet or forwarding decision.
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>
#include <bpf_tracing.h>

struct inode {
    unsigned long i_ino;
} __attribute__((preserve_access_index));

struct file {
    struct inode *f_inode;
} __attribute__((preserve_access_index));

// In 6.12 these sit inside an anonymous struct of mm_struct; CO-RE field
// matching descends into anonymous members, so the flat local view relocates.
struct mm_struct {
    unsigned long arg_start;
    unsigned long arg_end;
    struct file *exe_file;
} __attribute__((preserve_access_index));

struct task_struct {
    struct task_struct *group_leader;
    __u64 start_boottime;
    struct mm_struct *mm;
} __attribute__((preserve_access_index));

struct sock_common {
    __u16 skc_family;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
    __u8 sk_kern_sock : 1;
} __attribute__((preserve_access_index));

#define ARGV_MAX 128

enum event_flags {
    EV_MM = 1U << 0,
    EV_ARGV = 1U << 1,
    EV_EXE = 1U << 2,
};

struct event {
    __u64 cookie;
    __u64 start_time_ns;
    __u64 name_hash;
    __u64 exe_inode;
    __u64 arg_start;
    __u64 arg_end;
    __u64 cost_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 flags;
    __s32 argv_rc;
    __u16 family;
    __u16 reserved;
    char comm[16];
    char argv[ARGV_MAX];
};

_Static_assert(sizeof(struct event) == 224, "event layout shared with main.go");

enum stat_index {
    ST_READ_NS,
    ST_FNV_NS,
    ST_WORD_NS,
    ST_EXE_NS,
    ST_WORD_EQUAL_LEN,
    ST_EXE_DIRECT_NS,
    ST_CLOCK_NS,
    ST_CALLS,
    ST_FILTERED,
    ST_NO_MM,
    ST_ARGV_FAIL,
    ST_ARGV_EMPTY,
    ST_EXE_FAIL,
    ST_RING_FULL,
    ST_COST_NS,
    ST_COUNT,
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, ST_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump(__u32 index, __u64 amount)
{
    __u64 *value = bpf_map_lookup_elem(&stats, &index);
    if (value)
        *value += amount;
}

SEC("tp_btf/sbo_identity_socket_create")
int BPF_PROG(probe_argv, struct sock *sk)
{
    bump(ST_CALLS, 1);
    if (!sk || BPF_CORE_READ_BITFIELD_PROBED(sk, sk_kern_sock)) {
        bump(ST_FILTERED, 1);
        return 0;
    }
    __u16 family = sk->__sk_common.skc_family;
    if (family != 2 && family != 10) {
        bump(ST_FILTERED, 1);
        return 0;
    }

    // Timed section: exactly the work v2 adds to the producer.
    __u64 begin = bpf_ktime_get_ns();
    // u64 storage: 8-byte aligned for the word-hash variant below.
    __u64 words[ARGV_MAX / 8] = {};
    char *name = (char *)words;
    __u32 flags = 0;
    __s32 rc = 0;
    __u64 hash = 0, inode = 0, arg_start = 0, arg_end = 0;
    struct task_struct *task = bpf_get_current_task_btf();
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (mm) {
        flags |= EV_MM;
        arg_start = BPF_CORE_READ(mm, arg_start);
        arg_end = BPF_CORE_READ(mm, arg_end);
        rc = bpf_probe_read_user_str(name, ARGV_MAX, (const void *)arg_start);
        __u64 t_read = bpf_ktime_get_ns();
        bump(ST_READ_NS, t_read - begin);
        if (rc > 1) {
            // FNV-1a 64 over the bytes before the NUL.
            hash = 0xcbf29ce484222325ULL;
            for (int i = 0; i < ARGV_MAX; i++) {
                if (i >= rc - 1)
                    break;
                hash ^= (__u8)name[i];
                hash *= 0x100000001b3ULL;
            }
            __u64 t_fnv = bpf_ktime_get_ns();
            bump(ST_FNV_NS, t_fnv - t_read);
            // Candidate cheaper hash: one multiply per 8-byte word, the
            // bytes after the NUL masked off. Timed only, not reported.
            __u32 length = rc - 1;
            __u64 word_hash = 0xcbf29ce484222325ULL ^ length;
            for (int i = 0; i < ARGV_MAX / 8; i++) {
                if (i * 8 >= length)
                    break;
                __u64 word = words[i];
                __u32 remaining = length - i * 8;
                if (remaining < 8)
                    word &= (1ULL << (remaining * 8)) - 1;
                word_hash = (word_hash ^ word) * 0x100000001b3ULL;
                word_hash ^= word_hash >> 29;
            }
            __u64 t_word = bpf_ktime_get_ns();
            bump(ST_WORD_NS, t_word - t_fnv);
            if (word_hash != 0)
                bump(ST_WORD_EQUAL_LEN, length);
            flags |= EV_ARGV;
        }
        // Direct BTF pointer loads (PROBE_MEM) first, then the helper chain,
        // so the helper variant is the one that gets warm caches.
        __u64 t_direct = bpf_ktime_get_ns();
        struct mm_struct *direct_mm = task->mm; // BTF pointer from the trusted task
        struct file *exe_file = direct_mm ? direct_mm->exe_file : 0;
        __u64 direct_inode = 0;
        if (exe_file) {
            struct inode *exe_inode = exe_file->f_inode;
            if (exe_inode)
                direct_inode = exe_inode->i_ino;
        }
        __u64 t_exe = bpf_ktime_get_ns();
        bump(ST_EXE_DIRECT_NS, t_exe - t_direct);
        inode = BPF_CORE_READ(mm, exe_file, f_inode, i_ino);
        __u64 t_clock = bpf_ktime_get_ns();
        bump(ST_EXE_NS, t_clock - t_exe);
        if (direct_inode != inode)
            bump(ST_EXE_FAIL, 1000000);
        bump(ST_CLOCK_NS, bpf_ktime_get_ns() - t_clock);
        if (inode)
            flags |= EV_EXE;
    }
    __u64 cost = bpf_ktime_get_ns() - begin;

    if (!(flags & EV_MM))
        bump(ST_NO_MM, 1);
    else {
        if (rc < 0)
            bump(ST_ARGV_FAIL, 1);
        else if (rc <= 1)
            bump(ST_ARGV_EMPTY, 1);
        if (!(flags & EV_EXE))
            bump(ST_EXE_FAIL, 1);
    }
    bump(ST_COST_NS, cost);

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        bump(ST_RING_FULL, 1);
        return 0;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    event->cookie = bpf_get_socket_cookie(sk);
    event->start_time_ns = leader ? BPF_CORE_READ(leader, start_boottime) : 0;
    event->name_hash = hash;
    event->exe_inode = inode;
    event->arg_start = arg_start;
    event->arg_end = arg_end;
    event->cost_ns = cost;
    event->pid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->uid = (__u32)bpf_get_current_uid_gid();
    event->flags = flags;
    event->argv_rc = rc;
    event->family = family;
    event->reserved = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    __builtin_memcpy(event->argv, words, sizeof(words));
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
