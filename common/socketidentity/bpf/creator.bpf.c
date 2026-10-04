// SPDX-License-Identifier: GPL-2.0-only
// Creation-time identity only: no task registration, owner table, or TC program.
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

// In 6.12 these fields sit inside an anonymous struct of mm_struct; CO-RE
// member matching descends into anonymous members.
struct mm_struct {
    unsigned long arg_start;
    unsigned long arg_end;
    struct file *exe_file;
} __attribute__((preserve_access_index));

struct kernfs_node {
    const char *name;
} __attribute__((preserve_access_index));

struct cgroup {
    struct kernfs_node *kn;
} __attribute__((preserve_access_index));

struct css_set {
    struct cgroup *dfl_cgrp;
} __attribute__((preserve_access_index));

struct task_struct {
    struct task_struct *group_leader;
    __u64 start_boottime;
    struct mm_struct *mm;
    struct css_set *cgroups;
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
    __u64 process_name_hash;
    __u64 exe_inode;
};

// Flag bits, mirrored by sing-ebpf (native/tc.bpf.c) and identity.go.
#define CREATOR_VALID (1U << 0)
#define CREATOR_NAME_VALID (1U << 1)
#define CREATOR_EXE_VALID (1U << 2)
#define CREATOR_NAME_TRUNCATED (1U << 3)
#define CREATOR_NAME_LENGTH_SHIFT 8
#define ARGV_MAX 128

_Static_assert(sizeof(struct socket_creator) == 64, "creator size");
_Static_assert(__builtin_offsetof(struct socket_creator, cookie) == 0, "cookie offset");
_Static_assert(__builtin_offsetof(struct socket_creator, start_time_ns) == 8, "birth offset");
_Static_assert(__builtin_offsetof(struct socket_creator, process_id) == 16, "pid offset");
_Static_assert(__builtin_offsetof(struct socket_creator, thread_id) == 20, "tid offset");
_Static_assert(__builtin_offsetof(struct socket_creator, user_id) == 24, "uid offset");
_Static_assert(__builtin_offsetof(struct socket_creator, flags) == 28, "flags offset");
_Static_assert(__builtin_offsetof(struct socket_creator, comm) == 32, "comm offset");
_Static_assert(__builtin_offsetof(struct socket_creator, process_name_hash) == 48, "name hash offset");
_Static_assert(__builtin_offsetof(struct socket_creator, exe_inode) == 56, "exe inode offset");

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct socket_creator);
} socket_creators SEC(".maps");

// v2 creation-time facts, each behind its own flag so a failed read leaves
// only that fact unknown (the snapshot stays valid).
//
// argv[0] is the ActivityManager process record name: zygote's setArgv0 sets
// it before any app code can run (AndroidRuntime::setArgv0, called from
// Zygote.setAppProcessName). It is copied with strlcpy into zygote's original
// argv block, so a long name is cut to the block size minus one (99- and
// 78-byte blocks measured on the device). A string that fills the block or
// the read buffer is therefore marked NAME_TRUNCATED; the hashed byte count
// goes to bits 8-15 so userspace can hash the same prefix of manifest names.
// A native process with a single argument also fills its block; for it the
// flag is harmless because no manifest name is involved.
//
// Device probe (experimental/creator_v2_probe): 865/865 events matched /proc
// cmdline and /proc exe inode with zero read failures; this section costs
// about 2 us per inet socket, dominated by cache misses on the argv page and
// the mm/exe_file/inode chain, not by hashing.
static __always_inline void record_process_name(struct task_struct *task, struct socket_creator *creator)
{
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return; // kernel thread
    __u64 arg_start = BPF_CORE_READ(mm, arg_start);
    __u64 arg_end = BPF_CORE_READ(mm, arg_end);
    char name[ARGV_MAX] = {}; // variable-offset reads below need initialized stack
    long read = bpf_probe_read_user_str(name, sizeof(name), (const void *)arg_start);
    if (read > 1) {
        __u32 length = read - 1;
        __u64 hash = 0xcbf29ce484222325ULL; // FNV-1a 64
        for (int i = 0; i < ARGV_MAX; i++) {
            if (i >= length)
                break;
            hash ^= (__u8)name[i];
            hash *= 0x100000001b3ULL;
        }
        creator->process_name_hash = hash;
        creator->flags |= CREATOR_NAME_VALID | (length << CREATOR_NAME_LENGTH_SHIFT);
        if (read == ARGV_MAX || (arg_end > arg_start && (__u64)read >= arg_end - arg_start))
            creator->flags |= CREATOR_NAME_TRUNCATED;
    }
    __u64 inode = BPF_CORE_READ(mm, exe_file, f_inode, i_ino);
    if (inode) {
        creator->exe_inode = inode;
        creator->flags |= CREATOR_EXE_VALID;
    }
}

// Division of labour with the socket cgroup (ANDROID_ATTRIBUTION_PLAN.md,
// "cgroup 分工"): Android gives every process it starts - apps, system-UID
// apps, init services - its own cgroup v2 directory .../uid_<uid>/pid_<pid>,
// and the kernel stamps the creator's cgroup on the socket (cgroup_sk_alloc),
// which TC already records. When the creating process is the one its cgroup
// is named after, that cgroup identifies it exactly, so no snapshot is
// needed: userspace resolves the cgroup to the process and reads its name
// (argv[0]) and executable from /proc. Device probe: 5453/5453 app_process
// sockets were in their creator's own cgroup. Skipping saves the sk_storage
// allocation (~570 ns hot) and the argv/exe reads.
//
// Everything else still gets a snapshot: native children and app-zygote
// children inherit a parent's cgroup (pid_<parent>), and KernelSU/zygisk
// daemons, su shells and sing-box itself all live in the root cgroup.
#define CGROUP_NAME_MAX 24

static __always_inline int in_own_process_cgroup(struct task_struct *task, __u32 tgid)
{
    const char *name = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, name);
    char buf[CGROUP_NAME_MAX] = {};
    if (!name || bpf_probe_read_kernel_str(buf, sizeof(buf), name) < 6)
        return 0;
    if (buf[0] != 'p' || buf[1] != 'i' || buf[2] != 'd' || buf[3] != '_')
        return 0;
    __u64 value = 0;
    for (int i = 4; i < CGROUP_NAME_MAX; i++) {
        char c = buf[i];
        if (c == 0)
            return i > 4 && value == tgid;
        if (c < '0' || c > '9')
            return 0;
        value = value * 10 + (c - '0');
    }
    return 0;
}

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
    struct task_struct *task = bpf_get_current_task_btf();
    if (in_own_process_cgroup(task, pid_tgid >> 32))
        return 0;
    struct socket_creator creator = {
        .cookie = bpf_get_socket_cookie(sk),
        .process_id = pid_tgid >> 32,
        .thread_id = (__u32)pid_tgid,
        .user_id = (__u32)bpf_get_current_uid_gid(),
    };
    struct task_struct *leader = task ? task->group_leader : 0;
    if (leader)
        creator.start_time_ns = leader->start_boottime;
    if (!creator.cookie || !creator.start_time_ns || !creator.process_id || !creator.thread_id)
        return 0;
    if (bpf_get_current_comm(creator.comm, sizeof(creator.comm)))
        return 0;
    creator.flags = CREATOR_VALID;
    record_process_name(task, &creator);

    // The helper copies the complete initial value only when creating storage.
    // It never replaces an existing snapshot. No BPF_F_CLONE: accept is unknown.
    bpf_sk_storage_get(&socket_creators, sk, &creator, BPF_SK_STORAGE_GET_F_CREATE);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
