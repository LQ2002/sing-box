// SPDX-License-Identifier: GPL-2.0-only
// Module-free socket creator producer: BPF LSM socket_post_create.
//
// Does in BPF what the sbo_identity kernel module (kernel/sbo_identity)
// does before it fires its tracepoint for creator.bpf.c, and writes the same
// snapshot and exe_paths entries (creator_common.h). Needs a kernel that runs
// BPF trampolines (fentry/LSM) and has "bpf" in its LSM list; the stock
// Android 16 6.12 GKI on the test phone has neither FUNCTION_TRACER nor
// DYNAMIC_FTRACE_WITH_DIRECT_CALLS, so there the attach fails and the
// collector falls back to the module. On the user's rebuilt kernel
// (experimental/ftrace_attach_probe, 2026-10-12) lsm/socket_post_create
// fired 200/200 and bpf_path_d_path returned /proc/self/exe.
//
// Hook placement: __sock_create calls security_socket_post_create
// (net/socket.c:1597) after pf->create, and the module's
// android_vh_sock_create five lines later (:1602) when it returned 0. "bpf"
// is the last LSM, so an earlier LSM's refusal skips this program, and a
// socket whose creation fails afterwards is released with its storage.
// Same task, same socket, same moment as the module.
//
// Per socket, in the module's order (sbo_identity.c on_socket_create):
//  1. Only user inet sockets: kern == 0 (the value sk_kern_sock is set
//     from) and AF_INET/AF_INET6.
//  2. Kernel thread (no mm or PF_KTHREAD): snapshot flagged CREATOR_KERNEL.
//  3. Own-cgroup gate: the creator's cgroup v2 directory is named
//     pid_<its tgid> -> nothing is stored; the socket cgroup recorded by TC
//     identifies the creator (76-84% of inet sockets on the device).
//  4. Executable key (dev, ino, generation) read without a reference, then
//     mm->exe_file re-read: it must still be the same file. This program is
//     not sleepable, so it runs inside rcu_read_lock (the trampoline's
//     __bpf_prog_enter); struct file is SLAB_TYPESAFE_BY_RCU and inodes are
//     RCU-freed, as the module's comment explains. Reads use
//     bpf_probe_read_kernel (BPF_CORE_READ), which cannot fault.
//  5. Path cache: exe_paths itself (LRU, pinned, shared by every CPU) - a
//     key already stored needs no d_path. The module kept 4 per-CPU slots.
//  6. Miss: bpf_get_task_exe_file takes a real reference (get_task_exe_file),
//     bpf_path_d_path resolves it, bpf_put_file drops it - the module's
//     get_file_rcu/d_path/fput. These kfuncs are not KF_SLEEPABLE
//     (fs/bpf_fs_kfuncs.c:158-160), so a plain lsm/ program may call them.
//     -ENAMETOOLONG gives CREATOR_PATH_TOO_LONG (not cached: unlike the
//     module, the next socket of that binary resolves it again; one such
//     binary was seen in an hour). " (deleted)" is stripped and flagged.
#include "creator_common.h"

#define AF_INET 2
#define AF_INET6 10
#define PF_KTHREAD 0x00200000 // include/linux/sched.h
#define ENAMETOOLONG 36

struct super_block {
    dev_t s_dev;
} __attribute__((preserve_access_index));

struct inode {
    unsigned long i_ino;
    __u32 i_generation;
    struct super_block *i_sb;
} __attribute__((preserve_access_index));

struct path {
    void *mnt;
} __attribute__((preserve_access_index));

struct file {
    struct path f_path;
    struct inode *f_inode;
} __attribute__((preserve_access_index));

// The task/mm members creator_common.h does not declare. CO-RE merges both
// declarations by name: each access is relocated on its own.
struct mm_struct___exe {
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

struct task_struct___lsm {
    unsigned int flags;
    struct mm_struct *mm;
    struct css_set *cgroups;
} __attribute__((preserve_access_index));

struct socket {
    struct sock *sk;
} __attribute__((preserve_access_index));

extern struct file *bpf_get_task_exe_file(struct task_struct *task) __ksym;
extern void bpf_put_file(struct file *file) __ksym;
extern int bpf_path_d_path(struct path *path, char *buf, __u64 buf__sz) __ksym;

// Is the current task the process its cgroup v2 directory is named after?
// Same test as sbo_identity.c in_own_process_cgroup: "pid_" then decimal
// digits equal to the TGID, ending within 16 bytes. Android names every
// process it starts this way (.../uid_<uid>/pid_<pid>) and does not rename
// cgroup directories.
static __always_inline int in_own_process_cgroup(struct task_struct___lsm *task, __u32 tgid)
{
    const char *name = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, name);
    char buf[16] = {};
    if (!name || bpf_probe_read_kernel_str(buf, sizeof(buf), name) < 6)
        return 0;
    if (buf[0] != 'p' || buf[1] != 'i' || buf[2] != 'd' || buf[3] != '_')
        return 0;
    __u32 value = 0;
    for (int i = 4; i < 16; i++) {
        char c = buf[i];
        if (c == '\0')
            return i > 4 && value == tgid;
        if (c < '0' || c > '9')
            return 0;
        value = value * 10 + (c - '0');
    }
    return 0;
}

static const char deleted_suffix[] = " (deleted)";
#define DELETED_SUFFIX_LEN 10

// Resolves the executable under a real reference and stores its path.
// Returns the CREATOR_* bits for the snapshot (0 when nothing is known) and
// sets *key.
static __always_inline __u32 resolve_slow(struct task_struct *task, __u64 *key)
{
    __u32 zero = 0;
    struct exe_path *value = bpf_map_lookup_elem(&exe_path_scratch, &zero);
    if (!value)
        return 0;
    struct file *exe = bpf_get_task_exe_file(task);
    if (!exe)
        return 0;
    __u32 dev = BPF_CORE_READ(exe, f_inode, i_sb, s_dev);
    __u64 inode = BPF_CORE_READ(exe, f_inode, i_ino);
    __u32 generation = BPF_CORE_READ(exe, f_inode, i_generation);
    int length = bpf_path_d_path(&exe->f_path, value->path, sizeof(value->path));
    bpf_put_file(exe);

    *key = exe_key(dev, generation, inode);
    if (length == -ENAMETOOLONG)
        return CREATOR_EXE_KEY | CREATOR_PATH_TOO_LONG;
    if (length <= 1 || length > PATH_LEN)
        return 0; // a transient failure: no key, like the module's ERROR event

    __u32 flags = CREATOR_EXE_KEY;
    __u32 n = length - 1; // without the NUL; 1..255
    if (n >= DELETED_SUFFIX_LEN && n < PATH_LEN) {
        int match = 1;
        for (int i = 0; i < DELETED_SUFFIX_LEN; i++) {
            if (value->path[n - DELETED_SUFFIX_LEN + i] != deleted_suffix[i]) {
                match = 0;
                break;
            }
        }
        if (match) {
            n -= DELETED_SUFFIX_LEN;
            value->path[n & (PATH_LEN - 1)] = '\0';
            flags |= CREATOR_EXE_DELETED;
        }
    }
    value->dev = dev;
    value->generation = generation;
    value->inode = inode;
    value->length = n;
    value->flags = flags & CREATOR_EXE_DELETED;
    bpf_map_update_elem(&exe_paths, key, value, BPF_NOEXIST);
    return flags;
}

// The executable's key, from the path map when it is already there.
static __always_inline __u32 record_executable(struct task_struct *task, __u64 *key)
{
    struct mm_struct___exe *mm = (void *)BPF_CORE_READ(task, mm);
    struct file *exe = BPF_CORE_READ(mm, exe_file);
    struct inode *inode = exe ? BPF_CORE_READ(exe, f_inode) : 0;
    if (inode) {
        __u32 dev = BPF_CORE_READ(inode, i_sb, s_dev);
        __u64 ino = BPF_CORE_READ(inode, i_ino);
        __u32 generation = BPF_CORE_READ(inode, i_generation);
        // Only a key whose file is still the mm's executable may hit.
        if (BPF_CORE_READ(mm, exe_file) == exe) {
            *key = exe_key(dev, generation, ino);
            struct exe_path *stored = bpf_map_lookup_elem(&exe_paths, key);
            if (stored)
                return CREATOR_EXE_KEY | (stored->flags & CREATOR_EXE_DELETED);
        }
    }
    return resolve_slow(task, key);
}

SEC("lsm/socket_post_create")
int BPF_PROG(capture_creator, struct socket *sock, int family, int type, int protocol, int kern)
{
    if (kern || (family != AF_INET && family != AF_INET6))
        return 0;
    struct sock *sk = sock->sk;
    if (!sk)
        return 0;

    struct task_struct *task = bpf_get_current_task_btf();
    struct task_struct___lsm *t = (void *)task;
    int kernel = !BPF_CORE_READ(t, mm) || (BPF_CORE_READ(t, flags) & PF_KTHREAD);
    if (!kernel && in_own_process_cgroup(t, bpf_get_current_pid_tgid() >> 32))
        return 0;

    struct socket_creator creator = {};
    if (!fill_creator(sk, task, &creator))
        return 0;
    if (kernel) {
        creator.flags |= CREATOR_KERNEL;
    } else {
        record_process_name(task, &creator);
        __u64 key = 0;
        __u32 flags = record_executable(task, &key);
        if (flags) {
            creator.exe_inode = key;
            creator.flags |= flags;
        }
    }
    store_creator(sk, &creator);
    return 0; // never refuses a socket
}

char LICENSE[] SEC("license") = "GPL";
