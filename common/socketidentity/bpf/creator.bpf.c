// SPDX-License-Identifier: GPL-2.0-only
// Creation-time identity only: no task registration, owner table, or TC program.
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
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>
#include <bpf_tracing.h>

typedef __u32 dev_t;

// In 6.12 these fields sit inside an anonymous struct of mm_struct; CO-RE
// member matching descends into anonymous members.
struct mm_struct {
    unsigned long arg_start;
    unsigned long arg_end;
} __attribute__((preserve_access_index));

struct task_struct {
    struct task_struct *group_leader;
    __u64 start_boottime;
    struct mm_struct *mm;
} __attribute__((preserve_access_index));

struct sock;

struct socket_creator {
    __u64 cookie;
    __u64 start_time_ns;
    __u32 process_id;
    __u32 thread_id;
    __u32 user_id;
    __u32 flags;
    char comm[16];
    __u64 process_name_hash;
    __u64 exe_inode; // with CREATOR_EXE_KEY: the exe_paths key, not an inode
};

// Flag bits, mirrored by sing-ebpf (native/tc.bpf.c, bits 0-3) and
// identity.go (all). sing-ebpf only interprets CREATOR_VALID.
#define CREATOR_VALID (1U << 0)
#define CREATOR_NAME_VALID (1U << 1)
#define CREATOR_EXE_VALID (1U << 2)      // v2 producer only; never set here
#define CREATOR_NAME_TRUNCATED (1U << 3)
#define CREATOR_EXE_KEY (1U << 4)        // exe_inode is an exe_paths key
#define CREATOR_PATH_TOO_LONG (1U << 5)  // path >= 256 bytes, not stored
#define CREATOR_EXE_DELETED (1U << 6)    // executable was unlinked
#define CREATOR_KERNEL (1U << 7)         // creator had no mm (kernel thread)
#define CREATOR_NAME_LENGTH_SHIFT 8
#define ARGV_MAX 128
#define PATH_LEN 256 // PATH_MAX_LEN in kernel/sbo_identity/sbo_identity.c

// Mirrors SBO_EVENT_* in kernel/sbo_identity/sbo_identity_trace.h.
#define SBO_EVENT_PATH (1U << 0)
#define SBO_EVENT_TOO_LONG (1U << 1)
#define SBO_EVENT_DELETED (1U << 2)
#define SBO_EVENT_KERNEL (1U << 4)

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

// One entry per executable; identity.go PathValue mirrors it.
struct exe_path {
    __u32 dev;
    __u32 generation;
    __u64 inode;
    __u32 length;
    __u32 flags; // CREATOR_EXE_DELETED
    char path[PATH_LEN];
};

_Static_assert(sizeof(struct exe_path) == 280, "exe path size");

// LRU so a device running many distinct binaries cannot fill it; an evicted
// executable is stored again on its next socket, since every event carries
// the path. 1024 entries: an hour on the device saw 13 distinct executables
// among sockets that get a snapshot.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct exe_path);
} exe_paths SEC(".maps");

// Builds an exe_path (280 bytes) off the 512-byte stack, which also holds
// the snapshot and the 128-byte argv buffer.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct exe_path);
} exe_path_scratch SEC(".maps");

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
// cmdline with zero read failures.
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
}

// FNV-1a 64 over (dev, generation, inode) as 16 little-endian bytes; Go's
// socketidentity.ExeKey computes the same.
static __always_inline __u64 exe_key(__u32 dev, __u32 generation, __u64 inode)
{
    __u64 hash = 0xcbf29ce484222325ULL;
    __u64 words[2] = {(__u64)dev | ((__u64)generation << 32), inode};
    for (int w = 0; w < 2; w++) {
        for (int b = 0; b < 8; b++) {
            hash ^= (words[w] >> (8 * b)) & 0xff;
            hash *= 0x100000001b3ULL;
        }
    }
    return hash;
}

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

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct task_struct *task = bpf_get_current_task_btf();
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
    if (event & SBO_EVENT_KERNEL) {
        creator.flags |= CREATOR_KERNEL;
    } else {
        record_process_name(task, &creator);
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

    // The helper copies the complete initial value only when creating storage.
    // It never replaces an existing snapshot. No BPF_F_CLONE: an accepted child
    // inherits the listener's cgroup (cgroup_sk_clone) instead.
    bpf_sk_storage_get(&socket_creators, sk, &creator, BPF_SK_STORAGE_GET_F_CREATE);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
