// SPDX-License-Identifier: GPL-2.0-only
/* sbo_identity: socket creator identity for the sing-box eBPF inbound.
 *
 * android_vh_sock_create (end of __sock_create, net/socket.c:1602) runs in
 * the creating task. For each user inet socket this module either does
 * nothing - the creator is the process its cgroup is named after, which the
 * socket's cgroup (recorded by TC) already identifies - or fires the typed
 * tracepoint sbo_identity_socket with the creator's executable, which the
 * BPF producer (common/socketidentity/bpf/creator.bpf.c) turns into the
 * per-socket snapshot. Design, measurements and review history:
 * ANDROID_ATTRIBUTION_PLAN.md ("增强模块"), experimental/module_enhancement_probe.
 *
 * Per socket, in order of cost:
 *  1. Only user inet sockets (AF_INET/AF_INET6, !sk_kern_sock). Android
 *     creates 2.6-3.3 times as many non-inet sockets (measured over an hour);
 *     they return before anything else.
 *  2. Own-cgroup gate: Android gives every process it starts (apps,
 *     system-UID apps, init services) its own cgroup v2 directory
 *     .../uid_<uid>/pid_<pid>, and the kernel stamps the creator's cgroup on
 *     the socket. If the creator's cgroup is named pid_<its tgid>, the cgroup
 *     identifies it exactly and nothing is emitted: no BPF runs, no snapshot
 *     is allocated (~570 ns saved, measured in-kernel). Native children and
 *     app-zygote children sit in a parent's cgroup; sing-box, KernelSU and
 *     zygisk daemons and su shells sit in the root cgroup; those continue.
 *  3. Executable key (dev, ino, generation) read under rcu_read_lock without
 *     a reference. struct file is SLAB_TYPESAFE_BY_RCU (fs/file_table.c:529)
 *     and zeroed on reuse (kmem_cache_zalloc, :209/:243), so f_inode can be
 *     the old inode, NULL or a new one; inodes are RCU-freed (fs/inode.c:324).
 *     Hence: NULL-check f_inode, then re-check mm->exe_file still points to
 *     the same file. Only a validated key may hit the cache. /data is f2fs,
 *     which reuses inode numbers and randomises i_generation on new inodes
 *     (fs/f2fs/namei.c:253), so the generation is part of the key.
 *  4. Per-CPU path cache, touched only between get_cpu_ptr()/put_cpu_ptr();
 *     a hit fires the tracepoint straight from the slot (99.3% hit rate over
 *     an hour on the device).
 *  5. Miss: rcu_read_lock(); get_file_rcu(); rcu_read_unlock() - the
 *     sequence of get_mm_exe_file() (kernel/fork.c:1499-1506), which is not
 *     exported - then d_path() into 256 bytes and fput(). d_path never
 *     truncates: -ENAMETOOLONG (fs/d_path.c:23) is reported as TOO_LONG and
 *     cached. An unlinked executable gets " (deleted)" appended
 *     (fs/d_path.c:287); it is stripped and reported as DELETED.
 *
 * The module never includes socket or cgroup headers: those types differ
 * between our source tree and the shipped kernel (gen_layout.py), so their
 * few fields are read at offsets generated from the device BTF, and
 * verify_btf.py checks every struct the module does dereference through
 * headers against the device layout.
 *
 * capture_all (0600, default off) gates everything, like
 * sbo_identity_bridge's parameter of the same name; the collector requires it
 * to be set and never changes it. Clearing it waits for running callbacks.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kstrtox.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/clock.h>
#include <linux/dcache.h>
#include <linux/percpu.h>
#include <linux/math64.h>
#include <linux/tracepoint.h>
#include <linux/socket.h>

#include "sbo_layout.h"

struct sock;
struct sockaddr;
struct sk_buff;
#include <trace/hooks/net.h>

#if !IS_ENABLED(CONFIG_ANDROID_VENDOR_HOOKS) || !IS_ENABLED(CONFIG_BPF_EVENTS) || \
	!IS_ENABLED(CONFIG_DEBUG_INFO_BTF_MODULES)
#error "sbo_identity requires vendor hooks, BPF events and module BTF"
#endif

#define CREATE_TRACE_POINTS
#include "sbo_identity_trace.h"

MODULE_DESCRIPTION("sing-box socket creator identity");
MODULE_LICENSE("GPL");

static bool capture_all;

/* Disabling waits for callbacks that may still observe the old value, so
 * the caller knows no event fires after the write returns. */
static int set_capture_all(const char *value, const struct kernel_param *kp)
{
	bool enable;
	int err = kstrtobool(value, &enable);

	if (err)
		return err;
	WRITE_ONCE(capture_all, enable);
	if (!enable)
		tracepoint_synchronize_unregister();
	return 0;
}

static const struct kernel_param_ops capture_all_ops = {
	.set = set_capture_all,
	.get = param_get_bool,
};
module_param_cb(capture_all, &capture_all_ops, &capture_all, 0600);
MODULE_PARM_DESC(capture_all, "Emit creator identity for all processes (default off)");

/* --- Counters (per CPU, read without side effects via the stats parameter) --- */
enum sbo_stat {
	ST_INET, ST_SKIPPED, ST_OWN_CGROUP, ST_HIT, ST_MISS, ST_TOO_LONG,
	ST_DELETED, ST_ERROR, ST_KERNEL, ST_UNVALIDATED, ST_GET, ST_PUT, ST_COUNT,
};

static const char *const stat_names[ST_COUNT] = {
	"inet", "skipped", "own_cgroup", "hit", "miss", "too_long",
	"deleted", "error", "kernel", "unvalidated", "get", "put",
};

static DEFINE_PER_CPU(u64 [ST_COUNT], sbo_stats);

static inline void stat_inc(enum sbo_stat index)
{
	this_cpu_inc(sbo_stats[index]);
}

static u64 stat_sum(enum sbo_stat index)
{
	u64 sum = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		sum += per_cpu(sbo_stats[index], cpu);
	return sum;
}

/* Optional timing of the hook including the synchronous BPF consumer: the
 * extra cost a socket pays. Off by default (two local_clock() reads). The
 * clock ticks at 52 ns (19.2 MHz arch timer); means over many sockets count. */
enum sbo_path { PATH_OWN, PATH_HIT, PATH_MISS, PATH_KERNEL, PATH_KINDS };
static const char *const path_names[PATH_KINDS] = { "own", "hit", "miss", "kernel" };
struct path_timing { u64 ns; u64 count; };
static DEFINE_PER_CPU(struct path_timing [PATH_KINDS], sbo_timing);
static bool timing;
module_param(timing, bool, 0600);
MODULE_PARM_DESC(timing, "Measure per-socket hook cost (default off)");

static int stats_get(char *buffer, const struct kernel_param *kp)
{
	int len = 0, i, cpu;

	for (i = 0; i < ST_COUNT; i++)
		len += sysfs_emit_at(buffer, len, "%s%s=%llu", i ? " " : "", stat_names[i], stat_sum(i));
	for (i = 0; i < PATH_KINDS; i++) {
		u64 ns = 0, count = 0;

		for_each_possible_cpu(cpu) {
			ns += per_cpu(sbo_timing[i], cpu).ns;
			count += per_cpu(sbo_timing[i], cpu).count;
		}
		len += sysfs_emit_at(buffer, len, " t_%s=%llu/%llu", path_names[i],
				     count ? div64_u64(ns, count) : 0, count);
	}
	len += sysfs_emit_at(buffer, len, "\n");
	return len;
}

static const struct kernel_param_ops stats_ops = { .get = stats_get };
module_param_cb(stats, &stats_ops, NULL, 0400);
MODULE_PARM_DESC(stats, "Per-CPU counters, summed");

/* --- Fields of opaque kernel types, at device offsets (gen_layout.py) --- */
static inline const void *field_ptr(const void *object, size_t offset)
{
	return READ_ONCE(*(const void *const *)((const u8 *)object + offset));
}

static inline bool is_user_inet(const struct sock *sk)
{
	const u8 *base = (const u8 *)sk;
	u16 family = *(const u16 *)(base + SBO_SKC_FAMILY_OFFSET);

	return (family == AF_INET || family == AF_INET6) &&
	       !((base[SBO_SK_KERN_SOCK_BYTE] >> SBO_SK_KERN_SOCK_SHIFT) & 1);
}

/* Is current the process its cgroup v2 directory is named after? task->cgroups
 * is RCU-protected; css_set, cgroup and kernfs_node stay valid while the
 * css_set is referenced under rcu_read_lock. cgroup directories are not
 * renamed on Android. */
static bool in_own_process_cgroup(void)
{
	const void *cset, *cgrp, *kn;
	const char *name;
	u32 value = 0;
	bool own = false;
	int i;

	rcu_read_lock();
	cset = field_ptr(current, SBO_TASK_CGROUPS_OFFSET);
	cgrp = cset ? field_ptr(cset, SBO_CSS_SET_DFL_CGRP_OFFSET) : NULL;
	kn = cgrp ? field_ptr(cgrp, SBO_CGROUP_KN_OFFSET) : NULL;
	name = kn ? field_ptr(kn, SBO_KERNFS_NODE_NAME_OFFSET) : NULL;
	if (name && name[0] == 'p' && name[1] == 'i' && name[2] == 'd' && name[3] == '_') {
		for (i = 4; i < 16; i++) {
			char c = name[i];

			if (c == '\0') {
				own = i > 4 && value == (u32)current->tgid;
				break;
			}
			if (c < '0' || c > '9')
				break;
			value = value * 10 + (c - '0');
		}
	}
	rcu_read_unlock();
	return own;
}

/* --- Per-CPU path cache --- */
#define PATH_CACHE_SLOTS 4
#define PATH_MAX_LEN 256 /* longest of 4679 app native libraries on the device: 186 bytes */

static const char deleted_suffix[] = " (deleted)";
#define DELETED_SUFFIX_LEN (sizeof(deleted_suffix) - 1)

struct path_cache_entry {
	dev_t s_dev;
	u32 i_generation;
	unsigned long i_ino;
	u32 path_len;
	u32 flags;
	bool valid;
	char path[PATH_MAX_LEN];
};

struct percpu_cache {
	struct path_cache_entry slots[PATH_CACHE_SLOTS];
	unsigned int next_slot;
};

static DEFINE_PER_CPU(struct percpu_cache, pcpu_path_cache);

static inline void emit(struct sock *sk, dev_t dev, unsigned long ino, u32 gen,
			const char *path, u32 path_len, u32 flags)
{
	trace_sbo_identity_socket(sk, dev, ino, gen, path, path_len, flags);
}

static bool cache_emit(struct sock *sk, dev_t dev, unsigned long ino, u32 gen)
{
	struct percpu_cache *pcpu = get_cpu_ptr(&pcpu_path_cache);
	bool hit = false;
	int s;

	for (s = 0; s < PATH_CACHE_SLOTS; s++) {
		struct path_cache_entry *e = &pcpu->slots[s];

		if (e->valid && e->i_ino == ino && e->s_dev == dev && e->i_generation == gen) {
			emit(sk, dev, ino, gen, e->path, e->path_len, e->flags | SBO_EVENT_CACHE_HIT);
			hit = true;
			break;
		}
	}
	put_cpu_ptr(&pcpu_path_cache);
	return hit;
}

/* Resolves the creator's executable under a real reference. */
static void resolve_slow(struct sock *sk, struct mm_struct *mm)
{
	char buf[PATH_MAX_LEN];
	struct file *exe;
	struct inode *inode;
	struct percpu_cache *pcpu;
	struct path_cache_entry *e;
	char *path;
	dev_t dev;
	unsigned long ino;
	u32 gen, path_len = 0, flags;

	stat_inc(ST_MISS);
	rcu_read_lock();
	exe = get_file_rcu(&mm->exe_file);
	rcu_read_unlock();
	if (!exe) {
		stat_inc(ST_ERROR);
		emit(sk, 0, 0, 0, "", 0, SBO_EVENT_ERROR);
		return;
	}
	stat_inc(ST_GET);
	inode = file_inode(exe);
	dev = inode->i_sb->s_dev;
	ino = inode->i_ino;
	gen = inode->i_generation;
	path = d_path(&exe->f_path, buf, sizeof(buf));
	fput(exe);
	stat_inc(ST_PUT);

	if (IS_ERR(path)) {
		if (PTR_ERR(path) != -ENAMETOOLONG) {
			/* Not cached: a transient failure must not shadow later sockets. */
			stat_inc(ST_ERROR);
			emit(sk, dev, ino, gen, "", 0, SBO_EVENT_ERROR);
			return;
		}
		stat_inc(ST_TOO_LONG);
		flags = SBO_EVENT_TOO_LONG;
		path = "";
	} else {
		flags = SBO_EVENT_PATH;
		path_len = strlen(path);
		if (path_len >= DELETED_SUFFIX_LEN &&
		    !memcmp(path + path_len - DELETED_SUFFIX_LEN, deleted_suffix, DELETED_SUFFIX_LEN)) {
			path_len -= DELETED_SUFFIX_LEN;
			path[path_len] = '\0';
			flags |= SBO_EVENT_DELETED;
			stat_inc(ST_DELETED);
		}
	}

	pcpu = get_cpu_ptr(&pcpu_path_cache);
	e = &pcpu->slots[pcpu->next_slot++ % PATH_CACHE_SLOTS];
	e->s_dev = dev;
	e->i_ino = ino;
	e->i_generation = gen;
	e->flags = flags;
	e->path_len = path_len;
	memcpy(e->path, path, path_len);
	e->path[path_len] = '\0';
	e->valid = true;
	emit(sk, dev, ino, gen, e->path, path_len, flags);
	put_cpu_ptr(&pcpu_path_cache);
}

static enum sbo_path handle_inet(struct sock *sk)
{
	struct mm_struct *mm = current->mm;
	struct file *exe;
	struct inode *inode;
	dev_t dev = 0;
	unsigned long ino = 0;
	u32 gen = 0;
	bool validated = false;

	if (!mm || (current->flags & PF_KTHREAD)) {
		stat_inc(ST_KERNEL);
		emit(sk, 0, 0, 0, "", 0, SBO_EVENT_KERNEL);
		return PATH_KERNEL;
	}
	if (in_own_process_cgroup()) {
		stat_inc(ST_OWN_CGROUP);
		return PATH_OWN;
	}

	rcu_read_lock();
	exe = rcu_dereference(mm->exe_file);
	if (likely(exe)) {
		inode = READ_ONCE(exe->f_inode);
		if (likely(inode)) {
			dev = inode->i_sb->s_dev;
			ino = inode->i_ino;
			gen = inode->i_generation;
			validated = READ_ONCE(mm->exe_file) == exe;
		}
	}
	rcu_read_unlock();

	if (likely(validated)) {
		if (cache_emit(sk, dev, ino, gen)) {
			stat_inc(ST_HIT);
			return PATH_HIT;
		}
	} else {
		stat_inc(ST_UNVALIDATED);
	}
	resolve_slow(sk, mm);
	return PATH_MISS;
}

static void on_socket_create(void *unused, struct sock *sk)
{
	struct path_timing *t;
	enum sbo_path path;
	u64 start;

	if (!READ_ONCE(capture_all))
		return;
	if (!sk || !is_user_inet(sk)) {
		stat_inc(ST_SKIPPED);
		return;
	}
	stat_inc(ST_INET);
	if (likely(!READ_ONCE(timing))) {
		handle_inet(sk);
		return;
	}
	start = local_clock();
	path = handle_inet(sk);
	t = get_cpu_ptr(&sbo_timing[path]);
	t->ns += local_clock() - start;
	t->count++;
	put_cpu_ptr(&sbo_timing[path]);
}

static int __init sbo_identity_init(void)
{
	return register_trace_android_vh_sock_create(on_socket_create, NULL);
}

static void __exit sbo_identity_exit(void)
{
	u64 got, put;

	WRITE_ONCE(capture_all, false);
	unregister_trace_android_vh_sock_create(on_socket_create, NULL);
	tracepoint_synchronize_unregister();
	/* Read only after every in-flight callback has returned. */
	got = stat_sum(ST_GET);
	put = stat_sum(ST_PUT);
	pr_info("sbo_identity: file_ref check: get_file_rcu=%llu fput=%llu delta=%lld\n",
		got, put, (long long)(got - put));
}

module_init(sbo_identity_init);
module_exit(sbo_identity_exit);
