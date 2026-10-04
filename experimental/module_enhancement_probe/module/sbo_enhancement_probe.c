// SPDX-License-Identifier: GPL-2.0-only
/* All-in-one enhanced kernel module probe (Stage 2).
 *
 * android_vh_sock_create -> classify the creating executable -> typed
 * tracepoint sbo_enhancement_socket_identity, consumed by bpf/consumer.bpf.c.
 *
 * Hot path, in order of cost (review rounds 8-13 in ../REVIEW-claude.md):
 *  1. Only user inet sockets (AF_INET/AF_INET6, !sk_kern_sock) are handled
 *     (both fields read at offsets generated from the device BTF);
 *     unix/netlink sockets, which Android creates far more often, return
 *     before any pointer chasing.
 *  2. Gate: under rcu_read_lock, read mm->exe_file->f_inode without taking
 *     a reference. struct file is SLAB_TYPESAFE_BY_RCU (fs/file_table.c:529)
 *     and zeroed on reuse (kmem_cache_zalloc, :209/:243), so f_inode can be
 *     the old inode, NULL or the new one; inodes are RCU-freed
 *     (fs/inode.c:324). Hence: NULL-check f_inode and re-check that
 *     mm->exe_file still points to the same file. Only a validated key may
 *     match app_process64 or the cache; otherwise take the slow path, which
 *     re-reads the key under a real reference.
 *  3. Per-CPU cache keyed by (s_dev, i_ino, i_generation). /data is f2fs,
 *     which reuses inode numbers and randomises i_generation on new inodes
 *     (fs/f2fs/namei.c:253), so the generation is part of the key. Slots are
 *     only touched between get_cpu_ptr()/put_cpu_ptr(); a hit fires the
 *     tracepoint straight from the slot, no copy.
 *  4. Slow path: rcu_read_lock(); get_file_rcu(); rcu_read_unlock() - the
 *     same sequence as get_mm_exe_file() (kernel/fork.c:1499-1506), which is
 *     not exported - then d_path() into a 256-byte buffer and fput().
 *     d_path() never truncates: it returns -ENAMETOOLONG (fs/d_path.c:23),
 *     reported as TOO_LONG and cached so the program is not re-resolved.
 *     An unlinked exe gets " (deleted)" appended (fs/d_path.c:287); it is
 *     stripped and reported as DELETED.
 *
 * While collection is inactive (no holder of /dev/sbo_enhancement_probe) no
 * event is fired: a socket without a snapshot means "not collected", never
 * "app". Counters are per-CPU and readable without side effects from
 * /sys/module/sbo_enhancement_probe/parameters/stats.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/miscdevice.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/dcache.h>
#include <linux/percpu.h>
#include <linux/math64.h>
#include <linux/sched/clock.h>
#include <linux/tracepoint.h>
#include <linux/socket.h>

/* No <net/sock.h>: struct sock stays opaque so the tracepoint argument
 * resolves to the device kernel's BTF type (see gen_layout.py). The two
 * socket facts read here use offsets generated from the device BTF.
 */
#include "sbo_sock_layout.h"

struct sock;
struct sockaddr;
struct sk_buff;
#include <trace/hooks/net.h>

struct binder_proc;
struct binder_thread;
struct binder_transaction;
#include "binder_internal.h"
#include <trace/hooks/binder.h>

#define CREATE_TRACE_POINTS
#include "sbo_enhancement_trace.h"

MODULE_DESCRIPTION("SBO all-in-one enhanced module probe (Stage 2)");
MODULE_LICENSE("GPL");

static bool is_active;
static atomic_t open_count = ATOMIC_INIT(0);
static atomic_t binder_sample_count = ATOMIC_INIT(0);

static dev_t app_process_dev;
static unsigned long app_process_ino;
static u32 app_process_gen;

enum sbo_stat {
	ST_INET,        /* user inet sockets handled while active */
	ST_SKIPPED,     /* non-inet or kernel sockets, returned immediately */
	ST_APP,
	ST_HIT,
	ST_MISS,        /* slow path entered */
	ST_TOO_LONG,
	ST_DELETED,
	ST_ERROR,
	ST_KERNEL,
	ST_UNVALIDATED, /* gate could not validate its lock-free read */
	ST_GET,         /* get_file_rcu() returned a reference */
	ST_PUT,         /* fput() of that reference */
	ST_COUNT,
};

static const char *const stat_names[ST_COUNT] = {
	"inet", "skipped", "app", "hit", "miss", "too_long", "deleted",
	"error", "kernel", "unvalidated", "get", "put",
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

/* skc_family and the sk_kern_sock bit, at the device kernel's offsets. */
static inline bool is_user_inet(const struct sock *sk)
{
	const u8 *base = (const u8 *)sk;
	u16 family = *(const u16 *)(base + SBO_SKC_FAMILY_OFFSET);

	return (family == AF_INET || family == AF_INET6) &&
	       !((base[SBO_SK_KERN_SOCK_BYTE] >> SBO_SK_KERN_SOCK_SHIFT) & 1);
}

/* Optional per-path timing of the hook, including the synchronous BPF
 * consumer run by the tracepoint: the extra cost each socket pays. Off by
 * default (two local_clock() reads per socket); enable with
 * /sys/module/sbo_enhancement_probe/parameters/timing. local_clock() ticks at
 * the 19.2 MHz arch timer (52 ns), so single samples are quantised; the mean
 * over many sockets is what is reported.
 */
enum sbo_path { PATH_APP, PATH_HIT, PATH_MISS, PATH_KERNEL, PATH_KINDS };
static const char *const path_names[PATH_KINDS] = { "app", "hit", "miss", "kernel" };
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
	len += sysfs_emit_at(buffer, len, " active=%d holders=%d", READ_ONCE(is_active), atomic_read(&open_count));
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
MODULE_PARM_DESC(stats, "Per-CPU event counters, summed");

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
	u8 flags;
	bool valid;
	char path[PATH_MAX_LEN];
};

struct percpu_cache {
	struct path_cache_entry slots[PATH_CACHE_SLOTS];
	unsigned int next_slot;
};

static DEFINE_PER_CPU(struct percpu_cache, pcpu_path_cache);

static inline void emit(struct sock *sk, dev_t dev, unsigned long ino, u32 gen,
			const char *path, u32 path_len, u8 flags)
{
	trace_sbo_enhancement_socket_identity(sk, dev, ino, gen, path, path_len, flags);
}

/* Fires the event from a matching slot. Returns false on a miss. */
static bool cache_emit(struct sock *sk, dev_t dev, unsigned long ino, u32 gen)
{
	struct percpu_cache *pcpu = get_cpu_ptr(&pcpu_path_cache);
	bool hit = false;
	int s;

	for (s = 0; s < PATH_CACHE_SLOTS; s++) {
		struct path_cache_entry *e = &pcpu->slots[s];

		if (e->valid && e->i_ino == ino && e->s_dev == dev && e->i_generation == gen) {
			emit(sk, dev, ino, gen, e->path, e->path_len, e->flags | SBO_FLAG_CACHE_HIT);
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
	u32 gen, path_len = 0;
	u8 flags;

	stat_inc(ST_MISS);
	rcu_read_lock();
	exe = get_file_rcu(&mm->exe_file);
	rcu_read_unlock();
	if (!exe) {
		stat_inc(ST_ERROR);
		emit(sk, 0, 0, 0, "", 0, SBO_FLAG_ERROR);
		return;
	}
	stat_inc(ST_GET);
	inode = file_inode(exe);
	dev = inode->i_sb->s_dev;
	ino = inode->i_ino;
	gen = inode->i_generation;
	if (dev == app_process_dev && ino == app_process_ino && gen == app_process_gen) {
		/* Only reached when the gate could not validate its read. */
		fput(exe);
		stat_inc(ST_PUT);
		stat_inc(ST_APP);
		emit(sk, dev, ino, gen, "", 0, SBO_FLAG_APP_PROCESS);
		return;
	}
	path = d_path(&exe->f_path, buf, sizeof(buf));
	fput(exe);
	stat_inc(ST_PUT);

	if (IS_ERR(path)) {
		if (PTR_ERR(path) != -ENAMETOOLONG) {
			/* Not cached: a transient failure must not shadow later sockets. */
			stat_inc(ST_ERROR);
			emit(sk, dev, ino, gen, "", 0, SBO_FLAG_ERROR);
			return;
		}
		stat_inc(ST_TOO_LONG);
		flags = SBO_FLAG_TOO_LONG;
		path = "";
	} else {
		flags = SBO_FLAG_NATIVE_PATH;
		path_len = strlen(path);
		if (path_len >= DELETED_SUFFIX_LEN &&
		    !memcmp(path + path_len - DELETED_SUFFIX_LEN, deleted_suffix, DELETED_SUFFIX_LEN)) {
			path_len -= DELETED_SUFFIX_LEN;
			path[path_len] = '\0';
			flags |= SBO_FLAG_DELETED;
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

/* Classifies one user inet socket and fires its event. */
static enum sbo_path handle_inet(struct sock *sk)
{
	struct mm_struct *mm;
	struct file *exe;
	struct inode *inode;
	dev_t dev = 0;
	unsigned long ino = 0;
	u32 gen = 0;
	bool validated = false;

	mm = current->mm;
	if (!mm || (current->flags & PF_KTHREAD)) {
		stat_inc(ST_KERNEL);
		emit(sk, 0, 0, 0, "", 0, SBO_FLAG_KERNEL);
		return PATH_KERNEL;
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
		if (dev == app_process_dev && ino == app_process_ino && gen == app_process_gen) {
			stat_inc(ST_APP);
			emit(sk, dev, ino, gen, "", 0, SBO_FLAG_APP_PROCESS);
			return PATH_APP;
		}
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

/* 1. Socket creation hook (net/socket.c:1602, end of __sock_create) */
static void on_socket_create(void *unused, struct sock *sk)
{
	struct path_timing *t;
	enum sbo_path path;
	u64 start;

	if (!READ_ONCE(is_active))
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

/* 2. Binder caller hook (diagnostic metadata only, never used for routing) */
static void on_binder_received(void *unused, struct binder_transaction *t,
			       struct binder_proc *proc, struct binder_thread *thread, uint32_t cmd)
{
	if (!READ_ONCE(is_active))
		return;

	if (t && atomic_inc_return(&binder_sample_count) <= 5) {
		uid_t client_uid = from_kuid(&init_user_ns, t->sender_euid);
		pr_info("sbo_enh_probe [BINDER_TRANSACTION]: receiver_pid=%d receiver_comm=%s client_uid=%u client_pid=%d\n",
			current->pid, current->comm, client_uid, t->from_pid);
	}
}

/* 3. Misc device lifecycle: collection runs while at least one holder is open */
static int probe_open(struct inode *inode, struct file *file)
{
	int count = atomic_inc_return(&open_count);
	if (count == 1) {
		atomic_set(&binder_sample_count, 0);
		WRITE_ONCE(is_active, true);
		pr_info("sbo_enh_probe: first holder OPENED (holders=%d), is_active set to TRUE\n", count);
	} else {
		pr_info("sbo_enh_probe: additional holder OPENED (holders=%d), is_active remains TRUE\n", count);
	}
	return 0;
}

static int probe_release(struct inode *inode, struct file *file)
{
	int count = atomic_dec_return(&open_count);
	if (count == 0) {
		WRITE_ONCE(is_active, false);
		pr_info("sbo_enh_probe: last holder RELEASED (holders=0), is_active set to FALSE\n");
	} else {
		pr_info("sbo_enh_probe: holder RELEASED (remaining holders=%d), is_active remains TRUE\n", count);
	}
	return 0;
}

static const struct file_operations probe_fops = {
	.owner = THIS_MODULE,
	.open = probe_open,
	.release = probe_release,
};

static struct miscdevice probe_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "sbo_enhancement_probe",
	.fops = &probe_fops,
	.mode = 0600, /* Strict root-only permission */
};

static int __init probe_init(void)
{
	int err;
	struct path p;

	/* Resolve the zygote binary at load time instead of hard-coding it. */
	err = kern_path("/system/bin/app_process64", LOOKUP_FOLLOW, &p);
	if (err) {
		pr_err("sbo_enh_probe: failed to look up /system/bin/app_process64: %d\n", err);
		return err;
	}
	app_process_dev = d_inode(p.dentry)->i_sb->s_dev;
	app_process_ino = d_inode(p.dentry)->i_ino;
	app_process_gen = d_inode(p.dentry)->i_generation;
	path_put(&p);
	pr_info("sbo_enh_probe: baseline resolved dev=%u ino=%lu gen=%u\n",
		(unsigned int)app_process_dev, app_process_ino, app_process_gen);

	err = misc_register(&probe_misc);
	if (err) {
		pr_err("sbo_enh_probe: failed to register misc device: %d\n", err);
		return err;
	}

	err = register_trace_android_vh_sock_create(on_socket_create, NULL);
	if (err) {
		pr_err("sbo_enh_probe: failed to register sock_create hook: %d\n", err);
		misc_deregister(&probe_misc);
		return err;
	}

	err = register_trace_android_vh_binder_transaction_received(on_binder_received, NULL);
	if (err) {
		pr_err("sbo_enh_probe: failed to register binder hook: %d\n", err);
		unregister_trace_android_vh_sock_create(on_socket_create, NULL);
		tracepoint_synchronize_unregister();
		misc_deregister(&probe_misc);
		return err;
	}

	pr_info("sbo_enh_probe: loaded (/dev/%s mode 0600)\n", probe_misc.name);
	return 0;
}

static void __exit probe_exit(void)
{
	u64 got, put;

	WRITE_ONCE(is_active, false);
	unregister_trace_android_vh_binder_transaction_received(on_binder_received, NULL);
	unregister_trace_android_vh_sock_create(on_socket_create, NULL);
	tracepoint_synchronize_unregister();
	misc_deregister(&probe_misc);
	/* Read only after every in-flight hook has returned. */
	got = stat_sum(ST_GET);
	put = stat_sum(ST_PUT);
	pr_info("sbo_enh_probe: file_ref check: get_file_rcu=%llu fput=%llu delta=%lld\n",
		got, put, (long long)(got - put));
	pr_info("sbo_enh_probe: module unloaded\n");
}

module_init(probe_init);
module_exit(probe_exit);
