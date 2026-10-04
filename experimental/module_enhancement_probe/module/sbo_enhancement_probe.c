// SPDX-License-Identifier: GPL-2.0-only
/* All-in-One Enhanced Kernel Module Feasibility Probe - Stage 2 Acceptance Implementation.
 * Features:
 * 1. Safe RCU fast-path bypass for app_process (null check + pointer validation);
 * 2. Per-CPU cache (4 slots x 256 bytes) protected by get_cpu_ptr()/put_cpu_ptr();
 * 3. Cache key: (s_dev, i_ino, i_generation) preventing F2FS inode reuse ambiguity;
 * 4. d_path() called strictly OUTSIDE preemption-disabled sections;
 * 5. get_file_rcu() inside RCU read lock paired with fput();
 * 6. PATH_TRUNCATED flag for paths >= 256 bytes;
 * 7. Miscdevice mode 0600 with atomic open_count refcounting.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/miscdevice.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/dcache.h>
#include <linux/ktime.h>
#include <linux/uaccess.h>
#include <linux/percpu.h>
#include <linux/tracepoint.h>
#include <net/sock.h>

struct sockaddr;
struct sk_buff;
struct request_sock;
#include <trace/hooks/net.h>

struct binder_proc;
struct binder_thread;
struct binder_transaction;
#include "binder_internal.h"
#include <trace/hooks/binder.h>

MODULE_DESCRIPTION("SBO All-in-One Enhanced Module - Stage 2 Acceptance");
MODULE_LICENSE("GPL");

static bool is_active;
static atomic_t open_count = ATOMIC_INIT(0);
static atomic_t fast_sample_count = ATOMIC_INIT(0);
static atomic_t hit_sample_count = ATOMIC_INIT(0);
static atomic_t miss_sample_count = ATOMIC_INIT(0);
static atomic_t clone_sample_count = ATOMIC_INIT(0);
static atomic_t binder_sample_count = ATOMIC_INIT(0);
static atomic_t inactive_sample_count = ATOMIC_INIT(0);

static dev_t app_process_dev;
static unsigned long app_process_ino;
static u32 app_process_gen;

/* --- Per-CPU Path Cache Definitions --- */
#define PATH_CACHE_SLOTS 4
#define PATH_MAX_LEN 256
#define PATH_FLAG_TRUNCATED (1U << 0)

struct path_cache_key {
	dev_t s_dev;
	unsigned long i_ino;
	u32 i_generation;
};

struct path_cache_entry {
	struct path_cache_key key;
	char path[PATH_MAX_LEN];
	u32 path_len;
	u8 flags;
};

struct percpu_cache {
	struct path_cache_entry slots[PATH_CACHE_SLOTS];
	u8 next_slot;
};

static DEFINE_PER_CPU(struct percpu_cache, pcpu_path_cache);

/* 1. Socket Creation Hook */
static void on_socket_create(void *unused, struct sock *sk)
{
	u64 t0, t1;
	struct file *exe = NULL;
	bool is_app_process = false;
	dev_t dev = 0;
	unsigned long ino = 0;
	u32 gen = 0;
	u64 t_inact_0, t_inact_1;

	t_inact_0 = ktime_get_ns();
	if (!READ_ONCE(is_active)) {
		t_inact_1 = ktime_get_ns();
		if (atomic_inc_return(&inactive_sample_count) <= 5) {
			pr_info("sbo_enh_probe [INACTIVE_OVERHEAD]: pid=%d is_active=false cost_ns=%llu\n",
				current->pid, (t_inact_1 - t_inact_0));
		}
		return;
	}

	if (!current->mm)
		return; /* Kernel thread bypass */

	/* --- Phase 1: RCU Fast-Path Gate with Pointer Validation --- */
	t0 = ktime_get_ns();
	rcu_read_lock();
	exe = rcu_dereference(current->mm->exe_file);
	if (likely(exe)) {
		struct inode *inode = READ_ONCE(exe->f_inode);
		if (likely(inode && inode->i_sb)) {
			dev = inode->i_sb->s_dev;
			ino = inode->i_ino;
			gen = inode->i_generation;
			/* Pointer-validation check: ensure exe_file didn't change concurrently */
			if (likely(READ_ONCE(current->mm->exe_file) == exe)) {
				if (likely(dev == app_process_dev && ino == app_process_ino && gen == app_process_gen)) {
					is_app_process = true;
				}
			}
		}
	}
	rcu_read_unlock();
	t1 = ktime_get_ns();

	if (likely(is_app_process)) {
		/* Fast path: 99.9% of Java apps bypass here */
		if (atomic_inc_return(&fast_sample_count) <= 5) {
			pr_info("sbo_enh_probe [FAST_BYPASS]: pid=%d comm=%s is_java=true cost_ns=%llu dev=%u ino=%lu gen=%u\n",
				current->pid, current->comm, (t1 - t0), (unsigned int)dev, ino, gen);
		}
		return;
	}

	/* --- Phase 2: Per-CPU Cache Lookup (<5 ns under get_cpu_ptr) --- */
	{
		struct percpu_cache *pcpu;
		bool cache_hit = false;
		char hit_path[PATH_MAX_LEN];
		u32 hit_len = 0;
		u8 hit_flags = 0;
		int s;

		pcpu = get_cpu_ptr(&pcpu_path_cache); /* preempt_disable() */
		for (s = 0; s < PATH_CACHE_SLOTS; s++) {
			if (pcpu->slots[s].key.s_dev == dev &&
			    pcpu->slots[s].key.i_ino == ino &&
			    pcpu->slots[s].key.i_generation == gen &&
			    pcpu->slots[s].path_len > 0) {
				cache_hit = true;
				hit_len = min_t(u32, pcpu->slots[s].path_len, PATH_MAX_LEN - 1);
				memcpy(hit_path, pcpu->slots[s].path, hit_len);
				hit_path[hit_len] = '\0';
				hit_flags = pcpu->slots[s].flags;
				break;
			}
		}
		put_cpu_ptr(&pcpu_path_cache); /* preempt_enable() */

		if (cache_hit) {
			if (atomic_inc_return(&hit_sample_count) <= 10) {
				pr_info("sbo_enh_probe [CACHE_HIT]: pid=%d comm=%s path=%s len=%u truncated=%d dev=%u ino=%lu gen=%u\n",
					current->pid, current->comm, hit_path, hit_len,
					(hit_flags & PATH_FLAG_TRUNCATED) ? 1 : 0, (unsigned int)dev, ino, gen);
			}
			return;
		}

		/* --- Phase 3: Slow Path outside preemption-disabled section --- */
		{
			char buf[PATH_MAX_LEN];
			char *path_str = NULL;
			u64 t_get_0, t_get_1, t_dp_0, t_dp_1, t_fp_0, t_fp_1;
			u8 flags = 0;
			u32 path_len = 0;

			t_get_0 = ktime_get_ns();
			rcu_read_lock();
			exe = get_file_rcu(&current->mm->exe_file);
			rcu_read_unlock();
			t_get_1 = ktime_get_ns();

			if (exe) {
				t_dp_0 = ktime_get_ns();
				path_str = d_path(&exe->f_path, buf, sizeof(buf));
				t_dp_1 = ktime_get_ns();

				if (IS_ERR(path_str)) {
					path_str = "<err>";
				} else {
					path_len = strlen(path_str);
					if (path_len >= PATH_MAX_LEN - 1)
						flags |= PATH_FLAG_TRUNCATED;
				}

				if (exe->f_inode && exe->f_inode->i_sb) {
					ino = exe->f_inode->i_ino;
					dev = exe->f_inode->i_sb->s_dev;
					gen = exe->f_inode->i_generation;
				}

				t_fp_0 = ktime_get_ns();
				fput(exe); /* Strict refcount release */
				t_fp_1 = ktime_get_ns();

				if (atomic_inc_return(&miss_sample_count) <= 10) {
					pr_info("sbo_enh_probe [CACHE_MISS_FILLED]: pid=%d comm=%s path=%s total_ns=%llu (get_rcu=%llu, d_path=%llu, fput=%llu) dev=%u ino=%lu gen=%u\n",
						current->pid, current->comm, path_str,
						(t_fp_1 - t_get_0), (t_get_1 - t_get_0), (t_dp_1 - t_dp_0), (t_fp_1 - t_fp_0),
						(unsigned int)dev, ino, gen);
				}

				/* Phase 4: Write back to local per-CPU slot */
				if (!IS_ERR(path_str) && path_len > 0) {
					u8 slot;
					pcpu = get_cpu_ptr(&pcpu_path_cache); /* preempt_disable() */
					slot = pcpu->next_slot++ % PATH_CACHE_SLOTS;
					pcpu->slots[slot].key.s_dev = dev;
					pcpu->slots[slot].key.i_ino = ino;
					pcpu->slots[slot].key.i_generation = gen;
					pcpu->slots[slot].flags = flags;
					strscpy(pcpu->slots[slot].path, path_str, PATH_MAX_LEN);
					pcpu->slots[slot].path_len = path_len;
					put_cpu_ptr(&pcpu_path_cache); /* preempt_enable() */
				}
			}
		}
	}
}

/* 2. TCP Accept Child Socket Clone Hook */
static void on_inet_csk_clone(void *unused, struct sock *newsk, const struct request_sock *req)
{
	if (!READ_ONCE(is_active))
		return;

	if (newsk && atomic_inc_return(&clone_sample_count) <= 5) {
		pr_info("sbo_enh_probe [TCP_ACCEPT_CLONE]: newsk=%px family=%d state=%d\n",
			newsk, newsk->sk_family, newsk->sk_state);
	}
}

/* 3. Binder IPC Caller Attribution Hook */
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

/* 4. Misc Device Lifecycle Management (Mode 0600 + Atomic Refcount) */
static int probe_open(struct inode *inode, struct file *file)
{
	int count = atomic_inc_return(&open_count);
	if (count == 1) {
		atomic_set(&fast_sample_count, 0);
		atomic_set(&hit_sample_count, 0);
		atomic_set(&miss_sample_count, 0);
		atomic_set(&clone_sample_count, 0);
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

	/* Dynamic baseline resolution: read real app_process64 dev, ino & generation via kern_path */
	if (kern_path("/system/bin/app_process64", LOOKUP_FOLLOW, &p) == 0) {
		if (p.dentry && d_inode(p.dentry) && d_inode(p.dentry)->i_sb) {
			app_process_dev = d_inode(p.dentry)->i_sb->s_dev;
			app_process_ino = d_inode(p.dentry)->i_ino;
			app_process_gen = d_inode(p.dentry)->i_generation;
			pr_info("sbo_enh_probe: baseline resolved dev=%u ino=%lu gen=%u\n",
				(unsigned int)app_process_dev, app_process_ino, app_process_gen);
		}
		path_put(&p);
	} else {
		pr_warn("sbo_enh_probe: failed to lookup /system/bin/app_process64\n");
	}

	err = misc_register(&probe_misc);
	if (err) {
		pr_err("sbo_enh_probe: failed to register misc device: %d\n", err);
		return err;
	}

	/* Register 1: Socket creation hook */
	err = register_trace_android_vh_sock_create(on_socket_create, NULL);
	if (err) {
		pr_err("sbo_enh_probe: failed to register sock_create hook: %d\n", err);
		misc_deregister(&probe_misc);
		return err;
	}

	/* Register 2: TCP accept child socket clone hook */
	err = register_trace_android_vh_inet_csk_clone_lock(on_inet_csk_clone, NULL);
	if (err) {
		pr_err("sbo_enh_probe: failed to register inet_csk_clone hook: %d\n", err);
		unregister_trace_android_vh_sock_create(on_socket_create, NULL);
		misc_deregister(&probe_misc);
		return err;
	}

	/* Register 3: Binder IPC caller attribution hook */
	err = register_trace_android_vh_binder_transaction_received(on_binder_received, NULL);
	if (err) {
		pr_err("sbo_enh_probe: failed to register binder hook: %d\n", err);
		unregister_trace_android_vh_inet_csk_clone_lock(on_inet_csk_clone, NULL);
		unregister_trace_android_vh_sock_create(on_socket_create, NULL);
		misc_deregister(&probe_misc);
		return err;
	}

	pr_info("sbo_enh_probe: Stage 2 All-in-One module loaded successfully (/dev/%s mode 0600)\n",
		probe_misc.name);
	return 0;
}

static void __exit probe_exit(void)
{
	WRITE_ONCE(is_active, false);
	unregister_trace_android_vh_binder_transaction_received(on_binder_received, NULL);
	unregister_trace_android_vh_inet_csk_clone_lock(on_inet_csk_clone, NULL);
	unregister_trace_android_vh_sock_create(on_socket_create, NULL);
	tracepoint_synchronize_unregister();
	misc_deregister(&probe_misc);
	pr_info("sbo_enh_probe: module unloaded successfully\n");
}

module_init(probe_init);
module_exit(probe_exit);
