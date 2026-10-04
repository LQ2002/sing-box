// SPDX-License-Identifier: GPL-2.0-only
/* All-in-One Enhanced Kernel Module Feasibility Probe.
 * Demonstrates:
 * 1. Safe RCU fast-path bypass for app_process (<20 ns);
 * 2. get_file_rcu() + d_path() + fput() safe extraction for native children;
 * 3. Dynamic baseline dev/ino resolution (OverlayFS safe);
 * 4. Miscdevice mode 0600 with atomic refcounted lifecycle;
 * 5. TCP accept child socket clone hook (android_vh_inet_csk_clone_lock);
 * 6. Binder IPC caller attribution hook (android_vh_binder_transaction_received).
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
#include <linux/tracepoint.h>
#include <net/sock.h>

struct sockaddr;
struct sk_buff;
struct request_sock;
#include <trace/hooks/net.h>

/* Binder structures and hook headers */
struct binder_proc;
struct binder_thread;
struct binder_transaction;
#include "binder_internal.h"
#include <trace/hooks/binder.h>

MODULE_DESCRIPTION("SBO All-in-One Enhanced Module Feasibility Probe");
MODULE_LICENSE("GPL");

static bool is_active;
static atomic_t open_count = ATOMIC_INIT(0);
static atomic_t fast_sample_count = ATOMIC_INIT(0);
static atomic_t slow_sample_count = ATOMIC_INIT(0);
static atomic_t clone_sample_count = ATOMIC_INIT(0);
static atomic_t binder_sample_count = ATOMIC_INIT(0);
static atomic_t inactive_sample_count = ATOMIC_INIT(0);

static dev_t app_process_dev;
static unsigned long app_process_ino;

/* 1. Socket Creation Hook */
static void on_socket_create(void *unused, struct sock *sk)
{
	u64 t0, t1;
	struct file *exe = NULL;
	bool is_app_process = false;
	dev_t dev = 0;
	unsigned long ino = 0;
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

	/* --- Phase 1: RCU Fast-Path Gate (<20 ns) --- */
	t0 = ktime_get_ns();
	rcu_read_lock();
	exe = rcu_dereference(current->mm->exe_file);
	if (likely(exe)) {
		struct inode *inode = READ_ONCE(exe->f_inode);
		if (likely(inode && inode->i_sb)) {
			dev = inode->i_sb->s_dev;
			ino = inode->i_ino;
			/* Pointer-validation check: ensure exe_file didn't change concurrently during read */
			if (likely(READ_ONCE(current->mm->exe_file) == exe)) {
				if (likely(dev == app_process_dev && ino == app_process_ino)) {
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
			pr_info("sbo_enh_probe [FAST_BYPASS]: pid=%d comm=%s is_java=true cost_ns=%llu dev=%u ino=%lu\n",
				current->pid, current->comm, (t1 - t0), (unsigned int)dev, ino);
		}
		return;
	}

	/* --- Phase 2: Safe Slow Path for Native Children --- */
	if (atomic_inc_return(&slow_sample_count) <= 10) {
		char buf[256];
		char *path_str = NULL;
		u64 t_get_0, t_get_1, t_dp_0, t_dp_1, t_fp_0, t_fp_1;

		t_get_0 = ktime_get_ns();
		rcu_read_lock();
		exe = get_file_rcu(&current->mm->exe_file);
		rcu_read_unlock();
		t_get_1 = ktime_get_ns();
		if (exe) {
			t_dp_0 = ktime_get_ns();
			path_str = d_path(&exe->f_path, buf, sizeof(buf));
			if (IS_ERR(path_str))
				path_str = "<err>";
			if (exe->f_inode && exe->f_inode->i_sb) {
				ino = exe->f_inode->i_ino;
				dev = exe->f_inode->i_sb->s_dev;
			}
			t_dp_1 = ktime_get_ns();
			t_fp_0 = ktime_get_ns();
			fput(exe); /* Strict refcount release */
			t_fp_1 = ktime_get_ns();
			pr_info("sbo_enh_probe [NATIVE_CHILD]: pid=%d comm=%s d_path=%s total_ns=%llu (get_rcu=%llu, d_path=%llu, fput=%llu) dev=%u ino=%lu\n",
				current->pid, current->comm, path_str,
				(t_fp_1 - t_get_0), (t_get_1 - t_get_0), (t_dp_1 - t_dp_0), (t_fp_1 - t_fp_0),
				(unsigned int)dev, ino);
		} else {
			pr_info("sbo_enh_probe [NATIVE_CHILD]: pid=%d comm=%s <no_exe_file>\n", current->pid, current->comm);
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
		atomic_set(&slow_sample_count, 0);
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

	/* Dynamic baseline resolution: read real app_process64 dev & ino via kern_path */
	if (kern_path("/system/bin/app_process64", LOOKUP_FOLLOW, &p) == 0) {
		if (p.dentry && d_inode(p.dentry) && d_inode(p.dentry)->i_sb) {
			app_process_dev = d_inode(p.dentry)->i_sb->s_dev;
			app_process_ino = d_inode(p.dentry)->i_ino;
			pr_info("sbo_enh_probe: baseline resolved dev=%u ino=%lu\n",
				(unsigned int)app_process_dev, app_process_ino);
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

	pr_info("sbo_enh_probe: All-in-One module loaded successfully (/dev/%s mode 0600, 3 hooks active)\n",
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
