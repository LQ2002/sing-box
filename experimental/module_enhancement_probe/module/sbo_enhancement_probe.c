// SPDX-License-Identifier: GPL-2.0-only
/* Enhanced kernel module feasibility probe.
 * Demonstrates:
 * 1. Safe RCU fast-path bypass for app_process (<20 ns);
 * 2. get_mm_exe_file() + d_path() + fput() safe extraction for native children;
 * 3. Dynamic baseline dev/ino resolution (OverlayFS safe);
 * 4. Miscdevice with mode 0600 and atomic refcounted lifecycle.
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

struct sockaddr;
struct sk_buff;
#include <trace/hooks/net.h>

MODULE_DESCRIPTION("SBO All-in-One Enhanced Module Feasibility Probe");
MODULE_LICENSE("GPL");

static bool is_active;
static atomic_t open_count = ATOMIC_INIT(0);
static atomic_t fast_sample_count = ATOMIC_INIT(0);
static atomic_t slow_sample_count = ATOMIC_INIT(0);

static dev_t app_process_dev;
static unsigned long app_process_ino;

static void on_socket_create(void *unused, struct sock *sk)
{
	u64 t0, t1;
	struct file *exe = NULL;
	bool is_app_process = false;
	dev_t dev = 0;
	unsigned long ino = 0;

	if (!READ_ONCE(is_active))
		return;

	if (!current->mm)
		return; /* Kernel thread bypass */

	/* --- Phase 1: RCU Fast-Path Gate (<20 ns) --- */
	t0 = ktime_get_ns();
	rcu_read_lock();
	exe = rcu_dereference(current->mm->exe_file);
	if (likely(exe && exe->f_inode && exe->f_inode->i_sb)) {
		dev = exe->f_inode->i_sb->s_dev;
		ino = exe->f_inode->i_ino;
		if (likely(dev == app_process_dev && ino == app_process_ino)) {
			is_app_process = true;
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
		u64 t_slow_0, t_slow_1;

		t_slow_0 = ktime_get_ns();
		/* get_file_rcu() safely increments refcount under RCU, avoiding UAF on concurrent execve */
		rcu_read_lock();
		exe = get_file_rcu(&current->mm->exe_file);
		rcu_read_unlock();
		if (exe) {
			path_str = d_path(&exe->f_path, buf, sizeof(buf));
			if (IS_ERR(path_str))
				path_str = "<err>";
			if (exe->f_inode && exe->f_inode->i_sb) {
				ino = exe->f_inode->i_ino;
				dev = exe->f_inode->i_sb->s_dev;
			}
			t_slow_1 = ktime_get_ns();
			pr_info("sbo_enh_probe [NATIVE_CHILD]: pid=%d comm=%s d_path=%s cost_ns=%llu dev=%u ino=%lu\n",
				current->pid, current->comm, path_str, (t_slow_1 - t_slow_0), (unsigned int)dev, ino);
			fput(exe); /* Strict refcount release */
		} else {
			pr_info("sbo_enh_probe [NATIVE_CHILD]: pid=%d comm=%s <no_exe_file>\n", current->pid, current->comm);
		}
	}
}

static int probe_open(struct inode *inode, struct file *file)
{
	int count = atomic_inc_return(&open_count);
	if (count == 1) {
		atomic_set(&fast_sample_count, 0);
		atomic_set(&slow_sample_count, 0);
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

	err = register_trace_android_vh_sock_create(on_socket_create, NULL);
	if (err) {
		pr_err("sbo_enh_probe: failed to register vendor hook: %d\n", err);
		misc_deregister(&probe_misc);
		return err;
	}

	pr_info("sbo_enh_probe: module loaded successfully (/dev/%s mode 0600)\n", probe_misc.name);
	return 0;
}

static void __exit probe_exit(void)
{
	WRITE_ONCE(is_active, false);
	unregister_trace_android_vh_sock_create(on_socket_create, NULL);
	tracepoint_synchronize_unregister();
	misc_deregister(&probe_misc);
	pr_info("sbo_enh_probe: module unloaded\n");
}

module_init(probe_init);
module_exit(probe_exit);
