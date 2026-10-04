// SPDX-License-Identifier: GPL-2.0-only
/* Test module to verify kernel-space d_path() extraction and miscdevice lifecycle. */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
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

MODULE_DESCRIPTION("SBO Enhancement Feasibility Probe");
MODULE_LICENSE("GPL");

static bool is_active;
static atomic_t sample_count = ATOMIC_INIT(0);

static void on_socket_create(void *unused, struct sock *sk)
{
	char buf[256];
	char *path_str = NULL;
	u64 t0, t1, cost_ns;
	unsigned long ino = 0;
	dev_t dev = 0;
	struct file *exe = NULL;

	if (!READ_ONCE(is_active))
		return;

	if (!current->mm)
		return;

	/* Limit log output to first 20 samples to avoid dmesg spam */
	if (atomic_inc_return(&sample_count) > 20)
		return;

	t0 = ktime_get_ns();
	exe = current->mm->exe_file;
	if (exe) {
		path_str = d_path(&exe->f_path, buf, sizeof(buf));
		if (IS_ERR(path_str))
			path_str = "<err>";
		if (exe->f_inode) {
			ino = exe->f_inode->i_ino;
			if (exe->f_inode->i_sb)
				dev = exe->f_inode->i_sb->s_dev;
		}
	} else {
		path_str = "<no_exe>";
	}
	t1 = ktime_get_ns();
	cost_ns = t1 - t0;

	pr_info("sbo_enh_probe: pid=%d comm=%s d_path=%s cost_ns=%llu dev=%u ino=%lu\n",
		current->pid, current->comm, path_str, cost_ns, (unsigned int)dev, ino);
}

static int probe_open(struct inode *inode, struct file *file)
{
	atomic_set(&sample_count, 0);
	WRITE_ONCE(is_active, true);
	pr_info("sbo_enh_probe: misc device OPENED, is_active set to TRUE\n");
	return 0;
}

static int probe_release(struct inode *inode, struct file *file)
{
	WRITE_ONCE(is_active, false);
	pr_info("sbo_enh_probe: misc device RELEASED, is_active set to FALSE\n");
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
	.mode = 0666,
};

static int __init probe_init(void)
{
	int err;

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

	pr_info("sbo_enh_probe: module loaded successfully (/dev/%s)\n", probe_misc.name);
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
