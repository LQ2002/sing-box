// SPDX-License-Identifier: GPL-2.0-only
/* Isolated experiment: forward selected socket creations to a typed BPF hook. */
#include <linux/init.h>
#include <linux/kstrtox.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/tracepoint.h>

/* The vendor hook header expects these declarations from its caller. */
struct sockaddr;
struct sk_buff;
#include <trace/hooks/net.h>

#include "sbo_layout_asserts.h"

#if !IS_ENABLED(CONFIG_ANDROID_VENDOR_HOOKS) || !IS_ENABLED(CONFIG_BPF_EVENTS) || \
	!IS_ENABLED(CONFIG_DEBUG_INFO_BTF_MODULES)
#error "The experiment requires vendor hooks, BPF events, and module BTF"
#endif

#define CREATE_TRACE_POINTS
#include "sbo_identity_trace.h"

static unsigned int target_tgid;
static bool hook_registered;

static int set_target_tgid(const char *value, const struct kernel_param *parameter)
{
	unsigned int selected;
	int error;

	error = kstrtouint(value, 0, &selected);
	if (error)
		return error;
	WRITE_ONCE(*(unsigned int *)parameter->arg, selected);
	/* Disabling waits for callbacks that may have observed the old TGID.
	 * The parameter setter runs in process context and may wait here.
	 */
	if (!selected && READ_ONCE(hook_registered))
		tracepoint_synchronize_unregister();
	return 0;
}

static const struct kernel_param_ops target_tgid_ops = {
	.set = set_target_tgid,
	.get = param_get_uint,
};
module_param_cb(target_tgid, &target_tgid_ops, &target_tgid, 0600);
MODULE_PARM_DESC(target_tgid, "Only this init-namespace TGID is traced; 0 disables");

static void on_socket_create(void *unused, struct sock *sk)
{
	unsigned int selected = READ_ONCE(target_tgid);

	if (!selected || task_tgid_nr(current) != selected)
		return;
	if (!sk)
		return;
	/* Keep the socket opaque here. The BPF producer applies the family and
	 * kernel-socket filters using the running kernel's type information.
	 */
	trace_sbo_identity_socket_create(sk);
}

static int __init sbo_identity_bridge_init(void)
{
	int error;

	error = register_trace_android_vh_sock_create(on_socket_create, NULL);
	if (error)
		return error;
	WRITE_ONCE(hook_registered, true);
	return 0;
}

static void __exit sbo_identity_bridge_exit(void)
{
	WRITE_ONCE(target_tgid, 0);
	unregister_trace_android_vh_sock_create(on_socket_create, NULL);
	tracepoint_synchronize_unregister();
	WRITE_ONCE(hook_registered, false);
}

module_init(sbo_identity_bridge_init);
module_exit(sbo_identity_bridge_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test-TGID-only synchronous socket identity tracepoint bridge");
