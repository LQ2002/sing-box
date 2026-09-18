// SPDX-License-Identifier: GPL-2.0-only
/* Socket cookie -> creator identity map for the sing-box integration. */
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/sock_diag.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <net/sock.h>
#include <trace/hooks/net.h>

#if !IS_ENABLED(CONFIG_ANDROID_VENDOR_HOOKS) || !IS_ENABLED(CONFIG_TRACEPOINTS)
#error "Matching kernel must enable ANDROID_VENDOR_HOOKS and TRACEPOINTS"
#endif

/* 桶数与条目上限解耦：桶数只影响链长，上限决定内存占用。
 * 条目按需 kmalloc，所以 OWNER_MAX 是封顶而非预分配；空闲时实测只有几十条，
 * 留足余量以免活跃时触发淘汰。
 */
#define OWNER_HASH_BITS 12
/* 实测创建速率约 28.7 个/秒，8192 条不到 5 分钟就翻一遍，正好卡在 UDP 会话
 * 5 分钟超时的边界上——后台应用切回前台时条目可能刚好被挤掉。翻倍到 16384
 * 把周转时间推到约 10 分钟，留出安全余量。条目按需 kmalloc，这只是封顶。
 */
#define OWNER_MAX 16384
#define OWNER_GRACE (5 * HZ)

/* 容量压力下单次最多检查多少条，避免退化成 O(n) 全表扫描。
 *
 * 链表按"最近被查询"排序，所以头部是最久没人问的那些，绝大多数已经过期。
 * 取 32 而非更小的值是有代价考量的：扫得太少时，头部只要偶然聚集几个未过期
 * 的长寿条目，就会放弃寻找而直接挤掉它们——即使表里还有成千上万个过期条目
 * 可以回收。实测 created 与 freed 接近，说明绝大多数 socket 短命，32 条的
 * 窗口足以覆盖。
 */
#define OWNER_EVICT_SCAN 32
/* struct sbo_query 与 SBO_IOC_QUERY 定义在 UAPI 头里，模块和用户态共用同一份，
 * 两侧不会漂移。
 */
#include "sb_sockowner_probe_uapi.h"
/* 由 refresh-kernel-abi.py 从真机 BTF 生成；不入库，随内核而变。 */
#include "sbo_bitfields.h"

static_assert(SBO_COMM_LEN == TASK_COMM_LEN, "sbo_query comm ABI");
static_assert(sizeof(struct sbo_query) == 48, "sbo_query ioctl ABI size");

struct owner_entry {
	struct hlist_node node;
	/* 按"最近被查询"串起来：新建的挂到尾部，查询命中时也移到尾部，于是头部
	 * 永远是最久没人问的那些。容量压力下从头部 O(1) 淘汰。
	 *
	 * 不能按插入顺序排——那样最旧的排在淘汰端，而长寿 socket（浏览器 QUIC、
	 * 推送长连接）恰恰最旧，却又最需要保留：它们会被反复查询。
	 */
	struct list_head age;
	u64 cookie;
	pid_t tgid;
	kuid_t uid;
	u64 start_time_ns;
	u16 family;
	unsigned long expires;
	/* Captured while the creator is still alive: procfs is already gone by
	 * the time a short-lived process is looked up, and this is then the only
	 * surviving hint about who opened the socket. Truncated to 15 chars, so
	 * it corroborates rather than identifies.
	 */
	char comm[TASK_COMM_LEN];
};

static DEFINE_HASHTABLE(owner_map, OWNER_HASH_BITS);
static LIST_HEAD(owner_age);
static DEFINE_SPINLOCK(owner_lock);
static unsigned int owner_count;
static atomic64_t evicted = ATOMIC64_INIT(0);
static atomic64_t created4 = ATOMIC64_INIT(0);
static atomic64_t created6 = ATOMIC64_INIT(0);
static atomic64_t freed = ATOMIC64_INIT(0);
static struct proc_dir_entry *status_entry;

static bool eligible(const struct sock *sk)
{
	return sk && !sk->sk_kern_sock &&
		(sk->sk_family == AF_INET || sk->sk_family == AF_INET6);
}

static void drop_entry_locked(struct owner_entry *entry)
{
	hash_del(&entry->node);
	list_del(&entry->age);
	kfree(entry);
	owner_count--;
}

/* make_room_locked 在表满时腾出一个位置。
 *
 * 从"最久没人问"的一端起最多检查 OWNER_EVICT_SCAN 条：优先丢弃已过宽限期的，
 * 一条都没有才丢该端第一条。两种情况都是 O(1)，所以不会把代价转嫁到 socket
 * 创建路径上——那是高频路径，而这里只在真正触及上限时才走到。
 *
 * 过期条目平时不主动回收：probe_ioctl() 本就会拒绝返回过期条目，所以它们只占
 * 内存、不影响正确性，留到有容量压力时一并清理即可。
 */
static void make_room_locked(unsigned long now)
{
	struct owner_entry *entry, *tmp;
	int scanned = 0;

	list_for_each_entry_safe(entry, tmp, &owner_age, age) {
		if (scanned++ >= OWNER_EVICT_SCAN)
			break;
		if (entry->expires && time_after_eq(now, entry->expires)) {
			drop_entry_locked(entry);
			return;
		}
	}
	entry = list_first_entry_or_null(&owner_age, struct owner_entry, age);
	if (entry) {
		drop_entry_locked(entry);
		atomic64_inc(&evicted);
	}
}

static void record_create(struct sock *sk)
{
	struct owner_entry *entry;
	u32 words[2];
	unsigned long flags;
	u64 cookie;
	u16 family;

	sock_diag_save_cookie(sk, words);
	cookie = ((u64)words[1] << 32) | words[0];
	entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return;
	entry->cookie = cookie;
	entry->tgid = task_tgid_nr(current);
	entry->uid = current_uid();
	/* 必须取线程组组长的启动时间，不能用 current 的。
	 *
	 * 上面记录的是 TGID（进程），而非主线程创建 socket 时 current->start_boottime
	 * 是那个线程的启动时间，两者对不上，用户态拿 TGID 去 /proc 核对就永远不符。
	 *
	 * 选 start_boottime 而不是 start_time，是因为 /proc/<pid>/stat 的第 22 个
	 * 字段正是由它换算而来（fs/proc/array.c: nsec_to_clock_t(
	 * timens_add_boottime_ns(task->start_boottime))）；start_time 是 monotonic，
	 * 与 procfs 对不上。用户态据此才能判断 PID 是否已被复用。
	 */
	entry->start_time_ns = ktime_to_ns(current->group_leader->start_boottime);
	entry->family = sk->sk_family;
	entry->expires = 0;
	get_task_comm(entry->comm, current);

	/* 条目一旦挂进表里就不再属于本线程：其他 CPU 随时可能因容量压力把它淘汰
	 * 并 kfree。所以发布之后绝不能再解引用 entry——下面的计数用发布前存好的
	 * 局部量。
	 */
	family = entry->family;

	spin_lock_irqsave(&owner_lock, flags);
	if (owner_count >= OWNER_MAX)
		make_room_locked(jiffies);
	hash_add(owner_map, &entry->node, cookie);
	list_add_tail(&entry->age, &owner_age);
	owner_count++;
	spin_unlock_irqrestore(&owner_lock, flags);

	if (family == AF_INET)
		atomic64_inc(&created4);
	else
		atomic64_inc(&created6);
}

static void on_create(void *unused, struct sock *sk)
{
	if (eligible(sk))
		record_create(sk);
}

static void on_free(void *unused, struct sock *sk)
{
	u32 words[2];
	u64 cookie;
	struct owner_entry *entry;
	unsigned long flags;

	if (!eligible(sk))
		return;
	sock_diag_save_cookie(sk, words);
	cookie = ((u64)words[1] << 32) | words[0];
	spin_lock_irqsave(&owner_lock, flags);
	hash_for_each_possible(owner_map, entry, node, cookie) {
		if (entry->cookie == cookie) {
			entry->expires = jiffies + OWNER_GRACE;
			break;
		}
	}
	spin_unlock_irqrestore(&owner_lock, flags);
	atomic64_inc(&freed);
}

static long probe_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct sbo_query query;
	struct owner_entry *entry;
	unsigned long flags;
	long ret = -ENOENT;

	if (cmd != SBO_IOC_QUERY || copy_from_user(&query, (void __user *)arg,
						 sizeof(query)))
		return -EINVAL;
	spin_lock_irqsave(&owner_lock, flags);
	/* 不在这里做全表回收：下面的过期判断已经保证不会返回过期条目，
	 * 而查询是每条连接都会走的路径，不该为清理买单。
	 */
	hash_for_each_possible(owner_map, entry, node, query.cookie) {
		if (entry->cookie == query.cookie &&
			(!entry->expires || time_before(jiffies, entry->expires))) {
			/* 命中即移到链表尾部：把"插入顺序"变成"最近被查询优先保留"。
			 *
			 * 只按插入顺序淘汰会优先干掉最旧的条目，而长寿 socket（浏览器的
			 * QUIC 连接、推送长连接）恰恰排在那一端。它们又会被反复查询——
			 * UDP 会话每 5 分钟超时一次，流量恢复时 sing-box 用同一个 cookie
			 * 重新查一遍。按 28.7 个/秒的实测创建速率，8192 条不到 5 分钟就翻
			 * 一遍，正好卡在超时边界上，于是后台应用切回前台时归属就丢了。
			 *
			 * 被查询过的 cookie 正是 sing-box 关心的那些，让它们远离淘汰端；
			 * 真正没人问的旧条目自然沉到头部。
			 */
			list_move_tail(&entry->age, &owner_age);
			query.tgid = entry->tgid;
			query.uid = from_kuid(&init_user_ns, entry->uid);
			query.start_time_ns = entry->start_time_ns;
			query.family = entry->family;
			memcpy(query.comm, entry->comm, SBO_COMM_LEN);
			ret = 0;
			break;
		}
	}
	spin_unlock_irqrestore(&owner_lock, flags);
	if (!ret && copy_to_user((void __user *)arg, &query, sizeof(query)))
		return -EFAULT;
	return ret;
}

static const struct file_operations probe_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = probe_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = probe_ioctl,
#endif
};

static struct miscdevice probe_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "sb_sockowner_probe",
	.fops = &probe_fops,
	.mode = 0600,
};

static int status_show(struct seq_file *m, void *unused)
{
	unsigned long flags;

	spin_lock_irqsave(&owner_lock, flags);
	seq_printf(m, "entries %u\ncapacity %u\n", owner_count, OWNER_MAX);
	spin_unlock_irqrestore(&owner_lock, flags);
	seq_printf(m, "created_ipv4 %lld\ncreated_ipv6 %lld\nfreed %lld\n",
		(long long)atomic64_read(&created4),
		(long long)atomic64_read(&created6),
		(long long)atomic64_read(&freed));
	/* evicted 非零说明表被撑满过，未过期的条目被挤掉了——此时归属查询会开始
	 * 出现查不到的情况，是该调大 OWNER_MAX 的信号。
	 */
	seq_printf(m, "evicted %lld\n", (long long)atomic64_read(&evicted));
	return 0;
}

/* verify_bitfield_layout 在加载时确认位域真的落在真机 BTF 指明的位置。
 *
 * layout_probe.c 里的 _Static_assert 覆盖不了位域：C 的 offsetof 表达不了它们，
 * 而位域在同一存储单元内调换顺序，既不改变前后非位域成员的偏移，也不改变结构体
 * 大小——那些断言一个都不会失败，模块却会读到错误的位。
 *
 * 所以改为运行时自检：把归零结构体里的目标位置 1，看它落在哪个字节的哪一位。
 * 不符就拒绝加载，失败方向是安全的。
 */
static int __init verify_bitfield_layout(void)
{
	struct sock *probe;
	const u8 *bytes;
	int err = 0;

	probe = kzalloc(sizeof(*probe), GFP_KERNEL);
	if (!probe)
		return -ENOMEM;

	probe->sk_kern_sock = 1;
	bytes = (const u8 *)probe;
	if (bytes[SBO_SOCK_SK_KERN_SOCK_BYTE] != (u8)(1u << SBO_SOCK_SK_KERN_SOCK_BIT)) {
		pr_err("sb_sockowner_probe: sk_kern_sock 位域布局与目标内核不符，拒绝加载\n");
		err = -EINVAL;
	}

	kfree(probe);
	return err;
}

static int __init probe_init(void)
{
	int err;

	err = verify_bitfield_layout();
	if (err)
		return err;

	err = misc_register(&probe_device);
	if (err)
		return err;
	err = register_trace_android_vh_sk_free(on_free, NULL);
	if (err)
		goto unregister_device;
	err = register_trace_android_vh_sock_create(on_create, NULL);
	if (err)
		goto unregister_free;
	status_entry = proc_create_single("sb_sockowner_probe", 0400, NULL, status_show);
	if (!status_entry) {
		err = -ENOMEM;
		goto unregister_create;
	}
	pr_info("sb_sockowner_probe: cookie owner map registered\n");
	return 0;

unregister_create:
	unregister_trace_android_vh_sock_create(on_create, NULL);
unregister_free:
	unregister_trace_android_vh_sk_free(on_free, NULL);
	tracepoint_synchronize_unregister();
unregister_device:
	misc_deregister(&probe_device);
	return err;
}

static void __exit probe_exit(void)
{
	struct owner_entry *entry;
	struct hlist_node *tmp;
	unsigned long flags;
	int bucket;

	proc_remove(status_entry);
	unregister_trace_android_vh_sock_create(on_create, NULL);
	unregister_trace_android_vh_sk_free(on_free, NULL);
	tracepoint_synchronize_unregister();
	spin_lock_irqsave(&owner_lock, flags);
	hash_for_each_safe(owner_map, bucket, tmp, entry, node) {
		hash_del(&entry->node);
		list_del(&entry->age);
		kfree(entry);
	}
	owner_count = 0;
	spin_unlock_irqrestore(&owner_lock, flags);
	misc_deregister(&probe_device);
}

module_init(probe_init);
module_exit(probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Socket cookie to creator identity map for sing-box");
