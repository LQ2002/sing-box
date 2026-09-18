/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * sb_sockowner_probe 的用户态 ABI —— 内核模块与所有查询方的唯一事实来源。
 *
 * 模块本身 (sb_sockowner_probe.c) 也包含本头文件，所以两侧不可能漂移。
 * 为此这里用 <linux/types.h> 的 __u64/__s32 而不是 <stdint.h> 的 uint64_t：
 * 前者在内核态和用户态都可用，后者在内核态不可用。
 *
 * 注意 SBO_IOC_QUERY 的数值编码了 sizeof(struct sbo_query)，所以任何字段增删
 * 都会改变 ioctl 号。改完务必用真实编译器重新算一遍（见下方注释），不要手算，
 * 手算很容易漏掉 __u64 造成的尾部对齐补位。
 */
#ifndef SBO_SOCKOWNER_PROBE_UAPI_H
#define SBO_SOCKOWNER_PROBE_UAPI_H

#include <linux/types.h>

#ifdef __KERNEL__
#include <linux/ioctl.h>
#else
#include <sys/ioctl.h>
#endif

/* 等于内核的 TASK_COMM_LEN。写成字面量是为了让 ABI 不随内核常量悄悄变化；
 * 模块里有 static_assert 校验两者一致，不一致会在编译期报错。
 */
#define SBO_COMM_LEN 16

/*
 * 字段偏移（已用编译器实测，不是推算）：
 *   cookie=0  tgid=8  uid=12  start_time_ns=16  family=24  reserved=26  comm=28
 *   sizeof = 48（28 + 16 = 44，因 __u64 对齐补到 48）
 *
 * 调用约定：调用方填 cookie，其余字段由内核填充。
 * 查不到返回 -ENOENT，cookie 对应的条目已过宽限期同样返回 -ENOENT。
 */
struct sbo_query {
	__u64 cookie;         /* 入参：SO_COOKIE 取得的 socket cookie */
	__s32 tgid;           /* 创建该 socket 的进程 TGID */
	__u32 uid;            /* 创建时的 UID */
	__u64 start_time_ns;  /* 创建者的 start_boottime，纳秒 */
	__u16 family;         /* AF_INET 或 AF_INET6 */
	__u16 reserved;
	/* 创建时抓取的 current->comm。进程退出后 procfs 已消失，这是唯一幸存的
	 * 线索；但只有 15 个有效字符，长包名会被截断，所以它是佐证而非判据。
	 */
	char comm[SBO_COMM_LEN];
};

/*
 * = 0xc0305301。若结构体变更，用下面这段重新求值：
 *
 *   printf("0x%08lx\n", (unsigned long)SBO_IOC_QUERY);
 */
#define SBO_IOC_MAGIC 'S'
#define SBO_IOC_QUERY _IOWR(SBO_IOC_MAGIC, 0x01, struct sbo_query)

/* 字符设备路径，mode 0600 root:root，所以查询方必须是 root。 */
#define SBO_DEVICE_PATH "/dev/sb_sockowner_probe"

#endif /* SBO_SOCKOWNER_PROBE_UAPI_H */
