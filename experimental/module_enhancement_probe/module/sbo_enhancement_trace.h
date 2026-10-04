/* SPDX-License-Identifier: GPL-2.0-only */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM sbo_enhancement

#if !defined(_SBO_ENHANCEMENT_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _SBO_ENHANCEMENT_TRACE_H

#include <linux/tracepoint.h>
#include <linux/types.h>

struct sock;

/* Event flags, mirrored by bpf/consumer.bpf.c and user/acceptance.go.
 * Exactly one of APP_PROCESS / NATIVE_PATH / TOO_LONG / ERROR / KERNEL is set
 * per event; DELETED and CACHE_HIT are modifiers.
 */
#define SBO_FLAG_APP_PROCESS  (1U << 0) /* exe is the zygote binary app_process64 */
#define SBO_FLAG_NATIVE_PATH  (1U << 1) /* path holds the resolved executable path */
#define SBO_FLAG_TOO_LONG     (1U << 2) /* d_path returned -ENAMETOOLONG (>= 256 bytes) */
#define SBO_FLAG_DELETED      (1U << 3) /* exe was unlinked; " (deleted)" stripped */
#define SBO_FLAG_ERROR        (1U << 4) /* no exe_file or d_path failed otherwise */
#define SBO_FLAG_KERNEL       (1U << 5) /* creator has no mm (kernel thread) */
#define SBO_FLAG_CACHE_HIT    (1U << 6) /* served from the per-CPU path cache */

/* Fired once per user inet socket while collection is active. path points to
 * a NUL-terminated string valid only for the duration of the call (a per-CPU
 * cache slot, read with preemption disabled); consumers must copy it.
 */
DECLARE_TRACE(sbo_enhancement_socket_identity,
	TP_PROTO(struct sock *sk, dev_t dev, unsigned long ino, u32 gen, const char *path, u32 path_len, u8 flags),
	TP_ARGS(sk, dev, ino, gen, path, path_len, flags)
);

#endif /* _SBO_ENHANCEMENT_TRACE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE sbo_enhancement_trace
#include <trace/define_trace.h>
