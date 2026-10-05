/* SPDX-License-Identifier: GPL-2.0-only */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM sbo_identity

#if !defined(_SBO_IDENTITY_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _SBO_IDENTITY_TRACE_H

#include <linux/tracepoint.h>
#include <linux/types.h>

struct sock;

/* Event flags; mirrored by common/socketidentity/bpf/creator.bpf.c. Exactly
 * one of PATH / TOO_LONG / ERROR / KERNEL is set; DELETED and CACHE_HIT are
 * modifiers.
 */
#define SBO_EVENT_PATH       (1U << 0) /* path holds the creator's executable path */
#define SBO_EVENT_TOO_LONG   (1U << 1) /* d_path returned -ENAMETOOLONG (>= 256 bytes) */
#define SBO_EVENT_DELETED    (1U << 2) /* executable was unlinked; " (deleted)" stripped */
#define SBO_EVENT_ERROR      (1U << 3) /* no exe_file, or d_path failed otherwise */
#define SBO_EVENT_KERNEL     (1U << 4) /* creator has no mm (kernel thread) */
#define SBO_EVENT_CACHE_HIT  (1U << 5) /* served from the per-CPU path cache */

/* Fired synchronously in the creating task for each user inet socket whose
 * creator is not the process its cgroup is named after, while capture_all is
 * set. (dev, ino, gen) identify the creator's executable; path points to a
 * NUL-terminated string valid only during the call (a per-CPU cache slot,
 * preemption disabled): consumers must copy it.
 */
DECLARE_TRACE(sbo_identity_socket,
	TP_PROTO(struct sock *sk, dev_t dev, unsigned long ino, u32 gen,
		 const char *path, u32 path_len, u32 flags),
	TP_ARGS(sk, dev, ino, gen, path, path_len, flags));

#endif /* _SBO_IDENTITY_TRACE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE sbo_identity_trace
#include <trace/define_trace.h>
