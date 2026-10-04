/* SPDX-License-Identifier: GPL-2.0-only */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM sbo_enhancement

#if !defined(_SBO_ENHANCEMENT_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _SBO_ENHANCEMENT_TRACE_H

#include <linux/tracepoint.h>
#include <linux/types.h>

struct sock;

/* Flags passed via tracepoint to BPF consumer */
#define SBO_FLAG_APP_PROCESS  (1U << 0) /* Java host process (app_process64) */
#define SBO_FLAG_NATIVE_PATH  (1U << 1) /* Successfully resolved native executable path */
#define SBO_FLAG_TOO_LONG     (1U << 2) /* Path exceeds buffer length (-ENAMETOOLONG) */
#define SBO_FLAG_DELETED      (1U << 3) /* Executable was deleted (stripped suffix) */
#define SBO_FLAG_ERROR        (1U << 4) /* Resolution failed / no mm / error */

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
