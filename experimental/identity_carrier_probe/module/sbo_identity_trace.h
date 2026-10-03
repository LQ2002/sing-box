/* SPDX-License-Identifier: GPL-2.0-only */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM sbo_identity_bridge

#if !defined(_SBO_IDENTITY_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _SBO_IDENTITY_TRACE_H

#include <linux/tracepoint.h>

struct sock;

/* Standard trace machinery generates the typed BPF raw-tracepoint metadata.
 * No trace-event record, owner table, or userspace event queue is involved.
 */
DECLARE_TRACE(sbo_identity_socket_create,
	TP_PROTO(struct sock *sk),
	TP_ARGS(sk));

#endif

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE sbo_identity_trace
#include <trace/define_trace.h>
