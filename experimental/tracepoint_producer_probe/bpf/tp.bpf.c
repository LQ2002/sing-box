// SPDX-License-Identifier: GPL-2.0-only
// Feasibility probe: can a socket identity snapshot be produced WITHOUT the
// sbo_identity_bridge kernel module, from standard tracepoints only?
//   TCP: tp_btf/inet_sock_set_state, transition to TCP_SYN_SENT, which
//        tcp_v4_connect/tcp_v6_connect fire in the connect() caller's context
//        before tcp_connect() emits the SYN.
//   UDP: tp_btf/sock_send_length, which net/socket.c fires after
//        ops->sendmsg returned, i.e. after the first datagram passed TC.
// A TC egress observer (TCX head, returns TCX_NEXT, never alters traffic)
// counts how many packets find a snapshot already present. For UDP the
// observer creates the per-socket storage first and counts packets seen
// before the tracepoint fills in the identity.
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>
#include <bpf_tracing.h>

struct mm_struct {
    unsigned long arg_start;
    unsigned long arg_end;
} __attribute__((preserve_access_index));

struct task_struct {
    struct mm_struct *mm;
} __attribute__((preserve_access_index));

struct sock_common {
    unsigned short skc_family;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
    __u16 sk_protocol;
    __u8 sk_kern_sock : 1;
} __attribute__((preserve_access_index));

#define ARGV_MAX 128
#define TCX_NEXT (-1) // enum tcx_action_base: continue with the next program
#define TCP_SYN_SENT 2
#define PROTO_TCP 6
#define PROTO_UDP 17

enum source {
    SRC_NONE = 0,
    SRC_SYN_SENT = 1,
    SRC_SEND_LENGTH = 2,
};

// Per-socket state. identity_source == SRC_NONE means TC created the storage
// and the identity has not been written yet.
struct state {
    __u64 cookie;
    __u64 name_hash;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 identity_source;
    __u32 packets_before;   // TC egress packets seen before the identity
    __u32 packets_after;    // TC egress packets seen with the identity
    __u32 name_len;
    __u32 reserved;
};

struct event {
    __u64 cookie;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 source;
    __u32 packets_before;
    __s32 argv_rc;
    __u64 name_hash;
    char argv[ARGV_MAX];
};

enum stat_index {
    ST_SYN_SENT_CALLS,      // SYN_SENT transitions of inet sockets
    ST_SYN_SENT_CREATED,    // identities written there
    ST_SEND_UDP_CALLS,      // sock_send_length on UDP inet sockets
    ST_SEND_UDP_CREATED,    // identities written there
    ST_TC_TCP_SYN,          // TC egress TCP SYN (no ACK) packets
    ST_TC_TCP_SYN_WITH,     // ... that already had an identity
    ST_TC_UDP_PACKETS,      // TC egress UDP packets with a full socket
    ST_TC_UDP_WITH,         // ... that already had an identity
    ST_TC_UDP_SOCKET_FIRST, // UDP sockets first seen by TC
    ST_UDP_FILLED_LATE,     // UDP identities written after TC had counted packets
    ST_UDP_LATER_COVERED,   // UDP sockets whose later packet found the identity
    ST_KTHREAD,             // tracepoint ran without an mm (kernel context)
    ST_ARGV_FAIL,
    ST_COUNT,
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct state);
} states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

// One record per TC sighting that matters: every TCP SYN, and every UDP
// packet that found no identity yet. Lets userspace break counts down by
// interface and socket instead of guessing about duplicates.
struct tc_event {
    __u64 cookie;
    __u32 ifindex;
    __u32 protocol;
    __u32 socket_uid;
    __u32 with_identity;
    __u32 identity_pid;
    __u32 packets_before;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} tc_events SEC(".maps");

static __always_inline void tc_note(struct __sk_buff *skb, __u32 protocol, struct state *st)
{
    struct tc_event *event = bpf_ringbuf_reserve(&tc_events, sizeof(*event), 0);
    if (!event)
        return;
    event->cookie = bpf_get_socket_cookie(skb);
    event->ifindex = skb->ifindex;
    event->protocol = protocol;
    event->socket_uid = bpf_get_socket_uid(skb);
    event->with_identity = st && st->identity_source != SRC_NONE;
    event->identity_pid = st ? st->pid : 0;
    event->packets_before = st ? st->packets_before : 0;
    bpf_ringbuf_submit(event, 0);
}

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, ST_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump(__u32 index)
{
    __u64 *value = bpf_map_lookup_elem(&stats, &index);
    if (value)
        *value += 1;
}

// Writes the caller's identity into st; returns false for kernel context.
static __always_inline bool fill_identity(struct state *st, __u32 source, __u64 cookie)
{
    struct task_struct *task = bpf_get_current_task_btf();
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm) {
        bump(ST_KTHREAD);
        return false;
    }
    char name[ARGV_MAX] = {};
    long rc = bpf_probe_read_user_str(name, sizeof(name), (const void *)BPF_CORE_READ(mm, arg_start));
    __u64 hash = 0xcbf29ce484222325ULL;
    __u32 length = 0;
    if (rc > 1) {
        length = rc - 1;
        for (int i = 0; i < ARGV_MAX; i++) {
            if (i >= length)
                break;
            hash ^= (__u8)name[i];
            hash *= 0x100000001b3ULL;
        }
    } else {
        bump(ST_ARGV_FAIL);
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    st->cookie = cookie;
    st->pid = pid_tgid >> 32;
    st->tid = (__u32)pid_tgid;
    st->uid = (__u32)bpf_get_current_uid_gid();
    st->name_hash = hash;
    st->name_len = length;
    st->identity_source = source;

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        event->cookie = cookie;
        event->pid = st->pid;
        event->tid = st->tid;
        event->uid = st->uid;
        event->source = source;
        event->packets_before = st->packets_before;
        event->argv_rc = rc;
        event->name_hash = hash;
        __builtin_memcpy(event->argv, name, sizeof(name));
        bpf_ringbuf_submit(event, 0);
    }
    return true;
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(on_state, const struct sock *sk, const int oldstate, const int newstate)
{
    if (newstate != TCP_SYN_SENT || !sk)
        return 0;
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != 2 && family != 10)
        return 0;
    bump(ST_SYN_SENT_CALLS);
    struct state *st = bpf_sk_storage_get(&states, (void *)sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (!st || st->identity_source != SRC_NONE)
        return 0;
    if (fill_identity(st, SRC_SYN_SENT, bpf_get_socket_cookie((void *)sk)))
        bump(ST_SYN_SENT_CREATED);
    return 0;
}

SEC("tp_btf/sock_send_length")
int BPF_PROG(on_send, struct sock *sk, int ret, int flags)
{
    if (!sk || ret <= 0)
        return 0;
    if (BPF_CORE_READ(sk, sk_protocol) != PROTO_UDP)
        return 0;
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != 2 && family != 10)
        return 0;
    bump(ST_SEND_UDP_CALLS);
    struct state *st = bpf_sk_storage_get(&states, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (!st || st->identity_source != SRC_NONE)
        return 0;
    bool late = st->packets_before > 0;
    if (fill_identity(st, SRC_SEND_LENGTH, bpf_get_socket_cookie(sk))) {
        bump(ST_SEND_UDP_CREATED);
        if (late)
            bump(ST_UDP_FILLED_LATE);
    }
    return 0;
}

// TCX egress observer. Parses just enough to recognise a TCP SYN.
SEC("tc")
int observe(struct __sk_buff *skb)
{
    struct bpf_sock *sk = skb->sk;
    if (!sk)
        return TCX_NEXT;
    sk = bpf_sk_fullsock(sk);
    if (!sk)
        return TCX_NEXT;
    __u32 protocol = sk->protocol;
    if (protocol == PROTO_TCP) {
        // Raw-IP devices (rmnet) start at the IP header, Ethernet ones 14
        // bytes later. IPv6 SYNs from local sockets carry no extension headers.
        __u8 first;
        __u32 offset;
        if (bpf_skb_load_bytes(skb, 0, &first, 1) < 0)
            return TCX_NEXT;
        __u32 eth = (first >> 4) == 4 || (first >> 4) == 6 ? 0 : 14;
        if (eth && bpf_skb_load_bytes(skb, eth, &first, 1) < 0)
            return TCX_NEXT;
        if ((first >> 4) == 4)
            offset = eth + (first & 0xf) * 4;
        else if ((first >> 4) == 6)
            offset = eth + 40;
        else
            return TCX_NEXT;
        __u8 flags;
        if (bpf_skb_load_bytes(skb, offset + 13, &flags, 1) < 0)
            return TCX_NEXT;
        if ((flags & 0x02) && !(flags & 0x10)) {
            bump(ST_TC_TCP_SYN);
            struct state *st = bpf_sk_storage_get(&states, sk, 0, 0);
            if (st && st->identity_source != SRC_NONE)
                bump(ST_TC_TCP_SYN_WITH);
            tc_note(skb, PROTO_TCP, st);
        }
        return TCX_NEXT;
    }
    if (protocol != PROTO_UDP)
        return TCX_NEXT;
    bump(ST_TC_UDP_PACKETS);
    struct state *st = bpf_sk_storage_get(&states, sk, 0, 0);
    if (!st) {
        st = bpf_sk_storage_get(&states, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
        if (!st)
            return TCX_NEXT;
        bump(ST_TC_UDP_SOCKET_FIRST);
    }
    // Plain read-modify-write: a rare concurrent packet may be miscounted,
    // which is acceptable for these statistics.
    if (st->identity_source == SRC_NONE) {
        st->packets_before++;
        tc_note(skb, PROTO_UDP, st);
    } else {
        bump(ST_TC_UDP_WITH);
        if (st->packets_after == 0 && st->packets_before > 0)
            bump(ST_UDP_LATER_COVERED);
        st->packets_after++;
    }
    return TCX_NEXT;
}

char LICENSE[] SEC("license") = "GPL";
