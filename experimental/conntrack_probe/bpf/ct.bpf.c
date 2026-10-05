// SPDX-License-Identifier: GPL-2.0-only
// Read-only probe: can TC egress tell the reply of an inbound (passive)
// connection from an outbound one by asking conntrack, and at what cost?
//
// For every IPv4 TCP/UDP packet leaving the attached interface, call the
// conntrack kfunc bpf_skb_ct_lookup (net/netfilter/nf_conntrack_bpf.c:394,
// registered for SCHED_CLS at :535) with the packet's own tuple. On a hit
// the kernel writes the matched direction into opts->dir (:226): 0 = this
// packet travels in the connection's ORIGINAL direction (we opened it),
// 1 = REPLY (the peer opened it). The program only observes: it always
// returns TCX_NEXT and never changes a packet.
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

#define TCX_NEXT (-1)
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define BPF_F_CURRENT_NETNS (-1)

// A full (CO-RE) struct, not a forward declaration: cilium matches kfunc
// signatures against the kernel's BTF and rejects Fwd vs Struct.
struct nf_conn {
    unsigned long status;
} __attribute__((preserve_access_index));

// struct bpf_ct_opts in net/netfilter/nf_conntrack_bpf.c (NF_BPF_CT_OPTS_SZ 16).
struct bpf_ct_opts {
    __s32 netns_id;
    __s32 error;
    __u8 l4proto;
    __u8 dir;
    __u16 ct_zone_id;
    __u8 ct_zone_dir;
    __u8 reserved[3];
};

extern struct nf_conn *bpf_skb_ct_lookup(struct __sk_buff *skb, struct bpf_sock_tuple *tuple,
                                         __u32 tuple_len, struct bpf_ct_opts *opts, __u32 opts_len) __ksym;
extern void bpf_ct_release(struct nf_conn *ct) __ksym;

enum stat {
    // [proto][outcome] flattened: proto 0 TCP, 1 UDP; outcome below.
    OUT_ORIGINAL, OUT_REPLY, OUT_MISS, OUT_COUNT,
};
#define STAT_NS (2 * OUT_COUNT)        // summed lookup ns
#define STAT_LOOKUPS (STAT_NS + 1)     // lookups timed
#define STAT_MAX (STAT_LOOKUPS + 1)

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Per-packet detail for the test peer only (watch_ip), and for every TCP
// packet carrying SYN, so passive handshakes can be read one by one.
struct event {
    __u32 saddr, daddr;
    __u16 sport, dport;
    __u8 proto, tcp_flags, found, dir;
    __s32 error;
    __u32 sk_state; // skb->sk state (12 = TCP_NEW_SYN_RECV), 255 = no socket
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

volatile const __u32 watch_ip = 0; // network order; 0 = none

static __always_inline void bump(__u32 key, __u64 by)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &key);
    if (v)
        *v += by;
}

SEC("tc")
int observe(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    __u32 off = 0;
    // wlan0 is Ethernet; raw-IP devices start at the IP header.
    __u8 first;
    if (data + 1 > end)
        return TCX_NEXT;
    first = *(__u8 *)data;
    if ((first >> 4) != 4) {
        if (data + 14 > end || *(__u16 *)(data + 12) != bpf_htons(ETH_P_IP))
            return TCX_NEXT;
        off = 14;
    }
    if (data + off + 20 > end)
        return TCX_NEXT;
    __u8 *ip = data + off;
    __u32 ihl = (ip[0] & 0xf) * 4;
    __u8 proto = ip[9];
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return TCX_NEXT;
    if (ihl < 20 || data + off + ihl + 14 > end)
        return TCX_NEXT;
    __u8 *l4 = data + off + ihl;
    struct bpf_sock_tuple tuple = {};
    tuple.ipv4.saddr = *(__u32 *)(ip + 12);
    tuple.ipv4.daddr = *(__u32 *)(ip + 16);
    tuple.ipv4.sport = *(__u16 *)(l4 + 0);
    tuple.ipv4.dport = *(__u16 *)(l4 + 2);
    __u8 tcp_flags = proto == IPPROTO_TCP ? l4[13] : 0;

    struct bpf_ct_opts opts = {.netns_id = BPF_F_CURRENT_NETNS, .l4proto = proto};
    __u64 t0 = bpf_ktime_get_ns();
    struct nf_conn *ct = bpf_skb_ct_lookup(skb, &tuple, sizeof(tuple.ipv4), &opts, sizeof(opts));
    __u8 found = ct != 0;
    if (ct)
        bpf_ct_release(ct);
    __u64 t1 = bpf_ktime_get_ns();
    bump(STAT_NS, t1 - t0);
    bump(STAT_LOOKUPS, 1);
    __u32 base = proto == IPPROTO_TCP ? 0 : OUT_COUNT;
    bump(base + (!found ? OUT_MISS : opts.dir ? OUT_REPLY : OUT_ORIGINAL), 1);

    if ((watch_ip && (tuple.ipv4.daddr == watch_ip || tuple.ipv4.saddr == watch_ip)) || (tcp_flags & 0x02)) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->saddr = tuple.ipv4.saddr;
            e->daddr = tuple.ipv4.daddr;
            e->sport = bpf_ntohs(tuple.ipv4.sport);
            e->dport = bpf_ntohs(tuple.ipv4.dport);
            e->proto = proto;
            e->tcp_flags = tcp_flags;
            e->found = found;
            e->dir = opts.dir;
            e->error = opts.error;
            struct bpf_sock *sk = skb->sk;
            e->sk_state = sk ? sk->state : 255;
            bpf_ringbuf_submit(e, 0);
        }
    }
    return TCX_NEXT;
}

char LICENSE[] SEC("license") = "GPL";
