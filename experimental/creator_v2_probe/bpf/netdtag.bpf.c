// SPDX-License-Identifier: GPL-2.0-only
// Minimal TC egress program that borrows netd's cookie_tag_map. The probe
// replaces netd_cookie_tags with the pinned netd map at load time and attaches
// this program only inside a private network namespace.
#include <linux/bpf.h>
#include <bpf_helpers.h>

// Connectivity bpf/netd UidTagValue.
struct uid_tag {
    __u32 uid;
    __u32 tag;
};

struct result {
    __u64 cookie;
    __u64 packets;
    __u32 found;
    __u32 uid;
    __u32 tag;
    __u32 reserved;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u64);
    __type(value, struct uid_tag);
} netd_cookie_tags SEC(".maps");

// Keyed by socket cookie: loopback also carries the kernel's ICMP replies,
// which must not overwrite the probe socket's observation.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, struct result);
} results SEC(".maps");

SEC("tc")
int netd_tag_lookup(struct __sk_buff *skb)
{
    __u64 cookie = bpf_get_socket_cookie(skb);
    if (!cookie)
        return 0;
    struct result next = {.cookie = cookie, .packets = 1};
    struct result *previous = bpf_map_lookup_elem(&results, &cookie);
    if (previous)
        next.packets = previous->packets + 1;
    struct uid_tag *tag = bpf_map_lookup_elem(&netd_cookie_tags, &cookie);
    if (tag) {
        next.found = 1;
        next.uid = tag->uid;
        next.tag = tag->tag;
    }
    bpf_map_update_elem(&results, &cookie, &next, BPF_ANY);
    return 0; // TC_ACT_OK
}

char LICENSE[] SEC("license") = "GPL";
