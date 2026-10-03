// SPDX-License-Identifier: GPL-2.0-only
// Standalone identity-carrier experiment. The module filters the test TGID;
// this collection never changes a socket, packet, or forwarding decision.
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>
#include <bpf_tracing.h>

struct task_struct {
    struct task_struct *group_leader;
    __u64 start_boottime;
} __attribute__((preserve_access_index));

struct sock_common {
    __u16 skc_family;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
    __u8 sk_kern_sock : 1;
} __attribute__((preserve_access_index));

struct registration {
    __u64 token_lo;
    __u64 token_hi;
    __u64 generation;
    __u32 tgid;
    __u32 uid;
};

struct identity {
    __u64 cookie;
    __u64 token_lo;
    __u64 token_hi;
    __u64 start_ns;
    __u64 observed_ns;
    __u64 generation;
    __u32 tgid;
    __u32 tid;
    __u32 uid;
    __u16 family;
    __u16 flags;
};

struct observation {
    struct identity identity;
    __u64 first_ns;
    __u64 packet_count;
    __u32 packet_flags;
    __u32 ifindex;
};

_Static_assert(sizeof(struct registration) == 32, "registration ABI");
_Static_assert(sizeof(struct identity) == 64, "identity ABI");
_Static_assert(sizeof(struct observation) == 88, "observation ABI");

enum identity_flags {
    IDENTITY_REGISTERED = 1U << 0,
};

// packet_flags describe only the first packet successfully inserted in the
// observation map. Subsequent packets increase packet_count, not this snapshot.
enum packet_flags {
    PACKET_IPV4 = 1U << 0,
    PACKET_IPV6 = 1U << 1,
    PACKET_TCP = 1U << 2,
    PACKET_TCP_SYN = 1U << 3,
    PACKET_UDP = 1U << 4,
    PACKET_TCP_ACK = 1U << 5,
    PACKET_ETHERNET = 1U << 6,
};

enum capture_stat {
    STAT_HOOK_CALLS = 0,
    STAT_STORAGE_CREATE_FAILED = 1,
    STAT_REGISTERED = 2,
    STAT_UNREGISTERED = 3,
    STAT_REGISTRATION_MISMATCH = 4,
    STAT_OBSERVATION_INSERT_FAILED = 5,
    STAT_UNSUPPORTED_FAMILY = 6,
    STAT_MISSING_BIRTH = 7,
    STAT_DUPLICATE_CREATE = 8,
    STAT_MISSING_COOKIE = 9,
    STAT_COUNT = 10,
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int); // Userspace accesses the leader's storage using a pidfd.
    __type(value, struct registration);
} task_identity SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct identity);
} socket_identity SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, __u64);
    __type(value, struct observation);
} observed_by_cookie SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, STAT_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} capture_stats SEC(".maps");

static __always_inline void count_stat(__u32 key)
{
    __u64 *counter = bpf_map_lookup_elem(&capture_stats, &key);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

SEC("tp_btf/sbo_identity_socket_create")
int BPF_PROG(capture_identity, struct sock *sk)
{
    if (!sk)
        return 0;
    // The C bridge treats sock as opaque. Relocate both the offset and the
    // bit position here; this field's local declaration is not its real layout.
    if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_kern_sock))
        return 0;

    __u16 family = sk->__sk_common.skc_family;
    if (family != 2 && family != 10) {
        count_stat(STAT_UNSUPPORTED_FAMILY);
        return 0;
    }
    count_stat(STAT_HOOK_CALLS);
    if (bpf_sk_storage_get(&socket_identity, sk, 0, 0)) {
        count_stat(STAT_DUPLICATE_CREATE);
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct identity value = {
        .cookie = bpf_get_socket_cookie(sk),
        .observed_ns = bpf_ktime_get_boot_ns(),
        .tgid = pid_tgid >> 32,
        .tid = (__u32)pid_tgid,
        .uid = (__u32)bpf_get_current_uid_gid(),
        .family = family,
    };
    if (!value.cookie) {
        count_stat(STAT_MISSING_COOKIE);
        return 0;
    }

    struct task_struct *task = bpf_get_current_task_btf();
    // Direct CO-RE field access preserves the BTF pointer type required by
    // task_storage_get; a probe_read of group_leader would produce a scalar.
    struct task_struct *leader = task ? task->group_leader : 0;
    if (leader)
        value.start_ns = leader->start_boottime;

    if (!value.start_ns) {
        count_stat(STAT_MISSING_BIRTH);
        count_stat(STAT_UNREGISTERED);
    } else {
        struct registration *registration =
            bpf_task_storage_get(&task_identity, leader, 0, 0);
        if (!registration) {
            count_stat(STAT_UNREGISTERED);
        } else if (registration->tgid != value.tgid || registration->uid != value.uid) {
            count_stat(STAT_REGISTRATION_MISMATCH);
            count_stat(STAT_UNREGISTERED);
        } else {
            value.token_lo = registration->token_lo;
            value.token_hi = registration->token_hi;
            value.generation = registration->generation;
            value.flags = IDENTITY_REGISTERED;
            count_stat(STAT_REGISTERED);
        }
    }

    // Values are initialized once and left unchanged until socket destruction.
    // No CLONE flag: accepted sockets are outside this creation-only experiment.
    if (!bpf_sk_storage_get(&socket_identity, sk, &value,
                            BPF_SK_STORAGE_GET_F_CREATE))
        count_stat(STAT_STORAGE_CREATE_FAILED);
    return 0;
}

static __always_inline __u32 first_packet_flags(struct __sk_buff *skb)
{
    __u8 header[20];
    __u32 offset = 0;
    __u32 flags = 0;
    __u8 protocol;

    // Loopback TCX receives an Ethernet header on the target kernel. Also
    // recognize raw IPv4/IPv6, without assuming that every interface has L2.
    if (bpf_skb_load_bytes(skb, 0, header, 14))
        return 0;
    if ((header[12] == 0x08 && header[13] == 0x00) ||
        (header[12] == 0x86 && header[13] == 0xdd)) {
        offset = 14;
        flags = PACKET_ETHERNET;
    }
    if (bpf_skb_load_bytes(skb, offset, header, sizeof(header)))
        return flags;

    if ((header[0] >> 4) == 4) {
        __u32 length = (header[0] & 0x0f) * 4;
        if (length < 20)
            return flags;
        flags |= PACKET_IPV4;
        protocol = header[9];
        // A noninitial fragment has no transport header at this offset.
        if ((header[6] & 0x1f) || header[7])
            return flags;
        offset += length;
    } else if ((header[0] >> 4) == 6) {
        flags |= PACKET_IPV6;
        protocol = header[6];
        offset += 40;
        // IPv6 extension headers deliberately remain unclassified.
    } else {
        return flags;
    }

    if (protocol == 17) {
        flags |= PACKET_UDP;
    } else if (protocol == 6) {
        flags |= PACKET_TCP;
        __u8 tcp_flags = 0;
        if (!bpf_skb_load_bytes(skb, offset + 13, &tcp_flags, sizeof(tcp_flags))) {
            if (tcp_flags & 0x02)
                flags |= PACKET_TCP_SYN;
            if (tcp_flags & 0x10)
                flags |= PACKET_TCP_ACK;
        }
    }
    return flags;
}

SEC("tcx/egress")
int observe_identity(struct __sk_buff *skb)
{
    // TCX_NEXT leaves the private interface's normal delivery unchanged.
    if (!skb->sk)
        return -1;
    struct identity *identity = bpf_sk_storage_get(&socket_identity, skb->sk, 0, 0);
    if (!identity || !identity->cookie)
        return -1;

    __u64 cookie = identity->cookie;
    struct observation *existing = bpf_map_lookup_elem(&observed_by_cookie, &cookie);
    if (existing) {
        __sync_fetch_and_add(&existing->packet_count, 1);
        return -1;
    }

    struct observation first = {
        .identity = *identity,
        .first_ns = bpf_ktime_get_boot_ns(),
        .packet_count = 1,
        .packet_flags = first_packet_flags(skb),
        .ifindex = skb->ifindex,
    };
    if (bpf_map_update_elem(&observed_by_cookie, &cookie, &first, BPF_NOEXIST)) {
        // Another CPU may have won insertion. Never overwrite its identity or
        // first-packet flags, including when registration changes after create.
        existing = bpf_map_lookup_elem(&observed_by_cookie, &cookie);
        if (existing)
            __sync_fetch_and_add(&existing->packet_count, 1);
        else
            count_stat(STAT_OBSERVATION_INSERT_FAILED);
    }
    return -1;
}

char LICENSE[] SEC("license") = "GPL";
