# sbo_identity

Kernel module that supplies socket creator identity to the sing-box eBPF
inbound (`local.socket_creator`). It replaces `sbo_identity_bridge`
(`experimental/identity_carrier_probe/module`), which only forwarded the
socket pointer.

It hooks `android_vh_sock_create` (end of `__sock_create`, in the creating
task) and, while `capture_all=1`:

- returns immediately for non-inet and kernel sockets;
- returns without any event when the creator is the process its cgroup v2
  directory is named after (`.../uid_<uid>/pid_<tgid>`). Android gives every
  process it starts its own directory and the kernel stamps the creator's
  cgroup on the socket, which TC records; sing-box resolves those sockets
  through the cgroup and `/proc`. Over a device run 76% of inet sockets took
  this path and cost no BPF and no snapshot;
- otherwise fires the typed tracepoint `sbo_identity_socket(sk, dev, ino,
  gen, path, path_len, flags)` with the creator's executable, its full path
  resolved by `d_path` (cached per CPU by (dev, ino, i_generation)), and flags
  for paths of 256 bytes or more, unlinked executables, kernel threads and
  errors.

The BPF producer (`common/socketidentity/bpf/creator.bpf.c`) records the
64-byte snapshot TC copies — including the argv[0] hash used for shared-UID
package attribution — and stores each executable's path once in the
collector's path map, so a short-lived process keeps its path after it exits.

The design, the review history and all measurements are in
`ANDROID_ATTRIBUTION_PLAN.md` ("增强模块") and
`experimental/module_enhancement_probe/`.

## Parameters

| Parameter | Mode | Meaning |
|---|---|---|
| `capture_all` | 0600, default off | Emit events. The collector requires it and never changes it. Clearing it waits for running callbacks. |
| `stats` | 0400 | Per-CPU counters (inet, skipped, own_cgroup, hit, miss, too_long, deleted, error, kernel, unvalidated, get, put) and, if `timing` was on, mean ns per path. |
| `timing` | 0600, default off | Measure each hook including the synchronous BPF consumer. Two clock reads per socket; for measurements only. |

## Build

In WSL as root (the prepared kernel output tree belongs to root):

```sh
sh kernel/sbo_identity/build.sh
```

`gen_layout.py` reads the device's own `vmlinux.btf`
(`experimental/sb_sockowner_probe/target/`) and generates the offsets of the
few fields read through opaque types (`struct sock`, `struct css_set`,
`struct cgroup`, `struct kernfs_node`, `task_struct.cgroups`). The module
includes no socket or cgroup headers: our kernel tree differs from the shipped
kernel inside types reachable from them (KABI unions, `tls_statistics`), and a
module-local `struct sock` would make the verifier reject the producer.
`verify_btf.py` then checks the tracepoint type, that its socket argument is
the device's `struct sock`, and every struct the module does dereference
through headers against the device layout. `verify-ko.py` checks symbol CRCs.

## Load

Compare `.build/base-btf.sha256` with `/sys/kernel/btf/vmlinux` on the device,
then:

```sh
insmod sbo_identity.ko capture_all=1
```

Unload order: stop sing-box, remove the collector
(`sing-box tools socket-creator-remove`), write `capture_all=0`, `rmmod`.
On unload the module logs `file_ref check: get_file_rcu=N fput=N` (they must
be equal).
