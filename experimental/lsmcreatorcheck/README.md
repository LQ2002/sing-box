# lsmcreatorcheck

Device check of the socket creator collector (`common/socketidentity`): which
source attaches, whether snapshots are right, and what a snapshot costs.

It uses its own pin directory (`/sys/fs/bpf/sb-lsmcheck/creator`), never the
default one, and its own cgroups under `/sys/fs/cgroup/sb_lsmcheck`; both are
removed before it exits, as are the executable copies under `-dir`. Nothing of
a running sing-box is touched. Build in WSL as likayo:
`GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath ./experimental/lsmcreatorcheck`.
Run as root on the phone: `./lsmcreatorcheck -dir /data/local/tmp/lsmcheck`.

Checks:

- This process (root cgroup): IPv4/IPv6 x UDP/TCP sockets each have a
  snapshot whose PID, UID, birth time (USER_HZ ticks), argv[0] hash and
  executable path (from `exe_paths`, inode equal to `stat`) match `/proc`;
  an AF_UNIX socket has none.
- Children that hand their socket back over SCM_RIGHTS: in a cgroup named
  `pid_<own pid>` (gate: no snapshot), `pid_<other pid>`, a non-`pid_`
  cgroup, the parent's cgroup, run from an executable deleted before the
  socket (`CreatorExeDeleted`, path without " (deleted)"), and from a
  321-byte path (`CreatorPathTooLong`, nothing stored).
- Cost: `-ab` times socket()+close() attached vs detached (too noisy on the
  phone to resolve < 1 us); then the producer's own run time from the
  kernel's BPF statistics (`BPF_ENABLE_STATS`, on only while the fd is held).
- `-profile <obj>` runs a stage-timed copy built by `profile/build.sh` (the
  production source is copied and timers inserted; it is not changed).

## Results (2026-10-13, Xiaomi 25113PN0EC, rebuilt kernel `#1 SMP PREEMPT Mon Oct 12 03:45:56 UTC 2026`)

Source `lsm`, nothing skipped; 20/20 checks passed with the committed object.
Timing with CPU 4 pinned and its policy's `scaling_min_freq` raised to
`scaling_max_freq` for the run (restored to 883200 afterwards), 50000
sockets per round, ns per producer invocation:

| producer reads | snapshot (root cgroup) | gated (own `pid_` cgroup) |
|---|---|---|
| `BPF_CORE_READ` (helper per field) | 1520-1889 | 151-235 |
| direct BTF loads (committed) | 1114-1643 | 95-153 |

Stage split of a snapshot (timed copy, ns, 4 rounds): gate 61-111,
fill_creator 88-129, argv[0] read and hash 182-336, executable 135-253,
`bpf_sk_storage_get` creating the storage 845-1067. The storage allocation
is the same helper call the module's producer makes.

Not comparable one to one with the module's 50-52 / 762-787 ns
(ANDROID_ATTRIBUTION_PLAN.md): those were measured inside the module with
`local_clock` on the stock kernel, which cannot load the module's twin on
this kernel. In real use, an hour on the device made 4473 snapshots and
23050 gated sockets, i.e. about 6 ms + 2.5 ms of CPU per hour here.

After every run: no pins or cgroups left, `enabled_functions` empty, no
BPF/ftrace/CFI warnings in dmesg, `tainted` 4096 (unchanged).
