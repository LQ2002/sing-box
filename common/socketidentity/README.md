# Persistent socket creators

`Open(Config{PinPath: ...})` creates or reopens a root-owned bpffs collector.
The default directory is `/sys/fs/bpf/sing-box/socket-creator-v3`. While the v1 or
v2 directories (`/sys/fs/bpf/sing-box/socket-creator-v1`, `-v2`) still hold pins,
opening the default path is refused (two global producers would both run). The
`sbo_identity` module (`kernel/sbo_identity`) must already be loaded with
`capture_all=1` and expose its module BTF. The package does not load/unload
modules, mount bpffs, change module parameters, or attach a TC program. The
embedded producer supports Linux/Android arm64 little-endian.

The producer attaches to `tp_btf/sbo_identity_socket`. The module fires it only
for user IPv4/IPv6 sockets whose creator is not the process its cgroup is named
after (those are resolved through the socket cgroup instead), and passes the
creator's executable (dev, inode, generation) with its path resolved in the
kernel. The producer initializes `socket_creators` (`sb_sk_creator` in the
kernel) once with the creator's cookie, leader birth time, TGID, TID, UID,
current thread comm, an FNV-1a 64 hash of argv[0], and the executable's key
(`ExeKey`, flag `CreatorExeKey`, in the field that held the inode in v2). The
path itself is stored once per executable in `exe_paths` (`sb_sk_exe_path`, LRU,
1024 entries; `Collector.LookupPath`), so it survives the creator's exit.
UID zero is valid. Missing cookie/birth/PID/TID leaves identity unknown; a
failed argv or exe read only leaves that fact unflagged. argv[0] is the
ActivityManager process record name for zygote children, cut to zygote's
argument block (99 or 78 bytes measured), so a string that fills the block is
flagged as possibly truncated with its hashed length in flag bits 8-15. The
64-byte value is shared with the existing TC consumer; there is no
TASK_STORAGE map or package-token registration. Existing values are never
rewritten. There is no clone flag: an accepted child has no snapshot, but it
inherits the listener's cgroup.

`Collector.Map()` borrows the map descriptor until `Close()`. Consumers must stop
using it before closing the collector. `Close()` releases only this instance's
descriptors and directory lease: pinned storage and the pinned producer link
remain alive and continue collecting while the service is stopped. Existing
socket snapshots survive creator exit and service restarts within the same boot.

The private pin directory contains `creators`, `exe-paths`, `producer`, and a
frozen `metadata` Array map. Reopening checks the boot UUID, ABI, exact embedded producer
hash, program tag/type/name/root owner, actual link target, object IDs, and the
program's actual map references. It refuses partial sets and unexpected entries.
Every path component is opened without following symlinks and must belong to root.
Writable ancestors must have the sticky bit (as Android's `01777` bpffs mount
does), which protects their root-owned children from unprivileged replacement.
The final directory must be mode `0700` on
bpffs; existing objects must be private root-owned bpffs files.

Collector instances retain shared directory locks. Initialization is exclusive;
`Remove(pinPath)` requires an exclusive lock and returns `ErrBusy` while any
collector remains open. Remove validates the complete object set before unpinning
it. An unpin failure attempts to restore only the exact objects already removed;
if restoration also fails, the error identifies the partial state. A partial set
without trustworthy complete metadata is deliberately not deleted automatically.
The directory remains after removal to preserve its lock identity. These locks
coordinate this package's instances, not arbitrary external root operations.

Upgrades are explicit: a producer-object hash change is rejected on reuse. Before
changing builds, stop consumers and remove pins with the matching old binary;
then deploy the new build and open a fresh collector. Removing pins discards the
persisted collector once all other kernel references close. A collector restart
does not backfill sockets that were created before it was installed.

Build the embedded BPF object with `bash common/socketidentity/build-bpf.sh`
using the existing prepared Android kernel headers and Clang 19. The object
retains BTF and CO-RE relocations. Unit tests check the actual embedded BTF against
Go layout, identity/metadata validation, foreign map references, failure rollback,
and real Linux file-lock behavior on a temporary filesystem. They do not load
BPF. The separate `integration` build-tagged `TestDeviceCollectorPersistence`
requires explicit opt-in and a fresh private bpffs. It exercises actual storage
pinning, global capture, process-exit reuse, collector leases and removal, and
can invoke the dependency's live producer-to-TC test while the collector is open.

These isolated target-kernel checks passed on Android 6.12.69. They cover sixteen
root-created IPv4/IPv6 TCP/UDP sockets across collector lifecycle boundaries,
one pre-installation socket that stays unknown, and live IPv4 TCP/UDP/delivery
assignments. They do not validate real-app coverage, a complete sing-box service
restart, or performance. Actual results and remaining checks are recorded only
in `ANDROID_ATTRIBUTION_PLAN.md`.

Build the device test with `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c
-tags integration -o socketidentity.test ./common/socketidentity`. The external
`experimental/identity_carrier_probe/run-creator-integration-device.sh` harness
supplies the module and a private mount/network environment, checks the exact
test inventory and rejects skips, then removes its module and compares production
state. Run it only with a module built against the connected device's exact
kernel BTF and symbol CRCs.
