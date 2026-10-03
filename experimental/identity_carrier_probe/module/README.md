# Independent identity bridge module

This experimental module forwards the existing `android_vh_sock_create` callback
to a standard typed tracepoint, `sbo_identity_socket_create(struct sock *sk)`.
The tracepoint runs synchronously in the socket-creating task. The module has no
owner table, device node, ioctl, free hook, or userspace event queue. It is
independent of `sb_sockowner_probe` and does not replace the production module.

`target_tgid` is a root-only (`0600`) module parameter. Its default value, `0`,
disables forwarding. A nonzero value selects a TGID in the initial PID namespace.
The bridge forwards non-null opaque socket pointers without accessing socket
fields. The BPF producer must filter non-kernel IPv4/IPv6 sockets before storing
identity. Writing `0` drains callbacks that may have observed the previous selection.

## Build and inspect

Run `sh build.sh` in WSL with an existing prepared Android kernel output tree,
matching Clang, `pahole`, and `resolve_btfids`. The defaults refer to the local
prepared Android 6.12.69 environment; `KDIR` and `CLANG_BIN` can override them.
The script reads the actual extracted device `vmlinux.btf` and symbol CRC table
from `experimental/sb_sockowner_probe/target/`.

The script copies the prepared output tree into a private WSL Linux temporary
directory and saves its location in `.build/kernel-out.path`. This avoids case
collisions in generated kernel headers on Windows filesystems. It never changes
the original prepared output tree or the older probe's files. Temporary output
is retained for inspection.

The build verifies the device's `task_struct` size, the `tgid` offset read by the
callback, and the `stack_canary` offset used by the compiler. Socket types remain opaque so that standard
split-BTF generation can resolve them to the actual device base. It checks both classic and extended
symbol CRC tables, import coverage, and typed tracepoint metadata. The generated
`.build/btf-verification.json` records the module and base BTF hashes and explicitly
marks device loading as unverified. A local build alone does not prove module BTF
registration, BPF verification, hook execution, or production integration.
The runner must compare `.build/base-btf.sha256` against the current device's
`/sys/kernel/btf/vmlinux` before loading the module.

## Device experiment boundary

The build script performs no device operations. The coordinated runner must load
the module with `target_tgid=0`, confirm that
`/sys/kernel/btf/sbo_identity_bridge` exists, then load and attach the BPF producer.
Only after the producer is ready should it select the isolated test worker TGID.

Stop in this order: write `target_tgid=0`, close BPF links and programs, then unload
the module. The typed tracepoint attachment holds the module while attached, and
disabling first prevents new forwarded callbacks during cleanup. This experiment
does not modify the production service, startup scripts, root cgroup, or routing.
