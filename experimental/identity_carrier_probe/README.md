# Identity carrier probe

An isolated experiment on an existing Android kernel. It tests whether a trusted
process registration can be copied synchronously into a socket at creation and
read by TC on the first packet, without querying a userspace owner table.

The implementation status and device evidence belong to
[`ANDROID_ATTRIBUTION_PLAN.md`](../../ANDROID_ATTRIBUTION_PLAN.md). This directory
is not integrated into sing-box and is not an alternative implementation plan.

## What is being tested

1. A worker opens its own pidfd and passes it to the root registrar using
   `SCM_RIGHTS`. The registrar writes a random 128-bit synthetic identity and a
   generation number to the leader's `BPF_MAP_TYPE_TASK_STORAGE`.
2. The small `sbo_identity_bridge` module forwards the existing Android
   `android_vh_sock_create` hook to a standard typed tracepoint. Only the selected
   test TGID is forwarded; the default value, zero, disables forwarding.
3. A `tp_btf` BPF program reads the current thread group's leader, its kernel birth
   time, and its task storage. It copies the identity once into
   `BPF_MAP_TYPE_SK_STORAGE`. Missing or mismatched registrations produce an
   explicit unregistered snapshot with no token.
4. The worker passes a duplicate of each test socket FD to the registrar. Before
   sending, the registrar checks the actual socket storage against the worker's
   PID/TID/UID, birth time, token, and `SO_COOKIE`.
5. A read-only TCX program on a private network namespace's loopback device reads
   the same socket storage. It records the first packet's identity and flags in
   a small bounded observation map and always returns `TCX_NEXT`.

The snapshot belongs to the **socket creator**. Changing process registration or
passing a socket FD must not relabel an existing socket. A cookie is used here to
match test observations; TC gets the identity directly from socket storage.
The observation hash is test instrumentation, not the production carrier.

## Scope

No custom kernel is built, installed, or booted. The experiment still needs an
out-of-tree module matching the running kernel, working vendor hooks, module BTF,
TASK_STORAGE, SK_STORAGE, tracing BPF and TCX. Kernel configuration or source
inspection alone is not proof that the complete chain works.

The registrar and workers are test programs. Synthetic tokens do not establish
which Android package owns a process. AMS/zygote registration, isolated process
and SDK sandbox policy, registration ordering before application code, and
shared-process package ambiguity remain separate integration work.

The extended matrix uses a native C helper for real fork, leader/nonleader exec,
and accept. It verifies that fork needs a new task registration, nonleader exec
loses the old leader's registration, and accepted sockets have no identity in
this no-CLONE map. A passing boundary test does not mean automatic attribution
works for that case. Inherited, transferred, and pre-exec sockets keep their
original creation snapshot.

Android application traffic, production routing, io_uring, performance, power
consumption, and long-running memory behavior remain untested. Registration changes use explicit
barriers; concurrent TASK_STORAGE updates during socket creation are not tested.
The kernel birth timestamp is cross-checked at `/proc` clock-tick precision.
The module has no owner hash, free
hook, ioctl interface, automatic loading, or production service integration.
Without a selected worker it still executes a small filter on socket creation.

## Building and running

Build on Linux/WSL using the target kernel source and exact module toolchain. See
`module/build.sh` for its build prerequisites and verification steps. It keeps
generated files separate from the existing production module's build products.
Build BPF with `bash build-bpf.sh [ACK-source-directory]`; its output is
`build/probe.bpf.o`. The Go runner uses its own nested `go.mod`; run
`GO_BIN=/path/to/go bash build-runner.sh` to test and cross-compile it.
Run `bash build-native.sh` for the Android native fixture. It defaults to the
existing NDK r29 arm64/API 35 compiler; `NATIVE_CC` can override its location.

`run-device.sh` is the outer Android root harness. It expects its inputs under
`/data/local/tmp/sbo-identity-carrier-20261003` and takes the existing production
sing-box PID followed by runner flags. It records the protected process identity
and original network state, compares `base-btf.sha256` with the running kernel's
BTF, loads only the independent module, runs the worker
suite in `unshare -n`, then disables and unloads that module. It checks that the
protected process, boot ID, interfaces, routes and IPv4 policy rules are unchanged
(IPv6 route expiry countdowns are normalized, with raw snapshots retained).
`private-netns.sh` refuses the original namespace before bringing loopback up.

Use the final build/run commands and results recorded in the sole plan. Review
the selected device and its running kernel before repeating the experiment.
`build/`, `results/`, and module build products are ignored by Git; source,
validation code, and concise evidence are committed.

The verified device invocation was:

```sh
# All paths below are on the Android device, after pushing the built artifacts.
# base-btf.sha256 comes from module/.build/, and both .sh files come from here.
su -c 'sh /data/local/tmp/sbo-identity-carrier-20261003/run-device.sh 11765 \
  -object /data/local/tmp/sbo-identity-carrier-20261003/probe.bpf.o -timeout 90s'
```

`11765` was the protected production service PID for this recorded run, not a
constant for other devices or boots. The uploaded executable must be named
`identity-carrier-probe` and executable. The uploaded module is
`sbo_identity_bridge.ko`. Also upload the executable `identity-native-worker`
beside the runner; `-native-worker PATH` can override its location. No files are
installed into boot or service directories.

On 2026-10-03, the first matrix passed seven groups (18 sockets). The extended
matrix passed 15 groups: 35 creation snapshots, 34 matching first-packet records,
one listener that does not send, and one accepted child correctly found to lack
identity despite verified payload delivery. It intentionally injects two invalid
registrations; their rejection counts are expected. The final observed non-INET
filter count was one AF_UNIX socket, reported separately from failures.

`python3 audit-log.py results/lifecycle-run02.txt` independently checks the
extended log using exact integers, including old/new identities around fork and
exec. The sole plan records hashes, checks, and remaining limits. This does not
establish real package attribution or a performance improvement.
