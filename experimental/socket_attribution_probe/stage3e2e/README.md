# Stage 3 device acceptance scripts

Used for ANDROID_ATTRIBUTION_PLAN.md stage 3 on 2026-10-03; results are in
`../results/stage3-*` (ignored by git), summarised in the plan.

| Script | Where | What |
|---|---|---|
| `build-android.sh [output]` | WSL, as likayo | Android arm64 build from the repo's settings (BASE_TAGS, release/LDFLAGS, CGO + NDK r29); default output `../results/sing-box-android` |
| `build-old.sh <rev>` | WSL | same build of an older commit via `git archive` (baseline for the paired check) |
| `e2e-setup.sh` | phone, root | copies `/data/adb/services/sing-box` to `/data/local/tmp/sbe2/e2e` so the test never touches the user's cache.db or log |
| `e2e-ctl.sh start\|stop\|status` | phone | runs the test instance from that copy; refuses to start while another sing-box runs |
| `e2e-deploy.sh` | phone | installs a pushed build into the copy and restarts it |
| `e2e-scenarios.sh` | phone | Chrome cold start, NTP refresh, exclude_package install / reinstall / uninstall with log timings; does not prove the package rule's data-plane effect |
| `e2e-perf.sh <rounds> <conns> [connect\|echo] [target] [bytes]` | phone | paired old/new runs with `../stage3load` (a native workload sharing Chrome's cgroup and UID, not Chrome-created sockets) |
| `e2e-rss.sh` | phone | RSS at 5/30/90 s after start, old vs new |
| `restore.sh` | phone | restarts the user's own sing-box with its original command line |
| `e2e-config.json` | | minimal config (eBPF local TC + exclude_package test app + direct) |

The user's sing-box must be stopped first (only one eBPF inbound per
interface). The user's daily binary comes from another fork; its full config
may use fields this repository rejects, so check a config with
`sing-box check` before using it. Test APKs come from
`experimental/first_connection_probe/build`.

## Metric boundaries and controlled forwarding checks

The historical `stage3-device-perf-paired.txt` workload closed each socket as
soon as `connect()` returned. TC intercepts these connections locally: those
results measure local TCP establishment, not remote round-trip latency or
forwarding throughput. Joining Chrome's cgroup also does not make the native
workload's PID equal to Chrome's PID.

The new `stage3load -mode echo` waits for the exact sent payload to return.
Use a controlled server reachable through a real interface, and verify that
the sing-box test configuration intercepts the target. A loopback exchange
only checks the load tool. For example, with a peer at `10.211.0.2` in an
isolated namespace and `bypass_private_address: false` in the test config:

```sh
# In the peer namespace (no UID or cgroup change):
stage3load -listen 10.211.0.2:7000 -timeout 30s
# In the namespace running the test sing-box, using the tested package UID:
stage3load -mode echo -target 10.211.0.2:7000 -uid "$TEST_UID" \
  -conns 1000 -bytes 65536 -timeout 5s -label forwarding
```

The client exits nonzero if any expected echo fails. `connect_*` still covers
only TCP establishment. `data_rtt_*` covers payload write plus a fully verified
reply after connect; `transaction_*` includes connect and that exchange.
`echo_mib_per_s` counts one returned payload per successful connection divided
by total workload time, including failed attempts. It is sequential
request/response goodput, not maximum link capacity. For paired comparisons,
keep payload size, endpoint, config, connection count and namespace setup
identical, and retain CPU/RSS samples and failure counts. No new forwarding
performance result is implied merely by providing this tool.

`-expect blocked` requires echo mode and succeeds only when no connection gets
a verified reply; local TCP acceptance alone is never a successful exchange.
This is a traffic outcome, not evidence of which component blocked it. For
package-policy checks, require an immediately adjacent successful baseline
from the **same UID to the same endpoint** with the test TC policy bypassed;
then require the intended rule transition plus the expected traffic outcome.
Android netd's cgroup firewall also applies inside private network namespaces
and can block app UIDs before TC. In particular, after uninstalling a package,
an old-UID driver failure without a reachable bypass baseline is inconclusive,
not proof that stale TC rules were removed. Record native same-UID workload
checks as such; they are not real App self-initiated traffic tests.

The existing device scripts stop/start sing-box instances and must not be
run against the user's active service without coordination. An isolated
network namespace test should launch its own sing-box and echo peer directly,
without calling `e2e-ctl.sh stop` or `restore.sh`.

## Isolated device harness

`isolated-netns.sh` creates two private network namespaces held by dedicated
`sleep` processes. Only the private namespaces receive a veth pair, addresses,
routes, the controlled echo server and a test sing-box. It records each owned
PID and process start tick; cleanup signals only these identities and checks
that the protected user service, main-namespace links and IPv4 routes remain
unchanged. Android's default-interface monitor requires a `0xffff` fwmark-mask
rule to discover a default table, so the harness adds one inside the client
namespace. Each test start requires `bpftool` evidence that the local TCX
program is actually attached to the private interface.

Push the script, `stage3load`, the `isolated-*.json` configs and the finalized
test binary into `/data/local/tmp/sbe3-fix`. As device root:

```sh
sh /data/local/tmp/sbe3-fix/isolated-netns.sh setup USER_SERVICE_PID
sh /data/local/tmp/sbe3-fix/isolated-netns.sh baseline 9050
sh /data/local/tmp/sbe3-fix/isolated-perf.sh OLD_BINARY NEW_BINARY 5 1000 65536
sh /data/local/tmp/sbe3-fix/isolated-package.sh NEW_BINARY TEST_SINGLE_APK
sh /data/local/tmp/sbe3-fix/isolated-shared-package.sh NEW_BINARY TEST_A_APK TEST_B_APK
sh /data/local/tmp/sbe3-fix/isolated-netns.sh cleanup
```

`isolated-perf.sh` alternates old/new order across pairs and records binary,
config and driver hashes, verified payload metrics, CPU ticks and RSS. UID
9050 avoids Android's application firewall so this measures the controlled
TC forwarding path; it does not measure an ordinary application's package
attribution coverage. The performance config uses warning-level logging,
while `isolated-forward-config.json` enables debug evidence for separate
functional smoke checks. CPU ticks require the device's clock tick rate for
conversion to seconds. The sequential echo test does not establish maximum
sustained forwarding capacity.

`isolated-package.sh` refuses an already installed diagnostic package, starts
with an empty include-package set, installs and foregrounds the existing
test APK, and sends native traffic with its actual UID. A captured connection
meets a reject route; when test TC is stopped the same UID must successfully
exchange data with the same peer. The script checks that install/reinstall
events occur within one test instance, then checks removal of the old UID
after uninstall. It explicitly reports an inconclusive uninstall result if
netd also blocks the old UID without test TC. Its exit trap removes only the
diagnostic package installed by that invocation and stops its test instance.

`isolated-shared-package.sh` addresses the disappearing-UID firewall confound
without changing netd. Existing fixtures A and B share one UID; the TC config
includes only A. B stays installed and foregrounded to preserve that UID's
normal network permission. With one continuously running test instance, the
same UID must exchange verified payload with only B installed, be rejected
after installing A, and resume verified payload after uninstalling A while B
remains. Baselines with test TC stopped must also succeed. This directly tests
removal of the configured package's UID rule; it does not change the separate
inconclusive outcome when an uninstalled package's entire UID loses Android
network permission. Both fixtures must initially be absent and are uninstalled
by the script. The original fixture build is reused without a new APK toolchain.

For module unavailability, push `module-unavailable-exec.sh` and invoke
`isolated-netns.sh start-unavailable NEW_BINARY CONFIG`. It uses an additional
private mount namespace and a read-only regular-file bind over the module
device, verifies that `O_RDWR` fails, and starts sing-box there. The wrapper
uses the device's existing `/data/adb/ksu/bin/busybox`. Check startup logs for
the module-open failure and `process_tracking=tc_socket_identity`, then run
`isolated-netns.sh load ...`. The kernel module remains loaded, so this tests
the consumer's module-unavailable branch, not module removal or its absence
from kernel overhead measurements.

Raw outputs from the 2026-10-03 correction run, including binary/config hashes,
five paired payload samples, module-open failure and package transitions, are
in `../results/stage3-fix-device/` (ignored by Git). The current acceptance
status and remaining gaps belong to `ANDROID_ATTRIBUTION_PLAN.md`.
