# Stage 3 device acceptance scripts

Used for ANDROID_ATTRIBUTION_PLAN.md stage 3 on 2026-10-03; results are in
`../results/stage3-*` (ignored by git), summarised in the plan.

| Script | Where | What |
|---|---|---|
| `build-android.sh` | WSL, as likayo | Android arm64 build from the repo's settings (BASE_TAGS, release/LDFLAGS, CGO + NDK r29) |
| `build-old.sh <rev>` | WSL | same build of an older commit via `git archive` (baseline for the paired check) |
| `e2e-setup.sh` | phone, root | copies `/data/adb/services/sing-box` to `/data/local/tmp/sbe2/e2e` so the test never touches the user's cache.db or log |
| `e2e-ctl.sh start\|stop\|status` | phone | runs the test instance from that copy; refuses to start while another sing-box runs |
| `e2e-deploy.sh` | phone | installs a pushed build into the copy and restarts it |
| `e2e-scenarios.sh` | phone | Chrome cold start, NTP refresh, exclude_package install / reinstall / uninstall with timings |
| `e2e-perf.sh <rounds> <conns>` | phone | paired old/new runs with `../stage3load` (joins Chrome's cgroup and UID) |
| `e2e-rss.sh` | phone | RSS at 5/30/90 s after start, old vs new |
| `restore.sh` | phone | restarts the user's own sing-box with its original command line |
| `e2e-config.json` | | minimal config (eBPF local TC + exclude_package test app + direct) |

The user's sing-box must be stopped first (only one eBPF inbound per
interface). The user's daily binary comes from another fork; its full config
may use fields this repository rejects, so check a config with
`sing-box check` before using it. Test APKs come from
`experimental/first_connection_probe/build`.
