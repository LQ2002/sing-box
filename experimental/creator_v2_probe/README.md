# creator_v2_probe

Standalone device probe run before implementing socket creator v2
(`ANDROID_ATTRIBUTION_PLAN.md`, "Claude 目标设计" → "真机预验证"). It never
touches the production sing-box process, its config or modules.

- `capture`: loads `bpf/argv.bpf.c` at `tp_btf/sbo_identity_socket_create`
  (the `sbo_identity_bridge` module from `../identity_carrier_probe/module`,
  loaded and removed by `run-device.sh`), reads argv[0] (≤128 bytes, FNV-1a 64)
  and the exe inode exactly as the v2 producer would, and compares every event
  with `/proc/<pid>/cmdline` and `stat /proc/<pid>/exe`. Per-segment timings
  and an alternative word hash are measured alongside.
- `netd`: under `unshare -n`, opens netd's `cookie_tag_map` read-only, loads a
  TC program referencing it, tags one probe-owned socket the way
  libnetd_updatable's tagSocket does, checks the lookup, and removes the tag.
- `netdscan`: read-only join of netd's table with sock_diag (charge UID vs sk_uid).
- `procs`: argv[0] of every ProcessRecord in `dumpsys activity processes`.
- `coldstart.sh`: capture while launching apps that are not running.

Build: `bash build.sh` in WSL as likayo (Android Clang r536225, Go). Device
directory: `/data/local/tmp/sbo-creator-v2-probe` (root, 0700) with the probe,
both BPF objects, `sbo_identity_bridge.ko` and `base-btf.sha256`.

`results/` holds the raw outputs quoted in the plan. The full dumpsys output
is deliberately not kept.
