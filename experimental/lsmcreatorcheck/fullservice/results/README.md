# LSM socket creator, full-service run (2026-10-13)

Rebuilt kernel `#1 SMP PREEMPT Mon Oct 12 03:45:56 UTC 2026`, no kernel
module loaded (the boot package refused sbo_identity.ko: built for another
BTF). Binary `1.15.0-alpha.11-64f1b9b86`, sha256 87aa7031...: Ref
claude/lsm-creator 64f1b9b86 plus the string(Source) logging fix committed
together with this file (the working tree then equals that commit). Test config `../config-accuracy.json` (direct outbound only,
`socket_creator` enabled, default pin path `socket-creator-v4`); the
production instance was not running before and was not started.

`fullservice.sh accuracy 150`: test instance up, log line
`eBPF socket creator collector opened at /sys/fs/bpf/sing-box/socket-creator-v4 (source lsm)`;
cold starts of Chrome, WeChat, Security, bilibili; four `nc` requests from a
root shell (copied toybox, root cgroup) to www.baidu.com:80, all 200.

`analyze.py run` (`accuracy-analysis.txt`): 47 attributed lines, **0 wrong**.

| class | lines | what |
|---|---|---|
| correct | 7 | system-UID processes resolved by name: com.miui.securitycenter (.remote, main, :cache) 6, com.xiaomi.mi_connect_service 1; PID and package equal ActivityManager |
| group_level | 15 | ordinary app UIDs (Chrome, WeChat, bilibili, GMS, Play, ...) |
| no_truth | 24 | netd (PID 2017 = `pidof netd`, path /system/bin/netd) 20; `nc` 4 with path `/data/local/tmp/sbo-lsm/nc`, user root, its PID |
| unknown | 1 | PID 3937 `system` (system_server hosts android, settings, telecom) |

The four `nc` lines are the module-free path at work: root-cgroup processes
get a snapshot, the path comes from `exe_paths` filled by bpf_path_d_path.

Cleanup (`fullservice.sh cleanup`): test instance stopped, collector removed
(`socket-creator-remove`), no pins, no sing-box running, enabled_functions 0.

The first attempt panicked right after opening the collector: the log call
passed `socketidentity.Source` and sing's format.ToString does not know the
type. Fixed by passing `string(...)`; that run's pins were removed first.

dmesg after the run had one WARNING at drm_crtc_set_max_vblank_count
(msm_drm sde_crtc_enable, thread crtc_commit) when the script woke the
screen; no BPF/LSM/ftrace frame, taint 4096 -> 4608 from it.

`run/` (raw log with destinations, dumpsys snapshots) stays local.
