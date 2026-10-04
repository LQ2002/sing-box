#!/system/bin/sh
# Stage 2 acceptance on the device. Run as root in the global mount namespace
# (su -mm) from $DIR, which holds sbo_enhancement_probe.ko, consumer.bpf.o and
# sbo-acceptance.
#   run-device.sh quick           load/unload x3, selftests (normal, >256-byte
#                                 path, deleted exe), class triggers, checks
#   run-device.sh long <seconds>  system-wide watch for <seconds>, then checks
#   run-device.sh bench           pinned, frequency-locked socket() benchmark,
#                                 states interleaved: unloaded / collecting /
#                                 loaded-inactive
# Never touches the production sing-box service or its config; the sing-box
# binary is only executed as "tools synctime" (no config, no -w) from $DIR.
set -eu
DIR=/data/local/tmp/sboacc
KO=$DIR/sbo_enhancement_probe.ko
TOOL=$DIR/sbo-acceptance
OBJ=$DIR/consumer.bpf.o
BASE_BTF_SHA=37d2c7e7bc5ec219db6148d4a874d9cfc05216db3d7b860adfafc567576b5f35
cd "$DIR"
fail() { echo "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail 'run as root'
[ "$(sha256sum /sys/kernel/btf/vmlinux | awk '{print $1}')" = "$BASE_BTF_SHA" ] || fail 'kernel BTF differs from module build base'
[ ! -e /sys/module/sbo_enhancement_probe ] || fail 'module already loaded'
echo "PRECHECK taint=$(cat /proc/sys/kernel/tainted) file_nr=$(awk '{print $1}' /proc/sys/fs/file-nr) sing-box=$(pidof sing-box || echo none)"

# A /dev/kmsg marker bounds the dmesg check to this run. /proc/uptime cannot
# be used for that: it includes suspend time, the dmesg clock does not.
MARK="SBO_ACCEPT_MARK_$(date +%s)_$$"
echo "$MARK" > /dev/kmsg

load() { insmod "$KO"; for i in 1 2 3 4 5 6 7 8 9 10; do [ -c /dev/sbo_enhancement_probe ] && return 0; sleep 0.1; done; fail 'device node missing'; }
unload() {
  for i in 1 2 3; do rmmod sbo_enhancement_probe 2>/dev/null && break; sleep 1; done
  [ ! -e /sys/module/sbo_enhancement_probe ] || fail 'module still loaded'
}
kernel_check() {
  dmesg | sed -n "/$MARK/,\$p" > dmesg-since-mark.txt
  echo "DMESG lines_since_mark=$(wc -l < dmesg-since-mark.txt)"
  grep -E 'sbo_enh_probe: (file_ref|loaded|baseline)' dmesg-since-mark.txt | tail -n 8
  if grep -iE 'WARNING:|BUG:|Oops|Unable to handle|Kernel panic|refcount_t|use-after-free|KASAN' dmesg-since-mark.txt; then
    fail 'kernel warning since mark'
  fi
  echo "DMESG_CLEAN taint=$(cat /proc/sys/kernel/tainted)"
}
cleanup_mod() { [ -e /sys/module/sbo_enhancement_probe ] && unload || true; }
trap cleanup_mod EXIT

triggers() {
  # netd: its DNS sockets are created by netd itself.
  toybox ping -c 1 -W 1 "sbo-accept-$(date +%s).example.com" >/dev/null 2>&1 || true
  # iptables: getsockopt on a raw inet socket.
  /system/bin/iptables -w -L -n >/dev/null 2>&1 || true
  /system/bin/iptables -w -L -n >/dev/null 2>&1 || true
  # sing-box itself, without a config and without writing the clock.
  SB=/data/adb/services/sing-box/sing-box
  [ -x "$SB" ] && (cd "$DIR" && "$SB" tools synctime >/dev/null 2>&1) || true
  [ -x "$SB" ] && (cd "$DIR" && "$SB" tools synctime >/dev/null 2>&1) || true
}

case "${1:-}" in
quick)
  for round in 1 2 3; do load; unload; echo "LOAD_UNLOAD round=$round ok"; done
  load
  echo "STATS_LOADED $(cat /sys/module/sbo_enhancement_probe/parameters/stats)"
  "$TOOL" watch -object "$OBJ" -duration 90s -interval 30s -out watch-quick.json > watch-quick.log 2>&1 &
  WATCH=$!
  sleep 2
  "$TOOL" selftest -object "$OBJ" -n 2000

  # Executable path >= 256 bytes: d_path returns -ENAMETOOLONG.
  LONG=$DIR/L
  for i in 1 2 3 4 5 6 7 8; do LONG=$LONG/dir_$i-0123456789abcdef0123456789; done
  mkdir -p "$LONG"
  cp "$TOOL" "$LONG/sbo-acceptance"
  echo "LONG_PATH bytes=$(printf %s "$LONG/sbo-acceptance" | wc -c)"
  "$LONG/sbo-acceptance" selftest -object "$OBJ" -n 200
  rm -rf "$DIR/L"

  # Executable unlinked before it creates sockets.
  cp "$TOOL" "$DIR/sbo-deleted"
  "$DIR/sbo-deleted" selftest -object "$OBJ" -n 200 -wait-signal > deleted.log 2>&1 &
  DPID=$!
  for i in $(seq 1 50); do grep -q WAITING_FOR_SIGUSR1 deleted.log && break; sleep 0.1; done
  rm -f "$DIR/sbo-deleted"
  kill -USR1 "$DPID"
  wait "$DPID" || { cat deleted.log; fail 'deleted-exe selftest failed'; }
  cat deleted.log

  triggers
  wait "$WATCH" || true
  cat watch-quick.log
  echo "STATS_BEFORE_UNLOAD $(cat /sys/module/sbo_enhancement_probe/parameters/stats)"
  unload
  kernel_check
  ;;
long)
  seconds=${2:-3600}
  load
  echo "FILE_NR_START $(cat /proc/sys/fs/file-nr)"
  "$TOOL" watch -object "$OBJ" -duration "${seconds}s" -interval 300s -out watch-long.json > watch-long.log 2>&1 &
  WATCH=$!
  sleep 2
  triggers
  wait "$WATCH" || true
  cat watch-long.log
  echo "FILE_NR_END $(cat /proc/sys/fs/file-nr)"
  echo "STATS_BEFORE_UNLOAD $(cat /sys/module/sbo_enhancement_probe/parameters/stats)"
  unload
  kernel_check
  ;;
bench)
  POL=/sys/devices/system/cpu/cpufreq/policy0
  MIN=$(cat $POL/scaling_min_freq); MAX=$(cat $POL/scaling_max_freq)
  # Keep the CPU out of suspend while timing (the phone may be offline with
  # the screen off); released in restore().
  echo sboacc_bench > /sys/power/wake_lock
  restore() {
    echo sboacc_bench > /sys/power/wake_unlock 2>/dev/null || true
    echo "$MIN" > $POL/scaling_min_freq 2>/dev/null || true
    [ -n "${HOLD:-}" ] && kill "$HOLD" 2>/dev/null || true
    cleanup_mod
    echo "FREQ_RESTORED min=$(cat $POL/scaling_min_freq) max=$(cat $POL/scaling_max_freq) governor=$(cat $POL/scaling_governor)"
  }
  trap restore EXIT
  echo "$MAX" > $POL/scaling_min_freq
  echo "FREQ_LOCKED policy0 min=max=$(cat $POL/scaling_min_freq) cur=$(cat $POL/scaling_cur_freq)"
  bench() { taskset 10 "$TOOL" bench -n 20000 -rounds 5 -label "$1"; }
  for cycle in 1 2 3; do
    bench unloaded
    load
    "$TOOL" hold -object "$OBJ" -duration 600s > hold.log 2>&1 &
    HOLD=$!
    for i in $(seq 1 50); do grep -q HOLDING hold.log && break; sleep 0.1; done
    bench collecting
    kill "$HOLD"; wait "$HOLD" || true; HOLD=
    cat hold.log
    bench loaded_inactive
    unload
  done
  ;;
*)
  fail 'usage: run-device.sh quick | long <seconds> | bench'
  ;;
esac
