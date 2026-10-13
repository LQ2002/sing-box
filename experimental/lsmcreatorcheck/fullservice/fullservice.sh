#!/system/bin/sh
# Full-service check of the LSM socket creator on the device (run as root).
# Adapted from ebpf_sing-box experimental/creator_v2_probe/fullservice: a test
# instance with a direct-only config (config-accuracy.json), real apps
# cold-started, `dumpsys activity processes` snapshots as truth (analyze.py).
# No kernel module is loaded: the collector must pick the lsm source.
#
#   fullservice.sh accuracy <seconds>   test instance + apps + a root native client
#   fullservice.sh cleanup              stop the test instance, remove its collector
#
# It refuses to run while any sing-box runs, and never starts, stops or
# changes the production instance under /data/adb/services/sing-box.
set -eu
DIR=/data/local/tmp/sbo-lsm
RUN=$DIR/run
PINS=/sys/fs/bpf/sing-box/socket-creator-v4
fail() { echo "ERROR: $*" >&2; exit 1; }
mkdir -p "$RUN"

case "${1:-}" in
accuracy)
  seconds=${2:-150}
  [ -z "$(pidof sing-box sing-box-lsm)" ] || fail 'a sing-box is running'
  [ ! -e /sys/module/sbo_identity ] || fail 'sbo_identity is loaded; this run checks the module-free source'
  [ -z "$(ls -A $PINS 2>/dev/null)" ] || fail "collector pins already in $PINS"
  rm -f "$RUN"/accuracy.log "$RUN"/dumpsys-*.txt "$RUN"/stdout.log
  "$DIR/sing-box-lsm" check -D "$RUN" -c "$DIR/config-accuracy.json"
  cd "$RUN"
  nohup "$DIR/sing-box-lsm" run -D "$RUN" -c "$DIR/config-accuracy.json" > "$RUN/stdout.log" 2>&1 &
  test_pid=$!
  echo "$test_pid" > "$RUN/test.pid"
  sleep 4
  [ -d /proc/$test_pid ] || { cat "$RUN/stdout.log"; fail 'test instance did not start'; }
  echo "TEST_INSTANCE pid=$test_pid pins=$(ls $PINS | tr '\n' ' ')"
  grep -E 'socket creator' "$RUN/accuracy.log" || true
  snapshot() { dumpsys activity processes > "$RUN/dumpsys-$(date +%s).txt"; }
  snapshot
  input keyevent KEYCODE_WAKEUP
  # Cold starts: stop first so new processes and first sockets are seen.
  for package in com.android.chrome com.tencent.mm com.miui.securitycenter tv.danmaku.bili; do
    am force-stop $package
    snapshot
    monkey -p $package -c android.intent.category.LAUNCHER 1 > /dev/null 2>&1 || true
    sleep 12
    snapshot
  done
  am start -a android.intent.action.VIEW -d https://www.bing.com -p com.android.chrome > /dev/null 2>&1 || true
  cmd network_time_update_service force_refresh || true
  # A native client in the root cgroup, from a copied executable: its
  # sockets need the snapshot (no pid_ cgroup), path from exe_paths.
  cp /system/bin/toybox "$DIR/nc"
  for i in 1 2 3 4; do
    echo "nc $i: $(printf 'HEAD / HTTP/1.0\r\nHost: www.baidu.com\r\n\r\n' | "$DIR/nc" -w 5 www.baidu.com 80 2>&1 | head -1)"
  done
  echo "NC_PID_HINT $$"
  sleep 5
  input keyevent KEYCODE_HOME
  elapsed=$((4 * 12 + 10))
  while [ "$elapsed" -lt "$seconds" ]; do sleep 10; snapshot; elapsed=$((elapsed + 10)); done
  snapshot
  echo "ACCURACY_RUN_DONE log=$RUN/accuracy.log snapshots=$(ls $RUN/dumpsys-*.txt | wc -l)"
  ;;
cleanup)
  if [ -f "$RUN/test.pid" ]; then
    test_pid=$(cat "$RUN/test.pid")
    if [ -d /proc/$test_pid ]; then
      kill "$test_pid"
      for i in $(seq 1 50); do [ -d /proc/$test_pid ] || break; sleep 0.1; done
      [ ! -d /proc/$test_pid ] || fail 'test instance did not stop'
    fi
    rm -f "$RUN/test.pid"
  fi
  if [ -n "$(ls -A $PINS 2>/dev/null)" ]; then
    "$DIR/sing-box-lsm" tools socket-creator-remove --pin-path "$PINS"
  fi
  rmdir "$PINS" 2>/dev/null || true
  rm -f "$DIR/nc"
  echo "CLEANUP pins=$(ls -A $PINS 2>/dev/null | wc -l) sing-box=$(pidof sing-box sing-box-lsm || echo none) enabled_functions=$(wc -l < /sys/kernel/tracing/enabled_functions)"
  ;;
*) fail "usage: $0 accuracy [seconds] | cleanup" ;;
esac
