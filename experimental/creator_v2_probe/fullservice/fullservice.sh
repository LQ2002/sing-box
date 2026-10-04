#!/system/bin/sh
# Full-service acceptance of socket creator v2 on the device (run as root).
# The user's production sing-box is stopped only by "stop-prod" (with their
# approval) and restarted by "restore" with its exact recorded command line.
#
#   fullservice.sh stop-prod            record and stop the production instance
#   fullservice.sh accuracy <seconds>   bridge + collector + test instance, real apps,
#                                       periodic dumpsys snapshots as truth
#   fullservice.sh sockbench            socket()+close() cost: none / old module / bridge+v2
#   fullservice.sh hooks none|old|new   switch the global kernel hook state
#   fullservice.sh restore              hooks none, restart production, screen policy back
set -eu
DIR=/data/local/tmp/sbo-full
RUN=$DIR/run
PROD=/data/adb/services/sing-box
# Creation hook module. sbo_identity (kernel/sbo_identity) since the v3
# collector; earlier runs used sbo_identity_bridge with target_tgid=0.
BRIDGE=${SBO_MODULE:-sbo_identity}
fail() { echo "ERROR: $*" >&2; exit 1; }
ticks() { sed 's/^.*) //' "/proc/$1/stat" | awk '{print $20}'; }
mkdir -p "$RUN"

hooks() {
  case "$1" in
  none|old|new) ;;
  *) fail "hook state none|old|new" ;;
  esac
  # Remove the creator collector before its bridge can unload.
  if [ -d /sys/fs/bpf/sing-box/socket-creator-v3 ] && [ -n "$(ls -A /sys/fs/bpf/sing-box/socket-creator-v3 2>/dev/null)" ]; then
    "$DIR/sing-box-new" tools socket-creator-remove
  fi
  if [ -e /sys/module/$BRIDGE ]; then
    echo 0 > /sys/module/$BRIDGE/parameters/capture_all
    rmmod $BRIDGE
  fi
  [ ! -e /sys/module/sb_sockowner_probe ] || rmmod sb_sockowner_probe
  case "$1" in
  old) insmod /data/local/tmp/sb_sockowner_probe.ko ;;
  new)
    [ "$(sha256sum /sys/kernel/btf/vmlinux | awk '{print $1}')" = "$(awk '{print $1}' "$DIR/base-btf.sha256")" ] || fail 'kernel BTF differs from bridge build base'
    insmod "$DIR/$BRIDGE.ko" capture_all=1
    ;;
  esac
  echo "HOOKS=$1 modules=$(awk '{print $1}' /proc/modules | grep -E 'sbo_|sb_sock' | tr '\n' ' ')"
}

case "${1:-}" in
stop-prod)
  pid=$(pidof sing-box) || fail 'no production sing-box running'
  [ ! -f "$DIR/prod.cmdline" ] || fail 'production already recorded as stopped'
  tr '\0' '\n' < /proc/$pid/cmdline > "$DIR/prod.cmdline"
  [ "$(head -1 "$DIR/prod.cmdline")" = "$PROD/sing-box" ] || fail 'unexpected production command line'
  echo "$pid $(ticks "$pid")" > "$DIR/prod.pid"
  kill "$pid"
  for i in $(seq 1 50); do [ -d /proc/$pid ] || break; sleep 0.1; done
  [ ! -d /proc/$pid ] || fail 'production did not stop'
  svc power stayon usb
  echo "PRODUCTION_STOPPED pid=$pid"
  ;;
accuracy)
  seconds=${2:-150}
  [ -z "$(pidof sing-box sing-box-new sing-box-old)" ] || fail 'a sing-box is running'
  hooks new
  rm -f "$RUN/accuracy.log"
  "$DIR/sing-box-new" check -D "$RUN" -c "$DIR/config-accuracy.json"
  cd "$RUN"
  nohup "$DIR/sing-box-new" run -D "$RUN" -c "$DIR/config-accuracy.json" > "$RUN/stdout.log" 2>&1 &
  test_pid=$!
  sleep 4
  [ -d /proc/$test_pid ] || { cat "$RUN/stdout.log"; fail 'test instance did not start'; }
  echo "TEST_INSTANCE pid=$test_pid"
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
  sleep 5
  input keyevent KEYCODE_HOME
  elapsed=$((4 * 12 + 5))
  while [ "$elapsed" -lt "$seconds" ]; do sleep 10; snapshot; elapsed=$((elapsed + 10)); done
  snapshot
  kill "$test_pid"
  for i in $(seq 1 50); do [ -d /proc/$test_pid ] || break; sleep 0.1; done
  echo "ACCURACY_RUN_DONE log=$RUN/accuracy.log snapshots=$(ls $RUN/dumpsys-*.txt | wc -l)"
  ;;
sockbench)
  [ -z "$(pidof sing-box sing-box-new sing-box-old)" ] || fail 'stop sing-box instances first (collector pins must be removable)'
  for state in none old new none old new; do
    hooks $state > /dev/null
    "$DIR/creator-v2-probe" sockbench -n 20000 -rounds 5 -label "$state"
  done
  hooks none
  ;;
hooks)
  hooks "${2:-}"
  ;;
restore)
  [ -z "$(pidof sing-box sing-box-new sing-box-old)" ] || fail 'stop the test instance first'
  hooks none
  [ -f "$DIR/prod.cmdline" ] || fail 'no recorded production command line'
  cd "$PROD"
  # Exactly the recorded argv, detached like the original (setsid, ppid 1).
  set -- $(cat "$DIR/prod.cmdline")
  setsid nohup "$@" > /dev/null 2>&1 &
  sleep 4
  pid=$(pidof sing-box) || fail 'production did not restart'
  tr '\0' ' ' < /proc/$pid/cmdline; echo
  tr '\0' '\n' < /proc/$pid/cmdline | cmp - "$DIR/prod.cmdline" && echo COMMAND_LINE_IDENTICAL
  mv "$DIR/prod.cmdline" "$DIR/prod.cmdline.restored"
  svc power stayon false
  echo "PRODUCTION_RESTORED pid=$pid"
  ;;
*) fail "usage: $0 stop-prod|accuracy [seconds]|sockbench|hooks none|old|new|restore" ;;
esac
