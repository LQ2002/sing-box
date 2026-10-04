#!/system/bin/sh
# Production-chain checks of kernel/sbo_identity + the v3 producer + a test
# sing-box instance (config-accuracy.json: direct outbound only). Run as root
# in the global mount namespace from /data/local/tmp/sbo-full, which holds
# sing-box-new, sbo_identity.ko, creator.bpf.o, sbo-acceptance,
# config-accuracy.json and base-btf.sha256.
#
#   prod-longrun.sh long <seconds>   full service for <seconds>: app cold
#                                    starts, root-cgroup clients under a
#                                    >256-byte path and with an unlinked
#                                    executable, dumpsys truth every minute,
#                                    module stats / file-nr / RSS every 5 min,
#                                    the kernel log streamed to a file
#   prod-longrun.sh timing           in-kernel per-socket cost (module timing
#                                    parameter): own-cgroup skip vs snapshot
#
# The production sing-box service is never started or touched. The screen is
# never woken; it is sent to sleep at the end.
set -eu
DIR=/data/local/tmp/sbo-full
RUN=$DIR/run
MOD=sbo_identity
TOOL=$DIR/sbo-acceptance
fail() { echo "ERROR: $*" >&2; exit 1; }
mkdir -p "$RUN"
cd "$DIR"

[ "$(id -u)" = 0 ] || fail 'run as root'
[ "$(sha256sum /sys/kernel/btf/vmlinux | awk '{print $1}')" = "$(awk '{print $1}' base-btf.sha256)" ] || fail 'kernel BTF differs from the module build base'
[ ! -e /sys/module/$MOD ] || fail 'module already loaded'
[ -z "$(pidof sing-box sing-box-new 2>/dev/null)" ] || fail 'a sing-box is running'

KMSG=$RUN/kmsg-${1:-run}.txt
cat /dev/kmsg > "$KMSG" &
KMSG_PID=$!
MARK="SBO_PROD_MARK_$(date +%s)_$$"
sleep 0.5
echo "$MARK" > /dev/kmsg

SB=
cleanup() {
  [ -n "$SB" ] && kill "$SB" 2>/dev/null && sleep 1 || true
  if [ -n "$(ls -A /sys/fs/bpf/sing-box/socket-creator-v3 2>/dev/null)" ]; then
    "$DIR/sing-box-new" tools socket-creator-remove || true
  fi
  if [ -e /sys/module/$MOD ]; then
    echo 0 > /sys/module/$MOD/parameters/capture_all
    for i in 1 2 3; do rmmod $MOD 2>/dev/null && break; sleep 1; done
  fi
  kill "$KMSG_PID" 2>/dev/null || true
  input keyevent 223 2>/dev/null || true
}
trap cleanup EXIT

kernel_check() {
  sleep 1
  kill "$KMSG_PID" 2>/dev/null || true
  sed -n "/$MARK/,\$p" "$KMSG" > "$RUN/kmsg-since-mark.txt"
  lines=$(wc -l < "$RUN/kmsg-since-mark.txt")
  echo "KERNEL_LOG captured=$(wc -l < "$KMSG") since_mark=$lines"
  [ "$lines" -gt 1 ] || fail 'kernel log capture lost the marker'
  splats=$(grep -cE 'WARNING: CPU|BUG:|Oops|Unable to handle|Kernel panic|refcount_t:|use-after-free|KASAN' "$RUN/kmsg-since-mark.txt" || true)
  ours=$(grep -c "\[$MOD" "$RUN/kmsg-since-mark.txt" || true)
  echo "KERNEL_SPLATS total=$splats in_module_frames=$ours"
  grep -E 'WARNING: CPU|BUG:|Oops|Unable to handle|Kernel panic' "$RUN/kmsg-since-mark.txt" | cut -d';' -f2- | head -5
  grep "$MOD: file_ref" "$RUN/kmsg-since-mark.txt" | cut -d';' -f2- | tail -1
  [ "$ours" = 0 ] || fail 'a kernel report has frames in the module'
  echo "TAINT $(cat /proc/sys/kernel/tainted)"
}

snapshot() { dumpsys activity processes > "$RUN/dumpsys-$(date +%s).txt" 2>/dev/null || true; }
rss() { awk '/VmRSS/ {print $2 " kB"}' /proc/$1/status 2>/dev/null; }

case "${1:-}" in
long)
  seconds=${2:-3600}
  insmod "$DIR/$MOD.ko" capture_all=1
  rm -f "$RUN/accuracy.log" "$RUN"/dumpsys-*.txt
  "$DIR/sing-box-new" check -D "$RUN" -c "$DIR/config-accuracy.json"
  nohup "$DIR/sing-box-new" run -D "$RUN" -c "$DIR/config-accuracy.json" > "$RUN/stdout.log" 2>&1 &
  SB=$!
  sleep 4
  [ -d /proc/$SB ] || { cat "$RUN/stdout.log"; fail 'test instance did not start'; }
  echo "START $(date +%T) sing-box pid=$SB rss=$(rss $SB) file_nr=$(awk '{print $1}' /proc/sys/fs/file-nr)"
  snapshot
  # Cold starts with the screen left as it is (not woken).
  for package in com.android.chrome com.tencent.mm com.miui.securitycenter tv.danmaku.bili; do
    am force-stop $package
    monkey -p $package -c android.intent.category.LAUNCHER 1 > /dev/null 2>&1 || true
    sleep 10
    snapshot
  done
  input keyevent 223 2>/dev/null || true
  # Root-cgroup clients through the test instance.
  "$TOOL" dial -addr 1.1.1.1:80 -count 2
  LONG=$DIR/L
  for i in 1 2 3 4 5 6 7 8; do LONG=$LONG/dir_$i-0123456789abcdef0123456789; done
  mkdir -p "$LONG"
  cp "$TOOL" "$LONG/sbo-dial"
  "$LONG/sbo-dial" dial -addr 1.1.1.1:80 -count 2
  rm -rf "$DIR/L"
  cp "$TOOL" "$DIR/sbo-dial-deleted"
  "$DIR/sbo-dial-deleted" dial -addr 1.0.0.1:80 -count 2 -wait-signal > "$RUN/dial-deleted.log" 2>&1 &
  DPID=$!
  for i in $(seq 1 50); do grep -q DIAL_WAITING "$RUN/dial-deleted.log" && break; sleep 0.1; done
  rm -f "$DIR/sbo-dial-deleted"
  kill -USR1 "$DPID"
  wait "$DPID" || true
  cat "$RUN/dial-deleted.log"
  echo "SCENARIOS_DONE $(cat /sys/module/$MOD/parameters/stats)"
  elapsed=60
  while [ "$elapsed" -lt "$seconds" ]; do
    sleep 60
    elapsed=$((elapsed + 60))
    snapshot
    [ -d /proc/$SB ] || fail 'test instance exited'
    if [ $((elapsed % 300)) = 0 ]; then
      echo "PROGRESS $(date +%T) t=${elapsed}s rss=$(rss $SB) file_nr=$(awk '{print $1}' /proc/sys/fs/file-nr) kmsg_lines=$(wc -l < "$KMSG") module=$(cat /sys/module/$MOD/parameters/stats)"
    fi
  done
  echo "END $(date +%T) rss=$(rss $SB) module=$(cat /sys/module/$MOD/parameters/stats)"
  kill "$SB"; sleep 1; SB=
  "$DIR/sing-box-new" tools socket-creator-remove
  echo 0 > /sys/module/$MOD/parameters/capture_all
  rmmod $MOD
  kernel_check
  ;;
timing)
  POL=/sys/devices/system/cpu/cpufreq/policy0
  MIN=$(cat $POL/scaling_min_freq); MAX=$(cat $POL/scaling_max_freq)
  echo sbo_prod_timing > /sys/power/wake_lock
  echo "$MAX" > $POL/scaling_min_freq
  restore_freq() { echo "$MIN" > $POL/scaling_min_freq; echo sbo_prod_timing > /sys/power/wake_unlock; }
  for round in 1 2 3; do
    insmod "$DIR/$MOD.ko" capture_all=1 timing=1
    "$TOOL" prodhold -object "$DIR/creator.bpf.o" -duration 600s > "$RUN/prodhold.log" 2>&1 &
    HOLD=$!
    for i in $(seq 1 50); do grep -q PRODHOLDING "$RUN/prodhold.log" && break; sleep 0.1; done
    taskset 10 "$TOOL" bench -n 20000 -rounds 5 -label snapshot > /dev/null
    taskset 10 "$TOOL" ownbench -n 20000 -rounds 5 > /dev/null
    echo "TIMING round=$round $(tr ' ' '\n' < /sys/module/$MOD/parameters/stats | grep -E '^t_|^own_cgroup=|^hit=|^miss=' | tr '\n' ' ')"
    kill "$HOLD"; wait "$HOLD" 2>/dev/null || true
    echo 0 > /sys/module/$MOD/parameters/capture_all
    rmmod $MOD
  done
  restore_freq
  kernel_check
  ;;
*) fail 'usage: prod-longrun.sh long <seconds> | timing' ;;
esac
