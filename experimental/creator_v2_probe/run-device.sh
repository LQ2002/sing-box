#!/system/bin/sh
# Device entry point for creator_v2_probe. Run as root from $DIR.
#   run-device.sh capture <seconds>   load bridge, capture v2 reads, unload
#   run-device.sh netd                TC + netd map inside a private netns
#   run-device.sh procs               argv[0] vs dumpsys activity processes
# The production sing-box process is only observed (PID + start ticks before
# and after); its binary, config and modules are never touched. The bridge
# module is loaded only if absent and is removed again by this script.
set -eu
DIR=/data/local/tmp/sbo-creator-v2-probe
cd "$DIR"
mode=${1:-}
fail() { echo "ERROR: $*" >&2; exit 1; }
start_ticks() { sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}'; }
[ "$(id -u)" = 0 ] || fail 'run as root'
prod=$(pidof sing-box || true)
prod_ticks=
[ -n "$prod" ] && prod_ticks=$(start_ticks "$prod")
echo "PRODUCTION sing-box pid=${prod:-none} start_ticks=${prod_ticks:-none} context=$(cat /proc/${prod:-self}/attr/current 2>/dev/null | tr -d '\0')"
check_production() {
  if [ -n "$prod" ]; then
    [ "$(start_ticks "$prod")" = "$prod_ticks" ] && echo "PRODUCTION_UNCHANGED pid=$prod" || echo "PRODUCTION_CHANGED" >&2
  fi
}

case "$mode" in
capture)
  seconds=${2:-120}
  [ ! -e /sys/module/sbo_identity_bridge ] || fail 'bridge already loaded; refusing to take it over'
  [ "$(sha256sum /sys/kernel/btf/vmlinux | awk '{print $1}')" = "$(awk '{print $1}' base-btf.sha256)" ] || fail 'kernel BTF differs from module build base'
  insmod ./sbo_identity_bridge.ko target_tgid=0 capture_all=0
  cleanup() {
    echo 0 > /sys/module/sbo_identity_bridge/parameters/capture_all 2>/dev/null || true
    [ -n "${probe_pid:-}" ] && kill "$probe_pid" 2>/dev/null && wait "$probe_pid" 2>/dev/null || true
    for attempt in 1 2 3; do rmmod sbo_identity_bridge 2>/dev/null && break; sleep 1; done
    [ -e /sys/module/sbo_identity_bridge ] && echo 'BRIDGE_STILL_LOADED' >&2 || echo 'BRIDGE_REMOVED'
    check_production
  }
  trap cleanup EXIT
  ./creator-v2-probe capture -object ./argv.bpf.o -duration "${seconds}s" -out capture.jsonl > capture.log 2>&1 &
  probe_pid=$!
  for i in $(seq 1 50); do grep -q '^CAPTURING' capture.log && break; grep -q 'ERROR' capture.log && break; sleep 0.2; done
  grep -q '^CAPTURING' capture.log || { cat capture.log; fail 'probe did not attach'; }
  echo 1 > /sys/module/sbo_identity_bridge/parameters/capture_all
  echo "CAPTURE_ALL_ON for ${seconds}s"
  wait "$probe_pid" || true
  probe_pid=
  echo 0 > /sys/module/sbo_identity_bridge/parameters/capture_all
  cat capture.log
  ;;
netd)
  unshare -n ./creator-v2-probe netd -object ./netdtag.bpf.o
  dmesg 2>/dev/null | grep -i 'avc.*bpf' | tail -5 || true
  logcat -d -b events,main 2>/dev/null | grep -i 'avc.*denied.*bpf' | tail -5 || true
  check_production
  ;;
procs)
  dumpsys activity processes > processes.txt
  ./creator-v2-probe procs -dumpsys processes.txt -out procs.jsonl
  check_production
  ;;
*) fail "usage: $0 capture <seconds>|netd|procs" ;;
esac
