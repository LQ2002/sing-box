#!/system/bin/sh
# Unattended run while the phone is disconnected from adb. Start with
#   su -mm -c 'setsid nohup sh /data/local/tmp/sboacc/offline.sh >/dev/null 2>&1 < /dev/null &'
# Phases run one after another; a failing phase is recorded and the next one
# still runs. Everything lands in $DIR/report; REPORT.txt is the summary.
DIR=/data/local/tmp/sboacc
OUT=$DIR/report
mkdir -p "$OUT"
cd "$DIR"
log() { echo "$(date '+%F %T') $*" >> "$OUT/REPORT.txt"; }
log "OFFLINE_START taint=$(cat /proc/sys/kernel/tainted)"

# quick includes the selftests (normal, >256-byte path, deleted exe, and the
# BPF_F_CLONE accept inheritance test). Hold a wakelock so it is not
# suspended halfway.
echo sboacc_quick > /sys/power/wake_lock
sh run-device.sh quick > "$OUT/quick.log" 2>&1; rc=$?
echo sboacc_quick > /sys/power/wake_unlock
cp -f watch-quick.json "$OUT/" 2>/dev/null
log "PHASE quick rc=$rc $(grep -c SELFTEST_PASS "$OUT/quick.log") selftests passed; $(grep -E '^SELFTEST kind=accept' "$OUT/quick.log")"

sh run-device.sh bench > "$OUT/bench.log" 2>&1; rc=$?
log "PHASE bench rc=$rc"
grep -E '^BENCH' "$OUT/bench.log" >> "$OUT/REPORT.txt"

# Long run: no wakelock, the phone is used (or idle) normally.
sh run-device.sh long 3600 > "$OUT/long.log" 2>&1; rc=$?
cp -f watch-long.json "$OUT/" 2>/dev/null
log "PHASE long rc=$rc"
grep -E '^(WATCH_DONE|STATS_BEFORE_UNLOAD|DMESG_CLEAN|ERROR)' "$OUT/long.log" >> "$OUT/REPORT.txt"
grep 'file_ref check' "$OUT/long.log" | tail -1 >> "$OUT/REPORT.txt"

log "OFFLINE_DONE taint=$(cat /proc/sys/kernel/tainted) module_loaded=$([ -e /sys/module/sbo_enhancement_probe ] && echo yes || echo no)"
