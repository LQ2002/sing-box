#!/system/bin/sh
# Paired stage 3 performance check: old (pre-stage-3) and new builds,
# alternated, the user's config (log redirected), same workload.
# Usage: e2e-perf.sh <rounds> <connections> [connect|echo] [target] [bytes]
# Echo needs a controlled stage3load -listen server and an intercepted target.
# Connect measures local acceptance only. Echo measures verified round trips
# and sequential goodput, not maximum forwarding capacity.
# Output: /data/local/tmp/sbe2/perf.txt
DIR=/data/local/tmp/sbe2
OUT=$DIR/perf.txt
ROUNDS=${1:-5}
CONNS=${2:-1000}
MODE=${3:-connect}
TARGET=${4:-}
BYTES=${5:-65536}
case "$MODE" in
  connect) TARGET=${TARGET:-223.5.5.5:443} ;;
  echo) [ -n "$TARGET" ] || { echo "echo mode requires an explicit controlled target"; exit 2; } ;;
  *) echo "mode must be connect or echo"; exit 2 ;;
esac
APP_UID=$(pm list packages -U com.android.chrome | sed -n 's/^package:com.android.chrome uid://p')
[ -n "$APP_UID" ] || { echo "Chrome UID unavailable"; exit 1; }
ticks() { awk '{print $14+$15}' /proc/$1/stat; }
rss() { awk '/VmRSS/{print $2}' /proc/$1/status; }
svc power stayon usb
input keyevent KEYCODE_WAKEUP
cp $DIR/e2e-config-perf.json $DIR/e2e/config.json
sha256sum $DIR/sing-box-old $DIR/sing-box-new $DIR/e2e/config.json > $OUT
echo "METRICS mode=$MODE target=$TARGET bytes_per_conn=$BYTES workload_uid=$APP_UID" >> $OUT
i=1
while [ $i -le $ROUNDS ]; do
  for build in old new; do
    sh $DIR/e2e-ctl.sh stop >/dev/null
    cp $DIR/sing-box-$build $DIR/e2e/sing-box
    chmod 755 $DIR/e2e/sing-box
    sh $DIR/e2e-ctl.sh start >/dev/null
    sleep 5
    SB=$(pidof sing-box)
    # Chrome in the foreground, so netd's background firewall chain does not
    # drop the workload, which runs with Chrome's UID.
    am start -a android.intent.action.VIEW -d https://www.bing.com -p com.android.chrome >/dev/null
    sleep 3
    CHROME=$(pidof com.android.chrome | cut -d' ' -f1)
    CG=/sys/fs/cgroup/apps/uid_$APP_UID/pid_$CHROME
    [ -f "$CG/cgroup.procs" ] || { echo "Chrome cgroup unavailable: $CG"; exit 1; }
    T0=$(ticks $SB); R0=$(rss $SB)
    RESULT=$($DIR/stage3load -cgroup "$CG" -uid "$APP_UID" -target "$TARGET" -conns "$CONNS" -mode "$MODE" -bytes "$BYTES" -label "round=$i build=$build" 2>&1)
    LOAD_STATUS=$?
    sleep 2
    T1=$(ticks $SB); R1=$(rss $SB)
    echo "$RESULT singbox_cpu_ticks=$((T1-T0)) rss_kb_before=$R0 rss_kb_after=$R1" >> $OUT
    tail -1 $OUT
    if [ "$LOAD_STATUS" -ne 0 ]; then
      echo "workload failed; this pair is not a successful performance sample" >> $OUT
      sh $DIR/e2e-ctl.sh stop >/dev/null
      svc power stayon false
      exit "$LOAD_STATUS"
    fi
  done
  i=$((i+1))
done
sh $DIR/e2e-ctl.sh stop >/dev/null
svc power stayon false
echo done
