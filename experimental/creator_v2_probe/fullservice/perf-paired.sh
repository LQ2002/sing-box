#!/system/bin/sh
# Paired old/new forwarding through the isolated namespaces of
# stage3e2e/isolated-netns.sh, each variant with its own kernel hooks:
#   old = 7c12b1de + sb_sockowner_probe module (cookie -> creator via ioctl)
#   new = HEAD + sbo_identity_bridge + creator v2 producer (TC snapshot)
# The workload runs as UID 1000 with argv[0] com.miui.securitycenter.remote,
# a name declared by exactly one package of UID 1000, and the config routes
# by package_name, so every connection asks for attribution.
# Usage: perf-paired.sh [rounds=5] [conns=1000] [bytes=65536] [settle_seconds=0]
# settle_seconds waits after start, so start-up work (package table, manifest
# index prewarm) is measured separately (settle_cpu_ticks/rss) from the load.
set -eu
DIR=/data/local/tmp/sbe3-fix
FULL=/data/local/tmp/sbo-full
CTL=$DIR/isolated-netns.sh
ROUNDS=${1:-5}
CONNS=${2:-1000}
BYTES=${3:-65536}
SETTLE=${4:-0}
OUT=$DIR/perf-paired.txt
cpu() { awk '{print $14+$15}' "/proc/$1/stat"; }
rss() { awk '/VmRSS/{print $2}' "/proc/$1/status"; }
sha256sum $FULL/sing-box-old $FULL/sing-box-new $DIR/perf-old.json $DIR/perf-new.json $DIR/stage3load > "$OUT"
echo "WORKLOAD uid=1000 argv0=com.miui.securitycenter.remote conns=$CONNS bytes=$BYTES rounds=$ROUNDS settle=$SETTLE" >> "$OUT"
i=1
while [ "$i" -le "$ROUNDS" ]; do
  order="old new"
  [ $((i%2)) -ne 0 ] || order="new old"
  for variant in $order; do
    sh $FULL/fullservice.sh hooks $variant >> "$OUT"
    sh "$CTL" start "$FULL/sing-box-$variant" "$DIR/perf-$variant.json" >> "$OUT"
    read task_pid task_ticks < "$DIR/singbox.pid"
    s0=$(cpu "$task_pid")
    sleep "$SETTLE"
    t0=$(cpu "$task_pid"); r0=$(rss "$task_pid")
    if result=$(sh "$CTL" load -uid 1000 -argv0 com.miui.securitycenter.remote -conns "$CONNS" -bytes "$BYTES" -label "round=$i,build=$variant"); then
      t1=$(cpu "$task_pid"); r1=$(rss "$task_pid")
      echo "$result singbox_cpu_ticks=$((t1-t0)) rss_kb_before=$r0 rss_kb_after=$r1 settle_cpu_ticks=$((t0-s0)) startup_cpu_ticks=$s0" | tee -a "$OUT"
    else
      echo "$result" | tee -a "$OUT"
      echo "PAIR_FAILED round=$i build=$variant" | tee -a "$OUT"
      sh "$CTL" stop >> "$OUT"
      sh $FULL/fullservice.sh hooks none >> "$OUT"
      exit 1
    fi
    sh "$CTL" stop >> "$OUT"
  done
  i=$((i+1))
done
sh $FULL/fullservice.sh hooks none >> "$OUT"
echo "PAIRED_FORWARDING_COMPLETE" | tee -a "$OUT"
