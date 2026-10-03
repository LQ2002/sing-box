#!/system/bin/sh
# Five paired payload-forwarding workloads in an existing isolated topology.
# Does not manage or stop any sing-box outside isolated-netns.sh's own PID file.
# Usage: isolated-perf.sh <old-binary> <new-binary> [rounds=5] [conns=1000] [bytes=65536]
set -eu
DIR=/data/local/tmp/sbe3-fix
CTL=$DIR/isolated-netns.sh
OLD=$1
NEW=$2
ROUNDS=${3:-5}
CONNS=${4:-1000}
BYTES=${5:-65536}
OUT=$DIR/isolated-perf.txt
cpu() { awk '{print $14+$15}' "/proc/$1/stat"; }
rss() { awk '/VmRSS/{print $2}' "/proc/$1/status"; }
sh "$CTL" stop
sha256sum "$OLD" "$NEW" "$DIR/isolated-perf-config.json" "$DIR/stage3load" > "$OUT"
echo "WORKLOAD controlled_private_veth_echo uid=9050 conns=$CONNS bytes_per_conn=$BYTES rounds=$ROUNDS" >> "$OUT"
i=1
while [ "$i" -le "$ROUNDS" ]; do
  order="old new"
  [ $((i%2)) -ne 0 ] || order="new old"
  for variant in $order; do
    binary=$OLD
    [ "$variant" != new ] || binary=$NEW
    sh "$CTL" start "$binary" "$DIR/isolated-perf-config.json" >> "$OUT"
    read task_pid task_ticks < "$DIR/singbox.pid"
    t0=$(cpu "$task_pid"); r0=$(rss "$task_pid")
    if result=$(sh "$CTL" load -uid 9050 -conns "$CONNS" -bytes "$BYTES" -label "round=$i,build=$variant"); then
      t1=$(cpu "$task_pid"); r1=$(rss "$task_pid")
      echo "$result singbox_cpu_ticks=$((t1-t0)) rss_kb_before=$r0 rss_kb_after=$r1" | tee -a "$OUT"
    else
      echo "$result" | tee -a "$OUT"
      echo "PAIR_FAILED round=$i build=$variant; stop and investigate" | tee -a "$OUT"
      sh "$CTL" stop >> "$OUT"
      exit 1
    fi
    sh "$CTL" stop >> "$OUT"
  done
  i=$((i+1))
done
echo "PAIRED_FORWARDING_COMPLETE" | tee -a "$OUT"
