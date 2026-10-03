#!/system/bin/sh
# Pinned, finely interleaved socket()+close() comparison (cpu 3, 3 cycles).
DIR=/data/local/tmp/sbo-full
for cycle in 1 2 3; do
  for state in none old new; do
    sh $DIR/fullservice.sh hooks $state > /dev/null
    sleep 2
    taskset 08 $DIR/creator-v2-probe sockbench -n 20000 -rounds 5 -label "$state/c$cycle" | sed 's/ all=.*//'
  done
done
sh $DIR/fullservice.sh hooks none
