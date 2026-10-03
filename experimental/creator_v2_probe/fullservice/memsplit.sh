#!/system/bin/sh
# Which part of the new build's RSS is attribution: same binary, three configs.
#   creator  = socket_creator (bridge + v2 producer), package rule
#   module   = old sb_sockowner module source, package rule
#   noattr   = user_id rule only: no process attribution, no manifest index
DIR=/data/local/tmp/sbe3-fix
FULL=/data/local/tmp/sbo-full
rss() { awk '/VmRSS/{print $2}' "/proc/$1/status"; }
for cycle in 1 2; do
  for variant in creator:new:perf-new.json module:old:perf-old.json noattr:none:perf-noattr.json; do
    name=${variant%%:*}; rest=${variant#*:}; hooks=${rest%%:*}; config=${rest#*:}
    sh $FULL/fullservice.sh hooks $hooks > /dev/null
    sh $DIR/isolated-netns.sh start $FULL/sing-box-new $DIR/$config > /dev/null
    read pid ticks < $DIR/singbox.pid
    sleep 5; r5=$(rss $pid)
    sleep 15; r20=$(rss $pid)
    sh $DIR/isolated-netns.sh load -uid 1000 -argv0 com.miui.securitycenter.remote -conns 1000 -bytes 65536 -label mem > /dev/null
    sleep 5; rl=$(rss $pid)
    sleep 30; r60=$(rss $pid)
    echo "MEMSPLIT cycle=$cycle config=$name rss_kb_5s=$r5 rss_kb_20s=$r20 rss_kb_after_load=$rl rss_kb_60s=$r60 cpu_ticks=$(awk '{print $14+$15}' /proc/$pid/stat)"
    sh $DIR/isolated-netns.sh stop > /dev/null
  done
done
sh $FULL/fullservice.sh hooks none
