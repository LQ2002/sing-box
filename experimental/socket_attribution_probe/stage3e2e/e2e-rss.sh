#!/system/bin/sh
# RSS over time after start, old vs new, same config.
DIR=/data/local/tmp/sbe2
cp $DIR/e2e-config-perf.json $DIR/e2e/config.json
for build in old new; do
  sh $DIR/e2e-ctl.sh stop >/dev/null
  cp $DIR/sing-box-$build $DIR/e2e/sing-box
  sh $DIR/e2e-ctl.sh start >/dev/null
  SB=$(pidof sing-box)
  line="build=$build"
  for t in 5 30 90; do
    while [ $(cut -d. -f1 /proc/uptime) -lt 0 ]; do :; done
    sleep $([ $t = 5 ] && echo 5 || ([ $t = 30 ] && echo 25 || echo 60))
    line="$line rss_${t}s=$(awk '/VmRSS/{print $2}' /proc/$SB/status) anon_${t}s=$(awk '/RssAnon/{print $2}' /proc/$SB/status)"
  done
  echo "$line"
done
sh $DIR/e2e-ctl.sh stop >/dev/null
