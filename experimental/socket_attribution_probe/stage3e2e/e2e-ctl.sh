#!/system/bin/sh
# Start/stop the stage 3 test instance. Usage: e2e-ctl.sh start|stop|status
DST=/data/local/tmp/sbe2/e2e
case "$1" in
start)
  if pidof sing-box >/dev/null; then echo "a sing-box is already running: $(pidof sing-box)"; exit 1; fi
  rm -f $DST/e2e.log
  cd $DST
  nohup ./sing-box run -D $DST -c $DST/config.json >$DST/stdout.log 2>&1 &
  sleep 3
  echo "pid=$(pidof sing-box)"
  grep -E "eBPF|ebpf|started|FATAL|ERROR|socket owner|tracking" $DST/e2e.log | head -30
  ;;
stop)
  P=$(pidof sing-box)
  [ -n "$P" ] && kill $P
  sleep 2
  echo "after stop: $(pidof sing-box)"
  ;;
status)
  echo "pid=$(pidof sing-box)"
  ;;
esac
