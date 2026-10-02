# Measure how long a per-process cgroup v2 dir outlives its process.
pkg=com.miui.calculator
for mode in forcestop kill9; do
  am start -n $(cmd package resolve-activity --brief $pkg | tail -1) >/dev/null 2>&1
  sleep 3
  pid=$(pidof $pkg)
  cg=/sys/fs/cgroup$(tail -1 /proc/$pid/cgroup | cut -d: -f3)
  ino=$(stat -c %i $cg)
  t0=$(date +%s%N)
  if [ $mode = forcestop ]; then am force-stop $pkg; else kill -9 $pid; fi
  pgone=""; cgone=""
  for i in $(seq 1 1000); do
    now=$(date +%s%N)
    [ -z "$pgone" ] && [ ! -d /proc/$pid ] && pgone=$(( (now - t0) / 1000000 ))
    [ -z "$cgone" ] && [ ! -d $cg ] && cgone=$(( (now - t0) / 1000000 ))
    [ -n "$pgone" ] && [ -n "$cgone" ] && break
    sleep 0.01
  done
  echo "$mode pid=$pid cg=$cg cgid=$ino process_gone_ms=$pgone cgroup_gone_ms=${cgone:-still_present}"
done
