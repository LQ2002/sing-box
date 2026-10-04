#!/system/bin/sh
# In-kernel per-socket cost, measured by the module itself (parameter
# `timing`): time from the hook's entry to its return, which includes the
# BPF consumer the tracepoint runs synchronously. This is the extra cost a
# socket pays, without the userspace socket()+close() noise that swamped the
# wall-clock bench on this phone (rounds spread over 5.5-12 us).
#
# Variants, each on a freshly loaded module (counters start at zero):
#   none  collection active, no BPF program attached (module alone)
#   v1    first consumer: 320-byte snapshot with the path copied per socket
#   v2    current consumer: 64-byte snapshot + per-executable path table
#   v3    experiment: preallocated HASH keyed by socket cookie, 64-byte value
#         (no kmalloc/memcg per socket; deletion on free not implemented)
#   v4    the production BPF producer (creator.bpf.c: reads argv and the
#         mm->exe_file->f_inode chain itself) on this tracepoint
#   v0    control consumer: same attachment, only bumps a counter (cost of
#         running a BPF program, without creating sk_storage)
# Usage: timing.sh [variants] [rounds] [idle seconds], default "none v1 v2" 2 30
# Workload per variant: the pinned UDP socket()+close() loop (native process,
# path-cache hit) plus 30 s of whatever the phone does (app sockets).
set -eu
DIR=/data/local/tmp/sboacc
cd "$DIR"
KO=$DIR/sbo_enhancement_probe.ko
DEV=/dev/sbo_enhancement_probe
P=/sys/module/sbo_enhancement_probe/parameters
POL=/sys/devices/system/cpu/cpufreq/policy0
[ ! -e /sys/module/sbo_enhancement_probe ] || { echo 'module already loaded'; exit 1; }
MIN=$(cat $POL/scaling_min_freq); MAX=$(cat $POL/scaling_max_freq)
HOLD=
restore() {
  [ -n "$HOLD" ] && kill "$HOLD" 2>/dev/null || true
  rmmod sbo_enhancement_probe 2>/dev/null || true
  echo "$MIN" > $POL/scaling_min_freq 2>/dev/null || true
  echo sboacc_timing > /sys/power/wake_unlock 2>/dev/null || true
  echo "RESTORED min=$(cat $POL/scaling_min_freq) governor=$(cat $POL/scaling_governor) module=$([ -e /sys/module/sbo_enhancement_probe ] && echo loaded || echo unloaded)"
}
trap restore EXIT
echo sboacc_timing > /sys/power/wake_lock
echo "$MAX" > $POL/scaling_min_freq

VARIANTS=${1:-none v1 v2}
ROUNDS=${2:-2}
IDLE=${3:-30}
for round in $(seq 1 "$ROUNDS"); do
  for variant in $VARIANTS; do
    insmod "$KO"
    for i in 1 2 3 4 5 6 7 8 9 10; do [ -c $DEV ] && break; sleep 0.1; done
    echo 1 > $P/timing
    case $variant in
      # sleep itself holds the descriptor, so $! is the holder (a subshell
      # here left its sleep child holding the device after being killed).
      none) sleep 3600 3<"$DEV" & HOLD=$! ;;
      v0) ./sbo-acceptance hold -object consumer_v0.bpf.o -duration 3600s > hold.log 2>&1 & HOLD=$! ;;
      v3) ./sbo-acceptance hold -object consumer_v3.bpf.o -duration 3600s > hold.log 2>&1 & HOLD=$! ;;
      v4) ./sbo-acceptance hold -object consumer_v4.bpf.o -duration 3600s > hold.log 2>&1 & HOLD=$! ;;
      v1) ./sbo-acceptance hold -object consumer_v1.bpf.o -duration 3600s > hold.log 2>&1 & HOLD=$! ;;
      v2) ./sbo-acceptance hold -object consumer.bpf.o -duration 3600s > hold.log 2>&1 & HOLD=$! ;;
    esac
    sleep 1
    taskset 10 ./sbo-acceptance bench -n 20000 -rounds 5 -label "$variant" > /dev/null
    sleep "$IDLE"
    echo "TIMING round=$round variant=$variant $(cat $P/stats | tr ' ' '\n' | grep -E '^t_|^inet=|^hit=|^app=|^miss=' | tr '\n' ' ')"
    kill "$HOLD"; wait "$HOLD" 2>/dev/null || true; HOLD=
    rmmod sbo_enhancement_probe
  done
done
