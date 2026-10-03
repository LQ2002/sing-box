#!/system/bin/sh
# Dedicated device namespaces only. Never stops a system/user sing-box.
# Push stage3load and this script to /data/local/tmp/sbe3-fix before setup.
# Usage: setup <protected-user-sing-box-pid> | baseline [uid] | start <binary> <config>
#        start-unavailable <binary> <config> (private read-only module device mask)
#        load [stage3load arguments...] | stop | status | cleanup
set -eu
DIR=/data/local/tmp/sbe3-fix
ticks() { awk '{print $22}' "/proc/$1/stat" 2>/dev/null; }
netns() { ls -l "/proc/$1/ns/net" | awk '{print $NF}'; }
record() { printf '%s %s\n' "$2" "$(ticks "$2")" > "$DIR/$1.pid"; }
owned_pid() {
  read task_pid task_ticks < "$DIR/$1.pid"
  [ "$task_pid" -gt 2 ] && [ -r "/proc/$task_pid/stat" ] && [ "$(ticks "$task_pid")" = "$task_ticks" ] || {
    echo "process missing or reused: $1" >&2; return 1;
  }
  if [ "$1" != protected ]; then
    read protected_pid protected_ticks < "$DIR/protected.pid"
    [ "$task_pid" != "$protected_pid" ] || { echo "refusing protected PID" >&2; return 1; }
  fi
  echo "$task_pid"
}
stop_owned() {
  [ -f "$DIR/$1.pid" ] || return 0
  read task_pid task_ticks < "$DIR/$1.pid"
  if [ ! -r "/proc/$task_pid/stat" ]; then
    rm "$DIR/$1.pid"
    return 0
  fi
  task_pid=$(owned_pid "$1") || return 1
  kill -TERM "$task_pid"
  count=0
  while [ -r "/proc/$task_pid/stat" ] && [ "$(ticks "$task_pid")" = "$(awk '{print $2}' "$DIR/$1.pid")" ] && [ "$count" -lt 50 ]; do
    [ "$(awk '{print $3}' "/proc/$task_pid/stat")" != Z ] || break
    sleep 0.1; count=$((count+1))
  done
  if [ "$count" -ge 50 ]; then
    task_pid=$(owned_pid "$1")
    kill -KILL "$task_pid"
  fi
  rm "$DIR/$1.pid"
}
protected_ok() {
  task_pid=$(owned_pid protected)
  [ "$(netns "$task_pid")" = "$(cat "$DIR/protected.netns")" ]
  echo "PROTECTED_PROCESS_UNCHANGED pid=$task_pid start_ticks=$(ticks "$task_pid")"
}
client() { nsenter -t "$(owned_pid client)" -n -- "$@"; }
case "${1:-}" in
setup)
  [ "$#" = 2 ] || { echo "setup requires protected service PID"; exit 2; }
  mkdir -p "$DIR"
  [ ! -e "$DIR/client.pid" ] && [ ! -e "$DIR/peer.pid" ] && [ ! -e "$DIR/singbox.pid" ] || { echo "existing namespace state; inspect/cleanup first"; exit 1; }
  [ -x "$DIR/stage3load" ]
  record protected "$2"
  netns "$2" > "$DIR/protected.netns"
  ip -4 route show table all > "$DIR/original-ipv4-routes.txt"
  ip -o link show > "$DIR/original-links.txt"
  cat "/proc/$2/cmdline" > "$DIR/protected.cmdline"
  nohup unshare -n sleep 86400 > "$DIR/client-holder.log" 2>&1 &
  record client "$!"
  nohup unshare -n sleep 86400 > "$DIR/peer-holder.log" 2>&1 &
  record peer "$!"
  sleep 0.2
  client_pid=$(owned_pid client); peer_pid=$(owned_pid peer)
  [ "$(netns "$client_pid")" != "$(cat "$DIR/protected.netns")" ]
  [ "$(netns "$peer_pid")" != "$(cat "$DIR/protected.netns")" ]
  [ "$(netns "$client_pid")" != "$(netns "$peer_pid")" ]
  client ip link set lo up
  client ip link add e3client type veth peer name e3peer
  client ip link set e3peer netns "$peer_pid"
  client ip address add 10.211.0.1/24 dev e3client
  client ip link set e3client up
  client ip route add default via 10.211.0.2 dev e3client
  # sing-tun's Android monitor discovers the default table through a 0xffff
  # fwmark-mask rule. This private rule leaves TC's priority-8999 rule first.
  client ip rule add priority 12000 fwmark 0x0/0xffff lookup main
  nsenter -t "$peer_pid" -n -- ip link set lo up
  nsenter -t "$peer_pid" -n -- ip address add 10.211.0.2/24 dev e3peer
  nsenter -t "$peer_pid" -n -- ip link set e3peer up
  nohup nsenter -t "$peer_pid" -n -- "$DIR/stage3load" -listen 10.211.0.2:7000 -timeout 30s > "$DIR/echo.log" 2>&1 &
  record echo "$!"
  sleep 0.2
  owned_pid echo
  cat "$DIR/echo.log"
  echo "ISOLATED_NETNS_READY client_pid=$client_pid peer_pid=$peer_pid client=$(netns "$client_pid") peer=$(netns "$peer_pid")"
  protected_ok
  ;;
baseline)
  [ ! -f "$DIR/singbox.pid" ] || { echo "baseline requires test sing-box stopped"; exit 1; }
  client "$DIR/stage3load" -mode echo -target 10.211.0.2:7000 -uid "${2:-9050}" -conns 5 -bytes 65536 -timeout 3s -label no_singbox_baseline
  ;;
start|start-unavailable)
  [ "$#" = 3 ] || { echo "start requires binary and config paths"; exit 2; }
  [ ! -f "$DIR/singbox.pid" ] || { echo "test instance already recorded"; exit 1; }
  protected_ok
  cp "$2" "$DIR/sing-box-test"
  chmod 755 "$DIR/sing-box-test"
  mkdir -p "$DIR/runtime"
  client "$DIR/sing-box-test" check -D "$DIR/runtime" -c "$3"
  if [ "$1" = start-unavailable ]; then
    : > "$DIR/module-unavailable"
    nohup unshare -m -- /system/bin/sh "$DIR/module-unavailable-exec.sh" nsenter -t "$(owned_pid client)" -n -- "$DIR/sing-box-test" run -D "$DIR/runtime" -c "$3" > "$DIR/singbox-stdout.log" 2>&1 &
  else
    nohup nsenter -t "$(owned_pid client)" -n -- "$DIR/sing-box-test" run -D "$DIR/runtime" -c "$3" > "$DIR/singbox-stdout.log" 2>&1 &
  fi
  record singbox "$!"
  sleep 3
  task_pid=$(owned_pid singbox)
  [ "$(netns "$task_pid")" = "$(netns "$(owned_pid client)")" ]
  client bpftool net show dev e3client > "$DIR/tc-attachment.txt"
  grep 'tcx/egress sb_tc_local_l2' "$DIR/tc-attachment.txt" || {
    echo "expected TC program is not attached; forwarding evidence would be invalid" >&2
    stop_owned singbox
    exit 1
  }
  echo "TEST_SINGBOX_STARTED pid=$task_pid"
  cat "$DIR/singbox-stdout.log"
  ;;
load)
  shift
  client "$DIR/stage3load" -mode echo -target 10.211.0.2:7000 "$@"
  ;;
stop)
  stop_owned singbox
  protected_ok
  ;;
status)
  protected_ok
  for task in client peer echo singbox; do
    [ ! -f "$DIR/$task.pid" ] || echo "$task pid=$(owned_pid "$task") netns=$(netns "$(owned_pid "$task")")"
  done
  ;;
cleanup)
  stop_owned singbox
  stop_owned echo
  stop_owned client
  stop_owned peer
  protected_ok
  ip -4 route show table all > "$DIR/final-ipv4-routes.txt"
  ip -o link show > "$DIR/final-links.txt"
  cmp "$DIR/original-ipv4-routes.txt" "$DIR/final-ipv4-routes.txt"
  cmp "$DIR/original-links.txt" "$DIR/final-links.txt"
  echo "MAIN_NAMESPACE_LINKS_AND_IPV4_ROUTES_UNCHANGED"
  ;;
*) echo "usage: $0 setup PID | baseline [uid] | start BINARY CONFIG | start-unavailable BINARY CONFIG | load [args] | stop | status | cleanup"; exit 2 ;;
esac
