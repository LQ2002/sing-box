#!/system/bin/sh
set -eu
# Explicit standalone experiment. No module replacement or production TC attach.
DIR=/data/local/tmp/sbo-identity-carrier-20261003
[ "$#" -ge 1 ] || { echo "usage: $0 protected-sing-box-pid [runner flags...]" >&2; exit 2; }
protected_pid=$1
shift
case "$protected_pid" in ''|*[!0-9]*) exit 2;; esac
[ "$protected_pid" -gt 2 ] && [ -r "/proc/$protected_pid/stat" ]
[ ! -e /sys/module/sbo_identity_bridge ] || {
  echo "prototype module already loaded; inspect before retrying" >&2; exit 1
}
[ -x "$DIR/identity-carrier-probe" ]
[ -f "$DIR/sbo_identity_bridge.ko" ]
[ -f "$DIR/base-btf.sha256" ]
expected_btf=$(awk 'NR == 1 {print $1}' "$DIR/base-btf.sha256")
actual_btf=$(sha256sum /sys/kernel/btf/vmlinux | awk '{print $1}')
[ "${#expected_btf}" = 64 ] && [ "$expected_btf" = "$actual_btf" ] || {
  echo "running kernel BTF differs from the module's build base" >&2; exit 1
}
mkdir -p "$DIR/results"
protected_ticks=$(awk '{print $22}' "/proc/$protected_pid/stat")
main_netns=$(readlink /proc/self/ns/net)
[ "$(readlink "/proc/$protected_pid/ns/net")" = "$main_netns" ]
cat /proc/sys/kernel/random/boot_id > "$DIR/results/before-boot.txt"
cat "/proc/$protected_pid/cmdline" > "$DIR/results/before-cmdline.bin"
ip -o link show > "$DIR/results/before-links.txt"
ip -4 route show table all > "$DIR/results/before-ipv4-routes.txt"
ip -6 route show table all > "$DIR/results/before-ipv6-routes.txt"
sed 's/expires [0-9][0-9]*sec/expires COUNTDOWNsec/g' "$DIR/results/before-ipv6-routes.txt" > "$DIR/results/before-ipv6-routes-normalized.txt"
ip rule show > "$DIR/results/before-rules.txt"
owned_module=0
cleanup() {
  run_rc=$?
  trap - EXIT HUP INT TERM
  cleanup_rc=0
  if [ "$owned_module" = 1 ]; then
    echo 0 > /sys/module/sbo_identity_bridge/parameters/target_tgid || cleanup_rc=1
    rmmod sbo_identity_bridge || cleanup_rc=1
  fi
  [ ! -e /sys/module/sbo_identity_bridge ] || cleanup_rc=1
  [ "$(awk '{print $22}' "/proc/$protected_pid/stat" 2>/dev/null)" = "$protected_ticks" ] || cleanup_rc=1
  [ "$(readlink "/proc/$protected_pid/ns/net")" = "$main_netns" ] || cleanup_rc=1
  cat /proc/sys/kernel/random/boot_id > "$DIR/results/after-boot.txt"
  cat "/proc/$protected_pid/cmdline" > "$DIR/results/after-cmdline.bin"
  ip -o link show > "$DIR/results/after-links.txt"
  ip -4 route show table all > "$DIR/results/after-ipv4-routes.txt"
  ip -6 route show table all > "$DIR/results/after-ipv6-routes.txt"
  # Router-advertisement lifetimes decrease while we run. Preserve the raw
  # snapshots, but compare route identity without this expected countdown.
  sed 's/expires [0-9][0-9]*sec/expires COUNTDOWNsec/g' "$DIR/results/after-ipv6-routes.txt" > "$DIR/results/after-ipv6-routes-normalized.txt"
  ip rule show > "$DIR/results/after-rules.txt"
  for item in boot.txt cmdline.bin links.txt ipv4-routes.txt ipv6-routes-normalized.txt rules.txt; do
    cmp "$DIR/results/before-$item" "$DIR/results/after-$item" || cleanup_rc=1
  done
  echo "CLEANUP run_rc=$run_rc cleanup_rc=$cleanup_rc protected_pid=$protected_pid start_ticks=$protected_ticks"
  [ "$run_rc" = 0 ] || exit "$run_rc"
  exit "$cleanup_rc"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
uname -r
echo "PROTECTED_PID=$protected_pid START_TICKS=$protected_ticks MAIN_NETNS=$main_netns"
insmod "$DIR/sbo_identity_bridge.ko" target_tgid=0
owned_module=1
[ -f /sys/kernel/btf/sbo_identity_bridge ] || {
  echo "loaded module has no runtime BTF" >&2; exit 1
}
ls -l /sys/kernel/btf/sbo_identity_bridge
timeout -s TERM 120 unshare -n /system/bin/sh "$DIR/private-netns.sh" "$main_netns" "$@"
