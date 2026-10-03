#!/system/bin/sh
set -eu
# Device entry point. The caller uploads inputs; this script never touches adb.
# Only the named test module is loaded. All test mounts/network writes occur in
# fresh namespaces; the production process and existing owner module stay live.
DIR=/data/local/tmp/sbo-creator-integration-20261003
SCRIPT=$DIR/run-creator-integration-device.sh
BPFFS=/mnt/sbo-creator-integration/bpf
PIN_PATH=$BPFFS/collector
CORE_NAMES='TestTCSocketCreatorFirstPacket
TestTCSocketCreatorKeepsFirstSnapshot
TestTCSocketCreatorConfirmsMissingSnapshot
TestTCSocketCreatorRejectsInvalidStorage
TestTCSocketCreatorTupleReuse
TestTCSocketCreatorSurvivesDelivery
TestTCSocketCreatorBorrowedMapSurvivesBackend
TestTCSocketCreatorRejectsWrongMapBeforeLoading
TestTCSocketCreatorRecordsNetdCharge
TestTCSocketCreatorPlaceholderChargeIsCheckedOnly
TestTCSocketCreatorBorrowedCookieTagMapSurvivesBackend
TestTCSocketCreatorRejectsWrongCookieTagMap'
CORE_REGEX='^TestTCSocketCreator(FirstPacket|KeepsFirstSnapshot|ConfirmsMissingSnapshot|RejectsInvalidStorage|TupleReuse|SurvivesDelivery|BorrowedMapSurvivesBackend|RejectsWrongMapBeforeLoading|RecordsNetdCharge|PlaceholderChargeIsCheckedOnly|BorrowedCookieTagMapSurvivesBackend|RejectsWrongCookieTagMap)$'
COLLECTOR_NAME=TestDeviceCollectorPersistence
LIVE_NAME=TestTCSocketCreatorLiveProducer

fail() { echo "ERROR: $*" >&2; exit 1; }
start_ticks() {
  # comm may contain spaces or parentheses. Remove through its last ') '.
  sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}'
}
namespace_pids() {
  wanted_namespace=$1
  for process in /proc/[0-9]*; do
    candidate=${process##*/}
    [ "$candidate" != "$$" ] && [ "$candidate" != "$protected_pid" ] || continue
    [ "$(readlink "$process/ns/mnt" 2>/dev/null)" = "$wanted_namespace" ] || continue
    echo "$candidate"
  done
}
stop_namespace_processes() {
  wanted_namespace=$1
  [ -n "$wanted_namespace" ] || return 0
  [ "$wanted_namespace" != "$main_mntns" ] || return 1
  # Run the scanner in this shell. A command-substitution scanner is itself a
  # process in the private namespace but retains its parent's $$, so it could
  # keep reporting an otherwise empty namespace forever.
  cleanup_pids_file=$RESULTS/cleanup-pids-$$.txt
  for signal in TERM KILL; do
    namespace_pids "$wanted_namespace" > "$cleanup_pids_file"
    [ -s "$cleanup_pids_file" ] || return 0
    while IFS= read -r candidate; do
      candidate_ticks=$(start_ticks "$candidate")
      [ -n "$candidate_ticks" ] || continue
      [ "$(readlink "/proc/$candidate/ns/mnt" 2>/dev/null)" = "$wanted_namespace" ] || continue
      [ "$(start_ticks "$candidate")" = "$candidate_ticks" ] || continue
      echo "CLEANUP_TEST_PROCESS pid=$candidate start_ticks=$candidate_ticks signal=$signal"
      kill -"$signal" "$candidate" 2>/dev/null || true
    done < "$cleanup_pids_file"
    attempts=0
    while [ "$attempts" -lt 5 ]; do
      namespace_pids "$wanted_namespace" > "$cleanup_pids_file"
      [ -s "$cleanup_pids_file" ] || return 0
      sleep 1
      attempts=$((attempts + 1))
    done
  done
  namespace_pids "$wanted_namespace" > "$cleanup_pids_file"
  [ ! -s "$cleanup_pids_file" ]
}

if [ "${1:-}" = --inner ]; then
  [ "$#" = 5 ] || fail 'invalid private harness arguments'
  RESULTS=$2
  main_netns=$3
  main_mntns=$4
  protected_pid=$5
  private_netns=$(readlink /proc/self/ns/net)
  private_mntns=$(readlink /proc/self/ns/mnt)
  [ "$private_netns" != "$main_netns" ] || fail 'refusing original network namespace'
  [ "$private_mntns" != "$main_mntns" ] || fail 'refusing original mount namespace'
  [ "$private_netns" != "$(readlink "/proc/$protected_pid/ns/net")" ] || fail 'refusing production network namespace'
  printf '%s\n%s\n' "$private_mntns" "$private_netns" > "$RESULTS/private-namespaces.txt"
  mounted_tmpfs=0
  mounted_bpffs=0
  inner_cleanup() {
    inner_rc=$?
    trap - EXIT HUP INT TERM
    set +e
    inner_cleanup_rc=0
    stop_namespace_processes "$private_mntns" || inner_cleanup_rc=1
    if [ "$(readlink /proc/self/ns/mnt)" != "$private_mntns" ] || [ "$private_mntns" = "$main_mntns" ]; then
      echo 'ERROR: namespace changed; refusing mount cleanup' >&2
      inner_cleanup_rc=1
    else
      if [ "$mounted_bpffs" = 1 ]; then
        if ! umount "$BPFFS"; then
          inner_cleanup_rc=1
          umount -l "$BPFFS" || true
        fi
      fi
      if [ "$mounted_tmpfs" = 1 ]; then
        if ! umount /mnt; then
          inner_cleanup_rc=1
          umount -l /mnt || true
        fi
      fi
    fi
    echo "PRIVATE_CLEANUP run_rc=$inner_rc cleanup_rc=$inner_cleanup_rc"
    [ "$inner_rc" = 0 ] || exit "$inner_rc"
    exit "$inner_cleanup_rc"
  }
  trap inner_cleanup EXIT
  trap 'exit 130' HUP INT TERM
  # /data/local/tmp has an untrusted ancestor for Collector.Open. Overlay the
  # already-existing /mnt only after making this private mount tree recursive.
  # Android toybox may accept rprivate yet leave descendant propagation flags
  # intact. Prefer the known root-owned BusyBox on this device, then another
  # available BusyBox, with native mount as the fallback on other environments.
  if [ -x /data/adb/ksu/bin/busybox ]; then
    /data/adb/ksu/bin/busybox mount --make-rprivate /
  elif command -v busybox >/dev/null 2>&1; then
    busybox mount --make-rprivate /
  else
    mount --make-rprivate /
  fi
  cat /proc/self/mountinfo > "$RESULTS/private-tree-mountinfo.txt"
  awk '{ for (i=7; i<=NF && $i != "-"; i++) if ($i ~ /^(shared|master|propagate_from):/) exit 1 }' "$RESULTS/private-tree-mountinfo.txt" || fail 'private mount tree still propagates'
  mount -t tmpfs -o mode=0700,nosuid,nodev,noexec tmpfs /mnt
  mounted_tmpfs=1
  mkdir -p "$BPFFS"
  chmod 0700 /mnt /mnt/sbo-creator-integration "$BPFFS"
  mount -t bpf -o mode=1777,nosuid,nodev,noexec bpf "$BPFFS"
  mounted_bpffs=1
  cat /proc/self/mountinfo > "$RESULTS/private-mountinfo.txt"
  awk -v point="$BPFFS" '$5 == point { for (i=7; i<=NF; i++) if ($i == "-" && $(i+1) == "bpf") found=1 } END { exit !found }' /proc/self/mountinfo || fail 'private bpffs mount not found'
  # Android kernels instantiate these inert tunnel devices in every fresh
  # namespace. Allow only the exact defaults plus lo, all DOWN without the UP
  # flag, no non-loopback address, and no route in any IPv4 or IPv6 table.
  # Fixtures may then add their own private veth/dummy/peer namespaces.
  ip -o link show > "$RESULTS/private-links-before.txt"
  awk '
    BEGIN {
      split("lo tunl0 gre0 gretap0 erspan0 ip_vti0 ip6_vti0 sit0 ip6tnl0 ip6gre0", defaults, " ")
      for (i in defaults) allowed[defaults[i]]=1
    }
    {
      name=$2
      sub(/:$/, "", name)
      if (name ~ /@/ && name !~ /@NONE$/) exit 1
      sub(/@NONE$/, "", name)
      if (!(name in allowed) || seen[name]++) exit 1
      if (!match($0, /<[^>]*>/)) exit 1
      flags=substr($0, RSTART+1, RLENGTH-2)
      count=split(flags, flag, ",")
      for (i=1; i<=count; i++) if (flag[i] == "UP") exit 1
      down=0
      for (i=3; i<NF; i++) if ($i == "state" && $(i+1) == "DOWN") down=1
      if (!down) exit 1
    }
    END { if (!seen["lo"]) exit 1 }
  ' "$RESULTS/private-links-before.txt" || fail 'private namespace has an unexpected or active interface'
  ip -o address show > "$RESULTS/private-addresses-before.txt"
  awk '$2 != "lo" { exit 1 }' "$RESULTS/private-addresses-before.txt" || fail 'private namespace has a non-loopback address'
  for family in 4 6; do
    ip -"$family" route show table all > "$RESULTS/private-ipv$family-routes-before.txt"
    [ ! -s "$RESULTS/private-ipv$family-routes-before.txt" ] || fail "private namespace has an IPv$family route"
  done
  ip link set lo up
  echo "PRIVATE_NAMESPACE mnt=$private_mntns net=$private_netns bpffs=$BPFFS"

  check_test_list() {
    test_binary=$1
    test_pattern=$2
    test_expected=$3
    test_label=$4
    "$test_binary" -test.list "$test_pattern" > "$RESULTS/$test_label-list-raw.txt"
    grep '^Test' "$RESULTS/$test_label-list-raw.txt" | sort > "$RESULTS/$test_label-list.txt"
    printf '%s\n' "$test_expected" | sort > "$RESULTS/$test_label-list-expected.txt"
    cmp "$RESULTS/$test_label-list-expected.txt" "$RESULTS/$test_label-list.txt" || fail "$test_label test inventory differs"
  }
  run_test_binary() {
    test_binary=$1
    test_pattern=$2
    test_timeout=$3
    test_label=$4
    if "$test_binary" -test.run "$test_pattern" -test.v -test.count=1 -test.timeout "$test_timeout" > "$RESULTS/$test_label.log" 2>&1; then
      test_rc=0
    else
      test_rc=$?
    fi
    cat "$RESULTS/$test_label.log"
    [ "$test_rc" = 0 ] || return "$test_rc"
    if grep -q -- '--- SKIP:' "$RESULTS/$test_label.log"; then
      echo "ERROR: $test_label skipped required coverage" >&2
      return 1
    fi
  }
  require_pass() {
    grep -F -q -- "--- PASS: $2 (" "$RESULTS/$1.log" || fail "$1 did not report PASS for $2"
  }
  check_test_list "$DIR/core.test" "$CORE_REGEX" "$CORE_NAMES" core
  check_test_list "$DIR/core.test" "^$LIVE_NAME\$" "$LIVE_NAME" live
  check_test_list "$DIR/socketidentity.test" "^$COLLECTOR_NAME\$" "$COLLECTOR_NAME" collector
  export SING_EBPF_INTEGRATION=1
  run_test_binary "$DIR/core.test" "$CORE_REGEX" 120s core
  for test_name in $CORE_NAMES; do require_pass core "$test_name"; done
  echo 'CORE_SYNTHETIC_STORAGE_CASES=12 PASS'
  export SBO_SOCKET_CREATOR_DEVICE_TEST=1
  export SBO_SOCKET_CREATOR_TEST_BPFFS="$BPFFS"
  export SBO_SOCKET_CREATOR_TEST_PIN_PATH="$PIN_PATH"
  export SBO_SOCKET_CREATOR_CORE_TEST_BINARY="$DIR/core.test"
  run_test_binary "$DIR/socketidentity.test" "^$COLLECTOR_NAME\$" 180s collector
  require_pass collector "$COLLECTOR_NAME"
  require_pass collector "$LIVE_NAME"
  # The collector test owns/removes its pins. A leftover object is a failure,
  # even though destroying this private bpffs mount also bounds its lifetime.
  if [ -d "$PIN_PATH" ]; then
    [ -z "$(ls -A "$PIN_PATH")" ] || fail 'collector test left persistent pins'
  fi
  echo 'COLLECTOR_PERSISTENCE_AND_LIVE_TC=PASS'
  exit 0
fi

[ "$#" -ge 3 ] && [ "$#" -le 4 ] || fail "usage: $0 protected-pid expected-start-ticks expected-kernel-release [expected-boot-id]"
protected_pid=$1
protected_ticks=$2
expected_kernel=$3
expected_boot=${4:-}
case "$protected_pid:$protected_ticks" in *[!0-9:]*|:*|*:) fail 'PID/start ticks must be decimal integers';; esac
[ "$protected_pid" -gt 2 ] || fail 'invalid protected PID'
[ "$(id -u)" = 0 ] || fail 'run the harness as root'
[ "$(uname -m)" = aarch64 ] || fail 'the test binaries and producer require arm64'
[ "$(uname -r)" = "$expected_kernel" ] || fail 'unexpected running kernel release'
[ "$(start_ticks "$protected_pid")" = "$protected_ticks" ] || fail 'protected process does not match preflight'
[ ! -e /sys/module/sbo_identity_bridge ] || fail 'test bridge already exists; refusing to replace it'
[ -z "$expected_boot" ] || [ "$(cat /proc/sys/kernel/random/boot_id)" = "$expected_boot" ] || fail 'boot changed since preflight'
[ "$(stat -c %u "$DIR")" = 0 ] && [ "$(stat -c %a "$DIR")" = 700 ] || fail 'test directory must be root-owned mode 0700'
for binary in "$DIR/socketidentity.test" "$DIR/core.test"; do [ -x "$binary" ] || fail "missing executable $binary"; done
for input in "$SCRIPT" "$DIR/sbo_identity_bridge.ko" "$DIR/base-btf.sha256"; do [ -f "$input" ] || fail "missing input $input"; done
for tool in ip unshare mount umount timeout insmod rmmod readlink stat sha256sum awk sed grep sort cmp; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing device command $tool"
done
expected_btf=$(awk 'NR == 1 {print $1}' "$DIR/base-btf.sha256")
actual_btf=$(sha256sum /sys/kernel/btf/vmlinux | awk '{print $1}')
[ "${#expected_btf}" = 64 ] && [ "$expected_btf" = "$actual_btf" ] || fail 'running BTF differs from module build base'
umask 077
RESULTS=$DIR/results/run-$(date +%Y%m%d-%H%M%S)-$$
mkdir -p "$DIR/results"
mkdir "$RESULTS"
echo "RESULTS=$RESULTS"
main_netns=$(readlink /proc/self/ns/net)
main_mntns=$(readlink /proc/self/ns/mnt)
[ "$(readlink "/proc/$protected_pid/ns/net")" = "$main_netns" ] || fail 'outer shell is not in the protected process network namespace'

capture_state() {
  state=$1
  cat /proc/sys/kernel/random/boot_id > "$RESULTS/$state-boot.txt" || return 1
  cat /proc/sys/kernel/tainted > "$RESULTS/$state-taint.txt" || return 1
  uname -r > "$RESULTS/$state-kernel.txt" || return 1
  cat /proc/modules > "$RESULTS/$state-modules-raw.txt" || return 1
  awk '{print $1}' "$RESULTS/$state-modules-raw.txt" | sort > "$RESULTS/$state-module-names.txt" || return 1
  cat "/proc/$protected_pid/stat" > "$RESULTS/$state-production-stat.txt" || return 1
  start_ticks "$protected_pid" > "$RESULTS/$state-start-ticks.txt" || return 1
  cat "/proc/$protected_pid/cmdline" > "$RESULTS/$state-cmdline.bin" || return 1
  readlink "/proc/$protected_pid/exe" > "$RESULTS/$state-executable.txt" || return 1
  readlink "/proc/$protected_pid/ns/net" > "$RESULTS/$state-production-netns.txt" || return 1
  ip -o link show > "$RESULTS/$state-links.txt" || return 1
  ip -o address show > "$RESULTS/$state-addresses-raw.txt" || return 1
  sed -e 's/valid_lft [0-9][0-9]*sec/valid_lft COUNTDOWNsec/g' -e 's/preferred_lft [0-9][0-9]*sec/preferred_lft COUNTDOWNsec/g' "$RESULTS/$state-addresses-raw.txt" > "$RESULTS/$state-addresses.txt" || return 1
  for family in 4 6; do
    ip -"$family" route show table all > "$RESULTS/$state-ipv$family-routes-raw.txt" || return 1
    sed 's/expires [0-9][0-9]*sec/expires COUNTDOWNsec/g' "$RESULTS/$state-ipv$family-routes-raw.txt" > "$RESULTS/$state-ipv$family-routes.txt" || return 1
    ip -"$family" rule show > "$RESULTS/$state-ipv$family-rules.txt" || return 1
  done
}
capture_state before
sha256sum "$DIR/sbo_identity_bridge.ko" "$DIR/socketidentity.test" "$DIR/core.test" "$SCRIPT" > "$RESULTS/input-sha256.txt"
printf 'kernel=%s\nbtf=%s\nprotected_pid=%s\nstart_ticks=%s\nmain_netns=%s\nmain_mntns=%s\n' "$expected_kernel" "$actual_btf" "$protected_pid" "$protected_ticks" "$main_netns" "$main_mntns" > "$RESULTS/preflight.txt"
owned_module=0
outer_cleanup() {
  run_rc=$?
  trap - EXIT HUP INT TERM
  set +e
  cleanup_rc=0
  if [ -f "$RESULTS/private-namespaces.txt" ]; then
    private_mntns=$(sed -n '1p' "$RESULTS/private-namespaces.txt")
    case "$private_mntns" in mnt:\[[0-9]*\]) stop_namespace_processes "$private_mntns" || cleanup_rc=1;; *) cleanup_rc=1;; esac
  fi
  if [ "$owned_module" = 1 ]; then
    echo 0 > /sys/module/sbo_identity_bridge/parameters/capture_all || cleanup_rc=1
    echo 0 > /sys/module/sbo_identity_bridge/parameters/target_tgid || cleanup_rc=1
    unload_attempt=0
    while [ -e /sys/module/sbo_identity_bridge ] && [ "$unload_attempt" -lt 3 ]; do
      rmmod sbo_identity_bridge && break
      unload_attempt=$((unload_attempt + 1))
      sleep 1
    done
    [ ! -e /sys/module/sbo_identity_bridge ] || cleanup_rc=1
  fi
  [ "$(start_ticks "$protected_pid")" = "$protected_ticks" ] || cleanup_rc=1
  [ "$(readlink /proc/self/ns/net)" = "$main_netns" ] || cleanup_rc=1
  [ "$(readlink /proc/self/ns/mnt)" = "$main_mntns" ] || cleanup_rc=1
  capture_state after || cleanup_rc=1
  for item in boot.txt taint.txt kernel.txt module-names.txt start-ticks.txt cmdline.bin executable.txt production-netns.txt links.txt addresses.txt ipv4-routes.txt ipv6-routes.txt ipv4-rules.txt ipv6-rules.txt; do
    if ! cmp "$RESULTS/before-$item" "$RESULTS/after-$item"; then
      echo "STATE_CHANGED=$item" >&2
      cleanup_rc=1
    fi
  done
  echo "CLEANUP run_rc=$run_rc cleanup_rc=$cleanup_rc protected_pid=$protected_pid start_ticks=$protected_ticks results=$RESULTS"
  [ "$run_rc" = 0 ] || exit "$run_rc"
  exit "$cleanup_rc"
}
trap outer_cleanup EXIT
trap 'exit 130' HUP INT TERM
[ ! -e /sys/module/sbo_identity_bridge ] || fail 'bridge appeared before this run loaded it'
insmod "$DIR/sbo_identity_bridge.ko" target_tgid=0 capture_all=1
owned_module=1
[ -f /sys/kernel/btf/sbo_identity_bridge ] || fail 'loaded bridge has no runtime module BTF'
case "$(cat /sys/module/sbo_identity_bridge/parameters/capture_all)" in Y|1) ;; *) fail 'bridge global capture was not enabled';; esac
sha256sum /sys/kernel/btf/sbo_identity_bridge > "$RESULTS/loaded-module-btf-sha256.txt"
echo "PROTECTED_PID=$protected_pid START_TICKS=$protected_ticks MAIN_NETNS=$main_netns"
if timeout -s TERM -k 15 420 unshare -m -n /system/bin/sh "$SCRIPT" --inner "$RESULTS" "$main_netns" "$main_mntns" "$protected_pid" > "$RESULTS/inner.log" 2>&1; then
  test_rc=0
else
  test_rc=$?
fi
cat "$RESULTS/inner.log"
exit "$test_rc"
