#!/system/bin/sh
# Actual same-UID payload checks across package install/reinstall/uninstall.
# Native load driver, not the APK's own HTTP traffic. The APK is foregrounded
# solely to obtain Android's normal foreground UID firewall permissions.
# Usage: isolated-package.sh <new-binary> <existing-test-single.apk>
set -eu
DIR=/data/local/tmp/sbe3-fix
CTL=$DIR/isolated-netns.sh
PKG=dev.sbo.firstconnection.single
BINARY=$1
APK=$2
installed_by_test=0
cleanup() {
  if [ "$installed_by_test" = 1 ]; then
    pm uninstall "$PKG"
  fi
  sh "$CTL" stop
}
trap cleanup EXIT
package_uid() { pm list packages -U "$PKG" | sed -n "s/^package:$PKG uid://p"; }
foreground() { am start -W -n "$PKG/probe.MainActivity"; sleep 1; }
updates() { grep -c 'eBPF UID rules follow the package table' "$DIR/package.log" || true; }
same_instance() {
  [ "$(cat "$DIR/singbox.pid")" = "$instance" ] || { echo "test sing-box unexpectedly restarted"; exit 1; }
}
[ -z "$(package_uid)" ] || { echo "refusing to replace an installed diagnostic package"; exit 1; }
sh "$CTL" stop
echo "BINARY_AND_APK_HASHES"
sha256sum "$BINARY" "$APK" "$DIR/isolated-package-config.json"
sh "$CTL" start "$BINARY" "$DIR/isolated-package-config.json"
instance=$(cat "$DIR/singbox.pid")
echo "EMPTY_INCLUDE_SET: system UID9060 must bypass the reject route"
sh "$CTL" load -uid 9060 -conns 3 -bytes 4096 -timeout 2s -label package_absent_empty_include
echo "INSTALL"
pm install "$APK"
installed_by_test=1
test_uid=$(package_uid)
[ -n "$test_uid" ]
echo "TEST_PACKAGE_UID=$test_uid INSTANCE=$instance"
foreground
same_instance
sh "$CTL" load -uid "$test_uid" -conns 3 -bytes 4096 -timeout 2s -expect blocked -label installed_capture_reject
before=$(updates)
echo "REINSTALL update_count_before=$before"
pm install -r "$APK"
[ "$(package_uid)" = "$test_uid" ]
foreground
same_instance
after=$(updates)
echo "REINSTALL update_count_after=$after"
[ "$after" = "$before" ] || { echo "unexpected rule update on equivalent reinstall"; exit 1; }
sh "$CTL" load -uid "$test_uid" -conns 3 -bytes 4096 -timeout 2s -expect blocked -label reinstalled_capture_reject
echo "INSTALLED_SAME_UID_BASELINE_WITH_TEST_TC_STOPPED"
sh "$CTL" stop
sh "$CTL" baseline "$test_uid"
echo "INSTALL_AND_REINSTALL_DATAPLANE_PASS (same native UID, same endpoint, live instance across package events)"
sh "$CTL" start "$BINARY" "$DIR/isolated-package-config.json"
instance=$(cat "$DIR/singbox.pid")
sh "$CTL" load -uid "$test_uid" -conns 3 -bytes 4096 -timeout 2s -expect blocked -label before_uninstall_capture_reject
echo "UNINSTALL"
pm uninstall "$PKG"
installed_by_test=0
[ -z "$(package_uid)" ]
sleep 1
same_instance
if sh "$CTL" load -uid "$test_uid" -conns 3 -bytes 4096 -timeout 2s -label uninstalled_old_uid_bypass; then
  echo "UNINSTALL_DATAPLANE_PASS: old UID reaches echo while reject-configured test sing-box stays running"
else
  echo "UNINSTALL_OLD_UID_FAILED; checking pre-TC reachability without the test instance"
  sh "$CTL" stop
  if sh "$CTL" baseline "$test_uid"; then
    echo "UNINSTALL_DATAPLANE_FAIL: baseline reachable, live updated policy not reachable"
    exit 1
  fi
  echo "UNINSTALL_DATAPLANE_INCONCLUSIVE: same old UID cannot reach peer even with test TC stopped; do not credit a TC pass"
fi
