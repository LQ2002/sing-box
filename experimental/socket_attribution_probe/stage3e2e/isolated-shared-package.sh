#!/system/bin/sh
# Keep B installed/foreground so the shared UID retains normal netd permission
# while configured package A is installed and uninstalled. Only A is included
# in TC. This isolates package removal from the UID losing Android permission.
# Usage: isolated-shared-package.sh <new-binary> <test-a.apk> <test-b.apk>
set -eu
DIR=/data/local/tmp/sbe3-fix
CTL=$DIR/isolated-netns.sh
PKGA=dev.sbo.firstconnection.a
PKGB=dev.sbo.firstconnection.b
BINARY=$1
APKA=$2
APKB=$3
own_a=0
own_b=0
cleanup() {
  [ "$own_a" != 1 ] || pm uninstall "$PKGA"
  [ "$own_b" != 1 ] || pm uninstall "$PKGB"
  sh "$CTL" stop
}
trap cleanup EXIT
package_uid() { pm list packages -U "$1" | sed -n "s/^package:$1 uid://p"; }
foreground_b() { am start -W -n "$PKGB/probe.MainActivity"; sleep 1; }
same_instance() { [ "$(cat "$DIR/singbox.pid")" = "$instance" ]; }
[ -z "$(package_uid "$PKGA")" ] && [ -z "$(package_uid "$PKGB")" ] || {
  echo "refusing to replace installed diagnostic packages"; exit 1;
}
echo "BINARY_AND_APK_HASHES"
sha256sum "$BINARY" "$APKA" "$APKB" "$DIR/isolated-shared-package-config.json"
sh "$CTL" stop
pm install "$APKB"
own_b=1
shared_uid=$(package_uid "$PKGB")
[ -n "$shared_uid" ]
foreground_b
sh "$CTL" baseline "$shared_uid"
sh "$CTL" start "$BINARY" "$DIR/isolated-shared-package-config.json"
instance=$(cat "$DIR/singbox.pid")
echo "SHARED_UID=$shared_uid CONFIGURED_PACKAGE=$PKGA KEEPALIVE_PACKAGE=$PKGB INSTANCE=$instance"
sh "$CTL" load -uid "$shared_uid" -conns 5 -bytes 65536 -timeout 2s -label only_b_installed_bypass
echo "INSTALL_CONFIGURED_A"
pm install "$APKA"
own_a=1
[ "$(package_uid "$PKGA")" = "$shared_uid" ]
[ "$(package_uid "$PKGB")" = "$shared_uid" ]
foreground_b
same_instance
sh "$CTL" load -uid "$shared_uid" -conns 5 -bytes 65536 -timeout 2s -expect blocked -label a_plus_b_installed_capture_reject
echo "UNINSTALL_CONFIGURED_A_KEEP_B"
pm uninstall "$PKGA"
own_a=0
[ -z "$(package_uid "$PKGA")" ]
[ "$(package_uid "$PKGB")" = "$shared_uid" ]
foreground_b
same_instance
sh "$CTL" load -uid "$shared_uid" -conns 5 -bytes 65536 -timeout 2s -label a_uninstalled_b_remaining_bypass
echo "SHARED_UID_INSTALL_UNINSTALL_DATAPLANE_PASS: same live sing-box, same UID and endpoint; bypass -> captured rejection -> verified bypass"
sh "$CTL" stop
sh "$CTL" baseline "$shared_uid"
pm uninstall "$PKGB"
own_b=0
[ -z "$(package_uid "$PKGA")" ] && [ -z "$(package_uid "$PKGB")" ]
echo "SHARED_DIAGNOSTIC_PACKAGES_REMOVED"
