#!/system/bin/sh
# Must run under unshare -m. Do not invoke in the parent mount namespace.
# Bind a read-only ordinary file over this namespace's module device: O_RDWR
# fails with EROFS. The module itself stays loaded and the host device is intact.
set -eu
DIR=/data/local/tmp/sbe3-fix
BB=/data/adb/ksu/bin/busybox
own_mount=$(ls -l /proc/self/ns/mnt | awk '{print $NF}')
parent_mount=$(ls -l "/proc/$PPID/ns/mnt" | awk '{print $NF}')
[ "$own_mount" != "$parent_mount" ] || { echo "requires a private mount namespace" >&2; exit 1; }
"$BB" mount --make-rprivate /
"$BB" mount --bind "$DIR/module-unavailable" /dev/sb_sockowner_probe
"$BB" mount -o remount,bind,ro /dev/sb_sockowner_probe
if /system/bin/sh -c 'exec 9<>/dev/sb_sockowner_probe' 2> "$DIR/module-open-error.txt"; then
  echo "module mask did not prevent O_RDWR; refusing test" >&2
  exit 1
fi
echo "MODULE_O_RDWR_UNAVAILABLE mount_namespace=$own_mount"
cat "$DIR/module-open-error.txt"
exec "$@"
