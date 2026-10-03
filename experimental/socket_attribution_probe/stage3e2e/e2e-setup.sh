#!/system/bin/sh
# Prepare an isolated copy of the user's sing-box directory for the stage 3 run.
set -e
SRC=/data/adb/services/sing-box
DST=/data/local/tmp/sbe2/e2e
rm -rf $DST; mkdir -p $DST
for f in $(ls -A $SRC); do
  case "$f" in sing-box|sing-box.log|config*.json*) continue ;; esac
  cp -a "$SRC/$f" "$DST/"
done
cp /data/local/tmp/sbe2/sing-box-new $DST/sing-box
cp /data/local/tmp/sbe2/e2e-config.json $DST/config.json
chmod 755 $DST/sing-box
ls -la $DST
$DST/sing-box version | head -3
$DST/sing-box check -D $DST -c $DST/config.json && echo CHECK_OK
