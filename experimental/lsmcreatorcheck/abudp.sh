# UDP A/B: A = sing-box.db5eeba18 (queue + drain goroutine),
#          B = sing-box.65bcc588f (SS2022 recvmmsg batch read + direct batch write).
D=/data/adb/services/sing-box
T=/data/local/tmp
OUT=$T/abudp.log
A=$D/sing-box.db5eeba18
B=$D/sing-box.65bcc588f
URL=https://dl.google.com/android/repository/platform-tools-latest-linux.zip
switch() {
  before=$(pidof sing-box)
  cp "$1" $D/sing-box.tmp && mv -f $D/sing-box.tmp $D/sing-box && chmod 755 $D/sing-box
  sh /data/adb/services/box restart > /dev/null 2>&1
  sleep 6
  now=$(pidof sing-box)
  want=$(sha256sum "$1" | cut -c1-16); got=$(sha256sum /proc/$now/exe | cut -c1-16)
  echo "switch to $(basename $1): pid $before -> $now exe=$got" >> $OUT
  if [ -z "$now" ] || [ "$now" = "$before" ] || [ "$want" != "$got" ]; then
    echo "ABORT: switch to $(basename $1) did not take effect" >> $OUT
    exit 1
  fi
}
one() {
  p=$(pidof sing-box)
  set -- $(cut -d' ' -f14,15 /proc/$p/stat); u0=$(( $1 + $2 ))
  r=$(su -g 2000 -G 3003 2000 -c "$T/h3probe -url $URL -n 2 -timeout 60s" 2>&1 | grep '^H3' | awk '{print $8, $9}' | tr '\n' ' ')
  set -- $(cut -d' ' -f14,15 /proc/$p/stat); u1=$(( $1 + $2 ))
  echo "$label ticks=$(( u1 - u0 )) runs: $r" >> $OUT
}
: > $OUT
echo "start $(date) kernel=$(uname -v)" >> $OUT
for round in 1 2 3; do
  for v in A B; do
    if [ $v = A ]; then switch $A; else switch $B; fi
    label="r$round-$v"; one; one
  done
done
switch $A
echo "done $(date) production=$(sha256sum $D/sing-box | cut -c1-16) pid=$(pidof sing-box)" >> $OUT
