# Install/uninstall visibility lag, v2: uptime clock (10 ms), packages.xml
# decoded with abx2xml (it is binary ABX here), packages.list grep, and
# file mtimes. Times are ms after pm returned.
P=dev.sbo.firstconnection.single
A=/data/local/tmp/sbo-test-single.apk
up() { cut -d' ' -f1 /proc/uptime | tr -d '.'; }        # centiseconds
inxml() { abx2xml /data/system/packages.xml - 2>/dev/null | grep -q "name=\"$P\""; }
inlist() { grep -q "^$P " /data/system/packages.list; }
watch() { # $1 = 1 want present, 0 want absent; prints "xml list" in cs
  x=-; l=-; i=0
  while [ $i -lt 300 ]; do
    t=$(up)
    if [ "$x" = - ]; then if inxml; then r=1; else r=0; fi; [ $r = $1 ] && x=$t; fi
    if [ "$l" = - ]; then if inlist; then r=1; else r=0; fi; [ $r = $1 ] && l=$t; fi
    [ "$x" != - -a "$l" != - ] && break
    i=$((i+1))
  done
  echo "$x $l"
}
d() { [ "$1" = - ] && echo never || echo "+$(( ($1 - $2) * 10 ))ms"; }
for round in 1 2 3; do
  t0=$(up); pm install -r "$A" >/dev/null 2>&1; t1=$(up)
  q=$(pm list packages -U $P)
  set -- $(watch 1)
  echo "install#$round pm=$(( (t1-t0)*10 ))ms sync_query='$q' packages.xml=$(d $1 $t1) packages.list=$(d $2 $t1)"
  stat -c '   %y %n' /data/system/packages.xml /data/system/packages.list
  t0=$(up); pm uninstall $P >/dev/null 2>&1; t1=$(up)
  q=$(pm list packages -U $P)
  set -- $(watch 0)
  echo "uninstall#$round pm=$(( (t1-t0)*10 ))ms sync_query='$q' packages.xml=$(d $1 $t1) packages.list=$(d $2 $t1)"
  sleep 12
done
echo "left installed: $(pm list packages | grep -c $P)"
