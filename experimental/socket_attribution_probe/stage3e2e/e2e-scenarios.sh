#!/system/bin/sh
# Stage 3 functional scenarios against the running test instance.
LOG=/data/local/tmp/sbe2/e2e/e2e.log
APK=/data/local/tmp/sbe2/test-single.apk
PKG=dev.sbo.firstconnection.single
up() { cut -d' ' -f1 /proc/uptime; }
rules() { grep -c "eBPF UID rules follow the package table" $LOG; }
wait_rules() { # wait until the rule-update count exceeds $1, print the delay
  start=$(up); i=0
  while [ $(rules) -le $1 ] && [ $i -lt 200 ]; do sleep 0.05; i=$((i+1)); done
  echo "  rules lines: $(rules) (waited $(echo "$(up) - $start" | bc 2>/dev/null || echo "$i*50ms"))"
}

echo "== 1. Chrome cold start"
am force-stop com.android.chrome
input keyevent KEYCODE_WAKEUP
am start -W -a android.intent.action.VIEW -d https://www.bing.com -p com.android.chrome | grep -E "TotalTime|Status"
sleep 8
pidof com.android.chrome
grep "found package name: com.android.chrome" $LOG | tail -3

echo "== 2. system_server NTP refresh (UID 1000, process 'system')"
cmd network_time_update_service force_refresh
sleep 3

echo "== 3. Security center"
am start -W -n com.miui.securitycenter/com.miui.securityscan.MainActivity 2>/dev/null | grep -E "Status|Error"
sleep 8
input keyevent KEYCODE_HOME

echo "== 4. include/exclude_package follows installs"
pm list packages $PKG
before=$(rules)
echo "  rule lines before install: $before"
t0=$(up); pm install $APK; t1=$(up)
echo "  pm install took $(echo "$t1 - $t0" | bc 2>/dev/null) s; uid $(pm list packages -U $PKG)"
wait_rules $before
grep "eBPF UID rules follow the package table" $LOG | tail -1

echo "== 5. same-UID reinstall (pm install -r): no kernel write expected"
before=$(rules)
pm install -r $APK
sleep 3
echo "  rule lines: before $before, after $(rules)"

echo "== 6. uninstall"
before=$(rules)
pm uninstall $PKG
wait_rules $before
grep "eBPF UID rules follow the package table" $LOG | tail -1
pm list packages $PKG
