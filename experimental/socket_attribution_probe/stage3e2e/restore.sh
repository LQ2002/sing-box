#!/system/bin/sh
# Restart the user's own sing-box exactly as it ran before (same binary,
# config and command line; detached like the original, ppid 1).
D=/data/adb/services/sing-box
if pidof sing-box >/dev/null; then echo "already running: $(pidof sing-box)"; exit 0; fi
cd $D
setsid nohup $D/sing-box run -D $D -c $D/config.json >/dev/null 2>&1 &
sleep 4
P=$(pidof sing-box)
echo "pid=$P"
[ -n "$P" ] && tr '\0' ' ' < /proc/$P/cmdline && echo && $D/sing-box version | head -1
tail -3 $D/sing-box.log
