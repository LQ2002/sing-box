#!/system/bin/sh
# Unload on module removal. While a sing-box collector link is attached the
# module is still referenced and rmmod fails; it is then gone after reboot.
# capture_all is cleared first so a failed rmmod leaves the hook idle.
if [ -d /sys/module/sbo_identity ]; then
    echo 0 > /sys/module/sbo_identity/parameters/capture_all 2>/dev/null
    rmmod sbo_identity 2>/dev/null
fi
exit 0
