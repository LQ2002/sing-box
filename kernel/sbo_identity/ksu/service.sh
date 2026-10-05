#!/system/bin/sh
# Boot-time loader for sbo_identity (KernelSU/Magisk late_start service).
#
# Rules carried over from experimental/sb_sockowner_probe/magisk/service.sh,
# which learned them from a module pack that force-loaded mismatched modules
# and bootlooped the phone after a kernel update:
#
#   1. Plain insmod only. Its symbol-CRC check is the safety net.
#   2. Compare the kernel release string first: with CRCs, same_magic() skips
#      the version part of vermagic, so insmod alone may not refuse a new
#      kernel.
#   3. Also compare the sha256 of /sys/kernel/btf/vmlinux with the BTF the
#      module was built against. sbo_identity reads struct sock / css_set /
#      cgroup / kernfs_node fields at offsets generated from that BTF
#      (gen_layout.py), so a vendor rebuild with the same release string but
#      a different layout must also stop the load. This is the check the
#      README's "Load" section asks for.
#   4. late_start, never post-fs-data, and every path exits 0: a failure here
#      cannot block boot.
#   5. Three consecutive failures disable the module.
#
# capture_all=1 is what the v3 collector requires (common/socketidentity
# checkModule); it never changes module parameters itself. If this script
# does not load the module, sing-box with local.socket_creator enabled fails
# to start the eBPF inbound and says so in its log.
#
# Escape hatch: boot holding volume-down for KernelSU/Magisk safe mode.

MODDIR=${0%/*}
NAME=sbo_identity
LOG=$MODDIR/load.log
FAILCOUNT=$MODDIR/fail-count
MAXFAIL=3

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"
}

fail() {
    log "not loaded: $*"
    count=$(cat "$FAILCOUNT" 2>/dev/null || echo 0)
    count=$((count + 1))
    echo "$count" > "$FAILCOUNT"
    if [ "$count" -ge "$MAXFAIL" ]; then
        log "failed $count times in a row, disabling; remove $MODDIR/disable and $FAILCOUNT after fixing"
        touch "$MODDIR/disable"
    fi
    exit 0
}

: > "$LOG"
log "start"

if [ -d /sys/module/$NAME ]; then
    log "already loaded: $(cat /sys/module/$NAME/parameters/stats 2>/dev/null)"
    exit 0
fi

KO=$MODDIR/$NAME.ko
[ -f "$KO" ] || fail "missing $KO"

EXPECTED=$(cat "$MODDIR/kernel-release" 2>/dev/null)
RUNNING=$(uname -r)
[ -n "$EXPECTED" ] || fail "package has no kernel-release"
if [ "$EXPECTED" != "$RUNNING" ]; then
    log "  built for: $EXPECTED"
    log "  running:   $RUNNING"
    fail "kernel changed; regenerate the layout and rebuild (kernel/sbo_identity/README.md)"
fi

EXPECTED_BTF=$(cut -d' ' -f1 "$MODDIR/base-btf.sha256" 2>/dev/null)
RUNNING_BTF=$(sha256sum /sys/kernel/btf/vmlinux 2>/dev/null | cut -d' ' -f1)
[ -n "$EXPECTED_BTF" ] || fail "package has no base-btf.sha256"
if [ "$EXPECTED_BTF" != "$RUNNING_BTF" ]; then
    log "  built for BTF: $EXPECTED_BTF"
    log "  running BTF:   $RUNNING_BTF"
    fail "kernel BTF differs from the module build base"
fi

if ERR=$(insmod "$KO" capture_all=1 2>&1); then
    log "loaded: $(cat /sys/module/$NAME/parameters/capture_all 2>/dev/null) $(cat /sys/module/$NAME/parameters/stats 2>/dev/null)"
    rm -f "$FAILCOUNT"
    exit 0
fi
fail "insmod: $ERR"
