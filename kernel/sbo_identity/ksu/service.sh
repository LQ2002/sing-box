#!/system/bin/sh
# Boot-time loader for sbo_identity (KernelSU/SukiSU/Magisk late_start service).
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
# The manager shows the outcome: common.sh set_description replaces the
# static description with the current state. action.sh (the Action button)
# loads or unloads the module for the running boot.
#
# Escape hatch: boot holding volume-down for KernelSU/Magisk safe mode.

MODDIR=${0%/*}
. "$MODDIR/common.sh"

fail() {
    log "not loaded: $*"
    count=$(cat "$FAILCOUNT" 2>/dev/null || echo 0)
    count=$((count + 1))
    echo "$count" > "$FAILCOUNT"
    if [ "$count" -ge "$MAXFAIL" ]; then
        log "failed $count times in a row, disabling; remove $MODDIR/disable and $FAILCOUNT after fixing"
        touch "$MODDIR/disable"
        set_description "⛔ 连续 $count 次加载失败，已自动禁用：$* · 修复后删除 disable 与 fail-count"
    else
        set_description "❌ 未加载（$(date '+%m-%d %H:%M')）：$* · 失败 $count/$MAXFAIL · 点「动作」可重试"
    fi
    exit 0
}

: > "$LOG"
log "start"
set_description "⏳ 开机加载中…"

if loaded; then
    log "already loaded: $(cat /sys/module/$NAME/parameters/stats 2>/dev/null)"
    describe_loaded
    exit 0
fi

if reason=$(load_module); then
    log "loaded: $(cat /sys/module/$NAME/parameters/capture_all 2>/dev/null) $(cat /sys/module/$NAME/parameters/stats 2>/dev/null)"
    rm -f "$FAILCOUNT"
    describe_loaded
    exit 0
fi
fail "$reason"
