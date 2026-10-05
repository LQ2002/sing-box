#!/system/bin/sh
# Action button (KernelSU/SukiSU/Magisk manager): load or unload sbo_identity
# for the running boot. Booting again follows the manager's enable switch and
# service.sh as usual.
#
# Unload refuses while sing-box is running with the socket_creator collector:
# the collector's BPF link holds the module (rmmod would fail anyway), and
# turning capture_all off under it would silently stop the snapshots its
# attribution relies on. Stop sing-box first. With sing-box stopped, stale
# collector pins are removed before capture_all=0 and rmmod (README order).
#
# Load runs the same kernel release and BTF checks as service.sh.

MODDIR=${0%/*}
. "$MODDIR/common.sh"

if loaded; then
    echo "sbo_identity 当前：已加载（$(stats_summary)）"
    if singbox_running && collector_active; then
        echo "sing-box 正在使用本模块（socket_creator），已取消卸载。"
        echo "请先停止 sing-box，再点「动作」卸载。"
        describe_loaded stats
        exit 0
    fi
    echo "正在卸载…"
    if reason=$(unload_module); then
        log "unloaded by action"
        echo "✔ 已卸载。本次开机内保持卸载，重启后按模块开关自动加载。"
        set_description "⏸ 已手动卸载（$(date '+%m-%d %H:%M')）· 点「动作」重新加载"
    else
        log "action unload failed: $reason"
        echo "✘ 卸载失败：$reason"
        if loaded; then describe_loaded stats; fi
    fi
    exit 0
fi

echo "sbo_identity 当前：未加载"
echo "正在校验内核并加载…"
if reason=$(load_module); then
    log "loaded by action: $(cat /sys/module/$NAME/parameters/stats 2>/dev/null)"
    # Undo service.sh's self-disable (it wrote `disable` after MAXFAIL
    # failures); a disable set by the user from the manager is left alone.
    if [ "$(cat "$FAILCOUNT" 2>/dev/null || echo 0)" -ge "$MAXFAIL" ] && [ -f "$MODDIR/disable" ]; then
        rm -f "$MODDIR/disable"
        echo "已撤销之前因连续失败而设的自动禁用，下次开机会正常加载。"
    fi
    rm -f "$FAILCOUNT"
    echo "✔ 已加载（capture_all=1）。"
    if singbox_running; then
        echo "提示：sing-box 已在运行，它只在启动时打开 collector，需重启 sing-box 才会使用本模块。"
    fi
    describe_loaded
else
    log "action load failed: $reason"
    echo "✘ 加载失败：$reason"
    set_description "❌ 未加载（$(date '+%m-%d %H:%M')）：$reason · 点「动作」可重试"
fi
exit 0
