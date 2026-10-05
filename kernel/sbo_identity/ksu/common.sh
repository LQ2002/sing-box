#!/system/bin/sh
# Shared by service.sh (boot) and action.sh (the manager's Action button).
# Sourced with MODDIR set to the module directory.
#
# Description: KernelSU (and its forks such as SukiSU Ultra) can override the
# description shown in the manager with
#   ksud module config set override.description <text>
# (kernelsu.org/guide/module-config.html, "Overriding Module Description";
# scripts run with KSU_MODULE set to the module id). Older managers, or a
# Magisk install, do not have that; there the description line of
# module.prop is rewritten instead, which every manager reads.

NAME=sbo_identity
LOG=$MODDIR/load.log
FAILCOUNT=$MODDIR/fail-count
MAXFAIL=3
KO=$MODDIR/$NAME.ko
PINS=/sys/fs/bpf/sing-box/socket-creator-v3
# sing-box binaries that can remove the collector's pins cleanly.
SB_CANDIDATES="/data/adb/services/sing-box/sing-box /data/adb/box/bin/sing-box"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"
}

set_description() {
    text="$1"
    if [ -x /data/adb/ksud ] && KSU_MODULE=${KSU_MODULE:-$NAME} \
        /data/adb/ksud module config set override.description "$text" > /dev/null 2>&1; then
        return 0
    fi
    prop=$MODDIR/module.prop
    [ -f "$prop" ] || return 0
    grep -v '^description=' "$prop" > "$prop.tmp" && \
        echo "description=$text" >> "$prop.tmp" && \
        mv -f "$prop.tmp" "$prop"
}

loaded() { [ -d /sys/module/$NAME ]; }

stats_summary() {
    stats=$(cat /sys/module/$NAME/parameters/stats 2>/dev/null)
    hit=$(echo "$stats" | tr ' ' '\n' | sed -n 's/^hit=//p')
    miss=$(echo "$stats" | tr ' ' '\n' | sed -n 's/^miss=//p')
    skip=$(echo "$stats" | tr ' ' '\n' | sed -n 's/^own_cgroup=//p')
    err=$(echo "$stats" | tr ' ' '\n' | sed -n 's/^error=//p')
    echo "快照 $((${hit:-0} + ${miss:-0})) · 跳过 ${skip:-0} · 错误 ${err:-0}"
}

collector_active() { [ -n "$(ls -A $PINS 2>/dev/null)" ]; }
singbox_running() { [ -n "$(pidof sing-box 2>/dev/null)" ]; }

describe_loaded() {
    set_description "✅ 已加载（$(date '+%m-%d %H:%M')）· 内核与 BTF 校验通过 · $(stats_summary) · 点「动作」可卸载"
}

# check_kernel: returns 0 when the running kernel matches the build; on
# mismatch prints the reason and returns 1.
check_kernel() {
    expected=$(cat "$MODDIR/kernel-release" 2>/dev/null)
    running=$(uname -r)
    if [ -z "$expected" ]; then
        echo "包内缺少 kernel-release"
        return 1
    fi
    if [ "$expected" != "$running" ]; then
        log "  built for: $expected"
        log "  running:   $running"
        echo "内核已更换（需按 README 重新生成布局并重编模块）"
        return 1
    fi
    expected_btf=$(cut -d' ' -f1 "$MODDIR/base-btf.sha256" 2>/dev/null)
    running_btf=$(sha256sum /sys/kernel/btf/vmlinux 2>/dev/null | cut -d' ' -f1)
    if [ -z "$expected_btf" ]; then
        echo "包内缺少 base-btf.sha256"
        return 1
    fi
    if [ "$expected_btf" != "$running_btf" ]; then
        log "  built for BTF: $expected_btf"
        log "  running BTF:   $running_btf"
        echo "内核 BTF 与构建基准不一致"
        return 1
    fi
    return 0
}

# load_module: checks, then plain insmod with capture_all=1. Prints the
# failure reason and returns 1 on failure.
load_module() {
    [ -f "$KO" ] || { echo "找不到 $KO"; return 1; }
    reason=$(check_kernel) || { echo "$reason"; return 1; }
    if err=$(insmod "$KO" capture_all=1 2>&1); then
        return 0
    fi
    echo "insmod 失败：$err"
    return 1
}

# remove_pins: drop a stale collector (sing-box not running). Prefer the
# collector's own remover; fall back to unlinking the pins.
remove_pins() {
    collector_active || return 0
    for sb in $SB_CANDIDATES; do
        if [ -x "$sb" ] && "$sb" tools socket-creator-remove > /dev/null 2>&1; then
            collector_active || return 0
        fi
    done
    rm -f $PINS/* 2> /dev/null
    ! collector_active
}

# unload_module: the README order (collector gone, capture_all=0, rmmod).
unload_module() {
    remove_pins || { echo "无法移除 $PINS 下的 collector pin"; return 1; }
    echo 0 > /sys/module/$NAME/parameters/capture_all 2> /dev/null
    for i in 1 2 3; do
        rmmod $NAME 2> /dev/null && return 0
        sleep 1
    done
    echo "rmmod 失败（模块仍被引用），已关闭 capture_all；重启后不会残留"
    return 1
}
