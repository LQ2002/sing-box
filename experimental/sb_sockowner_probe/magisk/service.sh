#!/system/bin/sh
# 开机加载 sb_sockowner_probe。
#
# 本脚本的每一处设计都来自同一条教训：IPSET_LKM 的 service.sh 每次开机无条件
# 加载 21 个内核模块，而它的加载器靠改写符号绕过了 vermagic 校验；内核一升级，
# 模块被强行链接到错误的符号地址，直接 bootloop，只能靠卸载模块才能开机。
#
# 所以这里的原则是：
#
#   1. 只用普通 insmod，绝不强制。insmod 会校验符号 CRC，不匹配就干净失败，
#      这道保险是安全的来源，不是要绕开的障碍。
#   2. 加载前先比对内核版本串。带 CRC 的模块在 same_magic() 里会跳过 vermagic
#      的版本号部分，所以内核换代时 insmod 未必拦得住，需要这一道显式检查。
#   3. 跑在 service.sh（late_start）而非 post-fs-data：即使这里出任何问题，
#      系统已经起来了，不会影响开机。
#   4. 任何路径都 exit 0，绝不让失败向上传播。
#   5. 连续失败就自我禁用，不让每次开机都重试一个已知不匹配的模块。
#
# 出问题时的逃生手段：开机时长按音量减进入 Magisk core-only 模式，所有模块
# 都不会加载。

MODDIR=${0%/*}
LOG=$MODDIR/load.log
FAILCOUNT=$MODDIR/fail-count
MAXFAIL=3

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"
}

# 无论走到哪个分支都不要让失败冒出去。
fail() {
    log "未加载: $*"
    count=$(cat "$FAILCOUNT" 2>/dev/null || echo 0)
    count=$((count + 1))
    echo "$count" > "$FAILCOUNT"
    if [ "$count" -ge "$MAXFAIL" ]; then
        log "已连续失败 ${count} 次，自我禁用；修好后删除 $MODDIR/disable 与 $FAILCOUNT"
        touch "$MODDIR/disable"
    fi
    exit 0
}

: > "$LOG"
log "开始"

# 已经加载过就什么都不做（例如手动 insmod 过）。
if [ -d /sys/module/sb_sockowner_probe ]; then
    log "已在内核中，跳过"
    exit 0
fi

KO=$MODDIR/sb_sockowner_probe.ko
[ -f "$KO" ] || fail "找不到 $KO"

# --- 内核版本比对 -----------------------------------------------------------
EXPECTED=$(cat "$MODDIR/kernel-release" 2>/dev/null)
RUNNING=$(uname -r)
if [ -z "$EXPECTED" ]; then
    fail "包内缺少 kernel-release，无法确认模块与本机内核匹配"
fi
if [ "$EXPECTED" != "$RUNNING" ]; then
    log "内核不匹配"
    log "  构建针对: $EXPECTED"
    log "  当前运行: $RUNNING"
    fail "内核已更换，需要按 README 重新生成 ABI 基准并重编模块"
fi

# --- 加载 -------------------------------------------------------------------
# 普通 insmod：CRC 或 vermagic 不符时它会拒绝，这正是我们要的行为。
if ERR=$(insmod "$KO" 2>&1); then
    log "加载成功"
    log "  $(cat /proc/sb_sockowner_probe 2>/dev/null | tr '\n' ' ')"
    rm -f "$FAILCOUNT"
    exit 0
fi

fail "insmod 失败: $ERR"
