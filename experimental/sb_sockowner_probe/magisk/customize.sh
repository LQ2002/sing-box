#!/system/bin/sh
# 安装期检查。
#
# 刻意**不在这里加载模块**：安装时加载会让"装上就出事"和"开机才出事"混在一起，
# 排查困难。这里只做静态检查并如实报告，真正的加载留给下次开机的 service.sh，
# 那时系统已经起来，失败也不影响使用。
#
# 内核不匹配时不中止安装、只醒目警告并预先禁用：中止安装会让使用者以为
# 什么都没发生，而实际上他需要知道"装了但不会生效，得重新编"。

SKIPUNZIP=0

ui_print ""
ui_print "  sb_sockowner_probe"
ui_print "  socket cookie 到进程归属的诊断模块"
ui_print ""

EXPECTED=$(cat "$MODPATH/kernel-release" 2>/dev/null)
RUNNING=$(uname -r)

ui_print "- 构建针对内核: ${EXPECTED:-（缺失）}"
ui_print "- 当前运行内核: $RUNNING"

if [ -z "$EXPECTED" ]; then
    ui_print "! 包内缺少 kernel-release，无法确认匹配"
    ui_print "! 已预先禁用，不会在开机时加载"
    touch "$MODPATH/disable"
elif [ "$EXPECTED" != "$RUNNING" ]; then
    ui_print ""
    ui_print "! 内核不匹配，本模块不会加载"
    ui_print "! 符号 CRC 绑定于具体的内核构建，换了内核必须重新生成"
    ui_print "! 按 README 重跑这两条命令后重新打包："
    ui_print "!   python refresh-kernel-abi.py <boot.img>"
    ui_print "!   ./rebuild-and-verify.sh <KDIR>"
    ui_print ""
    ui_print "- 已预先禁用，避免每次开机徒劳重试"
    touch "$MODPATH/disable"
else
    ui_print "- 内核匹配"
    ui_print ""
    ui_print "- 本模块只在开机后加载（late_start），"
    ui_print "  失败不会影响开机；日志见 load.log"
    ui_print "- 出问题时开机长按音量减进入 core-only 模式可禁用全部模块"
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755
ui_print ""
