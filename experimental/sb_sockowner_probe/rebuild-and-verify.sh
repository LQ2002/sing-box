#!/bin/sh
# OTA 之后重建并验证模块。在 Linux/WSL 中运行。
#
#   ./rebuild-and-verify.sh <KDIR>
#
# KDIR 是已 modules_prepare 好的内核构建目录，其源码树版本必须与真机内核的
# sublevel 相同（例如真机 6.12.69 就要 android16-6.12.69_r00）。
#
# 依次做三件事，任何一步不过就停下：
#   1. 装入 target/Module.symvers.device（由 refresh-kernel-abi.py 生成）
#   2. 编译 layout_probe.c —— 结构体布局断言，编不过说明偏移不一致
#   3. 重编模块并逐个核对 CRC
#
# 全绿之后才可以手动 insmod。永远不要在验证通过前把模块放进开机加载路径。

set -eu

KDIR="${1:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SYMVERS="$HERE/target/Module.symvers.device"

[ -n "$KDIR" ] || { echo "用法: $0 <KDIR>"; exit 2; }
[ -f "$KDIR/Makefile" ] || { echo "不是内核构建目录: $KDIR"; exit 2; }
[ -f "$SYMVERS" ] || { echo "缺少 $SYMVERS，请先跑 refresh-kernel-abi.py"; exit 2; }
command -v clang >/dev/null || { echo "PATH 里没有 clang，请先加入 Android Clang 工具链"; exit 2; }

echo "== 0. 环境 =="
echo "   KDIR   $KDIR"
echo "   clang  $(clang --version | head -1)"

echo "== 1. 装入权威符号表 =="
if [ -f "$KDIR/Module.symvers" ] && ! cmp -s "$KDIR/Module.symvers" "$SYMVERS"; then
    cp -a "$KDIR/Module.symvers" "$KDIR/Module.symvers.bak.$(date +%Y%m%d-%H%M%S)"
    echo "   已备份原有 Module.symvers"
fi
cp "$SYMVERS" "$KDIR/Module.symvers"
echo "   $(wc -l < "$KDIR/Module.symvers") 个符号就位"

echo "== 2. 结构体布局验证 =="
PROBE=$(mktemp -d)
trap 'rm -rf "$PROBE"' EXIT
cp "$HERE/layout_probe.c" "$PROBE/"
echo 'obj-m += layout_probe.o' > "$PROBE/Makefile"
if make -C "$KDIR" M="$PROBE" ARCH=arm64 LLVM=1 modules > "$PROBE/log" 2>&1; then
    echo "   $(grep -c '_Static_assert' "$HERE/layout_probe.c") 条断言全部成立"
else
    if grep -q 'static assertion failed' "$PROBE/log"; then
        echo "   布局不一致，以下字段偏移与真机不符："
        grep -A1 'static assertion failed' "$PROBE/log" | grep -oE '"(size|off) [^"]+"' | sort -u
        echo
        echo "   停止。内核源码树与真机内核的结构体布局不同，加载会读到错误内存。"
        echo "   多半是源码树 sublevel 或 .config 不对，修正后重跑。"
        exit 1
    fi
    echo "   构建失败（并非断言问题），完整日志："
    cat "$PROBE/log"
    exit 1
fi

echo "== 3. 重编模块 =="
cd "$HERE"
rm -f sb_sockowner_probe.ko sb_sockowner_probe.o sb_sockowner_probe.mod.o .module-common.o
make KDIR="$KDIR" > /tmp/modbuild.log 2>&1 || { cat /tmp/modbuild.log; exit 1; }
ls -l sb_sockowner_probe.ko

echo "== 4. 逐个核对 CRC =="
# 校验逻辑放在 verify-ko.py 里，与 pack.sh 共用，避免两处各写一份慢慢漂移。
python3 "$HERE/verify-ko.py" "$HERE/sb_sockowner_probe.ko" "$SYMVERS"

echo
echo "== 全部通过 =="
echo "现在可以手动加载（不要写进开机脚本）："
echo "  adb push sb_sockowner_probe.ko /data/local/tmp/"
echo "  adb shell su -c 'insmod /data/local/tmp/sb_sockowner_probe.ko'"
echo "  adb shell su -c 'cat /proc/sb_sockowner_probe'"
echo "  adb shell su -c 'rmmod sb_sockowner_probe'"
