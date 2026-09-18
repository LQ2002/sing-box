#!/bin/sh
# 把已验证的模块打成 Magisk 包。
#
#   ./pack.sh [输出.zip]
#
# 这个脚本是"验证通过前绝不放进开机路径"这条纪律的实际执行点：它在打包前重跑
# 符号 CRC 校验，不通过就拒绝出包。光靠人记得是不够的——IPSET_LKM 的 bootloop
# 正是因为一个与内核不匹配的模块被放进了开机加载路径。
#
# 打出来的包本身还有三道防线，见 magisk/service.sh 顶部的说明：只用普通
# insmod、开机前比对内核版本串、失败绝不阻塞开机。

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
KO="$HERE/sb_sockowner_probe.ko"
SYMVERS="$HERE/target/Module.symvers.device"
RELEASE_FILE="$HERE/target/kernel-release"
OUT="${1:-$HERE/sb_sockowner_probe-magisk.zip}"

echo "== 1. 前置检查 =="
[ -f "$KO" ] || { echo "缺少 $KO，请先跑 rebuild-and-verify.sh"; exit 2; }
[ -f "$SYMVERS" ] || { echo "缺少 $SYMVERS，请先跑 refresh-kernel-abi.py"; exit 2; }
[ -f "$RELEASE_FILE" ] || {
    echo "缺少 $RELEASE_FILE。"
    echo "它由 refresh-kernel-abi.py 生成，包用它在开机前比对内核；没有它就无法"
    echo "保证模块与运行中的内核匹配，因此拒绝出包。"
    exit 2
}
command -v zip >/dev/null || { echo "缺少 zip 命令"; exit 2; }

RELEASE=$(cat "$RELEASE_FILE")
echo "   模块       $(stat -c%s "$KO") 字节"
echo "   目标内核   $RELEASE"

# --- 打包前重新校验，不通过就拒绝出包 ---------------------------------------
echo "== 2. 符号 CRC 校验 =="
if ! python3 "$HERE/verify-ko.py" "$KO" "$SYMVERS"; then
    echo
    echo "   拒绝出包：模块的符号 CRC 与目标内核不一致。"
    echo "   装上这样的包，开机时 insmod 会失败（这是好事，保险在起作用），"
    echo "   但把不匹配的东西放进开机路径本身就不该发生。"
    echo "   请先跑 refresh-kernel-abi.py 与 rebuild-and-verify.sh。"
    exit 1
fi

# --- 组装 -------------------------------------------------------------------
echo "== 3. 组装 =="
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

# 文本文件一律剥掉 \r 再放进包里，不要用 cp。
#
# 这一步是必须的，不是洁癖：Windows 检出（core.autocrlf）下这些脚本在工作区里
# 是 CRLF，原样打进包后装到机器上，sh 会把行尾的 \r 当成命令的一部分，报出来是
# ": not found" 和 "syntax error: unexpected elif"，安装直接失败，而错误信息完全
# 指不到真正的原因。仓库里的 .gitattributes 已经强制 LF 检出，这里再剥一次是因为
# 别人的检出不一定生效。
for f in service.sh customize.sh uninstall.sh module.prop; do
    tr -d '\r' < "$HERE/magisk/$f" > "$STAGE/$f"
done
cp "$KO" "$STAGE/"
tr -d '\r' < "$RELEASE_FILE" > "$STAGE/kernel-release"

# 剥干净了才放行。漏一个 \r 的代价是装到机器上才发现。
CR=$(printf '\r')
for f in service.sh customize.sh uninstall.sh module.prop kernel-release; do
    if LC_ALL=C grep -q "$CR" "$STAGE/$f"; then
        echo "   拒绝出包：$f 里仍有 CR，剥离失败"
        exit 1
    fi
done

# 版本号带上内核版本串与模块摘要：一眼能看出这个包是给哪个内核的，
# 也能区分同一内核上的不同构建。
DIGEST=$(sha256sum "$KO" | cut -c1-8)
sed -i "s|^version=.*|version=${RELEASE} (${DIGEST})|" "$STAGE/module.prop"
sed -i "s|^versionCode=.*|versionCode=$(date +%Y%m%d%H%M)|" "$STAGE/module.prop"

echo "   version=$(grep '^version=' "$STAGE/module.prop" | cut -d= -f2-)"

rm -f "$OUT"
( cd "$STAGE" && zip -q -r "$OUT" . )
echo "   -> $OUT ($(stat -c%s "$OUT") 字节)"

echo
echo "== 完成 =="
echo "在 Magisk 里安装后重启。首次务必确认："
echo "  cat /data/adb/modules/sb_sockowner_probe/load.log"
echo "  ls -l /dev/sb_sockowner_probe"
echo
echo "出问题时开机长按音量减进入 core-only 模式，可禁用全部模块。"
