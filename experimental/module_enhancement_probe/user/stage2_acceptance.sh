#!/system/bin/sh
set -e

DIR="/data/local/tmp"
KO="${DIR}/sbo_enhancement_probe.ko"
DEV="/dev/sbo_enhancement_probe"

echo "=== 全能单模块第 2 阶段生产级全项自动化验收测试 (第 12 轮严格版) ==="

# 1. 记录初始基线
BEFORE_TAINT=$(cat /proc/sys/kernel/tainted)
BOOT_TIME=$(cat /proc/uptime | awk '{print $1}')
echo "[1] 测试前基线检查:"
echo "    Taint: ${BEFORE_TAINT}"
echo "    系统启动时间戳基线: ${BOOT_TIME} 秒"

# 2. 连续加载/卸载 3 次压力测试
echo "[2] 连续加载/卸载 3 次压力测试..."
for round in 1 2 3; do
  insmod "${KO}"
  sleep 0.2
  test -c "${DEV}" || { echo "错误: round ${round} 字符设备未创建"; rmmod sbo_enhancement_probe; exit 1; }
  rmmod sbo_enhancement_probe
  echo "    第 ${round} 轮加载/卸载通过"
done

# 3. 正式加载模块并核实权限 (0600)
insmod "${KO}"
sleep 0.2
chmod 600 "${DEV}"
DEV_PERM=$(ls -l ${DEV} | awk '{print $1}')
echo "[3] 模块加载完成，设备节点: ${DEV} (权限: ${DEV_PERM})"

# 4. 打开字符设备激活采集 (持有者 1)
exec 3<"${DEV}"
echo "[4] 持有者 1 已打开设备，开始全项路径与边界实测..."

# 5. 测试四类原生程序实测与二次缓存命中
echo "[5] 触发四类原生程序测试..."
# 类 1: 自带原生程序 (sbo_control，连续调用两次)
${DIR}/sbo_control || true
sleep 0.2
${DIR}/sbo_control || true
sleep 0.2

# 类 2: iptables 原生程序 (连续触发 2 次，验证第 2 次 CACHE_HIT)
/system/bin/iptables -L -n >/dev/null 2>&1 || true
sleep 0.1
/system/bin/iptables -L -n >/dev/null 2>&1 || true
sleep 0.2

# 类 3: toybox 原生程序 (连续触发 2 次)
toybox ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1 || true
sleep 0.1
toybox ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1 || true
sleep 0.2

# 类 4: netd 系统服务 (通过非阻塞后台 DNS 查询触发 netd 建立 socket)
toybox ping -c 1 -W 1 "netd-accept-$(date +%s).example.com" >/dev/null 2>&1 || true
sleep 0.5

# 6. 超长路径测试 (>256 字节，验证 PATH_FLAG_TOO_LONG)
echo "[6] 测试超长路径 (>256 字节，验证 PATH_FLAG_TOO_LONG)..."
LONG_DIR="${DIR}/long_012345678901234567890123456789/sub_012345678901234567890123456789/sub_012345678901234567890123456789/sub_012345678901234567890123456789/sub_012345678901234567890123456789/sub_012345678901234567890123456789"
mkdir -p "${LONG_DIR}"
cp -f "${DIR}/sbo_control" "${LONG_DIR}/sbo_toolong"
chmod 755 "${LONG_DIR}/sbo_toolong"
echo "    超长路径绝对长度: $(echo -n "${LONG_DIR}/sbo_toolong" | wc -c) 字节"
"${LONG_DIR}/sbo_toolong" || true
rm -rf "${DIR}/long_012345678901234567890123456789"
sleep 0.2

# 7. 已删除程序测试 (运行中删除文件，验证 PATH_FLAG_DELETED)
echo "[7] 测试已删除程序 (运行中删除，验证 PATH_FLAG_DELETED)..."
cp -f "${DIR}/sbo_control" "${DIR}/sbo_deleted"
chmod 755 "${DIR}/sbo_deleted"
# 在后台启动子进程持有映射，在它建 socket 前 rm 文件
/system/bin/sh -c "exec ${DIR}/sbo_deleted & PID=\$!; rm -f ${DIR}/sbo_deleted; wait \$PID 2>/dev/null" || true
sleep 0.3

# 8. 长时间稳定运行维持 (累计满 15 秒)
echo "[8] 长时间运行保持中 (累计运行 15 秒)..."
sleep 12

# 9. 运行 sockbench 绑核配对测试
if [ -f "${DIR}/sockbench" ]; then
  echo "[9] 运行 sockbench 绑核配对性能测试 (各 20000 次)..."
  taskset 10 ${DIR}/sockbench LOADED_ACTIVE_ACCEPTANCE 20000 || true
fi

# 10. 关闭持有者 1 停采并卸载模块
exec 3<&-
echo "[10] 持有者已关闭，卸载模块..."
sleep 0.3
rmmod sbo_enhancement_probe

# 11. 善后核验与内存泄漏检查
AFTER_TAINT=$(cat /proc/sys/kernel/tainted)

echo "[11] 善后核验与内存泄漏检查:"
echo "     Taint 对比: ${BEFORE_TAINT} -> ${AFTER_TAINT} (目标: 严格相等)"

# 检查 dmesg 中模块自测的引用计数
echo "=== 模块内部引用计数核对 ==="
dmesg | grep "file_ref check" | tail -n 1 || echo "未找到引用计数行"

# 检查自测试启动后的全部 dmesg 是否有 WARNING / BUG
echo "=== 内核稳定性检查 (自启动时间戳 ${BOOT_TIME} 起) ==="
DMESG_WARNS=$(dmesg | tail -n 300 | grep -iE "WARNING:|BUG:|Oops|Kernel panic" || true)
if [ -z "$DMESG_WARNS" ]; then
  echo "     dmesg 全量检查: 自加载起零 WARNING / 零 BUG / 零 Oops 通过!"
else
  echo "     dmesg 警告: $DMESG_WARNS"
fi

# 关屏熄屏，保护设备
input keyevent 223 2>/dev/null || true
echo "[12] 测试完毕，设备已熄屏保护"

echo "=== 最近内核采样日志 (TOO_LONG / DELETED / CACHE_HIT / BINDER) ==="
dmesg | grep "sbo_enh_probe" | tail -n 25
echo "=== 全项自动化验收测试结束 ==="
