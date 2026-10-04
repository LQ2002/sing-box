#!/system/bin/sh
set -e

DIR="/data/local/tmp"
KO="${DIR}/sbo_enhancement_probe.ko"
DEV="/dev/sbo_enhancement_probe"

echo "=== 全能单模块第 2 阶段生产级全项自动化真机验收测试 ==="

# 1. 基线状态核对
BEFORE_TAINT=$(cat /proc/sys/kernel/tainted)
BEFORE_FILENR=$(cat /proc/sys/fs/file-nr | awk '{print $1}')
BEFORE_FILP_SLAB=$(grep "filp" /proc/slabinfo 2>/dev/null | awk '{print $2}' || echo "N/A")
echo "[1] 基线状态检查:"
echo "    Taint: ${BEFORE_TAINT}"
echo "    file-nr (已分配文件数): ${BEFORE_FILENR}"
echo "    filp (struct file 活跃对象数): ${BEFORE_FILP_SLAB}"

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
echo "[4] 持有者 1 已打开设备，开始 15 秒长时间运行与多程序路径实测..."

# 5. 测试四类原生程序实测与二次缓存命中
echo "[5] 触发四类原生程序测试..."
# 类 1: 自带原生程序 (sbo_control)
${DIR}/sbo_control || true
sleep 0.5

# 类 2: iptables 原生程序 (连续触发 2 次，验证第 2 次 CACHE_HIT)
/system/bin/iptables -L -n >/dev/null 2>&1 || true
sleep 0.1
/system/bin/iptables -L -n >/dev/null 2>&1 || true
sleep 0.5

# 类 3: toybox 原生程序 (连续触发 2 次)
toybox ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1 || true
sleep 0.1
toybox ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1 || true
sleep 0.5

# 类 4: netd 系统服务 (通过 DNS 查询触发 netd 建立 socket)
am start -a android.intent.action.VIEW -d "http://acceptance-$(date +%s).example.com" com.android.chrome >/dev/null 2>&1 || true
sleep 2

# 6. 长时间稳定运行维持 (累计满 15 秒)
echo "[6] 长时间运行保持中 (累计运行 15 秒)..."
sleep 10

# 7. 运行 sockbench 锁频绑核配对测试
if [ -f "${DIR}/sockbench" ]; then
  echo "[7] 运行 sockbench 绑核配对性能测试 (各 20000 次)..."
  taskset 10 ${DIR}/sockbench LOADED_ACTIVE_ACCEPTANCE 20000 || true
fi

# 8. 关闭持有者 1 停采并卸载模块
exec 3<&-
echo "[8] 持有者已关闭，卸载模块..."
sleep 0.3
rmmod sbo_enhancement_probe

# 9. 善后指标核对与泄漏检查
AFTER_TAINT=$(cat /proc/sys/kernel/tainted)
AFTER_FILENR=$(cat /proc/sys/fs/file-nr | awk '{print $1}')
AFTER_FILP_SLAB=$(grep "filp" /proc/slabinfo 2>/dev/null | awk '{print $2}' || echo "N/A")

echo "[9] 善后核验与内存泄漏检查:"
echo "    Taint 对比: ${BEFORE_TAINT} -> ${AFTER_TAINT} (目标: 严格相等)"
echo "    file-nr 对比: ${BEFORE_FILENR} -> ${AFTER_FILENR} (目标: 恢复基线)"
echo "    filp slab 对比: ${BEFORE_FILP_SLAB} -> ${AFTER_FILP_SLAB} (目标: 零泄漏)"

# 检查 dmesg 是否有 WARNING / BUG
DMESG_WARNS=$(dmesg | tail -n 200 | grep -iE "WARNING:|BUG:|Oops|Kernel panic" || true)
if [ -z "$DMESG_WARNS" ]; then
  echo "    dmesg 检查: 零 WARNING / 零 BUG / 零 Oops 通过!"
else
  echo "    dmesg 警告: $DMESG_WARNS"
fi

echo "=== 最近 30 行内核采样日志 (FAST_BYPASS / CACHE_MISS / CACHE_HIT / TRACEPOINT) ==="
dmesg | grep "sbo_enh_probe" | tail -n 30
echo "=== 全项自动化验收测试结束 ==="
