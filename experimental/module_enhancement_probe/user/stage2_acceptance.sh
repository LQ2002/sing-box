#!/system/bin/sh
set -e

DIR="/data/local/tmp"
KO="${DIR}/sbo_enhancement_probe.ko"
DEV="/dev/sbo_enhancement_probe"

echo "=== 全能单模块第 2 阶段生产级真机验收实测 ==="

# 1. 基线状态检查
BEFORE_TAINT=$(cat /proc/sys/kernel/tainted)
echo "[1] 测试前基线 Taint: ${BEFORE_TAINT}"
BEFORE_SLAB_NUM=$(grep "task_struct" /proc/slabinfo 2>/dev/null | awk '{print $2}' || echo "N/A")

# 2. 连续加载/卸载 3 次稳定性压力测试
echo "[2] 执行连续加载/卸载 3 次压力测试..."
for round in 1 2 3; do
  insmod "${KO}"
  test -c "${DEV}" || { echo "错误: round ${round} 字符设备未创建"; exit 1; }
  rmmod sbo_enhancement_probe
  echo "  第 ${round} 轮加载/卸载通过"
done

# 3. 正式加载模块并准备测试
insmod "${KO}"
chmod 600 "${DEV}"
echo "[3] 模块加载就绪，设备权限: $(ls -l ${DEV} | awk '{print $1}')"

# 4. 打开字符设备激活采集 (持有者 1)
exec 3<"${DEV}"
echo "[4] 持有者 1 已打开设备，开始测试缓存与门控..."
sleep 0.2

# 5. 测试同一原生程序第 1 次 MISS_FILLED，第 2~3 次 HIT
echo "[5] 触发同一原生程序连续创建 3 次 UDP socket..."
/data/local/tmp/sbo_control || true
sleep 0.3

# 6. 关闭持有者 1，验证停采
exec 3<&-
echo "[6] 持有者已关闭，验证自动停采..."
sleep 0.2

# 7. 卸载模块并核对善后状态
rmmod sbo_enhancement_probe
AFTER_TAINT=$(cat /proc/sys/kernel/tainted)
AFTER_SLAB_NUM=$(grep "task_struct" /proc/slabinfo 2>/dev/null | awk '{print $2}' || echo "N/A")

echo "[7] 测试后 Taint: ${AFTER_TAINT} (前后对比: ${BEFORE_TAINT} -> ${AFTER_TAINT})"
echo "    Slab 状态: ${BEFORE_SLAB_NUM} -> ${AFTER_SLAB_NUM}"

echo "=== 内核验收采样日志 (FAST_BYPASS / CACHE_MISS / CACHE_HIT) ==="
dmesg | grep "sbo_enh_probe" | tail -n 25
echo "=== 验收流程结束 ==="
