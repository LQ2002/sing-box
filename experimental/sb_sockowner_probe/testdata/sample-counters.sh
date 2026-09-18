#!/system/bin/sh
# 定期采样 /proc/sb_sockowner_probe，用于观察长时间运行下 owner 表的行为。
#
# 短测（cookietest、stresstest）能覆盖功能与容量边界，但覆盖不了"日常负载下
# 这张表会不会被打满"——那只能靠时间暴露。本脚本就是为这一个问题存在的。
#
# 只需要模块被加载，不需要 sing-box 在跑：钩子挂在 socket() 上，与数据面无关。
#
# 用法：
#   nohup sh sample-counters.sh > /dev/null 2>&1 &
#   ...正常使用设备...
#   cat /sdcard/sbo-counters.csv
#   pkill -f sample-counters.sh
#
# 要看的是 evicted 列：
#   一直 0        —— 容量绰绰有余
#   缓慢增长      —— 偶尔触顶，可接受
#   持续快速增长  —— 调大模块里的 OWNER_MAX，重编后重跑 rebuild-and-verify.sh

PROC=/proc/sb_sockowner_probe
OUT=${1:-/sdcard/sbo-counters.csv}
INTERVAL=${2:-300}

if [ ! -r "$PROC" ]; then
    echo "读不到 $PROC，模块没加载？" >&2
    exit 1
fi

[ -f "$OUT" ] || echo "timestamp,entries,capacity,created_ipv4,created_ipv6,freed,evicted" > "$OUT"

while [ -r "$PROC" ]; do
    # 把 "key value" 的多行输出拍平成一行 CSV。
    line=$(awk -v ts="$(date '+%Y-%m-%d %H:%M:%S')" '
        { value[$1] = $2 }
        END {
            printf "%s,%s,%s,%s,%s,%s,%s\n", ts,
                value["entries"], value["capacity"],
                value["created_ipv4"], value["created_ipv6"],
                value["freed"], value["evicted"]
        }' "$PROC")
    echo "$line" >> "$OUT"
    sleep "$INTERVAL"
done

echo "$PROC 消失，模块已卸载，采样结束" >&2
