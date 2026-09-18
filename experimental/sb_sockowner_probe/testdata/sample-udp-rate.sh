#!/system/bin/sh
# 采样 UDP 收发速率与 sing-box 的下行系统调用开销，用来判断"下行逐包 sendto
# 是不是真瓶颈"。
#
# 背景：eBPF 数据面的下行回写是 protocol/ebpf/tc_connection.go 里的
# socket.WriteToUDPAddrPort()，每个 UDP 包一次 sendto，既没有 UDP_SEGMENT
# 也没有 sendmmsg。QUIC 是高包率小包，理论上会被这条路径限制。
#
# 但"理论上"不等于"实际上"。先测清楚再决定要不要动架构：
#
#   - 下行包率上不去（比如只有几千/秒）  -> 不是瓶颈，这条线到此为止
#   - 包率很高且 sendto 占 CPU 可观      -> 才值得考虑 UDP_SEGMENT
#
# ---------------------------------------------------------------------------
# 结论（2026-09-12 真机实测，不必重测）：**下行 GSO 不值得做。**
#
# 刷视频等 QUIC 大流量时的实测数据：
#
#   峰值   6973 报文 / 14 秒 ≈ 498 包/秒
#   常态   2000~3000 / 14 秒 ≈ 150~215 包/秒
#   sing-box 内核态 CPU  每 14 秒 15~29 个 tick，约一个核的 1~2%
#
# 比"值得上 UDP_SEGMENT"的量级低两个数量级。在 500 包/秒上省系统调用，属于
# 为不存在的瓶颈增加复杂度，还要承担本机交付路径上分段行为的不确定性。
#
# 注意一个测量偏差：脚本是 sleep INTERVAL 加循环体耗时，而 sb_pid() 每轮要扫
# 一遍 /proc，手机上实际间隔约 14 秒而非 10 秒，所以 out_per_sec 那一列系统性
# 高估约 40%。上面的换算已按真实间隔做过修正。要更准的话把 INTERVAL 调大，
# 相对误差会变小。
# ---------------------------------------------------------------------------
#
# 用法：
#   nohup sh sample-udp-rate.sh > /dev/null 2>&1 &
#   ...刷十分钟视频或其他 QUIC 大流量...
#   cat /sdcard/sbo-udp-rate.csv
#   pkill -f sample-udp-rate.sh
#
# 列含义（均为区间增量，不是累计值）：
#   out_datagrams  本机发出的 UDP 报文数。sing-box 的下行回写计入这里。
#   in_datagrams   本机收到的 UDP 报文数。
#   out_per_sec    下行包率，判断是否值得优化的主要依据。

OUT=${1:-/sdcard/sbo-udp-rate.csv}
INTERVAL=${2:-10}

# /proc/net/snmp 的 Udp 段是两行：表头一行、数值一行，按列对应。
udp_field() {
    awk -v want="$1" '
        $1 == "Udp:" && header == "" { for (i = 2; i <= NF; i++) name[i] = $i; header = 1; next }
        $1 == "Udp:" { for (i = 2; i <= NF; i++) if (name[i] == want) print $i }
    ' /proc/net/snmp
}

sb_pid() {
    # 用 /proc/<pid>/comm 精确匹配进程名，不要拿 cmdline 做子串匹配：
    # 仓库路径里就含 "sing-box"（ebpf_sing-box），那样会把本脚本自己也匹配上。
    for p in /proc/[0-9]*; do
        [ -r "$p/comm" ] || continue
        [ "$(cat "$p/comm" 2>/dev/null)" = "sing-box" ] || continue
        basename "$p"
        return
    done
}

[ -f "$OUT" ] || echo "timestamp,out_datagrams,in_datagrams,out_per_sec,sb_pid,sb_utime,sb_stime" > "$OUT"

prev_out=$(udp_field OutDatagrams)
prev_in=$(udp_field InDatagrams)
prev_utime=0
prev_stime=0

while :; do
    sleep "$INTERVAL"

    out=$(udp_field OutDatagrams)
    in=$(udp_field InDatagrams)
    [ -n "$out" ] || continue

    d_out=$((out - prev_out))
    d_in=$((in - prev_in))
    rate=$((d_out / INTERVAL))
    prev_out=$out
    prev_in=$in

    # sing-box 的 CPU 时间（时钟滴答）。下行 sendto 的开销体现在 stime 上。
    pid=$(sb_pid)
    utime=0
    stime=0
    if [ -n "$pid" ] && [ -r "/proc/$pid/stat" ]; then
        # 从最后一个 ')' 之后切分：进程名可以含空格和右括号。
        # 切分后首个 token 是 stat 的第 3 字段（state），所以 token 编号 = 字段号 - 2：
        # utime 是第 14 字段 -> token 12，stime 是第 15 字段 -> token 13。
        # 必须写 ${12} 而非 $12x 形式的 $11/$12——POSIX shell 里 $11 解析为 ${1}1。
        set -- $(sed 's/.*) //' "/proc/$pid/stat")
        utime=${12}
        stime=${13}
    fi
    d_utime=$((utime - prev_utime))
    d_stime=$((stime - prev_stime))
    [ "$d_utime" -lt 0 ] && d_utime=0      # 进程重启会让计数倒退
    [ "$d_stime" -lt 0 ] && d_stime=0
    prev_utime=$utime
    prev_stime=$stime

    echo "$(date '+%Y-%m-%d %H:%M:%S'),$d_out,$d_in,$rate,${pid:-0},$d_utime,$d_stime" >> "$OUT"
done
