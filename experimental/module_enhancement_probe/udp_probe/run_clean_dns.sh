#!/system/bin/sh
set -e

# 1. 启动 tcpdump 抓包 53 端口
/system/bin/tcpdump -i any -n "udp port 53" -c 10 > /data/local/tmp/dns_cap.txt 2>&1 &
TCPDUMP_PID=$!
sleep 0.3

# 2. Chrome 前台请求新域名
TSTAMP=$(date +%s)
DOMAIN="clean-chrome-${TSTAMP}.example.com"
am start -a android.intent.action.VIEW -d "http://${DOMAIN}" com.android.chrome >/dev/null 2>&1

# 3. 等待发包
sleep 2

# 4. 结束抓包并输出
kill -9 $TCPDUMP_PID 2>/dev/null || true
echo "=== TCPDUMP RAW OUTPUT ==="
cat /data/local/tmp/dns_cap.txt 2>/dev/null || echo "no capture file"
rm -f /data/local/tmp/dns_cap.txt

# 5. 输出 dumpsys 最近记录
echo "=== RECENT DNSRESOLVER ==="
dumpsys dnsresolver | tail -n 8
