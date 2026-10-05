P=$(pidof sing-box)
a=$(awk '{print $14+$15}' /proc/$P/stat); sleep 3; b=$(awk '{print $14+$15}' /proc/$P/stat)
echo "sing-box background ticks in 3s: $((b-a))"
IP=$(ip -4 -o addr show wlan0 | awk '{split($4,x,"/"); print x[1]}')
echo "wlan0=$IP"
B=/data/local/tmp/udp-gso-probe
for gro in false true; do
  for spec in "single 1" "mmsg 4" "mmsg 16" "gso 4" "gso 16"; do
    set -- $spec
    taskset 10 $B -dst $IP -mode $1 -batch $2 -pps 20000 -duration 8s -gro=$gro 2>&1 | grep -E "RESULT|ERROR"
  done
done
