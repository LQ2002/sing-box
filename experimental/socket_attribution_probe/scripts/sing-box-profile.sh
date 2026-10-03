p=$(pidof sing-box)
set -- $(cut -d' ' -f14,15 /proc/$p/stat); u0=$(( $1 + $2 ))
r0=$(grep wlan0 /proc/net/dev | tr -s ' ' | cut -d' ' -f3); t0=$(grep wlan0 /proc/net/dev | tr -s ' ' | cut -d' ' -f11)
simpleperf record -p $p --call-graph fp -f 2000 --duration 20 -o /data/local/tmp/sbo-perf.data >/dev/null 2>&1
set -- $(cut -d' ' -f14,15 /proc/$p/stat); u1=$(( $1 + $2 ))
r1=$(grep wlan0 /proc/net/dev | tr -s ' ' | cut -d' ' -f3); t1=$(grep wlan0 /proc/net/dev | tr -s ' ' | cut -d' ' -f11)
echo "sing_box_ticks=$(( u1 - u0 )) wlan0_rx_bytes=$(( r1 - r0 )) wlan0_tx_bytes=$(( t1 - t0 ))"
echo ===DSO
simpleperf report -i /data/local/tmp/sbo-perf.data --sort dso 2>/dev/null | head -20
echo ===SELF
simpleperf report -i /data/local/tmp/sbo-perf.data --sort dso,vaddr_in_file,symbol --percent-limit 0.3 2>/dev/null | head -90
echo ===CHILDREN
simpleperf report -i /data/local/tmp/sbo-perf.data --children --sort dso,vaddr_in_file,symbol --percent-limit 2 2>/dev/null | head -90
