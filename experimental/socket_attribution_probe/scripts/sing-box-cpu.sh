p=$(pidof sing-box)
set -- $(cut -d' ' -f14,15 /proc/$p/stat); u0=$(( $1 + $2 ))
r0=$(grep wlan0 /proc/net/dev | tr -s ' ' | cut -d' ' -f3)
sleep 20
set -- $(cut -d' ' -f14,15 /proc/$p/stat); u1=$(( $1 + $2 ))
r1=$(grep wlan0 /proc/net/dev | tr -s ' ' | cut -d' ' -f3)
echo "sing_box_ticks=$(( u1 - u0 )) wlan0_rx_bytes=$(( r1 - r0 ))"
