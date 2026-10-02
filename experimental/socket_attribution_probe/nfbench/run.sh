# A/B: netfilter traversal cost for a marked root UDP socket to a local address.
B=/data/local/tmp/sbo-nfbench; M=0x5b0b0; IP=$(ip -4 addr show wlan0 | grep -o 'inet [0-9.]*' | cut -d' ' -f2)
RULES="raw:PREROUTING raw:OUTPUT mangle:PREROUTING mangle:INPUT mangle:OUTPUT mangle:POSTROUTING nat:OUTPUT nat:POSTROUTING filter:INPUT filter:OUTPUT"
for r in 1 2 3; do $B 200000 0 $IP; done
for tc in $RULES; do iptables -w -t ${tc%%:*} -I ${tc##*:} 1 -m mark --mark $M -j ACCEPT; done
for r in 1 2 3; do $B 200000 $M $IP; done
for tc in $RULES; do iptables -w -t ${tc%%:*} -D ${tc##*:} -m mark --mark $M -j ACCEPT; done
echo "leftover rules with test mark: $(iptables-save | grep -c 0x5b0b0)"
