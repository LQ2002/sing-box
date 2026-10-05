# udp_gso_probe

What one downlink UDP datagram costs on the TC data plane's write-back path,
and how much batching / UDP GSO would save. Read-only with respect to
sing-box: the probe opens its own sockets and never touches the running
service.

## Why this was measured (2026-10-05)

A sing-box CPU profile on the daily phone (SM8850, kernel 6.12.69-android16,
Ref_sing-box `b629fa643`) during a full-speed Chrome download over QUIC through
a Shadowsocks 2022 UDP outbound:

- 61% of sing-box CPU was inside syscalls; `tcPacketWriter.WritePacket` →
  `sendto` alone was ~46%. AES-GCM was 3.5%, GC ~5%. So PGO (Go code only)
  and BOLT (incompatible with Go's pclntab) were rejected.
- simpleperf with kernel stacks (20 s, ~18k downlink datagrams/s,
  `/proc/net/snmp` Udp in 43k/s out 25k/s): kernel 63% of samples.
  Inclusive: `__arm64_sys_sendto` 37%, `ip_output` 30.6%, `nf_hook_slow`
  14.4% (`ipt_do_table` 10%, Android netd's iptables), inline softirq
  `net_rx_action` 13.4% → `ip_rcv` 11.6% → `udp_rcv` 5.2%, wakeups 4.9%,
  `dev_queue_xmit_nit` + `tpacket_rcv` 2.3%.
- The `tpacket_rcv` share is a vendor service, not sing-box: Qualcomm WLAN
  logging `vendor.tcpdump` (`/vendor/bin/tcpdump -i any -s 134`, started by
  init when `persist.vendor.tcpdump.enable=true`,
  `/vendor/etc/init/hw/init.target.rc:639-672`) copies every packet on every
  interface, loopback included. `vendor.cnss_diag` runs alongside and wrote
  462 MB of logs under `/data/vendor/wlan_logs`. Not changed; the user decides.

An earlier conclusion (commit `6dc97eda`, "measure downlink UDP rate and
conclude GSO is not worth it") measured ~500 datagrams/s while watching
video. It still holds at that rate; a saturated QUIC download is ~35x higher.

## Probe

`main.go` reproduces `newTCUDPReplySocket`: an `IP_TRANSPARENT` socket bound
to a foreign source sends 1350-byte datagrams to a receiver bound on the
wlan0 address, so each datagram takes ip_output → netfilter → loopback →
inline softirq → ip_rcv → netfilter → udp_rcv inside the sender's syscall.
Paced in 1 ms ticks; CPU = process utime+stime (and, separately, system-wide
softirq) per datagram the receiver actually got.

Build in WSL: `CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build ./experimental/udp_gso_probe`;
run as root with `taskset 10` (one performance core).

## Results (2026-10-05, idle phone, sing-box running but idle)

ns per delivered datagram, process CPU (in brackets: plus system softirq):

| mode | batch | pps | receiver no GRO | receiver UDP_GRO |
|---|---|---|---|---|
| sendto (today) | 1 | 20k | 16 875 (22 500) | 16 938 (22 625) |
| UDP_SEGMENT | 4 | 20k | 11 375 (15 125) | 8 125 (10 312) |
| UDP_SEGMENT | 16 | 32k | 7 656 (9 961) | 3 672 (4 492) |

- GSO with 4 datagrams per call cuts ~33% (no receiver GRO) to ~52% (with);
  16 per call cuts ~55% to ~78%. Netfilter, routing, the vendor packet tap
  and loopback xmit run once per GSO skb instead of once per datagram.
- The `mmsg` rows of the raw log are not sendmmsg: `golang.org/x/net/ipv4`
  `WriteBatch` (batch.go:112) switches on `runtime.GOOS == "linux"`, which is
  `"android"` on the phone, and silently sends one message per call. sing's
  own batch writer is unaffected (build tag `linux` covers android).
- Whether Chromium enables UDP_GRO on its QUIC sockets was not verified; use
  the no-GRO column as the conservative estimate.

## What it means for sing-box

sing already implements UDP GSO on its batch path:
`github.com/sagernet/sing/common/bufio/packet_batch_offload_linux.go`
(reF1nd fork in Ref_sing-box) coalesces equal-size datagrams to one
destination into `UDP_SEGMENT` sendmmsg entries, disabling itself on
EINVAL/EIO/ENOPROTOOPT/EOPNOTSUPP. `tcPacketWriter.WritePacketBatch` uses it
through the reply socket pool (`protocol/ebpf/udp_state.go:473`). The
profile shows it is never reached: the downlink copy is
`copyPacketWaitWithPool` → `WritePacket`, one datagram at a time, because the
Shadowsocks UDP source yields single packets.

So the open question is batch size, not GSO support: how many downlink
datagrams are already available when one is read. Not measured yet. At
~18k datagrams/s the write-back costs ~0.30 core with sendto; batches of 4
would make it ~0.21, of 16 ~0.14 (no-GRO column).

## Achievable batch size on real traffic (2026-10-05)

Measured with a timing probe in `tcPacketWriter.WritePacket` (Ref_sing-box
branch `claude/udp-batch-measure`, `2f9e854a5` + `1c3d986ee`, deployed for a
few minutes only, then the daily binary was restored). A write that starts
within 10/30 us of the previous write's end found its datagram already
queued; runs of such writes are what an opportunistic batcher would get.

Two minutes of a full-speed Chrome QUIC download (115 283 datagrams; one
earlier 10 s window alone had 74 303):

| run length (30 us threshold) | share of datagrams |
|---|---|
| 1 | 0.8% |
| 2-4 | 6.7% |
| 5-8 | 11.4% |
| 9-16 | 22.6% |
| 17-32 | 32.5% |
| 33-64 | 19.9% |
| >64 | 6.0% |

- Gaps: 83% under 10 us, 6% at 1 ms or more. At a 10 us threshold the
  distribution shifts down a little (9-16: 25%, 17-32: 30%), so the answer
  is not sensitive to the threshold.
- 99.3% of back-to-back pairs (104 441 / 105 153) were GSO-mergeable: same
  reply socket, size not larger than the previous datagram.
- `WritePacketBatch` was called 0 times: the batch/GSO path is dead today.

So about 80% of downlink datagrams arrive in runs of 9 or more. With the
probe's per-datagram costs, batching them would take the write-back from
~16.9 us towards ~7.7 us per datagram (the x16 row), roughly halving its
CPU. At light load (video, ~500 datagrams/s, see 6dc97eda) the absolute
saving is negligible but the batcher adds no latency if it never waits for
more datagrams.
