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

## Device A/B of the batcher (2026-10-05)

Ref_sing-box `c56f897eb` (branch `claude/udp-downlink-batching`,
`udp_downlink_batcher.go`) against the daily build, interleaved A B A B,
30 s windows. Load: Ref_sing-box `experimental/h3probe` looping HTTP/3
downloads of a 9 MB file from dl.google.com through the daily config
(Chrome falls back to TCP for a while after every sing-box restart, so it
cannot drive an A/B). Per 100 Mbit/s of wlan0 receive:

| window | Mbit/s | sing-box CPU | system softirq | udp_out/s | downloads |
|---|---|---|---|---|---|
| A round 1 | 85.8 | 38.7% | 16.8% | 11 766 | 35 ok |
| B round 1 | 89.9 | 27.1% | 10.6% | 2 028 | 37 ok |
| A round 2 | 88.0 | 36.1% | 15.9% | 12 069 | 36 ok |
| B round 2 | 78.7 | 33.4% | 12.4% | 2 057 | 30 ok, 1 failed |

- sing-box CPU per 100 Mbit/s: 37.4% -> 30.3% (-19%); system softirq
  16.4% -> 11.5% (-30%); together -22%.
- `Udp OutDatagrams` fell ~5.8x: GSO sends count once per batch, so the
  average batch was ~6 datagrams, smaller than the run lengths measured with
  the timing probe (the drain keeps up, so the queue rarely gets deep).
- Throughput is the proxy server's limit in both builds. Single HTTP/3
  downloads before the A/B: A 82-87 Mbit/s, B 91-97 Mbit/s; google.com,
  youtube.com and cloudflare-quic.com load over HTTP/3 on both.
- One B download in 68 failed (0 of 71 on A). Not reproduced or explained
  yet; a longer run is needed before calling it noise.
- The earlier estimate (-25% to -33% for sing-box) was optimistic because it
  assumed batches near the measured run lengths.

## 50-minute offline soak (2026-10-05, results/soak-20261005.log)

A B A B, 10 min each, same request schedule in every block: an HTTP/3 GET of
google.com every ~3 s and a 9 MB dl.google.com download every 60 s. The user
was out: A-1, B-1 and most of A-2 ran on cellular (rmnet_data3), B-2 on
WiFi.

| block | net | small ok/fail | 9 MB ok/fail | sing-box CPU ticks | udp_out | RSS at end |
|---|---|---|---|---|---|---|
| A-1 | cellular | 158/0 | 10/0 | 786 | 119 362 | 37.3 MB |
| B-1 | cellular | 160/0 | 10/0 | 630 | 21 411 | 60.4 MB |
| A-2 | cellular→WiFi | 154/1 | 10/0 | 755 | 116 798 | 41.8 MB |
| B-2 | WiFi | 164/0 | 9/1 | 544 | 28 199 | 56.8 MB |

- Failures: one per build, both at 12:33-12:35 when the phone moved from
  cellular to WiFi ("no recent network activity": the QUIC path died with the
  network). No failure unrelated to a network change in 343 requests on B.
- sing-box CPU over identical work: A 770 ticks per block on average, B 587
  (-24%). B-1 vs A-1 on the same cellular network: -20%. udp_out fell ~5x
  (GSO batches).
- System softirq barely moved (742/722/733/729 ticks): at this load it is
  dominated by other traffic and the modem path.
- Receive bytes on cellular read 0: rmnet_data3's /proc/net/dev counters stay
  at zero on this phone (Qualcomm IPA offload), so throughput normalisation
  works on WiFi only.
- RSS at the end of each block: A 37-42 MB, B 57-60 MB. One sample per
  block, taken at an arbitrary point of a download cycle; earlier A runs read
  47-53 MB during downloads, so this may be noise, but it is consistent
  across both B blocks and must be measured properly (repeated samples, heap
  profile) before B goes into the daily build.
