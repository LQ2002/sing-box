# conntrack_probe：TC 出口能否用连接跟踪识别“入站连接的回包”（2026-10-05，只读）

问题：sing-ebpf 的 TC 本机出口选流不看 TCP 标志位，手机作为服务端时，回给公网客户端的 SYN-ACK 与后续包
会被当作本机外发连接重定向进 sing-box，握手失败（源码依据见 ANDROID_ATTRIBUTION_PLAN.md“被动连接”一节）。
两个候选判别法：首包是否纯 SYN；或用内核连接跟踪 `bpf_skb_ct_lookup` 查包的方向。

方法：`bpf/ct.bpf.c` 以 TCX 挂在 wlan0 出口最前端，只观察（恒返回 TCX_NEXT）；对每个 IPv4 TCP/UDP 包用包自身
五元组调用 `bpf_skb_ct_lookup`（`net/netfilter/nf_conntrack_bpf.c:394`，为 SCHED_CLS 注册于 :535），命中时
内核把方向写入 `opts->dir`（:226，0=ORIGINAL、1=REPLY），并记录 `skb->sk` 的状态。设备
`CONFIG_NF_CONNTRACK=y`，kfunc 在设备 BTF 中。测试流量：电脑（同一 Wi-Fi）连手机上的 TCP 18080 服务 3 次、
向 UDP 18081 发 3 个包并收回复；手机主动连 1.1.1.1:80 两次。用户自己的生产 sing-box 当时在运行，探针不影响它。

结果（`results/observe-20261005.log`，已删去与测试无关的目的地址）：

- 入站 TCP：每个连接的 SYN-ACK 都挂在请求 socket 上（`sk_state=12`，`TCP_NEW_SYN_RECV`），连接跟踪方向
  **REPLY**；其后的数据、ACK、FIN、RST 全部为 REPLY（子 socket 首包为 `PA`，状态 ESTABLISHED，不是 SYN）。
- 入站 UDP 的回复：3/3 为 **REPLY**。
- 主动外发 TCP：SYN 为 **ORIGINAL**（`sk_state=2`，SYN_SENT）。
- 观察期全部包：TCP ORIGINAL 41、REPLY 22、未命中 1；UDP REPLY 3。
- 代价：67 次查询平均 **1321 ns**（含一对 ktime，52 ns 一刻度；包速很低、缓存冷）。

结论：

1. 连接跟踪能可靠区分入站连接的回包（TCP、UDP 均如此），设备上可直接从 TC 调用。
2. 但每次约 1.3 µs，不适合逐包使用；UDP 没有可缓存的 socket 判定，只能逐包查。
3. TCP 用“首包纯 SYN”判别即可，零查询：被动连接的 SYN-ACK 挂在请求 socket（非 full socket），子 socket
   首包非 SYN；主动连接首包为 SYN。本次数据同时证实了这两条前提。连接跟踪只值得用于 UDP，且需另测
   在真实 UDP 负载下的开销后再定。

构建：`bash build.sh`（WSL，likayo）。运行（root，`su -mm`）：
`./conntrack-probe observe -object ct.bpf.o -iface wlan0 -watch <对端IPv4> -duration 40s`，配合
`tcpserve`/`udpserve`/`tcpdial`。
