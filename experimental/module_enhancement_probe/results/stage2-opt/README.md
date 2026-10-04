# 第 2 阶段：路径表优化后的验收与逐 socket 开销实测（2026-10-04）

改动（`bpf/consumer.bpf.c`）：每个 socket 的快照从 320 字节缩为 64 字节（与生产 creator 快照同大小），
不再逐 socket 复制 256 字节路径；路径按 `(dev, ino, generation)` 存在 `paths`（LRU_HASH，1024 项）里，
已有则只做一次查表。模块未改（后来只加了默认关闭的 `timing` 参数）。验收工具读快照后按同一键查路径，模拟生产读者。

`run-device.sh` 同时补了上一轮的两个缺口：

- 运行期间把 `/dev/kmsg` 持续写入文件，按标记行之后检查（上一轮 1 小时后环形缓冲区已被冲掉）；
- 仿 `/data/app/~~…==/<包名>-…==/lib/arm64/<名>.so` 的 156 字节路径，用 App UID（10999）运行并建 socket。

## quick（`quick.log`、`offline/quick.log`，两次均全部通过）

- 自测 8000/8000、超长路径 800/800、已删除 800/800、accept 继承 200/200（×3）、unix socket 无快照。
- App UID 原生程序：20 个 socket，uid=10999，路径 156 字节，与 `/proc/<pid>/exe` 一致。
- 全机 watch：11165 个事件 0 不符、0 重复、0 丢弃；`path_insert=9`。
- `get_file_rcu == fput`；内核日志（持续捕获）标记后无告警；taint 4608。

## 1 小时（`offline/long.log`、`offline/watch-long.json`，手机离线正常使用，19:34–20:34）

- 3600 秒，20323 个事件：app 14873 全部正确，native 5450 中 5357 正确、93 个 gone；0 不符、0 重复、
  0 丢弃；`path_insert=8`（一小时只写了 8 次路径）。
- 原生路径：netd、iptables、App 拉起的 `/system/bin/ip`（uid 10356/10410）、ping/ping6、`hyos_spawner`、
  `nicmd`、sing-box，全部正确。`get_file_rcu=42 fput=42`。
- **内核日志**：持续捕获 79734 行，标记后 70549 行（这次是有效检查）。脚本当时以 rc=1 结束，因为匹配到：
  1. 高通 fastrpc 驱动的普通 `Warning:` 文本（大小写不敏感的正则误匹配，不是内核 WARN）；
  2. 一次真正的内核 WARN：`drivers/gpu/drm/drm_vblank.c:1462 drm_crtc_set_max_vblank_count`，
     `crtc_commit` 内核线程，调用栈全部在 `msm_drm`（`sde_crtc_enable` → `complete_commit`），发生在
     息屏指纹触发的 `power mode OFF->LP` 切换时（`offline/drm-warn-excerpt.txt`）。条件是
     `drm_WARN_ON(dev, !READ_ONCE(vblank->inmodeset))`：显示驱动在 vblank 不处于 modeset 时设置
     max_vblank_count。日志中没有任何 `[sbo_enhancement_probe …]` 栈帧；模块只出现在每次 WARN 都会打印的
     “Modules linked in” 列表里。该小时内 `OFF->LP` 共 4 次，WARN 1 次。不加载模块的对照（6 次亮灭屏）
     只触发 1 次 `OFF->LP`、未出现该 WARN，次数太少，不能作为反证；依据是调用栈与触发条件。
  - 已修正检查：只认 `WARNING: CPU|BUG:|Oops|…`（区分大小写），并以是否出现 `[sbo_enhancement_probe`
    栈帧判定是否与模块有关；无关的 WARN 列出但不判失败。

## 用户态 bench（`offline/bench.log`、`bench-idle.log`）：噪声过大，不作结论

两次锁频绑核的 socket()+close() 测量，单轮在 5.5–12 µs 之间波动（手机处于 Doze/正常使用），
三种状态的差异淹没在噪声里。改用下面的内核内计时。

## 内核内逐 socket 开销（`timing*.out`，`acceptance/timing.sh`）

模块参数 `timing`（默认关）测量钩子从进入到返回的时间，包含 tracepoint 同步执行的 BPF 消费端，即每个 socket
额外付出的代价。每个变体新加载模块；负载为绑核 UDP socket()+close() 循环（原生程序、路径缓存命中，约 10 万个）
加上空闲期间手机自身的 App socket。数值为平均 ns（每轮）。

| 变体 | 命中路径（热，~10 万样本） | App 路径（冷，数十至数百样本） |
|---|---|---|
| 仅模块，无 BPF 程序 | 49 / 53 / 51 / 50 | 1140 / 763 / 1061 / 1167 |
| v0：空 BPF 程序（只计数） | 85 / 86 / 88 / 113 | 2236 / 1601 / 2571 / 2480 |
| v1：320 字节快照 + 逐 socket 复制路径 | 709 / 709 | 5342 / 3329 |
| **v2：64 字节快照 + 路径表（当前）** | 652–680（9 轮） | 2374–8220（噪声大） |
| v3：预分配 HASH 按 cookie 存 64 字节（无删除） | 487 / 476 | 4908 / 4153 |
| **v4：现行生产 BPF producer**（`creator.bpf.c`，自读 argv 与 exe inode 链） | 691 / 722 / 715 | 4379 / 4159 / 8190 |

结论：

1. **模块本身极便宜**：热路径约 50 ns；运行一个 BPF 程序约再加 35 ns。
2. **主导成本是创建 sk_storage**（v2 − v0 ≈ 570 ns，热路径），两次分配并计入 memcg。路径表优化只省约 50 ns。
3. **模块路线与现行 BPF 路线逐 socket 开销基本相同**：v2 约 650 ns，v4 约 710 ns（且 v4 还额外包含模块
   门控约 50 ns，生产桥接模块没有这部分）。模块路线的价值在能力：原生程序完整路径（含短命进程）、
   TOO_LONG/DELETED/KERNEL 语义、按 family 先过滤（一小时内跳过的非 inet socket 是 inet 的 2.6–3.3 倍），
   而不是更快。此前“BPF 净开销归零”的说法不成立：省掉的指针链读取在热路径上只有几十 ns。
4. 预分配 HASH（v3）比 sk_storage 快约 150 ns，但需要在 socket 释放时删除（模块 `android_vh_sk_free`，
   `net/core/sock.c:2209`，再加一次哈希删除），accept 子连接也要自己复制；抵消大半收益且更复杂，**不采用**。
5. 冷路径（真实 App socket，彼此间隔很长）每个 2–8 µs，主要是缓存未命中；样本少、波动大，各变体间无法区分。
