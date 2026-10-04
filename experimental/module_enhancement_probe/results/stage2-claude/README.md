# 第 2 阶段验收（Claude 接手实现，2026-10-04）

设备：Xiaomi，Android 16，内核 `6.12.69-android16`，KernelSU `su -mm`；生产 sing-box 处于停止状态（用户自行停止），
测试只以 `tools synctime`（无配置、不写时钟）执行过其二进制。复现：`acceptance/build.sh`、`module/build.sh`
（WSL），`acceptance/run-device.sh quick|long <秒>|bench`（真机，root）。

## 文件

| 文件 | 内容 |
|---|---|
| `quick.log` | quick 阶段完整输出（第二次运行，第一次结果一致） |
| `watch-quick.json` | quick 期间全机 watch 的逐路径统计 |
| `long-partial.log`、`watch-long.json` | 长时间运行，**因用户需要手机离线，在 334 秒时用 SIGTERM 正常结束**，不是 1 小时 |

## 结果

**quick 阶段（全部通过）**

- 加载/卸载 3 次：通过；`/dev/sbo_enhancement_probe` 为 `0600`。
- 本进程自测（每种 tcp4/udp4/tcp6/udp6 各 2000 个 socket，按 fd 读回快照，与 `SO_COOKIE`、`getpid()`、
  `/proc/self/exe` 比对）：8000/8000 正确，命中缓存 7996。
- 超长路径（可执行文件路径 303 字节）：800/800 为 `TOO_LONG`，path_len=0。
- 已删除可执行文件（启动后删除再建 socket）：800/800 为 `NATIVE_PATH|DELETED`，路径已去掉 `" (deleted)"`。
- unix socket：无快照（模块按 family 过滤，未发事件）。
- 全机 watch 90 秒：10065 个事件，与 `/proc/<pid>/exe` 比对 **0 不符**；BPF `duplicate=0`、`ringbuf_drop=0`、
  `storage_fail=0`、`path_read_fail=0`；`too_long` 中 206 个为 “gone”（被测进程在比对前已退出，不能判定，
  非错误）。路径覆盖：`/system/bin/netd`、`/system/bin/iptables`、`/data/adb/services/sing-box/sing-box`、
  本工具；`app` 事件的 `/proc/<pid>/exe` 均为 `app_process64`。
- 文件引用：模块卸载时 `get_file_rcu=21 fput=21`（在 `tracepoint_synchronize_unregister()` 之后读取）。
- dmesg：只检查本次 `/dev/kmsg` 标记行之后的全部日志，无 WARNING/BUG/Oops；taint 前后均为 4608。

**长时间运行（334 秒，部分）**

- 1628 个事件：app 1320 全部正确；native 308 中 301 正确、7 个 gone；0 不符、0 重复、0 丢弃。
- 缓存命中率：netd 179/186（96%），iptables 101/108（94%），sing-box 10/14。
- `get_file_rcu=18 fput=18`；file-nr 46665→46825（全机计数，受其他进程影响，不作判据）；dmesg 干净，taint 4608。

## 补充：accept 继承（BPF_F_CLONE）真机试跑

消费端 map 加 `BPF_F_CLONE` 后，本进程 listen/connect/accept 200 次：200/200 的子连接带有监听 socket
快照的副本（cookie 等于监听者、不等于子连接自身 cookie，pid/路径与监听者一致），即 TC 可按
“cookie 不等”识别继承；accept 不经 `__sock_create`，模块不额外发事件（inet=401 = 4×50 个自测 socket + 200 个
客户端 + 1 个监听者，200 个子连接不在其中）。注意：`bpf_sk_storage_clone()` 以 GFP_ATOMIC 为每个子连接分配，分配失败时
`sk_clone_lock()` 放弃该连接（`net/core/bpf_sk_storage.c:140`）。

## 离线运行（`offline/`，2026-10-04 18:04–19:05，手机离线、正常使用）

`offline/REPORT.txt` 为摘要；`quick.log`、`bench.log`、`long.log`、`watch-*.json` 为完整输出。

**quick**：rc=0，3 组自测全部 `SELFTEST_PASS`，accept 继承 200/200（共 3 次）。

**long，3600 秒全机监视**

- 42697 个事件（app 26895、native 15802）；与 `/proc/<pid>/exe` 比对 **0 不符**，95 个 gone（进程已退出）；
  BPF `duplicate=0`、`ringbuf_drop=0`、`storage_fail=0`、`path_read_fail=0`。
- 模块：`inet=42697`（与 BPF 事件数相等，即每个 user inet socket 恰好一个事件），`skipped=142112`
  （非 inet / 内核 socket，3.3 倍于 inet，按 family 先过滤是值得的），`hit=15692 miss=110`
  （原生路径缓存命中率 99.3%），`unvalidated=0`，`error=0`；`get_file_rcu=110 fput=110`。
- 13 个原生路径全部正确，包括 App 拉起的原生子进程：`/system/bin/ip`（uid 10356/10357/10361/10480，
  574 次）、`/system/bin/ping6`（uid 10357）、`/system/bin/ping`（uid 10480）、`/system_ext/bin/hyos_spawner`
  （uid 10287/10295）。未出现路径在 `/data/app` 下的 App 自带可执行文件。
- file-nr 47593→47241。taint 4608 不变。
- **dmesg 检查在本阶段无效**：1 小时内内核日志环形缓冲区已被高通驱动日志冲掉，标记行不在了
  （`lines_since_mark=0`），所以 `DMESG_CLEAN` 是空检查。taint 4608 = `W`(512) + `O`(4096)，`W` 在测试前
  已置位，也无法反映新告警。下次长时间运行须在运行期间持续抓取内核日志（如 `cat /proc/kmsg` 写文件）。

**bench（锁频 policy0 min=max，绑 CPU 4，UDP socket()+close() 各 20000 次 × 5 轮，三态交错 3 个周期）**

| 状态 | 3 个周期的中位数 (ns) | 平均 |
|---|---|---|
| 未加载 | 5585 / 5784 / 5672 | 5680 |
| 采集中（模块 + 生产形态消费端：只写快照，不写 ring buffer） | 7193 / 7016 / 7638 | 7282（+1.6 µs） |
| 已加载未采集 | 6208 / 6050 / 6677 | 6312（+0.6 µs） |

- 采集中比未加载多约 1.6 µs/socket。被测进程是原生程序，走缓存命中路径；这 1.6 µs 包括模块门控、缓存查找和
  BPF 消费端（`bpf_sk_storage_get` 创建 320 字节快照的分配、`bpf_get_socket_cookie`、comm、256 字节路径复制）。
  作为对照，现行 BPF producer 此前实测约 2 µs/socket（`common/socketidentity/bpf/creator.bpf.c` 注释）。
- 已加载未采集多出的约 0.6 µs 不应来自钩子本身（只读一次 `is_active`）。该状态总在“采集中”之后、消费端刚
  退出时测量，map 释放与 RCU 回调可能在后台占用；本数据不能区分，记为未解释。
- 优化方向（未实现）：每个 socket 只存 `(dev, ino, gen, flags)`，路径按 `(dev, ino, gen)` 另存一张 map、
  只在缓存未命中时写，可去掉每个 socket 256 字节的复制和较大的分配。
- 调频：结束后 `scaling_min_freq` 恢复为 bench 开始时读到的值（787200）；早先一次读数是 883200，
  该值看来会被系统动态调整。governor 为 walt。唤醒锁已释放。

## 结论

第 2 阶段验收清单中：路径正确性、超长/已删除、缓存、每 socket 一个事件、BPF 消费端（不读指针链）、
文件引用成对、加载/卸载、1 小时运行、配对性能测试均已在真机完成。未完成或无效的：长时间运行期间的
dmesg 检查（日志被冲掉），以及路径在 `/data/app` 下的 App 自带可执行文件（自然使用中未出现）。
