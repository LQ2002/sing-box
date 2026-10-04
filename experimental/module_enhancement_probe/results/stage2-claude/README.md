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

## 离线运行（进行中）

手机离线期间以 `acceptance/offline.sh`（`setsid nohup`）依次运行 quick → bench → long 3600，结果写到
设备 `/data/local/tmp/sboacc/report/`（`REPORT.txt` 为摘要）。重连后读取并补入本目录。

## 尚未完成（手机离线前中止）

1. 长时间运行只有 334 秒，未达到 ≥1 小时。
2. 锁频绑核的交错配对性能测试（`run-device.sh bench`：未加载 / 采集中 / 已加载未采集，各 3 轮交错）未运行。
3. accept 继承只做了上面的 200 次试跑；离线运行的 quick 阶段会再跑一次。
4. App 自带原生子程序（uid ≥ 10000、路径在 `/data/app` 下）在两次 watch 中均未自然出现，未覆盖。
