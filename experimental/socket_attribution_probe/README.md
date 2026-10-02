# socket 归属与包名识别的真机验证

这个目录存放 2026-10-02 在真机上做的一组诊断，目的是回答两个问题：

1. 现有的 `sb_sockowner_probe` 内核模块为什么会查不到 socket；
2. 在不猜包名的前提下，能不能把流量准确归到包，尤其是共享 UID 1000 下的系统应用。

这里的程序全部是一次性的诊断工具，**不参与 sing-box 的构建，也不改变路由**。每个子目录都是独立的 Go module，交叉编译后用 adb 推到手机上以 root 运行。

## 设备

- 小米，Android 17 / SDK 37
- 内核 `6.12.69-android16-6-g586bfab1b9c5-abogki536749445-4k`
- KernelSU（adb shell 已授权 root）、ZygiskNext、LSPosed
- 当时加载的是 48 字节 ABI 的 `sb_sockowner_probe`，`OWNER_MAX` = 16384

## 结论汇总

| # | 结论 | 证据等级 | 依据 |
|---|---|---|---|
| 1 | 模块的淘汰策略会丢掉**仍存活**的 socket 条目 | 已证实 | `evict/`：12 个存活且未再查询的 UDP socket，14 分钟内全部能查到；14～16 分钟间全机 2 分钟新建约 5.3 万个 socket，`evicted` 从 253 涨到 14717，之后这些 socket 全部查不到 |
| 2 | 第一次扫描里 48 个未命中的 socket 是否都由淘汰造成 | **不能确定** | cookie 按 CPU 分批分配，数值交错不能说明创建时间交错，也排除不了模块加载前就存在的 socket。只能确定其中只有 1 个像 accept() 产生的 |
| 3 | 主线程 comm 是进程名的**后** 15 个字符，`:xxx` 子进程的 comm 里几乎没有包名 | 已证实 | `results/comm-vs-cmdline.txt` |
| 4 | Manifest 里的 `android:process` 能把 (UID, 进程名) 唯一映射到包，UID 1000 下 86 个进程名中 84 个唯一 | 已证实 | `procmap/`。AMS 用同一个键：`ProcessList.mProcessNames.get(processName, uid)` |
| 5 | Android 给每个进程单独建 cgroup v2，路径里带 UID 和 PID | 已证实 | `/proc/<pid>/cgroup` → `0::/system/uid_1000/pid_23500`，App 进程在 `/apps/uid_X/pid_Y` |
| 6 | SOCK_DIAG 的 `INET_DIAG_CGROUP_ID` 给出的进程，和模块记录的 PID 一致 | 已证实 | `cgscan/`：两边都有值的 45 个 socket 全部一致；另有 50 个模块查不到的 socket 能通过 cgroup 找到进程 |
| 7 | TC 程序可以逐包调用 `bpf_skb_cgroup_id()`，值和 SOCK_DIAG 相同 | 已证实 | `tccg/`：verifier 接受；两边都有值的 51 个 socket 全部相同 |
| 8 | 进程退出时 cgroup 目录同时被删除 | 已证实 | `scripts/cgdeath.sh`：强制停止 99ms、kill -9 44ms，进程消失与目录删除在 10ms 精度内同时发生 |
| 9 | WebView 沙箱（UID 99xxx）进程没有网络 socket | 当次样本证实 | `cgscan` 的 175 个 socket 里 `uid_99` 为 0 |
| 10 | KernelSU 脚本启动的 root 进程（包括 sing-box）在根 cgroup，cgroup ID = 1 | 已证实 | `cgscan`、`tccg` |
| 11 | netd 的 `cookie_tag_map` 只包含被显式打过标签的 socket | 已证实 | 当次只有 4 条（GMS `0x407`、网络栈 `0xfffffe01`） |
| 12 | App 进程在运行任何 Java 代码之前就已进入自己的 cgroup，所以 App 的每个 socket 都带着自己的 cgroup | 源码证实 | `frameworks/base/core/jni/com_android_internal_os_Zygote.cpp` 的 `SpecializeCommon`：`createProcessGroup(uid, getpid())` 在 `setresuid`、SELinux 上下文设置和 Java 回调之前 |
| 13 | AMS 的事件日志 `am_proc_start`（tag 30014）在进程启动时给出 `[用户, PID, UID, 进程名, 启动原因, {触发启动的组件}]`，组件里的包名来自 AMS 本身 | 源码 + 真机证实 | `services/core/java/com/android/server/am/EventLogTags.logtags`；真机事件缓冲区里 470 次启动，到 `am_proc_bound` 的间隔最短 1ms、P10 22ms、中位数 43ms、最长 1393ms（`results/am-proc-events.txt`） |
| 14 | `AttributionSource` 只用于受权限保护的数据访问归属，和网络、socket、流量统计无关 | 源码证实 | `core/java/android/content/AttributionSource.java`。`system_server` 内部的网络流量在进程外没有可读的包级归属 |
| 15 | 这台厂商内核允许 BPF kprobe 挂在 `__sock_create`、`inet_create` 上；`tp_btf`（`sched_process_fork`）和 `sock/inet_sock_set_state` tracepoint 也可以用；LSM 和 fentry 不可用（`not supported`，内核没开 `CONFIG_FUNCTION_TRACER`）；没有 syscalls 类 tracepoint | 已证实 | `attachtest/`：每个点挂一个返回 0 的空程序，1 秒后卸载（`results/attachtest.txt`）。这推翻了"socket 归属只能靠内核模块"的旧结论，但 kprobe 拿不到 socket cookie（cookie 是按需生成的），要和 TC 侧关联还需要另外设计键 |
| 16 | Android 16 起有官方系统服务 `DynamicInstrumentationManager`，可以查询某个进程里某个 Java 方法编译后的文件和偏移，供 uprobe 只读观察 | 源码证实，设备上已在使用 | `packages/modules/UprobeStats/src/DynamicInstrumentationManager.cpp`（`ADynamicInstrumentationManager_getExecutableMethodFileOffsets`）；设备上有 `com.android.uprobestats` APEX 和 `/sys/fs/bpf/uprobestats/` 下的 map |
| 17 | 这个 ROM 不输出组件级事件日志（`am_create_service` 等） | 已证实 | 事件缓冲区里一条都没有，所以多包进程内部哪个组件在活动，靠事件日志看不到 |
| 18 | 创建 socket 的线程名不能作为可靠的身份信号 | 当次样本 | `threadscan/`：60 秒内系统 UID 只采到互联服务的 2 个 socket，线程名是自动生成的 `Thread-17`；`system_server` 和电话进程在这段时间里没有新建 socket（`results/threadscan.tsv`） |
| 19 | `ApplicationStartInfo`（`dumpsys activity start-info`）会持久化每个包的启动记录，里面明确有 package、process、pid，但**不完整** | 已证实 | 2899 条记录里 2285 条 pid 为 0；正在运行的安全中心、互联服务进程找不到对应记录，只有电话进程能找到（`results/start-info.txt`）。只适合作为 sing-box 重启后的补充来源 |
| 20 | `dynamic_instrumentation`（`IDynamicInstrumentationManager`）和 `uprobestats_bridge` 两个系统服务都已注册 | 已证实 | `service list`。root 能不能直接调用、需要什么权限，**未验证** |
| 21 | 纯 eBPF 可以在 socket **发送数据时**拿到 cookie 和发送线程：`tp_btf` 挂在 `sock_send_length`（`net/socket.c` 的 `sock_sendmsg_nosec()` 里触发，覆盖 sendto/sendmsg/sendmmsg/write，即 TCP、UDP 和 QUIC），对带类型的 `struct sock *` 调用 `bpf_get_socket_cookie()` | 已证实 | `sendtrace/`：verifier 接受、挂载成功；90 秒内记录到 4753 个 socket 的首次发送，其中对照时仍打开的网络 socket 160 个（TCP 126、UDP 34），全部能用 cookie 和 SOCK_DIAG 对上。发送线程的 cgroup 与 socket 自带的 cgroup 在 137/160 个上相同。这解决了第 15 条里"kprobe 拿不到 cookie"的问题，也能覆盖根 cgroup 里的 root 进程 |
| 22 | `tp_btf` 挂在 `binder_transaction_received` 上可以读到调用方的 PID 和 UID（`binder_transaction.from_pid` 在第 48 字节、`sender_euid` 在第 132 字节，偏移取自设备 BTF） | 已证实 | `sendtrace/`：例如 keystore2 在收到设置（UID 1000）的 Binder 调用 0.5ms 后发送，cameraserver 在收到 system_server 调用后发送 |
| 23 | 用"发送前不久收到过谁的 Binder 调用"来推断 system_server 替哪个 App 联网 | **未能评估** | 90 秒内 system_server 没有发送任何网络数据，没有样本。而且这只是时间上的相关，不是权威归属：工作交给其他线程异步执行时，关联就断了。只能作为诊断线索，不能用于分流规则 |
| 25 | 多包进程里会联网的 AOSP 组件大多给自己的 socket 打了标签：时间同步 `TAG_SYSTEM_NTP`（`0xFFFFFF41`）、GNSS 辅助数据 `TAG_SYSTEM_GPS`（`0xFFFFFF44`）、PAC `0xFFFFFF45`；网络栈的 DHCP `0xFFFFFE01`、邻居探测 `0xFFFFFE02`、热点 DHCP 服务 `0xFFFFFE03`，以及代表 App 的连通性探测 `0xFFFFFF81` 和 DNS `0xFFFFFF82`。彩信服务没有打标签 | 源码证实 | `core/java/android/net/SntpClient.java`、`services/core/java/com/android/server/location/gnss/GnssPsdsDownloader.java`、`core/java/com/android/internal/util/TrafficStatsConstants.java`、Connectivity 的 `staticlibs/.../NetworkStackConstants.java`、`packages/services/Mms/.../MmsHttpClient.java` |
| 26 | TC 程序可以**逐包**读取 netd 固定在 `/sys/fs/bpf/netd_shared/map_netd_cookie_tag_map` 的表 | 已证实 | `tagtrace/`：verifier 接受。挂载后执行 `cmd network_time_update_service force_refresh`，抓到 UID 1000、标签 `0xFFFFFF41`、cgroup 4115 的 socket，4115 正是 `system_server`（`/system/uid_1000/pid_3818`）。也就是说，`system_server` 内部的时间同步流量能在 TC 里被逐包、精确地识别 |
| 27 | `tagtrace/` 看到 21 个 netd 发出、标签为"代表 App 的 DNS"、计费 UID 为 `dns`（1051）的 socket | 已证实 | cgroup 1355 是 netd。**当初据此推断"小米开启了 `enforceDnsUid`"是错的**，见第 28 条；这些更可能是 netd 自己发起的查询（例如网络验证） |
| 28 | netd 替 App 发出的明文 DNS 包，socket UID 就是发起查询的 App 的 UID；TC 里用 `bpf_get_socket_uid()` 即可逐包拿到，零额外开销 | 已证实 + 源码 | `dnsuid/`：在所有网卡出口记录来自 netd cgroup 的包的 socket UID。让浏览器打开一个新域名后，看到 10309（`com.android.chrome`），以及 B 站、GMS、应用商店的后台查询；以 root 查询时是 0。源码 `binder/android/net/ResolverOptionsParcel.aidl`：默认用 `fchown()` 把明文查询改成 App 的 UID，DoT 用 `AID_DNS`；`enforceDnsUid` 是可选的 OEM 开关，在这台机器上**没有**生效。私人 DNS 处于关闭状态。以 shell（2000）查询时 netd 直接返回失败、没有发包，原因未查。注意：这只给出 UID；共享 UID 的应用发起的 DNS 查询，区分不到包 |
| 29 | sing-box 的 TC 出口程序 `sb_tc_local_l2` 平均每个包约 **2.45 µs**；同期系统 netd 的流量统计约 3.0～3.6 µs/包，另有挂在收发包路径上的 kprobe（`miui_tcp_rcv_est` 两个、`__dev_queue_xmit`、`ip_queue_xmit`）合计约 2～5 µs/包 | 已证实（单次 30 秒采样，流量较少） | 临时打开 `kernel.bpf_stats_enabled`，前后各读一次 `bpftool -j prog show`，按 `run_time_ns / run_cnt` 计算（`results/bpf-prog-stats-30s.json.txt`）。统计本身也有少量开销。这几个 kprobe 的加载者未确认 |
| 30 | sing-ebpf 的按 socket 分流缓存（`tc_local_verdict`）**只对 TCP 生效**，UDP（包括 QUIC）每个包都要跑完整条判断链，其中有容量 65536 的 LPM 前缀树查询；进程追踪开启时，每个被选中的包还要多查一次 `tc_assignment` | 源码证实 | `sing-ebpf/native/tc.bpf.c` 的 `local_selected_cached()` 注释："只对 TCP 缓存。未连接的 UDP socket 每个包的目的地址都可能不同"；`record_local_socket_cookie()`。但已 `connect()` 的 UDP socket（QUIC 客户端的常见用法）目的地是固定的，可以缓存 |
| 31 | 小米自己的网络 eBPF 也只按 UID 工作 | 已证实 | `/system/etc/bpf/miui/HyperWifiWmm.o`（按 UID 设置 WMM 优先级）、`tclimiter.o`（按 UID 限速，系统 UID 直接放行），都调用 `bpf_get_socket_uid()` |
| 24 | `sock_send_length` 对所有 socket 类型都触发，包括 unix 和 netlink，而且是**每次发送都触发** | 已证实 | 4753 个里只有 160 个是对照时仍打开的网络 socket。正式使用时应在程序开头过滤：只处理根 cgroup（ID 为 1）的发送，Android 启动的进程直接用 socket 自带的 cgroup，这样对 App 流量几乎没有额外开销 |

## 各工具

| 目录 | 做什么 | 怎么读结果 |
|---|---|---|
| `missscan/` | 用 SOCK_DIAG 枚举全部 inet socket，逐个向模块查询；查不到的打印协议状态、UID、inode 对应的进程，以及 cookie | `MISS` 行的 `accepted_like=true` 表示本地端口和某个监听端口相同 |
| `evict/` | 新建 12 个 UDP socket 并各查一次，之后在第 1、2、4……24 分钟各查其中**一个**（每个只查一次，不会互相刷新 LRU），同时记录 `/proc/sb_sockowner_probe` | `hit=false` 且 `evicted` 跳涨，说明存活条目被淘汰 |
| `procmap/` | 解析 `pm list packages -f -U` 列出的每个 base.apk 的 Manifest，建立 (appId, 进程名) → 包集合，再对照正在运行的 zygote 子进程 | `SINGLE` 唯一、`MULTI` 多包、`NONE` 查不到；`TABLE1000` 是 UID 1000 的完整表 |
| `cgscan/` | 读出每个 socket 的 `INET_DIAG_CGROUP_ID`，用 cgroupfs 的 inode 反查路径，和模块对照 | `DISAGREE` 且 `cg=` 为空的，都是根 cgroup 里的 root 进程，不是真正的矛盾 |
| `tccg/` | 在指定网卡的 TCX egress 最前面挂一个只记录 cookie → cgroup ID、返回 `TCX_NEXT` 的程序，20 秒后卸载，再和 SOCK_DIAG 对照 | `diag=0` 的不一致是对照时 socket 已进入 TIME_WAIT 等状态 |
| `scripts/cgdeath.sh` | 启动计算器，分别用强制停止和 kill -9 结束它，以 10ms 间隔测进程和 cgroup 目录各自何时消失 | — |
| `scripts/proctree.sh` | 按父进程把全部进程分为 zygote 子进程、webview_zygote 子进程、init 子进程等 | — |

## 构建与运行

所有 Go 构建都在 WSL 里以 `likayo` 用户执行（见仓库的构建约定），例如：

```sh
cd experimental/socket_attribution_probe/cgscan
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o cgscan .
```

在 Windows 的 Git Bash 里调用 adb 时，必须先 `export MSYS_NO_PATHCONV=1`，否则 `/data/local/tmp/...` 会被改写成 Windows 路径。

```sh
adb push cgscan /data/local/tmp/sbo-cgscan
adb shell "su -c 'chmod 755 /data/local/tmp/sbo-cgscan; /data/local/tmp/sbo-cgscan; rm /data/local/tmp/sbo-cgscan'"
```

`evict` 要跑 24 分钟，应当用 `nohup` 在手机上后台运行、把输出写到手机上的文件，结束后再取回；中途手机最好保持连接，否则深度休眠会让计时暂停。`tccg` 需要传入网卡名（例如 `wlan0`），会在该网卡出口临时挂载程序约 20 秒。

## 已知不足

- `results/evict-poll-output.txt` **不是完整的原始日志**：手机上的原始文件已经删除，本地只保留了轮询输出，其中 t=0 时 12 个 socket 的 cookie 行被过滤掉了。要引用这项结论，应当重跑并完整保存。
- `procmap` 只解析 base.apk。GMS 的部分组件声明在 split APK 里，所以 `com.google.android.gms.unstable` 等进程显示为 `NONE`；Chrome、WebView、Quetta 的 Manifest 含有解析不了的资源引用，被计为失败。正式实现时这两处都要补上。
- `missscan` 是在 `experimental/process_identity_probe/owner_scan.go`（另一个会话写的探针，未入库）的基础上改的。
- `results/` 里有设备上已安装应用的包名、UID 和 PID，按仓库里其他探针的惯例不入库，只保存在本地。
