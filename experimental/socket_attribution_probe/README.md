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
| 32 | sing-box 进程已在 `top-app` 的 cpuset 和 cpu 控制组里，可用全部 8 个核（后台组只有 0～3 号核），调度策略 `SCHED_OTHER`、nice 0 | 已证实 | `/proc/<pid>/cgroup`、`/dev/cpuset/*/cpus` |
| 33 | 用 `BPF_PROG_TEST_RUN` 对**正在运行的** `sb_tc_local_l2`（1795 条指令，JIT 后 9324 字节）各跑 20 万次构造包：UDP 443 走代理 148 ns、走绕行 154～173 ns；TCP 443 走代理 81 ns、走绕行 27 ns；DNS 80 ns；局域网 23 ns | 已证实 | `tcbench/`（`results/tcbench.txt`）。测试包上没有 socket，所以 cookie、socket 存储、进程追踪这几步查表都被跳过，而 UID 是溢出值；缓存全是热的。它说明判断链本身在热缓存下很便宜，第 29 条在低流量下测到的 2.45 µs 主要应来自缓存未命中，**大流量下的真实单包开销还需要实测**。这台机器的 `bpftool` 不支持 `prog profile`，读不了硬件计数器 |
| 34 | 事件日志缓冲区为 2 MiB，当前覆盖约 4.2 小时（52221 条） | 已证实 | `logcat -g -b events` 以及最早一条的时间戳。实时读取 `am_proc_start` 不会因为缓冲区轮转而丢事件；sing-box 重启后，也能用缓冲区里的这几个小时补回已经在运行的进程 |
| 35 | **播放视频时**（`wlan0` 下行约 10～12 Mbit/s，上行 0.22 Mbit/s）：`sb_tc_local_l2` 平均 1017 ns/包，30 秒运行 9295 次、合计 9.5 ms，约为单核的 0.03%；同期 netd 的 `egress_stats` 1634 ns/包。sing-box 进程本身 20 秒用掉 0.65 s CPU，约为单核的 3.2%（约 3.2 ms CPU / Mbit） | 已证实（单次采样） | 方法同第 29 条（`results/bpf-prog-stats-30s-video.json.txt`）；进程 CPU 用 `scripts/sing-box-cpu.sh` 读 `/proc/<pid>/stat` 的 utime+stime 差值（`results/sing-box-cpu-video.txt`）。结论：TC 热路径只占 sing-box 总开销的 1% 左右，**第 30 条的 UDP 缓存在性能上没有实际意义**；第 29 条的 2.45 µs 是低流量下缓存变凉造成的。性能的大头在用户态转发 |
| 36 | **包名发现速度**：冷启动 App 时，`am_proc_start` 在每一个会联网的进程发出第一个 IPv4/IPv6 包之前就已写入，领先 317 ms～5.7 s；其中共享 UID 1000 的 `com.miui.securitycenter.remote` 领先 2487 ms | 已证实（8 个进程） | `discovery/`：`tp_btf` `sock_send_length` 按 cgroup 记录首次网络发送的单调时钟时间（只计 `skc_family` 为 2 或 10 的 socket，字段在第 16 字节），换算成墙钟后与同一 PID 的 `am_proc_start` 对齐（`results/discovery.txt`）。冷启动了设置、时钟、计算器、Chrome、飞猪、小米应用商店、安全中心、Telegram；另有 45 个进程在窗口内没有联网 |
| 37 | 实时读取事件流时，`am_proc_start` 从写入到被读到只需 0.8～6.5 ms | 已证实（5 个事件） | `logdlat/`：流式读取 `logcat -b events`，用到达时间减去条目时间戳（`results/logdlat.txt`）。直接读 logd 的 socket 应当更快。结合第 36 条：包名在第一个包之前至少约 300 ms 就能确定 |
| 38 | 多包进程实际发出的网络连接很少：两次采集共 5 分钟，`system_server` 11 个（2 个带 NTP 标签，9 个不带），`com.android.phone`、`android.process.media`、网络栈和几个高通进程都是 **0** | 已证实（日常使用，两次采集） | `multitag/`：在每个网络 socket 第一次发送时，在内核里当场查 netd 的 `cookie_tag_map`，同时记录 cgroup 和发送线程名（`results/multitag.txt`） |
| 39 | `system_server` 不带标签的连接来自 `OkHttp Connecti…` 线程，即平台的 `HttpURLConnection`（内部用 OkHttp）；带 NTP 标签的来自 Binder 线程 | 已证实（样本少） | 同上。和它同处一个进程的另外 4 个包（inputdevices、location.fused、providers.settings、server.telecom）在 AOSP 里没有发 HTTP 的代码，所以这类流量归为 `android` 是合理的；小米加进 `system_server` 的服务是闭源的，这一点无法从源码确认 |
| 40 | GMS 有 socket 的标签计费 UID 是 10309（Chrome），即 GMS **替 Chrome** 联网 | 已证实（1 例） | 同上。按 cgroup 它属于 GMS，按标签它为 Chrome 服务；走哪条规则是策略选择 |
| 41 | 创建 socket 的进程就是发送它的进程：三轮共 1443 个网络 socket（第三轮期间依次冷启动了抖音、B 站、Chrome、微信、小红书、京东、淘宝），**没有一个被第二个 cgroup 用来发送**；对照时仍打开的 201 个，创建者 cgroup 全部等于首个发送者 | 已证实 | `senderscan/`：记录每个 socket 的首个发送进程，之后若有别的 cgroup 在同一 socket 上发送，单独记入另一张表（覆盖已关闭的 socket）；再与 SOCK_DIAG 的 cgroup 对照（`results/senderscan.txt`）。所以"按发送者分流"用 socket 自带的 cgroup 就能做到。**更正第 21 条**：那里的"137/160 相同"，以及 `sendtrace` 里看到的"抖音的连接 UID 为 0"，都是因为 TIME_WAIT 等状态的 socket 在 SOCK_DIAG 里报告的 cgroup 和 UID 都是 0，并不是真的不一致 |
| 42 | `DynamicInstrumentationManagerService.getExecutableMethodFileOffsets()` 只检查调用方是否有 `DYNAMIC_INSTRUMENTATION` 权限，没有 UID 限制；对 system_server 用 `VMDebug.getExecutableMethodFileOffsets()`，对其他进程交给 AMS；整个功能受 ART 运行时开关 `executableMethodFileOffsets` 控制 | 源码证实；root 可调用是推断 | `services/core/java/com/android/server/os/instrumentation/DynamicInstrumentationManagerService.java`。AOSP 的 `checkComponentPermission()` 对 UID 0 和 1000 一律放行，所以 root 应当能调用，**未在真机上实测** |
| 43 | 用流量消耗器跑到 `wlan0` 下行 **73.2 Mbit/s** 时，sing-box 占约**单核的 27%**（约 3.7 ms CPU/Mbit）。其中 **64% 的采样在内核里**，32% 在 sing-box 自己的代码里 | 已证实（单次 20 秒） | `scripts/sing-box-profile.sh`：`simpleperf record -p <pid> --call-graph fp -f 2000 --duration 20`（`results/sing-box-profile-73mbit.txt`）。手机上的 sing-box 与 `E:\Ref_sing-box\sing-box` 的 MD5 相同（`291e236f…`，版本 1.15.0-alpha.9-c71e88dba），也就是说**手机跑的是 Ref_sing-box 编译的版本**，不是本仓库 |
| 44 | sing-box 的内核时间里，**`sendto` 占 65%**、`write` 15%、`read` 7%；内核里最大的单个热点是 **`ipt_do_table`（14.7%）**，其次是 `_raw_spin_unlock_irqrestore` 10.4%、`__dev_queue_xmit` 5.1%、`ip_output` 4.5% | 已证实（同上） | 含义：下行数据回写给 App 时，每个 UDP 包都要单独 `sendto`，走完整的 IP 输出路径，并匹配一遍 Android 的 iptables 规则。估算这部分约占单核的 11%。这和 2026-09-12 的结论（提交 `6dc97eda`："下行 GSO 不值得做"）**并不矛盾**：那次是刷视频时测的，约 500 包/秒，内核态只占 1～2%；而在大吞吐的 UDP 下载场景下，逐包 `sendto` 就成了主要开销。流量消耗器的流量是不是以 UDP 为主，是从 `sendto` 占比推断的，未单独确认 |
| 45 | sing-box 用户态的热点很分散：AES-GCM 解密约 1.8%，Go 运行时（分配、GC、调度）约 6%，sing 的 buffer 约 1.7%，`protocol/ebpf` 约 0.9% | 已证实（符号还原只覆盖了用户态样本的一部分） | 用 `go tool addr2line` 对 `E:\Ref_sing-box\sing-box` 还原前 400 个热点地址（`results/sing-box-profile-user-symbols.txt`）。其中 `internal/runtime/cgroup.parseV2Limit` 约 0.9%，可能是 Go 1.25 起按 cgroup 自动调整 GOMAXPROCS 的周期性开销，**也可能是符号还原有偏差**，未确认 |
| 46 | 手机自带 `/apex/com.android.art/bin/oatdump`，`--dump-method-and-offset-as-json` 能列出每个 oat 文件里 Java 方法的编译偏移；偏移相对于 ELF 动态符号 `oatdata`，加上它的文件偏移就是 uprobe 的文件偏移。预编译覆盖率不高：`boot-framework.oat` 288054 个方法里只有 31410 个有编译代码（`SntpClient` 全部没有），但网络相关的关键方法都编译了：`BlockGuardOs.socket`、`IoBridge.connect`（4 参数版）、`java.net.Socket.connect`、平台 OkHttp 的 `RealConnection.connectSocket` 和 `HttpURLConnectionImpl.connect` | 已证实 | `cmd dynamic_instrumentation` 没有 shell 实现，所以改用早期 UprobeStats 的 oatdump 方法 |
| 47 | 对 `system_server` 的 `BlockGuardOs.socket()`（`boot-core-libart.oat`，`oatdata` 在文件偏移 0x668）挂只读 uprobe **可以正常命中**：20 秒 188 次 | 已证实 | `artstack/`（`results/artstack-system_server.txt`） |
| 48 | **在 eBPF 里还原 Java 调用链行不通**：`bpf_get_stackid(BPF_F_USER_STACK)` 只能顺着帧指针回溯，188 次命中里 174 次只有第 0 帧，其余的第 1 帧是 `0xffffffa00fbd5de8` 这类不属于任何映射的值，第 2 帧落进 Java 堆 | 已证实 | 同上。ART 编译代码不维护帧指针链，返回地址的高位还带着 arm64 指针认证（PAC）签名。所以"按调用栈判断 system_server 里是哪个服务发的请求"做不到；uprobe 只能告诉我们"某个方法被调用了"，以及调用发生在哪个线程 |
| 49 | IPv4 iptables 共 118 条规则（raw 10、mangle 36、nat 8、filter 64），IPv6 107 条；**没有** `box_for_root` 的透明代理规则。出站路径上串着 AOSP netd 的 `fw_/st_/bw_OUTPUT`（含 xt_bpf 程序）、小米的 `oem_out`、`onelink_*`、`tc_limiter_OUTPUT`、`tc_upload_blacklist`，以及高通 QoS 的若干链 | 已证实 | `iptables-save`、`iptables -t <表> -S OUTPUT/POSTROUTING` |
| 50 | root 向本机地址发 UDP（与 sing-box 下行回写走同一条路径：OUTPUT/POSTROUTING → 回环 → PREROUTING/INPUT），每个包约 **7.3 µs** CPU（含接收端）；给 socket 打 mark、并在 10 条内置链最前面对这个 mark 直接 `ACCEPT` 后降到约 **6.0 µs**，**每包省约 1.3 µs（约 18%）**，墙钟时间快约 22% | 已证实（各 3 次，每次 20 万包） | `nfbench/run.sh`（`results/nfbench.txt`）；测完规则全部删除，残留检查为 0。按第 43 条的 73 Mbit/s（约 7600 包/秒）折算，只能省约单核的 1%；逐包发送本身的开销（约 7 µs/包）才是大头，所以第 44 条提到的批量/GSO 方向收益更大。跳过这些链会绕过 Android 的防火墙和流量统计，只适合 sing-box 自己的回写 socket |
| 51 | 同一条本机回写路径上，用 `UDP_SEGMENT`（GSO，每段 1200 字节）把多个数据报合成一次 `sendto`：逐包发送 **8.2～8.4 µs/包**；每次 8 个 1.39～1.46 µs；16 个 1.19～1.24 µs；32 个 0.97～1.05 µs；53 个 **0.90～0.94 µs**，即快 6～9 倍 | 已证实（两轮，每轮 21.2 万个数据报，接收端照常收到） | `gsobench/`（`results/gsobench.txt`）。走的是回环网卡；sing-box 真实的下行回写经过自建的 `sbt/sbd` veth（见提交 `6dc97eda`），veth 上的分段行为**未验证**。按 73 Mbit/s（约 7600 包/秒）、平均每次合并 8 个计，约省单核的 5%，大约是 sing-box 总 CPU 的五分之一。实际能合并多少取决于流量是否成串到达：大流量下载时收益大，刷视频（约 500 包/秒）时很小，这与 `6dc97eda` 的结论并不冲突 |
| 52 | 静态扫描 `system_server` 映射的全部 167 个 jar/apk（`dexdump -d` 找 `URL.openConnection/openStream`、`Network.openConnection`、OkHttp、`Socket.connect`、`DatagramSocket.<init>` 等调用点），27 个里有联网代码。小米的有：`miui-wifi-service.jar`（`RouterParser`、`HttpProbeDiagnostics`、`WcnsHttpUtils` 诊断上传等）、`miui-services.jar`（电池服务、音频云配置、预装云控）、`miui-framework.jar`（系统更新、电量策略、安全权限上报）；AOSP 的有：时间同步、PAC、GNSS、证书吊销列表、Wi-Fi 运营商认证、Hotspot 2.0、QUIC 连接关闭、SIP | 已证实（静态） | `scripts/system-server-netscan.sh`（`results/netscan-classpath.txt`、`results/netscan-all-mapped.txt`）。只覆盖 Java 直接调用，不含 native 代码，也不含经过其他封装库的间接调用 |
| 53 | **LSPosed 模块的代码运行在 `system_server` 里**：映射列表中有 `tornaco.apps.shortx`（ShortX，自带 HTTP、jsoup、Rhino）和 `nep.timeline.freezer`，二者都有联网代码，它们发出的请求在系统看来就是 `system_server`（UID 1000）的流量。小米相机、系统界面、搜狗输入法的 apk 也被映射了，但更可能只是加载资源，未确认其代码是否在此执行 | 已证实（映射）/ 推断（执行） | `/proc/<system_server>/maps` |
| 54 | `system_server` 平时几乎不联网：连续追踪 10 分钟，只有手动触发的那 1 次时间同步（Binder 线程，UDP） | 已证实 | `sstrace/`：`tp_btf inet_sock_set_state` 在 TCP 进入 `SYN_SENT` 时记录执行 `connect()` 的线程名和目的地址，`tp_btf sock_send_length` 记录其他 socket 的首次发送（`results/sstrace-10min.txt`）。由此推测第 38 条里那 9 个不带标签的 socket，多半是更早建立的连接在关闭时才首次被看到 |
| 55 | **静态候选 + 建连时的线程名，可以把 `system_server` 的流量精确归到组件**：关闭再打开 Wi-Fi 后，立即抓到线程 `RouterParser` 向 `192.168.10.1:80`（路由器）发起 TCP 连接，正对应 `miui-wifi-service.jar` 的 `RouterParser.startParseRouterInternal()` | 已证实（1 例） | `results/sstrace-wifi-reconnect.txt`。小米的服务大多运行在以类名命名的 `HandlerThread` 上，所以线程名就能区分组件；对于在 Binder 线程或线程池里执行的请求，这个方法就区分不了 |
| 56 | **GSO 在 sing-box 真实的回写方式下同样有效，且回写走的是 `lo` 而不是 `sbt/sbd` veth**。按 `E:\Ref_sing-box` 的 `newTCUDPReplySocket()` 照做：发送端 `IP_TRANSPARENT` 并绑定外部地址 `8.8.8.8:443`，发往 App 的本机地址；接收端绑定本机地址并 `connect()` 到 `8.8.8.8:443`（与 QUIC 客户端一致）。逐包 9.6～9.9 µs/数据报；每次合并 8 个 1.6～2.5 µs，16 个 1.5～1.9 µs，32 个 0.96～1.5 µs。`/proc/net/dev` 显示只有 `lo` 的发送计数增加，且等于合并后的大包数（如合并 8 个时为 20000），App 照常收到独立的数据报 | 已证实（两轮，每轮 16 万个数据报） | `gsobench2/`（`results/gsobench2-transparent.txt`）。合并 16、32 个时的少量丢失来自单线程接收端的缓冲区，与 GSO 无关。**更正第 51 条**：那里说"真实回写经过 `sbt/sbd` veth、尚未验证"，实际 TC 数据面的回写目的地是本机地址，走 local 路由表经 `lo`；veth 用于上行重定向。提交 `6dc97eda` 里"下行走 veth"的说法与当前代码不符 |
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
