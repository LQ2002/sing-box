# Claude 对本探针的审查意见（2026-10-04）

对象：提交 `f57b4666`（`module/sbo_enhancement_probe.c`、`user/control.go`、
`results/kernel_dpath_lifecycle_20261004.txt`、`README.md`）。本文件只记录审查意见，
不修改探针的任何文件。较早的 `3b7a2727` 版本（循环论证的 inode 统计、`sk_mark` 设想）
已由本版自行勘误，这里不再重复。

## 核实过的事实

- **仓库**：`f57b4666` 相对 `3b7a2727` 只改动 `experimental/module_enhancement_probe/`，
  生产代码未动；2.9 MB 预编译二进制已删除。
- **真机原始日志**：设备 `dmesg` 中有与结果文件一致的记录（`[221458.878243] module loaded` 到
  `[221459.746434] module unloaded`），包括 `d_path=/data/local/tmp/sbo_control`、
  `/system/bin/app_process64`、`/vendor/bin/shsusrd`、`/system/bin/ping`、`/system/bin/netd`，
  以及两次 `RELEASED, is_active set to FALSE`。期间无 WARNING / BUG / Oops。
- **事后设备状态**：模块已卸载，`/dev/sbo_enhancement_probe` 不存在，生产 sing-box 仍为 pid 26306。
- **内核 taint = 4608（O + W）**：W（曾发生内核 WARNING）**不是本次运行造成的**。
  `ANDROID_ATTRIBUTION_PLAN.md` 第 1211、1268、1355 行记录了 10-03 同一次开机期间 taint
  已是 4608；本机 `dmesg` 环形缓冲区只回溯到 221021 秒，无法看到更早的 WARNING 来源。

## 结论

本版比上一版扎实：主动纠正了 `sk_mark` 改写与“只比 inode 不比设备号”两处错误，
使用真实模块在真机上实测。**“创建现场取可执行路径（`d_path`）”与“字符设备 `release()`
自动停采”两项能力的可行性已证实**，与此前“作为可选增强”的判断一致。但以下几点超出了证据，
离生产可用仍有距离。

## 问题

1. **开销被低估。** 探针对**每个** socket 都调用 `d_path`，实测 0.4–11 µs，冷调用多为 4–6.5 µs，
   高于当前 v2 整段约 2 µs（`creator_v2_probe` 分段测量）。若落地，必须先比较
   `(i_sb->s_dev, i_ino)` 与 app_process 是否相同，只对原生程序调用；探针未实现此门控。
   “停采后 <0.3 ns”未实测（已注册的 vendor hook 仍有回调分发开销，量级为纳秒，但不是测出来的）。
2. **“安全、零崩溃、无泄漏”依据不足。** 只运行数秒、记录 20 个样本。代码直接读取
   `current->mm->exe_file`（`__rcu` 指针），既未 `rcu_read_lock()` 也未取引用；同一进程另一
   线程恰好 exec（或 `prctl(PR_SET_MM_EXE_FILE)`）时可能访问已释放的 `struct file`。
   生产实现应使用 `get_mm_exe_file()` 取得引用，用后 `fput()`。
3. **字符设备只适合探针。**
   - `.mode = 0666`：任何进程都能打开设备，从而开关采集；生产应为 0600（并配合 SELinux 标签）。
   - `is_active` 是无计数的全局开关：两个持有者时，任一关闭即停采；`open()` 还会重置样本计数。
     生产应按持有者计数，最后一个关闭才停采。
4. **“彻底消除劣势”忽略了代价。** 退出即停采意味着 sing-box 停止或重启期间新建的 socket
   没有快照（当前 pin 持久化正是为覆盖这一窗口）。应作为可选项，而不是对现状的全面改进。
5. **“绕过 ptrace 权限检查、SELinux 跨域拦截”不成立。** sing-box 以 root 在 `u:r:ksu:s0`
   运行，读取 `/proc/<pid>/exe` 无障碍（整服务验收中路径均读到）。现场取路径的真实收益
   只在原生进程于查询前已退出的情形。
6. **又提交了构建中间产物** `module/.module-common.o`。
7. **overlay 情形未覆盖。** 若 root 模块以 overlay 方式替换 `/system/bin` 下的文件，
   `exe_file` 的 `(s_dev, i_ino)` 可能与用户态 `stat` 不一致；本次未见此情况，但未验证。

## 若要落地（建议）

- 在现有 `sbo_identity_bridge` 中实现，而不是另起一个模块；模块保持精简。
- 只在 `(s_dev, i_ino)` 不同于 app_process 时取路径；用 `get_mm_exe_file()`/`fput()`；
  缓冲区放在 per-CPU 区或缩小栈占用。
- 把路径（或其哈希与长度）经 typed tracepoint 参数交给 BPF producer 写入快照，用户态不再读 /proc。
- 停采开关：设备 0600、按持有者计数；默认仍保持 pin 持久化，停采作为配置选项。
- 验收：完整设备测试（含 exec 竞争、多持有者）、长时间运行、分段开销测量，并在测试前后记录 taint。

---

# 第二次审查（2026-10-04 下午）

对象：提交 `8395f3e7`（第二轮：RCU 快速门控、`get_file_rcu`、动态基线、原子持有者计数）与
`2ea23781`（第三轮：增加 `android_vh_inet_csk_clone_lock`、`android_vh_binder_transaction_received`
两个钩子），以及 Gemini 随附的两份文字结论（用户提供的 `E:\work_sb\001.txt`、`002.txt`）。
同样只记录意见，不修改探针文件。

## 核实过的事实

- **仓库**：两次提交只改动本文件夹；`module/.module-common.o` 已删除。
- **设备**：模块已卸载，`/dev/sbo_enhancement_probe` 不存在，taint 仍为 4608（无新增标记）。
  生产 sing-box 当时未运行，系用户自行停止；配置与二进制的修改时间均早于 10-01，未被改动。
- **两个新钩子确实存在**：`include/trace/hooks/net.h:46`
  `DECLARE_HOOK(android_vh_inet_csk_clone_lock, TP_PROTO(struct sock *newsk, const struct request_sock *req))`，
  调用点 `net/ipv4/inet_connection_sock.c:1284`；`include/trace/hooks/binder.h:52`
  `android_vh_binder_transaction_received(t, proc, thread, cmd)`，调用点 `drivers/android/binder.c:5360`。
- **第一次审查的意见已被采纳**：exe_file 改为 `get_file_rcu` + `fput`，非 app_process 才走 `d_path`，
  设备 0600，按持有者原子计数。这几处修正是对的。
- **`002.txt` 所述原始数据不在仓库中**：UDP 受控测试（“`tc_udp_with_identity=17`、`udp_later_covered=3`”）、
  DNS 的 tcpdump 与 `dumpsys dnsresolver` 输出均未入库，无法复核。

## 对 001（“全能单模块”）的意见

1. **accept 克隆只证明了钩子被调用，没有复制任何数据。** 结果日志只有
   `[TCP_ACCEPT_CLONE]: newsk=... family=2 state=3`。模块无法写 BPF 的 SK_STORAGE（本机内核不向模块
   导出 `bpf_map_*`），要复制仍需经 tracepoint 交给 BPF；继承来的快照带监听者 cookie，现有 TC 会拒收，
   “完全不需要改 TC”不成立。同一效果用 `BPF_F_CLONE` 无需模块即可得到。
2. **binder“穿透 system_server”未被证明。** 日志只显示 binder 线程收到 `client_uid=1000 client_pid=2160`
   的事务（UID 1000 是系统进程，不是 App）。从“收到事务”到“某个 socket 是替谁建的”这一步完全未测，
   而 binder 线程复用、联网常交给其他线程异步执行，正是不可靠之处。`binder_transaction` 是驱动内部
   结构体，其布局不受符号 CRC 保护，内核更新可能悄悄读错字段。且用户要求按发送者路由，
   此类信息最多用于诊断。
3. **“停采后 <0.3 ns”仍未实测。**
4. 现场取路径的开销：热调用 573 ns、冷调用 2.8–4.2 µs，仅对原生程序发生，可以接受。

## 对 002（UDP 与 DNS）的意见

1. **“模块对 UDP 首包 100% 覆盖”不是新发现**：现行 v2 的桥接模块就挂在 socket 创建处。覆盖由执行顺序
   保证（`socket()` 返回先于任何 `sendto()`），所称“600 µs 时间余量”与结论无关。
2. **免模块路线的多包 UDP 数据**补上了 `tracepoint_producer_probe` 未完成的测试，结论与预期一致
   （首包必丢、后续包可补），但原始数据未入库。
3. **DNS 复测方法正确（停生产服务、Chrome 前台），但没有回答关键问题。** tcpdump 看不到包的 socket UID，
   `dumpsys dnsresolver` 记录的是请求发起方，也不是包的 socket UID。真正的问题是 netd 发出的 DNS 包在
   TC 中的 `sk_uid`，应以 `experimental/socket_attribution_probe/dnsuid/` 之类的出口探针测量。
   因此“已实测证实 enforceDnsUid 未开启”缺少直接证据；“1051 是 netd 自身网络验证探测”说得通
   （与研究结论 27 的推测一致），但未给出证据（例如查询的域名）。

## 结论（更新）

沿 C 模块路线：**现场取路径**与**退出即停采**两项已具备进入正式开发的条件（门控、引用、权限、计数
均已修正）；accept 继承建议用 `BPF_F_CLONE`，或“钩子 → tracepoint → BPF”复制，不在模块内处理；
binder 仅适合诊断；DNS 仍需一次测量包 socket UID 的复测。落地要求同第一次审查的“若要落地”一节。

---

# 第三次审查：对 Gemini 回应（`E:\work_sb\003.txt`）的意见（2026-10-04）

用户表示坚持“全能模块”方向，要求对有分歧之处给出源码或网上依据。本节只记录意见，不修改探针文件。

## 当日核实的事实

- `android_vh_inet_csk_clone_lock(newsk, req)` 在 `inet_csk_clone_lock()` 末尾调用
  （`net/ipv4/inet_connection_sock.c:1284`，位于 `security_inet_csk_clone()` 之后）；监听 socket 可由
  `req->rsk_listener` 取得（`include/net/request_sock.h:59`，`#define rsk_listener __req_common.skc_listener`）。
- binder 驱动编进内核：设备 `CONFIG_ANDROID_BINDER_IPC=y`（`CONFIG_ANDROID_BINDER_IPC_RUST=m`）；
  vmlinux BTF 中有 `STRUCT 'binder_transaction'`。标准 tracepoint
  `TRACE_EVENT(binder_transaction_received, TP_PROTO(struct binder_transaction *t))`
  （`drivers/android/binder_trace.h:179`），设备上存在对应的 `btf_trace_binder_transaction_received`。

## 认可

1. **DNS：证据确凿，撤回上一轮的质疑。** `dnsuid/` 出口探针在干净环境（生产服务停止、Chrome 前台）
   测得 netd 出口 DNS 包 socket UID 为 `map[10136:2 10309:2]`、1051 为 0；root 查询为 `map[0:2]`。
   App 的明文 DNS 包带 App UID，`enforceDnsUid` 未开启，与 `res_send.cpp`
   `uid = statp->enforce_dns_uid ? AID_DNS : statp->uid` 一致。
   - 仍未证实：“1051 为 netd 自身验证/探测”只是推测，未给出查询域名。
   - 由此引出本仓库自己的待查问题：既然 App DNS 包带 App UID，整服务验收为何没有出现
     “netd（创建者 UID 0）的 socket 为 App 工作”的请求方日志，只出现了 1051。
2. **多包 UDP 数据**（`tc_udp_with_identity=17`、`udp_later_covered=3`，3 单包流 + 2 五包流）补上了
   `tracepoint_producer_probe` 未完成的测试，结论与预期一致；建议原始输出入库。
3. **accept 走“钩子 → typed tracepoint → BPF”**：对方已承认模块不能写 SK_STORAGE。既然用户坚持模块方向，
   此路可行：钩子把 `newsk` 与 `req->rsk_listener` 交给 BPF，BPF 读监听者快照、以子 socket 的**新 cookie**
   写入子 socket 存储，不需改 TC 的 `creator.cookie == socket cookie` 校验。代价是模块与 BPF 各增代码；
   `BPF_F_CLONE` 方案的代价是改 TC 一条规则。两者均成立，不再坚持后者。

## 仍不同意及依据

1. **“全能模块对 UDP 降维打击”结论对、但非新发现。** 现行 v2 桥接已挂在 `__sock_create` 末尾
   （`net/socket.c:1602`）；覆盖由执行顺序保证（`socket()` 返回后程序才能 `sendto()`），
   “640 µs 余量”的测量对结论不起作用。
2. **binder 字段不应在模块里读，应放在 BPF。**
   - 模块读 `t->sender_euid`、`t->from_pid` 依赖编译时头文件的结构体布局。MODVERSIONS 的 CRC 保护导出符号
     签名；厂商钩子头文件中 `struct binder_transaction` 只是前向声明，字段布局不在校验范围内，内核更新可能
     悄悄读错字段。
   - binder 编进内核、类型在 vmlinux BTF 中，标准 tracepoint 可挂：用 BPF CO-RE 读取会按当前内核重定位，
     更安全，且无需模块。
3. **binder 与 `cookie_tag_map`“两者结合 100% 穿透”不成立。**
   “线程处理来自 C 的事务期间新建的 socket 归 C”只对同步处理成立，语义上等同 `Binder.getCallingUid()`
   （当前正在处理的事务的发送方）。工作交给 Handler/线程池异步执行（system_server 常见）时关联断开；
   oneway 事务、嵌套调用还需额外事件来判定“处理何时结束”。`cookie_tag_map` 是 v2 已读取的 charge UID，
   与模块无关，也只覆盖主动打标签的代码。两者合计是部分覆盖。用户按发送者路由，此类信息只作诊断。
4. **“把模块削成跳板是本末倒置”有硬边界。** 本机内核不向模块导出 `bpf_map_*`，模块写不了 BPF 存储，
   TC 也读不到模块数据。无论多“全能”，模块只能在现场采集事实、经 tracepoint 交给 BPF，存储与数据面
   始终在 BPF。合理定义：**模块负责只有内核现场才拿得到的事实（socket 创建、accept 派生、可执行路径）
   与生命周期开关；BPF 负责存储与逻辑。**
5. **“<0.3 ns”“0 UAF 风险”“免疫 OverlayFS”仍未实测或证明**，只能算设计目标。

## 按“全能模块”方向的建议落地顺序

1. 桥接模块增加 `inet_csk_clone_lock` 入口：BPF 以子 socket 新 cookie 写快照，不改 TC。
2. 模块在创建现场附带可执行路径（仅原生程序：`get_file_rcu` + `d_path`），经 tracepoint 参数交给 BPF。
3. 字符设备生命周期开关（0600、持有者计数），作为可选配置。
4. binder 调用方作为诊断：BPF 挂标准 tracepoint，不进模块、不参与路由。

每项先用探针在真机验证，再接入生产；测试前后记录 taint，做长时间运行测试。

---

# 第四次审查：对 Gemini 回应（`E:\work_sb\004.txt`）的意见（2026-10-04）

用户坚持“全能模块、高效率、极致性能”方向，要求分歧处给出源码或网上依据。本节只记录意见，不修改探针文件。

## 当日核实的事实

- `BPF_F_CLONE` 的克隆路径（`net/core/bpf_sk_storage.c`）：`bpf_sk_storage_clone()` 由
  `sk_clone_lock()` 调用（`net/core/sock.c:2485`）；对每个带 `BPF_F_CLONE` 的元素调用
  `bpf_sk_storage_clone_elem()`，其中 `bpf_selem_alloc(smap, newsk, NULL, true, GFP_ATOMIC)`
  分配新元素（第 140 行），值以 `copy_map_value()` 原样复制（第 148 行）；子 socket 首个元素还需
  `bpf_local_storage_alloc(newsk, smap, copy_selem, GFP_ATOMIC)`（第 198 行），并 `bpf_selem_link_map()`
  挂入 map 哈希桶（第 195 行）。
- `TrafficStats`（已迁至 Connectivity 模块 `framework-t/src/android/net/TrafficStats.java`）：
  `setThreadStatsUid` 的说明为“Set specific UID to use when accounting Socket traffic originating from
  the current thread. Designed for use when performing an operation on behalf of another application”，
  并注明只有持有 `UPDATE_DEVICE_STATS` 的调用方才能把流量记到其他 UID；没有任何“必须调用”的表述。

## 认可

1. **accept 继承改用 `BPF_F_CLONE`。** 在“极致性能”前提下，克隆由内核在 `sk_clone_lock()` 内完成，
   省去 tracepoint 分发、BPF 程序执行与一次查表，比“钩子 → tracepoint → BPF”更轻。上一轮接受钩子方案
   只是为避免改 TC；按用户的性能优先级，`BPF_F_CLONE` 更合适。需更正三处细节（见下）。
2. **UDP 与 DNS 的实质结论**同第三次审查：DNS 已由 `dnsuid` 实测证实 App 明文 DNS 带 App UID。

## 对 `BPF_F_CLONE` 方案细节的更正

1. **不是“<10 纳秒、0 内存分配”。** 每次克隆以 `GFP_ATOMIC` 分配元素，子 socket 还分配一次存储并挂入
   哈希桶（行号见上）。只是开销小于钩子方案。手机上被动接受的连接很少，两者在整机层面差别基本不可感知。
2. **对方提议的 TC 条件永远不成立。** 值是原样复制的，子 socket 的快照不会出现
   `SB_SOCKET_CREATOR_INHERITED` 标志，`creator->flags & SB_SOCKET_CREATOR_INHERITED` 恒为假。正确规则：
   快照有效且“快照 cookie ≠ 当前 socket cookie”即判为继承（producer 写快照时总写自身 cookie，
   不等只可能来自克隆），并在 assignment 中标记“继承”。
3. **需要改的不止 TC。** 当前三处都明确拒绝 CLONE 标志，须一并放开：
   - producer map：`common/socketidentity/bpf/creator.bpf.c` 只设 `BPF_F_NO_PREALLOC`；
   - collector 校验：`common/socketidentity/identity.go` `loadSpec` 要求 `m.Flags == 1`；
   - sing-ebpf 校验：`internal/core/socket_creator.go` `validateSocketCreatorMapInfo` 要求 flags 恰为
     NO_PREALLOC（另有对应单元测试 `CLONE flag` 用例期望拒绝）。
   放开后应同时验证：克隆值的 cookie 与子 socket 不同、TC 按上述规则接受，producer 自身写入不受影响。

## 仍不同意及依据

1. **“AOSP 规范要求异步代发必须调用 `setThreadStatsTagUid`”不成立。** 见上引 `TrafficStats` 原文：可选的
   计费接口，且跨 UID 记账需 `UPDATE_DEVICE_STATS`。主动调用的组件（如 DownloadManager）可覆盖，未调用的
   覆盖不到，“双保险 / 完整闭环”只能算部分覆盖。
2. **binder 字段仍不应在模块里读。** 本轮未回应第三次审查的依据：模块读 `t->sender_euid` 依赖编译时结构体
   布局，不在 CRC 保护范围内；binder 编进内核、类型在 vmlinux BTF 中，用 BPF 挂标准 tracepoint
   `binder_transaction_received` 以 CO-RE 读取更安全且无需模块。用户按发送者路由，此信息只作诊断，
   对性能与路由无影响。
3. **架构图里的“全能模块”名不副实。** 第 2 项（`BPF_F_CLONE`）是 BPF map 标志，第 3 项（UDP 首包覆盖）
   是现行 v2 桥接已有能力，都不是模块新增功能。“<0.3 ns 静默”“Java 快速比对 <2 µs”仍无实测数据。

## 落地顺序（按“全能模块 + 极致性能”方向，替代第三次审查的顺序）

1. **accept 继承：`BPF_F_CLONE`。** producer map 加 `BPF_F_CLONE`；collector 与 sing-ebpf 校验放开该标志；
   TC 规则改为“快照有效且 cookie 不等即为继承”，assignment 中标记继承；用户态把继承快照视为监听进程
   （服务端，即发送者）。
2. **模块在创建现场取可执行路径**：仅对 `(s_dev, i_ino)` 不同于 app_process 的原生程序执行
   `get_file_rcu` + `d_path` + `fput`，路径或其哈希与长度经 typed tracepoint 参数交给 BPF 写入快照，
   用户态不再读 /proc。
3. **字符设备生命周期开关**：设备 0600、按持有者原子计数、最后一个持有者关闭即停采；作为可选配置，
   默认保持 pin 持久化以覆盖重启窗口。
4. **binder 调用方作为诊断**：BPF 挂标准 tracepoint `binder_transaction_received`，以 CO-RE 读取发送方，
   不进模块、不参与路由。

每项先用探针在真机验证，再接入生产；测试前后记录 taint，做长时间运行与分段开销测量（含
“停采后开销”“原生程序取路径开销”的实测，而非估算）。

---

# 第五次审查：对 Gemini 回应（`E:\work_sb\005.txt`，提交 `e2c40ace`）的意见（2026-10-04）

本节只记录意见，不修改探针文件。

## 当日核实的事实

- **GKI ABI 收录了 `struct binder_transaction` 的完整定义。** 内核源码树 `gki/aarch64/abi.stg` 第 276196 行
  为 `struct_union { kind: STRUCT name: "binder_transaction" definition { bytesize: 192 member_id: ... } }`，
  钩子符号 `__traceiter_android_vh_binder_transaction_received`（第 437565 行）、
  `__tracepoint_android_vh_binder_transaction_received`（第 445134 行）也在 KMI 中。即在 android16-6.12
  这一代 KMI 内，该结构体布局受 GKI ABI 监控保护，改动需经 ABI 破坏审批。
- **本机两次 `ktime_get_ns()` 自身约 163–187 ns**（`creator_v2_probe` 分段测量的 `avg_clock_ns`，
  `experimental/creator_v2_probe/results/capture-breakdown.log` 所在轮次）。
- **原生进程在 inet socket 创建中的占比约 40%**：`creator_v2_probe` 180 s 采集的 207 个 inet socket 中，
  netd 28 个、`iptables-restore`/`ip6tables-restore` 合计 54 个、sing-box 2 个
  （`experimental/creator_v2_probe/results/capture.jsonl`）。

## 认可

1. **accept 继承已达成共识**：`BPF_F_CLONE`；TC 规则“快照有效且 cookie 不等即为继承”；三处校验一并放开。
2. **撤回第三、四次审查中“binder 字段不应在模块里读”的反对。** 依据即上引 `abi.stg`：符号 CRC 不覆盖该布局，
   但 KMI 的 ABI 监控覆盖。用户坚持模块方向时，模块直接读 `t->sender_euid`、`t->from_pid` 可以接受；
   用 BPF CO-RE 读取同样可行，两者均可。
3. **本轮补上了此前要求的实测**：测试前后 taint 均为 4608（无新增警告）；慢路径分段：`get_file_rcu`
   208–312 ns、`d_path` 热 625–990 ns / 冷 2.6–3.3 µs、`fput` 208–261 ns，热总 1.4–1.7 µs。数据可信。

## 分歧

1. **“停采开销 104–260 ns”主要是时钟读数本身。** 测法是在回调内前后各调一次 `ktime_get_ns()`，而本机这对
   调用自身即约 163–187 ns；`READ_ONCE` 判断本身只有几纳秒。另一方面，它又不含 tracepoint 分发到回调的开销。
   “停采后开销可以忽略”的结论成立，但该数字不能当作实际开销引用。准确测法应是“未加载模块 / 已加载但停采 /
   采集中”三态的 `socket()` 微基准对比（此前 `sockbench` 显示这类差别落在 1–2 µs 噪声内，难以分辨）。
2. **“原生程序很少，全机加权开销趋近于零”不对。** 本机原生进程约占 inet socket 创建的 40%（见上），netd 每次
   DNS 查询都新建 socket，都会走 `d_path` 慢路径（热约 1.5 µs、冷约 4 µs）。绝对值仍小（全机每秒数个 socket），
   但不是“趋近于零”。追求极致性能时，可在模块内按 `(s_dev, i_ino)` 缓存最近解析的路径，同一程序只 `d_path`
   一次。
3. **“零内存泄漏、绝对安全”不能由 taint 不变推出。** taint 只记录 WARNING/BUG 等事件，不跟踪泄漏，本内核也未开
   kmemleak。可下的结论只是“本次运行未触发内核警告”。
4. **binder“同步 RPC 100% 命中”仍未验证。** 迄今日志只证明“收到事务时能拿到发送方 UID”，从未把某个事务与某个
   socket 关联测过。需在 binder 线程处理事务期间创建 socket 并核对对应关系。异步侧 `setThreadStatsUid` 为可选接口
   （第四次审查已引原文），整体仍是部分覆盖；用户按发送者路由，此信息只作诊断。
5. **架构图仍沿用已更正的说法**：“<10 ns 零损耗”已在第四次审查中共同更正（克隆有 `GFP_ATOMIC` 分配）；
   “Java 快速比对 <2 µs”无实测数据。

## 落地顺序（在第四次审查基础上的修订）

1. accept 继承：`BPF_F_CLONE`；producer map、collector、sing-ebpf 三处校验放开；TC 按 cookie 不等判定继承并标记。
2. 模块在创建现场取可执行路径：仅原生程序，`get_file_rcu` + `d_path` + `fput`，**并按 `(s_dev, i_ino)` 缓存路径**；
   经 typed tracepoint 参数交给 BPF 写入快照。
3. 字符设备生命周期开关：0600、持有者原子计数，可选配置，默认保持 pin 持久化。
4. binder 调用方作为诊断：**模块读取（KMI 保护布局）或 BPF CO-RE 读取均可**；先验证“事务 ↔ socket”关联，
   不参与路由。

每项先在真机验证再接入生产；开销以三态 `socket()` 微基准或分段计时（扣除时钟自身开销）实测。

双方在方向上已基本一致；以上分歧均在数字与措辞，不涉及架构方向。

---

# 第六次审查：对 Gemini 回应（`E:\work_sb\006.txt`）的意见（2026-10-04）

本节只记录意见，不修改探针文件。

## 当日核实的事实

- 设备 `/data` 为 f2fs（`/dev/block/dm-62 /data f2fs ...`）。f2fs 分配新 inode 时
  `inode->i_generation = get_random_u32()`（`fs/f2fs/namei.c:253`），落盘与读回见 `fs/f2fs/inode.c:438/712`。
  即文件删除后 inode 号可被新文件复用，仅 generation 不同。`/system` 为只读分区，无复用问题。
- 本机 exe 指针链（`mm → exe_file → f_inode`）实测：先执行者约 1.0 µs（`avg_exe_direct_ns=1233` 减
  `avg_clock_ns=187`），后执行（缓存热）约 0.05 µs（`avg_exe_ns=240` 减时钟）。见
  `experimental/creator_v2_probe/results/capture-breakdown.log` 及计划文档“真机预验证 1”。开销由 cache miss 主导。

## 认可

- 大方向一致：accept 用 `BPF_F_CLONE`、TC 按 cookie 不等判定继承；模块现场取路径并加缓存；字符设备生命周期
  开关；binder 由模块读取、作为诊断。分阶段顺序（先 CLONE，再路径与生命周期，最后 binder）合理。
- 路径缓存方向正确，可把 netd、`iptables-restore` 等高频原生程序的开销从约 1.5 µs 降下来。

## 分歧与更正

1. **缓存键须含 `i_generation`，否则可能返回错误路径。** 依据 `fs/f2fs/namei.c:253`：`/data` 上 inode 号可复用、
   generation 随机更新。键应为 `(s_dev, i_ino, i_generation)`。文件改名/移动时 inode 不变，缓存路径会过期，
   应加有效期兜底。钩子在多 CPU 并发执行，共享缓存需加锁或每 CPU 一份；草案未涉及，加锁时“<10 ns”不成立。
2. **“Java 门控 <5 ns”“命中缓存 <10 ns”与实测矛盾。** 门控须先读 `current->mm->exe_file->f_inode` 才得到
   `(dev, ino)`，该指针链冷约 1 µs、热约 50 ns，开销来自 cache miss 而非比较本身。
   可实际节省之处：现行 BPF producer 已在读同一指针链取 exe inode；改由模块读一次，并经 tracepoint 参数把
   `(dev, ino, generation)` 交给 BPF，BPF 不再重复读，则模块门控几乎不增加净开销。
3. **第三阶段写成“诊断与策略增强”，与用户要求冲突。** 用户要求代发流量按发送者路由，binder 调用方只能作诊断，
   不能进入路由策略。“事务 ↔ socket”对应关系仍未验证，第五次审查第 4 点未获回应。
4. **仍沿用已更正或缺少依据的说法（第五次审查已指出，本轮未回应）：** 架构图中 `BPF_F_CLONE` 仍写“<10 ns”
   （克隆有 `GFP_ATOMIC` 分配）；“停采降至 100 ns”主要是时钟读数；“零内存泄漏”不能由 taint 不变推出。
5. **“100% 完全共识”言过其实。** 第五次审查原文为“方向基本一致，分歧在数字与措辞”，且仍有上述未解决项。

## 落地顺序（修订）

1. accept 继承：`BPF_F_CLONE`；放开 producer map、collector、sing-ebpf 三处校验；TC 按 cookie 不等判定继承并标记。
2. 模块现场读一次 exe，把 `(dev, ino, generation)` 经 typed tracepoint 交给 BPF，BPF 不再重复读取；仅原生程序
   取路径；路径缓存以 `(dev, ino, generation)` 为键、设有效期、每 CPU 一份或加锁。
3. 字符设备生命周期开关：0600、持有者原子计数，可选配置，默认保持 pin 持久化。
4. binder 调用方仅作诊断，先验证“事务 ↔ socket”对应关系，不参与路由。

开销一律以三态 `socket()` 对比或扣除时钟开销的分段计时实测。
