# Android 归属与包表更新：执行计划

这是本任务唯一的执行检查表。执行前读本文件，执行后在同一处更新状态、证据和未完成项。
不另建平行方案，不把源码推断或探针结果写成生产功能已经完成。

## 给 Claude 的接手摘要（2026-10-03）

用户要求把设计目标、已完成、未完成及测试写入文件，由 Claude 接手完成目标设计。
请先阅读本节，再按下面的代码入口与详细实施记录核对事实；后续设计、实施和验收继续更新
本文件。当前这轮实现与隔离测试已经结束，接手时无需等待旧测试进程。

### 设计目标与已确认约束

**目标**：在不使用自定义内核的前提下，同时减少 Android 流量归属的查询环节，并提高
创建进程/应用归属的可靠性。尽量把创建现场已知的事实随 socket 保留，再由现有 TC
一次交给 sing-box；缺少证据时明确未知。用户希望同时获得少环节与更高精度，尚未接受
“只能二选一”作为最终设计结论，也没有把当前实现认定为最终架构。

- 不考虑自定义内核；当前已证实匹配现有内核的小桥接模块可行。
- 主实现位于 `E:\ebpf_sing-box`，依赖改动在已有 `E:\sing-ebpf`。不改 `E:\Ref_sing-box`，
  不新增 sing/sing-tun/fswatch fork，不提交本机路径 replace。
- 当前生产集成复用已有 TC，不增加独立 TC/TCX 采集挂点或常驻 Java/app_process 助手。
  私有 netns 内的 TCX 测试挂载仅用于验收，不是额外生产架构。
- 保留包表与 UID 规则热更新；正常更新不拆除重建整个后端，不引入临时丢包保护。
- 创建者 UID、socket 记账 UID、代发请求来源、包名是不同语义。cgroup 目录中的 PID、
  comm、单个数字 PID、当前包表中的唯一 UID，都不能单独充当所有场景的创建实例/请求包证明。
- 默认关闭新采集器，显式启用失败要报错；未知不能被路由器再次补成整组候选包，
  也不能隐式变更为直连或其他出口。
- 用户允许研究超出既有项目假设的方案。若目标设计需要修改 AOSP 启动/代发链路，
  应明确列出系统改动、可信来源、部署及维护条件；当前尚未实现这些平台改动。

### 当前架构及其边界

已接通的创建者链路：

```text
现有 Android socket-create vendor hook
  → 小模块 sbo_identity_bridge 的同步 typed tracepoint
  → BPF producer 在 SK_STORAGE 初始化 48 字节创建者快照
  → 现有 sing-ebpf TC 读取并复制到 assignment
  → sing-box 消费快照，再按现有证据规则细化进程/包名
```

快照包括 cookie、TGID、TID、创建者 UID、leader 出生时间和 comm；UID 0 合法。
创建者事实与可变的 socket 记账身份分开；快照已有效时不改写，换 cookie 或 shared
路径不沿用旧创建者。只有当前包确实拿到 full socket 且 storage 不存在，才缓存“已查无”。
普通唯一应用 UID 保留快速归包；共享/系统 UID 等路径仍可能需要 `/proc` 与 Manifest。
普通快路径可附带快照中的真实创建者 PID，但仍不查询精确 exe；其包名是应用/组级归属，
不是逐 socket 的可信 APK token。
进程已经退出时，创建者数值快照仍可存在，但这不保证能恢复其完整 exe/cmdline 或唯一 APK。

producer link、map 和冻结 metadata 都会 pin。正常 Close 只释放本实例 FD/lease，
停止期间继续采集；重开校验 boot/ABI/对象哈希、对象 ID 及真实关联，拒绝覆盖不兼容对象。
显式 Remove 与普通停止分开，使用者仍持有 lease 时拒绝移除。升级 producer 前，须用
匹配旧对象的旧版维护命令移除；已存在且未采集的 socket 不补记创建历史。

生产代码**没有**可信 APK token、TASK_STORAGE 登记器或 AOSP 启动注册通道。另一套
独立原型验证了“父进程用子进程自身交出的 pidfd 登记 TASK_STORAGE，再复制 token 到
SK_STORAGE”，其中 token 是随机合成值，不能解释为已经绑定真实包名。

### 已完成与未完成总览

| 工作 | 当前状态 | 证据与限制 |
|---|---|---|
| 包表监听、不可变快照、失败保留旧表 | 已完成 | 阶段 1 本机与 10 轮安装/卸载真机验收；升级样本为覆盖重装 |
| UID 规则热更新及 assignment 基础身份 | 已完成 | 阶段 2 及阶段 3 的规则实际生效验证；不宣称多 map 写入原子无窗口 |
| 修正把 cgroup 目录 PID 当创建者的错误 | 已完成 | `cae57485` 及相应用例；组身份与每个 cookie 的创建者分开 |
| 持久创建者 producer、TC 传递、用户态接线 | 第一轮实现完成 | `ee0208de` 与依赖 `33964031`/`74ad17e7`；新功能默认关闭 |
| 新链路在目标内核加载与隔离真包测试 | 已完成 | 8 组 TC 用例、3 组真实 producer→TC、16 个生命周期快照，详见下表 |
| 新链路下真实 App 与完整 sing-box 服务验收 | 未完成 | 当前服务未切换到新功能；组件测试不替代完整服务重启及路由验证 |
| 可信进程实例→APK/请求来源绑定 | 目标设计待完成 | 仅有创建者事实和独立 token 载体原型，没有平台可信登记实现 |
| accept、exec、代发、异步及复用连接的完整身份语义 | 设计与验证未完成 | 下节列出已经发现的边界；不能按普通 socket 创建场景外推 |
| 新旧全链路的性能、内存、功耗和长稳对照 | 未完成 | 旧消费端对比数据存在，但不是本次 SK_STORAGE 新方案对比 |
| 依赖发布、正式部署、移植 | 未完成 | 本轮提交未推送；未修改移植目标仓库 |

### 请 Claude 完成的设计决策

1. **先定义要对谁归属。** 区分创建 socket 的 task、当前使用 socket 的进程、记账对象、
   Android 包/宿主，以及代理服务的原始请求方。定义输出字段、证据等级、未知原因和路由
   使用规则；多个包共用同一进程或一条连接承载多来源请求时，不强行选唯一包。
2. **决定可信包身份从哪里来。** 评估保留当前 proc/Manifest 细化的适用范围，以及是否
   需要在 AOSP 可信启动路径同步登记进程实例→包/宿主关系。若采用 token，明确注册方、
   权限、在最早可能建 socket 前的时序、pidfd/实例绑定、元数据字典寿命及撤销规则。
   迟到事件中的 PID 再去打开 pidfd，不能证明仍是事件原来的 task。
3. **定义生命周期语义。** 独立原型已观察到：fork 新 task 不继承登记；继承的父 socket
   保留父身份；非 leader exec 可保持数字 PID 和出生时间，但原 TASK_STORAGE 丢失；
   当前未开 clone 标志，accepted child 无快照。普通 exec 也可能改变 exe/cmdline。
   明确新旧 socket、acceptor/listener、exec 代际、启动存量、包升级和 UID/PID 复用的处理。
   不把 `PID + 出生时间` 当作覆盖所有 exec/task 替换的令牌。
4. **决定特殊来源的边界。** 为 shared UID、共享进程、isolated/SDK sandbox、系统 native、
   DNS/netd/DownloadProvider 等代发，以及 io_uring 定义可证明的归属。代发请求方通常
   需要服务入口的可信上下文；对多来源共用的 HTTP/2、QUIC 等连接，评估请求级路由或
   按来源拆连接池，不能用最后一次请求覆盖整条 socket 的创建身份。
5. **明确兼容和失效策略。** 给出模块/producer 缺失、半套 pins、版本不兼容、无旧来源、
   分配失败、消费者重启、模块停止和设备重启的状态转换与降级结果。保留已证实的
   持久化契约，区分正常停止、禁用配置、升级与显式卸载。
6. **以测量决定代价。** 说明每个处理环节发生在进程启动、socket 创建、首包、每连接
   还是每包。当前 assignment 由 40 增至 88 字节，8192 项仅 value 容量增加 384 KiB；
   SK_STORAGE 分配、全局 hook、索引和用户态缓存的实际开销仍需测。普通快路径原本
   已能避开 ioctl/proc，不能把省查询次数直接换算为总体性能提升。

建议交付：在本文件补齐选定架构及候选方案取舍、身份数据模型与信任来源、事件时序、
生命周期/错误状态转换、兼容与迁移策略、开销模型、实现落点和可复现验收矩阵。
将“已由证据支持”“待验证假设”“尚未实现”逐项标明，再据此推进阶段 3 的后续工作。

### 测试现状与下一轮验收

| 测试层级 | 已执行结果 | 不能据此推出的结论 |
|---|---|---|
| 主仓库本机 | 五个相关包 race、vet 通过；完整 Android arm64 构建通过 | 不代表手机上的完整应用服务已经启用新链路 |
| producer/模块构建 | 内嵌 BPF ABI 检查；15/15 传统及扩展 CRC、14 个导入覆盖；目标内核实际加载通过 | 不代表其他 Android 内核或 ROM 自动兼容 |
| WSL/Android 合成 storage→TC | 同一套 8 组真实数据面用例通过：首包、保持、缺失、无效值、tuple 复用、delivery、外借 FD、错误 map | storage 由真实 socket FD 注入，单独这组不验证创建钩子 |
| Android 真实 producer→TC | IPv4 TCP 首包、UDP 首包、TCP delivery 三组通过；首次发送前已有记录，48 字节完全一致 | 不是实际 App 自主流量，也不是 IPv6/shared 完整转发验收 |
| Android collector 生命周期 | 四阶段各 4 个 IPv4/IPv6×TCP/UDP，共 16 个快照、29 次观察；另一个旧 socket 始终未知；子进程退出后复用相同对象；Remove 忙/成功均通过 | 是采集器组件重开，不是完整 sing-box 服务重启 |
| 独立 TASK_STORAGE 原型 | 15 组；35 个创建快照、34 个首次发送匹配，另有 accepted child 缺失的明确结果 | 随机 token 不代表可信 APK 登记；该原型不等于生产方案 |
| 旧消费端配对实验 | 历史五对真实 echo 检查及详细限制已记录在后文 | 不证明本轮 SK_STORAGE 链路更快、更省内存或更省电 |

下一轮未完成验收应至少包括以下项目，继续沿用阶段 3 的复选框，跑完再勾选：

- 真实 App 自主发流、冷/热启动、普通/共享 UID、共享进程歧义、native/宿主区分；
  独立 ground truth 与归属结果逐条匹配，分别统计错误归属、正确归属、未知和漏采。
- 完整 sing-box 入口上的 TCP/UDP、IPv4/IPv6、UDP 多目的地、delivery/shared；
  对端核验实际业务载荷及回包，不能只用 connect 成功判定转发完成。
- 新链路无旧模块来源、producer/模块缺失的预期行为；完整服务关闭/重启前后旧、新
  socket 的身份和实际路由；兼容升级、显式移除与资源清理。
- 包真实版本升级、进程退出/受控 PID 复用、UID/包表变化、启动存量、Framework 重启。
  历史“不使用 AM 日志”只使 AM 断连测试不适用，不免除 Framework 变化的验证。
- accept、fork/exec、FD 转交、io_uring 与多来源连接的目标语义确定后，补生产路径测试。
- 相同设备/配置/负载、明确模块及 hook 开启状态下，比较仅旧方案与仅新方案；交替多轮，
  分离建连和回包尾延迟、CPU、用户态/内核内存、吞吐及功耗，补长时间持有/释放与重启循环。
  阈值和采样办法先在设计里写清，不能剔除变慢轮次或用双来源同时运行的数据称“仅新方案”。

### 仓库、代码和证据入口

| 入口 | 用途 |
|---|---|
| `E:\ebpf_sing-box`，分支 `codex/strict-app-attribution` | 主仓库；交接前实现 `ee0208de`，验收记录 `7bc72605` |
| `E:\sing-ebpf`，分支 `android-attribution` | 依赖；功能 `33964031`，BPF 外部 memcmp 修复 `74ad17e7`，真实 producer 测试 `2354018` |
| `common/socketidentity/` | 48 字节 ABI、BPF producer、持久对象及 lease、实际设备生命周期测试 |
| `protocol/ebpf/socket_creator.go`、`inbound_lifecycle.go` | 采集器配置及 TC 借用 map 的启动/关闭顺序 |
| `protocol/ebpf/socket_identity.go`、`socket_owner_resolve.go`、`process_package_index.go` | 创建者消费、旧来源回退、proc/Manifest 细化与诊断 |
| `common/androidpackages/`、`common/androidmanifest/`、`protocol/ebpf/android_uid_update.go` | 包表、Manifest 证据、UID 规则热更新 |
| 依赖的 `api.go`、`internal/core/socket_creator.go`、`internal/core/tc.go`、`native/tc.bpf.c` | 外借 map 接口、assignment ABI 与 TC 读取/失效逻辑；生成物须与 C 同步 |
| `experimental/identity_carrier_probe/` | 独立 token 原型、桥接模块、隔离生产组件验收脚本；两类实验语义分开 |
| `docs/configuration/inbound/ebpf.zh.md` 的 `local.socket_creator` | 默认关闭、启用前提、pin 路径、停止/移除/升级约定 |
| `build/socket-creator-integration/device-audit.json` | 最后一轮独立离线审计：16/29/3、14 份前后状态相同 |
| `build/socket-creator-integration/device-results/run-20261003-200332-15455/` | 最终 `core.log`、`collector.log`、`inner.log`、输入哈希及前后状态 |
| `build/socket-creator-integration/device-run0{1,2,3}.txt` | 两轮在测试前安全拒绝的原因，以及最终完整通过/清理输出 |
| `experimental/identity_carrier_probe/results/lifecycle-*` | 独立 token 原型的 fork/exec/accept 原始证据 |

原始日志、构建工具缓存和产物被 Git 忽略，仅在此工作区存在；跨机器交接须另行带走
必要证据，不能假设 git clone 含有日志。两个仓库的本轮提交均未推送。主仓库正式依赖
固定在 `v0.1.0-alpha.11.0.20261003114235-74ad17e7ec35`；本机通过标准 Git 模块归档
离线校验，其他机器需先能取得该依赖提交。不要把依赖 `2354018` 的测试新增误认为主仓库
已经升级到它；生产代码所需修复已经包含在当前固定版本中。

可复用的主仓库本机命令（WSL/Linux，已使用 Go 1.26.6；race 需要本机 CGO 工具链）：

```sh
go test -race -tags with_ebpf ./protocol/ebpf ./common/socketidentity ./common/androidpackages ./common/androidmanifest ./option -count=1
go vet -tags with_ebpf ./protocol/ebpf ./common/socketidentity ./common/androidpackages ./common/androidmanifest ./option
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -tags integration -o socketidentity.test ./common/socketidentity
```

完整 Android 构建使用 `.github/workflows/android-ebpf.yml` 的 `BASE_TAGS`、`release/LDFLAGS`
和 NDK r29；本轮实际脚本及日志在 `build/socket-creator-integration/pinned-checks.sh`、
`pinned-race.log`、`pinned-vet.log`、`android-build-info.txt`。在依赖仓库构建手机 TC 测试：

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -tags 'with_ebpf ebpf_integration' -o core.test ./internal/core
```

手机入口是 `experimental/identity_carrier_probe/run-creator-integration-device.sh`。
它要求匹配设备 BTF/CRC 的模块、两个测试二进制、base BTF 哈希，以及当次确认的生产
PID/出生 ticks/内核/boot ID；不要把历史 PID 11765 或 boot ID 当常量重放。
模块不能与已有同名桥接模块盲目替换；脚本核验私有 mount/netns、测试清单、无跳过及完整清理。
模块构建说明在 `experimental/identity_carrier_probe/module/README.md`。

最后一次设备测试后，测试模块已卸载、pins 和私有挂载已清理、专用临时目录已删除；
生产服务保持原实例。接手时重新检查设备和 Git 状态。主仓库已有 7 个历史未跟踪实验目录：
`attribution_bench`、`attribution_precision_probe`、`cookie_tag_probe`、`dns_uid_probe`、
`first_connection_probe`、`mainline_validation`、`process_identity_probe`，均在 `experimental/`
下；保留它们，尤其其中被下文引用的证据，不执行全量清理或顺手批量提交。

## Claude 目标设计（2026-10-03，分支 `claude/attribution-target-design`）

本节回答上面“请 Claude 完成的设计决策”1–6，是后续实施与验收的依据。分支：主仓库与
`E:\sing-ebpf` 均为 `claude/attribution-target-design`，分别从 `b7d7f230` 与 `2354018` 切出。
每条结论标注依据：**[源码]** 已读到的 AOSP/Linux 源码位置；**[实测]** 已有真机或本机测量；
**[待验证]** 设计假设，必须在下文验收矩阵中实测后才能改为已证实；**[未实现]** 尚无代码。

### 选定架构：创建现场固化 + 内核已有记账来源 + 用户态纯函数解析

不改 AOSP、不改 netd、不用自定义内核；沿用 GPT 已实现并实测的桥接模块 typed tracepoint
与持久 SK_STORAGE producer，扩充创建现场写入的事实，再由已有 TC 一次交给 sing-box。

```text
__sock_create 末尾 trace_android_vh_sock_create        [源码] net/socket.c:1602
  → sbo_identity_bridge typed tracepoint → BPF producer（创建线程上下文）
      v1 已有：cookie、TGID、TID、创建者 UID、leader 出生时间、线程 comm
      v2 新增：argv[0] 哈希（进程记录名）、exe inode、标志位            [未实现]
  → SK_STORAGE（不可改写、随 socket 释放）
  → 已有 TC 首包/刷新时复制到 assignment
      另读：sk_uid、socket cgroup id（已有）；netd cookie_tag_map 记账 UID/标签 [未实现]
  → sing-box：纯函数解析，按证据等级给出包名或明确未知
```

**为何不采用 AOSP/zygote 启动登记（TASK_STORAGE token）**：
- **更正（2026-10-04）**：原先写的“bootloader 锁定（`ro.boot.verifiedbootstate=green`、
  `vbmeta.device_state=locked`）”是错的。用户指出设备已解锁 BL；`/proc/bootconfig` 实测为
  `androidboot.verifiedbootstate = "orange"`、`androidboot.vbmeta.device_state = "unlocked"`，
  `getprop` 读到的 green/locked 是 root 模块（如 TA_enhanced、oh_my_keymint）伪装的属性，
  不能作为证据。所以“无法修改 system_server/zygote/netd”不成立：netd 的 BPF 程序仍在签名的
  mainline APEX `com.android.tethering/etc/bpf/mainline/netd.o` 中，但解锁设备上替换或覆盖它
  技术上可行（代价是随 mainline 更新失效、需自行维护，用户已明确不接受自定义内核，系统分区
  改动未经用户同意不做）。本设计不依赖这条理由：下面两条以及 v2 的实测结果已足以支持选型；
  如用户愿意承担系统侧改动，AOSP/zygote 登记可作为后续可选研究，而非被设备状态排除。
- 启动登记能得到的是“进程为哪个包启动”。对多包共享进程，这与 `am_proc_start` 同源，
  后续载入同一进程的其他包无法区分（阶段 1 探针 B 被误认为 A）[实测]。因此它对
  真正剩余的歧义没有额外区分力，只能缩短事后查询。
- 事后查询可在创建现场直接固化进程记录名来消除：zygote 在任何 App 代码运行前用
  `Process.setArgV0(niceName)` 设定 argv[0] [源码] `ZygoteConnection.java:514`、
  `Zygote.java:920`；App 必须先运行代码才能建 socket，所以创建时的 argv[0] 就是 AMS 的记录名
  （system_server 的 `system_server`→`system` 已按 `ZygoteInit.java:728` 与
  `ActivityManagerService.setSystemProcess` 处理）。tracing 程序可用
  `bpf_get_current_task_btf` 与 `bpf_probe_read_user_str` [源码] `kernel/trace/bpf_trace.c:1448,1474`，
  `mm->arg_start`、`mm->exe_file` 在 BTF 结构中 [源码] `include/linux/mm_types.h:968,1001`。
- 结论：用“创建现场 argv[0] 哈希 +（UID, 进程名）唯一 Manifest 声明”得到与 AMS 同键的归包，
  不依赖创建者仍存活，也不受创建后 exec 影响；多包共享进程仍判未知。

### 决策 1：归属对象与输出

| 对象 | 来源 | 何时可信 | 用途 |
|---|---|---|---|
| 创建者 task | v1/v2 快照：TGID、TID、UID、leader 出生时间、comm、argv[0] 哈希、exe inode | 快照有效且 cookie 等于当前 socket cookie [源码] `tc.bpf.c:186` | 路由主体（用户决定按发送者分流）；`ProcessID`、`UserId` |
| socket 记账 UID | `sk_uid` | 内核事实；可被持有 `CAP_CHOWN` 的进程 fchown（netd 代发 DNS）[实测] 研究结论 28 | 推断代发请求方，不作发送者 |
| 进程组 UID | socket cgroup id → `/apps|system/uid_X` | 仅组标签；fork 子进程继承、可迁入 [实测] 3 个非组首进程持有网络 socket | 与 sk_uid 一致时的应用级快路径与无快照回退 |
| 包/宿主 | 由上面三者推导 | 见证据等级 | `PackageNames` |
| 代发请求方 | netd 记账 UID（≠ 创建者时）或 sk_uid（≠ 创建者时） | 跨 UID 记账要求 `UPDATE_DEVICE_STATS` [源码] Connectivity `BpfHandler.cpp:344`；fchown 要求特权 | 仅记录与诊断；不参与路由 |

**包名证据等级**（只有 E1–E3 才填 `PackageNames`，其余返回非 nil 未知并记原因）：
- **E1**：普通应用 UID 且当前包表只有一个包；创建者 UID（无快照时用组 UID 且与 sk_uid 一致）决定。
- **E2**：共享/系统 UID，快照 argv[0] 哈希在该 appId 的 Manifest 声明进程名中只对应一个包。
  名称截断（flags `NAME_TRUNCATED`，见“真机预验证”）时按声明名前 `len` 字节比对；
  `system_server` 只在 UID 1000 视为 `system`。[实测] 2041 个声明名同 appId 内哈希碰撞 0。
- **E3**：SDK 沙箱 UID → 宿主 UID−10000 [源码] `Process.getAppUidForSdkSandboxUid`；宿主为单包时
  即 E1，宿主为共享 UID 时把 argv[0] 去掉 `_sdk_sandbox` 后缀对宿主 appId 走 E2
  [源码] `SdkSandboxServiceProviderImpl.toSandboxProcessName`。
- 未知原因：`multi_package_process`、`undeclared_process`、`no_creator_snapshot`、
  `name_unavailable`、`index_pending`、`index_failed`、`native_process`、`root_cgroup`、`uid_mismatch`。

`ProcessPaths` 只在快照 exe inode 与 `/proc/<pid>/exe` 的 inode 相同、且 `(pid, 出生时间)` 吻合时
填写；否则不填，避免 exec 或 PID 复用后报错路径。请求方以独立字段写入本地诊断与日志，
不加入上游 `adapter.ConnectionOwner`（遵守不改主线类型的约束）。

### 决策 2：可信包身份来源

见上节。保留 proc/Manifest 细化，但输入改为创建现场固化的进程名哈希；`/proc` 只用于
native 进程的可执行路径展示，并用 exe inode 校验。Manifest 索引增加“进程名哈希 → 包”的
映射，按 `codePath + ut + version` 失效（沿用已有机制）。

### 决策 3：生命周期语义

| 情形 | 语义 | 依据 |
|---|---|---|
| 新 socket | 创建时快照，之后不改写 | [实测] GPT 隔离真机 16 快照/重开不变 |
| fork 后子进程新建 socket | 记录子进程自身（生产 producer 取当前 task，不用 TASK_STORAGE） | 由构造保证；[待验证] 生产链路真机 |
| fork 继承的父 socket | 保留父进程快照（创建者语义） | [实测] 原型 |
| exec（leader 或非 leader）后 | 旧 socket 保留 exec 前的名称哈希与 exe inode；新 socket 记录新程序 | v2 设计；[待验证] |
| accept 子 socket | 无快照（TC 拒绝克隆来的 listener cookie）；组 UID 与 sk_uid 由 `sk_clone` 自 listener 复制，E1 仍可用 | [源码] `sock.c:2485`、`bpf_sk_storage.c:175`；[实测] 原型 accept 无身份 |
| producer 安装前已存在的 socket | 无快照，回退到 E1 组级或可选旧模块 | [实测] 1 个旧 socket 保持未知 |
| 创建者退出 | 快照仍在；E2 仍可归包；native 路径不可得 | v2 设计；[待验证] |
| PID 复用 | `(pid, 出生时间)` 不符则拒绝 /proc | [实测] 单元测试 |
| io_uring 建 socket | io-wq 线程 `CLONE_THREAD` 属提交者线程组，记录提交者 | [源码] `kernel/fork.c:2757` |
| FD 转交 | 仍是创建者，不是当前使用者 | 用户“按发送者”的定义以创建者近似；已知边界 |
| 包升级 | 索引按 codePath+stamp 重读；哈希映射重建 | [实测] 阶段 3 单元测试 |
| 卸载后 UID | 当前包表无该 UID → 未知 | 阶段 1 机制 |
| Framework 重启 | 包表重读；重启后 appId 分配器重置，跨重启存活的长连接可能被新包占用同一 UID → 该 socket 可能误归属 | [源码] `AppIdSettingMap`（研究结论）；已知风险，[待验证] 频度 |

### 决策 4：特殊来源

| 来源 | 归属 |
|---|---|
| 共享 UID、进程名唯一 | E2 |
| 多包共享进程（如 `com.android.phone` 承载 11 个包） | 未知 `multi_package_process`；需要进程内请求级钩子才能区分，超出本设计 |
| isolated 进程 | SELinux 禁止其创建 inet socket [实测] 研究结论 62；宿主传入的 socket 带宿主快照 → 宿主。真机所见为 WebView 渲染沙箱，记录名属 WebView 包、`packageList` 是宿主 [实测] 预验证 3 |
| SDK 沙箱 | E3（宿主 E1，或去后缀后的宿主 E2）；本机 Killswitch 开启，仅 [源码] |
| 系统 native（netd、daemon） | 无包名；exe 路径经 inode 校验；`UserId` |
| netd 代发 DNS | 发送者 = netd；请求方 = sk_uid（fchown 的 App UID） |
| GMS/DownloadProvider 等代发 | 发送者 = 服务进程；请求方 = netd 记账 UID |
| HTTP/2、QUIC 多来源复用 | 请求方只代表打标签时的来源，是 socket 级而非请求级；不覆盖创建者 |

### 决策 5：兼容与失效

- 默认关闭；显式启用而模块/BTF/producer 缺失时启动报错（GPT 已实现）。
- v2 使用新 pin 目录 `/sys/fs/bpf/sing-box/socket-creator-v2`；发现 v1 pins 仍在时拒绝启动并
  提示先用旧版维护命令移除，避免两个 producer 同时全局采集。[未实现]
- TC 只认 64 字节 v2 快照；v1 map 不能借给 v2 TC（大小校验拒绝）。[已实现] sing-ebpf `aa849f4`，
  WSL root 集成测试 `TestTCSocketCreatorRejectsWrongMapBeforeLoading` 含 48 字节 v1 存储被拒。
- netd `cookie_tag_map` 不存在或不可读：请求方未知，不报错、不影响路由。TC 侧 [已实现]
  sing-ebpf `aa849f4`（未借表时绑定空占位表，只置 CHECKED）；sing-box 侧打开与降级 [未实现]。
- 正常停止、禁用配置、升级、显式卸载沿用 GPT 已证实的持久化契约。

### 决策 6：开销模型（实测前为估算）

| 阶段 | 新增工作 | 量级 |
|---|---|---|
| 进程启动 | 无 | 0 |
| socket 创建（全机 inet socket） | tracepoint + 一次 SK_STORAGE 分配 + ≤128 字节用户态读与哈希 + exe inode 读 | v2 新增部分约 2 µs/socket（argv 读 ~1.0、exe 链 ~0.9 冷、FNV ~0.2），cache miss 主导；全机约 1–2 socket/s [实测] 预验证 1 |
| 首包/刷新 | sk_storage_get + netd 表查找 + assignment 写 | 每 socket 一次 [待验证] |
| 每包 | 已有 creator 变体的有效性判断 | 阶段 2 量级 [待验证] |
| 每连接（用户态） | 缓存命中的 map 查找；E2 为哈希表查找，无 /proc | 微秒以下 [待验证] |
| 内存 | SK_STORAGE 每 socket 64 B 数据 + 元素开销；assignment 88→112 B，Android 使用 `CompactTCAssignmentCapacity` 项 | 布局已证实；占用 [待验证] |

### 实施落点与顺序

1. `E:\sing-ebpf`：creator ABI v2（64 B）与 assignment 扩展；可选外借 netd `cookie_tag_map`，
   在记录时读取记账 UID/标签；C/Go 布局断言、生成物、集成测试。**[已完成] `aa849f4`**：
   make check、vet、gofmt、unit、race、android vet、宿主 C 状态迁移测试、WSL root 全部集成测试通过；
   真机 arm64 verifier 加载与真实 netd 表随整链验收进行（netd 表借用已由预验证 2 独立证实）。
   sing-ebpf `6ab9da7` 另定义 flags bit 3 `NAME_TRUNCATED` 与 bits 8–15 名称长度（布局不变）。
2. `common/socketidentity`：producer v2（argv[0] FNV-1a 64 哈希、exe inode、标志位）、
   v2 pin 目录、v1 残留检测；Go ABI 与 BTF 布局测试。**[已完成]**：`bpf/creator.bpf.c` 增加
   `record_process_name`（读 `mm->arg_start/arg_end`、≤128 字节 `bpf_probe_read_user_str`、FNV-1a 64、
   填满参数块或缓冲即置截断位、`mm->exe_file->f_inode->i_ino`），各事实独立标志，读失败只缺该事实；
   `ValueSize` 64、`abiVersion` 2、metadata magic `sbo.creator.v2`、`DefaultPinPath`
   `/sys/fs/bpf/sing-box/socket-creator-v2`；`Valid()` 拒绝未定义的标志位；默认路径下
   `socket-creator-v1` 仍有 pins 时 `Open` 拒绝（`checkLegacyCollector`，空目录放行）。
   `build-bpf.sh` 增加内核树 `-fdebug-prefix-map`：同一源码在两个不同目录、两个内核树副本下构建
   得到同一 sha256 `d9270fe2…3cc9`（v1 对照：程序段相同，仅 DWARF 头路径不同）。
3. `protocol/ebpf`：E2 走哈希索引、exe inode 校验、请求方记录、未知原因计数；单元测试。
   **[已完成]**：`creator_snapshot.go`（E1/E2/E3 纯函数、截断前缀匹配、`system_server` 别名仅限
   UID 1000、SDK 沙箱去后缀走宿主 E2）；`process_package_index.go` 的查找泛化为
   `lookupMatching`，返回结果原因（找到/多包/未声明/读取失败/待建）；`resolveSocketOwner`
   有名称快照时不读 cmdline、创建者退出后仍可归包；`ProcessPaths` 仅在 `/proc/<pid>/exe` 的
   inode 等于快照时给出（缓存键含 exe inode）；netd `cookie_tag_map` 只读借给 TC，缺失时只记 debug；
   请求方（charge UID 优先，其次 sk_uid）只进 debug 日志与诊断，不进 `ConnectionOwner`；
   诊断新增 `multi_package_process`、`undeclared_process`、`index_failed_lookups`、
   `index_pending_connections`、`creator_name_unavailable`、`creator_exe_mismatch`、
   `charge_checked`、`charge_found`、`requester_differs`。
4. 文档与验收：按下方矩阵在真机执行，逐项记录。

### 验收矩阵（执行后在此逐项填写）

- 本机：两仓库 race/vet；C/Go ABI；BPF 加载（WSL）；哈希一致性（BPF 与 Go 对同一名称）。
  **[已通过 2026-10-03]** sing-ebpf：make check、vet（含 integration tag）、gofmt、unit、race、
  android vet、宿主 C 状态迁移、WSL root 全部集成测试。主仓库（经仓库外 `go.work` 指向本地
  sing-ebpf，`go.mod` 未改）：`protocol/ebpf`、`common/socketidentity`、`common/androidmanifest`、
  `common/androidpackages` 的 vet、android/arm64 vet、unit、race、gofmt 全过。新增测试 FNV 对照
  `hash/fnv`；变异检验：去掉截断前缀、别名不限 UID、去掉 exe inode 比对三处各自使对应测试失败，
  恢复后 sha 校验一致。
- 真机 producer：创建时哈希与 `/proc/<pid>/cmdline` 一致；exe inode 一致；fork、exec、
  accept、创建者退出、io_uring 各一组。**[部分通过]** 独立探针 865/865（预验证 1）；生产 producer v2
  经 `run-creator-integration-device.sh`（清单扩为 12 个 TC 用例 + 持久化 + 实时 producer→TC）
  全部通过：16 个快照 `flags=0x4407`（VALID|NAME|EXE，长度 68），哈希与 exe inode 等于 /proc
  真值，跨收集器关闭、进程退出、重开不变；实时用例 `flags=0x3a07` 完整复制进 assignment；
  4 个 netd charge 用例在真机 arm64 verifier 上通过；清理后模块卸载、生产 PID 11765 与
  start ticks 不变（日志 `experimental/creator_v2_probe/results/v2-collector-tc-device-run.txt`）。
  **生命周期分组 [已通过]**：新增 `TestDeviceCreatorLifecycle`（`common/socketidentity/lifecycle_device_test.go`，
  接入同一 harness，在同一私有 bpffs/netns 中运行），日志
  `experimental/creator_v2_probe/results/v2-lifecycle-device-run.txt`：子进程自建 socket 记录子进程
  （pid 31319），子进程退出后快照仍在；fork 继承的父 socket 在子进程使用后快照逐字节不变；
  exec 前建的 socket 保留 exec 前名称哈希与 exe inode 2036820，exec 后同一 pid 新建的 socket 记录
  `sbo-exec-target`（`flags=0xf07`，长度 15）与副本 inode 2405210，两者 leader 出生时间相同；
  accept 子 socket 查无快照（listener 与 client 有）；io_uring `IORING_OP_SOCKET` 内联执行记录提交线程
  （tid 31311），`IOSQE_ASYNC` 记录 io-wq 工作线程（tid 31345），两者 TGID、名称、exe 均为提交进程。
  同次运行 12 个 TC 用例、持久化与实时 producer→TC 再次全部通过，清理后生产 PID/ticks 不变。
  exec 后 `ProcessPaths` 被拦截的用户态逻辑由单元测试覆盖（`TestIdentityV2ExeInodeGuardsProcessPath`）。
- 真机完整服务：真实 App 冷/热启动，普通/共享 UID、多包进程、native、netd DNS、
  GMS 代发；与 `dumpsys activity processes` 的 `packageList` 逐条比对，统计正确/错误/未知/漏采。
  **[已通过 2026-10-04，主命名空间、生产服务经用户同意暂停]**（`experimental/creator_v2_probe/fullservice/`：
  `fullservice.sh accuracy`、`analyze.py`；结果 `results/fullservice/accuracy-analysis.txt`）。
  `b1af4410` 构建、`config-accuracy.json`（socket_creator 开启、按 package_name 路由），桥接模块
  capture_all=1，冷启动 Chrome、微信、安全中心、哔哩哔哩并触发 NTP，180 s 内 18 份 dumpsys 快照作
  真值。46 条带 PID 的归属日志：**正确 22、错误 0**、未知 2（system_server：`system` 被 5 个包声明，
  按设计判多包）、native 21（netd，路径经 exe inode 核验）、组级 1（`com.android.vending`）。正确项
  包括 UID 1000 的 `com.miui.securitycenter`、`.remote`、`:cache` 三个进程（E2 按创建时名称），以及
  微信 `:push`/`:support`、哔哩哔哩 `:download`/`:pushservice`/`:web`、GMS、WebView 服务等。
  请求方：GMS（10136）的 socket 被 netd 记账给 Chrome（10309）与 `com.binance.dev`（10466），只进
  debug 日志，路由按 GMS；另有 124 条 netd（创建者 UID 0）socket 的 sk_uid 为 1051（AID_DNS）。
  **更正（2026-10-04）**：此前据此写的“本系统上 DNS 看不到具体 App 请求方”不成立。研究结论 28
  （`experimental/socket_attribution_probe/README.md`，`dnsuid/` 真机证实）显示 netd 替 App 发出的
  明文 DNS 会被 `fchown` 成发起 App 的 UID（`res_send.cpp`：`uid = enforce_dns_uid ? AID_DNS :
  statp->uid`，本机 `enforceDnsUid` 未生效、私人 DNS 关闭）；1051 的 socket 更可能是 netd 自身查询
  （如网络验证）。本次验收为什么只出现 1051、没有出现 App UID 的 DNS 请求方，尚未查明。未覆盖：SDK 沙箱（Killswitch 开启）、DownloadManager 主动下载、IPv6 回包。
  未提交原始日志与 dumpsys（含用户流量目的地址与进程列表）。
- 完整 sing-box 入口 TCP/UDP、IPv4/IPv6、delivery/shared，校验实际载荷回包。
- 无模块、半套 pins、v1 残留、netd 表缺失的预期行为。
- 仅旧方案与仅新方案交替配对：建连与回包尾延迟、CPU、内核与用户态内存、吞吐、
  长时间持有/释放。**[已执行 2026-10-04]** 原文转录见
  `experimental/creator_v2_probe/results/fullservice/paired-and-memory.md`。旧 = `7c12b1de` +
  `sb_sockowner_probe.ko`；新 = HEAD + 桥接 + producer v2；隔离 netns veth 回显，UID 1000、
  argv[0] `com.miui.securitycenter.remote`、按 package_name 路由（旧只得路径，新经 E2 得包名）。
  - 首轮（启动 3 s 后即加压）新版 connect p50 多约 40 µs、吞吐低 10–19%：原因是启动期工作与
    负载重叠（新版启动 CPU 约 50 tick，旧版约 20 tick，主要是解码内核 BTF 加载 producer 和
    Manifest 索引预热）。等待 20 s 后两轮配对：吞吐、connect/数据/事务 p50/p99、每千连接 CPU
    均无可测差异；单轮水平随 CPU 频率档位在约 42/82/92 MiB/s 间跳变，与版本无关。
  - 内存：默认构建新版 RSS 高 13–30 MB。smaps 与 `creator_memprobe` 证明不是活对象：加载后
    Go 堆在用约 1 MB，其余是运行时已用 MADV_FREE 归还、但内核无压力时仍计入 RSS 的页。Go 只在
    GOOS=linux 默认 MADV_DONTNEED（`runtime1.go parseRuntimeDebugVars`），android 不是。
    `release/LDFLAGS` 的 `godebugDefault` 加 `madvdontneed=1` 后：creator 33 MB、仅模块 32 MB、
    不归属 31 MB，差距消失；该设置影响整个 Android 二进制，与 Linux 默认一致。尝试过的
    `debug.FreeOSMemory()` 在两种设置下都无效果，未保留。
  - socket() 内核开销（`creator-v2-probe sockbench`，无钩子/旧模块/新桥接交替，含绑核 3×3 段）：
    噪声 1–2 µs，三态无法区分；与独立探针测得的 v2 段约 2 µs 一致而不矛盾（全机约 1–2 socket/s）。
  - 未测：功耗、长时间持有/释放下的内核内存（SK_STORAGE 随 socket 释放，模块按 free 钩子回收，
    均为设计保证，未量化）。

### 结论：v2 与此前方案的对比（2026-10-04）

对比对象：**旧方案** = `7c12b1de` + `sb_sockowner_probe` 模块（socket 创建时记 cookie→创建者，
连接时 ioctl 查询再读 /proc）；**阶段 3 v1** = GPT 的桥接 + 48 字节快照（共享 UID 归包仍要在连接时
读 `/proc/<pid>/cmdline`）；**v2** = 本设计（64 字节快照含创建时进程名哈希与 exe inode，netd 请求方，
E1–E3 纯函数解析）。只引用上面已记录的实测；没有测过的写为未测。

**总体判断**：按本项目三个目标衡量，v2 优于此前两种方案，但不是全面占优。
- 包名准确（含共享 UID）：**明显更好**。旧方案对共享/系统 UID 一律不给包名（配对 sanity 中旧版只得
  路径）；v2 在整服务验收中 22 正确 / 0 错误，UID 1000 的安全中心三个进程按创建时名称正确归包。
- 快速识别新进程：**更好**。名称在 socket 创建瞬间写入内核，不依赖连接时进程还活着、PID 未被复用、
  /proc 可读；冷启动（含 USAP 特化、出生 379 ms 的进程）全部带正确名称。v1 与旧方案都要在连接时读
  /proc，短命进程会落空。
- 性能：**持平**。稳态转发吞吐、延迟分位、每连接 CPU 无可测差异；RSS 在 `madvdontneed=1` 后持平；
  新增成本集中在一次性启动和每个 inet socket 创建，均在下文列出。

**优势**（均有实测）：
1. 共享/系统 UID 按 `(进程名, UID)` 唯一 Manifest 声明归包（E2），与 ActivityManager 同键；2041 个
   声明名同 appId 内哈希碰撞 0。
2. 创建者退出、PID 复用后仍能归包：名称来自快照，不读 /proc（单元测试 + 真机“子进程退出后快照仍在”）。
3. exec 语义正确：旧 socket 保留 exec 前名称与 inode，新 socket 记录新程序；路径只在 `/proc/<pid>/exe`
   inode 与快照一致时给出，exec 后不会把新程序路径安到旧 socket 上。
4. 截断、`system_server`→`system`（仅 UID 1000）、SDK 沙箱宿主均有明确规则，歧义一律判未知而非猜测。
5. 新增请求方可见：netd 记账 UID（GMS 代 Chrome 等）进入 debug 日志与诊断，路由仍按发送者，符合用户要求。
6. 未知有原因计数（多包、未声明、索引待建/失败、无名称、exe 不符），便于定位，而不是只有“未知”。
7. 桥接模块只转发一个 tracepoint，没有设备节点、ioctl、哈希表或释放钩子；状态全在 BPF SK_STORAGE，
   随 socket 释放，不存在旧模块表满淘汰的问题。
8. 连接路径不再为 E2 读 cmdline；`madvdontneed=1` 顺带降低了整个 Android 二进制的常驻内存读数。

**劣势与代价**：
1. 仍需内核模块：桥接模块与旧模块一样必须按设备内核的 BTF/符号 CRC 构建，内核升级要重编，
   这一点没有比旧方案省事。
2. 全局开销：capture_all 下全机每个 inet socket 创建多约 2 µs（独立探针分段测得，cache miss 主导；
   socket() 微基准在 1–2 µs 噪声内无法区分三种状态）。producer 以 pin 持久化，sing-box 停止后仍在采集，
   需显式 `tools socket-creator-remove` 才停。
3. 启动更重：每次启动多约 0.2–0.4 s CPU（解码 vmlinux BTF 加载 producer、校验 pins、Manifest 索引预热）。
4. argv[0] 是进程自报的：同一 UID 内的进程可以改写自己的 argv[0]，从而在本 UID 的包之间“选择”归属；
   跨 UID 不受影响（UID 来自内核）。旧方案读 /proc cmdline 同样是自报值，这不是新增风险，但也没有消除。
5. 普通 App 的 UID 快路径只给包名和 PID，不给可执行路径；App 内部原生子进程的 `process_path`
   规则失去输入。旧方案对这类进程保留真实路径（见“与旧模块方案的对照复核”）。
6. 升级需人工：v1 pins 存在时 v2 拒绝启动，必须先用 v1 构建移除；producer 构建哈希变化同样要求先移除旧 pins。

**仍有的不足**（设计边界或未验证）：
1. 多包共享同名进程仍判未知：本机 9 个名称（`system`、`com.android.phone`、`android.process.acore`
   等），system_server 的全部流量因此没有包名；区分需要进程内请求级信息，超出本设计。
2. producer 安装前已存在的 socket、accept 子 socket 没有快照，只能按 UID 组级归属（accept 已真机验证）。
3. 请求方：netd 标签只在首个满 socket 包读取一次，之后改标签不跟随。App 的明文 DNS 由 netd 发出时
   sk_uid 应为 App UID（研究结论 28），但整服务验收只记录到 1051 的请求方，原因未查明（待验证）。
4. 名称截断：参数块 78/99 字节，超长名称按前缀匹配，存在前缀歧义（本机已安装 1 个 78 字节名称）。
5. FD 转交后按创建者归属，而不是实际使用者（用户“按发送者”的定义以创建者近似）。
6. Framework 重启后 appId 可能被复用，跨重启存活的长连接可能误归属（研究结论，频度未测）。
7. 未测：SDK 沙箱（本机 Killswitch 开启）、DownloadManager 主动下载、整服务 IPv6 回包、功耗、
   长时间持有/释放下的内核内存量化。
8. BL 实际已解锁（见上文更正），系统侧（netd/zygote）方案未被设备状态排除，只是用户尚未选择；
   若将来接受系统侧改动，请求级区分与多包进程问题才有进一步改善的空间。

### 外部方案核查：Gemini 对劣势与不足的改进建议（2026-10-04）

用户转来 Gemini 的方案，逐条按源码与真机核查（2026-10-04 当日在设备上重跑 `attachtest`）。
设备事实：`/sys/kernel/security/lsm` = `capability,landlock,safesetid,selinux,bpf`，`CONFIG_BPF_LSM=y`，
但 `# CONFIG_FUNCTION_TRACER is not set`；vmlinux BTF 中 `btf_trace_android_*` 只有
`android_trigger_vendor_lmk_kill` 一个。

| 建议 | 结论 | 依据 |
|---|---|---|
| 改用 `lsm/socket_post_create` 去掉模块 | **本机不可行** | 当日实测 `lsm socket_post_create FAIL create raw tracepoint: not supported`；arm64 上 BPF LSM/fentry 经 trampoline 挂载，需函数跟踪支持，本内核未开 |
| 直接 `raw_tracepoint/android_vh_sock_create` | **不可行** | 厂商钩子用 `DECLARE_HOOK`，无 `btf_trace_android_vh_*`；只有内核模块能 `register_trace_*` |
| 免模块的真实候选 | 未实现，可研究 | 标准 tracepoint 可挂：`tp_btf` 的 `inet_sock_set_state`（TCP connect 在调用者上下文）、`sock_send_length`（研究结论 21：可得 cookie 与发送线程）。代价：记录的是“首次连接/发送者”而非创建者；UDP 的 `sock_send_length` 在 `sendmsg` 返回后触发，首包已过 TC，需要后续包补读或用户态回退 |
| 不 pin link / `is_active` 开关，停止即停采 | 可做成选项 | 技术上正确；代价是 sing-box 停止或重启期间创建的 socket 没有快照。当前 pin 是为覆盖重启窗口的有意选择 |
| 在 fork 或 setArgV0 时把名称写入 TASK_STORAGE，降到 <20 ns | **设计有误** | fork 时 argv 仍是 `zygote64`/`usap64`；argv 改写是用户态内存写，没有内核事件；`setArgv0` 先 `pthread_setname_np`（`task_rename`）后 `strlcpy` argv（`AndroidRuntime.cpp`），在 rename 事件里读到的仍是旧名。按进程懒缓存可行，但全机约 1–2 socket/s，收益约数 µs/s，且引入缓存过期语义（已在决策 6 否决） |
| Minified BTF、Manifest 二进制缓存 | 收益低 | 最小 BTF 会把产物绑死到某一内核 BTF，失去跨 OTA 的 CO-RE；启动 0.2–0.4 s 是一次性成本且未拆分出 BTF 占比；Manifest 索引本就在后台懒构建，不在连接路径 |
| uprobe Zygote 特权期记录真名防自报 | 可行但不值 | `CONFIG_UPROBES=y`，但需解析 ART/JNI 字符串；只防同一 UID 内的自我误归属 |
| `bpf_d_path` 取原生子进程路径 | **不可行** | `kernel/trace/bpf_trace.c:915-942`：只允许 `security_file_open` 等白名单函数的 fentry/LSM 及迭代器；本机 fentry/LSM 又挂不上。正确做法在用户态：UID 快路径遇到快照 exe inode 不是 `app_process` 时走已核验的 /proc 路径（未实现，成本低） |
| 首包后再读 `cookie_tag_map` 穿透 system_server | 方向可用，前提未证 | “很多客户端在 connect 之后才 tagSocket”未经实测；且用户要求按发送者路由（请求方只作诊断）。研究结论 38：多包进程 5 分钟内仅 `system_server` 11 个 socket，其余为 0，实际影响很小 |
| accept 经 `security_inet_csk_clone`/sock_ops 继承快照 | LSM 不可行；有更简单办法 | 可给 SK_STORAGE 加 `BPF_F_CLONE`（`bpf_sk_storage_clone`，`sock.c:2485`），TC 把 cookie 不符的克隆值标为“继承自 listener”；手机上本地服务的入站连接很少，优先级低 |
| sock_diag + /proc 为存量 socket 补快照 | 可行但侵入 | 需 `pidfd_getfd` 拿他进程 fd 才能写 SK_STORAGE；pin 持久化后只剩每次开机首次安装前的窗口 |
| DNS 需挂 dnsproxyd 或改 DnsResolver APEX | **前提错误** | DnsResolver 默认把明文查询 `fchown` 成 App UID（研究结论 28 真机证实，`enforceDnsUid` 未生效）；无需改 APEX。本次验收为何只见 1051 待查 |
| 借 BL 改 framework/APEX 打标 | 技术可行，代价高 | 每次 OTA 需重做并处理签名/校验；收益受结论 38 限制，且与“按发送者路由”冲突 |
| “源码保证”SDK 沙箱、DownloadManager、IPv6、功耗零影响 | 不能替代实测 | E3 已实现但本机 Killswitch 开启；功耗未测 |

**第二版补充核查**（Gemini 联网后的版本；与上表重复的 LSM、TASK_STORAGE、不 pin link、精简 BTF 不再重列）：
- “fchown 只改 sockfs inode，`sk_uid` 仍是 AID_DNS”：**错误**。`net/socket.c:599-614`
  `sockfs_setattr` 在 `ATTR_UID` 时执行 `sock->sk->sk_uid = iattr->ia_uid`；研究结论 28 也在真机上用
  `bpf_get_socket_uid()` 读到了 App UID。`resolv_tag_socket` 同时 `tagSocket(..., TAG_SYSTEM_DNS, uid)`
  这一点属实，TC 现有的 charge 读取已经覆盖。
- “Java HTTP 客户端在 connect 之后才打标签，所以首包查不到”：**与源码不符**。libcore
  `BlockGuardOs.socket()`/`accept()`/`socketpair()` 在 inet socket 创建后立即 `SocketTagger.tag(fd)`，
  线程标签（`setThreadStatsTag`/`setThreadStatsTagUid`）在 connect 前已写入 `cookie_tag_map`；只有 App
  事后显式调用 `TrafficStats.tagSocket()` 才可能晚于首包，未见证据。
- `BPF_F_CLONE`：机制正确（`net/core/bpf_sk_storage.c:175`），但“0 额外代码、100% 继承”不准确：克隆值
  带着 listener 的 cookie，现有 TC 校验 `creator.cookie == socket cookie` 会拒收，需要改 TC 的接受规则并
  标记“继承”；继承的是 listener 创建者，对服务进程而言即发送者。
- 原生子进程路径按 exe inode 按需走 /proc：与上表第 ① 项相同，赞同。

**第三版补充核查**（`E:\0001.txt`，2026-10-04）：
- “124 条 1051 是小米开启 `enforceDnsUid` 所致”：**未证实**。源码引用属实：`DnsProxyListener.cpp`
  `isUidNetworkingBlocked()` 中“enforceDnsUid is an OEM feature … if
  (resolv_is_enforceDnsUid_enabled_network(netId)) return false;”。但它与研究结论 28（真机见 App UID）
  矛盾。当日在蜂窝网络（rmnet_data4）用 `dnsuid/` 复测：以 root 查询，netd 发出 2 个 UID 0 的包；以
  GMS（10136，netpolicy `effective=NONE`）和 Chrome（10309，`APP_BACKGROUND` 被拦）查询，netd 一个包
  都没发，ping 立即 unknown host。若开关开启，按上面源码拦截检查应被跳过、以 1051 发包，所以结果更像是
  **未开启**；但生产 sing-box 正在接管 DNS（root 查询随机域名也“成功”），环境有干扰，**本次不作结论**。
  定论需要停用生产服务、让 App 在前台查询后重测。即使开启，按用户要求路由也按发送者，DNS 请求方只用于诊断。
- `BPF_F_CLONE` 的 TC 接受规则（cookie 不符但快照有效即视为“继承”并置标志）：可行。克隆只发生在
  accept，生产者写入时 cookie 必等于自身，故 cookie 不符的有效快照只能来自克隆。
- 免模块路线的 TCP 时序：**正确**。`tcp_v4_connect` 先 `tcp_set_state(sk, TCP_SYN_SENT)`
  （`net/ipv4/tcp_ipv4.c`，函数内第 87 行），经 `inet_sk_state_store` 触发 `trace_inet_sock_set_state`
  （`net/ipv4/af_inet.c:1365/1372`），之后才 `tcp_connect(sk)` 发 SYN（第 126 行），且在 connect 调用者
  上下文。程序须只处理 `newstate == TCP_SYN_SENT`（其他转换多在软中断，`current` 无关）。UDP 仍是缺口：
  `sock_send_length` 在首包过 TC 之后触发，需 TC 不再缓存“缺失”并在后续包补读，单包 UDP 流无法补齐。
- 原生子进程路径、可选停止即停采：与已列后续项一致。

可采纳的后续项（按收益/成本）：① UID 快路径为 App 原生子进程补可执行路径（用户态）；② 查明整服务验收中
App DNS 请求方缺失的原因；③ 可选“停止即停采”开关；④ accept 子 socket 用 `BPF_F_CLONE` 继承；
⑤ 若用户希望去掉模块，先用独立探针评估 `inet_sock_set_state` + `sock_send_length` 的时序与覆盖。

### 免模块路线与模块增强试验（2026-10-04，只做试验，生产代码未改）

用户要求先做试验、不改代码。探针 `experimental/tracepoint_producer_probe/`（只观察：TCX head、
`TCX_NEXT`），生产 sing-box（pid 26306）全程运行，屏幕关闭，结果在其 `results/`。

**免模块 producer（标准 tracepoint）**：verifier 接受，两个 `tp_btf` 均能挂载。
- TCP（`inet_sock_set_state` → `TCP_SYN_SENT`）：受控负载（run3，`toybox nc` 以 UID 10136 与 root
  各 10 次）**20 个新连接的首个 SYN 全部已带快照（20/20）**，argv[0] 与 /proc 20/20 一致；唯一无快照的
  SYN（cookie 7752270，root）在 run2 已出现、只见于 `rmnet_ipa0`，是探针启动前的旧连接重试，非新连接。
- UDP（`sock_send_length`）：按源码（`net/socket.c:722-736`）与实测，**首包必然先于快照经过 TC**
  （run2 7/7、run3 4/4）；后续包补上的 socket 极少（run1 1/11，run2/run3 0），观察到的 UDP 多为单包
  流，免模块路线对它们完全无快照。多包 UDP 的受控测试因 `toybox nc -u` 不随 stdin 结束退出而未完成。
- 重复计数：同一包会在 `rmnet_data4` 与生产 sing-box 的 `sbt66c20001`（或 `rmnet_ipa0`）上各计一次，
  run1 的“首包前 2 个包”实为 1 个包，按 cookie 去重后结论如上。
- 结论：创建现场的覆盖只有模块（vendor hook）能完整提供；免模块路线 TCP 等价、UDP 有先天缺口，
  **保留桥接模块**。

**“增强模块”方案核查**（用户转来的 Gemini 方案）：
| 增强 | 结论 | 依据 |
|---|---|---|
| 模块写 `sk_mark` 携带身份 | 不做 | netd `include/Fwmark.h`：`netId:16`、`explicitlySelected:1`、`protectedFromVpn:1`、`permission:2`、`uidBillingDone:1`、`reserved:8`、`vendor:2`、`ingress_cpu_wakeup:1`，32 位已占满；sing-box 还用 `0x40000000`；TC 每 socket 只读一次，收益≈0 |
| 模块在创建时 `d_path` 固化原生路径 | 可选 | `d_path` 对模块导出；仅非 app_process 时调用；收益限于原生进程在查询前退出的情形 |
| sk_mark 继承 accept、Netfilter LOCAL_OUT 补旧连接 | 不做 | mark 问题同上，accept 用 `BPF_F_CLONE` 即可；LOCAL_OUT 每包执行，加重热路径，只为补开机到首次安装前的窗口 |
| 监听 binder 事务归属 system_server 代发 | 不做 | `btf_trace_binder_transaction*` 在本机 vmlinux BTF 中存在，BPF 不需模块即可挂；但“工作线程处理请求后下一个 socket 属于该客户端”不可靠（线程复用、异步线程/进程），且用户按发送者路由 |
| 字符设备 `release()` 绑定生命周期，退出即停采 | 可选 | 简单可靠，等同不 pin link；代价是停止/重启期间新建 socket 无快照 |

建议：模块保持精简（创建现场的唯一入口），按需加“退出即停采”选项，`d_path` 视需要；其余交给 BPF 与用户态。
未做：多包 UDP 受控测试、DNS 干净复测（需停生产服务并亮屏）。

### 真机预验证（2026-10-03，独立探针，未接入生产）

用户要求在写 producer v2 之前，先用独立小探针在真机上核对设计依赖的不确定点，全程不动
生产 sing-box、`config.json` 与模块。探针：`experimental/creator_v2_probe/`（`build.sh` 在
WSL 以 likayo 构建；`run-device.sh capture|netd|procs`、`coldstart.sh` 在设备 root 运行；
原始结果在 `results/`）。设备：内核 `6.12.69-android16-6-g586bfab1b9c5-abogki536749445-4k`，
SELinux Enforcing，`/sys/kernel/btf/vmlinux` sha256 `37d2c7e7…5f35` 与桥接模块构建基线一致。
生产 sing-box pid 11765（start_ticks 14670767，上下文 `u:r:ksu:s0`）在每次运行前后核对未变
（每次输出 `PRODUCTION_UNCHANGED`）；桥接模块每次由脚本加载、`capture_all` 置 1 采集、
结束后置 0 并卸载（每次输出 `BRIDGE_REMOVED`）。

**1. producer v2 的读取能否通过 verifier、是否与 /proc 一致 —— 通过 [实测]**
- `tp_btf/sbo_identity_socket_create` 上的探针程序（读 `task->mm->arg_start/arg_end`、
  `bpf_probe_read_user_str` ≤128 字节、FNV-1a 64、`mm->exe_file->f_inode->i_ino`）被 verifier
  接受：初版 657 条指令/处理 2206 条；带分段计时与对照哈希的版本处理 32977 条，远低于上限。
- 五轮共 865 个 inet socket 创建事件（180 s 自然流量 207、冷启动 75 s 264、三轮分段计时
  98/176/120）：argv[0] 与事件当刻 `/proc/<pid>/cmdline` 首段 **865/865 一致**，exe inode 与
  `stat /proc/<pid>/exe` **865/865 一致**，BPF 内 FNV 与 Go `hash/fnv` 对同一字节串 865/865 一致；
  `no_mm`、`argv_fail`（返回负值）、`argv_empty`、`exe_fail`、ringbuf 满均为 **0**。
  覆盖 system_server、普通 App、带冒号子进程（`com.tencent.mm:push`、`com.xiaomi.xmsf:services`）、
  native（netd、iptables-restore）、root 进程（sing-box 本身）。
- 冷启动：`coldstart.sh` 启动未运行的 `com.xiaomi.market`（由 MIUI 的 USAP 预孵化进程特化，
  pid 10985 此前名为 `usap64`），其后 48 个 socket 的 argv[0] 全部为 `com.xiaomi.market`；
  `com.xiaomi.finddevice` 在出生 379 ms 时建的 socket 已是正确名称；另一轮 24 个出生不到 60 s
  的进程同样一致。**未出现任何 App UID 的 socket 带 zygote/usap 名称**（计数器
  `app_uid_pre_rename_name` 为 0）。`com.android.browser` 在设备上被禁用，未能启动。
- 开销分段（每个 inet socket 一次，不在包路径；`bpf_ktime_get_ns` 自身约 163–187 ns 已扣除）：
  用户态 argv 读取约 1.0 µs；exe 指针链约 0.9 µs（冷）/ 约 0.05 µs（热）；FNV 约 0.2 µs
  （平均哈希 17–20 字节）。直接 BTF 指针解引用与 `BPF_CORE_READ` 辅助函数链交换先后各测一次：
  先执行者都约 1 µs、后执行者都 <0.1 µs，说明成本是 cache miss，不是辅助函数调用；
  按 8 字节分组的哈希比 FNV 只省约 0.1 µs。整段 p50 1.46 µs、p90 4.7 µs、p99 7.6 µs。
  全机自然流量约 1–2 个 inet socket/秒（180 s 207 个），故 **v2 新增 CPU 约每秒数 µs**。
- `argv[0]` 有长度上限 [源码]：`AndroidRuntime::setArgv0` 为
  `memset(mArgBlockStart, 0, mArgBlockLength); strlcpy(mArgBlockStart, argv0, mArgBlockLength)`，
  `mArgBlockLength` 来自 `app_main.cpp computeArgBlockSize`（zygote 原始参数块）。真机参数块：
  `zygote64`、`webview_zygote` 与两个 `usap64` 为 99 字节，另一个 `usap64`（pid 5055，
  `com.miui.home`、`com.miui.gallery` 等由它特化）为 **78 字节**，即进程名最多 77 字节。
  全部已安装 Manifest 中最长进程名 78 字节
  （`com.google.android.accessibility.switchaccess:playcore_missing_splits_activity`），
  在 78 字节块中会被截成 77 字节——截断是真实情形，不能只比对完整哈希。
- native 单参数进程（如 `/system/bin/netd`）的 argv[0] 恰好填满参数块，属正常，不是截断。

**2. 借用 netd `cookie_tag_map` —— 通过 [实测]**
- 在 `u:r:ksu:s0`（与生产 sing-box 相同）以 root 只读打开
  `/sys/fs/bpf/netd_shared/map_netd_cookie_tag_map`（文件 `root:net_bw_acct 0660`，
  标签 `u:object_r:fs_bpf_netd_shared:s0`）成功。Info：`name="cookie_tag_map" id=22 type=Hash
  key=8 value=8 max_entries=10000 flags=0x0`，与 sing-ebpf `validateCookieTagMapInfo` 一致。
- 引用该表的最小 TC 程序用**只读 fd** 做 `MapReplacements` 加载成功，在 `unshare -n` 私有网络
  命名空间的 `lo` 上以 TCX egress 挂载：未打标签的探针 socket `found=0`；把探针自己的 socket
  按 `libnetd_updatable` 的 tagSocket 同样方式写入 `{uid 0, tag 0x5b0c2e}` 后 TC 查到
  `found=1 uid=0 tag=0x5b0c2e`，随后删除该条目（`UNTAGGED`）。无 avc 拒绝。
  首轮因 lo 上内核 ICMP 端口不可达包覆盖了单槽结果而误显示未命中，改为按 cookie 分键后正确。
- 只读扫描（`creator-v2-probe netdscan`，sock_diag 关联）：当时主命名空间 42 个 inet socket，
  表中 2 条，均为活跃 socket，**charge UID 与 sk_uid 不同者 0**。即稳态下“请求方 ≠ 发送方”
  很少出现；DownloadManager/GMS 代发需在完整服务验收中专门触发才能看到。

**3. 进程名哈希与 Manifest/AMS 能否对上 —— 通过，附三条约束 [实测]+[源码]**
- 对 `dumpsys activity processes` 的 89 条 ProcessRecord：88 条 argv[0] 与记录名完全相同，
  1 条为 system_server（argv[0] `system_server`，记录名 `system`）。另有 UID 10088
  （`com.miui.rom`，`framework-ext-res.apk`）的进程记录名也是 `system`（argv[0] `system`）：
  名称只能在同一 appId 内解释，`system_server`→`system` 的别名只属于 UID 1000。
- 已有设备测试 `TestDeviceProcessNamesMatchManifests`：运行中 89 个 zygote 子进程，
  唯一归包 76、多包共享同名进程 8、无包声明 0、isolated 5；533 个已安装包解析 0 失败。
  新增 `TestDeviceProcessNameHashes`（`common/androidmanifest/device_test.go`）：462 个 appId、
  2041 个声明进程名，**同 appId 内 FNV-1a 64 碰撞 0**；同 appId 被多个包声明的进程名 9 个
  （`system`、两处 `com.android.phone`、`android.process.acore`、`android.process.media`、
  `com.android.networkstack.process`、`com.qti.phone`、`.dataservices`、`.qtidataservices`），
  这些名称只能落到 UID 级；以 `.` 开头的进程名按原样使用，与 `buildCompoundName` 一致。
- isolated（UID 99xxx）进程为 WebView 渲染沙箱：记录名是 `com.google.android.webview:sandboxed_process0:…`，
  `packageList` 是宿主（`com.tencent.mm`、`tv.danmaku.bili` 等）；本次采集中它们未创建 inet socket。
- SDK 沙箱 [源码]：`SdkSandboxServiceProviderImpl.toSandboxProcessName` =
  宿主 `ApplicationInfo.processName + "_sdk_sandbox"`（插桩为 `_sdk_sandbox_instr`）；UID 为
  `Process.toSdkSandboxUid`（+10000，20000–29999 一一对应）。本机 `dumpsys sdk_sandbox`：
  `Killswitch enabled: true`、无会话，**无法实测**，保持 [源码] 级。

**4. 新旧方案配对性能测试**：需要停用生产 sing-box，按用户要求先询问，尚未执行。

**据此对设计的修订**（已写入下方各决策；producer 实现随后按此进行）：
- creator flags 增加 `NAME_TRUNCATED`（bit 3）与名称字节数（bits 8–15）：当读到的字符串填满
  参数块（`len + 1 >= arg_end - arg_start`）或填满 128 字节缓冲时置位。未置位按完整名哈希比对；
  置位时按 Manifest 名称前 `len` 字节的哈希比对，多个候选即判歧义。64 字节布局不变，TC 不解释
  这些位（只校验 VALID），sing-ebpf 无需再改。
- E2 的“唯一”指同 appId 内只有一个包声明该名称；上面 9 个多包同名进程判 `multi_package_process`。
- E3 扩展：SDK 沙箱先换算宿主 UID，再去掉 `_sdk_sandbox` 后缀对宿主 appId 走 E2（宿主可能是共享 UID）。
- 开销模型改用上面的实测值；不做按进程缓存：唯一能省的是约 2 µs/socket 的 cache miss，
  全机约每秒数 µs，却要引入“argv 被改写后缓存过期”的新语义，不值得。

### cgroup 分工（2026-10-04）

依据：`experimental/module_enhancement_probe/results/cgroup-probe/README.md`（真机只读探针）。
socket 的 cgroup（TC 已记录的 `socket_cgroup_id`，即 `bpf_skb_cgroup_id()` =
`cgroup_id(sock_cgroup_ptr(&sk->sk_cgrp_data))`，`net/core/filter.c:5005-5014`）在 10232/10232 个 socket
上等于创建线程的 cgroup；app_process 创建的 5453/5453 个 socket 在创建者自己的 `…/uid_X/pid_<tgid>` 里。
系统 UID 的 App（system_server、com.android.phone 等）与 init 服务在 `/system/uid_X/pid_Y`，路径中的
uid 对 init 服务总是 0；原生子进程、App zygote 派生进程在父进程的 cgroup；sing-box、KernelSU/zygisk/
LSPosed、su shell 在根 cgroup。在模块内计时实测中，建 sk_storage 快照约占 570 ns/socket（热路径）。

实现：

- `common/socketidentity/bpf/creator.bpf.c`：`in_own_process_cgroup` 读
  `task->cgroups->dfl_cgrp->kn->name`，为 `pid_<当前 tgid>` 时直接返回，不建快照、不读 argv/exe。
  其余情况（子进程、根 cgroup、他人的 pid 目录）照旧建 v2 快照。快照布局与 ABI 不变；对象 sha256
  `1473de52…5727`（已与上一版不同，旧 pins 须按原契约用旧版二进制移除，真机当前无旧 pins）。
- `protocol/ebpf/socket_identity.go`：`cgroupOwner` 记下目录对应的 pid；无快照、producer 生效、且
  cgroup 是进程目录时，`ownerFromProcessCgroup` 校验 `/proc/<pid>/cgroup` 所指目录的 inode 等于 socket
  的 cgroup id（同一进程实例；cgroup id 开机内不复用），取进程自己的 UID 与启动时间，再交给
  `resolveSocketOwner`：argv[0] 进程名（`/proc/<pid>/cmdline`）、exe 路径、E1/E2 归包与快照路径相同。
  UID 取进程而非 socket：init 服务目录都标 uid_0，netd 会把 DNS socket fchown 给请求 App；
  socket UID 不同时只作请求方计入诊断（按发送者分流，决策 1）。producer 未启用时 cgroup 仍只是
  UID 标签（fork 的子进程共享 cgroup，无法据此认定创建者）。
- 诊断新增 `resolved_by_cgroup_process`、`cgroup_process_gone`。
- Manifest 索引不变（冒号前缀快速判断经测试证明并非总成立——包可以把 `android:process` 写成别的包名
  开头的完整名字——且用户决定暂不改动 Manifest 部分，已撤回）。

验证：

- 本机（WSL）：`protocol/ebpf`、`common/socketidentity`、`common/androidmanifest` 的 vet（android/arm64
  与本机）、单元测试、race 全部通过；新增 `socket_identity_cgroup_test.go` 5 项：共享 UID 经 cgroup 归包、
  producer 未启用时不取 PID、netd 为发送者而 App 为请求方、UID 取进程不取目录标签、进程已迁出时拒绝。
- 真机 producer 门控（`sbo-acceptance producercheck`，生产对象挂桥接模块 `capture_all=1`）：校验器接受
  （263 条指令）；根 cgroup 200/200 有快照、`pid_<自己>` 0/200、`pid_<他人>` 200/200、移回后 200/200；
  桥接模块已卸载、临时 cgroup 已删除、taint 4608。
- 整链路真机验收（`experimental/creator_v2_probe/fullservice/fullservice.sh accuracy 150`，仓库编译设置构建的
  新 sing-box、桥接模块 + 新 producer、测试配置只有 direct 出站，生产 sing-box 保持用户停止的状态；冷启动
  Chrome、微信、手机管家、哔哩哔哩，dumpsys 进程记录为真值；结果
  `experimental/module_enhancement_probe/results/cgroup-fullservice/accuracy-analysis.txt`）：53 条归属，
  **错误 0**；带 PID 的 6 条与 ActivityManager 记录一致（含 uid 1000 的 `com.miui.securitycenter.remote`、
  `:cache`，uid 6110 的 `com.xiaomi.finddevice`——均在自己的 cgroup，producer 不建快照，经 cgroup 路径归包）；
  netd 23 条按发送者归 `/system/bin/netd`（pid 2006，原生无 AMS 真值）；普通 App 22 条按 UID；system_server
  1 条判未知（多包进程，正确）；1 条进程在快照前已退出。之后已移除 collector、卸载桥接模块、关屏，taint 4608。
- **未执行**：该整链路运行没有导出 `resolved_by_cgroup_process` 计数（诊断只经 API 暴露），上述经 cgroup
  路径的结论由“进程在自己 cgroup → producer 必然跳过”推得；开销的整链路复测未做（模块内计时见增强模块探针）。

剩余（按顺序）：整链路真机验收；sing-ebpf 放开 `BPF_F_CLONE` 与 TC 继承标记（accept 子连接；其 cgroup
已随 `cgroup_sk_clone` 继承监听者，App 监听者无快照时已能经 cgroup 归属）；以增强模块替换桥接模块
（原生程序完整路径，且须保留 argv[0] 哈希）。

### 增强模块 sbo_identity（2026-10-04）

`kernel/sbo_identity`（README 说明参数、构建与加载）取代 `sbo_identity_bridge`。设计与全部测量来自
`experimental/module_enhancement_probe`（REVIEW-claude.md 第 8–13 次审查、results/）。

实现：

- 模块（C）：`android_vh_sock_create` 中只处理用户 inet socket；创建者在自己的 `pid_<tgid>` cgroup 时直接返回
  （不运行 BPF、不建快照；cgroup 门控从上一版 producer 移入模块）；其余经 RCU 校验读取可执行文件
  `(dev, ino, i_generation)`、按 CPU 缓存、未命中时 `get_file_rcu`+`d_path`+`fput`，经 typed tracepoint
  `sbo_identity_socket(sk, dev, ino, gen, path, path_len, flags)` 交出路径与 TOO_LONG/DELETED/KERNEL/ERROR 标志。
  socket 与 cgroup 相关字段按真机 BTF 生成的偏移读取（`gen_layout.py`），`verify_btf.py` 校验 tracepoint 的
  sk 为设备 `struct sock` 及其余所有解引用字段的偏移。参数沿用 `capture_all`（collector 只检查、不修改）。
- producer v3（`common/socketidentity/bpf/creator.bpf.c`）：仍读 argv[0] 并记 FNV-1a 64 哈希（共享 UID 归包所需）；
  快照 64 字节 ABI 不变，原 exe inode 字段改存可执行文件键（`ExeKey`，标志位 4 `CreatorExeKey`），路径按键
  只存一次于 LRU `exe_paths`；新标志位 5–7：路径过长、已删除、内核线程。sing-ebpf 只解释 VALID 位，无需改动。
- collector：模块名 `sbo_identity`、目录 `socket-creator-v3`、v1/v2 残留 pins 时拒绝启动；新增 `exe-paths` pin、
  metadata 记录路径表 ID（原 4 字节保留位）；核对 producer 恰好引用 creators、exe_paths 与一个 scratch map。
- 用户态：快照带 exe key 时直接从路径表取路径，不读 `/proc`（创建者退出后仍有路径）；表中缺失（被淘汰）
  再回退 `/proc`。诊断新增 `creator_exe_path_from_snapshot`、`creator_exe_path_missing`。

验证（结果：`experimental/module_enhancement_probe/results/sbo-identity-fullservice/`）：

- 本机：vet（android/arm64、本机、integration 标签）、单元、race 全部通过；新增测试：快照路径在创建者退出后仍可得、
  路径表缺失时回退 `/proc`、app_process 路径仍走 E1、ExeKey 字节布局；collector 校验新增路径表 ID/形状/引用集合用例。
- 真机 producercheck：校验器接受（305 条指令）；根 cgroup 与他人 pid 目录 200/200 快照，均带 argv 哈希与 exe key，
  路径表路径等于 `/proc/self/exe`；自有 cgroup 0/200（模块跳过）。
- 真机整链路（测试配置 direct 出站，生产 sing-box 保持停止）：45 条归属错误 0（带 PID 5 条与 ActivityManager 一致、
  netd 21、App 按 UID 17、system_server 未知 1）；模块计数 inet 5815，其中自有 cgroup 4427（76%）不发事件，
  缓存命中 1366/未命中 22，非 inet 10913 在入口返回；`get_file_rcu=fput=22`。根 cgroup 中的原生程序（KernelSU
  shell 中的 `nc`）4 个连接均归为其路径与 PID。收尾后模块卸载、taint 4608。
- 1 小时长跑与开销（`experimental/module_enhancement_probe/acceptance/prod-longrun.sh`，结果
  `results/sbo-identity-longrun/`，不点亮屏幕）：
  - 开销（模块 `timing`，锁频、CPU 4，3 轮各约 10 万 socket）：自有 cgroup 跳过 50–52 ns/socket；建快照（模块 +
    v3 producer，缓存命中）762–787 ns/socket。
  - 1 小时：inet 27523 个，其中 own_cgroup 23050（83.7%）不发事件、建快照 4473（缓存未命中 31）；归属 163 条
    **错误 0**（带 PID 10 条与 ActivityManager 一致；多包未知 3；按 UID 52；netd 91；根 cgroup 客户端 6 条，含 299 字节
    路径——路径表不存、回退 `/proc` 得完整路径——和运行中被删除的程序，均为正确路径）；内核日志全程捕获，
    标记后 20717 行 **0 个告警**；`get_file_rcu=fput=31`；taint 4608；测试实例 RSS 稳定在约 18 MB。

## 仓库与范围

- 主实施仓库：`E:\ebpf_sing-box`。
- 依赖改动：已有 `E:\sing-ebpf` / `LQ2002/sing-ebpf`，允许在这个已有 fork 中增加所需能力。
- 移植目标：`E:\Ref_sing-box`。当前不修改该目录；保留清晰提交边界及依赖提交，便于移植。
- 不新增 sing-tun、sing、fswatch 等 fork；不提交指向本机目录的 go.mod replace。
- 不新增独立 TC/TCX 采集程序、Java/app_process 常驻辅助程序、临时丢包保护程序，
  也不为正常包表更新设计整套后端拆除/重建机制。
  2026-10-03 用户另行授权独立身份载体验证原型、明确不考虑自定义内核；此授权仅允许
  下文原型在私有网络命名空间挂测试 TCX，不改变上述生产集成范围。
- 只有三个阶段，依次执行，各自具备独立价值和验收标准。前一阶段未通过，不扩大到下一阶段。
  如果用户只要求某一阶段，就完成该阶段；若授权执行全计划，按顺序继续，不逐阶段重复索要确认。

## 当前进度

| 阶段 | 交付内容 | 状态 | 代码提交 / 验收证据 |
|---|---|---|---|
| 1 | 修复包表刷新与查询一致性 | **已完成**（本地测试与真机验收均通过） | 代码 `35624e63`；记录见“阶段 1 实施记录” |
| 2 | 已有 sing-ebpf fork 的 UID 热更新与归属字段 | **已完成**（本地、真机与真实 App 验收均通过） | sing-ebpf `3c1b28f`（已推送）；应用依赖 `6252b171`；记录见“阶段 2 实施记录” |
| 3 | sing-box 接入新归属路径并完成整链路验收 | **归属修复、持久创建者第一轮集成及隔离真机验证完成；目标设计与完整验收仍有未完成项** | 修复 `cae57485`；创建者集成 `ee0208de`；实际数据面证据与剩余项见阶段 3 |
| 目标设计 | creator v2（创建时进程名哈希、exe inode）、netd 请求方、E1–E3 解析 | **实现完成；本机、隔离真机、整服务真实 App（正确 22/错误 0）与新旧配对（稳态无可测差异，内存经 `madvdontneed=1` 持平）均已验收**；sing-ebpf 已推送（`6ab9da7`），`go.mod` 已升级（`6f291cf8`） | 分支 `claude/attribution-target-design`；sing-ebpf `aa849f4`、`6ab9da7`；见“Claude 目标设计”的预验证与验收矩阵 |
| cgroup 分工 | 创建者在自己的 `pid_<tgid>` cgroup 时不建快照，由 socket cgroup 定位进程 | **实现完成；本机测试、真机 producer 门控、整链路真实 App（错误 0）验收通过** | 见“cgroup 分工（2026-10-04）” |
| 增强模块 | `sbo_identity` 模块取代桥接模块：自有 cgroup 门控移入模块、创建现场解析可执行文件完整路径，producer v3 | **实现完成；本机测试、真机 producer、整链路（错误 0）、1 小时长跑（错误 0、内核告警 0）与开销复测通过** | 见“增强模块 sbo_identity（2026-10-04）” |

阶段 1、2 已有实现及验收记录；阶段 3 已修正 cgroup 进程归属假设，并补做真实数据回包验证。
阶段是否通过以实际证据为准；未执行和不适用的检查分别列出，不用勾选掩盖未完成项。

## 执行纪律

1. 读取本文件、相关 AGENTS.md、两个仓库的 git status，以及当前阶段涉及的源码。
2. 确认上一阶段证据和依赖提交仍有效；尊重现有未提交改动，不根据聊天记忆推断完成情况。
3. 只实现当前阶段的必要内容；发现会影响正确性的缺口，先在该阶段记录并解决，不暗中改范围。
4. 更新实现项、实际执行的检查、原始日志路径和提交。没有跑过的检查写“未执行”。
5. 阶段完成以验收为准。能编译、能加载、函数存在，都不单独等于完成。
6. 代码提交按阶段保持可移植；同一阶段跨两个仓库时，记录应用提交与依赖提交的对应关系。

## 阶段 1：修复包表刷新

目标：应用安装、卸载、升级以后，包名查询持续更新；不需要重启 sing-box。
本阶段修复已有 bug，不改归属算法、不改变 TC 捕获规则。

### 实现项

- [x] 在 sing-box 增加本地 PackageManager 适配器，实现现有 tun.PackageManager 接口，
  在 `route/network.go` 替换创建入口；外部持有的对象保持稳定。
- [x] 复用现有 ABX 解码器，将必要的包表解析封装为本地纯函数，输出不可变的完整快照。
  不反复启动依赖内部的 watcher；这种实现仍是本地适配，不是新增组件 fork。
- [x] 监听 `/data/system` 并筛选 `packages.xml`，采用 100 ms 去抖、串行重读。
  先订阅再初读；读取期间再次收到变化则追加重读；监听错误/溢出有重建与补读处理。
- [x] 一次复合解析使用同一快照；查询返回的切片不得暴露内部可写存储。
  完整校验后一次发布，截断/读取失败保留上一份有效表并退避重试。
- [x] 语义内容没有变化不发送更新通知；变化时更新包集合和负查询结果，不冻结旧包名映射。
- [x] 保留原始 UID/包名/用户配置，为阶段 2 的纯编译函数提供输入；不在本阶段重复调用
  追加式 resolveAndroidUIDPolicy 来冒充规则热更新。

### 验收

- [x] 连续至少 10 轮安装/卸载，包含升级和共享 UID 集合 A→A+B→A，包表始终正确刷新。
  （“升级”以 `pm install -r` 覆盖重装模拟，见记录。）
- [x] 原子替换、突发通知、截断 ABX/XML、失败恢复和关闭期间回调均有针对性测试。
- [x] 并发查询/发布的 race 检查通过；反复更新后 watcher、FD、goroutine 无持续增长。
- [x] Android 构建与相关既有回归检查通过，记录实际运行的命令和设备结果。

交付边界：该阶段完成后，新包可被最新包表查到；如果它此前被 TC 的静态 UID 条件排除，
不能据此宣称其流量已被自动接管。该能力由阶段 2、3 完成。

### 阶段 1 实施记录

**改动**（全部在本仓库，未改任何依赖）：

- 新增 `common/androidpackages/`：`snapshot.go`（解析纯函数、不可变快照、语义比较）、
  `manager.go`（实现 `tun.PackageManager`：目录监听、去抖串行重读、失败退避、原子发布）。
- `route/network.go`：只把 `tun.NewPackageManager` 换成 `androidpackages.New`（另加一行 import）。
- `protocol/ebpf/android_uid.go`：首次解析时保存原始数值 UID 配置，之后每次都从它计算。

**实施中发现并处理的两个问题**（均有源码依据）：

1. **读到写了一半的 `packages.xml`**。AOSP `Settings.getSettingsFile()` 用
   `ResilientAtomicFile` 写该文件：`startWrite()` 把它改名为 `packages-backup.xml`，再直接在
   原路径写新内容；`finishWrite()` 刷盘后才删除备份；`openRead()` 在备份存在时优先读备份。
   实现按同样规则读取，并以“根元素必须闭合”拒绝任何残缺文档。
2. **`sing/common/abx` 读取器对截断输入无限循环**。`readAttribute()` 读到末尾时返回
   nil 错误，`readAttributes()` 只认 `io.EOF`，于是不断追加空属性直到内存耗尽（开发中三次
   拖垮 WSL）。对 1241 字节的 xml2abx 样本逐一截断，1237 个截断位置中 584 个在毫秒级内堆超
   64 MiB。不改 sing，改为在数据后补 0xFFFF+64 个 `END_DOCUMENT`（0x01）字节：同样 1237 个
   位置失控 0、卡死 0。补丁使读取器在截断处“正常结束”，因此根元素闭合检查不可省。

**已执行的检查**（WSL Debian，`likayo`，Go 1.25.5/1.26.6）：

- `CGO_ENABLED=1 go test -race -count=1 ./common/androidpackages/`：17 个测试全部通过，含
  Android 式重写（写入期间旧包不丢失）、写入失败读备份、损坏文件退避重试、内容不变不通知、
  突发合并、连续写入 1 s 上限、Close 后无回调且 20 次启停无 goroutine 泄漏、启动时恰逢写入、
  返回切片为拷贝、并发查询与更新、文本/ABX 解析、全部截断前缀的拒绝（ABX 1241 个前缀仅
  末尾 5 个、文本仅 1 个被接受，且都是完整表）、已知失控截断点 5 s 内返回错误、畸形输入。
- 对照验证（证明测试能发现问题）：①把 `android_uid.go` 换回修改前版本，新测试
  `TestResolveAndroidUIDPolicyStartsFromConfiguredUIDs` 失败（旧 UID 10001 残留）；
  ②去掉 1 s 上限，`TestManagerReadsDuringContinuousWrites` 断言失败；③不加补丁直接解析
  截断 ABX，堆看门狗在 0.34 s、308 MiB 时中止测试。三项对照后代码均已恢复。
- `go test -tags with_ebpf ./protocol/ebpf/`：通过；`go vet` 通过；
  `CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -tags <BASE_TAGS> ./common/androidpackages/ ./route/ ./protocol/ebpf/`：通过。

**真机验收**（2026-10-03，设备 `8b97939c`，Android 17 / 内核 6.12.69；以 root 运行
`device_test.go` 交叉编译出的测试程序，命令见该文件头部注释；原始输出
`experimental/socket_attribution_probe/results/stage1-device-acceptance.txt`，被 git 忽略）：

- `TestDeviceParityWithSingTun`：通过。对真实 `/data/system/packages.xml`，本地解析与
  sing-tun 解析器在 533 个包、462 个 UID、26 个共享用户上逐项一致，`PackageByID` 的首项也一致。
- `TestDeviceRefreshAcrossInstalls`：通过，46.8 s。10 轮，每轮：安装独立 UID 包 → 覆盖重装
  （UID 不变、包仍在）→ 卸载（旧 UID 不再映射到该包）；安装 A → 安装 B（两包同属一个共享
  UID）→ 卸载 B（只剩 A）→ 卸载 A（包与共享用户都消失）。每步都与 `pm list packages -U`
  的同步查询核对。60 次变化中，从 `pm` 返回到管理器可见：最短 23 µs、中位 52 µs、最长 55 ms。
  测试前后 goroutine 4→4、FD 9→9。回调 61 次（初始 1 次 + 每次变化 1 次；覆盖重装内容不变，
  不产生回调）。
- 测试前确认三个测试包均未安装，测试后均已卸载、临时目录已删除。
- 测试包只有一个版本，“升级”以 `pm install -r` 覆盖重装模拟：它走包替换流程、保留 UID，
  但不是版本号升高的升级。

## 阶段 2：在已有 sing-ebpf fork 中补齐两项能力

目标：UID 规则可以在线更新；现有 TC assignment 直接携带归属所需字段。
修改 `E:\sing-ebpf`，不增加额外 TC 挂载点，不改变既有流量分流架构。

### UID 热更新

- [x] 新增公开的 `UpdateUIDPolicy` 接口，输入最终 UID 决策和默认动作，不把 Android
  包名语义放进依赖。保存上一份有效规则，对等价更新直接返回未变化。
- [x] `tc_uid_policy` 的 max_entries 使用已有编译上限 4096，而非启动条目数。
  保持 LPM 的 NO_PREALLOC；超上限在写 map 前报错。差量更新顺序同时考虑过渡容量。
- [x] 同步处理 UID 策略启用位、默认动作以及 control。包含“配置了 include，但所有
  包均未安装”的空集合情形，不能误变成全量捕获或全量放行。
- [x] 成功提交和失败恢复都正确失效 TCP socket verdict 缓存。计算前读取判定序号，
  缓存只能标记为此次计算所用的序号；不得把旧规则计算的值写成新序号的有效结果。
  覆盖计算与提交交错、同 socket 并发访问的测试。（交错与并发由代码结构保证并有注释，
  见记录；没有能确定性复现纳秒级交错的测试，未执行此类测试。）
- [x] 复用已有策略更新的加锁、差量和回滚机制；回滚成功后重新失效可能受中间状态
  污染的缓存。回滚失败按已有健康状态机制报告故障，不继续声称更新成功。
- [x] 不把多条 map 写入称为整套策略的原子事务。正常包事件更新不拆后端、不主动断开
  会话；调用返回成功后，UID map、默认动作、缓存失效和用户态状态必须一致。
  并发更新期间的过渡行为必须通过定向抓包和失败注入验证，不能写成“零窗口”的承诺。

核查依据：当前 map 按启动条目数设置容量；控制信息有独立默认动作和
`PolicyGeneration`；`native/tc.bpf.c:local_selected_cached` 缓存 TCP 判定。
[内核 LPM 文档](https://docs.kernel.org/bpf/map_lpm_trie.html)保证单元素替换，
不能据此推导多条规则整体原子切换。因此该项不能只写成“给 map 加一个增删函数”。

### 现有 TC 程序补充归属字段

- [x] 扩展现有 `tc_assignment` 的 C/Go 对应结构，记录完整 socket cgroup ID、socket UID、
  有效字段标志，保留 cookie、接口、来源 MAC 和路径信息；不占用其他字段偷传信息。
- [x] 在原本记录 cookie 的路径调用 helper，正常只在需要建立/刷新 assignment 证据时
  读取补充字段；核对同 cookie 的 UID 改变与 UDP 复用，不能只凭 cookie 不变永久早退。
- [x] 所有 TCP/UDP、IPv4/IPv6、Ethernet/raw-IP、delivery 转发处都正确保留新增字段。
  非本机 shared 路径不填假的本机 UID/cgroup。（实测覆盖 IPv4 TCP/UDP、Ethernet、
  delivery；IPv6 与 raw-IP 走同一份 record/build_assignment 代码，未单独实测。）
- [x] 同步公开 Go API、结构大小/偏移断言、测试、生成对象和编译产物。测试不能仅验证
  C 或 Go 单边布局。
- [x] 保留无归属需求时的轻量路径；区分“启用 assignment 身份采集”和“存在旧
  ProcessTracker”。后续不使用模块时，cookie 与新字段也能得到。

### 验收

- [x] 动态规则覆盖新增、删除、空集合、默认动作、最大容量、重叠 UID 区间和失败恢复。
- [x] 建立 TCP 判定缓存后再更新规则，确认后续判定会刷新；UDP 按目的地处理，不套用
  TCP 的每 socket 结论。未受策略变更影响的长连接不因更新主动断开。
- [x] 完整 ABI 测试与 verifier/真机加载通过，相关既有后端测试通过。
- [x] 实际数据面核对新增字段与应用真值；提供与原 TC 程序配对的开销测量。
  已有约 1.5 ns 是单项 helper 微基准，不是新增结构和整段代码的最终成本。
  （配对开销、内核层真值、真实 App 真值（Chrome、Via）均已在真机完成，见记录。）
- [x] 记录可获取的远程依赖提交；应用仓库不留下本机路径 replace。
  （`LQ2002/sing-ebpf` 分支 `android-attribution`，提交 `3c1b28f0eb65`；应用仓库 replace 为
  `v0.1.0-alpha.10.0.20261003060717-3c1b28f0eb65`，提交 `6252b171`。）

实施记录（2026-10-03）：

**提交**：`E:\sing-ebpf` 分支 `android-attribution`（基于 `3420ee2`，即阶段 2 前应用 pin 的
alpha11 重放提交）上的 `3c1b28f`
“tc: hot-update the UID policy and record socket identity in assignments”。
提交信息里有完整的设计理由与验证记录。已推送；应用仓库依赖更新为提交 `6252b171`。

**接口**：`TCBackend.UpdateUIDPolicy(decisions []UIDDecision, defaultAction Decision) (bool, error)`；
`TCConfig.RecordSocketIdentity`；`TCAssignment` 新增 `SocketUID`、`SocketCgroupID`、
`IdentityFlags`、`HasSocketIdentity()`；常量 `TCIdentityUIDValid/TCIdentityCgroupValid`。
重叠语义沿用启动编译：与默认动作不同的决策胜出，调用方须先自行扣除 exclude。

**过渡保证（不是原子切换）**：先删“完全离开”的块、再加新块、最后删“改形”的块，
每个 UID 的匹配结果最多变化一次；若过渡容量超过 4096（v6.12 `trie_update_elem`
在找键之前就检查 `n_entries == max_entries`），改形块提前删除，期间这些 UID 可能
短暂落回默认动作。默认动作改变时先关 UID 策略：窗口是“全部拦截”，不会“全部放行”。
回滚成功后再写一次 control 推进代号；这次写失败则后端标记需重建。CIDR 与 host 地址
更新原本有同样的缓存污染缺口，一并改用同一 helper。

**判定缓存**：代号在计算前读；计算前后代号不同则不缓存；generation+verdict 以一个
对齐 64 位字读写。残余：control 由 bpf 系统调用无锁整块拷贝，弱内存序 CPU 上读到
撕裂值的窗口被缩小但未从形式上排除。

**身份字段**：两个 helper 在内核中用同一判断（`net/core/filter.c` v6.12 的
`sk_to_full_sk`+`sk_fullsock`），cgroup id 非 0 即证明 UID 有效；socket cgroup 在
创建时定下（`kernel/cgroup/cgroup.c` `cgroup_sk_alloc`）；sk_uid 可被 fchown 改
（`net/socket.c` `sockfs_setattr`），因此同 cookie 每包比较 UID。cookie 只在被选中的包
上读取。

**验证**（WSL 6.18 root 与真机）：
- `make check`（NDK r29 clang 21 可复现）、vet、unit、-race、internal/core/runtime/根包
  全部 integration 通过。
- 真实 socket 测试（双 netns veth、TCX、fchown 设 UID）：TCP 缓存在更新后刷新；
  无关长连接不受影响、相关长连接中断后回滚恢复；空集合/默认动作/关策略/等价更新；
  control 写失败注入（恢复或标记重建）；真实 trie 上 4096 条满容量改形；身份字段对照
  SO_COOKIE、fchown UID、创建时 cgroup（进程迁出再迁回）、fchown 后变化、UDP 五元组复用、
  经真实 delivery 路径（veth＋透明监听＋fwmark 本地路由）后保留。
- 变异检验：去掉 delivery 携带、恢复同 cookie 早退、跳过最终 control 写，对应测试均失败。
- 真机（Android 17 / 6.12.69）：internal/core 全部 integration 137 PASS、0 FAIL
  （cgroup 测试因本机拒绝加载 cgroup 程序而 skip，与本次无关）。原始输出
  `experimental/socket_attribution_probe/results/stage2-device-sing-ebpf-core-integration.txt`。
  真机测试使用系统段 UID：netd 挂在根 cgroup 的 egress 程序对应用段 UID 执行防火墙链，
  早于 TC（AOSP Connectivity `bpf/progs/netd.h` `is_system_uid`、`netd.c`
  `bpf_owner_match`）；最初用 10050 时 SYN 计入 TcpOutSegs 却从未出现在任何网卡上。
- 配对开销（真机，内核 BPF run-time 统计，旧 `3420ee2` 与新提交交替 5 轮，ns/次，中位数）：
  UDP 被选中轻量 94.6→93.8；UDP 被选中身份 134.3→140.3（配对差中位 +1.9）；
  UDP 未选中身份 80.6→78.1；TCP 缓存命中轻量 68.7→69.4；TCP 缓存命中身份 69.9→69.0。
  原始输出 `experimental/socket_attribution_probe/results/stage2-device-overhead-paired.txt`。
- 应用仓库对 `3c1b28f` 的构建：经 /tmp 下临时 go.work，Android arm64 按 workflow
  BASE_TAGS（含 with_ebpf）与 linux 无 with_ebpf 均构建通过，protocol/ebpf 与
  androidpackages 测试通过；两个仓库的 go.mod 均未改动。

**远程依赖**：经用户确认已推送并更新 replace（见验收最后一项）。

**真实 App 真值**（真机解锁、App 在前台；`tc_android_app_identity_integration_test.go`，
驱动方式见文件头注释）：在主网络命名空间只加测试 veth `idta`/`idtb`、dummy `idtd`
和一条未用地址 10.211.0.2/32 进默认网络的路由表（wlan0 = 1024），用 `am start` 让
App 打开 `http://10.211.0.2:7000/`，SYN 被记录后重定向到 dummy 丢弃，结束时全部清理，
事后核对 wlan0 表恢复原样。网卡名避开 runtime 使用的 `sbt*/sbd*/sbi*/sbo*/sbc*`，
因为手机上运行中的 sing-box 用 `sbt…` 命名。真值判据：SocketUID 等于 `pm` 的包 UID；
cgroup id 按 inode 解析为 `apps/uid_<UID>/pid_<P>`；进程 P 的真实 UID 等于该 UID 且
cmdline 为包名。
- Chrome（UID 10309）：2 条连接，均为 `apps/uid_10309/pid_19344`，进程 UID 10309，
  cmdline `com.android.chrome`。PASS。
- Via（`mark.via`，UID 10286）：1 条连接，`apps/uid_10286/pid_25616`，进程 UID 10286，
  cmdline `mark.via`。PASS。
- 原始输出 `results/stage2-device-app-truth-{chrome,via}.txt`。首次在锁屏（Dozing、keyguard）
  时运行，App 没有发起任何连接（程序只处理了 ARP/IPv6，/proc/net/tcp 无该连接）；
  这是锁屏下 App 不加载页面，不是数据面问题，解锁后重跑通过。

**交给阶段 3 的发现（仅读源码确认编译语义，可达性未验证）**：`protocol/ebpf/action_policy.go`
`compileActionPolicy` 在配置 include 时把 include（拦截）与 exclude（放行，等于默认动作）
一起传入；`compileUIDActionPolicy` 会丢弃与默认动作相同的决策，所以落在 include 区间
内的 exclude 在 TC 路径上不生效。`compileProcessUIDPolicy` 已先做扣除，没有此问题。
阶段 3 调用 `UpdateUIDPolicy` 时必须传扣除后的决策，并核实启动路径是否受影响。

## 阶段 3：sing-box 接线和整链路验收

目标：用新增字段完成普通 App 快速归属，并让包表变化驱动已配置的包规则更新。
只保留一条确定的运行路径，不引入多套发行/试验配置。

### 实现项

- [x] 在 `protocol/ebpf` 接收新的 assignment；普通、非共享应用 UID 优先查当前包表，
  保留完整 UID/userId。socket UID 与 cgroup 的 UID 标签一致时可提供应用级包归属，
  不从目录 PID 推断创建者；共享/系统归包只使用 cookie 创建者证据与核验后的进程名。
- [x] Go Manifest 缓存按 APK 路径与包更新信息失效；包升级、进程声明变化重新读取。
  组件/共享 UID 歧义、不完整解析和缺失证据均保持未知，不再扩展 Java 构建链。
- [x] 不把 46/46 或当前第三方应用 UID 分布当作一般性证明。AM 日志没有出生令牌，
  不能仅凭 PID/进程名/接收时间窗口永久绑定；校验当前实例与事件来源，过期、重连、
  PID 复用或证据矛盾即失效。存量补齐使用有界查询，不在每条连接轮询 /proc。
  （cgroup id 仅标识组。模块提供 socket 创建时的 PID/UID/start_boottime；同一 proc
  目录 FD 核验启动时间和 UID 后读取 exe/cmdline。元数据仅缓存 1 s，不承诺立即检测 exec。）
- [x] 普通唯一路径不等待 AM；共享/系统 UID 无法唯一归包时返回未知。
  未知返回非 nil ConnectionOwner，阻止路由器回退后填入整组候选包。
- [x] 已有模块仅按需提供创建者后备；创建者、socket UID、宿主和记账 UID 语义分开。
  不要求安装模块，不自动卸载模块，不把未知暗中改为直连或其他出口。
- [x] 由包表更新通知驱动纯函数：原始配置＋同一包表快照→最终 UID 决策；只在最终
  规则改变时调用 UpdateUIDPolicy。序列化并合并重复更新，区分目标规则与已生效规则。
- [x] Android 新路径不依赖旧 ProcessTracker 的 UID 过滤器；如果仍保留其可选调用，
  必须同步更新或明确停用，不能让一套过滤器停留在启动状态。其他平台契约保持不变。
- [x] 接入现有诊断：包表状态、更新失败、目标/实际规则是否一致、归属来源、未知原因，
  以及事件/assignment 缺失。避免逐包日志。（接入内部 `EBPFDiagnostics`；未改上游
  daemon protobuf，见记录。）

### 验收与交付

- [x] 包规则指定未安装包，安装后该 UID 的实际流量自动被接管；卸载配置包后规则移除。
  已用共享 UID 的 A/B 包与同 UID 原生负载验证：只装 B 时回包、装 A 后拒绝、卸载 A 保留 B
  后恢复回包，始终为同一 sing-box 实例。同包覆盖重装不更新 TC。规则未应用时诊断不显示
  已生效有单元测试。此项不等于真实 App 自主发流或版本号升高的升级验收。
- [ ] TCP/UDP、IPv4/IPv6、冷/热启动、UDP 多目的地、共享进程未知、模块缺失均通过。
  测试真实 sing-box 转发入口，不以 loopback 独立探针代替集成验收。
  （本轮完成 IPv4 TCP 真实转发及消费者无法打开模块的真机分支；其余矩阵未完整重跑。
  共享进程歧义与模块缺失有单元测试，未物理卸载模块。）
- [ ] 包升级、进程退出/重用、system_server 重启及启动存量，不能把旧身份
  贴给新进程或新包；证据不足明确未知。（AM 日志断连不适用；未使用 AM 并不免除
  system_server 重启后包表/UID 变化的验收。本次不重启用户设备的 Framework。）
- [x] 相同设备/配置/负载下五组配对数据转发检查，报告已校验 echo 吞吐、CPU、RSS、
  建连延迟与数据回包尾延迟，逐轮交替新旧版；共 10000 次完整 64 KiB 回包。
  仅覆盖系统段原生 UID 经 TC 的受控 IPv4 TCP 负载，不代表普通 App 识别覆盖、饱和吞吐
  或长期内存行为；识别范围和未知边界见下方记录，不据此宣称总体提速。
- [x] 提供最小移植清单：主仓库提交、依赖提交、触及的接口、已执行测试。
  `E:\Ref_sing-box` 仍不在本次修改范围内，移植时依照这份清单执行。

实施记录（2026-10-03）：

**提交**（`E:\ebpf_sing-box`，`codex/strict-app-attribution` 分支，依赖 `6252b171` 之后）：
`851da4e3` 3a 包表驱动 UID 规则；`ee23be21` 3b-1 TC 身份归属；`c9580c3c` 3b-2 Manifest
进程名索引；`0550992a` 诊断；`72560a86`、`af5ee10b` 归属日志与启动提示修正；
`dc9c85b5` Android App 用户名。每个提交信息含完整理由与验证。

**3a 规则热更新**（`protocol/ebpf/android_uid_update.go`）：`androidpackages.Manager`
新增 `Snapshot()`（一次计算只读同一张表）与 `Subscribe()`；通知只向容量 1 的通道投递，
突发合并；单 goroutine 串行写内核；`resolveAndroidUIDRanges`＋`compileUIDDecisions`
为纯函数，与启动同一路径；决策不变不写内核；目标/已生效分开，`InSync` 只在
`UpdateUIDPolicy` 成功后为真；失败退避重试，后端需重建时停止重试；cgroup 数据面无法
原地更新，报告 `restart_required`。旧 cgroup ProcessTracker 的 UID 过滤器启动后无法更新，
包规则跟随包表时改为不过滤。顺带修复：文档规定 exclude 优先于 include，但启动策略把两者
并列交给 sing-ebpf，后者丢弃与默认动作相同的决策，include 区间内的 exclude 在 TC 与 cgroup
上都失效；现统一用扣除后的决策。

**3b 归属**（`protocol/ebpf/socket_identity.go`、`process_package_index.go`、新包
`common/androidmanifest`）：
- **复核修正**：TC 的 cgroup id 只定位 Android 进程组。fork 子进程继承该组，迁入进程也可
  共用它；`pid_Y` 不是 socket 创建者，kernfs id 也不是进程出生令牌。
- socket UID 与组 UID 一致、且是普通唯一应用 UID 时 → 包名，无 /proc 或模块查询，
  `ProcessID=0`、不填路径；SDK 沙箱 → 宿主（UID−10000）。这是 UID/应用组级归属，
  不声称精确识别创建进程，也不对有权限任意迁组、改凭据或 fchown 的行为作安全保证。
- 共享/系统 UID、UID 矛盾、根组或组已消失 → 按 socket cookie 查询可选模块；用模块的
  创建者 UID/PID/start_boottime 核验 procfs 后，exe 为 app_process 才用完整 cmdline 查
  Manifest，唯一才归包。netd 的 fchown socket 在模块有记录时归 netd；无证据不归给 App。
  不同 cookie 的创建者不能共用按 cgroup id 缓存的进程结果。
- 效率：cgroup id 仅缓存组 UID；进程元数据复用原有 `(PID, UID, start_boottime)` 的 1 s
  缓存，核验失败或 cmdline 不完整不缓存。Manifest 解析不在连接路径上：
  后台单 goroutine 按 appId 建索引，仅有可选创建者来源时预热共享/系统 UID，按
  codePath+ut+version 失效；resources.arsc 只在出现引用时读取，并跨该包全部 APK 解析
  （Chrome 的 split 引用 base 资源）。`open_by_handle_at` 本可 O(1)，但真机 GKI 未开
  `CONFIG_FHANDLE`（ENOSYS）。
- `am_proc_start` 不采用：它给出“启动该进程的组件所属包”，而其他包的组件之后会载入同一
  进程（阶段 1 探针已见到误认），对 (进程名, UID) 没有额外区分力，且只能按 PID 拼接、
  没有出生令牌；因此精确进程证据取自可选模块，而非 cgroup 目录。
- 包表新增 codePath 与版本戳；只改这两项（原地升级）时静默发布，不触发回调。
- 用户名：Go 的 `os/user` 在 android 上未实现（与 CGO 无关），只有当前用户 root 能解析；
  App/isolated UID 按 bionic 公式生成 `u<user>_a<n>`/`u<user>_i<n>`。
- 诊断：`EBPFDiagnostics.android_uid_policy`（目标/已生效、更新/失败计数）与
  `attribution`（按 UID/按进程名归包数、未知原因、索引进度）。上游 daemon 的 protobuf
  未改（需重新生成上游代码、增加 rebase 成本），所以这些字段暂不经 API 输出；归属结果
  普通快路径按 cgroup 组记日志，模块元数据按已有短期缓存抑制重复日志。

**验证**：
- 本地：全部单元测试（含 -race）、android/arm64 vet；Manifest 解析用 aapt2 生成的真实 APK
  夹具（各种资源编码、split 引用 base），截断输入全部报错。
- 真机 `TestDeviceProcessNamesMatchManifests`：79 个运行中 App 进程 67 唯一、7 多包、0 无法
  解释，533 个包 0 解析失败（`results/stage3-device-manifest-process-names.txt`）。
- 修复前真机记录（`results/stage3-device-acceptance-summary.txt`，不能代替修复后的验收）：Chrome 冷启动首连接即归包；
  一分钟内后台流量归属涵盖普通 App、UID 1000 的 securitycenter、同一共享 UID 下两个进程
  分别归包、系统 AID 6110；system_server 按设计未知，netd 给出可执行路径；
  exclude_package 测试 App 安装后 0.16 s 规则生效、覆盖重装不写内核、卸载后 0.06 s 移除；
  IPv6 连接被拦截并归属（本网络无 IPv6 出口）。用户 config.json 下 check 通过、归属正常。
- 修复前配对性能（用户配置，5 轮×1000 连接，`results/stage3-device-perf-paired.txt`）：本地 TCP 建立连接
  p50 110.3→109.4 µs、p90 210.3→198.8 µs、p99 539→603 µs（逐轮互有高低）、sing-box CPU
  0.37 s→0.37 s/1000 连接；启动后 RSS 新版前 30 s 多约 7 MB（Manifest 预热解压
  resources.arsc 的临时堆），90 s 时已回落到 39.4 MB（旧版 44.9 MB）。
- 上述性能脚本在 connect 返回后立即关闭，无业务数据回包；p99 不是转发尾延迟。
  CPU 采样含后台流量和负载后 2 s 等待，RSS 是短时观测；不能据此宣称整体性能优于旧方案。
- 原次未执行：物理卸载模块、实际版本升级、Framework 重启；不适用：AM 日志断连。
  修复后模块是所有精确进程归属的可选来源，而非只用于根 cgroup。
- 发现：用户日常二进制来自另一分支，其完整 config.json 含本仓库不支持的字段
  （`experimental.urltest_unified_delay`、`group` 类型 DNS 等）；用户随后换用的 config.json
  本仓库可直接运行。

### 阶段 3 复核修正与补充验收（2026-10-03）

**代码提交**：`cae57485`。`E:\sing-ebpf` 本轮未修改，仍使用 `3c1b28f0eb65`；
`E:\Ref_sing-box` 未修改。

**修正内容**：
- 删除 cgroup 缓存中的 PID、exe、进程名及基于目录 PID 的 procfs 查询。普通唯一应用
  快路径仅返回 UID/包名、PID 为 0；其余按每条流的 cookie 找创建者，绝不在同组 cookie
  之间复用某个进程的身份。组 UID 与 socket UID 矛盾且无创建者证据时，UID 也保持未知。
- procfs 元数据继续用 `(PID, UID, start_boottime)` 短期缓存；共享/系统归包所需的完整
  cmdline 必须来自同一个已核验的 proc 目录。缺失、空或无 NUL 结束的 argv[0] 不缓存。
  包名细化先取得一份包表快照；后台 Manifest 索引只在存在 cookie 创建者来源时启动。
- TC 身份新路径限制为 Android，Linux 保留旧 tracker 路径。诊断新增创建者不可用与 UID
  矛盾计数，把误称创建者消失的字段改为组无法解析。
- 原突发通知测试用调度相关的“最多 5 次更新”断言，完整 race 复跑暴露偶发失败；现用
  同步门控持有一次后端写入，再投递 50 次更新，严格断言一次在途写入加一次最终更新。
  只修正测试，不改变实际合并算法。

**本地验证**（WSL Debian / Go 1.26.6）：
- `go test -race -tags with_ebpf ./protocol/ebpf ./common/androidpackages ./common/androidmanifest -count=1`
  通过；最后的 Android-only guard 与测试门控修改后，完整 `protocol/ebpf` race 再次通过
  （10.724 s），对应平台与合并测试 `-count=20 -race` 通过（2.215 s）。
- 新回归覆盖同组不同 cookie/创建者、组目录父进程退出、同组 PID 重用、UID/启动时间不符、
  cmdline 不完整、模块不可用/查无记录、netd fchown、普通快路径零 procfs/模块查询，以及
  一次细化只用同一包表快照。独立最终代码复核未发现阻断问题。
- android/arm64 vet 通过；NDK r29、CGO、仓库工作流 BASE_TAGS 的 Android arm64 构建通过。
  最终 guard 不改变 Android 成品字节，重建哈希一致。最终测试二进制
  `results/sing-box-android` SHA-256：
  `07260be09bab492f147d6b10ce47cb224067af557af521f4dc09f1e6de2dfb36`。
  它在提交前构建（当时 HEAD `0dd5dbb7`，含本次修复），不能仅用构建时 HEAD 代表其源代码。
  本地原始输出：`results/stage3-fix-{local-race,platform-coalescing,android-build}.txt`。
- 验收负载工具的 race、vet、arm64 构建及回包损坏/截断/超时测试通过；所有验收 shell
  脚本语法检查与 `git diff --check` 通过。旧 connect-only 模式与新 echo 模式分别标注指标。

**真机数据面**（设备 `8b97939c`；以下 `results/` 均指
`experimental/socket_attribution_probe/results/`，已被 Git 忽略）：
- 使用两个私有网络命名空间、veth 和可核验的 echo 对端；每次启动先用 bpftool 确认私有
  接口已挂 TCX。负载必须完整发送并逐字节核对回包；connect 成功不再作为转发成功。
- 旧 `7c12b1de` 与上述最终修复二进制交替五组，每组每版 1000 次 × 64 KiB，10000 次全部
  校验通过。各版五轮中位数如下；“配对差”是逐轮新减旧后取中位数，不是两列中位数相减。

| 指标 | 旧版 | 修复版 | 配对差中位数 |
|---|---:|---:|---:|
| 建连 p50 / p99（µs） | 122.865 / 399.844 | 120.938 / 381.355 | -0.885 / +20.937 |
| 64 KiB 数据回包 p50 / p99（µs） | 468.958 / 1042.083 | 468.593 / 930.677 | +0.469 / -24.010 |
| 建连到完整回包 p99（µs） | 1183.229 | 1139.323 | -42.812 |
| 已校验 echo 吞吐（MiB/s） | 95.988 | 96.940 | +0.472 |
| sing-box CPU（tick，100 tick/s） | 59 | 60 | -1 |
| 负载结束 RSS（KiB） | 31892 | 38316 | +6464 |

  第五组两版都明显变慢，完整保留；RSS 为启动约 3 s 后的短时观测，修复版此时约多 6.3 MiB。
  负载为 UID 9050 原生程序，不是普通 App 归包覆盖；顺序 echo 吞吐不是最大承载能力。
  原始数据：`stage3-fix-device/isolated-perf.txt`、`perf-summary.json`。
- **消费者模块不可用**：在测试进程的私有 mount namespace 内，用只读普通文件覆盖设备
  节点，使打开模块返回 EROFS；日志确认 `process_tracking=tc_socket_identity`、无 cookie
  来源。100 次 × 64 KiB 回包全部通过。全局模块保持加载，因此不代表卸载模块后的系统
  开销或普通 App 归属覆盖。见 `stage3-fix-device/module-unavailable-final.txt`、`forward.log`。
- **安装与同包重装**：`include_package` 指定起初未安装的测试包；安装后实际 UID 10495
  的同目的流量被捕获并由 reject 路由拒绝，同一实例内覆盖重装仍拒绝且规则更新计数
  1→1。不挂测试 TC 时同 UID 5/5 完整回包，排除端点自身故障。完全卸载独占 UID 后，
  有无测试 TC 都被 netd 阻断，此结果明确为 INCONCLUSIVE，不能证明规则清除。
- **卸载配置包**：为排除上项 netd 干扰，另用共享 UID 10496 的 A/B 夹具，配置只 include A。
  同一实例 PID 12242/start 14903174：只安装 B → 5/5 完整回包；安装 A → 5/5 拒绝；
  卸载 A 保留 B → 同 UID 5/5 完整回包恢复。前后不挂测试 TC 的基线也均 5/5 通过。
  这验证配置包卸载后实际 UID 规则移除，未把原生同 UID 负载写成 App 自主发流。
  见 `stage3-fix-device/isolated-shared-package.txt`、`shared-package.log`。
- 测试包已全部卸载、测试进程和私有命名空间已清理，本次 `/data/local/tmp/sbe3-fix`
  临时目录已删除。用户服务始终为 PID 11765、
  start ticks 14670767；前后 cmdline、主命名空间 links/IPv4 routes 逐字节一致，模块设备
  仍为 10,300。清理核对见 `stage3-fix-device/shared-cleanup.txt` 等原始文件。

**仍未完成的完整验收**：本轮修复后真实 App 自主发流与冷/热启动矩阵、UDP 多目的地及
IPv6 完整转发、真实版本升级、Framework 重启、真机受控 PID 重用及长期内存行为未验证；
未物理卸载模块。当前成果不能把阶段 3 整张检查表标为全部通过。

### 与旧模块方案的对照复核（2026-10-03）

用户要求查询、实测后比较性能、速度与准确度。本次比较旧基线为 `7c12b1de`＋模块，
新基线为 `cae57485`（验收工具与记录 `d8edd60b`）＋同一个模块。二者 go.mod 与模块实现
没有差异，均使用 sing-ebpf `3c1b28f`；旧版 `TrackProcess=true` 和新版
`RecordSocketIdentity=true` 都选同一 TC process 变体，因此本组数据主要比较消费端逻辑。
不要与阶段 2 对更老依赖 `3420ee2` 的内核开销实验混为一次整体对照。

**源码可确定的取舍**：
- 普通唯一应用：旧版每条连接/新 UDP 会话查模块 cookie，proc 元数据缓存 1 s；新版组缓存
  命中时不做 ioctl 或 procfs 查询，直接从当前包表返回包名，但 PID 为 0、无可执行路径。
  组缓存未命中仍需目录扫描，不能仅凭热路径结构推导首次连接必然更快。
  归属查询主要发生在建连/新会话，不能把省一次 ioctl 按每个数据包计算吞吐收益。
- 共享/系统 UID：旧版保守不填包名；新版有 cookie 创建者证据、proc 核验及 Manifest 唯一
  声明后能归包。此路径仍需模块，并增加 cmdline、索引查询和后台 APK 解析成本。
  79 个运行中进程的历史 Manifest 样本（67 唯一、7 歧义、5 沙箱/隔离）只是声明匹配覆盖，
  不是 79 条 socket 真值，也不是新方案准确率的分母。
- 普通 UID 下的原生子进程：旧版保留真实 PID/native 路径；新版快路径按应用组归包。
  按原生可执行文件名、路径或路径正则的规则因此失去输入；Android `process_path` 用包名
  匹配的兼容分支仍可工作。按包分流和精确进程分流的收益不能合成一个“准确度提升”。
- SDK sandbox 新增宿主映射；模块不可用时新版仍能普通应用归包，而特殊创建者保持未知。
  安装/卸载后 TC 包规则自动跟随也有实际数据面验证；旧基线虽有阶段 1 包表刷新，尚未把
  该通知接到 TC 规则更新。
- 模块仍加载时，全局 socket create/free 钩子、分配和哈希维护照常执行。模块
  `experimental/sb_sockowner_probe/sb_sockowner_probe.c` 没有按查询者需求或普通 App UID
  停采开关。因此减少 ioctl 不等于消除模块的内核 CPU/内存成本；本次未测卸载模块后的功耗。
- cgroup PID 误认是阶段 3 中间实现的问题，旧模块方案原本就用真实 cookie 创建者；
  本轮修复不能重复算作“比旧模块准确”的收益。官方依据：
  [Linux cgroup 继承/迁移语义](https://docs.kernel.org/admin-guide/cgroup-v2.html#processes)、
  [Android 多包共享进程语义](https://developer.android.com/guide/topics/manifest/application-element#proc)。

**已有真机配对数据重新核算**：上节五组全部保留。吞吐中位数 95.988→96.940 MiB/s，
两列差约 +0.99%，逐组差中位数仅 +0.472 MiB/s；数据 p99 有 3 组改善、2 组变慢；
CPU 中位数 59→60 tick，无稳定降低证据。新版短时 RSS 每组都较高，配对增量中位数
6464 KiB（约 6.3 MiB）。第五组两版同时明显变慢，不能用五组中位数声称总体显著提速。
此负载为系统段原生 UID，不验证普通应用快路径的整体收益，未测功耗或最大持续吞吐。

**新增查询微基准准备**：`protocol/ebpf/attribution_query_device_test.go` 可原样放入旧
`7c12b1de` 源树，直接调用其生产 `lookupProcessInfo`；当前树另加
`attribution_query_current_device_test.go` 调用 `ownerFromIdentity`。只有同时使用
`android`、`with_ebpf`、`attribution_query_device` 构建标签并设 `SBO_QUERY_BENCH=1`
才执行。每轮保存 500 次用户态缓存未命中和 5000 次热查询的原始 ns，五轮，并保存空计时器
分布。前者不等于 App 冷启动，计时不包含包表初始化、缓存重置或结果校验。

模块输入为测试进程实际创建、保持打开且未 connect 的原生 TCP socket；快路径输入为
真实已安装普通 App 的 UID/组目录 inode 构成的受控 identity，并非 TC 实际采集的 App
socket。两种输出的语义和 fixture 不同，只能分别描述函数成本，不能据此计算同一 App
的整体加速倍数。运行不会加载 BPF、发网络包、迁组、安装 App 或更改用户服务。

本次准备时 `adb devices -l` 为空，新增真机查询耗时尚未取得。上文数字仍来自上一轮
已完成的配对验收；不能把本次编译准备写成新增真机性能或准确率结果。
两版最终测试程序均已通过 Android arm64 交叉编译；模块输出逐次核对实际 `/proc/self/exe`
绝对路径，comm-only 回退不能冒充已核验元数据。产物位于原有 `results/`：
- `query-current.test`：SHA-256
  `5701ec28f528e95c41e860b4dd3fe83d4adbabdd67c3842f047439c388f623da`。
- `query-old.test`（`7c12b1de` 源树＋同一公共测试文件）：SHA-256
  `bfb5ef749be302a923cdd12eca2dbf08588057de668325f5a29bd267f6ac796f`。

**移植清单（→ `E:\Ref_sing-box`）**：
- 依赖：`github.com/LQ2002/sing-ebpf` `3c1b28f0eb65`（`UpdateUIDPolicy`、
  `TCConfig.RecordSocketIdentity`、`TCAssignment.SocketUID/SocketCgroupID/IdentityFlags`）。
- 新增文件（可整体复制）：`common/androidpackages/view.go`、`common/androidmanifest/*`
  （含 testdata）、`protocol/ebpf/android_uid_update.go`、`socket_identity.go`、
  `process_package_index.go` 及对应测试。
- 修改点：`common/androidpackages/{manager,snapshot}.go`（Subscribe、codePath/版本戳、
  静默发布）；`protocol/ebpf/action_policy.go`（`buildActionPolicy`/`compileUIDDecisions`，
  exclude 优先）；`android_uid.go`（`resolveAndroidUIDRanges`、启动提示）；
  `inbound.go`（字段）；`inbound_lifecycle.go`（RecordSocketIdentity、回退、跳过 cgroup
  追踪器、启动/停止 updater 与索引）；`tc_connection.go`、`inbound_connection.go`、
  `udp_state.go`（身份传递）；`socket_owner_resolve.go`（用户名、创建者元数据与同快照归包）；
  `diagnostics.go`。必须包含本轮修复 `cae57485` 及对应 creator/platform 回归测试，不能只
  移植 `0dd5dbb7` 以前的 cgroup PID 归属实现。
- 测试：`go test -race -tags with_ebpf ./protocol/ebpf/ ./common/androidpackages/
  ./common/androidmanifest/`；真机 `common/androidmanifest` 的 Device 测试；按上面的
  真机整链路步骤复验（脚本与说明在 `experimental/socket_attribution_probe/stage3e2e/`）。

### 进程身份到 socket 存储的独立原型（2026-10-03）

用户允许跳出当前项目的既有假设，深入 AOSP/Linux 源码，并明确授权“验证原型可以，
但是不考虑自定义内核”，要求代码提交。本实验属于阶段 3 的独立研究，不新增第四阶段，
不把原型结果算作生产集成验收；不修改 `E:\sing-ebpf` 或移植目标。

原型代码提交：`7ffa23f2`（`experiment: verify task-to-socket identity carrier on Android`）。

**已实测路径**：测试登记者使用进程自身交出的 pidfd 写 TASK_STORAGE；独立小模块把
现有 Android socket-create vendor hook 桥接为带 `struct sock *` 的标准 typed tracepoint；
BPF 在创建现场从线程组 leader 的 TASK_STORAGE 复制身份到 SK_STORAGE；私有 lo 上的
TCX 直接读取同一 socket storage。模块不维护 owner 哈希表、不提供查询 ioctl，不修改
当前运行内核；用户生产模块与 sing-box 保持运行。

原型位于 `experimental/identity_carrier_probe/`，只对指定测试 TGID 启用桥接；登记使用
随机 128 位合成 token，**不代表已实现 AMS/zygote 的可信 App 包名登记**。由 root 父进程
写入 task storage；worker 通过 `SCM_RIGHTS` 交出自身打开的 pidfd，未向 worker 交付 map FD，
也未在事后用裸 PID 重新打开登记目标。未登记时 token 为零，保留实际创建者元信息。

**构建与兼容性**：
- 模块以 Android Clang r536225 构建；13/13 传统 CRC 与 13/13 扩展 CRC 均一致，12 个导入
  全部有设备 CRC。当前运行内核的 BTF SHA-256 与构建底座逐字节相同，加载脚本强制核对。
- 最初包含完整 `net/sock.h` 的构建暴露了关联类型图差异，不能仅凭 `sock` 本身布局相同
  就绕过 verifier 的类型要求。最终 C 桥只检查 TGID、不解引用 socket；标准 pahole 自然
  将 opaque `struct sock` 解析到真实设备 base BTF ID 2886，没有修改 BTF ID 或放宽验证。
  对 C 实际用到的 task size/TGID/stack canary 偏移保留设备布局断言。
- BPF 由 clang 19 构建；`sk_kern_sock` 位字段使用 CO-RE 重定位，非内核 INET4/6 socket
  才进入采集。Go 1.26.6 的普通测试、race、vet 与 Linux arm64 静态交叉编译通过；单测
  覆盖 ABI、错误 token/出生时间/首包标志、FD 传输协议及只允许 loopback 目的地址。

**真机结果**：设备 `8b97939c`，原有内核
`6.12.69-android16-6-g586bfab1b9c5-abogki536749445-4k`。
模块加载、runtime module BTF、BPF verifier、typed tracepoint 和私有 lo TCX 均实际通过。
两轮各 7 组、18 个 socket 全部通过；每个 socket 首次 send/connect 前，父进程都用收到的
真实 socket FD 核对 SK_STORAGE，且确认 TC 观察记录尚不存在。对端收到并核验完整载荷，
随后按真实 `SO_COOKIE` 核对 TC 的首个观察；TCP 必须为 SYN 且无 ACK，UDP 必须只有一次
数据报观察，并核对地址族、接口、token、generation、TGID/TID、UID 与 leader 出生时间。

| 场景 | 每轮 socket 数 | 已观察到的行为 |
|---|---:|---|
| root IPv4/IPv6 × TCP/UDP | 4 | 首个 SYN/数据报已有创建时身份 |
| shell worker A，同上 | 4 | UID 2000，身份与本 worker 的登记一致 |
| shell worker B，同上 | 4 | 同 UID 下不同进程/token 严格区分 |
| 登记 A→建 socket A→登记 B→建 socket B→发送 | 2 | 两个 socket 分别保留 A/B 快照 |
| 未登记 worker | 1 | token/generation/registered flag 均为零，未伪造身份 |
| 非主线程创建 | 1 | TID 不等于 TGID，token 与出生时间来自 leader |
| 转交 FD 后创建者退出，再由父进程首次发送 | 2 | 旧 pidfd 已 ESRCH、TASK_STORAGE 已 ENOENT，TCP/UDP 仍携带原创建者身份 |

两轮计数均为 `hook_calls=18, registered=17, unregistered=1`，其余七项错误计数全为 0。
主命名空间直接运行的拒绝检查也实际通过。原始日志（Git 忽略）在原型的
`results/device-run01.txt`、`device-run02.txt`、`device-run0{1,2}-state/` 与
`main-namespace-refusal.txt`。

首轮测试全过，但清理比较把移动网络 IPv6 RA 路由 `expires 64312sec→64311sec` 的自然
倒计时误报为变化。保留原始快照，比较时只规范化 `expires` 秒数后重跑：最终
`CLEANUP run_rc=0 cleanup_rc=0`；接口、IPv4 路由、IPv4 policy rules、IPv6 路由条目均一致。
boot ID 未变，生产 sing-box 始终 PID 11765/start ticks 14670767，cmdline 相同；原生产
模块仍加载、taint 4608 未变。原型模块已卸载，无原型进程或 pinned BPF 对象；日志取回后，
本轮专用 `/data/local/tmp/sbo-identity-carrier-20261003` 目录已删除。

**最终构建 SHA-256**：
- runner：`811c990f3f5ee4902b50ecf19343b72a3a5f7daa67515a3f9fb690f1af3245ac`。
- BPF：`b8f3e83c4df712ebd56e5ff0d89004185bf0eec684fcd125237280fbdcdb3001`。
- 模块：`c840d6b2463fcd0698b983522fc408a61a30100229ff5ce3bd9a5473fd110d2b`。
- 设备 base BTF：`37d2c7e7bc5ec219db6148d4a874d9cfc05216db3d7b860adfafc567576b5f35`。

**结论与边界**：现有内核上，创建时把进程实例身份固化到 socket、再由 TC 首包直接读取
已经有实测证据；创建者退出和同 UID 不会迫使此载体退化为猜测 PID/UID。它仍使用一个小
桥接模块，尚未接入 AOSP 可信包名登记、真实 App 流量或生产 sing-ebpf assignment；没有
替换现有生产 owner 模块。纯 fork、exec/非主线程 exec、accept clone、io_uring、长期内存、
真实性能/功耗对比均未执行，不能据本轮声称包归属覆盖或速度已经提升。
登记切换通过屏障串行执行，未验证创建 socket 时并发更新 TASK_STORAGE 的原子性；内核
出生时间只以 `/proc` 的 USER_HZ ticks 交叉核验，root/shell 夹具不代表 App SELinux 场景。

**后续生命周期与异常路径验证（2026-10-03）**：用户要求继续验证。本轮保持同一现有
内核和隔离边界，模块与生产服务均未修改；新增原生 C 夹具执行真实 fork/exec/accept，
而非用 Go 的 fork+exec 代替纯 fork。夹具以 UID 2000 运行，父子与 exec 前后通过私有
SOCK_SEQPACKET 屏障同步；自身 pidfd 经 SCM_RIGHTS 交给登记者，另用 fdinfo 的内核 PID
核对该 FD 的绑定，未根据数字 PID 重新打开登记对象。

验证扩展代码提交：`6f29b413`（`experiment: verify identity carrier lifecycle boundaries`）。

最终 15 组测试通过：原有 7 组继续通过，新增 8 组如下。**“通过”指行为与实际边界一致，
不表示缺失身份的场景已有自动归属能力。**

| 新增场景 | 已验证结果 |
|---|---|
| UID / TGID 不匹配登记（各一组） | 初次 socket 不复制错误 token；修正登记后新 socket 正常，原 socket 仍保持未知 |
| 删除登记 | 旧 socket 保留创建时身份；删除后创建的 socket 为未知 |
| 迟到的登记 | 登记前 socket 不被追补重标；登记后新 socket 正常 |
| 单线程原生 fork | 子 task 不继承父 task 登记；继承的父 socket 保留父身份，新建 socket 先为未知，子进程重新登记后恢复 |
| leader 执行 exec | task 登记保留，旧、新 socket 都使用原进程实例 token；不代表可执行文件元数据会自动更新 |
| 非 leader 执行 exec | PID 与 kernel `StartNS` 均保持，但原 leader 的 TASK_STORAGE 丢失；旧 socket 保留身份，新 socket 为未知，重新登记后新建 socket 恢复 |
| 原生 accept | listener 有身份；accept child 的 SK_STORAGE 为 ENOENT。实际发送载荷被对端完整收到，TC 仍无该 child 的身份记录，证实当前不覆盖此路径 |

最终共核对 35 个创建路径 socket 的存储，34 个首次发送观察与创建快照逐字段完全一致；
剩余一个是未发送的 listener。另核对 1 个缺少身份的 accepted child，未把它算成首包
归属成功。统计为 `hook_calls=35, registered=28, unregistered=7, registration_mismatch=2`；
后者是两个明确注入的错误登记，其余存储/插入/出生时间/重复创建/cookie 错误均为 0。

首次扩展运行的所有用例已通过，但旧汇总把一次非 INET socket 的正常过滤当成错误。
补充只读地址族直方图后重跑，实测为 `AF_UNIX=1`；仍核对其总数与过滤计数完全相等，
没有静默忽略额外计数。最终 `run_result=pass`，`CLEANUP run_rc=0 cleanup_rc=0`。
`audit-log.py` 使用 Python 精确整数独立重算日志：15 组、35 个创建快照、34 个首包匹配、
19 个不同随机登记 token；fork 实际发送者与原 socket 创建者不同；非 leader exec 的
三份创建记录有相同 PID/内核 StartNS，registered 状态为 `1→0→1`，验证了缺失与补登记。

本地 Go 1.26.6 race、vet、arm64 构建通过；原生夹具以 NDK r29、`-Wall -Wextra -Werror`
构建通过。原始记录位于原型 `results/lifecycle-run0{1,2}.txt`、对应 `*-state/`、
`lifecycle-final-local-checks.txt`、`lifecycle-audit.json` 和 `lifecycle-cleanup.txt`（均不入库）。

最终 runner SHA-256 `aa778acc509701619a7400e45d15cd8ab4a3c1b910b845c1d72c347f6b0143f0`；
native helper `1d04f30c40fb94acb726c2d892db0fbae2c14771e5d2cac0b873016d63b479d9`；
BPF `9b347594bf08e3c77f7de43b3413d56b0b314b180c902fc32101f9218258e9f9`；模块哈希与上轮一致。
设备 boot ID、taint 4608、生产 PID 11765/start ticks 14670767、接口及路由检查均保持；
测试模块已卸载，原生父子进程与 Go worker 均退出；日志取回后专用手机临时目录已删除。

这些结果缩小了可用范围：可信启动登记必须覆盖新的 fork 实例及非 leader exec 的 task
替换，accept 要另行定义 listener/acceptor 的身份语义并验证克隆或新采集入口；仅用
`PID+出生时间` 判断“仍是同一个 task”在非 leader exec 上不成立。本轮未接入 AOSP/真实
App 或生产 assignment，未验证并发登记原子性、io_uring、长期内存及性能/功耗。

### 创建者存储接入现有 TC（2026-10-03，本机集成与隔离真机验证完成）

用户在确认“不需要自定义内核”的独立原型结果后，授权实施第一轮生产代码集成，
并要求提交。起初手机撤下，只做本机实现、构建及测试；随后用户重新连接手机，
本轮继续安排隔离的目标内核验收，仍保留原生产服务。
这是阶段 3 的后续改进，不增加新阶段，也不把原型实测当作本次生产集成验收。

范围：先采集创建时的 cookie、TGID、TID、UID、leader 出生时间和 comm，保存到
SK_STORAGE，再通过已有 sing-ebpf TC 的 assignment 交给 sing-box。暂不接入
TASK_STORAGE/APK token，不变更共享 UID 的包名判据，不新增 TC 挂点或常驻辅助进程。
配置默认关闭；显式启用后的采集/加载失败必须报错。旧来源保留作迁移期间的回退。

主仓库实现与验收夹具提交：`ee0208de`（`feat: integrate persistent socket creators with TC attribution`）。
依赖仓库提交：`33964031`（功能）、`74ad17e7`（BPF 比较修复）、`2354018`（真实 producer-to-TC 测试）。
本轮均为本地提交，未推送。正式 `go.mod` 的依赖版本使用对应 Git 提交生成的标准模块归档
在本地校验；其他机器拉取此版本前需先发布依赖提交。

- [x] sing-ebpf：48 字节创建者 ABI、外借 SK_STORAGE map、现有 TC 变体和 assignment 扩展。
- [x] sing-box：直接消费创建者快照，保留普通 App 快路径、proc/Manifest 解析及缺失诊断。
- [x] 持久采集器：map 与 producer link 同时保留，启动校验后复用，显式卸载与正常停止分开。
- [x] 桥接模块：增加显式全量采集开关，保留实验 TGID 过滤；严格 CRC/BTF 构建检查。
- [x] 本机：ABI、归因边界、资源所有权、加载失败和重启复用校验逻辑的测试及构建。
- [x] WSL：8 组真实 TC 数据面测试通过；创建记录通过 socket FD 合成，不代表 Android producer。
- [x] 真机隔离：真实 producer → 现有 TC 的 IPv4 TCP/UDP 首包和 TCP delivery；另通过上述 8 组合成 storage 数据面测试。
- [x] 真机隔离：活 socket、关闭期间新 socket、独立采集进程退出及重开、并发使用和显式移除。
- [ ] 真机：真实 App、IPv6 完整转发、shared 路径，以及无旧来源时的完整服务归因/回退。
- [ ] 真机：完整 sing-box 服务重启、正式部署与生产流量观察。
- [ ] 真机：仅旧方案与仅新方案的配对性能、内存和长期观察。

**已完成实现**：外借 map 的生命周期由采集器持有，TC 关闭后才释放本实例引用；正常停止
保留 map、producer link 和冻结 metadata。启动复用校验 boot ID、ABI、producer 对象哈希、
map/link/program ID、类型和实际关联，拒绝不完整或不兼容对象。维护命令
`tools socket-creator-remove` 单独移除经过校验的对象，活跃采集器持有目录共享锁时拒绝移除。
逐层使用 root ownership 与 no-follow 校验，最终目录 `0700`；root 拥有的 sticky 父目录
可接受，兼容 Android 默认 `01777` bpffs，同时拒绝可被普通用户替换的父目录与子目录。

TC 把创建者 UID 与 socket 记账 UID 分开；fchown 不改创建快照。已有有效快照保持，
cookie 变化、shared 转交会清掉旧创建者。只有当前包确实取得 full socket 且其 storage
不存在时才记“已查无记录”，避免每包重复查询；无 full socket 或无效非空记录不缓存为不存在。
用户态直接使用合法快照，仍校验 proc 出生时间和 Manifest，不把 comm、TGID 或记账 UID
当成精确包名；共享 UID 的既有证据要求保持。缺少记录时保留旧来源回退。

**本机证据**：依赖仓库功能提交 `33964031`，随后修复 `74ad17e7`。首次真实内核测试
发现 clang 将结构比较生成外部 `memcmp`，导致程序无法加载；改为显式字段比较并重新生成
大小端 BPF，新回归检查在旧对象检出 9 个未解析调用，在新对象通过。WSL 内核
`6.18.33.2-microsoft-standard-WSL2` 下 8 组真实用例全部通过：首包、首份快照保留、确认缺失、
拒绝无效 storage、五元组复用、delivery、外借 map 的正常/失败释放、错误 map 的提前拒绝。
测试在独立 netns 内运行；另通过变体隔离与宿主 C 状态转换测试。最终接口/路由前后精确相同。
首轮 dummy 驱动自动加载产生了主命名空间默认 dummy0；后续运行明确以 `numdummies=0`
预载，避免该副作用，原始首轮失败日志另行保留，未把其清理比较误报为通过。

真实 producer-to-TC 用例在依赖仓库另提交为 `2354018`；主仓库使用正式 `go.mod` 固定版本
`v0.1.0-alpha.11.0.20261003114235-74ad17e7ec35`，无提交的本地路径替换。
`protocol/ebpf`、`common/socketidentity`、`common/androidpackages`、`common/androidmanifest`、
`option` 的 race 与 vet 通过，完整 Android arm64 构建通过。模块 15/15 传统与扩展 CRC
均匹配，14 个导入覆盖，socket BTF 仍解析到真实 base ID 2886。

**目标内核实测**：重新连接的设备 `8b97939c`，内核及 base BTF 与上节相同。
新版模块以 `capture_all=1` 加载；外层使用私有 mount/net namespace 和新建 bpffs，
以 `01777` 挂载根目录验证 Android 默认权限语义，collector 子目录保持 `0700`。
第一次运行因 Toybox 的挂载传播参数没有生效而拒绝继续；换用设备 BusyBox 后，第二次
运行又因内核自动创建的默认关闭隧道接口被旧“只有 lo”断言拒绝。两次均在测试前退出，
`cleanup_rc=0`，没有把未运行用例当作通过。最终脚本检查递归私有挂载，精确允许 lo 和
默认隧道接口，要求其全部 DOWN、没有非 loopback 地址，IPv4/IPv6 所有路由表均为空。

第三次运行完整通过，结果目录 `run-20261003-200332-15455`：

- 上述 8 组真实 TC 数据面用例在 Android 上全部通过，其 storage 值由测试通过 socket FD 合成。
- 独立真实 producer 用例没有写入模拟记录：TCP 首包、UDP 首包、TCP delivery 的 3 个
  socket 在首次 send/connect 前均已有创建记录；TC assignment 的全部 48 字节与其一致。
  创建者 UID 为 0，随后 fchown 的记账 UID 为 9050，分别保持正确；path 为 `0/0/2`。
- `TestDeviceCollectorPersistence` 核对 16 个 root 创建的 IPv4/IPv6 × TCP/UDP socket：
  初次打开、所有采集器关闭期间、独立采集进程退出后、重开后各 4 个。PID/TID/UID/comm
  与现场一致，出生时间按 `/proc` USER_HZ ticks 交叉校验；早于 producer 安装的 1 个
  socket 始终无记录，未被补采。重开后原 12 个快照逐字段不变。
- map/link/program ID 始终为 `5304/583/1562`。独立进程 15741 实际打开复用后直接
  `os.Exit(0)`，由内核释放其 FD；父进程保留 socket，之后的新 socket 仍立即有创建记录。
  两个及一个采集器存活时 Remove 均为 Busy；全部关闭后显式 Remove 成功，pins 为 0。
- `PRIVATE_CLEANUP run_rc=0 cleanup_rc=0`，最终 `CLEANUP run_rc=0 cleanup_rc=0`。
  原生产进程始终为 PID 11765/start ticks 14670767；boot ID、taint 4608、原模块列表、
  接口、地址、IPv4/IPv6 路由和规则全部一致（仅规范化自然寿命倒计时）。测试模块已卸载。

全部日志与前后快照保存于 `build/socket-creator-integration/device-results/`，不入库；
外层完整输出为 `device-run0{1,2,3}.txt`，失败轮次也保留。
共取回 156 个证据文件，随后已删除本轮专用手机临时目录。独立离线审计
`device-audit.json` 用精确整数重算 16 个独立快照、29 次观察与 3 组实际传递，并逐字节
比较 14 份规范化前后状态，均通过；1 个旧 socket 未知的证据来自两处实际断言及测试 PASS，
日志没有为它单独输出一行，不将其计为新的捕获快照。
本轮没有替换生产 sing-box，没有执行真实 App 或完整服务重启；原有 TASK_STORAGE 原型
的 fork/exec/accept 结果也不被混算为这次生产 consumer 的覆盖。

最终 SHA-256：内嵌 BPF `131445b9b10ae061ea3fe84256dfbda97231f9cc7c961128e22fa8c2d5f13b20`；
模块 `754222c931ad1612fe8fc5b0c0c5d98f84ad740427eb2a1017be7f6fc4ee5530`；
完整 Android sing-box `f0ced3b8ff5fac65ef424fdef688a9f5c71349ab56b61979668ab8287f4b8904`；
采集器测试 `d944e80c1d39910e8f3e9acfaa983e7127defa61ee5efd1cd431eea8cc17912a`；
TC 测试 `bf72ffd5db1abcae82a3784a5fbe1a7019179b46e506e05f6f8694093786f46f`。

本轮尚无性能改善结论：assignment 从 40 增至 88 字节，Android 默认 8192 项仅 value
容量即增加 384 KiB，尚未包含内核分配开销；创建时 SK_STORAGE 的实测内存和长期成本待测。
已有 socket 不补采，accept child 保持未知；非 leader exec 的 task 替换边界仍按上节处理。

## 已移除的设计

不再采用此前提出的独立 TCX 采集、Java 辅助服务、正常更新时临时丢包保护与整体后端
重建，也不要求三个阶段全部结束才能交付前面已独立验证的修复。
保留不可变包表、明确未知、失败不发布空数据和必要缓存失效。

实验与原始证据仍保存在 `experimental/mainline_validation/`；其中历史研究结论是
事实记录，本文件是实施与阶段状态的唯一入口。
