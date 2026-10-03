# Android 归属与包表更新：执行计划

这是本任务唯一的执行检查表。执行前读本文件，执行后在同一处更新状态、证据和未完成项。
不另建平行方案，不把源码推断或探针结果写成生产功能已经完成。

## 仓库与范围

- 主实施仓库：`E:\ebpf_sing-box`。
- 依赖改动：已有 `E:\sing-ebpf` / `LQ2002/sing-ebpf`，允许在这个已有 fork 中增加所需能力。
- 移植目标：`E:\Ref_sing-box`。当前不修改该目录；保留清晰提交边界及依赖提交，便于移植。
- 不新增 sing-tun、sing、fswatch 等 fork；不提交指向本机目录的 go.mod replace。
- 不新增独立 TC/TCX 采集程序、Java/app_process 常驻辅助程序、临时丢包保护程序，
  也不为正常包表更新设计整套后端拆除/重建机制。
- 只有三个阶段，依次执行，各自具备独立价值和验收标准。前一阶段未通过，不扩大到下一阶段。
  如果用户只要求某一阶段，就完成该阶段；若授权执行全计划，按顺序继续，不逐阶段重复索要确认。

## 当前进度

| 阶段 | 交付内容 | 状态 | 代码提交 / 验收证据 |
|---|---|---|---|
| 1 | 修复包表刷新与查询一致性 | **已完成**（本地测试与真机验收均通过） | 代码 `35624e63`；记录见“阶段 1 实施记录” |
| 2 | 已有 sing-ebpf fork 的 UID 热更新与归属字段 | **已完成**（本地、真机与真实 App 验收均通过） | sing-ebpf `3c1b28f`（已推送）；应用依赖 `6252b171`；记录见“阶段 2 实施记录” |
| 3 | sing-box 接入新归属路径并完成整链路验收 | **归属修复与本轮补充验收完成；完整验收仍有未执行项** | 修复 `cae57485`；实际数据面证据与剩余项见阶段 3 |

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

## 已移除的设计

不再采用此前提出的独立 TCX 采集、Java 辅助服务、正常更新时临时丢包保护与整体后端
重建，也不要求三个阶段全部结束才能交付前面已独立验证的修复。
保留不可变包表、明确未知、失败不发布空数据和必要缓存失效。

实验与原始证据仍保存在 `experimental/mainline_validation/`；其中历史研究结论是
事实记录，本文件是实施与阶段状态的唯一入口。
