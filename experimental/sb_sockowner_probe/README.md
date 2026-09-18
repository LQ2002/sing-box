# sb_sockowner_probe

把 socket cookie 映射到创建它的进程身份（UID、TGID、进程启动时间、comm）的
外部内核模块，供 sing-box 的 eBPF 数据面在连接建立时查询归属。

> 这份文档写给**没有任何对话上下文**的接手者。所有结论都标注了验证方式，
> 请重新验证而不是直接相信——其中相当一部分绑定于某一个内核构建。

## 为什么是内核模块，而不是纯 eBPF

这不是偏好，是这台设备上的两个硬约束叠加的结果。接手时请先重新验证这两条，
如果任何一条不再成立，**整个模块都可以删掉**，改回 eBPF 方案。

1. **cgroup/sock 钩子挂不上。** 真机启动实测，确切错误是：

   ```
   attach eBPF process tracker connect4 hook: create link: operation not permitted
   ```

   注意程序本身**加载是成功的**——`sing-box tools ebpf status` 里所有
   `CGroupSockAddr` 相关项全部 PASS，map 也建得出来。失败的只有
   `bpf(BPF_LINK_CREATE)` 这一步，而且是以 root 运行时被拒，所以不是权限
   不足，是内核或 SELinux 策略层面禁止把 BPF 附加到 cgroup。

   不要和另一条 sing-box 自己的检查混淆：
   `eBPF cgroup self-bypass unavailable ... process cgroup contains other
   processes` 是完全不同的检查、不同的原因。

   这正是 `common/ebpf/process_tracker.go` 里那张 `sb_proc_owner` LRU map
   在本机永远是空的原因——数据面其余部分都是好的，只是没有生产者。

2. **Android vendor hook 无法被 BPF 挂载。** `android_vh_sock_create` 之类
   用 `DECLARE_HOOK` 声明，产生的是"裸 tracepoint"，不走 `TRACE_EVENT` 宏，
   因此没有 `__bpf_trace_*` 桩、也没有 `raw_tp`/`tp_btf` 挂载所必需的
   `btf_trace_*` BTF 类型。用真机 BTF 实测：其中有 1144 个 `btf_trace_*`
   类型，而 `android_vh_*` / `android_rvh_*` 的是 **0 个**。只有内核模块能
   通过 `register_trace_<name>()` 探测它们。

   复验方法：解出真机 BTF 后，在字符串区里找 `btf_trace_android_vh_sock_create`。

模块也无法抄近路直接写 BPF map：本机内核**没有导出任何 `bpf_map_*` 符号**给
模块（只有 `bpf_prog_add/put/sub` 和 `bpf_trace_run*`）。所以数据只能经用户态
中转。好在这并不构成损失，原因见下一节。

## 它如何接入 sing-box

关键事实：**`sb_proc_owner` 这张 map 只有用户态读，TC 的 BPF 程序从不碰它。**
（`common/ebpf/native/tc.bpf.c` 里对 owner 表、uid 策略表零引用。）

唯一的消费点是 `protocol/ebpf/tc_connection.go` 的
`lookupProcessInfo(socketCookie)`，它在 Go 侧调用
`processTracker.LookupOwner(cookie)`——那是一次 `bpf(BPF_MAP_LOOKUP_ELEM)`
系统调用。

于是模块可以**直接取代那次 map 查询**，链路反而更短：

```
cgroup 可用时（本机不可用）
  socket()   → cgroup BPF 程序写 sb_proc_owner
  第一个包   → TC 记 socket_cookie
  连接建立   → 用户态 bpf() 读 map

本模块方案
  socket()   → 模块写内核内部哈希表
  第一个包   → TC 记 socket_cookie          ← 完全不变
  连接建立   → 用户态 ioctl 查模块          ← 替代那次 bpf()
```

成本对等（都是一次系统调用加一次哈希查找），但少了 BPF map 这一层中转，
也就没有生产者/消费者之间的异步间隙。

**时序是结构性保证的，不是靠时间窗赌的**：`android_vh_sock_create` 在
`socket()` 时触发，而查询发生在连接建立时，中间隔着 `connect()`/`sendto()`、
整条协议栈和 TC。写必然早于读。

### 实际的接入点

`protocol/ebpf/Inbound` 的 `processTracker` 字段已从具体类型改为接口
（见 `common/ebpf/socket_owner.go`）：

```go
type SocketOwnerSource interface {
    LookupSocketOwner(socketCookie uint64) (SocketOwner, error)
    TrackingMode() string
    Close() error
}
```

`SocketOwner` **刻意不复用** `ProcessSocketOwner`：后者是 `sb_proc_owner` 这张
BPF map 的 value 类型，长度被 `MapSpec.ValueSize=8` 和
`processTrackerInstructions` 里手写的 BPF 存取指令同时锁死，往里加字段会让
map 定义和那段指令一起失效。所以 `StartTimeNs`、`Comm` 这类额外信息放在用户态
类型里，由能提供的来源填充，cgroup 来源留零值。

`AttachSocketOwnerSource()` 负责选择来源：先试 cgroup（上游原生路径），挂不上
再试本模块，都不可用则回退用户态 procfs 搜索。取舍放在 `common/ebpf` 而非调用
方，所以**以后增删归属来源都不必再改 `protocol/ebpf`**。

这么设计的理由是上游 `testing-ebpf-tc-rewrite` 迭代很快（曾一天内落 25 个提交，
含把一个 1157 行文件拆成三个的重构）。契约窄到只有这三个方法，上游怎么重构
数据面都影响不到本模块——实测上游文件累计只动了 11 增 19 删。

**不要往 sing-box 主线类型（如 `adapter.ConnectionOwner`）里加字段**，额外信息
放本地类型，边界处再转换。

## 验证所针对的设备

```
6.12.69-android16-6-gb1493ec68d4a-abogki514973465-4k
Android (14043575, +pgo, +bolt, +lto, +mlgo, based on r536225) clang 19.0.1
```

相关内核配置（取自 `/proc/config.gz`，完整副本见 `target/kernel.config`）：

| 配置 | 值 | 影响 |
|---|---|---|
| `CONFIG_MODULE_SIG_FORCE` | 未设置 | 未签名模块可加载，不需要厂商私钥 |
| `CONFIG_LTO_NONE` | `=y` | 内核未开 LTO（工具链名里的 `+lto` 是编译器自身特性，不代表内核配置） |
| `CONFIG_CFI_CLANG` | `=y`，非 permissive | 模块必须带 KCFI 编译，Kbuild 会自动处理 |
| `CONFIG_MODVERSIONS` | `=y` | 符号 CRC 严格校验 |
| `CONFIG_GENDWARFKSYMS` | `=y` | CRC 由 DWARF 生成，对源码/配置极其敏感 |

**这个内核的源码不公开。** 真机配置里有六个选项在公开 ACK 树中根本不存在
（`MI_SCHED_EXT`、`MI_SCX_PERFETTO_TRACK`、`ANDROID_WRAPFD`、
`BLOCK_HYBRID_UFS`、`F2FS_VIP_FILE`、`ARM64_ERRATUM_4311569`），`olddefconfig`
会把它们静默丢弃。真机 BTF 里确实存在 `MI_SCX_*` 类型，证明这些补丁编进去了。
公开的 `android16-6.12.69_r00`、第三方小米 sm8850 树（6.12.23）、MiCode 官方
仓库（Android 16 世代只有 `yili-w-oss` 是 6.12 线，且为 6.12.38）都不含它们。

**所以 CRC 不可能靠重编公开源码复现——必须从真机内核镜像里提取。**

## 构建

> 宿主环境、工具链的实际安装路径与版本、以及四种产物各自用哪套编译器，
> 见 [BUILD-ENVIRONMENT.md](BUILD-ENVIRONMENT.md)。本节只讲命令。

先装 Android Clang r536225（作者用的同一个 LLVM 版本）：

```bash
mkdir -p ~/toolchains/clang-r536225 && cd ~/toolchains
curl -L --max-time 1800 -o clang-r536225.tar.gz \
  'https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/refs/heads/main/clang-r536225.tar.gz'
tar -xzf clang-r536225.tar.gz -C clang-r536225   # 该 tar 无顶层目录，必须解到指定目录
export PATH="$HOME/toolchains/clang-r536225/bin:$PATH"
```

准备与真机 sublevel 相同的 ACK 源码树（本例 6.12.69）：

```bash
git clone --depth 1 -b android16-6.12.69_r00 \
  https://android.googlesource.com/kernel/common ~/gki
adb shell su -c 'zcat /proc/config.gz' | tr -d '\r' > ~/gki-out/.config
make -C ~/gki O=~/gki-out LLVM=1 ARCH=arm64 olddefconfig modules_prepare
```

从真机 boot 分区取镜像，重建 ABI 基准，然后构建并验证：

```bash
# 设备上
su -c 'dd if=/dev/block/by-name/boot$(getprop ro.boot.slot_suffix) of=/sdcard/boot.img'

# 主机上
python refresh-kernel-abi.py /path/to/boot.img
./rebuild-and-verify.sh ~/gki-out
```

## 构建 sing-box 本体

真机验证需要带 `with_ebpf` 的 Android 构建。**必须开 CGO**，这不只是惯例：
关掉 CGO 时 `user.LookupId()` 会退回解析 `/etc/passwd`，而 Android 上根本没有
AID_* 那些系统账户，`UserName` 会是空的，`user` 路由规则随之失效；开了 CGO
才会走 bionic 的 `getpwuid`，认得 `root`、`system`、`u0_a123` 这些名字。

官方配方见 `.github/workflows/android-ebpf.yml`。在 WSL 里（Windows 上的宿主
构建会卡在 tfo-go 的 linkname 引用）：

```sh
NDK="$HOME/android-ndk-r29"
export CGO_ENABLED=1 GOOS=android GOARCH=arm64
export CC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang"

VERSION=$(CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go run ./cmd/internal/read_tag)
go build \
  -tags "with_gvisor,with_quic,with_dhcp,with_utls,with_clash_api,with_ebpf,badlinkname,tfogo_checklinkname0" \
  -trimpath \
  -ldflags "-s -w -buildid= \
    -X runtime.godebugDefault=multipathtcp=0,tlssha1=1,tlsunsafeekm=1 \
    -X github.com/sagernet/sing-box/constant.Version=${VERSION} \
    -checklinkname=0" \
  -o sing-box ./cmd/sing-box
```

`badlinkname`、`tfogo_checklinkname0` 这两个 tag 和 `-checklinkname=0` 必须同时
给：它们是让指向 runtime / net 内部符号的 `//go:linkname` 在新版 Go 上能通过
链接的前提，缺了要么链接失败，要么行为悄悄变化。

产物应当是 `for Android 35, built by NDK r29`，并链接 `libc.so` / `libdl.so` /
`liblog.so`——没有这些动态依赖说明 CGO 没生效。

## OTA 之后怎么办

每次内核更新，符号 CRC 都会变。重跑上面最后两条命令即可，**不需要改代码**。

`refresh-kernel-abi.py` 不含任何写死的偏移，靠自动发现：

- 以 `module_layout` 字符串为锚，用标识符密度筛出 `__ksymtab_strings`
- 在其前方窗口扫描 PREL32 的 `kernel_symbol` 数组，取最长等距游程
- 用字母序回退点切分 `__ksymtab` / `__ksymtab_gpl`
- **自校验**：`__kcrctab` 能容纳的 u32 个数必须等于符号数，不等就拒绝输出

如果 sublevel 变了（如 6.12.69 → 6.12.81），ACK 源码树要切到对应的
`android16-6.12.<新版本>_r00` 标签后重新 `modules_prepare`。脚本会打印真机
版本串供比对。

`rebuild-and-verify.sh` 有三道独立的闸，任何一道不过都会停下：

1. 装入权威符号表
2. 编译 `layout_probe.c`——由真机 BTF 生成的结构体布局断言。**编不过说明
   源码树的结构体偏移与真机不符，此时绝不能加载**，模块会按错误偏移访问内存
3. 逐符号核对 CRC

## 用户态 ABI

见 `sb_sockowner_probe_uapi.h`。**内核模块和用户态共用这一份**，不会漂移。

```
/dev/sb_sockowner_probe   字符设备，mode 0600 root:root（查询方必须是 root）
/proc/sb_sockowner_probe  状态快照，仅用于诊断，不要用于逐次查询

SBO_IOC_QUERY = 0xc0305301
struct sbo_query 长 48 字节：
  cookie=0 tgid=8 uid=12 start_time_ns=16 family=24 reserved=26 comm=28
```

ioctl 号编码了结构体长度，**增删字段就会变**。改动后用真实编译器重新求值，
不要手算（容易漏掉 `__u64` 的尾部对齐补位：28+16=44，实际 48）。

调用方填 `cookie`，其余由内核填充；查不到或已过宽限期返回 `-ENOENT`。

## 身份解析：用 PID，不要用 UID

`completeProcessInfo()`（`common/process/searcher.go`）对**每一个**进程无条件
执行 `PackagesByID(uid % 100000)`。这在本机是个正确性缺陷而不只是精度问题：

- MIUI 上 48 个系统应用共享 `android.uid.system`(1000)，`package_name` 规则
  因此会匹配到一大片
- 以 UID 1000 运行的**原生守护进程**（`/system/bin/netd`、
  `/vendor/bin/minetd`）也会被填上这 48 个包名，于是一条写给某个 App 的
  `package_name` 规则会把守护进程的流量一并分流走——静默误匹配

判别器是 `/proc/<pid>/exe`（现有代码读了它，但只拿去填 `ProcessPaths`，
从不用于判断）。真机实测：

```
2068   exe=/system/bin/netd            cmdline=/system/bin/netd
3130   exe=/vendor/bin/minetd          cmdline=/vendor/bin/minetd
22364  exe=/system/bin/app_process64   cmdline=com.android.settings:provider
27693  exe=/system/bin/app_process64   cmdline=com.android.settings
```

建议的解析顺序：

```
读 /proc/<pid>/exe
├─ 读不到（进程已退出）
│    → ProcessPaths = [模块记录的 comm]，PackageNames 置空
├─ base(exe) 以 "app_process" 开头  →  zygote 派生的 Android App
│    → argv0 = cmdline 读到第一个 NUL（zygote 用 NUL 填满 argv 区）
│    → PackageNames = [argv0 在 ':' 之前的部分]   ← 精确到单个包
└─ 其他  →  原生二进制
     → ProcessPaths = [exe，剥掉 " (deleted)" 后缀]
     → PackageNames 置空（它不属于任何 App）
```

`':'` 截断是必需的：`com.android.settings:provider` 是同一个 App 的子进程，
不截断的话 `package_name: [com.android.settings]` 匹配不到它，而后台联网
恰恰常发生在这类进程里。

解析结果按 `(pid, start_boottime)` 缓存。`start_boottime` 不是可有可无的元
数据——它是 **PID 复用的判据**，PID 回绕后它必然不同，缓存自动失效，不会把
新进程误认成旧 App。

热路径上最贵的是读 procfs（open+read+close），不是那次 ioctl。不要为了省
ioctl 去做事件推送，除非实测证明它确实是瓶颈。

## 已验证的内容

`cookietest/` 下的程序（`GOOS=linux GOARCH=arm64 CGO_ENABLED=0` 静态编译，
不依赖 bionic）在真机上 7/7 全过：

- IPv4/IPv6 × TCP/UDP 四种组合：`SO_COOKIE` 取得的 cookie 可反查，
  `tgid`/`uid`/`family`/`comm` 与本进程一致
- 不存在的 cookie 干净返回 `ENOENT`
- socket 关闭后立即查询仍命中（`on_free` 只打过期戳，不立即删除）
- 超过 `OWNER_GRACE`（5 秒）后条目被回收

模块可干净 `rmmod`，说明 `unregister_trace_android_vh_*` 加
`tracepoint_synchronize_unregister()` 的注销路径完整。这也是刻意**只用普通
`android_vh_*` 而不用 `android_rvh_*`** 的原因——受限钩子无法注销，装上就
卸不掉。

**socket cookie 不单调。** 内核按每 CPU 批发 4096 个再本地分配
（`include/linux/cookie.h` 的 `COOKIE_LOCAL_BATCH`）。实测后创建的 socket
可能拿到更小的号。只能当不透明键用，**不要排序、不要做区间判断、不要推断新旧**。

## 已知限制

- **`accept()` 产生的 socket 不覆盖。** 钩子在 `net/socket.c` 的
  `__sock_create()` 末尾，而 `do_accept()` 直接调 `sock_alloc()`。客户端侧
  代理场景影响很小（出站连接都经 `socket()`）。若要补，可用
  `android_vh_inet_csk_clone_lock(newsk, req)` 经 `req->rsk_listener` 从监听
  socket 继承归属——**注意那里在软中断上下文，`current` 不是 accept 的进程，
  绝不能读 `current`**。
- **记录的是创建者，不是发送者。** fd 经 `SCM_RIGHTS` 传递或 fork 后由子进程
  使用，归属会错。Android 上 App 自建 socket 是常态，可接受。
- **代为联网的守护进程。** 若 `/vendor/bin/minetd`、`DownloadManager` 之类
  替 App 中转流量，归属会指向它们。这是任何基于 socket 创建者的方案共有的
  边界。建议先观察日志中归属落在这类进程的比例再决定是否特殊处理。
- **精确包名需要 root。** Android 的 `/proc` 挂了 `hidepid`，非 root 读不到
  别的进程的 `cmdline`，此时只能退化回 UID 级精度。
- `comm` 只有 15 个有效字符，长包名会被截断，是佐证而非判据。

## 已接入 sing-box

代码侧已经打通，见同一分支的后续提交：

| 文件 | 作用 |
|---|---|
| `common/ebpf/socket_owner.go` | `SocketOwnerSource` 接口 + `AttachSocketOwnerSource()` 工厂 |
| `common/ebpf/socket_owner_module.go` | 本模块的 Go 客户端（ioctl） |
| `protocol/ebpf/socket_owner_resolve.go` | 上面那套身份解析，含 `(pid, start_boottime)` 缓存 |

上游文件累计只动了 8 增 19 删，全部集中在 `inbound.go`、`inbound_lifecycle.go`、
`tc_connection.go` 三处。

## 真机端到端已验证

在 `6.12.69-android16-6-...-4k` 上，用 CGO 构建的 Android arm64 sing-box 跑通：

```
process_tracking=module_socket_create        模块来源被选中
attachments=[wlan0(local,l2,tcx)]            TC 经 tcx 挂载
51 × match[0] package_name=[...] => direct   应用归属链路打通
18 × match[1] process_name=[netd minetd ...] 原生二进制分支打通
```

测试用 `testdata/attribution-probe.json`，退出后无 TC 残留。

同次日志里有 46 条 `dial i/o timeout`，与本模块无关：该配置把所有流量强制走
`direct`，超时目标全是需要代理才能到达的地址；国内目标的 60 条连接正常完成。

## 修复后的一天期数据

链表改为"最近被查询优先保留"之后，在设备上连续运行约一天：

```
entries 16384 / capacity 16384
created  647,492   (IPv4 560,802 + IPv6 86,690)
freed    664,759
evicted  418
```

| | 淘汰率 | 表周转时间 |
|---|---|---|
| 修复前 | 122 / 38,621 = 0.40% | 8192 / 28.7 ≈ 不到 5 分钟 |
| 修复后 53 分钟 | 14 / 37,585 = 0.037% | — |
| 修复后一天 | 418 / 647,492 = **0.065%** | 16384 / 7.5 ≈ **约 36 分钟** |

**周转 36 分钟对 UDP 会话 5 分钟超时，有 7 倍余量。** 这才是修复真正起作用的
地方——原来的失败机制是"表在会话恢复之前就翻完一遍"，淘汰率下降只是表象。

淘汰率在 53 分钟和一天两个尺度上分别是 0.037% 与 0.065%，没有随时间恶化，
说明是稳态而非累积。`entries` 恒为上限是设计如此（过期条目不主动回收），
内存被硬上限兜住。

`freed` 比 `created` 多 2.7%：模块加载之前就存在的长寿 socket 在运行期间陆续
关闭，`on_free` 会计数而当初没有 `created`。方向与量级都合理，不是问题。

## 三轮外部审查的修复，真机验证结果

八条 findings 全部属实（零误报），修复后在真机上的验证：

| 修复 | 验证方式与结果 |
|---|---|
| 位域自检（`sk_kern_sock` 字节 562 第 1 位） | 模块能 `insmod` 成功即意味着自检通过；不符会拒绝加载并打印原因 |
| `group_leader->start_boottime` | 跨进程 4 个 UID 各 64/64，`tgid`/`uid` 全部对上 |
| 发布后不再解引用 entry（释放后访问） | 25ms 内连建 3000 个 socket（125 个/毫秒）无异常 |
| `/proc/<pid>` 目录 fd（消除竞态） | 两次 sing-box 运行共 1069 次归属查询，`has been reused` 与 `open eBPF socket owner proc dir` **各 0 条** |
| fd 上限只抬不降 | `fd 上限: 524287，无需抬升`（此前会被调低到 4024） |

`has been reused` 零命中是关键证据：它同时证明了 `userHZ=100` 的假设、选
`start_boottime` 而非 `start_time`、以及取线程组组长这三件事在真机上都成立。
其中任何一环错了，这里都会大面积出现该日志，归属会集体退化成只有 comm。

**尚未被真机触发的路径**：`ownerFromCommOnly()`。查询发生在连接建立时，距
socket 创建只有微秒到毫秒，进程几乎必然还活着，所以这条回退从未走到。它的
正确性目前只有构造上的保证，没有实测。

## 压测与跨进程归属结果

`stresstest/` 在真机上的结果：

```
== 跨进程归属（子进程以不同 UID 建 socket，本进程以 root 查询）==
  PASS uid=2000   pid=20701  comm="sbo-stresstest"  报告 64 个，查到 64 个，归属不符 0 个
  PASS uid=1000   pid=20709  comm="sbo-stresstest"  报告 64 个，查到 64 个，归属不符 0 个
  PASS uid=10001  pid=20714  comm="sbo-stresstest"  报告 64 个，查到 64 个，归属不符 0 个
  PASS uid=10002  pid=20720  comm="sbo-stresstest"  报告 64 个，查到 64 个，归属不符 0 个

== 容量与淘汰（一次建 3000 个 socket）==
  压测前: entries=393  capacity=8192  evicted=0
  建立 3000 个 socket，耗时 37ms（81.1 个/毫秒）
  压测后: entries=3393 capacity=8192  evicted=0
  PASS 最新 256 个 cookie 中查不到 0 个
  ioctl 平均耗时 652ns
```

几个可以据此下结论的点：

- **跨进程归属成立。** 应用 UID 段（10001/10002）的子进程建的 socket，root
  进程能查到正确的 tgid/uid，`comm` 也是子进程自己的名字。这正是真实场景。
- **条目零丢失。** 393 → 3393，不多不少正好 +3000。旧版 `OWNER_MAX=1024`
  在同样的测试里会丢掉近 2000 个新条目。
- **ioctl 亚微秒（652ns）。** 归属链路上最贵的是读 procfs 解析包名，不是这次
  查询。不要为了省掉它去做事件推送，除非实测证明它真的是瓶颈。
- **socket 创建没被拖慢。** 每个约 12.3µs，含完整 `socket()` 系统调用和模块钩子。

淘汰路径用 `-stress 12000` 覆盖（程序会自行抬 `RLIMIT_NOFILE`，不需要手动设
`ulimit`）：

```
  压测前: entries=7083 capacity=8192 evicted=0
  建立 12000 个 socket，耗时 84ms（144.6 个/毫秒）
  压测后: entries=8192 capacity=8192 evicted=4123
  PASS 最新 256 个 cookie 中查不到 0 个
  PASS 最旧 256 个 cookie 中已被淘汰 256 个
  ioctl 平均耗时 1.118µs
```

- **严格封顶在 `OWNER_MAX`**，且淘汰方向正确：最新的一个没丢，最旧的全丢。
- 表满后 ioctl 从 652ns 升到 1.118µs。8192 条目对 4096 个桶，平均链长 2，
  符合预期，仍在微秒级。
- 计数的算法值得注意：7083 + 12000 = 19083，最终 8192，共移除 10891 条，而
  `evicted` 只有 4123。差额是过期条目——`make_room_locked()` 优先丢过期条目
  且**不计入 evicted**。这是刻意的：`evicted` 只统计被强行挤掉的**未过期**
  条目，那才是"容量不够、归属可能查不到"的信号。

## 长时间运行观察

用 `testdata/sample-counters.sh` 每 30 秒采样，在设备上做 30.4 分钟重度使用
（持续切换应用、刷内容）：

```
socket 创建   52321 个  = 28.7 个/秒（峰值区间达 124/秒）
强制淘汰      208 个    = 创建量的 0.40%
entries       全程恒为 8192（已饱和）
```

**`entries` 顶满是设计如此，不是问题。** 模块不主动回收过期条目，所以表会一直
填到上限然后停住，之后每次插入都触发一次 `make_room_locked()`。它有 52321 次
机会去找可丢的条目，其中 99.6% 在链表头部 8 条之内就找到了过期条目（不计入
`evicted`），只有 208 次没找到、不得不挤掉未过期的。

淘汰无失控迹象：59 个采样区间里 24 个增量为 0，单区间最大 24 个，全程平稳，
不随时间加速。

### 淘汰与创建量不相关

17:16:38 创建 3717 个只淘汰 6 个，17:33:39 创建 952 个却淘汰 24 个。

原因是链表按插入序排列，长寿 socket（监听 socket、持久连接）会随时间漂到头部
**结块**。一旦头部连续 `OWNER_EVICT_SCAN` 条都是长寿未过期的，接下来每次腾位置
就只能强行挤掉它们，于是出现小爆发。

### 判定为无需调整——后来被真机推翻

当时的推理是：被挤掉的是最旧的未过期条目，也就是早就建立、早就被查询过归属的
长寿 socket；sing-box 在连接建立时查询，那一刻条目还在链表尾部，离被淘汰很远。

**这个推理漏了一种情况：长寿 socket 上会反复建立新会话。**

UDP 会话默认 5 分钟超时，流量恢复时 sing-box 会用同一个 cookie 重新查一遍归属
（`NewPacketConnectionEx` → `lookupProcessInfo`）。对 TCP 而言"查过一次就不再查"
成立，对 UDP/QUIC 不成立。

真机症状：从别的应用切回 Chrome 时，该连接的 `processPath` 为空、`ProcessInfo`
整个是 nil。当时 `entries 16384/16384`（原为 8192）、`evicted 122`。

按实测 28.7 个/秒的创建速率，8192 条不到 5 分钟就翻一遍，**正好卡在 UDP 会话
超时的边界上**。而 `make_room_locked()` 从头部只扫 8 条，头部偶然聚集几个未过期
的长寿条目就会放弃寻找、直接挤掉它们——即使表里还有成千上万个过期条目可回收。

### 修复

1. **链表语义从"插入顺序"改为"最近被查询优先保留"**：`probe_ioctl()` 命中时
   `list_move_tail()`。被查询过的 cookie 正是 sing-box 关心的，让它们远离淘汰端；
   没人问的旧条目自然沉到头部。这是对症的那一项。
2. `OWNER_EVICT_SCAN` 8 → 32，更容易在头部找到过期条目而不是放弃。
3. `OWNER_MAX` 8192 → 16384，把周转时间从不到 5 分钟推到约 10 分钟，与 UDP
   会话超时拉开距离。

前两项解决机制问题，第三项只是留余量。

## 修复后的一天期数据

链表改为"最近被查询优先保留"之后，在设备上连续运行约一天：

```
entries 16384 / capacity 16384
created  647,492   (IPv4 560,802 + IPv6 86,690)
freed    664,759
evicted  418
```

| | 淘汰率 | 表周转时间 |
|---|---|---|
| 修复前 | 122 / 38,621 = 0.40% | 8192 / 28.7 ≈ 不到 5 分钟 |
| 修复后 53 分钟 | 14 / 37,585 = 0.037% | — |
| 修复后一天 | 418 / 647,492 = **0.065%** | 16384 / 7.5 ≈ **约 36 分钟** |

**周转 36 分钟对 UDP 会话 5 分钟超时，有 7 倍余量。** 这才是修复真正起作用的
地方——原来的失败机制是"表在会话恢复之前就翻完一遍"，淘汰率下降只是表象。

淘汰率在 53 分钟和一天两个尺度上分别是 0.037% 与 0.065%，没有随时间恶化，
说明是稳态而非累积。`entries` 恒为上限是设计如此（过期条目不主动回收），
内存被硬上限兜住。

`freed` 比 `created` 多 2.7%：模块加载之前就存在的长寿 socket 在运行期间陆续
关闭，`on_free` 会计数而当初没有 `created`。方向与量级都合理，不是问题。

## 三轮外部审查的修复，真机验证结果

八条 findings 全部属实（零误报），修复后在真机上的验证：

| 修复 | 验证方式与结果 |
|---|---|
| 位域自检（`sk_kern_sock` 字节 562 第 1 位） | 模块能 `insmod` 成功即意味着自检通过；不符会拒绝加载并打印原因 |
| `group_leader->start_boottime` | 跨进程 4 个 UID 各 64/64，`tgid`/`uid` 全部对上 |
| 发布后不再解引用 entry（释放后访问） | 25ms 内连建 3000 个 socket（125 个/毫秒）无异常 |
| `/proc/<pid>` 目录 fd（消除竞态） | 两次 sing-box 运行共 1069 次归属查询，`has been reused` 与 `open eBPF socket owner proc dir` **各 0 条** |
| fd 上限只抬不降 | `fd 上限: 524287，无需抬升`（此前会被调低到 4024） |

`has been reused` 零命中是关键证据：它同时证明了 `userHZ=100` 的假设、选
`start_boottime` 而非 `start_time`、以及取线程组组长这三件事在真机上都成立。
其中任何一环错了，这里都会大面积出现该日志，归属会集体退化成只有 comm。

**尚未被真机触发的路径**：`ownerFromCommOnly()`。查询发生在连接建立时，距
socket 创建只有微秒到毫秒，进程几乎必然还活着，所以这条回退从未走到。它的
正确性目前只有构造上的保证，没有实测。

## 压测与跨进程归属结果

`stresstest/` 在真机上的结果：

```
== 跨进程归属（子进程以不同 UID 建 socket，本进程以 root 查询）==
  PASS uid=2000   pid=20701  comm="sbo-stresstest"  报告 64 个，查到 64 个，归属不符 0 个
  PASS uid=1000   pid=20709  comm="sbo-stresstest"  报告 64 个，查到 64 个，归属不符 0 个
  PASS uid=10001  pid=20714  comm="sbo-stresstest"  报告 64 个，查到 64 个，归属不符 0 个
  PASS uid=10002  pid=20720  comm="sbo-stresstest"  报告 64 个，查到 64 个，归属不符 0 个

== 容量与淘汰（一次建 3000 个 socket）==
  压测前: entries=393  capacity=8192  evicted=0
  建立 3000 个 socket，耗时 37ms（81.1 个/毫秒）
  压测后: entries=3393 capacity=8192  evicted=0
  PASS 最新 256 个 cookie 中查不到 0 个
  ioctl 平均耗时 652ns
```

几个可以据此下结论的点：

- **跨进程归属成立。** 应用 UID 段（10001/10002）的子进程建的 socket，root
  进程能查到正确的 tgid/uid，`comm` 也是子进程自己的名字。这正是真实场景。
- **条目零丢失。** 393 → 3393，不多不少正好 +3000。旧版 `OWNER_MAX=1024`
  在同样的测试里会丢掉近 2000 个新条目。
- **ioctl 亚微秒（652ns）。** 归属链路上最贵的是读 procfs 解析包名，不是这次
  查询。不要为了省掉它去做事件推送，除非实测证明它真的是瓶颈。
- **socket 创建没被拖慢。** 每个约 12.3µs，含完整 `socket()` 系统调用和模块钩子。

淘汰路径用 `-stress 12000` 覆盖（程序会自行抬 `RLIMIT_NOFILE`，不需要手动设
`ulimit`）：

```
  压测前: entries=7083 capacity=8192 evicted=0
  建立 12000 个 socket，耗时 84ms（144.6 个/毫秒）
  压测后: entries=8192 capacity=8192 evicted=4123
  PASS 最新 256 个 cookie 中查不到 0 个
  PASS 最旧 256 个 cookie 中已被淘汰 256 个
  ioctl 平均耗时 1.118µs
```

- **严格封顶在 `OWNER_MAX`**，且淘汰方向正确：最新的一个没丢，最旧的全丢。
- 表满后 ioctl 从 652ns 升到 1.118µs。8192 条目对 4096 个桶，平均链长 2，
  符合预期，仍在微秒级。
- 计数的算法值得注意：7083 + 12000 = 19083，最终 8192，共移除 10891 条，而
  `evicted` 只有 4123。差额是过期条目——`make_room_locked()` 优先丢过期条目
  且**不计入 evicted**。这是刻意的：`evicted` 只统计被强行挤掉的**未过期**
  条目，那才是"容量不够、归属可能查不到"的信号。

## 长时间运行观察

用 `testdata/sample-counters.sh` 每 30 秒采样，在设备上做 30.4 分钟重度使用
（持续切换应用、刷内容）：

```
socket 创建   52321 个  = 28.7 个/秒（峰值区间达 124/秒）
强制淘汰      208 个    = 创建量的 0.40%
entries       全程恒为 8192（已饱和）
```

**`entries` 顶满是设计如此，不是问题。** 模块不主动回收过期条目，所以表会一直
填到上限然后停住，之后每次插入都触发一次 `make_room_locked()`。它有 52321 次
机会去找可丢的条目，其中 99.6% 在链表头部 8 条之内就找到了过期条目（不计入
`evicted`），只有 208 次没找到、不得不挤掉未过期的。

淘汰无失控迹象：59 个采样区间里 24 个增量为 0，单区间最大 24 个，全程平稳，
不随时间加速。

### 淘汰与创建量不相关

17:16:38 创建 3717 个只淘汰 6 个，17:33:39 创建 952 个却淘汰 24 个。

原因是链表按插入序排列，长寿 socket（监听 socket、持久连接）会随时间漂到头部
**结块**。一旦头部连续 `OWNER_EVICT_SCAN` 条都是长寿未过期的，接下来每次腾位置
就只能强行挤掉它们，于是出现小爆发。

### 为什么判定为无需调整

被挤掉的是**最旧的未过期条目**，也就是早就建立、早就被查询过归属的长寿 socket。
sing-box 在连接建立时查询，那一刻条目还在链表尾部，离被淘汰很远。所以这 208 次
淘汰几乎不会转化成实际的归属缺失。

若日后在日志里观察到归属缺失变多，按这个顺序处理：

1. 先把 `OWNER_EVICT_SCAN` 从 8 调到 32。它直接针对头部结块，仍是 O(1)，且只
   在容量路径上执行，代价极低。
2. 仍不够再考虑把 `OWNER_MAX` 从 8192 提到 16384（内存 1MB → 2MB）。它推迟
   饱和，但不解决结块本身。

在没有观察到实际归属缺失之前不要动这两个值——那属于凭感觉调参。注意 `record_create()` 目前在**持自旋锁的状态下**做 O(n)
  全表回收扫描，而 socket 创建是高频路径；`OWNER_MAX` 满时丢弃的是**新**
  条目，而新条目恰恰是马上要查的——这两处的失败模式都需要在压测后调整
- 跨进程归属未测（当前测试中创建方和查询方都是 root 本进程）
- 未做 Magisk 打包，也没有开机自启脚本。**首次验证一律手动 `insmod`**；
  在验证通过前把模块放进开机加载路径，失败就是 bootloop

## 打成 Magisk 包

```sh
./pack.sh                 # 产出 sb_sockowner_probe-magisk.zip
```

### 安全是结构性的，不靠人记得

IPSET_LKM 的 bootloop 是这套设计的反面教材：它的 `service.sh` 每次开机无条件
加载 21 个模块，而它的加载器靠改写符号绕过了 vermagic 校验——保险被绕开，内核
一升级就起不来。

所以这里有四道防线，每一道都在代码里，而不是在注意事项里：

1. **`pack.sh` 拒绝打包未通过校验的模块。** 打包前重跑符号 CRC 校验，不一致
   就退出，不产出任何文件。已用 6.12.23 的符号表做过反向测试，确认会拦住。
   缺 `target/kernel-release` 同样拒绝，因为那样就无法在开机前确认匹配。
2. **只用普通 `insmod`，绝不强制。** 它会逐个校验符号 CRC，不符就干净失败。
   这道保险是安全的来源，不是要绕开的障碍。
3. **开机前比对内核版本串。** 带 CRC 的模块在 `same_magic()` 里会跳过 vermagic
   的版本号部分，所以内核换代时 `insmod` 未必拦得住，需要这一道显式检查。
   版本串由 `refresh-kernel-abi.py` 从 boot 镜像提取并写进包里。
4. **失败绝不阻塞开机。** 加载跑在 `service.sh`（late_start），那时系统已经
   起来；脚本任何路径都 `exit 0`；连续失败 3 次自我 `touch disable`，不再徒劳
   重试。

安装时**刻意不加载**：装上就加载会把"装出的问题"和"开机出的问题"混在一起。
`customize.sh` 只做静态检查并如实报告，内核不匹配时预先禁用并告诉使用者要重编，
而不是静默中止安装让人以为什么都没发生。

### 逃生手段

开机时长按音量减进入 Magisk core-only 模式，所有模块都不加载。

### 首次安装后务必确认

```sh
cat /data/adb/modules/sb_sockowner_probe/load.log
ls -l /dev/sb_sockowner_probe
```

## 目录内容

| 文件 | 说明 |
|---|---|
| `sb_sockowner_probe.c` | 模块本体 |
| `sb_sockowner_probe_uapi.h` | 内核与用户态共用的 ABI 定义 |
| `refresh-kernel-abi.py` | 从 boot 镜像重建符号 CRC 表、BTF、布局断言、内核版本串 |
| `rebuild-and-verify.sh` | 三道闸：装 symvers、验布局、核对 CRC |
| `verify-ko.py` | 符号 CRC 校验，被上面两者与 `pack.sh` 共用 |
| `pack.sh` | 打 Magisk 包；校验不过拒绝出包 |
| `magisk/` | Magisk 包模板（`service.sh` 顶部有安全设计说明） |
| `cookietest/` | 真机端到端测试（Go，静态 arm64） |
| `preflight.sh` | 真机只读预检脚本 |
| `BUILD-ENVIRONMENT.md` | 编译环境：宿主、四套工具链、Go 版本陷阱、换机步骤 |
| `target/` | 证据与说明；大体积产物均已 gitignore，可重新生成 |
