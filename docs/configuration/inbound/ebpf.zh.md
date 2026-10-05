---
icon: material/memory
---

# eBPF

!!! quote "sing-box 1.15.0 中的更改"

    eBPF 入站仍为实验功能，仅在带有 `with_ebpf` 编译标签的 Linux 和 Android
    构建中可用。

eBPF 入站将选中的本机或下游 TCP/UDP 流量透明送入 sing-box 常规路由流程，并自动
创建和清理所需的内核网络状态。它不使用[监听字段](/zh/configuration/shared/listen/)。

## 示例

使用默认 cgroup 数据面接管本机流量：

```json
{
  "type": "ebpf",
  "tag": "ebpf-in",
  "network": ["tcp", "udp"],
  "local": {
    "enabled": true,
    "data_plane": "cgroup",
    "dns_mode": "respect_policy",
    "bypass_private_address": true,
    "bypass_exclude": ["100.64.0.0/10"]
  }
}
```

还需要接管下游客户端时，加入 shared 路径并替换接口名：

```json
{
  "shared": {
    "enabled": true,
    "data_plane": "packet_rewrite",
    "interface": ["wlan1"],
    "dns_mode": "respect_policy",
    "bypass_private_address": true,
    "bypass_exclude": ["fd7a:115c:a1e0::/48"]
  }
}
```

## 数据面

| 路径 | 数据面 | 用途 |
| --- | --- | --- |
| local | `cgroup`（默认） | 在 cgroup v2 层级接管本机 socket，不跟随网络接口。 |
| local | `tc` | 在当前默认接口接管本机报文。 |
| shared | `packet_rewrite`（默认） | 在以太网帧下游接口改写报文并恢复回复。 |
| shared | `socket_assign` | 将报文分配给透明监听器，也支持 raw-IP、PPP 和隧道链路。 |

除非目标内核或链路类型需要其他路径，建议使用默认值。各路径的内核能力与接口差异
见 [eBPF 内核要求](/zh/manual/misc/ebpf-kernel-requirements/)。

## 字段

### network

启用的传输协议：`tcp`、`udp` 或两者，默认同时启用。

### udp_timeout

UDP 会话超时，默认 `5m`。为兼容旧格式，JSON 数字按秒解释；也可以使用
`30s`、`5m` 等 duration 字符串。该值不能小于 `5s`，写入内核数据面时会向上
取整到整秒。

### tc_priority

TC filter 优先级，范围 1 至 65535，默认 `1`。仅在需要与其他 filter 协调顺序时
修改。默认值允许在内核支持时使用 TCX；自定义优先级会使用 `clsact`，以保留数值
排序语义。

### fakeip_icmp

| 值 | 行为 |
| --- | --- |
| `off` | 不响应发往 FakeIP 的 ICMP Echo Request，默认值。 |
| `reply` | 对发往已配置 FakeIP 前缀且安全、未分片的请求合成本地 Echo Reply。 |

该回复只表示本机作出了响应，不反映映射目标的可达性或延迟。local `cgroup` 没有报文
hook，无法响应本机 ICMP；local `tc` 和两种 shared 数据面可响应各自路径上的请求。

## local

### local.enabled

启用本机流量接管。如果 local/shared 均未显式配置 `enabled`，默认启用 local、禁用
shared；一旦任一字段显式出现，未显式启用的路径即为禁用。

### local.data_plane

可选 `cgroup`（默认）或 `tc`。TC 路径跟随当前默认接口，cgroup 路径跟随选中的
cgroup v2 子树。

### local.cgroup_path

`cgroup` 数据面使用的绝对 cgroup v2 子树。省略时接管当前可见的 cgroup v2 根层级
及其子层级。

Android 厂商的 netd hook 可能造成挂载冲突。sing-box 优先尝试多程序挂载，只在兼容
错误下回退旧式独占挂载；设备无法安全共享根 cgroup hook 时应使用 local `tc`。

### local.socket_creator

可选的 socket 创建者采集器，默认关闭。仅用于 arm64、`local.data_plane=tc`，且不能
与平台提供的进程查询器同时启用。创建钩子、持久采集器和现有 TC 已通过目标 Android
内核上的隔离测试；真实 App 覆盖、完整服务上线和性能对比仍待验证，仍使用既有包名解析规则。

```json
{
  "local": {
    "enabled": true,
    "data_plane": "tc",
    "socket_creator": {
      "enabled": true,
      "pin_path": "/sys/fs/bpf/sing-box/socket-creator-v3"
    }
  }
}
```

`pin_path` 可省略，默认如上；必须是 bpffs 上 root 拥有、权限 `0700` 的专用绝对目录。
父目录均须属于 root；可写父目录须设置 sticky bit，兼容 Android 常见的 `01777`
bpffs 挂载目录，不接受符号链接。启用前需由管理员加载
与运行内核匹配的 `sbo_identity` 模块（`kernel/sbo_identity`），并设置 `capture_all=1`。sing-box 不会
自动加载模块或修改开关。创建者就是其 Android cgroup（`…/uid_X/pid_<pid>`）所对应进程的
socket 不建记录：TC 记录的 socket cgroup 即可定位该进程，名称与可执行文件取自 `/proc`。
其余 socket 由采集器在创建时记录 PID、线程 ID、创建者 UID、进程出生时间、截断的 comm、
argv[0] 哈希，以及内核在创建现场解析出的可执行文件路径，由现有 TC 交付；创建者退出后
路径仍可得。不会把 socket 记账 UID 或 comm 当作精确包名证据。

显式启用后的加载失败会阻止该入站启动。未采到创建记录的旧 socket、accept child 等
仍使用既有归因路径；诊断中的 `creator_snapshots`、`creator_snapshot_missing`、
`creator_snapshot_invalid`、`creator_cookie_fallbacks` 分别记录有效快照、缺失、无效和
实际回退查询。普通 App 不因此增加逐连接 `/proc` 读取。

正常停止保留创建采集挂载和存储，以继续记录服务停止期间新建的 socket；转发 TC 和
路由仍按正常流程清理。重启会核对持久对象版本和布局，不兼容时拒绝覆盖。停用配置
不会删除已持久化的采集器。需要彻底移除时，先停止所有使用该目录的 sing-box 实例，再运行：

```shell
sing-box tools socket-creator-remove --pin-path /sys/fs/bpf/sing-box/socket-creator-v3
```

该命令不卸载桥接模块。采集器仍有活跃使用者时拒绝删除；升级导致对象不兼容时应先用
旧版本命令移除旧采集器，再启动新版。移除会丢失已有 socket 的创建快照，无法事后补采。

### local.dns_mode

| 值 | 对目标端口 53 的行为 |
| --- | --- |
| `hijack` | 在 UID/包名筛选前接管。 |
| `respect_policy` | 先应用 UID/包名筛选，再接管。默认值。 |
| `off` | 绕过。 |

`hijack` 下 53 端口属于全局 DNS 控制面规则：即使 `include_uid`、
`include_package` 或其他筛选器对该 socket 的普通结果是放行，也仍会接管
DNS。上述筛选仍然作用于普通的非 DNS 流量，因此 `hijack` 不会禁用包名筛选，
也不会退化成全局接管。下面的组合是合法的：所有 socket 的 DNS 都会被接管，
其他端口只接管列出的包：

```json
{
  "dns_mode": "hijack",
  "include_package": ["org.example.browser"]
}
```

`respect_policy` 会先应用 UID/包名筛选，再处理 53 端口规则。该选项只处理已
启用的 TCP/UDP 流量，不识别 DoH 或 DoT。

### local.ipv6

启用本机 IPv6 接管，默认 `true`。

### local.bypass_private_address

绕过私有和特殊用途目标地址，默认 `true`。

### local.bypass_exclude

这些 CIDR 前缀会在所有 bypass 决策之前被强制接管，即使
`local.bypass_private_address`、`local.bypass_port` 或其他 bypass 规则本会让
它们在内核直连。内核在检查所有 bypass 之前先检查强制接管前缀。

每个地址族最多接受一个前缀（后端每地址族只保留一个强制接管前缀）。与 DNS
fake-ip 范围重叠的前缀会在启动时报错，因为 fake-ip 已占用该槽位；需要使用
`redir-host` DNS 模式才能配置 bypass_exclude。

典型用途：让 VPN/CGNAT 网段（如 Tailscale 的 `100.64.0.0/10` 及 IPv6
`fd7a:115c:a1e0::/48`）保持被接管，使 tailnet 流量能够到达 `tailscale`
出站节点，而不是被内核直连放行。

### local.bypass_rule_set

目标 IP CIDR 命中这些规则集时绕过 local 数据面，非 IP 规则会被忽略。该策略与
`shared.bypass_rule_set` 独立，并以事务方式更新所有启用的 local 后端。

### local.include_uid

需要接管的 UID。配置任一 include UID、范围或包名后，未匹配的 UID 默认绕过。

### local.include_uid_range

需要接管的 UID 范围，格式为包含两端的 `start:end`。

### local.exclude_uid

需要绕过的 UID。exclude 优先于 include。

### local.exclude_uid_range

需要绕过的 UID 范围，格式为包含两端的 `start:end`。

### local.include_android_user

需要接管的 Android 用户 ID，仅 Android。

### local.include_package

解析出的 UID 需要接管的 Android 包名，仅 Android。

### local.exclude_package

解析出的 UID 需要绕过的 Android 包名，仅 Android。无法区分共用 UID 的包，也无法
把其他系统 UID 代发的流量归属于原始包名。

### local.bypass_port

需要绕过的目标端口。FakeIP 强制接管和 DNS 模式优先于此字段，因此配置端口 53 时
会产生告警。

### local.bypass_port_range

需要绕过的目标端口范围，格式为包含两端的 `start:end`。

## shared

### shared.enabled

启用从所配置下游接口进入的流量接管。

### shared.data_plane

可选 `packet_rewrite`（默认）或 `socket_assign`。`packet_rewrite` 要求以太网帧；
raw-IP、PPP/PPPoE 和受支持的隧道链路应使用 `socket_assign`。local 与 shared 可
独立选择数据面。

### shared.dns_mode

取值与 `local.dns_mode` 相同。`respect_policy` 会先应用来源 CIDR/MAC 筛选，再
接管端口 53。

### shared.interface

==启用 shared 接管时必填==

客户端流量进入本机的下游接口，可配置多个。暂不存在的接口会重试；接口成为当前默认
上游时暂时排除，恢复下游角色后重新接管。不接受 loopback。

### shared.ipv6

启用 shared IPv6 接管，默认 `true`。此字段不会为客户端配置地址、路由器通告、转发
或上游 IPv6 路由。

### shared.bypass_private_address

绕过私有和特殊用途目标地址，默认 `true`。

### shared.bypass_exclude

与 `local.bypass_exclude` 相同，但作用于 shared 数据面：这些 CIDR 前缀会在
所有 shared bypass 决策之前被强制接管。每个地址族最多接受一个前缀，与 DNS
fake-ip 范围重叠的前缀会在启动时报错。

### shared.bypass_rule_set

目标 IP CIDR 命中这些规则集时绕过 shared 数据面，非 IP 规则会被忽略。该策略与
`local.bypass_rule_set` 独立，并以事务方式更新所有启用的 shared 后端。

### shared.include_source_cidr

需要接管的客户端来源 CIDR。当 CIDR 或 MAC include 列表任一配置时，命中任一列表的
来源即接管，均未命中时绕过。

### shared.exclude_source_cidr

需要绕过的客户端来源 CIDR。exclude 优先。

### shared.include_mac_address

需要接管的 48 位来源 MAC，仅适用于以太网帧接口。MAC 与 CIDR include 是或（OR）关系，
不是同时满足。

### shared.exclude_mac_address

需要绕过的 48 位来源 MAC，仅适用于以太网帧接口。CIDR 或 MAC 任一 exclude 命中都会
优先绕过，覆盖所有 include。

### shared.bypass_port

需要绕过的目标端口。FakeIP 与 DNS 优先级同 local。

### shared.bypass_port_range

需要绕过的目标端口范围，格式为包含两端的 `start:end`。

!!! note

    shared 模式不提供转发、NAT、DHCP、IPv6 路由器通告或热点管理，这些功能应由
    操作系统配置。

## 策略顺序

安全与服务流量绕过最先执行；随后 FakeIP 前缀强制接管；DNS 模式及 local UID/shared
来源筛选早于端口、私网地址和各自数据面的规则集绕过。顶层兼容规则集会应用到所有
已启用路径，路径级规则集策略仍彼此独立。shared 的 CIDR 与 MAC include 为或关系，
任一 exclude 命中都优先绕过。

## Android 连接归属

本机连接按 socket cookie 查询创建者的 PID、UID 和进程启动时间。只有 procfs 中的
启动时间、UID、可执行文件均通过核对，且包管理器把普通应用 UID 唯一映射到一个
未声明共享 UID 的包时，才填写用于路由的 `package_name`。

`cmdline`、`comm` 和进程启动时报告的包名不作为单次连接的包名证据。共享 UID、
隔离 UID、SDK sandbox、系统 UID，以及记录缺失或验证失败的连接，包名保持未知，
不会命中包名规则；查不到 socket 记录时也不会回退到按 UID 罗列候选包名的查询。
已有的 UID 信息仍可用于 `user_id` 规则，原生进程保留经核对的可执行文件路径。

这里的连接归属不同于 `local.include_package` / `local.exclude_package`：这两个
接管选项仍将包名解析成 UID，并作用于该 UID 的全部流量。下游设备流量不具有本机
Android 包归属。

## 诊断

- `sing-box tools ebpf status` 对所选数据面执行不挂载的内核能力和对象加载预检。
- `sing-box api ebpf` 从运行实例读取 attachment、恢复状态、活动程序、map 占用、资源、
  UDP/会话统计、分片/放行计数和失败信息。local cgroup 还会报告回退后实际使用的挂载、
  UDP 清理、socket storage 和时间源模式；需要启用
  [sing-box API 服务](/zh/configuration/service/api/)。

local TC 和 shared `socket_assign` 还会报告实际的 TCX/clsact 挂载机制、SOCKMAP/direct
listener 查找、delivery 接口、策略路由值、活动/待回收资源数量、health/reconcile 时间，
以及在受管网络切换边界递增的网络代数。

诊断响应在顶层携带 `schemaVersion`，即使当前没有运行中的 eBPF 入站也会返回。客户端
应以该字段作为整份响应的版本。

具体命令和计数解释见 [eBPF 问题排查](/zh/manual/misc/ebpf-troubleshooting/)。

## 限制

- 一个 sing-box 实例只能有一个 eBPF 入站启用 local 接管；其他 eBPF 入站必须仅启用
  shared。
- IPv4 分片和非 atomic IPv6 分片会绕过接管，因为无法取得完整传输层 tuple；IPv6
  atomic fragment 正常处理。
- 网络变化会触发 attachment 与受管状态协调，但上游连通性和热点能力仍由操作系统负责。
