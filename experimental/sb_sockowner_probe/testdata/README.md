# 真机归属链路验证

`attribution-probe.json` 用来验证这条完整链路是否打通：

```
应用 socket()  →  模块经 android_vh_sock_create 记录 cookie→身份
应用发包       →  TC 记录 socket_cookie
连接建立       →  sing-box 用 cookie 向模块 ioctl 查询
                 →  PID → /proc/<pid>/cmdline → 精确包名
                 →  package_name 规则匹配
```

## 这份配置为什么是安全的

它**刻意不改变任何路由结果**：所有出站都是 `direct`，`package_name` 和
`process_name` 规则命中之后也仍然是 `direct`。规则存在的唯一目的是让
`NeedFindProcess()` 返回真，从而启用归属查询。

所以链路是否打通只体现在日志里，不会影响设备的实际联网。

唯一有副作用的是：eBPF inbound 会在网络接口上挂载 TC 程序。sing-box 正常退出
时会自行清理；若异常中止，用 `tc qdisc show` 检查是否有残留。

## 步骤

**第一步：只读能力探测（零风险，不挂任何东西）**

```sh
su
/data/local/tmp/sing-box tools ebpf status --process-tracking
```

这只做内核能力探测，不附加到接口、不接管流量。关注输出里进程跟踪那一项——
在 cgroup 钩子被禁的内核上它应当报告不可用，这从 sing-box 自己的视角印证了
需要内核模块的前提。

**第二步：加载模块**

```sh
insmod /data/local/tmp/sb_sockowner_probe.ko
cat /proc/sb_sockowner_probe        # 确认 entries 在增长
```

**第三步：运行 sing-box 观察归属**

```sh
cd /data/local/tmp
./sing-box run -c attribution-probe.json
```

然后让配置里列出的应用产生流量（打开设置、Chrome、Play 商店均可），观察日志。

**判定标准**：日志里出现命中 `package_name` 规则的行，即证明整条链路打通。
若只看到 `process_name` 规则命中（`netd` / `minetd`），说明模块在工作但应用
侧的包名解析没走通，需要检查 `/proc/<pid>/cmdline` 是否可读。

结束时 Ctrl+C，sing-box 会清理 TC 挂载；随后 `rmmod sb_sockowner_probe`。

## 出问题时看什么

| 现象 | 含义 |
|---|---|
| 启动时报 `prepare eBPF self-bypass ... operation not permitted` | 没有以 root 运行 |
| 日志里归属全部为空 | 模块没加载，或 `/dev/sb_sockowner_probe` 权限不对 |
| 包名是一整组而非单个 | cmdline 没读到，回退到了按 UID 推断；检查是否 root |
| 原生守护进程带着包名 | 本分支的解析逻辑没生效，检查用的是不是新构建的二进制 |
| 退出后网络异常 | `tc qdisc show` 查残留，必要时 `tc qdisc del dev <iface> clsact` |
