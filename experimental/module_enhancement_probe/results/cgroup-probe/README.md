# cgroup 分工探针（2026-10-04）

问题：TC 用 `bpf_skb_cgroup_id()` 读到的 socket cgroup，能否替代模块快照、只把 cgroup 覆盖不到的情况留给模块？

方法（只读，不改生产代码）：

- `sbo-acceptance cgscan`：遍历全部进程的 `/proc/<pid>/cgroup`、uid、exe、argv0，归类为
  `own`（`…/uid_X/pid_<自己>`）、`own_uid_x`（pid 是自己、路径里的 uid 不同）、`ancestor`（在祖先进程的
  pid 目录里，fork 继承）、`other_pid`、`shared`（不在任何 pid 目录里，如根 `/`）。
- 消费端在 socket 创建时额外记下 `sk->sk_cgrp_data.cgroup->kn->id`（就是 TC 的
  `bpf_skb_cgroup_id()` = `cgroup_id(sock_cgroup_ptr(&sk->sk_cgrp_data))`，`net/core/filter.c:5005-5014`；
  64 位上等于该 cgroup 目录的 inode，`kernfs_id_ino`）和创建线程的 `bpf_get_current_cgroup_id()`；用户态
  用模块记下的创建者 pid 读 `/proc/<pid>/cgroup`、`stat` 该目录 inode 核对后归类。
- 10 分钟全机监视（`run-device.sh cgroup 600`），触发 netd、iptables、sing-box `tools synctime`，以及从
  KernelSU root shell 和 `su 10999` 各跑一次 `toybox ping`。

## 结果

**静态（`cgscan-before.log`，281 个进程）**

- App：64 个在自己的 cgroup；2 个不在：`com.xingin.xhs:widgetProvider` 及其 `zygote` 子进程，都在
  另一个进程的 `/apps/uid_10410/pid_18584` 里（App zygote 派生的进程继承父进程 cgroup）。
- 隔离进程（uid 99xxx）：5/5 在自己的 cgroup。
- 系统服务：在 `/system/uid_0/pid_N`；路径中的 uid 总是 0，真实 uid 为 1000/1001/9999 等，所以 uid
  必须取 socket 自身的 uid，不能取路径。
- **26 个进程在根 cgroup `/`**：KernelSU 的 busybox/sh、zygisk 守护进程、LSPosed（lspd）、Sui、
  keymint 模块、su shell、本探针工具——sing-box 也在这里。对它们 cgroup 不提供任何区分。
- netd 拉起的 `iptables-restore`、AVF 的 `crosvm` 等在父服务的 cgroup 里（ancestor）。

**逐 socket（`watch-cgroup.json`，10232 个 inet socket）**

- **socket 的 cgroup 与创建线程的 cgroup 10232/10232 相同**（`sk_task_differ=0`）。
- **app_process 创建的 socket：5453/5453 在创建者自己的 cgroup**（App 3761、system_server 等系统
  UID 1692）。即 TC 读到的 cgroup id 唯一对应创建该 socket 的进程实例。
- 原生程序 4779：
  - `own` 3596（netd 等 init 服务）+ `own_uid_x` 263（`/vendor/bin/qms`，pid 是自己）；
  - `ancestor` 780：`iptables` 在 netd 的 cgroup（626），App 拉起的 `/system/bin/ip` 在 App 的 cgroup（154）
    ——按“发送者”语义归到父进程，但拿不到子程序本身；
  - `shared`（根 `/`）47：sing-box（13）、KernelSU shell 里跑的 iptables（32）和 toybox（2）——cgroup 无法区分；
  - `gone` 91：比对前进程已退出（短命原生进程）。
- 同时段模块验收：0 不符、0 重复、0 丢弃，`get_file_rcu=699 fput=699`；内核日志标记后 19340 行，
  无告警；taint 4608。

## 结论

| 情况 | 交给谁 | 依据 |
|---|---|---|
| App / 系统 UID 的 app_process 进程（本轮 inet socket 的 53%） | **cgroup** | 5453/5453 在自己的 cgroup，零创建开销 |
| init 启动的原生服务（netd、qms 等） | **cgroup** | own / own_uid_x |
| 服务或 App 拉起的原生子进程（iptables、ip） | cgroup 给父进程；要子程序路径则**模块** | ancestor |
| 根 cgroup 里的进程（sing-box、KernelSU/zygisk/LSPosed、su shell 及其子进程） | **模块** | shared `/`，cgroup 无区分 |
| 计费 UID（代发流量） | cookie_tag_map（诊断/可选规则） | 此前 `experimental/cookie_tag_probe` |

注意：

1. App zygote 派生进程会落在另一个进程的 cgroup（静态 2 例，本轮无 socket），cgroup→进程名对它们会给出
   父进程的名字。这类进程的 exe 也是 app_process，模块门控同样会走“App”分支，需要额外判别（例如比对
   cgroup 的 pid 与创建者 tgid，不同则仍由模块记快照）。
2. cgroup id → 进程名在用户态解析；短命进程退出后解析不到（本轮原生 gone 91）。
3. 路径中的 uid 不可信（系统服务都写成 0）。
4. 结论针对本机这一 ROM 与内核；OTA 后需重测。
