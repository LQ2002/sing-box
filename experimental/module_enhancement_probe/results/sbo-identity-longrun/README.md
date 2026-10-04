# sbo_identity 生产链路：1 小时长跑与开销（2026-10-04/05）

`acceptance/prod-longrun.sh`：`sbo_identity.ko capture_all=1` + v3 producer（经测试 sing-box 实例的 collector）+
测试配置（direct 出站）；生产 sing-box 保持停止；全程 `/dev/kmsg` 写文件；不点亮屏幕，结束时关屏。

## 开销（`prod-longrun.sh timing`，policy0 锁频、CPU 4，模块 `timing` 参数，3 轮各约 10 万 socket）

| 路径 | 每 socket（模块进入到返回，含同步运行的 producer） |
|---|---|
| 创建者在自有 cgroup（模块跳过，不运行 BPF） | 51 / 50 / 52 ns |
| 建快照（模块 + v3 producer：argv[0] 读取与哈希、sk_storage 创建、路径表查找），缓存命中 | 774 / 787 / 762 ns |
| 未命中（每轮 1 个，进程首个 socket 的完全冷态，含 d_path） | 27–33 µs，样本过少仅供参考 |

内核日志标记后 14 行、无告警；`get_file_rcu=fput=1`；taint 4608。

## 1 小时（`long.out`、`accuracy-analysis.txt`、`native-paths.txt`）

- 23:31:45–00:31:47。模块计数：inet 27523，其中 **own_cgroup 23050（83.7%）不发事件**，建快照 4473（命中 4442、
  未命中 31）；非 inet 44619 在入口返回；too_long 2、deleted 2（场景）；error/kernel/unvalidated 0；
  `get_file_rcu=fput=31`。
- 归属 163 条，**错误 0**：带 PID 10 条与 ActivityManager 一致；多包进程判未知 3；普通 App 按 UID 52；
  netd 91；根 cgroup 客户端 6 条：`sbo-acceptance`（创建时路径）、299 字节路径的 `sbo-dial`（路径表不存，
  回退 `/proc` 得完整路径）、运行中被删除的 `sbo-dial-deleted`（原路径）。
- 内核日志持续捕获 29061 行，标记后 20717 行：**0 个内核告警**，模块栈帧 0；taint 4608。
- sing-box 测试实例 RSS 36 MB（启动）→ 17.6–28.6 MB 波动，结束 18.2 MB；file-nr 52457 → 53065（全机计数，波动于
  51593–54025）。
- 收尾：collector 已移除、模块已卸载、关屏；生产 sing-box 未启动。
