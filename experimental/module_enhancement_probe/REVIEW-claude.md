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
