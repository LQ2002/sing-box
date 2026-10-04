# 第 2 阶段：路径表优化后的验收（2026-10-04）

改动（`bpf/consumer.bpf.c`）：每个 socket 的快照从 320 字节缩为 64 字节（与生产 creator 快照同大小），
不再逐 socket 复制 256 字节路径；路径按 `(dev, ino, generation)` 存在 `paths`（LRU_HASH，1024 项）里，
已有则只做一次查表。模块未改。验收工具读快照后按同一键查路径，模拟生产读者。

`run-device.sh` 同时补了上一轮的两个缺口：

- 运行期间把 `/dev/kmsg` 持续写入文件，按标记行之后检查（上一轮 1 小时后环形缓冲区已被冲掉）；
- 仿 `/data/app/~~…==/<包名>-…==/lib/arm64/<名>.so` 的 156 字节路径，用 App UID（10999）运行并建 socket。

bench 每个周期的顺序改为 未加载 → 已加载未采集 → 采集中，避免“未采集”紧接在消费端退出之后测量。

## quick（`quick.log`，全部通过）

- 自测 8000/8000、超长路径 800/800、已删除 800/800、accept 继承 200/200（×3）、unix socket 无快照。
- App UID 原生程序：20 个 socket，uid=10999，路径 156 字节，与 `/proc/<pid>/exe` 一致。
- 全机 watch：11165 个事件 0 不符、0 重复、0 丢弃；`path_insert=9`（11165 个事件只写入 9 次路径）。
- `get_file_rcu=42 fput=42`；内核日志捕获 9973 行，标记后 1216 行，无 WARNING/BUG/Oops；taint 4608。

## 离线 bench + 1 小时（进行中）

19:32:50 启动 `offline.sh`，结果在设备 `/data/local/tmp/sboacc/report/`。
