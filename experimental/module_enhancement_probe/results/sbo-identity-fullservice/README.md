# sbo_identity 模块整链路验收（2026-10-04）

构建：`kernel/sbo_identity/build.sh`（模块，WSL root）、`common/socketidentity/build-bpf.sh`（producer）、
`release/build-android-ebpf.sh`（sing-box，仓库 Android 设置）。设备内核 BTF sha256 `37d2c7e7…5f35` 与构建基准一致。

1. `sbo-acceptance producercheck`（生产 producer 对象 + `insmod sbo_identity.ko capture_all=1`）：校验器接受
   （305 条指令）；根 cgroup 200/200、`pid_<他人>` 200/200 有快照，且每个都带 argv[0] 哈希与 exe key，
   路径表中的路径等于 `/proc/self/exe`；`pid_<自己>` 0/200（模块跳过，`own_cgroup` 计数）；`get_file_rcu=2 fput=2`。
2. 整服务准确性（`fullservice.sh accuracy 150`，测试配置只有 direct 出站，生产 sing-box 保持停止；冷启动
   Chrome、微信、手机管家、哔哩哔哩；dumpsys 为真值，`accuracy-analysis.txt`）：45 条归属，**错误 0**；
   带 PID 的 5 条与 ActivityManager 一致；netd 21 条；普通 App 17 条；system_server 判未知 1 条。
   模块计数：inet 5815，其中 **own_cgroup 4427（76%）不发事件**，其余命中缓存 1366、未命中 22；
   非 inet socket 10913 个在入口直接返回；`get_file_rcu=22 fput=22`。
3. 根 cgroup 的原生程序（KernelSU root shell 中运行复制出的 toybox `nc`，经测试实例代理）：4 个连接均归为
   `process path: /data/local/tmp/sbo-full/nc, user: root`，PID 正确。
4. 收尾：collector 已移除、模块已卸载、关屏、taint 4608；生产 sing-box 未启动。
