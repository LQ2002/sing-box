# Android arm64 eBPF：保守包名归属构建

此产物用于替换 Android 上独立运行的 `sing-box` 可执行文件。它不是 APK，也不是
KernelSU/Magisk 模块安装包。现有 `sb_sockowner_probe` 模块的 ABI 未改动，无须因这次
修正重新编译或更换 `.ko`。

## 行为变化

- 删除从 `cmdline` / `comm` 猜包名的逻辑。仅在 procfs 身份核对通过，且包管理器确认
  普通应用 UID 唯一对应一个非共享包时填写包名。
- 共享、隔离、SDK sandbox、系统 UID 或证据不足时，包名保持未知。这些连接不会
  命中 `package_name` 规则；已有 UID 仍可用于 `user_id` 规则。
- 模块查询缺失时明确返回未知，阻止路由器用通用查询重新补入共享 UID 的候选包名。
- 缓存包含 PID、UID 和启动时间，只缓存已验证的 procfs 信息，生命周期为 1 秒。
  包名映射每次重新查询；不完整的读取不缓存。

`local.include_package` / `local.exclude_package` 仍然按 UID 控制是否接管流量，
对共享 UID 的全部流量生效。此版本未实现共享进程中逐个 APK 的连接识别。

启动时间核对受 procfs 的 10 ms 精度限制；包管理器数据更新和同 PID 的 exec 变化
也有时序边界。本次修改减少已发现的误归属路径，不构成所有生命周期竞态的形式证明。

## 产物与部署

- `sing-box`：Android arm64 / API 35 可执行文件，使用 NDK r29 和 CGO。
- `build-info.txt`：从成品读取的 Go 构建信息及功能标签。
- `build-environment.txt`：源提交、分支、构建时间及编译器版本。
- `SHA256SUMS`：文件完整性校验值。

先在解压目录执行 `sha256sum -c SHA256SUMS`，再上传到临时位置检查：

```sh
adb push sing-box /data/local/tmp/sing-box-strict-attribution
adb shell chmod 0755 /data/local/tmp/sing-box-strict-attribution
adb shell /data/local/tmp/sing-box-strict-attribution version
```

使用已有服务的停止/启动方式部署：停止服务并备份旧二进制，将新文件替换到现有
可执行文件位置，保留原权限和配置，然后重新启动。不要在旧实例运行时启动第二个
实例接管同一网络。需要回滚时停止服务、还原备份并重启。此构建不要求变更配置格式。

## 复现构建

在仓库根目录的 Linux/WSL shell 中运行；Go 版本不得低于 `go.mod` 的要求：

```sh
ANDROID_NDK_HOME=/path/to/android-ndk-r29 \
GO_BINARY=/path/to/go/bin/go \
bash release/build-android-ebpf.sh dist/android-arm64-ebpf
```

脚本从 `.github/workflows/android-ebpf.yml` 和 `release/LDFLAGS` 读取标签与链接参数，
处理 Windows CRLF，使用 `-mod=readonly`，并写出成品构建信息和校验值。
发布构建使用 CGO，以保留 bionic 的 Android 用户名解析；不能用纯 Go 诊断程序的
编译参数直接代替。
