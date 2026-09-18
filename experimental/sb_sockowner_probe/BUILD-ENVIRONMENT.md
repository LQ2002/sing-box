# 编译环境

这份文档记录**怎么把这个分支从零构建出来**：宿主环境、四种产物各自需要哪套工具
链、以及那些不写下来就一定会踩的坑。

模块本身的设计与验证见 `README.md`，这里只讲构建。

## 为什么需要单独一份

因为这个分支要产出的东西不止一个，而且**它们用的编译器互不相同，且都不能替换**：

| 产物 | 编译器 | 为什么是这个版本 |
|---|---|---|
| `sing-box` 二进制 | NDK r29 Clang 21（做 CGO 的 CC） | 上游 CI 用的就是 r29，换版本就不是同一个 ABI 基线 |
| `common/ebpf/internal/bpfgen/*.o` | NDK r29 Clang 21 | `common/ebpf/Makefile` 里**硬性校验** `clang version 21.`，不是 21 直接拒绝生成 |
| `sb_sockowner_probe.ko` | Android Clang **r536225**（19.0.1） | 必须与真机内核的编译器同版本，否则 DWARF 生成的符号 CRC 对不上，`insmod` 报 `disagrees about version of symbol module_layout` |
| `sbo-cookietest` / `sbo-stresstest` | 不需要 C 编译器 | 纯 Go，`CGO_ENABLED=0` 静态交叉编译 |

一句话：**NDK 的 Clang 21 编译不出能加载的内核模块，r536225 也编译不了 sing-box。
两套都要装。**

## 宿主

```
Windows 11 Pro                仓库在 E:\ebpf_sing-box
└─ WSL2  Debian GNU/Linux 13 (trixie)
   内核 6.18.33.2-microsoft-standard-WSL2
   仓库映射为 /mnt/e/ebpf_sing-box
```

**所有构建都在 WSL 里做，不要在 Windows 宿主上构建 sing-box。** Windows 上的构
建会卡在 `tfo-go` 对 net 内部符号的 `//go:linkname` 引用上。

工具链分散在两个用户的家目录下，这是历史原因造成的，记住就行：

| 东西 | 路径 | 属主 |
|---|---|---|
| Android Clang r536225 | `/home/likayo/toolchains/clang-r536225` | likayo |
| Android NDK r29 | `/home/likayo/android-ndk-r29` | likayo |
| Go SDK | `/home/likayo/go-sdk` | likayo |
| GOPATH | `/home/likayo/go` | likayo |
| ACK 内核源码树 | `/root/common-6.12.69` | root |
| 内核构建输出 | `/root/common-6.12.69-out` | root |

`/home/likayo/.bashrc` 已经把 `go-sdk/bin`、`go/bin`、`toolchains/clang-r536225/bin`
都加进 PATH，并设好 `GOPATH`。**内核相关的活要用 root 跑**（源码树在 `/root` 下），
其余用 likayo。

## Go 版本：go.mod 的 `go` 行是下限，不是锁

实测（2026-09-14 复核）：

```
/usr/bin/go                     go1.24.4    ← 系统包，低于 go.mod 下限，不能用
/home/likayo/go-sdk/bin/go      go1.26.7    ← PATH 里的那个
go.mod 声明                      go 1.25.5   ← 下限，且没有 toolchain 指令
E:\sing-box-ebpf-arm64 的 buildinfo   go1.25.5
```

**`go 1.25.5` 是最低要求，不会把工具链钉在 1.25.5。** `GOTOOLCHAIN` 默认 `auto`
时，Go 只在本地工具链**低于**该下限时才去下载切换；go-sdk 的 1.26.7 已经满足
1.25.5，于是直接用 1.26.7。在 Ref_sing-box 上用同一套环境实测，产出的就是
`go1.26.7`。

所以 `E:\sing-box-ebpf-arm64` 那个 go1.25.5 的产物，**不是** plain `go build` 在
当前环境下的自然结果（模块缓存里确实有
`toolchain@v0.0.1-go1.25.5.linux-amd64`，下载于 2026-09-12 16:17，产物构建于当天
20:36，但 go-sdk 自 2026-08-18 起就是 1.26.7 了）。它是被显式指定过的。

**要精确复现某个工具链，只能显式钉住：**

```sh
GOTOOLCHAIN=go1.25.5 go build ...
```

`make build` 是另一回事：根 `Makefile` 的 `build` 目标写死 `GOTOOLCHAIN=local`，
强制使用 go-sdk 本身、绝不下载。本地低于下限时它直接报错而不是自动补救。
## Debian 侧依赖（已装，列出来是为了换机时对照）

```
make 4.4.1     git 2.47.3     python3 3.13.5     zip
bison 3.8.2    flex 2.6.4     bc     openssl     rsync
libelf-dev 0.192-4            libssl-dev 3.5.7-1~deb13u2
```

`bison` / `flex` / `libelf-dev` / `libssl-dev` 是内核 `modules_prepare` 要的；
`zip` 是 `pack.sh` 打 Magisk 包要的；`python3` 跑 `refresh-kernel-abi.py` 和
`verify-ko.py`——**这两个脚本只用标准库**（`gzip io os re struct sys`），不需要
pip 装任何东西，也就不需要 venv。

## 四条流水线

### 1. sing-box 二进制

完整命令见 `README.md` 的「构建 sing-box 本体」。要点复述：

- `CGO_ENABLED=1` 是**必须**的，不是习惯问题。关掉 CGO 后 `user.LookupId()` 退回
  解析 `/etc/passwd`，而 Android 上没有 AID_* 系统账户，`user` 路由规则会失效。
- `badlinkname`、`tfogo_checklinkname0` 两个 tag 和 `-checklinkname=0` 必须同时给。
- 产物应当报 `for Android 35, built by NDK r29`，并动态链接 `libc.so` /
  `libdl.so` / `liblog.so`。**没有这些依赖说明 CGO 没生效**，回去检查 `CC`。

自检：

```sh
/home/likayo/go-sdk/bin/go version -m ./sing-box | head -3
```

`mod` 那行如果带 `+dirty` 后缀，说明构建时工作区有未提交改动——排查问题时这条很
有用，因为它意味着产物对应不上任何一个 commit。

### 2. eBPF 对象

```sh
make -C common/ebpf generate     # ANDROID_NDK_HOME 指向 r29
make -C common/ebpf check        # 重新生成并比对，确认没有陈旧产物入库
```

`generate` 开头有五道前置断言（clang / llvm-strip / llvm-objcopy 存在、UAPI 头文
件存在、**clang 主版本必须是 21**），任何一条不过就停。生成时会清空 `CPATH` 一族
环境变量，避免宿主头文件污染 BPF 目标。

生成后写 `internal/bpfgen/manifest.txt`，里面有 clang 完整版本串、bpf2go 版本和所
有源文件与产物的 sha256。**改了 `native/*.c` 就必须重跑 `generate` 并把 manifest
一起提交**，否则 `check` 会失败。

> ⚠️ `/home/likayo/regenerate-bpfgen.sh` 是早期的手写脚本，它里面 `cd` 的是
> **`/mnt/e/Ref_sing-box`**（另一个参考检出），不是本仓库。别直接跑它，用上面的
> `make -C common/ebpf generate`。

### 3. 内核模块

这是唯一需要 r536225 的地方，也是唯一有真实变砖风险的地方。

**内核源码树**（已就位，OTA 后才需要重做）：

```
/root/common-6.12.69       tag android16-6.12.69_r00, commit b18aa09ef
/root/common-6.12.69-out   已 modules_prepare，含 Module.symvers
```

源码树的 sublevel **必须**与真机内核相同。真机是 6.12.69，就得是
`android16-6.12.69_r00`；OTA 到 6.12.81 就得换 `android16-6.12.81_r00` 标签重新
`modules_prepare`。

完整流程（命令见 `README.md` 的「构建」与「OTA 之后怎么办」）：

```sh
python refresh-kernel-abi.py /path/to/boot.img   # 从真机镜像重建 ABI 基准
./rebuild-and-verify.sh /root/common-6.12.69-out # 三道闸：符号表 / 布局 / CRC
./pack.sh                                        # 打包前再校验一次 CRC
```

**为什么要从 boot 镜像提取而不是重编源码**：这台机器的内核源码不公开，真机配置里
有六个选项在公开 ACK 树里根本不存在（`MI_SCHED_EXT` 等），`olddefconfig` 会静默丢
掉它们。CRC 由 DWARF 生成，对配置极其敏感，重编公开源码得不到相同的 CRC。详见
`README.md` 的「验证所针对的设备」。

一个诚实的版本差异：本地这份 r536225 的完整版本串是

```
Android (12833971, +pgo, +bolt, +lto, +mlgo, based on r536225) clang version 19.0.1
```

而真机内核 banner 里是 `(14043575, ...)`。**构建号不同，r536225 基线和 19.0.1 版
本号相同。** 这个差异无法从上游预编译包消除，也不必消除——真正的判据是
`rebuild-and-verify.sh` 的逐符号 CRC 比对，它过了就是过了。

### 4. 测试程序

不需要任何 C 工具链，两个都是独立的 Go module（`cookietest/go.mod`、
`stresstest/go.mod`），无第三方依赖：

```sh
cd experimental/sb_sockowner_probe/cookietest
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o sbo-cookietest .
```

注意 `GOOS=linux` 而不是 `android`——它们只用 syscall，不需要 bionic。

## 换机 / 重装时的顺序

1. WSL 装 Debian 13，`apt install` 上面那串包
2. 装 Go SDK 到 `~/go-sdk`，PATH 里放它，**不要**依赖 `/usr/bin/go`
3. 装 NDK r29 到 `~/android-ndk-r29`
4. 装 Android Clang r536225 到 `~/toolchains/clang-r536225`
   （tar 包没有顶层目录，`tar -xzf ... -C clang-r536225` 必须先建目录）
5. 只有要重建内核模块时才需要第 5 步：clone ACK 对应 tag、灌入真机
   `/proc/config.gz`、`modules_prepare`

前四步装完就能构建 sing-box 和 eBPF 对象；内核模块那套是独立的，可以晚点再搭。

## 从仓库文件里读构建参数，必须剥掉 CR

这个检出是 Windows 侧 git 建立的，工作树是 **CRLF**（git 库里存的是 LF）。于是
任何"从仓库文件里读一个值"的写法，读到的末尾都带一个回车：

```sh
TAGS=$(sed -n 's/^ *BASE_TAGS: *//p' .github/workflows/android-ebpf.yml)
LDFLAGS_SHARED=$(cat release/LDFLAGS)
```

`TAGS` 的最后一个 tag 会变成 `tfogo_checklinkname0\r`——一个不存在的 tag 名，
**于是它静默地不生效**，链接照样成功，只是行为变了。`LDFLAGS` 末尾同理会得到
`-checklinkname=0\r`。这是最难发现的一类错误：没有任何报错。

正确写法是一律过一道 `tr -d '\r'`：

```sh
TAGS=$(sed -n 's/^ *BASE_TAGS: *//p' .github/workflows/android-ebpf.yml | tr -d '\r')
LDFLAGS_SHARED=$(tr -d '\r' < release/LDFLAGS)
```

复检办法：`go version -m <产物> | grep -P '\\r'`，有输出就说明还带着 CR。

另外别用 Git Bash 的 `grep -q $'\r' <文件>` 去判断行尾——实测会给出错误答案。
要确认就用 `od -c <文件> | tail`，直接看字节。

## Windows 检出 + WSL 构建：`+dirty` 是假象

同一个原因的另一个表现。Go 在版本戳里调 `git status` 判断工作树是否干净，而
WSL 侧的 git 没有设 `core.autocrlf`，会把整棵 CRLF 工作树都看成已修改——连没碰
过的 `LICENSE` 都报 17 增 17 删。于是产物的 buildinfo 恒带 `+dirty`。

```
Windows git status   干净
WSL     git status   1900+ 个文件 M
```

**这不代表有未提交的改动**，不必去"修"。真要判断工作树是否干净，用 Windows 侧
的 git 看。
## 三个真实踩过的坑

**`refresh-kernel-abi.py` 的产物不入库。** `target/Module.symvers.device`、
`layout_probe.c`、`sbo_bitfields.h`、`vmlinux.btf` 全在 `.gitignore` 里，而且是**故
意的**——它们绑定某一次内核构建，OTA 后立即失效，留在仓库里只会诱使人用陈旧的版
本去编模块。每次都从真机镜像重新生成。

**`.gitignore` 里的 `*.mod` 要锚定。** 不加前导斜杠的 `*.mod` 会把
`cookietest/go.mod` 一起吞掉。现在写的是 `/*.mod`。

**绝不强制加载模块。** 只用普通 `insmod`，不用任何绕过 vermagic / CRC 的加载器。
IPSET_LKM 的 bootloop 正是因为一个与内核不匹配的模块被塞进了开机路径。`pack.sh`
在出包前会重跑 CRC 校验，不过就拒绝出包——这条纪律靠脚本执行，不靠人记得。