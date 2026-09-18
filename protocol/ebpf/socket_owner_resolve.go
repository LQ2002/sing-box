//go:build with_ebpf && (linux || android)

package ebpf

// socket 归属的用户态精化。
//
// 上游的 process.FindProcessInfoByPID() 对每一个进程都无条件执行
// PackagesByID(uid % 100000)，这在 Android 上既不精确也不正确：
//
//   - 共享 UID 的应用会被填上一整组包名。MIUI 上有 48 个系统应用共享
//     android.uid.system(1000)，于是 package_name 规则会匹配到一大片。
//   - 以系统 UID 运行的**原生二进制**（/system/bin/netd、/vendor/bin/minetd）
//     同样会被填上那 48 个包名，于是一条写给某个 App 的 package_name 规则会
//     把守护进程的流量一并分流走——静默误匹配，最难排查的一类问题。
//
// 判别依据是 /proc/<pid>/exe：zygote 派生的应用进程恒为 app_process64
// （32 位为 app_process32），此时 cmdline 才是包名；其他一律是原生二进制，
// exe 路径本身就是身份。真机实测：
//
//   2068   exe=/system/bin/netd            cmdline=/system/bin/netd
//   3130   exe=/vendor/bin/minetd          cmdline=/vendor/bin/minetd
//   22364  exe=/system/bin/app_process64   cmdline=com.android.settings:provider
//   27693  exe=/system/bin/app_process64   cmdline=com.android.settings
//
// 本文件不调用上游的 process.FindProcessInfoByPID()，而是自己读 procfs。原因
// 不是行为差异——补全用户名与按 UID 取候选包名的逻辑逐字复刻在 completeOwnerInfo
// 里，user / user_id 规则的行为不变——而是那个函数按**路径**读
// /proc/<pid>/exe，绕不开 PID 复用的竞态。这里全部读取都经同一个
// /proc/<pid> 目录 fd，见 resolveThroughProcDir 的说明。

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
	"golang.org/x/sys/unix"
)

const (
	// zygote 派生的应用进程，其 /proc/<pid>/exe 恒指向 app_process64 或
	// app_process32，这是区分应用与原生二进制的唯一可靠依据。
	zygoteExecutablePrefix = "app_process"

	// 二进制被删除或替换后，readlink 会追加这个后缀；不剥掉的话
	// process_path 规则匹配不上。
	deletedPathSuffix = " (deleted)"

	socketOwnerCacheCapacity = 1024
)

// socketOwnerCacheKey 必须同时包含 StartTimeNs：PID 会回绕复用，只用 PID 做键
// 会把新进程误认成已退出的旧应用。
type socketOwnerCacheKey struct {
	ProcessID   uint32
	StartTimeNs uint64
}

// 缓存放在包级而非 Inbound 字段上：键 (PID, 启动时间) 是全机唯一的，与哪个
// Inbound 实例无关；这样也不必为它改动上游的结构体定义。
var socketOwnerCache = sync.OnceValue(func() *freelru.Cache[socketOwnerCacheKey, *adapter.ConnectionOwner] {
	cache, err := freelru.New[socketOwnerCacheKey, *adapter.ConnectionOwner](
		socketOwnerCacheCapacity,
		maphash.NewHasher[socketOwnerCacheKey]().Hash32,
		true,
	)
	if err != nil {
		return nil
	}
	return cache
})

// resolveSocketOwner 把归属来源给出的身份解析成路由规则可用的 ConnectionOwner。
func (i *Inbound) resolveSocketOwner(ctx context.Context, owner SocketOwner) *adapter.ConnectionOwner {
	// StartTimeNs 为零说明来源提供不了它（cgroup 路径即如此），此时 PID 复用
	// 无法判别，缓存会给出错误答案，只能不缓存。
	cacheable := owner.StartTimeNs != 0
	key := socketOwnerCacheKey{ProcessID: owner.ProcessID, StartTimeNs: owner.StartTimeNs}
	cache := socketOwnerCache()
	if cacheable && cache != nil {
		if cached, loaded := cache.Get(key); loaded {
			return cached
		}
	}

	processInfo := i.resolveThroughProcDir(owner)

	if cacheable && cache != nil && processInfo != nil {
		cache.Add(key, processInfo)
	}
	// 只在缓存未命中时打，频率与上游 findProcessInfoCached 相当。
	//
	// 这条日志是必要的补偿：上游那两条 "found process path/package name" 在
	// route/process_cache.go 的 searchProcessInfo() 里，而它开头就是
	// `if ... || metadata.ProcessInfo != nil { return }`——eBPF 路径一旦提供了
	// 归属，整个函数连同日志都被跳过。以前能看到那两条，恰恰是因为 eBPF 归属
	// 返回了 nil、回退到了路由器自己的搜索。
	logResolvedOwner(ctx, i.logger, processInfo)
	return processInfo
}

// logResolvedOwner 复刻 route/process_cache.go 的输出格式与优先级，使
// eBPF 路径提供归属时的日志与回退路径保持一致。
func logResolvedOwner(ctx context.Context, logger log.ContextLogger, info *adapter.ConnectionOwner) {
	if info == nil {
		return
	}
	if len(info.ProcessPaths) > 0 {
		processPath := strings.Join(info.ProcessPaths, ", ")
		switch {
		case info.UserName != "":
			logger.InfoContext(ctx, "found process path: ", processPath, ", user: ", info.UserName)
		case info.UserId != -1:
			logger.InfoContext(ctx, "found process path: ", processPath, ", user id: ", info.UserId)
		default:
			logger.InfoContext(ctx, "found process path: ", processPath)
		}
		return
	}
	if len(info.PackageNames) > 0 {
		logger.InfoContext(ctx, "found package name: ", strings.Join(info.PackageNames, ", "))
	}
}

// resolveThroughProcDir 把对 /proc/<pid> 的全部读取绑定到同一个目录 fd 上。
//
// 分别按路径读 stat、exe、cmdline 是有竞态的：校验启动时间之后、读 exe 之前，
// 进程可能退出且 PID 被复用，于是把新进程的身份绑到了旧 socket 上。仅在读取
// 之后再校验一次只能缩小窗口，消不掉它。
//
// 目录 fd 才是正确的原语：它绑定到具体的进程实例，进程一旦退出，经它的读取
// 返回 ESRCH，**不会**被重新绑定到同 PID 的新进程。所以先开 fd、再校验启动
// 时间、再读其余内容，三者必然属于同一个进程实例。
func (i *Inbound) resolveThroughProcDir(owner SocketOwner) *adapter.ConnectionOwner {
	dir, err := os.Open(filepath.Join("/proc", strconv.FormatUint(uint64(owner.ProcessID), 10)))
	if err != nil {
		// 进程已经退出——短命进程在连接建立时 procfs 往往已经消失。
		i.logger.Trace("open eBPF socket owner proc dir: ", err)
		return ownerFromCommOnly(owner)
	}
	defer dir.Close()
	dirFD := int(dir.Fd())

	// 来源提供了启动时间才能判别 PID 复用；cgroup 来源留零值，那时只能信任 PID。
	if owner.StartTimeNs != 0 {
		raw, statErr := readFileAt(dirFD, "stat")
		if statErr != nil {
			return ownerFromCommOnly(owner)
		}
		ticks, ok := parseStartTicks(raw)
		if !ok || !startTicksMatch(ticks, owner.StartTimeNs) {
			i.logger.Trace("eBPF socket owner pid ", owner.ProcessID,
				" has been reused; falling back to comm")
			return ownerFromCommOnly(owner)
		}
	}

	info := &adapter.ConnectionOwner{
		ProcessID: owner.ProcessID,
		UserId:    int32(owner.UserID),
	}
	if executable, linkErr := readLinkAt(dirFD, "exe"); linkErr == nil {
		info.ProcessPaths = []string{executable}
	}
	completeOwnerInfo(info, i.networkManager.PackageManager())

	// cmdline 经同一个目录 fd 读出，再交给已有的分类逻辑；后者只负责判断与
	// 取舍，不再自己碰 procfs。
	cmdline, _ := readFileAt(dirFD, "cmdline")
	packageName := parsePackageName(cmdline)
	refineConnectionOwner(info, owner, func(uint32) string { return packageName })
	return info
}

// completeOwnerInfo 复刻 common/process.completeProcessInfo 的补全行为：
// 填用户名，并按 UID 填一组候选包名。后者会被 refineConnectionOwner 按进程
// 类别修正或清空，这里只负责提供原始素材。
//
// 之所以自己做而不调用上游的 FindProcessInfoByPID，是因为那个函数内部按路径
// 读 /proc/<pid>/exe，绕不开上面说的竞态。
func completeOwnerInfo(info *adapter.ConnectionOwner, packageManager tun.PackageManager) {
	if info.UserId != -1 && info.UserName == "" {
		if osUser, err := user.LookupId(strconv.FormatInt(int64(info.UserId), 10)); err == nil {
			info.UserName = osUser.Username
		}
	}
	if packageManager == nil || info.UserId == -1 {
		return
	}
	appID := uint32(info.UserId) % 100000
	var packageNames []string
	if shared, loaded := packageManager.SharedPackageByID(appID); loaded {
		packageNames = append(packageNames, shared)
	}
	if packages, loaded := packageManager.PackagesByID(appID); loaded {
		packageNames = append(packageNames, packages...)
	}
	info.PackageNames = common.Uniq(packageNames)
}

func readFileAt(dirFD int, name string) ([]byte, error) {
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	return io.ReadAll(file)
}

func readLinkAt(dirFD int, name string) (string, error) {
	buffer := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(dirFD, name, buffer)
	if err != nil {
		return "", err
	}
	return string(buffer[:n]), nil
}

// userHZ 是 /proc/<pid>/stat 第 22 个字段的时间单位。Linux 上恒为 100，
// 内核以 nsec_to_clock_t() 用它换算，见 fs/proc/array.c。
const userHZ = 100

// startTicksMatch 比对 /proc/<pid>/stat 报告的启动时间与模块记录的值。
//
// 模块记录的是线程组组长的 start_boottime，而 /proc/<pid>/stat 的第 22 个字段
// 正由同一个值换算而来：
//
//	start_time = nsec_to_clock_t(timens_add_boottime_ns(task->start_boottime))
//
// 所以两者可以直接比。注意不能改用 task->start_time——那是 monotonic 的，
// 与 procfs 报告的不是同一个时钟。
func startTicksMatch(ticks uint64, startTimeNs uint64) bool {
	expected := startTimeNs / (1_000_000_000 / userHZ)
	// 容忍 ±1 个 tick。两侧本应是同一个 u64 做同样的整数除法、结果精确相等，
	// 留这点余量是为了不因取整的边角差异把正常进程误判成 PID 复用——误判的
	// 代价是丢失归属，比放过一次复用更常见也更可惜。
	if expected > ticks {
		return expected-ticks <= 1
	}
	return ticks-expected <= 1
}

// parseStartTicks 解析 /proc/<pid>/stat 的第 22 个字段。
//
// 该文件不能按空格直接切分：第 2 个字段是括号包住的进程名，其中可以含空格
// 甚至右括号。标准做法是从**最后一个**右括号之后开始切分。
func parseStartTicks(raw []byte) (uint64, bool) {
	end := bytes.LastIndexByte(raw, ')')
	if end < 0 {
		return 0, false
	}
	// 切分后的第一项是 state，也就是 stat 的第 3 个字段，
	// 因此第 22 个字段位于下标 22-3 = 19。
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 {
		return 0, false
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, false
	}
	return ticks, true
}

// ownerFromCommOnly 在无法信任 procfs 时给出仅凭模块记录能确定的身份。
//
// UID 和 PID 是模块在 socket() 那一刻记下的，权威可信；包名无从确定，
// 因为确定它必须读 procfs。
func ownerFromCommOnly(owner SocketOwner) *adapter.ConnectionOwner {
	info := &adapter.ConnectionOwner{
		ProcessID: owner.ProcessID,
		UserId:    int32(owner.UserID),
	}
	if owner.Comm != "" {
		info.ProcessPaths = []string{owner.Comm}
	}
	if osUser, err := user.LookupId(strconv.FormatUint(uint64(owner.UserID), 10)); err == nil {
		info.UserName = osUser.Username
	}
	return info
}

// refineConnectionOwner 按进程类别修正 FindProcessInfoByPID 的结果。
//
// lookupPackage 以参数注入，便于测试时替换掉真实的 procfs 读取。
func refineConnectionOwner(
	info *adapter.ConnectionOwner,
	owner SocketOwner,
	lookupPackage func(processID uint32) string,
) {
	if info == nil {
		return
	}

	executable := ""
	if len(info.ProcessPaths) > 0 {
		executable = strings.TrimSuffix(info.ProcessPaths[0], deletedPathSuffix)
	}

	switch {
	case executable == "":
		// procfs 读不到，进程已退出。模块在 socket() 时抓的 comm 是唯一幸存的
		// 线索——那一刻创建者必然还活着。它被截断到 15 字符，所以只作为
		// process_name 的兜底，不足以确定包名。
		info.ProcessPaths = nil
		info.PackageNames = nil
		if owner.Comm != "" {
			info.ProcessPaths = []string{owner.Comm}
		}

	case strings.HasPrefix(filepath.Base(executable), zygoteExecutablePrefix):
		// zygote 派生的应用：cmdline 即包名，精确到单个，取代按 UID 得到的一组。
		//
		// 刻意**不填 ProcessPaths**。对应用来说 /proc/<pid>/exe 恒为
		// app_process64，那是 zygote 的路径而不是这个应用的，零区分度。而且
		// 上游的展示与日志逻辑都是"路径优先、包名兜底"——
		// clashapi/connections.go:64 与 route/process_cache.go:54 都如此——
		// 填了它反而会把真正有用的包名挤掉，面板上人人都是 app_process64。
		//
		// 代价：process_name 与 process_path_regex 规则对应用不再匹配。但它们
		// 此前能匹配到的也只有 app_process64，本就等于没用；process_path 规则
		// 在 Android 上有回退到包名的分支（rule_item_process_path.go:37），不受影响。
		info.ProcessPaths = nil
		if packageName := lookupPackage(owner.ProcessID); packageName != "" {
			info.PackageNames = []string{packageName}
		} else if len(info.PackageNames) == 0 && owner.Comm != "" {
			// cmdline 读不到（进程刚退出，或无权限）时退回 comm；再不济就保留
			// FindProcessInfoByPID 按 UID 得到的那一组，总比没有强。
			info.PackageNames = []string{owner.Comm}
		}

	default:
		// 原生二进制：exe 路径就是身份，它不属于任何应用包。
		// 清空按 UID 推出的包名，避免 package_name 规则误匹配到守护进程。
		info.ProcessPaths = []string{executable}
		info.PackageNames = nil
	}
}

// parsePackageName 从 /proc/<pid>/cmdline 的内容取出应用包名。
//
// 两个必须处理的细节，均经真机验证：
//   - zygote 用 NUL 把 argv 区填满，所以只能取到第一个 NUL 为止；整块读会把
//     填充或后续参数一起带进来。
//   - 子进程的 cmdline 形如 "com.android.settings:provider"，必须在 ':' 处
//     截断，否则 package_name: [com.android.settings] 匹配不到它，而后台联网
//     恰恰常发生在这类进程里。
func parsePackageName(raw []byte) string {
	argv0, _, _ := bytes.Cut(raw, []byte{0})
	name := string(argv0)
	if index := strings.IndexByte(name, ':'); index > 0 {
		name = name[:index]
	}
	// 原生二进制走不到这里，但 cmdline 仍可能是带路径的命令行；包名不含 '/'。
	if strings.ContainsRune(name, '/') {
		return ""
	}
	return name
}
