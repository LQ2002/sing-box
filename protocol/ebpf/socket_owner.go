//go:build with_ebpf && (linux || android)

package ebpf

import (
	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

// 本文件是 socket 归属来源的抽象层。数据面拿到 socket cookie 之后，需要知道
// 是哪个进程创建了这个 socket；提供这个答案的组件在不同内核上不同：
//
//   - cgroup/sock 钩子（sing-ebpf 的 ProcessTracker）：常规路径，把归属写进
//     sb_proc_owner 这张 BPF map，用户态再读出来。
//   - 外部内核模块：某些厂商内核（例如部分小米 GKI 构建）禁止挂载 cgroup 钩子，
//     且 Android vendor hook 不是可被 BPF 挂载的 tracepoint，此时只能由内核
//     模块经 android_vh_sock_create 采集，用户态通过它自己的字符设备查询。
//
// 数据面只依赖下面这个接口，因此新增归属来源不需要改动调用点。

// SocketOwner 是归属查询的结果。
//
// 它刻意不是 commonEBPF.ProcessSocketOwner：后者是 sb_proc_owner 这张 BPF map
// 的 value 类型，长度被 map 定义和手写的 BPF 存取指令锁死在 8 字节，往里加字段
// 会同时破坏两者。它还属于上游的外部模块 github.com/CHIZI-0618/sing-ebpf，本地
// 根本改不了。所以额外信息放在这个本地类型里。
type SocketOwner struct {
	ProcessID uint32
	UserID    uint32

	// StartTimeNs 是创建者进程的 start_boottime。它的用途不只是元数据：
	// PID 会回绕复用，(ProcessID, StartTimeNs) 组合才能唯一确定一个进程，
	// 因此上层按包名解析的缓存必须以这个组合为键，否则会把新进程误认成
	// 已退出的旧 App。
	//
	// 只有能提供它的来源才会填；cgroup 来源留零，上层需容忍。
	StartTimeNs uint64

	// Comm 是创建 socket 时抓取的进程名（内核 TASK_COMM_LEN 截断到 15 字符）。
	//
	// 价值在于时机：它是在 socket() 时记录的，那一刻创建者必然还活着。而归属
	// 查询发生在连接建立时，短命进程到那时 /proc/<pid> 已经消失，procfs 什么
	// 都读不到，这是唯一幸存的线索。
	//
	// 因为被截断，长包名会不完整，所以它是佐证和兜底，不能当作判据。
	// 只有能提供它的来源才会填；cgroup 来源留空。
	Comm string
}

// SocketOwnerSource 是数据面查询 socket 归属所依赖的全部契约。
//
// 刻意保持窄：上游 eBPF 数据面迭代很快（一次强推就把整个 common/ebpf 搬成了
// 外部模块，并把数据面重排成三个提交），把依赖收敛到这几个方法，上游怎么重构
// 都不会波及具体的归属实现。
//
// IsClosed 不是本地需求，而是上游 closeProcessTrackerOwner() 的既有契约：
// 关闭失败时它靠这个判断资源是否真的释放、要不要保留句柄重试。归属来源顶替了
// 那个位置，就必须继续满足它。
type SocketOwnerSource interface {
	// LookupSocketOwner 按 socket cookie 查询归属。查不到时返回错误。
	LookupSocketOwner(socketCookie uint64) (SocketOwner, error)

	// TrackingMode 返回用于日志和诊断的来源标识。由来源自己给出，避免调用方
	// 硬编码某一种实现的名字。
	TrackingMode() string

	// IsClosed 报告底层内核资源是否已经释放。
	IsClosed() bool

	// Close 释放该来源持有的内核资源。
	Close() error
}

// cgroupSocketOwnerSource 把上游的 *commonEBPF.ProcessTracker 适配成
// SocketOwnerSource。
//
// 用包装而不是给 ProcessTracker 直接加方法，是因为它现在属于外部模块
// github.com/CHIZI-0618/sing-ebpf，Go 不允许为外部类型定义方法。
type cgroupSocketOwnerSource struct {
	tracker *commonEBPF.ProcessTracker
}

var _ SocketOwnerSource = cgroupSocketOwnerSource{}

// LookupSocketOwner 让 cgroup 追踪器满足 SocketOwnerSource。
//
// cgroup 钩子只能拿到 PID 和 UID，所以 StartTimeNs 和 Comm 留零值——这是
// 来源能力的差异，不是错误，上层必须容忍它们缺失。
func (s cgroupSocketOwnerSource) LookupSocketOwner(socketCookie uint64) (SocketOwner, error) {
	owner, err := s.tracker.LookupOwner(socketCookie)
	if err != nil {
		return SocketOwner{}, err
	}
	return SocketOwner{
		ProcessID: owner.ProcessID,
		UserID:    owner.UserID,
	}, nil
}

// TrackingMode 区分 owner 表项是靠 sock_release 钩子即时清理，还是只能依赖
// map 的 LRU 淘汰——后者发生在 sock_release 挂不上的内核上，表项会滞留更久。
func (s cgroupSocketOwnerSource) TrackingMode() string {
	if s.tracker == nil {
		return "off"
	}
	if s.tracker.ReleaseCleanup() {
		return "cgroup_socket_release"
	}
	return "cgroup_socket_lru"
}

func (s cgroupSocketOwnerSource) IsClosed() bool {
	if s.tracker == nil {
		return true
	}
	return s.tracker.IsClosed()
}

func (s cgroupSocketOwnerSource) Close() error {
	if s.tracker == nil {
		return nil
	}
	return s.tracker.Close()
}

// attachSocketOwnerFallback 在 cgroup 钩子挂不上时挑选替代的归属来源。
//
// 只在**软失败**时调用，即 AttachProcessTracker 返回 (nil, err)：那种情况下
// 内核里没有留下任何半挂载的资源，回退是安全的。硬失败（返回了非 nil 的半成品
// 追踪器）仍由上游的 rollback 路径处理，本函数不介入——那条路径的语义属于上游，
// 在这里复刻一份只会平白增加耦合。
//
// 把"用哪个替代来源"的取舍收在这里而不是散在生命周期代码里，是为了让数据面
// 只认 SocketOwnerSource 一个契约：以后增删归属来源都不必改动调用点。
func attachSocketOwnerFallback(cgroupErr error) (SocketOwnerSource, error) {
	module, moduleErr := OpenSocketOwnerModule()
	if moduleErr == nil && module != nil {
		return module, nil
	}
	// 这里必须返回无类型的 nil：返回带类型的 nil 指针会被装箱成非 nil 接口，
	// 调用方的判空会静默失效。
	return nil, E.Errors(cgroupErr, moduleErr)
}
