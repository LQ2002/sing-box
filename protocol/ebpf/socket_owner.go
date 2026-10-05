//go:build with_ebpf && (linux || android)

package ebpf

import (
	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
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

	// v2 socket creator snapshot facts (creator_snapshot.go). Only the TC
	// creator source fills them; every other source leaves them zero.
	name     snapshotName
	hasName  bool
	exeInode uint64
	hasExe   bool
	// sbo_identity snapshots (socketidentity.CreatorExeKey): exeKey names the
	// creator's executable in the collector's path map, whose path the kernel
	// resolved at creation; exeFlags keeps CreatorPathTooLong,
	// CreatorExeDeleted and CreatorKernel.
	exeKey    uint64
	hasExeKey bool
	exeFlags  uint32
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

// preferSocketOwnerModule 先于 cgroup 尝试外部内核模块。
//
// 顺序按来源的**能力**排，不按"谁更轻"排。两者查一次的成本本就相当——一次
// ioctl 对一次 BPF map 查找，模块那边反而少了 map 这层中转——但能力差一截：
// cgroup 钩子只拿得到 PID 和 UID，模块还带回创建时的 start_boottime。少了启动
// 时间有两个后果，都不是小事：
//
//   - socket_owner_resolve.go 的归属缓存以 (PID, 启动时间) 为键，拿不到启动
//     时间就整个停用，于是每条新连接都要去读一次 /proc，而不是每个进程一次。
//   - PID 会回绕复用。没有启动时间就无从判别，一个新进程拿到刚退出的 App 的
//     PID 时，归属会安静地张冠李戴，而 package_name 路由规则正是按它匹配的。
//
// 历史上这个顺序是反的，原因是模块最初就是为"厂商内核禁止挂载 cgroup/sock
// 钩子"这一种情况写的后备（已确认的有小米的旧 GKI 构建）。在那些内核上 cgroup
// 必然失败，模块每次都顶班，于是"cgroup 优先"这条分支从来没有真正被执行过，
// 它缺启动时间这件事也就一直没暴露。内核升级放行 cgroup 之后，优先级的问题才
// 显出来：顶班的那个比正式的更能干。
//
// 设备节点不存在时这里什么也不做，调用方原样落回 cgroup，所以没装模块的机器
// 行为与改动前完全一致。
func preferSocketOwnerModule() (SocketOwnerSource, error) {
	module, moduleErr := OpenSocketOwnerModule()
	if moduleErr == nil && module != nil {
		return module, nil
	}
	// 这里必须返回无类型的 nil：返回带类型的 nil 指针会被装箱成非 nil 接口，
	// 调用方的判空会静默失效。
	return nil, moduleErr
}
