//go:build with_ebpf && (linux || android)

package ebpf

// SocketOwnerSource 的外部内核模块实现，对应 experimental/sb_sockowner_probe。
//
// 为什么需要它：某些厂商内核（已确认的有部分小米 GKI 构建）禁止挂载
// cgroup/sock 钩子，于是 sb_proc_owner 这张 BPF map 永远没有生产者。而
// Android 的 vendor hook 用 DECLARE_HOOK 声明，产生的是裸 tracepoint，不走
// TRACE_EVENT 宏，因此没有 raw_tp/tp_btf 挂载所需的 btf_trace_* 类型——BPF
// 挂不上去，只有内核模块能用 register_trace_android_vh_sock_create() 探测。
// 该模块也无法直接写 BPF map（这类内核不向模块导出任何 bpf_map_* 符号），
// 所以它自建哈希表，经字符设备对外提供查询。
//
// 这并不比 cgroup 路径慢：sb_proc_owner 只有用户态读（TC 的 BPF 程序从不碰
// 它），原本那次读也是一次 bpf(BPF_MAP_LOOKUP_ELEM) 系统调用，现在换成一次
// ioctl，成本相同，反而少了 BPF map 这层中转。
//
// 时序由结构保证而非靠时间窗：模块在 socket() 时记录，查询发生在连接建立时，
// 中间隔着 connect()/sendto()、整条协议栈和 TC，写必然早于读。

import (
	"os"
	"sync"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/unix"
)

// 与 experimental/sb_sockowner_probe/sb_sockowner_probe_uapi.h 保持一致。
const (
	socketOwnerModuleDevice = "/dev/sb_sockowner_probe"

	// _IOWR('S', 0x01, struct sbo_query)。这个数值编码了 sizeof(struct
	// sbo_query)，所以模块那边增删字段它就会变，用真实编译器求值得到，不要
	// 手算（容易漏掉 __u64 造成的尾部对齐补位：28+16=44，实际 48）。
	//
	// 这同时是一道安全网：若加载的模块与本文件的结构体定义不一致，ioctl 号
	// 对不上，模块会直接返回 EINVAL，而不是按错误布局解析出垃圾数据。
	socketOwnerModuleIoctlQuery = 0xc0305301

	// 等于内核的 TASK_COMM_LEN。
	socketOwnerModuleCommLen = 16
)

// sboQuery 必须与模块中的 struct sbo_query 二进制一致：
// cookie@0 tgid@8 uid@12 start_time_ns@16 family@24 reserved@26 comm@28，共 48 字节。
type sboQuery struct {
	Cookie      uint64
	TGID        int32
	UID         uint32
	StartTimeNs uint64
	Family      uint16
	Reserved    uint16
	Comm        [socketOwnerModuleCommLen]byte
}

// 布局一旦漂移，取回的字段就全是错位的垃圾，所以在编译期钉死总长为 48。
var _ [1]struct{} = [unsafe.Sizeof(sboQuery{}) - 47]struct{}{}

// SocketOwnerModule 通过 sb_sockowner_probe 的字符设备查询归属。
//
// access 保护的只是 file 这个字段本身，不是 ioctl：查询持读锁，Close 持写锁。
// 需要它是因为 Close 会把 file 置空，而归属查询可能正在另一个 goroutine 里读
// 同一个字段——上游的生命周期代码允许在数据面仍在跑的时候关闭归属来源。
// ioctl 本身仍然是并发的，读锁不会把查询串行化。
type SocketOwnerModule struct {
	access sync.RWMutex
	file   *os.File
}

var _ SocketOwnerSource = (*SocketOwnerModule)(nil)

// OpenSocketOwnerModule 打开模块的字符设备。
//
// 设备节点是 mode 0600 root:root，所以进程必须以 root 运行；非 root 会得到
// 权限错误，调用方据此回退到其他归属来源。
func OpenSocketOwnerModule() (*SocketOwnerModule, error) {
	file, err := os.OpenFile(socketOwnerModuleDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, E.Cause(err, "open socket owner module device")
	}
	return &SocketOwnerModule{file: file}, nil
}

// LookupSocketOwner 按 socket cookie 查询创建者身份。
//
// 查不到、或条目已过模块内的宽限期，返回的错误会包装 ENOENT。
func (m *SocketOwnerModule) LookupSocketOwner(socketCookie uint64) (SocketOwner, error) {
	if m == nil {
		return SocketOwner{}, E.New("socket owner module is not open")
	}
	m.access.RLock()
	defer m.access.RUnlock()
	if m.file == nil {
		return SocketOwner{}, E.New("socket owner module is not open")
	}
	// 每次调用各自持有栈上的 query，同一个 fd 上的并发 ioctl 互不影响：
	// 这个设备没有文件位置概念，模块侧也是逐次 copy_from_user/copy_to_user。
	query := sboQuery{Cookie: socketCookie}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL,
		m.file.Fd(),
		uintptr(socketOwnerModuleIoctlQuery),
		uintptr(unsafe.Pointer(&query)),
	)
	if errno != 0 {
		return SocketOwner{}, E.Cause(errno, "query socket owner module")
	}
	return SocketOwner{
		ProcessID:   uint32(query.TGID),
		UserID:      query.UID,
		StartTimeNs: query.StartTimeNs,
		Comm:        socketOwnerModuleComm(query.Comm),
	}, nil
}

// TrackingMode 报告归属来自内核模块的 socket 创建钩子，以便与 cgroup 路径
// 在日志和诊断里区分开。
func (m *SocketOwnerModule) TrackingMode() string {
	return "module_socket_create"
}

// IsClosed 报告字符设备是否已经关闭。上游的 closeProcessTrackerOwner() 用它
// 判断关闭是否真的生效：没生效就保留句柄，留待后续重试。
func (m *SocketOwnerModule) IsClosed() bool {
	if m == nil {
		return true
	}
	m.access.RLock()
	defer m.access.RUnlock()
	return m.file == nil
}

func (m *SocketOwnerModule) Close() error {
	if m == nil {
		return nil
	}
	m.access.Lock()
	defer m.access.Unlock()
	if m.file == nil {
		return nil
	}
	err := m.file.Close()
	m.file = nil
	return err
}

// socketOwnerModuleComm 取到第一个 NUL 为止：内核侧是定长数组，尾部是填充。
func socketOwnerModuleComm(raw [socketOwnerModuleCommLen]byte) string {
	for index, value := range raw {
		if value == 0 {
			return string(raw[:index])
		}
	}
	return string(raw[:])
}
