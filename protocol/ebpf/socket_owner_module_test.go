//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"
	"unsafe"
)

// TestSBOQueryABI 钉死 Go 结构体与内核模块 struct sbo_query 的二进制布局。
//
// 这里是最容易静默漂移的地方：字段顺序或类型一旦改动，ioctl 仍然会成功，但
// 取回的 pid/uid 全是错位的垃圾，而且看起来像是"归属查错了"，极难定位。
//
// 期望值来自 experimental/sb_sockowner_probe/sb_sockowner_probe_uapi.h，
// 并用真实编译器实测过，不是推算。
func TestSBOQueryABI(t *testing.T) {
	t.Parallel()

	if got, want := unsafe.Sizeof(sboQuery{}), uintptr(48); got != want {
		t.Fatalf("sizeof(sboQuery) = %d, want %d（ioctl 号编码了该长度，"+
			"变了必须同步更新 socketOwnerModuleIoctlQuery）", got, want)
	}

	var query sboQuery
	for _, testCase := range []struct {
		name   string
		offset uintptr
		want   uintptr
	}{
		{"cookie", unsafe.Offsetof(query.Cookie), 0},
		{"tgid", unsafe.Offsetof(query.TGID), 8},
		{"uid", unsafe.Offsetof(query.UID), 12},
		{"start_time_ns", unsafe.Offsetof(query.StartTimeNs), 16},
		{"family", unsafe.Offsetof(query.Family), 24},
		{"reserved", unsafe.Offsetof(query.Reserved), 26},
		{"comm", unsafe.Offsetof(query.Comm), 28},
	} {
		if testCase.offset != testCase.want {
			t.Errorf("offsetof(%s) = %d, want %d", testCase.name, testCase.offset, testCase.want)
		}
	}
}

// TestSocketOwnerModuleIoctlNumber 复核 ioctl 号与结构体长度一致。
//
// _IOWR(type, nr, size) 的编码是 dir<<30 | size<<16 | type<<8 | nr。
// 若有人改了结构体却忘了更新常量，这里会先于真机失败。
func TestSocketOwnerModuleIoctlNumber(t *testing.T) {
	t.Parallel()

	const (
		directionReadWrite = 3
		magic              = 'S'
		number             = 0x01
	)
	want := uintptr(directionReadWrite)<<30 |
		unsafe.Sizeof(sboQuery{})<<16 |
		uintptr(magic)<<8 |
		uintptr(number)
	if got := uintptr(socketOwnerModuleIoctlQuery); got != want {
		t.Fatalf("socketOwnerModuleIoctlQuery = %#x, want %#x", got, want)
	}
}

func TestSocketOwnerModuleComm(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"正常截断", []byte("netd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), "netd"},
		{"全空", make([]byte, socketOwnerModuleCommLen), ""},
		{"填满无 NUL", []byte("0123456789abcdef"), "0123456789abcdef"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var raw [socketOwnerModuleCommLen]byte
			copy(raw[:], testCase.raw)
			if got := socketOwnerModuleComm(raw); got != testCase.want {
				t.Errorf("socketOwnerModuleComm() = %q, want %q", got, testCase.want)
			}
		})
	}
}

// TestSocketOwnerModuleClosed 确认未打开或已关闭的实例不会 panic，而是返回
// 错误——数据面在归属来源不可用时会继续调用它。
func TestSocketOwnerModuleClosed(t *testing.T) {
	t.Parallel()

	var module *SocketOwnerModule
	if _, err := module.LookupSocketOwner(1); err == nil {
		t.Error("nil 接收者应返回错误")
	}
	if err := module.Close(); err != nil {
		t.Errorf("nil 接收者 Close() = %v, want nil", err)
	}

	opened := &SocketOwnerModule{}
	if _, err := opened.LookupSocketOwner(1); err == nil {
		t.Error("未打开的实例应返回错误")
	}
	if err := opened.Close(); err != nil {
		t.Errorf("未打开的实例 Close() = %v, want nil", err)
	}
}
