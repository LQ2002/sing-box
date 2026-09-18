// sbo-cookietest 验证 sb_sockowner_probe 的 cookie -> 创建者归属查询。
//
// 对每种 socket 族/类型组合：创建 socket，用 getsockopt(SO_COOKIE) 取内核
// 分配的 64 位 cookie，再通过 /dev/sb_sockowner_probe 的 ioctl 反查，核对
// 模块记录的 tgid/uid/family 是否与本进程一致。
//
// 另外覆盖两个边界：不存在的 cookie 必须返回 ENOENT；socket 关闭后应在
// 宽限期内仍可查到、宽限期过后被回收。
//
// 需要 root（设备节点 mode 0600）。构建：
//
//	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o sbo-cookietest .
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	devPath = "/dev/sb_sockowner_probe"

	// include/uapi/asm-generic/socket.h:96
	soCookie = 57

	// _IOWR('S', 0x01, struct sbo_query)，其中 sizeof(struct sbo_query) == 48。
	// ioctl 号编码了结构体长度，所以每次增删字段它都会变；该常量是用内核头文件
	// 实际编译核对出来的，不要按字段数手算（手算容易漏掉 __u64 的对齐补位）。
	iocQuery = 0xc0305301

	commLen = 16 // TASK_COMM_LEN

	graceSeconds = 5 // 模块里的 OWNER_GRACE = 5 * HZ
)

// sboQuery 必须与模块中的 struct sbo_query 二进制一致：
// cookie@0 tgid@8 uid@12 start_time_ns@16 family@24 reserved@26 comm@28，总长 48。
type sboQuery struct {
	Cookie      uint64
	Tgid        int32
	Uid         uint32
	StartTimeNs uint64
	Family      uint16
	Reserved    uint16
	Comm        [commLen]byte
}

// 布局一旦漂移，后面所有比对都会变成无意义的垃圾，所以在编译期钉死总长为 48。
var _ [1]struct{} = [unsafe.Sizeof(sboQuery{}) - 47]struct{}{}

// commString 取到第一个 NUL 为止：内核侧是定长数组，尾部是填充。
func commString(raw [commLen]byte) string {
	if i := bytes.IndexByte(raw[:], 0); i >= 0 {
		return string(raw[:i])
	}
	return string(raw[:])
}

func socketCookie(fd int) (uint64, error) {
	var val uint64
	size := uint32(unsafe.Sizeof(val))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
		uintptr(fd), uintptr(syscall.SOL_SOCKET), uintptr(soCookie),
		uintptr(unsafe.Pointer(&val)), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return 0, errno
	}
	return val, nil
}

func query(devFD int, cookie uint64) (sboQuery, error) {
	q := sboQuery{Cookie: cookie}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(devFD), uintptr(iocQuery), uintptr(unsafe.Pointer(&q)))
	if errno != 0 {
		return q, errno
	}
	return q, nil
}

type result struct {
	name string
	ok   bool
	note string
}

func (r *result) fail(format string, a ...any) {
	r.ok = false
	r.note = fmt.Sprintf(format, a...)
}

func checkSocket(devFD int, name string, domain, typ, wantFamily int) result {
	r := result{name: name, ok: true}

	fd, err := syscall.Socket(domain, typ, 0)
	if err != nil {
		r.fail("socket(): %v", err)
		return r
	}
	defer syscall.Close(fd)

	cookie, err := socketCookie(fd)
	if err != nil {
		r.fail("getsockopt(SO_COOKIE): %v", err)
		return r
	}
	if cookie == 0 {
		r.fail("内核返回 cookie 为 0")
		return r
	}

	q, err := query(devFD, cookie)
	if err != nil {
		r.fail("cookie 0x%x 查不到: %v", cookie, err)
		return r
	}

	switch {
	case int(q.Tgid) != os.Getpid():
		r.fail("tgid 不符: 模块记录 %d, 本进程 %d", q.Tgid, os.Getpid())
	case int(q.Uid) != os.Getuid():
		r.fail("uid 不符: 模块记录 %d, 本进程 %d", q.Uid, os.Getuid())
	case int(q.Family) != wantFamily:
		r.fail("family 不符: 模块记录 %d, 期望 %d", q.Family, wantFamily)
	case q.StartTimeNs == 0:
		r.fail("start_time_ns 为 0")
	default:
		// comm 是内核在 socket() 时抓的，应当等于本进程名（截断到 15 字符）。
		// 它的价值在于进程退出后 procfs 已经消失，这是唯一幸存的线索。
		comm := commString(q.Comm)
		want := selfComm()
		if comm != want {
			r.fail("comm 不符: 模块记录 %q, 本进程 %q", comm, want)
			return r
		}
		r.note = fmt.Sprintf("cookie=0x%x tgid=%d uid=%d comm=%q start=%.3fs",
			cookie, q.Tgid, q.Uid, comm, float64(q.StartTimeNs)/1e9)
	}
	return r
}

// selfComm 读本进程的 comm，用作 ioctl 返回值的比对基准。
// 内核把它截断到 TASK_COMM_LEN-1 个字符，这里做同样的截断。
func selfComm() string {
	raw, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		return ""
	}
	name := strings.TrimRight(string(raw), "\n")
	if len(name) > commLen-1 {
		name = name[:commLen-1]
	}
	return name
}

// checkUnknown 确认查询一个从未存在过的 cookie 会干净地返回 ENOENT，
// 而不是命中残留条目或返回未初始化数据。
func checkUnknown(devFD int) result {
	r := result{name: "不存在的 cookie -> ENOENT", ok: true}
	_, err := query(devFD, 0xdeadbeefcafef00d)
	if err == nil {
		r.fail("竟然查到了")
	} else if !errors.Is(err, syscall.ENOENT) {
		r.fail("期望 ENOENT，实际 %v", err)
	}
	return r
}

// checkGrace 验证 on_free 只是打上过期时间戳而非立刻删除：关闭后应仍可查到，
// 超过 OWNER_GRACE 之后才被回收。这决定了 sing-box 侧在 socket 关闭与
// 归属查询之间能容忍多大的时间窗。
func checkGrace(devFD int) []result {
	out := []result{}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return append(out, result{name: "宽限期", note: fmt.Sprintf("socket(): %v", err)})
	}
	cookie, err := socketCookie(fd)
	if err != nil {
		syscall.Close(fd)
		return append(out, result{name: "宽限期", note: fmt.Sprintf("SO_COOKIE: %v", err)})
	}
	syscall.Close(fd)

	r1 := result{name: "关闭后立即查询仍可命中", ok: true}
	if _, err := query(devFD, cookie); err != nil {
		r1.fail("cookie 0x%x: %v", cookie, err)
	}
	out = append(out, r1)

	wait := time.Duration(graceSeconds+1) * time.Second
	fmt.Printf("   等待 %v 让宽限期过去...\n", wait)
	time.Sleep(wait)

	r2 := result{name: "宽限期过后被回收", ok: true}
	if _, err := query(devFD, cookie); err == nil {
		r2.fail("宽限期已过仍能查到，条目没有被回收")
	} else if !errors.Is(err, syscall.ENOENT) {
		r2.fail("期望 ENOENT，实际 %v", err)
	}
	return append(out, r2)
}

func main() {
	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "需要 root：设备节点是 mode 0600 root:root")
		os.Exit(2)
	}

	devFD, err := syscall.Open(devPath, syscall.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "打开 %s 失败: %v\n（模块没加载？）\n", devPath, err)
		os.Exit(2)
	}
	defer syscall.Close(devFD)

	fmt.Printf("pid=%d uid=%d  设备 %s\n\n", os.Getpid(), os.Getuid(), devPath)

	results := []result{
		checkSocket(devFD, "IPv4 TCP", syscall.AF_INET, syscall.SOCK_STREAM, syscall.AF_INET),
		checkSocket(devFD, "IPv4 UDP", syscall.AF_INET, syscall.SOCK_DGRAM, syscall.AF_INET),
		checkSocket(devFD, "IPv6 TCP", syscall.AF_INET6, syscall.SOCK_STREAM, syscall.AF_INET6),
		checkSocket(devFD, "IPv6 UDP", syscall.AF_INET6, syscall.SOCK_DGRAM, syscall.AF_INET6),
		checkUnknown(devFD),
	}
	results = append(results, checkGrace(devFD)...)

	failed := 0
	for _, r := range results {
		mark := "PASS"
		if !r.ok {
			mark = "FAIL"
			failed++
		}
		fmt.Printf("%-4s %-28s %s\n", mark, r.name, r.note)
	}

	fmt.Printf("\n%d 项，通过 %d，失败 %d\n", len(results), len(results)-failed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}
