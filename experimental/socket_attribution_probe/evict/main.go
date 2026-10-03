// Controlled eviction test: do idle-but-alive sockets drop out of the
// sb_sockowner_probe table? Each socket is queried at t=0 and then exactly
// once more at a different delay, so no socket is refreshed in between.
package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type query struct {
	Cookie   uint64
	PID      int32
	UID      uint32
	Start    uint64
	Family   uint16
	Reserved uint16
	Comm     [16]byte
}

func cookieOf(fd int) uint64 {
	var c uint64
	l := uint32(8)
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), syscall.SOL_SOCKET, 57 /* SO_COOKIE */, uintptr(unsafe.Pointer(&c)), uintptr(unsafe.Pointer(&l)), 0)
	if e != 0 {
		panic(e)
	}
	return c
}

func lookup(dev *os.File, c uint64) bool {
	q := query{Cookie: c}
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, dev.Fd(), 0xc0305301, uintptr(unsafe.Pointer(&q)))
	return e == 0
}

func status() string {
	b, _ := os.ReadFile("/proc/sb_sockowner_probe")
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "evicted") || strings.HasPrefix(l, "created_ipv4") || strings.HasPrefix(l, "entries") {
			out = append(out, l)
		}
	}
	return strings.Join(out, " ")
}

func main() {
	dev, err := os.OpenFile("/dev/sb_sockowner_probe", os.O_RDWR, 0)
	if err != nil {
		panic(err)
	}
	delays := []int{1, 2, 4, 6, 8, 10, 12, 14, 16, 18, 21, 24} // minutes
	cookies := make([]uint64, len(delays))
	for i := range delays {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
		if err != nil {
			panic(err)
		}
		cookies[i] = cookieOf(fd)
		fmt.Printf("t=0 sock=%d cookie=%d hit=%v\n", i, cookies[i], lookup(dev, cookies[i]))
	}
	fmt.Println("t=0", status())
	start := time.Now()
	for i, m := range delays {
		time.Sleep(time.Until(start.Add(time.Duration(m) * time.Minute)))
		fmt.Printf("t=%dm sock=%d hit=%v %s\n", m, i, lookup(dev, cookies[i]), status())
	}
}
