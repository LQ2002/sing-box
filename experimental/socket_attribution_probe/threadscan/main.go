// Inside multi-package processes, which threads create sockets? The
// sb_sockowner_probe module records the creating thread's comm, so poll
// SOCK_DIAG + the module for a while and tally (process name, thread comm).
package main

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strconv"
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

func procName(pid int32) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/cmdline")
	if err != nil {
		return "?"
	}
	return string(bytes.SplitN(b, []byte{0}, 2)[0])
}

func main() {
	dev, err := os.OpenFile("/dev/sb_sockowner_probe", os.O_RDWR, 0)
	if err != nil {
		panic(err)
	}
	seen := map[uint64]bool{}
	tally := map[string]int{}
	end := time.Now().Add(60 * time.Second)
	for time.Now().Before(end) {
		for _, fam := range []byte{syscall.AF_INET, syscall.AF_INET6} {
			for _, pr := range []byte{syscall.IPPROTO_TCP, syscall.IPPROTO_UDP} {
				ss, _ := dump(fam, pr)
				for _, s := range ss {
					if seen[s.cookie] {
						continue
					}
					seen[s.cookie] = true
					q := query{Cookie: s.cookie}
					if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, dev.Fd(), 0xc0305301, uintptr(unsafe.Pointer(&q))); e != 0 {
						continue
					}
					if q.UID >= 10000 && q.UID%100000 >= 10000 {
						continue // ordinary app UIDs are already unambiguous
					}
					comm := string(bytes.TrimRight(q.Comm[:], "\x00"))
					tally[fmt.Sprintf("%d\t%s\t%s", q.UID, procName(q.PID), comm)]++
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	var keys []string
	for k := range tally {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%d\t%s\n", tally[k], k)
	}
	fmt.Printf("SOCKETS_SEEN %d\n", len(seen))
}
