// Verify on the target kernel that a TC egress program may call
// bpf_skb_cgroup_id(), and that the value it sees per packet equals the
// INET_DIAG_CGROUP_ID that SOCK_DIAG reports for the same socket cookie.
// The program only records cookie -> cgroup id and returns TCX_NEXT.
package main

import (
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

func main() {
	ifname := os.Args[1]
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		panic(err)
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 8, ValueSize: 8, MaxEntries: 16384})
	if err != nil {
		panic(err)
	}
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.FnGetSocketCookie.Call(),
		asm.JEq.Imm(asm.R0, 0, "out"),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.FnSkbCgroupId.Call(),
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord),
		asm.LoadMapPtr(asm.R1, m.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -16),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, -1).WithSymbol("out"), // TCX_NEXT
		asm.Return(),
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SchedCLS, Instructions: insns, License: "GPL"})
	if err != nil {
		fmt.Println("PROG_LOAD_FAILED", err)
		os.Exit(1)
	}
	fmt.Println("PROG_LOAD_OK (verifier accepted bpf_skb_cgroup_id in sched_cls)")
	l, err := link.AttachTCX(link.TCXOptions{Interface: iface.Index, Program: prog, Attach: ebpf.AttachTCXEgress, Anchor: link.Head()})
	if err != nil {
		fmt.Println("ATTACH_FAILED", err)
		os.Exit(1)
	}
	time.Sleep(20 * time.Second)
	l.Close()
	fmt.Println("DETACHED")

	// SOCK_DIAG view of the same sockets
	diag := map[uint64]uint64{}
	for _, fam := range []byte{syscall.AF_INET, syscall.AF_INET6} {
		for _, pr := range []byte{syscall.IPPROTO_TCP, syscall.IPPROTO_UDP} {
			ss, err := dump(fam, pr)
			if err != nil {
				continue
			}
			for _, s := range ss {
				diag[s.cookie] = s.cg
			}
		}
	}
	paths := map[uint64]string{}
	filepath.WalkDir("/sys/fs/cgroup", func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			var st syscall.Stat_t
			if syscall.Stat(p, &st) == nil {
				paths[st.Ino] = p[len("/sys/fs/cgroup"):]
			}
		}
		return nil
	})
	re := regexp.MustCompile(`/pid_\d+$`)
	var k, v uint64
	seen, agree, disagree, gone := 0, 0, 0, 0
	kinds := map[string]int{}
	it := m.Iterate()
	for it.Next(&k, &v) {
		seen++
		dv, ok := diag[k]
		switch {
		case !ok:
			gone++
		case dv == v:
			agree++
		default:
			disagree++
			fmt.Printf("DISAGREE cookie=%d tc=%d diag=%d\n", k, v, dv)
		}
		kinds[re.ReplaceAllString(paths[v], "/pid_N")]++
	}
	fmt.Printf("SUMMARY sockets_seen_by_tc=%d agree_with_sockdiag=%d disagree=%d closed_before_compare=%d\n", seen, agree, disagree, gone)
	for kk, n := range kinds {
		if kk == "" {
			kk = "(root cgroup or removed)"
		}
		fmt.Printf("CGROUP %4d %s\n", n, kk)
	}
}
