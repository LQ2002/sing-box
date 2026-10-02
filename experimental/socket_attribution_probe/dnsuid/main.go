// Is the OEM enforceDnsUid option on? Default Android fchown()s each
// plaintext DNS socket to the requesting app's UID; with the option on the
// socket stays AID_DNS (1051). Record socket UID for packets leaving from
// netd's cgroup while a lookup is made as the shell user (UID 2000).
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

func must[T any](v T, err error) T {
	if err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
	}
	return v
}

func mapPtr(m *ebpf.Map) asm.Instruction {
	ins := asm.LoadMapPtr(asm.R1, 0)
	if err := ins.AssociateMap(m); err != nil {
		panic(err)
	}
	return ins
}

func main() {
	pid := must(exec.Command("pidof", "netd").Output())
	var st syscall.Stat_t
	cgPath := ""
	b := must(os.ReadFile("/proc/" + string(pid[:len(pid)-1]) + "/cgroup"))
	for _, l := range splitLines(string(b)) {
		if len(l) > 3 && l[:3] == "0::" {
			cgPath = "/sys/fs/cgroup" + l[3:]
		}
	}
	if err := syscall.Stat(cgPath, &st); err != nil {
		panic(err)
	}
	netdCg := st.Ino
	fmt.Println("netd cgroup", cgPath, netdCg)
	out := must(ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 8, ValueSize: 4, MaxEntries: 4096}))
	prog := must(ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SchedCLS, License: "GPL", Instructions: asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.FnSkbCgroupId.Call(),
		asm.LoadImm(asm.R1, int64(netdCg), asm.DWord),
		asm.JNE.Reg(asm.R0, asm.R1, "out"),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.FnGetSocketCookie.Call(),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.FnGetSocketUid.Call(),
		asm.StoreMem(asm.RFP, -12, asm.R0, asm.Word),
		mapPtr(out),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -12),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, -1).WithSymbol("out"),
		asm.Return(),
	}}))
	ifaces := must(net.Interfaces())
	var links []link.Link
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		lk, err := link.AttachTCX(link.TCXOptions{Interface: ifc.Index, Program: prog, Attach: ebpf.AttachTCXEgress, Anchor: link.Head()})
		if err != nil {
			fmt.Println("skip", ifc.Name, err)
			continue
		}
		links = append(links, lk)
	}
	fmt.Println("attached to", len(links), "interfaces")
	time.Sleep(time.Second)
	name := "sbo-" + strconv.FormatInt(time.Now().UnixNano(), 36) + ".example.com"
	o, cerr := exec.Command("/system/bin/sh", "-c", strings.ReplaceAll(os.Getenv("CMD"), "NAME", name)).CombinedOutput()
	fmt.Printf("lookup as shell: %s err=%v\n%s\n", name, cerr, o)
	time.Sleep(6 * time.Second)
	for _, lk := range links {
		lk.Close()
	}
	var k uint64
	var uid uint32
	count := map[uint32]int{}
	it := out.Iterate()
	for it.Next(&k, &uid) {
		count[uid]++
	}
	fmt.Printf("NETD_EGRESS_SOCKET_UIDS %v\n", count)
}

func splitLines(s string) []string {
	var r []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			r = append(r, s[start:i])
			start = i + 1
		}
	}
	return append(r, s[start:])
}
