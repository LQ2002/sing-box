// Can a TC egress program read netd's pinned cookie_tag_map per packet?
// Records cookie -> {uid, tag, cgroup id} for tagged sockets, then (while
// attached) the caller triggers an NTP refresh to see TAG_SYSTEM_NTP.
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
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

var names = map[uint32]string{
	0xFFFFFF01: "DOWNLOAD", 0xFFFFFF02: "MEDIA", 0xFFFFFF03: "BACKUP", 0xFFFFFF04: "RESTORE",
	0xFFFFFF05: "APP_STORE", 0xFFFFFF41: "NTP", 0xFFFFFF44: "GPS", 0xFFFFFF45: "PAC",
	0xFFFFFE01: "DHCP", 0xFFFFFE02: "NEIGHBOR", 0xFFFFFE03: "DHCP_SERVER",
	0xFFFFFF81: "PROBE(on behalf)", 0xFFFFFF82: "DNS(on behalf)", 0xFFFFFF42: "PROBE",
}

func main() {
	tagMap := must(ebpf.LoadPinnedMap("/sys/fs/bpf/netd_shared/map_netd_cookie_tag_map", &ebpf.LoadPinOptions{ReadOnly: true}))
	out := must(ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 8, ValueSize: 16, MaxEntries: 4096}))
	prog := must(ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SchedCLS, License: "GPL", Instructions: asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.FnGetSocketCookie.Call(),
		asm.JEq.Imm(asm.R0, 0, "out"),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		mapPtr(tagMap),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "out"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord), // {uid, tag}
		asm.StoreMem(asm.RFP, -24, asm.R1, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.FnSkbCgroupId.Call(),
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord),
		mapPtr(out),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -24),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, -1).WithSymbol("out"),
		asm.Return(),
	}}))
	fmt.Println("LOAD_OK TC program may read netd's cookie_tag_map")
	iface := must(net.InterfaceByName(os.Args[1]))
	l := must(link.AttachTCX(link.TCXOptions{Interface: iface.Index, Program: prog, Attach: ebpf.AttachTCXEgress, Anchor: link.Head()}))
	time.Sleep(2 * time.Second)
	o, err := exec.Command("cmd", "network_time_update_service", "force_refresh").CombinedOutput()
	fmt.Printf("NTP force_refresh: %q err=%v\n", string(o), err)
	secs, _ := strconv.Atoi(os.Args[2])
	time.Sleep(time.Duration(secs) * time.Second)
	l.Close()
	var k uint64
	var v struct {
		UID, Tag uint32
		Cgroup   uint64
	}
	it := out.Iterate()
	n := 0
	for it.Next(&k, &v) {
		n++
		fmt.Printf("TAGGED cookie=%d uid=%d tag=0x%08x %s cgroup=%d\n", k, v.UID, v.Tag, names[v.Tag], v.Cgroup)
	}
	fmt.Printf("SUMMARY tagged_sockets_seen=%d\n", n)
}
