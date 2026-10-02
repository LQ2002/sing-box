// Pure-eBPF, read-only: for every socket (TCP, UDP, QUIC-over-UDP) record on
// its first send which thread sent it, that thread's cgroup, and which
// process/UID last made a binder call into that thread. The question is
// whether system_server traffic can be attributed to the app that asked
// for it. Offsets of binder_transaction are from this device's BTF:
// from_pid @48, sender_euid @132.
package main

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

type sendRec struct {
	PidTgid    uint64
	Cgroup     uint64
	BinderPid  uint32
	BinderUID  uint32
	BinderAge  uint64
}

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

func cmdline(pid uint32) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/cmdline")
	if err != nil {
		return "?"
	}
	return string(bytes.SplitN(b, []byte{0}, 2)[0])
}

func main() {
	sendMap := must(ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 8, ValueSize: 32, MaxEntries: 65536}))
	binderMap := must(ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 4, ValueSize: 16, MaxEntries: 16384}))

	sendProg := must(ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Tracing, AttachType: ebpf.AttachTraceRawTp, AttachTo: "sock_send_length", License: "GPL",
		Instructions: asm.Instructions{
			asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord), // sk
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.FnGetSocketCookie.Call(),
			asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
			asm.FnGetCurrentPidTgid.Call(),
			asm.StoreMem(asm.RFP, -40, asm.R0, asm.DWord),
			asm.StoreMem(asm.RFP, -44, asm.R0, asm.Word),
			asm.FnGetCurrentCgroupId.Call(),
			asm.StoreMem(asm.RFP, -32, asm.R0, asm.DWord),
			asm.StoreImm(asm.RFP, -24, 0, asm.DWord),
			asm.StoreImm(asm.RFP, -16, 0, asm.DWord),
			mapPtr(binderMap),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -44),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "upd"),
			asm.Mov.Reg(asm.R7, asm.R0),
			asm.LoadMem(asm.R1, asm.R7, 0, asm.Word),
			asm.StoreMem(asm.RFP, -24, asm.R1, asm.Word),
			asm.LoadMem(asm.R1, asm.R7, 4, asm.Word),
			asm.StoreMem(asm.RFP, -20, asm.R1, asm.Word),
			asm.LoadMem(asm.R8, asm.R7, 8, asm.DWord),
			asm.FnKtimeGetNs.Call(),
			asm.Sub.Reg(asm.R0, asm.R8),
			asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord),
			mapPtr(sendMap).WithSymbol("upd"),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -8),
			asm.Mov.Reg(asm.R3, asm.RFP),
			asm.Add.Imm(asm.R3, -40),
			asm.Mov.Imm(asm.R4, 1), // BPF_NOEXIST: keep the first send
			asm.FnMapUpdateElem.Call(),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	}))
	binderProg := must(ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Tracing, AttachType: ebpf.AttachTraceRawTp, AttachTo: "binder_transaction_received", License: "GPL",
		Instructions: asm.Instructions{
			asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord),   // struct binder_transaction *t
			asm.LoadMem(asm.R7, asm.R6, 48, asm.Word),  // t->from_pid
			asm.LoadMem(asm.R8, asm.R6, 132, asm.Word), // t->sender_euid
			asm.FnGetCurrentPidTgid.Call(),
			asm.StoreMem(asm.RFP, -20, asm.R0, asm.Word),
			asm.StoreMem(asm.RFP, -16, asm.R7, asm.Word),
			asm.StoreMem(asm.RFP, -12, asm.R8, asm.Word),
			asm.FnKtimeGetNs.Call(),
			asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
			mapPtr(binderMap),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -20),
			asm.Mov.Reg(asm.R3, asm.RFP),
			asm.Add.Imm(asm.R3, -16),
			asm.Mov.Imm(asm.R4, 0),
			asm.FnMapUpdateElem.Call(),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	}))
	fmt.Println("LOAD_OK both programs passed the verifier")
	l1 := must(link.AttachTracing(link.TracingOptions{Program: sendProg}))
	l2 := must(link.AttachTracing(link.TracingOptions{Program: binderProg}))
	fmt.Println("ATTACH_OK")
	secs := 90
	if len(os.Args) > 1 {
		secs, _ = strconv.Atoi(os.Args[1])
	}
	time.Sleep(time.Duration(secs) * time.Second)
	l1.Close()
	l2.Close()

	diag := map[uint64]sock{}
	for _, fam := range []byte{syscall.AF_INET, syscall.AF_INET6} {
		for _, pr := range []byte{syscall.IPPROTO_TCP, syscall.IPPROTO_UDP} {
			ss, _ := dump(fam, pr)
			for _, s := range ss {
				diag[s.cookie] = s
			}
		}
	}
	var k uint64
	var v sendRec
	total, joined, tcp, udp, cgSame, viaBinder := 0, 0, 0, 0, 0, 0
	lines := map[string]int{}
	it := sendMap.Iterate()
	for it.Next(&k, &v) {
		total++
		tgid := uint32(v.PidTgid >> 32)
		d, ok := diag[k]
		if ok {
			joined++
			if d.proto == syscall.IPPROTO_TCP {
				tcp++
			} else {
				udp++
			}
			if d.cg == v.Cgroup {
				cgSame++
			}
		}
		recent := v.BinderPid != 0 && v.BinderPid != tgid && v.BinderAge < uint64(time.Second)
		if recent {
			viaBinder++
		}
		name := cmdline(tgid)
		uid := -1
		if ok {
			uid = int(d.uid)
		}
		if uid >= 0 && uid%100000 >= 10000 && !recent {
			continue // plain app traffic: nothing new to learn
		}
		tag := "self"
		if recent {
			tag = fmt.Sprintf("after_binder_from uid=%d %s (%.1fms)", v.BinderUID, cmdline(v.BinderPid), float64(v.BinderAge)/1e6)
		}
		lines[fmt.Sprintf("sockuid=%d\t%s\t%s", uid, name, tag)]++
	}
	var keys []string
	for kk := range lines {
		keys = append(keys, kk)
	}
	sort.Strings(keys)
	for _, kk := range keys {
		fmt.Printf("%d\t%s\n", lines[kk], kk)
	}
	fmt.Printf("SUMMARY sockets_with_send=%d still_open=%d tcp=%d udp=%d send_cgroup_eq_socket_cgroup=%d sent_within_1s_of_foreign_binder_call=%d\n",
		total, joined, tcp, udp, cgSame, viaBinder)
}
