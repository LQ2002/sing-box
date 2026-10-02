// Which threads of one process (system_server) open network connections,
// and to where. TCP: tp_btf inet_sock_set_state at TCP_SYN_SENT, which runs
// in the connect() caller's context. UDP and anything else: first send via
// tp_btf sock_send_length. sock_common offsets from this device's BTF:
// skc_daddr @0, skc_dport @12, skc_family @16, skc_v6_daddr @56.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"sort"
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

type rec struct {
	TS     uint64
	TID    uint32
	DPort  uint16
	Family uint16
	DAddr  [4]byte
	_      uint32
	V6     [16]byte
	Comm   [16]byte
}

// record builds a program body that, given r6 = struct sock *, fills a rec
// on the stack and stores it under the socket cookie with the given flags.
func record(m *ebpf.Map, tgid int64, flags int32) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(asm.R2, asm.R6, 16, asm.Half),
		asm.JEq.Imm(asm.R2, 2, "inet"),
		asm.JEq.Imm(asm.R2, 10, "inet"),
		asm.Ja.Label("out"),
		asm.FnGetCurrentPidTgid.Call().WithSymbol("inet"),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.RSh.Imm(asm.R0, 32),
		asm.LoadImm(asm.R1, tgid, asm.DWord),
		asm.JNE.Reg(asm.R0, asm.R1, "out"),
		asm.StoreMem(asm.RFP, -56, asm.R7, asm.Word), // tid
		asm.LoadMem(asm.R1, asm.R6, 16, asm.Half),
		asm.StoreMem(asm.RFP, -50, asm.R1, asm.Half), // family
		asm.LoadMem(asm.R1, asm.R6, 12, asm.Half),
		asm.StoreMem(asm.RFP, -52, asm.R1, asm.Half), // dport (network order)
		asm.LoadMem(asm.R1, asm.R6, 0, asm.Word),
		asm.StoreMem(asm.RFP, -48, asm.R1, asm.Word), // daddr v4
		asm.StoreImm(asm.RFP, -44, 0, asm.Word),
		asm.LoadMem(asm.R1, asm.R6, 56, asm.Word),
		asm.StoreMem(asm.RFP, -40, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R6, 60, asm.Word),
		asm.StoreMem(asm.RFP, -36, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R6, 64, asm.Word),
		asm.StoreMem(asm.RFP, -32, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R6, 68, asm.Word),
		asm.StoreMem(asm.RFP, -28, asm.R1, asm.Word),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -24),
		asm.Mov.Imm(asm.R2, 16),
		asm.FnGetCurrentComm.Call(),
		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.RFP, -64, asm.R0, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.FnGetSocketCookie.Call(),
		asm.StoreMem(asm.RFP, -72, asm.R0, asm.DWord),
		mapPtr(m),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -72),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -64),
		asm.Mov.Imm(asm.R4, flags),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("out"),
		asm.Return(),
	}
}

func main() {
	tgid, _ := strconv.Atoi(os.Args[1])
	secs, _ := strconv.Atoi(os.Args[2])
	conn := must(ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 8, ValueSize: 56, MaxEntries: 8192}))
	send := must(ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 8, ValueSize: 56, MaxEntries: 8192}))
	connProg := must(ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Tracing, AttachType: ebpf.AttachTraceRawTp, AttachTo: "inet_sock_set_state", License: "GPL",
		Instructions: append(asm.Instructions{
			asm.LoadMem(asm.R2, asm.R1, 16, asm.DWord), // newstate
			asm.JNE.Imm(asm.R2, 2, "out"),              // TCP_SYN_SENT
			asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord),
		}, record(conn, int64(tgid), 0)...),
	}))
	sendProg := must(ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Tracing, AttachType: ebpf.AttachTraceRawTp, AttachTo: "sock_send_length", License: "GPL",
		Instructions: append(asm.Instructions{
			asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord),
		}, record(send, int64(tgid), 1)...),
	}))
	l1 := must(link.AttachTracing(link.TracingOptions{Program: connProg}))
	l2 := must(link.AttachTracing(link.TracingOptions{Program: sendProg}))
	fmt.Printf("tracing pid %d for %ds\n", tgid, secs)
	time.Sleep(time.Duration(secs) * time.Second)
	l1.Close()
	l2.Close()

	type row struct {
		kind string
		r    rec
	}
	var rows []row
	tcp := map[uint64]bool{}
	var k uint64
	var r rec
	it := conn.Iterate()
	for it.Next(&k, &r) {
		tcp[k] = true
		rows = append(rows, row{"TCP connect", r})
	}
	it = send.Iterate()
	for it.Next(&k, &r) {
		if !tcp[k] {
			rows = append(rows, row{"first send ", r})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].r.TS < rows[j].r.TS })
	byThread := map[string]int{}
	for _, x := range rows {
		port := binary.BigEndian.Uint16([]byte{byte(x.r.DPort), byte(x.r.DPort >> 8)})
		var dst string
		if x.r.Family == 2 {
			dst = netip.AddrFrom4(x.r.DAddr).String()
		} else {
			dst = netip.AddrFrom16(x.r.V6).String()
		}
		comm := string(bytes.TrimRight(x.r.Comm[:], "\x00"))
		byThread[comm]++
		fmt.Printf("%s  t=%9.3fs  tid=%-6d thread=%-16s -> %s:%d\n", x.kind, float64(x.r.TS)/1e9, x.r.TID, comm, dst, port)
	}
	fmt.Println("--- by thread")
	for c, n := range byThread {
		fmt.Printf("%4d  %s\n", n, c)
	}
}
