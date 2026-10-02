// Does the process that creates an inet socket ever differ from the one
// that sends on it? Attribution by the socket's own cgroup names the
// creator; the routing policy wants the sender. Records, per socket, the
// first sending process (tgid + cgroup) and any later sender from another
// cgroup, then compares with SOCK_DIAG's cgroup id and UID for the socket.
package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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

type sender struct {
	PidTgid uint64
	Cgroup  uint64
}

func name(pid uint32) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/cmdline")
	if err != nil {
		return "(exited)"
	}
	return string(bytes.SplitN(b, []byte{0}, 2)[0])
}

func main() {
	first := must(ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 8, ValueSize: 16, MaxEntries: 65536}))
	other := must(ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 8, ValueSize: 16, MaxEntries: 8192}))
	// stack: cookie @-8, value {pid_tgid @-24, cgroup @-16}
	prog := must(ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Tracing, AttachType: ebpf.AttachTraceRawTp, AttachTo: "sock_send_length", License: "GPL",
		Instructions: asm.Instructions{
			asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord),
			asm.LoadMem(asm.R2, asm.R6, 16, asm.Half),
			asm.JEq.Imm(asm.R2, 2, "inet"),
			asm.JEq.Imm(asm.R2, 10, "inet"),
			asm.Ja.Label("out"),
			asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("inet"),
			asm.FnGetSocketCookie.Call(),
			asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
			asm.FnGetCurrentPidTgid.Call(),
			asm.StoreMem(asm.RFP, -24, asm.R0, asm.DWord),
			asm.FnGetCurrentCgroupId.Call(),
			asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord),
			asm.Mov.Reg(asm.R7, asm.R0), // current cgroup
			mapPtr(first),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -8),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "new"),
			asm.LoadMem(asm.R1, asm.R0, 8, asm.DWord),
			asm.JEq.Reg(asm.R1, asm.R7, "out"),
			mapPtr(other), // a different cgroup is sending on this socket
			asm.Ja.Label("put"),
			mapPtr(first).WithSymbol("new"),
			asm.Mov.Reg(asm.R2, asm.RFP).WithSymbol("put"),
			asm.Add.Imm(asm.R2, -8),
			asm.Mov.Reg(asm.R3, asm.RFP),
			asm.Add.Imm(asm.R3, -24),
			asm.Mov.Imm(asm.R4, 0),
			asm.FnMapUpdateElem.Call(),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("out"),
			asm.Return(),
		},
	}))
	l := must(link.AttachTracing(link.TracingOptions{Program: prog}))
	secs, _ := strconv.Atoi(os.Args[1])
	time.Sleep(time.Duration(secs) * time.Second)
	l.Close()

	diag := map[uint64]sock{}
	for _, fam := range []byte{syscall.AF_INET, syscall.AF_INET6} {
		for _, pr := range []byte{syscall.IPPROTO_TCP, syscall.IPPROTO_UDP} {
			ss, _ := dump(fam, pr)
			for _, s := range ss {
				diag[s.cookie] = s
			}
		}
	}
	re := regexp.MustCompile(`/pid_(\d+)$`)
	cgProc := map[uint64]string{}
	filepath.WalkDir("/sys/fs/cgroup", func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			var st syscall.Stat_t
			if syscall.Stat(p, &st) == nil {
				label := p[len("/sys/fs/cgroup"):]
				if m := re.FindStringSubmatch(p); m != nil {
					pid, _ := strconv.Atoi(m[1])
					label += " " + name(uint32(pid))
				}
				if label == "" {
					label = "/ (root)"
				}
				cgProc[st.Ino] = label
			}
		}
		return nil
	})
	cgLabel := func(id uint64) string {
		if s, ok := cgProc[id]; ok {
			return s
		}
		return fmt.Sprintf("cgroup %d (removed)", id)
	}
	var k uint64
	var v sender
	total, open, same, differ := 0, 0, 0, 0
	lines := map[string]int{}
	it := first.Iterate()
	for it.Next(&k, &v) {
		total++
		d, ok := diag[k]
		if !ok || d.cg == 0 {
			continue
		}
		open++
		if d.cg == v.Cgroup {
			same++
			continue
		}
		differ++
		lines[fmt.Sprintf("CREATOR %s (sock uid %d)  <-  FIRST SENDER %s [%s]", cgLabel(d.cg), d.uid, cgLabel(v.Cgroup), name(uint32(v.PidTgid>>32)))]++
	}
	multi := 0
	it = other.Iterate()
	for it.Next(&k, &v) {
		multi++
		f := sender{}
		first.Lookup(&k, &f)
		lines[fmt.Sprintf("SHARED SOCKET first sender %s  +  later sender %s [%s]", cgLabel(f.Cgroup), cgLabel(v.Cgroup), name(uint32(v.PidTgid>>32)))]++
	}
	var keys []string
	for s := range lines {
		keys = append(keys, s)
	}
	sort.Strings(keys)
	for _, s := range keys {
		fmt.Printf("%4d  %s\n", lines[s], s)
	}
	fmt.Printf("SUMMARY inet_sockets_sent=%d still_open=%d creator_cgroup==first_sender=%d differ=%d sockets_with_a_second_sending_cgroup=%d\n", total, open, same, differ, multi)
}
