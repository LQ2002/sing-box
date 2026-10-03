// For processes that host several packages, how much of their network
// traffic carries a TrafficStats tag (and hence a precise owner), and which
// thread sent the rest? On each inet socket's first send, look up netd's
// cookie_tag_map in-kernel and record {cgroup id, uid+tag, thread comm}.
// skc_family @16 from the device BTF.
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

var tagNames = map[uint32]string{
	0xFFFFFF01: "DOWNLOAD", 0xFFFFFF02: "MEDIA", 0xFFFFFF03: "BACKUP", 0xFFFFFF04: "RESTORE",
	0xFFFFFF05: "APP_STORE", 0xFFFFFF41: "NTP", 0xFFFFFF42: "PROBE", 0xFFFFFF44: "GPS", 0xFFFFFF45: "PAC",
	0xFFFFFE01: "DHCP", 0xFFFFFE02: "NEIGHBOR", 0xFFFFFE03: "DHCP_SERVER",
	0xFFFFFF81: "PROBE_ON_BEHALF", 0xFFFFFF82: "DNS_ON_BEHALF",
}

type record struct {
	Cgroup   uint64
	UID, Tag uint32
	Comm     [16]byte
}

func tagText(v record) string {
	if v.Tag == 0 && v.UID == 0 {
		return "untagged"
	}
	tn := tagNames[v.Tag]
	if tn == "" {
		tn = fmt.Sprintf("0x%08x", v.Tag)
	}
	return fmt.Sprintf("%s uid=%d", tn, v.UID)
}

func main() {
	tagMap := must(ebpf.LoadPinnedMap("/sys/fs/bpf/netd_shared/map_netd_cookie_tag_map", &ebpf.LoadPinOptions{ReadOnly: true}))
	rec := must(ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 8, ValueSize: 32, MaxEntries: 65536}))
	// stack: key cookie @-8; value {cgroup @-40, uid+tag @-32, comm @-24..-9}
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
			asm.FnGetCurrentCgroupId.Call(),
			asm.StoreMem(asm.RFP, -40, asm.R0, asm.DWord),
			asm.StoreImm(asm.RFP, -32, 0, asm.DWord),
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, -24),
			asm.Mov.Imm(asm.R2, 16),
			asm.FnGetCurrentComm.Call(),
			mapPtr(tagMap),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -8),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "store"),
			asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord),
			asm.StoreMem(asm.RFP, -32, asm.R1, asm.DWord),
			mapPtr(rec).WithSymbol("store"),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -8),
			asm.Mov.Reg(asm.R3, asm.RFP),
			asm.Add.Imm(asm.R3, -40),
			asm.Mov.Imm(asm.R4, 1),
			asm.FnMapUpdateElem.Call(),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("out"),
			asm.Return(),
		},
	}))
	l := must(link.AttachTracing(link.TracingOptions{Program: prog}))
	secs, _ := strconv.Atoi(os.Args[1])
	fmt.Println("tracing", secs, "s")
	time.Sleep(time.Duration(secs) * time.Second)
	l.Close()

	re := regexp.MustCompile(`uid_(\d+)/pid_(\d+)$`)
	multi := regexp.MustCompile(`system_server|com\.android\.phone|android\.process\.media|networkstack|qtidataservices|\.dataservices|com\.qti\.phone`)
	cgName := map[uint64]string{}
	filepath.WalkDir("/sys/fs/cgroup", func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			if m := re.FindStringSubmatch(p); m != nil {
				var st syscall.Stat_t
				if syscall.Stat(p, &st) == nil {
					b, _ := os.ReadFile("/proc/" + m[2] + "/cmdline")
					cgName[st.Ino] = "uid " + m[1] + " " + string(bytes.SplitN(b, []byte{0}, 2)[0])
				}
			}
		}
		return nil
	})
	type agg struct {
		total, untagged int
		tags            map[string]int
	}
	per := map[string]*agg{}
	var k uint64
	var v record
	it := rec.Iterate()
	for it.Next(&k, &v) {
		name, ok := cgName[v.Cgroup]
		if !ok {
			name = "(root cgroup or exited)"
		}
		if multi.MatchString(name) {
			fmt.Printf("MULTI %-32s thread=%-16s %s\n", name, string(bytes.TrimRight(v.Comm[:], "\x00")), tagText(v))
		}
		a := per[name]
		if a == nil {
			a = &agg{tags: map[string]int{}}
			per[name] = a
		}
		a.total++
		if v.Tag == 0 && v.UID == 0 {
			a.untagged++
			continue
		}
		a.tags[tagText(v)]++
	}
	var names []string
	for n := range per {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return per[names[i]].total > per[names[j]].total })
	for _, n := range names {
		a := per[n]
		fmt.Printf("%5d sockets  untagged=%-5d %s  %v\n", a.total, a.untagged, n, a.tags)
	}
}
