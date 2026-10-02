// Read-only uprobe on an AOT-compiled Java method inside one process
// (system_server), capturing the user stack on each hit and mapping the
// frames back to Java methods with oatdump's method/offset tables.
// oatdump offsets are relative to the oat file's "oatdata" symbol; the file
// offset for a uprobe is oatdata's file offset plus that value.
package main

import (
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
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

type method struct {
	off  uint64
	name string
}

type oatInfo struct {
	oatdataFileOff uint64
	methods        []method // sorted, compiled only
}

var oats = map[string]*oatInfo{}

func loadOat(path string) *oatInfo {
	if o, ok := oats[path]; ok {
		return o
	}
	o := &oatInfo{}
	oats[path] = o
	f, err := elf.Open(path)
	if err != nil {
		return o
	}
	syms, _ := f.DynamicSymbols()
	for _, s := range syms {
		if s.Name == "oatdata" {
			for _, p := range f.Progs {
				if p.Type == elf.PT_LOAD && s.Value >= p.Vaddr && s.Value < p.Vaddr+p.Memsz {
					o.oatdataFileOff = s.Value - p.Vaddr + p.Off
				}
			}
		}
	}
	f.Close()
	out, err := exec.Command("/apex/com.android.art/bin/oatdump", "--oat-file="+path, "--dump-method-and-offset-as-json").Output()
	if err != nil && len(out) == 0 {
		return o
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e struct{ Method, Offset string }
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		v, _ := strconv.ParseUint(strings.TrimPrefix(e.Offset, "0x"), 16, 64)
		if v != 0 {
			o.methods = append(o.methods, method{v, e.Method})
		}
	}
	sort.Slice(o.methods, func(i, j int) bool { return o.methods[i].off < o.methods[j].off })
	return o
}

func (o *oatInfo) lookup(fileOff uint64) string {
	rel := fileOff - o.oatdataFileOff
	i := sort.Search(len(o.methods), func(i int) bool { return o.methods[i].off > rel }) - 1
	if i < 0 {
		return "?"
	}
	return fmt.Sprintf("%s +0x%x", o.methods[i].name, rel-o.methods[i].off)
}

type mapping struct {
	start, end, off uint64
	path            string
}

func readMaps(pid int) []mapping {
	b, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/maps")
	var ms []mapping
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 6 {
			continue
		}
		se := strings.SplitN(f[0], "-", 2)
		s, _ := strconv.ParseUint(se[0], 16, 64)
		e, _ := strconv.ParseUint(se[1], 16, 64)
		off, _ := strconv.ParseUint(f[2], 16, 64)
		ms = append(ms, mapping{s, e, off, f[5]})
	}
	return ms
}

func symbolize(ms []mapping, addr uint64) string {
	for _, m := range ms {
		if addr >= m.start && addr < m.end {
			fo := addr - m.start + m.off
			if strings.HasSuffix(m.path, ".oat") || strings.HasSuffix(m.path, ".odex") {
				return loadOat(m.path).lookup(fo) + "  [" + m.path[strings.LastIndex(m.path, "/")+1:] + "]"
			}
			return fmt.Sprintf("%s+0x%x", m.path, fo)
		}
	}
	return fmt.Sprintf("0x%x (unmapped)", addr)
}

func main() {
	pid, _ := strconv.Atoi(os.Args[1])
	oatPath, methodName := os.Args[2], os.Args[3]
	secs, _ := strconv.Atoi(os.Args[4])
	o := loadOat(oatPath)
	var target uint64
	for _, m := range o.methods {
		if m.name == methodName {
			target = m.off
		}
	}
	if target == 0 {
		fmt.Println("method not compiled in", oatPath)
		os.Exit(1)
	}
	fileOff := o.oatdataFileOff + target
	fmt.Printf("oatdata file offset 0x%x, method offset 0x%x -> uprobe file offset 0x%x\n", o.oatdataFileOff, target, fileOff)

	stacks := must(ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.StackTrace, KeySize: 4, ValueSize: 8 * 64, MaxEntries: 1024}))
	counts := must(ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 1024}))
	ld := func(m *ebpf.Map, r asm.Register) asm.Instruction {
		ins := asm.LoadMapPtr(r, 0)
		ins.AssociateMap(m)
		return ins
	}
	prog := must(ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.Kprobe, License: "GPL", Instructions: asm.Instructions{
		ld(stacks, asm.R2),
		asm.Mov.Imm(asm.R3, 256), // BPF_F_USER_STACK
		asm.FnGetStackid.Call(),
		asm.JSLT.Imm(asm.R0, 0, "out"),
		asm.StoreMem(asm.RFP, -4, asm.R0, asm.Word),
		ld(counts, asm.R1),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "new"),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
		asm.Ja.Label("out"),
		asm.StoreImm(asm.RFP, -16, 1, asm.DWord).WithSymbol("new"),
		ld(counts, asm.R1),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -16),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("out"),
		asm.Return(),
	}}))
	ex := must(link.OpenExecutable(oatPath))
	up := must(ex.Uprobe("java_method", prog, &link.UprobeOptions{Address: fileOff, PID: pid}))
	fmt.Println("UPROBE_ATTACHED pid", pid)
	if len(os.Args) > 5 {
		time.Sleep(2 * time.Second)
		exec.Command("/system/bin/sh", "-c", os.Args[5]).Run()
	}
	time.Sleep(time.Duration(secs) * time.Second)
	up.Close()

	ms := readMaps(pid)
	var id uint32
	var n uint64
	it := counts.Iterate()
	total := 0
	for it.Next(&id, &n) {
		total += int(n)
		var frames [64]uint64
		if err := stacks.Lookup(&id, &frames); err != nil {
			continue
		}
		fmt.Printf("=== stack %d hit %d times\n", id, n)
		for i, a := range frames {
			if a == 0 {
				break
			}
			fmt.Printf("  #%-2d %s\n", i, symbolize(ms, a))
		}
	}
	fmt.Printf("SUMMARY hits=%d\n", total)
}
