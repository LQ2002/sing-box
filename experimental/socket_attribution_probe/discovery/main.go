// Package discovery race: for each process (cgroup v2 id), when did it send
// its first IPv4/IPv6 packet, relative to ActivityManager's am_proc_start
// event for the same pid? If the event always precedes the first send, the
// package is known before any packet needs a verdict.
// sock_common.skc_family is at byte 16 in this device's BTF.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
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

func run(cmd string) { exec.Command("/system/bin/sh", "-c", cmd).Run() }

func main() {
	first := must(ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: 8192}))
	prog := must(ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Tracing, AttachType: ebpf.AttachTraceRawTp, AttachTo: "sock_send_length", License: "GPL",
		Instructions: asm.Instructions{
			asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord),
			asm.LoadMem(asm.R2, asm.R6, 16, asm.Half), // skc_family
			asm.JEq.Imm(asm.R2, 2, "inet"),
			asm.JEq.Imm(asm.R2, 10, "inet"),
			asm.Ja.Label("out"),
			asm.FnGetCurrentCgroupId.Call().WithSymbol("inet"),
			asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
			asm.FnKtimeGetNs.Call(),
			asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord),
			mapPtr(first),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -8),
			asm.Mov.Reg(asm.R3, asm.RFP),
			asm.Add.Imm(asm.R3, -16),
			asm.Mov.Imm(asm.R4, 1), // BPF_NOEXIST: keep first send only
			asm.FnMapUpdateElem.Call(),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("out"),
			asm.Return(),
		},
	}))
	l := must(link.AttachTracing(link.TracingOptions{Program: prog}))
	var rt, mono unix.Timespec
	unix.ClockGettime(unix.CLOCK_REALTIME, &rt)
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono)
	offset := rt.Nano() - mono.Nano() // realtime = monotonic + offset
	startEpoch := float64(rt.Nano()) / 1e9

	apps := strings.Split(os.Args[1], ",")
	for _, a := range apps {
		run("am force-stop " + a)
	}
	time.Sleep(2 * time.Second)
	for _, a := range apps {
		run("monkey -p " + a + " -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1")
		time.Sleep(8 * time.Second)
	}
	l.Close()

	// cgroup id -> uid/pid while the processes are still alive
	re := regexp.MustCompile(`uid_(\d+)/pid_(\d+)$`)
	cgPid := map[uint64]string{}
	filepath.WalkDir("/sys/fs/cgroup", func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			if m := re.FindStringSubmatch(p); m != nil {
				var st syscall.Stat_t
				if syscall.Stat(p, &st) == nil {
					cgPid[st.Ino] = m[2]
				}
			}
		}
		return nil
	})
	firstByPid := map[string]int64{}
	var k, v uint64
	it := first.Iterate()
	for it.Next(&k, &v) {
		if pid, ok := cgPid[k]; ok {
			firstByPid[pid] = int64(v) + offset
		}
	}
	// am_proc_start events during the run
	out := must(exec.Command("logcat", "-b", "events", "-d", "-v", "epoch").Output())
	evRe := regexp.MustCompile(`^\s*([\d.]+)\s.*am_proc_start: \[\d+,(\d+),(\d+),([^,]+),([^,]+),\{?([^/}]*)`)
	type row struct {
		name, comp, uid string
		delta          float64
	}
	var rows []row
	never := 0
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		m := evRe.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		ts, _ := strconv.ParseFloat(m[1], 64)
		if ts < startEpoch {
			continue
		}
		f, ok := firstByPid[m[2]]
		if !ok {
			never++
			continue
		}
		rows = append(rows, row{m[4], m[6], m[3], float64(f)/1e6 - ts*1000})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].delta < rows[j].delta })
	for _, r := range rows {
		fmt.Printf("first_inet_send - am_proc_start = %8.1f ms  uid=%-6s %s (component pkg %s)\n", r.delta, r.uid, r.name, r.comp)
	}
	fmt.Printf("SUMMARY started_with_send=%d started_without_send_in_window=%d\n", len(rows), never)
}
