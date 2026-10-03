// Event-driven identity join instead of polling /proc: when does an app
// process enter its /apps/uid_X/pid_Y cgroup (tp_btf cgroup_attach_task,
// written by zygote before setresuid and any Java code), when is
// am_proc_start written and when does it reach a live reader, and when does
// the process send its first IPv4/IPv6 packet? All on CLOCK_MONOTONIC.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
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

func mono() int64 {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return ts.Nano()
}

type startEv struct {
	writtenMono, arriveMono int64
	pid, uid                string
	name, comp              string
}

func main() {
	rb := must(ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 1 << 20}))
	first := must(ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: 8192}))
	// cgroup_attach_task(dst_cgrp, path, task, threadgroup): ctx[1] = path
	attachProg := must(ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Tracing, AttachType: ebpf.AttachTraceRawTp, AttachTo: "cgroup_attach_task", License: "GPL",
		Instructions: asm.Instructions{
			asm.LoadMem(asm.R3, asm.R1, 8, asm.DWord), // path
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, -128),
			asm.Mov.Imm(asm.R2, 120),
			asm.FnProbeReadKernelStr.Call(),
			asm.FnKtimeGetNs.Call(),
			asm.StoreMem(asm.RFP, -136, asm.R0, asm.DWord),
			mapPtr(rb),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -136),
			asm.Mov.Imm(asm.R3, 128),
			asm.Mov.Imm(asm.R4, 0),
			asm.FnRingbufOutput.Call(),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	}))
	sendProg := must(ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Tracing, AttachType: ebpf.AttachTraceRawTp, AttachTo: "sock_send_length", License: "GPL",
		Instructions: asm.Instructions{
			asm.LoadMem(asm.R6, asm.R1, 0, asm.DWord),
			asm.LoadMem(asm.R2, asm.R6, 16, asm.Half),
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
			asm.Mov.Imm(asm.R4, 1),
			asm.FnMapUpdateElem.Call(),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("out"),
			asm.Return(),
		},
	}))
	l1 := must(link.AttachTracing(link.TracingOptions{Program: attachProg}))
	l2 := must(link.AttachTracing(link.TracingOptions{Program: sendProg}))

	var rt unix.Timespec
	unix.ClockGettime(unix.CLOCK_REALTIME, &rt)
	offset := rt.Nano() - mono() // realtime = mono + offset

	var mu sync.Mutex
	rawCount := 0
	var rawSeen []string
	attach := map[string]int64{} // pid -> first attach to its own uid_X/pid_Y cgroup
	attachUID := map[string]string{}
	pathRe := regexp.MustCompile(`^/(apps|system)/uid_(\d+)/pid_(\d+)$`)
	rd := must(ringbuf.NewReader(rb))
	go func() {
		for {
			r, err := rd.Read()
			if err != nil {
				return
			}
			ts := int64(binary.LittleEndian.Uint64(r.RawSample[0:8]))
			p := string(bytes.TrimRight(r.RawSample[8:], "\x00"))
			if i := bytes.IndexByte(r.RawSample[8:], 0); i >= 0 {
				p = string(r.RawSample[8 : 8+i])
			}
			mu.Lock()
			rawCount++
			if len(rawSeen) < 15 {
				rawSeen = append(rawSeen, p)
			}
			mu.Unlock()
			if m := pathRe.FindStringSubmatch(p); m != nil {
				mu.Lock()
				if _, ok := attach[m[3]]; !ok {
					attach[m[3]] = ts
					attachUID[m[3]] = m[2]
				}
				mu.Unlock()
			}
		}
	}()

	var starts []startEv
	lc := exec.Command("logcat", "-b", "events", "-v", "epoch", "-T", "1")
	out, _ := lc.StdoutPipe()
	lc.Start()
	evRe := regexp.MustCompile(`^\s*([\d.]+)\s.*am_proc_start: \[\d+,(\d+),(\d+),([^,]+),([^,]+),\{?([^/}]*)`)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			arrive := mono()
			if m := evRe.FindStringSubmatch(sc.Text()); m != nil {
				ts, _ := strconv.ParseFloat(m[1], 64)
				mu.Lock()
				starts = append(starts, startEv{int64(ts*1e9) - offset, arrive, m[2], m[3], m[4], m[6]})
				mu.Unlock()
			}
		}
	}()
	time.Sleep(time.Second)
	for _, a := range strings.Split(os.Args[1], ",") {
		exec.Command("/system/bin/sh", "-c", "am force-stop "+a+"; monkey -p "+a+" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1").Run()
		time.Sleep(7 * time.Second)
	}
	l1.Close()
	l2.Close()
	lc.Process.Kill()
	time.Sleep(300 * time.Millisecond)
	rd.Close()

	cgPid := map[uint64]string{}
	filepath.WalkDir("/sys/fs/cgroup", func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			if m := pathRe.FindStringSubmatch(strings.TrimPrefix(p, "/sys/fs/cgroup")); m != nil {
				var st syscall.Stat_t
				if syscall.Stat(p, &st) == nil {
					cgPid[st.Ino] = m[3]
				}
			}
		}
		return nil
	})
	firstSend := map[string]int64{}
	var k, v uint64
	it := first.Iterate()
	for it.Next(&k, &v) {
		if pid, ok := cgPid[k]; ok {
			firstSend[pid] = int64(v)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	sort.Slice(starts, func(i, j int) bool { return starts[i].writtenMono < starts[j].writtenMono })
	ms := func(d int64) string { return fmt.Sprintf("%8.2f", float64(d)/1e6) }
	fmt.Printf("RAW attach events=%d samples=%q\n", rawCount, rawSeen)
	fmt.Println("all times in ms relative to am_proc_start written; ready = max(cgroup attach, event arrival)")
	fmt.Println("   attach   arrive    ready  1stSend   uid    process (component pkg)")
	for _, s := range starts {
		a, okA := attach[s.pid]
		attachStr := "     n/a"
		ready := s.arriveMono
		if okA {
			attachStr = ms(a - s.writtenMono)
			if a > ready {
				ready = a
			}
			if attachUID[s.pid] != s.uid {
				attachStr += "!uid"
			}
		}
		fs := "        -"
		if f, ok := firstSend[s.pid]; ok {
			fs = ms(f - s.writtenMono)
		}
		fmt.Printf(" %s %s %s %s  %-6s %s (%s)\n", attachStr, ms(s.arriveMono-s.writtenMono), ms(ready-s.writtenMono), fs, s.uid, s.name, s.comp)
	}
}
