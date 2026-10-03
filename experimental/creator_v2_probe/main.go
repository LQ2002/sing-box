// creator_v2_probe checks, on the real device, the facts the socket creator v2
// design depends on (ANDROID_ATTRIBUTION_PLAN.md, "Claude 目标设计"):
//
//	capture  load the v2 reads at tp_btf/sbo_identity_socket_create and compare
//	         every captured argv[0] / exe inode with /proc at that moment
//	netd     borrow netd's cookie_tag_map from a TC program inside a private
//	         network namespace (run under `unshare -n`)
//	procs    compare live argv[0] with `dumpsys activity processes`
//
// It never touches the production sing-box process, its config or modules.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: creator-v2-probe capture|netd|procs [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "capture":
		err = runCapture(os.Args[2:])
	case "netd":
		err = runNetd(os.Args[2:])
	case "procs":
		err = runProcs(os.Args[2:])
	case "netdscan":
		err = runNetdScan()
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------- capture

type event struct {
	Cookie      uint64
	StartTimeNs uint64
	NameHash    uint64
	ExeInode    uint64
	ArgStart    uint64
	ArgEnd      uint64
	CostNs      uint64
	PID         uint32
	TID         uint32
	UID         uint32
	Flags       uint32
	ArgvRC      int32
	Family      uint16
	Reserved    uint16
	Comm        [16]byte
	Argv        [128]byte
}

const (
	evMM   = 1 << 0
	evArgv = 1 << 1
	evExe  = 1 << 2
)

var _ [224]byte = [unsafe.Sizeof(event{})]byte{}

type record struct {
	PID        uint32 `json:"pid"`
	TID        uint32 `json:"tid"`
	UID        uint32 `json:"uid"`
	Comm       string `json:"comm"`
	Argv0      string `json:"argv0"`
	ArgvRC     int32  `json:"argv_rc"`
	BlockLen   uint64 `json:"block_len"`
	Flags      uint32 `json:"flags"`
	HashOK     bool   `json:"hash_ok"`
	ProcArgv0  string `json:"proc_argv0"`
	ArgvResult string `json:"argv_result"`
	ExeInode   uint64 `json:"exe_inode"`
	ProcInode  uint64 `json:"proc_inode"`
	ProcExe    string `json:"proc_exe"`
	ExeResult  string `json:"exe_result"`
	CostNs     uint64 `json:"cost_ns"`
	StartNs    uint64 `json:"start_time_ns"`
	AgeMs      int64  `json:"process_age_ms"`
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func fnv1a(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

func runCapture(args []string) error {
	flags := flag.NewFlagSet("capture", flag.ExitOnError)
	object := flags.String("object", "argv.bpf.o", "compiled argv probe")
	duration := flags.Duration("duration", 120*time.Second, "capture duration")
	output := flags.String("out", "capture.jsonl", "per-event JSON lines")
	_ = flags.Parse(args)

	spec, err := ebpf.LoadCollectionSpec(*object)
	if err != nil {
		return err
	}
	var collection *ebpf.Collection
	collection, err = ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats, LogSizeStart: 1 << 20},
	})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("VERIFIER_REJECTED\n%+v\n", verr)
		}
		return err
	}
	defer collection.Close()
	program := collection.Programs["probe_argv"]
	fmt.Printf("VERIFIER_ACCEPTED program=probe_argv insns=%d\n", len(spec.Programs["probe_argv"].Instructions))
	if program.VerifierLog != "" {
		lines := strings.Split(strings.TrimSpace(program.VerifierLog), "\n")
		fmt.Println("VERIFIER_STATS", lines[len(lines)-1])
	}
	attached, err := link.AttachTracing(link.TracingOptions{Program: program})
	if err != nil {
		return fmt.Errorf("attach tp_btf: %w", err)
	}
	defer attached.Close()
	reader, err := ringbuf.NewReader(collection.Maps["events"])
	if err != nil {
		return err
	}
	defer reader.Close()
	file, err := os.Create(*output)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	defer writer.Flush()
	encoder := json.NewEncoder(writer)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	deadline := time.Now().Add(*duration)
	go func() {
		select {
		case <-stop:
		case <-time.After(*duration):
		}
		_ = reader.Close()
	}()
	fmt.Printf("CAPTURING until %s\n", deadline.Format(time.RFC3339))

	summary := map[string]int{}
	blockLens := map[uint64]int{}
	mismatches := []record{}
	var item ringbuf.Record
	for {
		if err = reader.ReadInto(&item); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			return err
		}
		var ev event
		if err = binary.Read(bytes.NewReader(item.RawSample), binary.LittleEndian, &ev); err != nil {
			return err
		}
		// /proc is read immediately; the process may already have exited or
		// exec'd, which is reported separately, never counted as a mismatch.
		rec := record{
			PID: ev.PID, TID: ev.TID, UID: ev.UID, Comm: cString(ev.Comm[:]),
			Argv0: cString(ev.Argv[:]), ArgvRC: ev.ArgvRC, Flags: ev.Flags,
			ExeInode: ev.ExeInode, CostNs: ev.CostNs, StartNs: ev.StartTimeNs,
		}
		// Process age at capture time: CLOCK_BOOTTIME now minus leader birth.
		var now unix.Timespec
		if unix.ClockGettime(unix.CLOCK_BOOTTIME, &now) == nil && ev.StartTimeNs > 0 {
			rec.AgeMs = (now.Nano() - int64(ev.StartTimeNs)) / 1e6
		}
		if ev.ArgEnd > ev.ArgStart {
			rec.BlockLen = ev.ArgEnd - ev.ArgStart
		}
		rec.HashOK = ev.Flags&evArgv == 0 || fnv1a(rec.Argv0) == ev.NameHash
		cmdline, cmdErr := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", ev.PID))
		switch {
		case ev.Flags&evMM == 0:
			rec.ArgvResult = "no_mm"
		case ev.Flags&evArgv == 0:
			rec.ArgvResult = fmt.Sprintf("read_failed_rc_%d", ev.ArgvRC)
		case cmdErr != nil:
			rec.ArgvResult = "proc_gone"
		default:
			rec.ProcArgv0 = cString(cmdline)
			switch {
			case rec.ProcArgv0 == rec.Argv0:
				rec.ArgvResult = "match"
			case len(rec.Argv0) == 127 && strings.HasPrefix(rec.ProcArgv0, rec.Argv0):
				rec.ArgvResult = "match_probe_truncated"
			default:
				rec.ArgvResult = "mismatch"
			}
		}
		var stat unix.Stat_t
		statErr := unix.Stat(fmt.Sprintf("/proc/%d/exe", ev.PID), &stat)
		rec.ProcExe, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", ev.PID))
		switch {
		case ev.Flags&evMM == 0:
			rec.ExeResult = "no_mm"
		case ev.Flags&evExe == 0:
			rec.ExeResult = "read_failed"
		case statErr != nil:
			rec.ExeResult = "proc_gone"
		default:
			rec.ProcInode = stat.Ino
			if stat.Ino == ev.ExeInode {
				rec.ExeResult = "match"
			} else {
				rec.ExeResult = "mismatch"
			}
		}
		summary["events"]++
		summary["argv_"+rec.ArgvResult]++
		summary["exe_"+rec.ExeResult]++
		if !rec.HashOK {
			summary["hash_disagrees_with_go_fnv"]++
		}
		if rec.ArgvResult == "match" && rec.BlockLen > 0 && uint64(len(rec.Argv0))+1 >= rec.BlockLen {
			summary["argv_fills_whole_block"]++
		}
		blockLens[rec.BlockLen]++
		// A zygote child that opened a socket before setArgv0 would still
		// carry the zygote's own name.
		if rec.UID%100000 >= 10000 && (strings.HasPrefix(rec.Argv0, "zygote") || strings.HasPrefix(rec.Argv0, "usap") || strings.HasSuffix(rec.Argv0, "_zygote") || rec.Argv0 == "<pre-initialized>") {
			summary["app_uid_pre_rename_name"]++
			mismatches = append(mismatches, rec)
		}
		if rec.AgeMs >= 0 && rec.AgeMs < 60000 {
			summary["process_younger_than_60s"]++
			fmt.Printf("YOUNG_PROCESS pid=%d uid=%d age_ms=%d argv0=%q result=%s\n", rec.PID, rec.UID, rec.AgeMs, rec.Argv0, rec.ArgvResult)
		}
		if rec.ArgvResult == "mismatch" || rec.ExeResult == "mismatch" || !rec.HashOK {
			mismatches = append(mismatches, rec)
		}
		if err = encoder.Encode(rec); err != nil {
			return err
		}
	}

	var counters []uint64
	names := []string{"read_ns", "fnv_ns", "word_ns", "exe_ns", "hashed_bytes", "exe_direct_ns", "clock_ns", "calls", "filtered", "no_mm", "argv_fail", "argv_empty", "exe_fail", "ring_full", "cost_ns"}
	fmt.Println("BPF_COUNTERS (summed over CPUs):")
	for index := range names {
		if err = collection.Maps["stats"].Lookup(uint32(index), &counters); err != nil {
			return err
		}
		var total uint64
		for _, value := range counters {
			total += value
		}
		fmt.Printf("  %s=%d\n", names[index], total)
		summary["bpf_"+names[index]] = int(total)
	}
	if calls := summary["bpf_calls"] - summary["bpf_filtered"]; calls > 0 {
		fmt.Printf("  avg_v2_cost_ns=%.0f\n", float64(summary["bpf_cost_ns"])/float64(calls))
		// Segment timings include one bpf_ktime_get_ns call each; cost_ns
		// covers the whole section including them.
		for _, part := range []string{"read_ns", "fnv_ns", "word_ns", "exe_ns", "exe_direct_ns", "clock_ns"} {
			fmt.Printf("  avg_%s=%.0f\n", part, float64(summary["bpf_"+part])/float64(calls))
		}
		fmt.Printf("  avg_hashed_bytes=%.1f\n", float64(summary["bpf_hashed_bytes"])/float64(calls))
	}
	keys := make([]string, 0, len(summary))
	for key := range summary {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fmt.Println("SUMMARY:")
	for _, key := range keys {
		if strings.HasPrefix(key, "bpf_") {
			continue
		}
		fmt.Printf("  %s=%d\n", key, summary[key])
	}
	lens := make([]uint64, 0, len(blockLens))
	for key := range blockLens {
		lens = append(lens, key)
	}
	sort.Slice(lens, func(i, j int) bool { return lens[i] < lens[j] })
	fmt.Print("ARG_BLOCK_LENGTHS:")
	for _, key := range lens {
		fmt.Printf(" %d:%d", key, blockLens[key])
	}
	fmt.Println()
	for index, rec := range mismatches {
		if index == 20 {
			fmt.Printf("... %d more mismatches in %s\n", len(mismatches)-20, *output)
			break
		}
		fmt.Printf("MISMATCH %+v\n", rec)
	}
	return nil
}

// ---------------------------------------------------------------- netd

const netdCookieTagPin = "/sys/fs/bpf/netd_shared/map_netd_cookie_tag_map"

type uidTag struct {
	UID uint32
	Tag uint32
}

type tagResult struct {
	Cookie   uint64
	Packets  uint64
	Found    uint32
	UID      uint32
	Tag      uint32
	Reserved uint32
}

func runNetd(args []string) error {
	flags := flag.NewFlagSet("netd", flag.ExitOnError)
	object := flags.String("object", "netdtag.bpf.o", "compiled TC probe")
	writeTag := flags.Bool("tag", true, "tag one probe-owned socket in netd's map (as libnetd_updatable's tagSocket does) and remove it afterwards")
	_ = flags.Parse(args)

	context, _ := os.ReadFile("/proc/self/attr/current")
	fmt.Printf("SELINUX_CONTEXT=%s UID=%d\n", strings.TrimRight(string(context), "\x00\n"), os.Getuid())
	netns, _ := os.Readlink("/proc/self/ns/net")
	initNetns, _ := os.Readlink("/proc/1/ns/net")
	fmt.Printf("NETNS self=%s init=%s\n", netns, initNetns)
	if netns == initNetns {
		return errors.New("refusing to attach TC in the initial network namespace; run under unshare -n")
	}

	readOnly, err := ebpf.LoadPinnedMap(netdCookieTagPin, &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("open %s read-only: %w", netdCookieTagPin, err)
	}
	defer readOnly.Close()
	info, err := readOnly.Info()
	if err != nil {
		return fmt.Errorf("map info: %w", err)
	}
	id, _ := info.ID()
	fmt.Printf("NETD_MAP_INFO name=%q id=%d type=%s key=%d value=%d max_entries=%d flags=%#x\n",
		info.Name, id, info.Type, info.KeySize, info.ValueSize, info.MaxEntries, info.Flags)
	if info.Type != ebpf.Hash || info.KeySize != 8 || info.ValueSize != 8 {
		return errors.New("netd map layout differs from HASH u64 -> {u32 uid; u32 tag}")
	}

	spec, err := ebpf.LoadCollectionSpec(*object)
	if err != nil {
		return err
	}
	// Align the placeholder spec with the real map, as sing-ebpf's loader does.
	placeholder := spec.Maps["netd_cookie_tags"]
	placeholder.MaxEntries, placeholder.Flags = info.MaxEntries, info.Flags
	placeholder.Key, placeholder.Value = nil, nil
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{"netd_cookie_tags": readOnly},
	})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("VERIFIER_REJECTED\n%+v\n", verr)
		}
		return fmt.Errorf("load TC program with read-only netd map: %w", err)
	}
	defer collection.Close()
	fmt.Println("TC_PROGRAM_LOADED with read-only netd map fd")

	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}
	if err = setLinkUp(loopback.Name); err != nil {
		return err
	}
	attached, err := link.AttachTCX(link.TCXOptions{
		Interface: loopback.Index, Program: collection.Programs["netd_tag_lookup"], Attach: ebpf.AttachTCXEgress,
	})
	if err != nil {
		return fmt.Errorf("attach tcx egress on private lo: %w", err)
	}
	defer attached.Close()

	results := collection.Maps["results"]
	send := func(label string) (tagResult, uint64, error) {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return tagResult{}, 0, err
		}
		defer unix.Close(fd)
		cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
		if err != nil {
			return tagResult{}, 0, err
		}
		var writable *ebpf.Map
		if label == "tagged" {
			writable, err = ebpf.LoadPinnedMap(netdCookieTagPin, nil)
			if err != nil {
				return tagResult{}, cookie, fmt.Errorf("open netd map writable: %w", err)
			}
			defer writable.Close()
			if err = writable.Update(&cookie, &uidTag{UID: 0, Tag: 0x5b0c2e}, ebpf.UpdateNoExist); err != nil {
				return tagResult{}, cookie, fmt.Errorf("tag probe socket: %w", err)
			}
			defer func() {
				if err := writable.Delete(&cookie); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					fmt.Println("UNTAG_FAILED", err)
				} else {
					fmt.Printf("UNTAGGED cookie=%d\n", cookie)
				}
			}()
		}
		if err = unix.Sendto(fd, []byte("netd-tag-probe"), 0, &unix.SockaddrInet4{Port: 9, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
			return tagResult{}, cookie, err
		}
		var result tagResult
		err = results.Lookup(&cookie, &result)
		return result, cookie, err
	}
	for _, label := range []string{"untagged", "tagged"} {
		if label == "tagged" && !*writeTag {
			continue
		}
		result, cookie, err := send(label)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		fmt.Printf("TC_LOOKUP %s socket_cookie=%d seen_cookie=%d packets=%d found=%d uid=%d tag=%#x\n",
			label, cookie, result.Cookie, result.Packets, result.Found, result.UID, result.Tag)
	}
	return nil
}

func setLinkUp(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	request, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err = unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, request); err != nil {
		return err
	}
	request.SetUint16(request.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, request)
}

// ---------------------------------------------------------------- procs

type processRecord struct {
	PID         int      `json:"pid"`
	Name        string   `json:"name"`
	UID         int      `json:"uid"`
	Packages    []string `json:"packages"`
	Argv0       string   `json:"argv0"`
	BlockLen    int      `json:"block_len"`
	Result      string   `json:"result"`
	Categories  []string `json:"categories"`
	NameHash    string   `json:"name_hash"`
	Argv0Hash   string   `json:"argv0_hash"`
	SameUIDPeer int      `json:"same_uid_processes"`
}

var processLine = regexp.MustCompile(`^\s*\*(APP|PERS)\*\s+UID\s+(\d+)\s+ProcessRecord\{[0-9a-f]+\s+(\d+):(.*)/([a-z0-9]+)\}`)
var packageLine = regexp.MustCompile(`^\s*packageList=\{(.*)\}`)

func runProcs(args []string) error {
	flags := flag.NewFlagSet("procs", flag.ExitOnError)
	dump := flags.String("dumpsys", "processes.txt", "output of `dumpsys activity processes`")
	output := flags.String("out", "procs.jsonl", "per-process JSON lines")
	_ = flags.Parse(args)
	content, err := os.ReadFile(*dump)
	if err != nil {
		return err
	}
	var records []*processRecord
	var current *processRecord
	for _, line := range strings.Split(string(content), "\n") {
		if match := processLine.FindStringSubmatch(line); match != nil {
			pid, _ := strconv.Atoi(match[3])
			uid, _ := strconv.Atoi(match[2])
			current = &processRecord{PID: pid, UID: uid, Name: match[4]}
			records = append(records, current)
			continue
		}
		if match := packageLine.FindStringSubmatch(line); match != nil && current != nil && current.Packages == nil {
			for _, name := range strings.Split(match[1], ",") {
				if name = strings.TrimSpace(name); name != "" {
					current.Packages = append(current.Packages, name)
				}
			}
		}
	}
	perUID := map[int]int{}
	for _, rec := range records {
		perUID[rec.UID]++
	}
	file, err := os.Create(*output)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	summary := map[string]int{}
	for _, rec := range records {
		rec.SameUIDPeer = perUID[rec.UID]
		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", rec.PID))
		if err != nil {
			rec.Result = "proc_gone"
		} else {
			rec.Argv0 = cString(cmdline)
			rec.BlockLen = argBlockLength(rec.PID)
			switch {
			case rec.Argv0 == rec.Name:
				rec.Result = "exact"
			case rec.Name == "system" && rec.Argv0 == "system_server":
				rec.Result = "system_alias"
			case strings.HasPrefix(rec.Name, rec.Argv0) && rec.BlockLen > 0 && len(rec.Argv0) == rec.BlockLen-1:
				rec.Result = "truncated_to_block"
			default:
				rec.Result = "mismatch"
			}
		}
		rec.NameHash = fmt.Sprintf("%016x", fnv1a(rec.Name))
		rec.Argv0Hash = fmt.Sprintf("%016x", fnv1a(rec.Argv0))
		appID := rec.UID % 100000
		if rec.Name == "system" {
			rec.Categories = append(rec.Categories, "system_server")
		}
		if strings.Contains(rec.Name, ":") {
			rec.Categories = append(rec.Categories, "colon_subprocess")
		}
		if len(rec.Packages) > 1 {
			rec.Categories = append(rec.Categories, "multi_package")
		}
		if appID < 10000 || perUID[rec.UID] > 1 {
			rec.Categories = append(rec.Categories, "shared_uid")
		}
		if appID >= 20000 && appID <= 29999 {
			rec.Categories = append(rec.Categories, "sdk_sandbox")
		}
		if appID >= 90000 {
			rec.Categories = append(rec.Categories, "isolated")
		}
		summary["result_"+rec.Result]++
		for _, category := range rec.Categories {
			summary[category+"_"+rec.Result]++
		}
		if err = encoder.Encode(rec); err != nil {
			return err
		}
		if rec.Result == "mismatch" || rec.Result == "truncated_to_block" || len(rec.Categories) > 0 && rec.Result != "exact" {
			fmt.Printf("PROCESS %s pid=%d uid=%d name=%q argv0=%q block=%d packages=%v categories=%v\n",
				rec.Result, rec.PID, rec.UID, rec.Name, rec.Argv0, rec.BlockLen, rec.Packages, rec.Categories)
		}
	}
	fmt.Printf("PROCESS_RECORDS=%d\n", len(records))
	keys := make([]string, 0, len(summary))
	for key := range summary {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Printf("  %s=%d\n", key, summary[key])
	}
	return nil
}

// argBlockLength reads arg_start/arg_end (fields 48/49 of /proc/<pid>/stat).
func argBlockLength(pid int) int {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	text := string(stat)
	text = text[strings.LastIndexByte(text, ')')+2:]
	fields := strings.Fields(text)
	// fields[0] is field 3 (state); field N is fields[N-3].
	if len(fields) < 47 {
		return 0
	}
	start, _ := strconv.ParseUint(fields[45], 10, 64)
	end, _ := strconv.ParseUint(fields[46], 10, 64)
	if end <= start {
		return 0
	}
	return int(end - start)
}
