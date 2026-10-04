// Command sbo-acceptance verifies the Stage 2 module end to end on the device:
// module tracepoint -> bpf/consumer.bpf.o (tp_btf) -> per-socket snapshot.
//
//	selftest  create sockets in this process, read each snapshot back by fd
//	          and compare it with SO_COOKIE, getpid() and /proc/self/exe
//	watch     system-wide: every event from the ring buffer is checked against
//	          /proc/<pid>/exe while the process is still alive
//	bench     socket()+close() timing, run once per module state
//	hold      production-like consumer (snapshot only, no ring buffer) held
//	          active for the benchmark's "collecting" state
//
// Every mode that needs collection opens /dev/sbo_enhancement_probe itself,
// so the module is active exactly while a mode runs.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// Module event flags (module/sbo_enhancement_trace.h).
const (
	flagApp      = 1 << 0
	flagNative   = 1 << 1
	flagTooLong  = 1 << 2
	flagDeleted  = 1 << 3
	flagError    = 1 << 4
	flagKernel   = 1 << 5
	flagCacheHit = 1 << 6

	devicePath   = "/dev/sbo_enhancement_probe"
	statsPath    = "/sys/module/sbo_enhancement_probe/parameters/stats"
	appProcess   = "/system/bin/app_process64"
	snapshotSize = 64
	pathLen      = 256
	pathValueLen = 8 + pathLen
)

var bpfStatNames = []string{"events", "duplicate", "storage_fail", "path_read_fail", "ringbuf_drop", "path_insert"}

// rawSnapshot mirrors struct snapshot in bpf/consumer.bpf.c (64 bytes).
type rawSnapshot struct {
	Cookie   uint64
	PID      uint32
	TID      uint32
	UID      uint32
	Flags    uint32
	Ino      uint64
	Dev      uint32
	Gen      uint32
	PathLen  uint32
	Reserved uint32
	Comm     [16]byte
}

// snapshot is a decoded snapshot plus its path, looked up in the `paths`
// map by (dev, ino, gen) the way a production reader would.
type snapshot struct {
	rawSnapshot
	Path        string
	PathMissing bool // native snapshot whose key has no `paths` entry
}

type pathKey struct {
	Dev uint32
	Gen uint32
	Ino uint64
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func (c *consumer) decode(raw []byte) (snapshot, error) {
	var s snapshot
	if len(raw) < snapshotSize {
		return s, fmt.Errorf("short snapshot: %d bytes", len(raw))
	}
	if err := binary.Read(bytes.NewReader(raw[:snapshotSize]), binary.LittleEndian, &s.rawSnapshot); err != nil {
		return s, err
	}
	if s.Flags&flagNative != 0 && s.PathLen > 0 {
		value := make([]byte, pathValueLen)
		key := pathKey{Dev: s.Dev, Gen: s.Gen, Ino: s.Ino}
		if err := c.coll.Maps["paths"].Lookup(&key, &value); err != nil {
			s.PathMissing = true
		} else {
			s.Path = cString(value[8:])
		}
	}
	return s, nil
}

func kind(flags uint32) string {
	switch {
	case flags&flagApp != 0:
		return "app"
	case flags&flagNative != 0 && flags&flagDeleted != 0:
		return "native_deleted"
	case flags&flagNative != 0:
		return "native"
	case flags&flagTooLong != 0:
		return "too_long"
	case flags&flagKernel != 0:
		return "kernel"
	case flags&flagError != 0:
		return "error"
	}
	return fmt.Sprintf("unknown_%#x", flags)
}

type consumer struct {
	coll *ebpf.Collection
	lnk  link.Link
	hold *os.File
}

// load attaches the consumer first, then opens the device, so no event is
// fired before a program is listening.
func load(object string, mirror bool) (*consumer, error) {
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		return nil, err
	}
	if !mirror {
		if err := spec.Variables["mirror_events"].Set(uint32(0)); err != nil {
			return nil, err
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("VERIFIER_REJECTED\n%+v\n", verr)
		}
		return nil, err
	}
	lnk, err := link.AttachTracing(link.TracingOptions{Program: coll.Programs["on_socket_identity"]})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach tp_btf: %w", err)
	}
	hold, err := os.Open(devicePath)
	if err != nil {
		lnk.Close()
		coll.Close()
		return nil, fmt.Errorf("open %s: %w", devicePath, err)
	}
	return &consumer{coll: coll, lnk: lnk, hold: hold}, nil
}

func (c *consumer) close() {
	c.hold.Close()
	c.lnk.Close()
	c.coll.Close()
}

func (c *consumer) bpfStats() map[string]uint64 {
	out := map[string]uint64{}
	for i, name := range bpfStatNames {
		var values []uint64
		if err := c.coll.Maps["stats"].Lookup(uint32(i), &values); err != nil {
			continue
		}
		var sum uint64
		for _, v := range values {
			sum += v
		}
		out[name] = sum
	}
	return out
}

func moduleStats() string {
	b, err := os.ReadFile(statsPath)
	if err != nil {
		return "unavailable: " + err.Error()
	}
	return strings.TrimSpace(string(b))
}

func fileNr() string {
	b, err := os.ReadFile("/proc/sys/fs/file-nr")
	if err != nil {
		return "?"
	}
	return strings.Fields(string(b))[0]
}

// exePath returns /proc/<pid>/exe with a trailing " (deleted)" removed.
func exePath(pid uint32) (string, bool, error) {
	p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", false, err
	}
	if strings.HasSuffix(p, " (deleted)") {
		return strings.TrimSuffix(p, " (deleted)"), true, nil
	}
	return p, false, nil
}

// check compares one snapshot with /proc. ok, gone (process exited or
// re-exec'd before we looked: cannot be judged), or a mismatch reason.
func check(s snapshot) (string, string) {
	exe, deleted, err := exePath(s.PID)
	if err != nil {
		return "gone", ""
	}
	path := s.Path
	switch {
	case s.Flags&flagNative != 0 && s.PathMissing:
		return "mismatch", "no paths entry for the snapshot's key"
	case s.Flags&flagApp != 0:
		if exe == appProcess {
			return "ok", ""
		}
		return "mismatch", "app flag but exe=" + exe
	case s.Flags&flagNative != 0:
		if exe != path {
			return "mismatch", fmt.Sprintf("path=%q exe=%q", path, exe)
		}
		if (s.Flags&flagDeleted != 0) != deleted {
			// The file may have been unlinked after the socket was created.
			if !deleted {
				return "mismatch", "deleted flag but exe not deleted"
			}
		}
		if uint32(len(path)) != s.PathLen {
			return "mismatch", fmt.Sprintf("path_len=%d len(path)=%d", s.PathLen, len(path))
		}
		return "ok", ""
	case s.Flags&flagTooLong != 0:
		full := exe
		if deleted {
			full += " (deleted)"
		}
		if len(full) >= pathLen {
			return "ok", ""
		}
		return "mismatch", fmt.Sprintf("too_long but exe has %d bytes", len(full))
	}
	return "unjudged", ""
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sbo-acceptance selftest|watch|bench [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "selftest":
		err = runSelftest(os.Args[2:])
	case "watch":
		err = runWatch(os.Args[2:])
	case "bench":
		err = runBench(os.Args[2:])
	case "hold":
		err = runHold(os.Args[2:])
	case "sockets":
		err = runSockets(os.Args[2:])
	case "cgscan":
		err = runCgscan(os.Args[2:])
	case "producercheck":
		err = runProducerCheck(os.Args[2:])
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func runSelftest(args []string) error {
	flags := flag.NewFlagSet("selftest", flag.ExitOnError)
	object := flags.String("object", "consumer.bpf.o", "consumer object")
	n := flags.Int("n", 1000, "sockets per kind")
	waitSignal := flags.Bool("wait-signal", false, "wait for SIGUSR1 before creating sockets (deleted-exe test)")
	_ = flags.Parse(args)

	c, err := load(*object, true)
	if err != nil {
		return err
	}
	defer c.close()
	if *waitSignal {
		ready := make(chan os.Signal, 1)
		signal.Notify(ready, syscall.SIGUSR1)
		fmt.Println("WAITING_FOR_SIGUSR1 pid", os.Getpid())
		<-ready
	}
	self, selfDeleted, err := exePath(uint32(os.Getpid()))
	if err != nil {
		return err
	}
	full := self
	if selfDeleted {
		full += " (deleted)"
	}
	want := uint32(flagNative)
	switch {
	case len(full) >= pathLen:
		want = flagTooLong
	case selfDeleted:
		want = flagNative | flagDeleted
	}
	fmt.Printf("SELF exe=%q bytes=%d deleted=%v expect=%s\n", self, len(full), selfDeleted, kind(want))

	kinds := []struct {
		name         string
		family, kind int
	}{
		{"tcp4", unix.AF_INET, unix.SOCK_STREAM}, {"udp4", unix.AF_INET, unix.SOCK_DGRAM},
		{"tcp6", unix.AF_INET6, unix.SOCK_STREAM}, {"udp6", unix.AF_INET6, unix.SOCK_DGRAM},
	}
	failures := 0
	for _, k := range kinds {
		fds := make([]int, 0, *n)
		for i := 0; i < *n; i++ {
			fd, err := unix.Socket(k.family, k.kind|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				return err
			}
			fds = append(fds, fd)
		}
		counts := map[string]int{}
		for _, fd := range fds {
			raw := make([]byte, snapshotSize)
			if err := c.coll.Maps["snapshots"].Lookup(uint32(fd), &raw); err != nil {
				counts["missing"]++
				continue
			}
			s, err := c.decode(raw)
			if err != nil {
				return err
			}
			cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
			if err != nil {
				return err
			}
			path := s.Path
			switch {
			case s.Cookie != cookie:
				counts["bad_cookie"]++
			case s.PID != uint32(os.Getpid()):
				counts["bad_pid"]++
			case s.Flags&^flagCacheHit != want:
				counts[fmt.Sprintf("bad_flags_%#x", s.Flags)]++
			case want&flagNative != 0 && path != self:
				counts["bad_path"]++
			case want == flagTooLong && s.PathLen != 0:
				counts["bad_path_len"]++
			default:
				counts["ok"]++
				if s.Flags&flagCacheHit != 0 {
					counts["ok_cache_hit"]++
				}
			}
		}
		for _, fd := range fds {
			unix.Close(fd)
		}
		bad := len(fds) - counts["ok"]
		failures += bad
		fmt.Printf("SELFTEST kind=%s n=%d %v\n", k.name, len(fds), counts)
	}
	// Stage 1 semantics: accepted children inherit the listener's snapshot
	// through BPF_F_CLONE and are recognised by the cookie mismatch.
	bad, err := acceptTest(c, 200)
	if err != nil {
		return err
	}
	failures += bad
	// Non-inet sockets must be skipped by the module: no snapshot at all.
	ufd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	raw := make([]byte, snapshotSize)
	unixErr := c.coll.Maps["snapshots"].Lookup(uint32(ufd), &raw)
	unix.Close(ufd)
	fmt.Printf("SELFTEST unix_socket_snapshot_absent=%v (%v)\n", unixErr != nil, unixErr)
	if unixErr == nil {
		failures++
	}
	fmt.Printf("SELFTEST_BPF_STATS %v\n", c.bpfStats())
	fmt.Printf("SELFTEST_MODULE_STATS %s\n", moduleStats())
	if failures != 0 {
		return fmt.Errorf("selftest: %d failures", failures)
	}
	fmt.Println("SELFTEST_PASS")
	return nil
}

type pathTally struct {
	Path   string         `json:"path"`
	Kind   string         `json:"kind"`
	Events int            `json:"events"`
	Hits   int            `json:"cache_hits"`
	UIDs   map[uint32]int `json:"uids"`
	Comms  map[string]int `json:"comms"`
}

func runWatch(args []string) error {
	flags := flag.NewFlagSet("watch", flag.ExitOnError)
	object := flags.String("object", "consumer.bpf.o", "consumer object")
	duration := flags.Duration("duration", time.Hour, "watch duration")
	interval := flags.Duration("interval", time.Minute, "progress interval")
	output := flags.String("out", "watch-summary.json", "summary JSON")
	_ = flags.Parse(args)

	c, err := load(*object, true)
	if err != nil {
		return err
	}
	defer c.close()
	reader, err := ringbuf.NewReader(c.coll.Maps["events"])
	if err != nil {
		return err
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-stop:
		case <-time.After(*duration):
		}
		reader.Close()
	}()
	start := time.Now()
	fmt.Printf("WATCHING duration=%s file_nr=%s module=%s\n", *duration, fileNr(), moduleStats())

	kinds := map[string]int{}
	printed := map[string]int{}
	verdicts := map[string]map[string]int{}
	tallies := map[string]*pathTally{}
	cg := newCgroupTally()
	var mismatches []map[string]any
	total := 0
	next := start.Add(*interval)
	var rec ringbuf.Record
	for {
		reader.SetDeadline(next)
		err := reader.ReadInto(&rec)
		if errors.Is(err, os.ErrDeadlineExceeded) || time.Now().After(next) {
			fmt.Printf("PROGRESS t=%s events=%d kinds=%v verdicts=%v bpf=%v file_nr=%s module=%s\n",
				time.Since(start).Round(time.Second), total, kinds, verdicts, c.bpfStats(), fileNr(), moduleStats())
			next = next.Add(*interval)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
		}
		if errors.Is(err, ringbuf.ErrClosed) {
			break
		}
		if err != nil {
			return err
		}
		s, err := c.decode(rec.RawSample)
		if err != nil {
			return err
		}
		total++
		cg.add(rec.RawSample, s)
		k := kind(s.Flags)
		kinds[k]++
		verdict, reason := check(s)
		if verdicts[k] == nil {
			verdicts[k] = map[string]int{}
		}
		verdicts[k][verdict]++
		comm := cString(s.Comm[:])
		path := s.Path
		if verdict == "mismatch" && len(mismatches) < 200 {
			mismatches = append(mismatches, map[string]any{"pid": s.PID, "uid": s.UID, "comm": comm,
				"flags": s.Flags, "path": path, "reason": reason})
		}
		if (k == "native_deleted" || k == "too_long" || k == "error" || k == "kernel" ||
			(k == "native" && s.UID >= 10000)) && printed[k] < 5 {
			printed[k]++
			fmt.Printf("EVENT kind=%s pid=%d uid=%d comm=%s path=%q verdict=%s %s\n", k, s.PID, s.UID, comm, path, verdict, reason)
		}
		key := k + "\x00" + path
		t := tallies[key]
		if t == nil {
			t = &pathTally{Path: path, Kind: k, UIDs: map[uint32]int{}, Comms: map[string]int{}}
			tallies[key] = t
		}
		t.Events++
		if s.Flags&flagCacheHit != 0 {
			t.Hits++
		}
		t.UIDs[s.UID]++
		if len(t.Comms) < 8 {
			t.Comms[comm]++
		}
	}
	list := make([]*pathTally, 0, len(tallies))
	for _, t := range tallies {
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Events > list[j].Events })
	summary := map[string]any{
		"seconds": time.Since(start).Seconds(), "events": total, "kinds": kinds, "verdicts": verdicts,
		"bpf": c.bpfStats(), "module": moduleStats(), "file_nr_end": fileNr(),
		"paths": list, "mismatches": mismatches, "cgroup": cg,
	}
	b, _ := json.MarshalIndent(summary, "", "  ")
	if err := os.WriteFile(*output, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("CGROUP by_kind=%v sk_task_differ=%d shared=%v\n", cg.ByKind, cg.SkTaskDiff, cg.Shared)
	fmt.Printf("WATCH_DONE events=%d kinds=%v verdicts=%v bpf=%v module=%s distinct_paths=%d mismatches=%d\n",
		total, kinds, verdicts, c.bpfStats(), moduleStats(), len(list), len(mismatches))
	return nil
}

// runBench times socket()+close() on a locked OS thread; the caller pins the
// CPU and alternates module states between runs.
func runBench(args []string) error {
	flags := flag.NewFlagSet("bench", flag.ExitOnError)
	n := flags.Int("n", 20000, "sockets per round")
	rounds := flags.Int("rounds", 5, "rounds")
	label := flags.String("label", "", "state label")
	_ = flags.Parse(args)
	runtime.LockOSThread()
	per := make([]float64, 0, *rounds)
	for r := 0; r < *rounds; r++ {
		start := time.Now()
		for i := 0; i < *n; i++ {
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				return err
			}
			unix.Close(fd)
		}
		per = append(per, float64(time.Since(start).Nanoseconds())/float64(*n))
	}
	sorted := append([]float64(nil), per...)
	sort.Float64s(sorted)
	fmt.Printf("BENCH label=%s n=%d rounds=%d median=%.0f min=%.0f max=%.0f all=%.0f\n",
		*label, *n, *rounds, sorted[len(sorted)/2], sorted[0], sorted[len(sorted)-1], per)
	return nil
}

func runHold(args []string) error {
	flags := flag.NewFlagSet("hold", flag.ExitOnError)
	object := flags.String("object", "consumer.bpf.o", "consumer object")
	duration := flags.Duration("duration", time.Minute, "how long to hold")
	_ = flags.Parse(args)
	c, err := load(*object, false)
	if err != nil {
		return err
	}
	defer c.close()
	fmt.Println("HOLDING")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-stop:
	case <-time.After(*duration):
	}
	fmt.Printf("HOLD_DONE bpf=%v\n", c.bpfStats())
	return nil
}

func lookup(c *consumer, fd int) (snapshot, error) {
	raw := make([]byte, snapshotSize)
	if err := c.coll.Maps["snapshots"].Lookup(uint32(fd), &raw); err != nil {
		return snapshot{}, err
	}
	return c.decode(raw)
}

func acceptTest(c *consumer, n int) (int, error) {
	ln, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(ln)
	if err := unix.Bind(ln, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		return 0, err
	}
	if err := unix.Listen(ln, n); err != nil {
		return 0, err
	}
	addr, err := unix.Getsockname(ln)
	if err != nil {
		return 0, err
	}
	lnCookie, err := unix.GetsockoptUint64(ln, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		return 0, err
	}
	lnSnap, err := lookup(c, ln)
	if err != nil || lnSnap.Cookie != lnCookie {
		return 1, fmt.Errorf("listener snapshot missing or wrong: %v", err)
	}
	counts := map[string]int{}
	for i := 0; i < n; i++ {
		cl, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return 0, err
		}
		if err := unix.Connect(cl, addr); err != nil {
			unix.Close(cl)
			return 0, err
		}
		child, _, err := unix.Accept4(ln, unix.SOCK_CLOEXEC)
		if err != nil {
			unix.Close(cl)
			return 0, err
		}
		childCookie, _ := unix.GetsockoptUint64(child, unix.SOL_SOCKET, unix.SO_COOKIE)
		clCookie, _ := unix.GetsockoptUint64(cl, unix.SOL_SOCKET, unix.SO_COOKIE)
		cs, cerr := lookup(c, child)
		ks, kerr := lookup(c, cl)
		switch {
		case kerr != nil || ks.Cookie != clCookie:
			counts["client_bad"]++
		case cerr != nil:
			counts["child_missing"]++
		case cs.Cookie == childCookie:
			counts["child_not_marked_inherited"]++
		case cs.Cookie != lnCookie || cs.PID != lnSnap.PID || cs.Path != lnSnap.Path:
			counts["child_not_listener_copy"]++
		default:
			counts["ok_inherited"]++
		}
		unix.Close(child)
		unix.Close(cl)
	}
	fmt.Printf("SELFTEST kind=accept n=%d %v\n", n, counts)
	return n - counts["ok_inherited"], nil
}

// runSockets needs no privileges: it only creates inet sockets and keeps
// them open, so a concurrent `watch` can check the snapshots while this
// process is alive. Used to run a copy of this binary as an app UID from a
// /data/app-shaped path.
func runSockets(args []string) error {
	flags := flag.NewFlagSet("sockets", flag.ExitOnError)
	n := flags.Int("n", 20, "sockets to create")
	hold := flags.Duration("hold", 3*time.Second, "keep them open this long")
	_ = flags.Parse(args)
	fds := make([]int, 0, *n)
	for i := 0; i < *n; i++ {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		fds = append(fds, fd)
	}
	exe, _ := os.Readlink("/proc/self/exe")
	fmt.Printf("SOCKETS pid=%d uid=%d n=%d exe=%q bytes=%d\n", os.Getpid(), os.Getuid(), len(fds), exe, len(exe))
	time.Sleep(*hold)
	for _, fd := range fds {
		unix.Close(fd)
	}
	return nil
}

func errorsAs(err error, target any) bool { return errors.As(err, target) }
