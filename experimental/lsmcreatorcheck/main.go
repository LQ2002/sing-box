//go:build linux

// Command lsmcreatorcheck checks the socket creator collector on a device:
// which source it attaches, the snapshot of sockets made by this process and
// by children in chosen situations, and the per-socket cost.
//
// It uses its own pin directory, never the default one, and removes it
// (Remove + rmdir) before exiting. Cgroups it creates live under
// /sys/fs/cgroup/sb_lsmcheck and are removed too. Run as root:
//
//	./lsmcreatorcheck -dir /data/local/tmp/lsmcheck
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/socketidentity"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	pinPath    = "/sys/fs/bpf/sb-lsmcheck/creator"
	cgroupRoot = "/sys/fs/cgroup/sb_lsmcheck"
)

func main() {
	child := flag.String("child", "", "internal: socket | bench")
	count := flag.Int("n", 20000, "sockets per benchmark run")
	rounds := flag.Int("rounds", 3, "benchmark rounds per state")
	cpu := flag.Int("cpu", 4, "CPU the benchmark is pinned to")
	dir := flag.String("dir", "/data/local/tmp/lsmcheck", "scratch directory for executable copies")
	profile := flag.String("profile", "", "only run the stage-timed object built by profile/build.sh")
	ab := flag.Bool("ab", true, "also time socket()+close() attached vs detached (noisy without a locked frequency)")
	flag.Parse()
	switch *child {
	case "socket":
		childSocket()
		return
	case "bench":
		childBench(*count, *cpu)
		return
	}
	if *profile != "" {
		if err := runProfile(*profile, *count, *rounds, *cpu); err != nil {
			fmt.Println("FAIL:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(*dir, *count, *rounds, *cpu, *ab); err != nil {
		fmt.Println("FAIL:", err)
		os.Exit(1)
	}
}

func run(dir string, count, rounds, cpu int, ab bool) (result error) {
	defer func() {
		result = errors.Join(result, cleanup())
	}()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cgroup, _ := os.ReadFile("/proc/self/cgroup")
	fmt.Printf("kernel %s; own cgroup %q\n", strings.TrimSpace(readFile("/proc/sys/kernel/version")), lastLine(cgroup))
	fmt.Println("module capturing:", socketidentity.ModuleCapturing())

	collector, err := socketidentity.Open(socketidentity.Config{PinPath: pinPath})
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	fmt.Println("source:", collector.Source(), "skipped:", collector.SkippedSources())
	creators := collector.Map()

	failures := 0
	check := func(name string, ok bool, detail string) {
		state := "ok  "
		if !ok {
			state = "FAIL"
			failures++
		}
		fmt.Printf("  [%s] %-34s %s\n", state, name, detail)
	}

	// 1. This process (root cgroup): one socket per family/type.
	fmt.Println("== this process")
	exe, _ := os.Readlink("/proc/self/exe")
	for _, kind := range []struct {
		name           string
		family, typ    int
	}{{"inet udp", unix.AF_INET, unix.SOCK_DGRAM}, {"inet tcp", unix.AF_INET, unix.SOCK_STREAM}, {"inet6 udp", unix.AF_INET6, unix.SOCK_DGRAM}, {"inet6 tcp", unix.AF_INET6, unix.SOCK_STREAM}} {
		fd, err := unix.Socket(kind.family, kind.typ|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		creator, err := lookup(creators, fd)
		check(kind.name+" snapshot", err == nil && creator.Valid(), describe(creator, err))
		if err == nil {
			verifySelf(check, collector, creator, exe)
		}
		unix.Close(fd)
	}
	// Non-inet sockets get none.
	if fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err == nil {
		_, err := lookup(creators, fd)
		check("unix socket skipped", errors.Is(err, ebpf.ErrKeyNotExist) || err != nil, fmt.Sprint(err))
		unix.Close(fd)
	}

	// 2. Children in chosen situations.
	fmt.Println("== children")
	if err := os.MkdirAll(cgroupRoot, 0o755); err != nil {
		return fmt.Errorf("cgroup root: %w", err)
	}
	type situation struct {
		name     string
		exe      string
		cgroup   func(pid int) string // "" = stay in this cgroup
		deleted  bool
		snapshot bool
	}
	copyTo := func(path string) string {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			panic(err)
		}
		data, err := os.ReadFile(self)
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(path, data, 0o700); err != nil {
			panic(err)
		}
		return path
	}
	longDir := dir
	for len(longDir) < 300 {
		longDir = filepath.Join(longDir, strings.Repeat("d", 40))
	}
	situations := []situation{
		{name: "own pid_ cgroup (gate)", exe: self, cgroup: func(pid int) string { return "pid_" + strconv.Itoa(pid) }, snapshot: false},
		{name: "pid_ cgroup of another pid", exe: self, cgroup: func(pid int) string { return "pid_" + strconv.Itoa(pid+1) }, snapshot: true},
		{name: "non-pid cgroup", exe: self, cgroup: func(int) string { return "uid_0" }, snapshot: true},
		{name: "same cgroup as parent", exe: self, snapshot: true},
		{name: "deleted executable", exe: copyTo(filepath.Join(dir, "deleted-copy")), deleted: true, snapshot: true},
		{name: "path >= 256 bytes", exe: copyTo(filepath.Join(longDir, "long-copy")), snapshot: true},
	}
	for _, s := range situations {
		fd, pid, childExe, err := spawnSocketChild(s.exe, s.cgroup, s.deleted)
		if err != nil {
			check(s.name, false, err.Error())
			continue
		}
		creator, err := lookup(creators, fd)
		if !s.snapshot {
			check(s.name, errors.Is(err, ebpf.ErrKeyNotExist), "want no snapshot: "+describe(creator, err))
			unix.Close(fd)
			continue
		}
		ok := err == nil && creator.Valid() && creator.ProcessID == uint32(pid)
		check(s.name, ok, describe(creator, err))
		if ok {
			path, found := collector.LookupPath(creator.ExeInode)
			switch {
			case s.deleted:
				check("  deleted flag and path", creator.Flags&socketidentity.CreatorExeDeleted != 0 && found && path.String() == s.exe && path.Flags&socketidentity.CreatorExeDeleted != 0,
					fmt.Sprintf("flags=%#x path=%q (child saw %q)", creator.Flags, path.String(), childExe))
			case len(s.exe) >= 256:
				check("  too-long flag, no path", creator.Flags&socketidentity.CreatorPathTooLong != 0 && creator.Flags&socketidentity.CreatorExeKey != 0 && !found,
					fmt.Sprintf("flags=%#x len=%d stored=%t", creator.Flags, len(s.exe), found))
			default:
				check("  path", found && path.String() == s.exe, fmt.Sprintf("%q", path.String()))
			}
		}
		unix.Close(fd)
	}

	// 3. Per-socket cost: socket()+close() with and without the producer,
	// in this process's cgroup (full path) and in an own pid_ cgroup (gate).
	fmt.Printf("== cost: %d x socket(AF_INET,SOCK_DGRAM)+close on CPU %d, ns/socket\n", count, cpu)
	type state struct {
		name     string
		attached bool
	}
	results := map[string][]float64{}
	open := true
	abRounds := rounds
	if !ab {
		abRounds = 0
	}
	for round := 0; round < abRounds; round++ {
		for _, st := range []state{{"attached", true}, {"detached", false}} {
			if st.attached && !open {
				if collector, err = socketidentity.Open(socketidentity.Config{PinPath: pinPath}); err != nil {
					return err
				}
				open = true
			}
			if !st.attached && open {
				collector.Close()
				if err := socketidentity.Remove(pinPath); err != nil {
					return err
				}
				open = false
			}
			for _, place := range []string{"root cgroup", "own pid_ cgroup"} {
				var cg func(int) string
				if place != "root cgroup" {
					cg = func(pid int) string { return "pid_" + strconv.Itoa(pid) }
				}
				ns, err := spawnBench(self, cg, count, cpu)
				if err != nil {
					return err
				}
				key := place + " " + st.name
				results[key] = append(results[key], ns)
			}
		}
	}
	for _, place := range []string{"root cgroup", "own pid_ cgroup"} {
		a, d := results[place+" attached"], results[place+" detached"]
		fmt.Printf("  %-16s attached %v  detached %v  delta(median) %.0f\n", place, round1(a), round1(d), median(a)-median(d))
	}

	// The program's own run time, from the kernel's BPF statistics
	// (BPF_ENABLE_STATS: on only while the returned fd is open, no sysctl
	// change). It excludes the trampoline's enter/exit, which the A/B above
	// includes but cannot resolve on an unlocked-frequency phone.
	if !open {
		if collector, err = socketidentity.Open(socketidentity.Config{PinPath: pinPath}); err != nil {
			return err
		}
		open = true
	}
	stats, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		return fmt.Errorf("enable BPF stats: %w", err)
	}
	program, err := producerProgram()
	if err != nil {
		stats.Close()
		return err
	}
	fmt.Println("== producer run time (kernel BPF stats), ns per invocation")
	for round := 0; round < rounds; round++ {
		for _, place := range []string{"root cgroup", "own pid_ cgroup"} {
			var cg func(int) string
			if place != "root cgroup" {
				cg = func(pid int) string { return "pid_" + strconv.Itoa(pid) }
			}
			before, _ := programStats(program)
			if _, err := spawnBench(self, cg, count, cpu); err != nil {
				stats.Close()
				return err
			}
			after, _ := programStats(program)
			runs := after.count - before.count
			fmt.Printf("  %-16s runs %d  %.0f ns\n", place, runs, float64(after.ns-before.ns)/float64(max(runs, 1)))
		}
	}
	stats.Close()
	program.Close()
	if open {
		collector.Close()
	}
	if failures > 0 {
		return fmt.Errorf("%d check(s) failed", failures)
	}
	fmt.Println("all checks passed")
	return nil
}

func verifySelf(check func(string, bool, string), collector *socketidentity.Collector, c socketidentity.Creator, exe string) {
	stat := readFile("/proc/self/stat")
	fields := strings.Fields(stat[strings.LastIndexByte(stat, ')')+1:])
	ticks, _ := strconv.ParseUint(fields[19], 10, 64) // starttime, field 22
	cmdline, _ := os.ReadFile("/proc/self/cmdline")
	argv0 := cmdline
	if i := bytes.IndexByte(cmdline, 0); i >= 0 {
		argv0 = cmdline[:i]
	}
	n := c.NameLength()
	hashOK := n > 0 && n <= len(argv0) && fnv(argv0[:n]) == c.ProcessNameHash
	path, found := collector.LookupPath(c.ExeInode)
	var st unix.Stat_t
	_ = unix.Stat(exe, &st)
	ok := c.ProcessID == uint32(os.Getpid()) && c.UserID == uint32(os.Getuid()) &&
		c.StartTimeNs/10_000_000 == ticks && hashOK &&
		c.Flags&socketidentity.CreatorExeKey != 0 && found && path.String() == exe && path.Inode == st.Ino
	check("  fields match /proc", ok, fmt.Sprintf("pid=%d tid=%d uid=%d start=%dticks(proc %d) comm=%q name=%t path=%q",
		c.ProcessID, c.ThreadID, c.UserID, c.StartTimeNs/10_000_000, ticks, cstr(c.Comm[:]), hashOK, path.String()))
}

// spawnSocketChild starts exe as a socket child, optionally moves it into a
// fresh cgroup and deletes its executable, then lets it create a UDP socket
// and receives that socket.
func spawnSocketChild(exe string, cgroup func(int) string, deleteExe bool) (int, int, string, error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, 0, "", err
	}
	parentEnd, childEnd := os.NewFile(uintptr(pair[0]), "parent"), os.NewFile(uintptr(pair[1]), "child")
	defer parentEnd.Close()
	cmd := exec.Command(exe, "-child", "socket")
	cmd.ExtraFiles = []*os.File{childEnd}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		childEnd.Close()
		return -1, 0, "", err
	}
	childEnd.Close()
	pid := cmd.Process.Pid
	defer cmd.Wait()
	var cgroupDir string
	if cgroup != nil {
		cgroupDir = filepath.Join(cgroupRoot, cgroup(pid))
		if err := os.Mkdir(cgroupDir, 0o755); err != nil {
			cmd.Process.Kill()
			return -1, 0, "", err
		}
		defer os.Remove(cgroupDir) // empty again once the child has exited
		if err := os.WriteFile(filepath.Join(cgroupDir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0); err != nil {
			cmd.Process.Kill()
			return -1, 0, "", err
		}
	}
	childExe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if deleteExe {
		if err := os.Remove(exe); err != nil {
			cmd.Process.Kill()
			return -1, 0, "", err
		}
	}
	if _, err := parentEnd.Write([]byte{1}); err != nil {
		return -1, 0, "", err
	}
	buf, oob := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(int(parentEnd.Fd()), buf, oob, 0)
	if err != nil {
		return -1, 0, "", err
	}
	messages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(messages) != 1 {
		return -1, 0, "", fmt.Errorf("no fd from child: %v", err)
	}
	fds, err := unix.ParseUnixRights(&messages[0])
	if err != nil || len(fds) != 1 {
		return -1, 0, "", fmt.Errorf("no fd from child: %v", err)
	}
	// Leave the cgroup before it is removed: the child exits after sending.
	if err := cmd.Wait(); err != nil {
		return -1, 0, "", fmt.Errorf("child: %w", err)
	}
	return fds[0], pid, childExe, nil
}

func childSocket() {
	control := os.NewFile(3, "control")
	buf := make([]byte, 1)
	if _, err := control.Read(buf); err != nil {
		os.Exit(2)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		os.Exit(3)
	}
	if err := unix.Sendmsg(int(control.Fd()), []byte{1}, unix.UnixRights(fd), nil, 0); err != nil {
		os.Exit(4)
	}
}

func spawnBench(exe string, cgroup func(int) string, count, cpu int) (float64, error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	parentEnd, childEnd := os.NewFile(uintptr(pair[0]), "parent"), os.NewFile(uintptr(pair[1]), "child")
	defer parentEnd.Close()
	cmd := exec.Command(exe, "-child", "bench", "-n", strconv.Itoa(count), "-cpu", strconv.Itoa(cpu))
	cmd.ExtraFiles = []*os.File{childEnd}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		childEnd.Close()
		return 0, err
	}
	childEnd.Close()
	if cgroup != nil {
		dir := filepath.Join(cgroupRoot, cgroup(cmd.Process.Pid))
		if err := os.Mkdir(dir, 0o755); err != nil {
			cmd.Process.Kill()
			cmd.Wait()
			return 0, err
		}
		defer os.Remove(dir)
		if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(cmd.Process.Pid)), 0); err != nil {
			cmd.Process.Kill()
			cmd.Wait()
			return 0, err
		}
	}
	parentEnd.Write([]byte{1})
	if err := cmd.Wait(); err != nil {
		return 0, err
	}
	return strconv.ParseFloat(strings.TrimSpace(out.String()), 64)
}

func childBench(count, cpu int) {
	control := os.NewFile(3, "control")
	buf := make([]byte, 1)
	if _, err := control.Read(buf); err != nil {
		os.Exit(2)
	}
	var set unix.CPUSet
	set.Set(cpu)
	_ = unix.SchedSetaffinity(0, &set)
	for i := 0; i < 2000; i++ { // warm up
		fd, _ := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		unix.Close(fd)
	}
	start := time.Now()
	for i := 0; i < count; i++ {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		if err != nil {
			os.Exit(3)
		}
		unix.Close(fd)
	}
	fmt.Printf("%.1f\n", float64(time.Since(start).Nanoseconds())/float64(count))
}

// runProfile attaches the stage-timed producer (unpinned, detached on
// return) and splits its time per stage while a child creates sockets in
// this process's cgroup, so every socket takes the snapshot path.
func runProfile(path string, count, rounds, cpu int) error {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return err
	}
	var objects struct {
		Producer *ebpf.Program `ebpf:"capture_creator"`
		Prof     *ebpf.Map     `ebpf:"prof_ns"`
	}
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return err
	}
	defer objects.Producer.Close()
	defer objects.Prof.Close()
	l, err := link.AttachLSM(link.LSMOptions{Program: objects.Producer})
	if err != nil {
		return err
	}
	defer l.Close()
	self, err := os.Executable()
	if err != nil {
		return err
	}
	names := []string{"gate", "fill_creator", "argv name", "executable", "sk storage"}
	fmt.Printf("== stage split, ns per snapshot (%d sockets per round, CPU %d)\n", count, cpu)
	for round := 0; round < rounds; round++ {
		before, err := profSums(objects.Prof)
		if err != nil {
			return err
		}
		if _, err := spawnBench(self, nil, count, cpu); err != nil {
			return err
		}
		after, err := profSums(objects.Prof)
		if err != nil {
			return err
		}
		runs := after[5] - before[5]
		line := fmt.Sprintf("  runs %d:", runs)
		var total float64
		for i, name := range names {
			ns := float64(after[i]-before[i]) / float64(max(runs, 1))
			total += ns
			line += fmt.Sprintf(" %s %.0f", name, ns)
		}
		fmt.Printf("%s  total %.0f\n", line, total)
	}
	return nil
}

func profSums(m *ebpf.Map) ([8]uint64, error) {
	var sums [8]uint64
	for i := uint32(0); i < 8; i++ {
		var perCPU []uint64
		if err := m.Lookup(&i, &perCPU); err != nil {
			return sums, err
		}
		for _, v := range perCPU {
			sums[i] += v
		}
	}
	return sums, nil
}

// producerProgram opens the program behind the pinned producer link (the
// collector's "producer" pin, store_linux.go linkPin).
func producerProgram() (*ebpf.Program, error) {
	l, err := link.LoadPinnedLink(pinPath+"/producer", nil)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	info, err := l.Info()
	if err != nil {
		return nil, err
	}
	return ebpf.NewProgramFromID(info.Program)
}

type runStats struct{ count, ns uint64 }

func programStats(p *ebpf.Program) (runStats, error) {
	stats, err := p.Stats()
	if err != nil {
		return runStats{}, err
	}
	return runStats{stats.RunCount, uint64(stats.Runtime.Nanoseconds())}, nil
}

func lookup(m *ebpf.Map, fd int) (socketidentity.Creator, error) {
	var c socketidentity.Creator
	key := int32(fd)
	err := m.Lookup(&key, &c)
	return c, err
}

func describe(c socketidentity.Creator, err error) string {
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("pid=%d uid=%d comm=%q flags=%#x", c.ProcessID, c.UserID, cstr(c.Comm[:]), c.Flags)
}

func cleanup() error {
	var result error
	if err := socketidentity.Remove(pinPath); err != nil {
		result = errors.Join(result, err)
	}
	for _, path := range []string{pinPath, filepath.Dir(pinPath), cgroupRoot} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
	}
	return result
}

func fnv(data []byte) uint64 {
	hash := uint64(0xcbf29ce484222325)
	for _, b := range data {
		hash ^= uint64(b)
		hash *= 0x100000001b3
	}
	return hash
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func readFile(path string) string {
	data, _ := os.ReadFile(path)
	return string(data)
}

func lastLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return lines[len(lines)-1]
}

func median(v []float64) float64 {
	s := append([]float64(nil), v...)
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
	if len(s) == 0 {
		return 0
	}
	return s[len(s)/2]
}

func round1(v []float64) []string {
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = strconv.FormatFloat(x, 'f', 0, 64)
	}
	return out
}
