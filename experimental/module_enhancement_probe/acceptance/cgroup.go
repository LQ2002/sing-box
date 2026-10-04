package main

// Cgroup probe: can the socket's cgroup (what TC reads with
// bpf_skb_cgroup_id()) stand in for a module snapshot?
//
// Android puts processes it starts into their own cgroup v2 directory
// .../uid_<uid>/pid_<pid>. The kernel stamps the creator's cgroup on every
// socket in sk_alloc (cgroup_sk_alloc), and on 64-bit the cgroup id equals
// the directory's inode number (kernfs_id_ino). So for each socket we
// compare the cgroup id seen at creation with /proc/<pid>/cgroup of the
// creator the module recorded.
//
//	cgscan  static: every process, which cgroup it is in
//	watch   per socket (cgroupTally below), alongside the path checks

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const cgroupRoot = "/sys/fs/cgroup"

var pidCgroup = regexp.MustCompile(`/uid_(\d+)/pid_(\d+)$`)

func uidClass(uid uint32) string {
	switch {
	case uid == 0:
		return "root"
	case uid < 10000:
		return "system"
	case uid < 20000:
		return "app"
	case uid >= 20000 && uid < 30000:
		return "sdk_sandbox"
	case uid >= 90000 && uid < 100000:
		return "isolated"
	}
	return "other"
}

// procCgroup returns the cgroup v2 path of pid ("0::<path>").
func procCgroup(pid int) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::"), nil
		}
	}
	return "", fmt.Errorf("no cgroup v2 line")
}

func cgroupInode(path string) uint64 {
	var st unix.Stat_t
	if unix.Stat(cgroupRoot+path, &st) != nil {
		return 0
	}
	return st.Ino
}

func ppid(pid int) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 2 {
		return 0
	}
	p, _ := strconv.Atoi(f[1])
	return p
}

// classify says how a process's cgroup relates to it:
//
//	own        .../uid_<its uid>/pid_<its pid>
//	own_uid_x  pid matches but the uid in the path differs (isolated etc.)
//	ancestor   .../pid_<an ancestor's pid> (inherited across fork)
//	other_pid  .../pid_<some pid that is not an ancestor>
//	shared     anything else (root, system, a service group ...)
func classify(pid int, uid uint32, path string) string {
	m := pidCgroup.FindStringSubmatch(path)
	if m == nil {
		return "shared"
	}
	cuid, _ := strconv.Atoi(m[1])
	cpid, _ := strconv.Atoi(m[2])
	if cpid == pid {
		if uint32(cuid) == uid {
			return "own"
		}
		return "own_uid_x"
	}
	for p, n := ppid(pid), 0; p > 1 && n < 32; p, n = ppid(p), n+1 {
		if p == cpid {
			return "ancestor"
		}
	}
	return "other_pid"
}

// sharedKey generalises a shared cgroup path for tallies.
func sharedKey(path string) string {
	return pidCgroup.ReplaceAllString(path, "/uid_N/pid_N")
}

type procInfo struct {
	PID    int    `json:"pid"`
	UID    uint32 `json:"uid"`
	Argv0  string `json:"argv0"`
	Exe    string `json:"exe"`
	Cgroup string `json:"cgroup"`
	Class  string `json:"class"`
}

func runCgscan(args []string) error {
	flags := flag.NewFlagSet("cgscan", flag.ExitOnError)
	output := flags.String("out", "cgscan.json", "per-process JSON")
	_ = flags.Parse(args)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	var procs []procInfo
	counts := map[string]map[string]int{}
	shared := map[string]int{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		var st unix.Stat_t
		if unix.Stat(fmt.Sprintf("/proc/%d", pid), &st) != nil {
			continue
		}
		cg, err := procCgroup(pid)
		if err != nil {
			continue
		}
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if exe == "" {
			continue // kernel thread
		}
		cmd, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		p := procInfo{PID: pid, UID: st.Uid, Argv0: cString(cmd), Exe: exe, Cgroup: cg}
		p.Class = classify(pid, st.Uid, cg)
		uc := uidClass(st.Uid)
		if counts[uc] == nil {
			counts[uc] = map[string]int{}
		}
		counts[uc][p.Class]++
		if p.Class == "shared" {
			shared[sharedKey(cg)]++
		}
		procs = append(procs, p)
	}
	fmt.Printf("CGSCAN processes=%d by_uid_class=%v\n", len(procs), counts)
	keys := make([]string, 0, len(shared))
	for k := range shared {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return shared[keys[i]] > shared[keys[j]] })
	for _, k := range keys {
		fmt.Printf("CGSCAN_SHARED %d %s\n", shared[k], k)
	}
	for _, p := range procs {
		if p.Class != "own" {
			fmt.Printf("CGSCAN_NOT_OWN class=%s uid=%d pid=%d argv0=%q exe=%q cgroup=%q\n", p.Class, p.UID, p.PID, p.Argv0, p.Exe, p.Cgroup)
		}
	}
	b, _ := json.MarshalIndent(procs, "", "  ")
	return os.WriteFile(*output, b, 0o644)
}

// cgroupTally accumulates the per-socket comparison during watch.
type cgroupTally struct {
	ByKind      map[string]map[string]int `json:"by_kind_uidclass_class"`
	SkTaskDiff  int                       `json:"sk_task_cgroup_differ"`
	Shared      map[string]int            `json:"shared_paths"`
	NotOwnPaths map[string]int            `json:"not_own_exe_paths"`
}

func newCgroupTally() *cgroupTally {
	return &cgroupTally{ByKind: map[string]map[string]int{}, Shared: map[string]int{}, NotOwnPaths: map[string]int{}}
}

// add classifies one socket. The cgroup ids follow the 64-byte snapshot in
// the ring-buffer record.
func (t *cgroupTally) add(raw []byte, s snapshot) {
	if len(raw) < snapshotSize+16 {
		return
	}
	skID := binary.LittleEndian.Uint64(raw[snapshotSize:])
	taskID := binary.LittleEndian.Uint64(raw[snapshotSize+8:])
	if skID != taskID {
		t.SkTaskDiff++
	}
	class := "gone"
	path, err := procCgroup(int(s.PID))
	if err == nil {
		switch ino := cgroupInode(path); {
		case ino == 0:
			class = "gone"
		case ino != skID:
			class = "moved" // creator changed cgroup after creating the socket
		default:
			class = classify(int(s.PID), s.UID, path)
		}
	}
	key := kind(s.Flags) + "/" + uidClass(s.UID)
	if t.ByKind[key] == nil {
		t.ByKind[key] = map[string]int{}
	}
	t.ByKind[key][class]++
	if class == "shared" {
		t.Shared[sharedKey(path)]++
	}
	if class != "own" && class != "gone" {
		exe := s.Path
		if s.Flags&flagApp != 0 {
			exe = appProcess
		}
		t.NotOwnPaths[class+" "+exe+" @ "+filepath.Clean(sharedKey(path))]++
	}
}
