// cghandle checks, on the device, that a cgroup v2 id can be turned back into
// its cgroup directory with one open_by_handle_at call (kernfs file handle,
// FILEID_KERNFS = 0xfe, 8-byte node id; fs/kernfs/mount.c kernfs_encode_fh),
// in sing-box's SELinux domain, and how long that takes compared with walking
// /sys/fs/cgroup.
//
// For every running process whose /proc/<pid>/cgroup names an apps/ or
// system/ cgroup, it takes the directory's inode (= cgroup id), resolves it
// back through the handle, and compares the path. Run as root:
//
//	GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -o cghandle .
//	su -c ./cghandle
package main

import (
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const fileIDKernfs = 0xfe

func resolve(mountFD int, id uint64) (string, error) {
	handle := make([]byte, 8)
	binary.LittleEndian.PutUint64(handle, id)
	fh := unix.NewFileHandle(fileIDKernfs, handle)
	fd, err := unix.OpenByHandleAt(mountFD, fh, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	return os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
}

func main() {
	mount, err := os.Open("/sys/fs/cgroup")
	if err != nil {
		panic(err)
	}
	defer mount.Close()
	mountFD := int(mount.Fd())

	entries, _ := os.ReadDir("/proc")
	type sample struct {
		pid  string
		path string
		id   uint64
	}
	var samples []sample
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		raw, err := os.ReadFile("/proc/" + entry.Name() + "/cgroup")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			relative, ok := strings.CutPrefix(line, "0::")
			if !ok || !(strings.HasPrefix(relative, "/apps/") || strings.HasPrefix(relative, "/system/")) {
				continue
			}
			path := "/sys/fs/cgroup" + relative
			var stat unix.Stat_t
			if unix.Stat(path, &stat) == nil {
				samples = append(samples, sample{pid: entry.Name(), path: path, id: stat.Ino})
			}
		}
	}
	match, mismatch, failed := 0, 0, 0
	var firstErr error
	for _, s := range samples {
		got, err := resolve(mountFD, s.id)
		switch {
		case err != nil:
			failed++
			if firstErr == nil {
				firstErr = err
			}
		case got == s.path:
			match++
		default:
			mismatch++
			fmt.Printf("MISMATCH pid=%s id=%d want=%s got=%s\n", s.pid, s.id, s.path, got)
		}
	}
	fmt.Printf("samples=%d match=%d mismatch=%d failed=%d first_error=%v\n", len(samples), match, mismatch, failed, firstErr)
	if len(samples) == 0 || failed > 0 {
		return
	}

	// Latency of one resolution, repeated over the sample set.
	const rounds = 20000
	durations := make([]time.Duration, 0, rounds)
	for i := 0; i < rounds; i++ {
		s := samples[i%len(samples)]
		start := time.Now()
		if _, err := resolve(mountFD, s.id); err != nil {
			panic(err)
		}
		durations = append(durations, time.Since(start))
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	fmt.Printf("open_by_handle_at+readlink: p50=%v p90=%v p99=%v max=%v (n=%d)\n",
		durations[rounds/2], durations[rounds*9/10], durations[rounds*99/100], durations[rounds-1], rounds)

	// The alternative: walk cgroupfs comparing inodes.
	target := samples[len(samples)-1]
	start := time.Now()
	walked := 0
	_ = filepath.WalkDir("/sys/fs/cgroup", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || !entry.IsDir() {
			return nil
		}
		walked++
		var stat unix.Stat_t
		if unix.Stat(path, &stat) == nil && stat.Ino == target.id {
			return filepath.SkipAll
		}
		return nil
	})
	fmt.Printf("walk to one id: %v over %d directories\n", time.Since(start), walked)

	// A cgroup id that no longer exists must fail, not resolve to something.
	_, err = resolve(mountFD, 1<<62)
	fmt.Printf("nonexistent id: err=%v\n", err)
}
