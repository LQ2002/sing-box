// stage3load drives connections through the eBPF inbound as if an app made
// them, for the stage 3 paired performance check (ANDROID_ATTRIBUTION_PLAN.md).
//
// It moves itself into an existing app process's cgroup and switches to that
// app's UID before opening any socket, so every socket carries the app's
// cgroup id and sk_uid exactly like the app's own: the new build attributes
// it through the TC socket identity, the old one through the socket owner
// module and procfs. It then opens -conns TCP connections one at a time to
// -target and closes each as soon as connect() returns. With the TC
// interception connect() completes against sing-box's local listener, so the
// connect time is the local interception and accept path, not the remote.
//
// It reports the connect-time distribution. sing-box's CPU time and memory
// are sampled by the caller as root before and after: once this process has
// switched UID it can no longer read /proc of a root process. Run as root:
//
//	stage3load -cgroup /sys/fs/cgroup/apps/uid_10309/pid_1234 -uid 10309 \
//	    -target 223.5.5.5:443 -conns 1000 -label x
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"syscall"
	"time"
)

func main() {
	cgroup := flag.String("cgroup", "", "app process cgroup directory to join")
	uid := flag.Int("uid", 0, "app UID to switch to")
	target := flag.String("target", "223.5.5.5:443", "destination host:port (not private, so it is intercepted)")
	conns := flag.Int("conns", 1000, "connections to open")
	label := flag.String("label", "", "label printed with the result")
	flag.Parse()

	runtime.LockOSThread()
	if *cgroup != "" {
		if err := os.WriteFile(filepath.Join(*cgroup, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
			fmt.Println("join cgroup:", err)
			os.Exit(1)
		}
	}
	if *uid != 0 {
		// Go applies these to every thread on Linux.
		if err := syscall.Setresgid(*uid, *uid, *uid); err != nil {
			fmt.Println("setresgid:", err)
			os.Exit(1)
		}
		if err := syscall.Setresuid(*uid, *uid, *uid); err != nil {
			fmt.Println("setresuid:", err)
			os.Exit(1)
		}
	}
	durations := make([]time.Duration, 0, *conns)
	failures := 0
	start := time.Now()
	for range *conns {
		begin := time.Now()
		conn, err := net.DialTimeout("tcp", *target, 5*time.Second)
		elapsed := time.Since(begin)
		if err != nil {
			failures++
			continue
		}
		durations = append(durations, elapsed)
		_ = conn.Close()
	}
	wall := time.Since(start)
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	q := func(p float64) time.Duration {
		if len(durations) == 0 {
			return 0
		}
		return durations[int(float64(len(durations)-1)*p)]
	}
	fmt.Printf("RESULT label=%s conns=%d ok=%d fail=%d wall=%v connect_p50=%v p90=%v p99=%v max=%v\n",
		*label, *conns, len(durations), failures, wall.Round(time.Millisecond), q(0.5), q(0.9), q(0.99), q(1))
}
