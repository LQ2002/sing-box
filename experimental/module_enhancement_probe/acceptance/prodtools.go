package main

// Helpers for the production-chain checks (prod-longrun.sh):
//
//	dial      wait (optionally for SIGUSR1), then open TCP connections - a
//	          root-cgroup native client whose executable can be unlinked or
//	          live under a >256-byte path before its sockets exist
//	prodhold  load and attach the production producer
//	          (common/socketidentity/bpf/creator.bpf.c) without sing-box, for
//	          in-kernel timing of the module plus the real producer
//	ownbench  the bench loop inside a cgroup named pid_<self>, i.e. the path
//	          the module skips

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func runDial(args []string) error {
	flags := flag.NewFlagSet("dial", flag.ExitOnError)
	addr := flags.String("addr", "1.1.1.1:80", "TCP address")
	count := flags.Int("count", 3, "connections")
	waitSignal := flags.Bool("wait-signal", false, "wait for SIGUSR1 first")
	hold := flags.Duration("hold", 2*time.Second, "keep each connection open")
	_ = flags.Parse(args)
	if *waitSignal {
		ready := make(chan os.Signal, 1)
		signal.Notify(ready, syscall.SIGUSR1)
		fmt.Println("DIAL_WAITING pid", os.Getpid())
		<-ready
	}
	exe, _ := os.Readlink("/proc/self/exe")
	ok := 0
	for i := 0; i < *count; i++ {
		conn, err := net.DialTimeout("tcp", *addr, 5*time.Second)
		if err != nil {
			fmt.Println("DIAL_ERROR", err)
			continue
		}
		ok++
		time.Sleep(*hold)
		conn.Close()
	}
	fmt.Printf("DIAL pid=%d exe=%q bytes=%d connected=%d/%d\n", os.Getpid(), exe, len(exe), ok, *count)
	return nil
}

func runProdHold(args []string) error {
	flags := flag.NewFlagSet("prodhold", flag.ExitOnError)
	object := flags.String("object", "creator.bpf.o", "production producer object")
	duration := flags.Duration("duration", time.Hour, "how long to hold")
	_ = flags.Parse(args)
	coll, err := ebpf.LoadCollection(*object)
	if err != nil {
		return err
	}
	defer coll.Close()
	lnk, err := link.AttachTracing(link.TracingOptions{Program: coll.Programs["capture_creator"], AttachType: ebpf.AttachTraceRawTp})
	if err != nil {
		return err
	}
	defer lnk.Close()
	fmt.Println("PRODHOLDING")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-stop:
	case <-time.After(*duration):
	}
	return nil
}

// runOwnBench runs the socket()+close() loop from inside a cgroup named
// pid_<own tgid>, then moves back and removes the cgroups it made.
func runOwnBench(args []string) error {
	flags := flag.NewFlagSet("ownbench", flag.ExitOnError)
	n := flags.Int("n", 20000, "sockets per round")
	rounds := flags.Int("rounds", 5, "rounds")
	label := flags.String("label", "own_cgroup", "state label")
	_ = flags.Parse(args)
	start, err := procCgroup(os.Getpid())
	if err != nil {
		return err
	}
	base := filepath.Join(cgroupRoot, "sbo_ownbench")
	own := filepath.Join(base, "pid_"+strconv.Itoa(os.Getpid()))
	for _, dir := range []string{base, own} {
		if err := os.Mkdir(dir, 0o755); err != nil && !os.IsExist(err) {
			return err
		}
	}
	defer func() {
		_ = os.WriteFile(filepath.Join(cgroupRoot, start, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0)
		_ = unix.Rmdir(own)
		_ = unix.Rmdir(base)
	}()
	if err := os.WriteFile(filepath.Join(own, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		return err
	}
	runtime.LockOSThread()
	per := make([]float64, 0, *rounds)
	for r := 0; r < *rounds; r++ {
		begin := time.Now()
		for i := 0; i < *n; i++ {
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				return err
			}
			unix.Close(fd)
		}
		per = append(per, float64(time.Since(begin).Nanoseconds())/float64(*n))
	}
	sorted := append([]float64(nil), per...)
	sort.Float64s(sorted)
	fmt.Printf("BENCH label=%s n=%d rounds=%d median=%.0f min=%.0f max=%.0f all=%.0f\n",
		*label, *n, *rounds, sorted[len(sorted)/2], sorted[0], sorted[len(sorted)-1], per)
	return nil
}
