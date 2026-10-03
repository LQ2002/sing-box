package main

import (
	"flag"
	"fmt"
	"runtime"
	"sort"
	"time"

	"golang.org/x/sys/unix"
)

// runSockBench times socket()+close() for IPv4/IPv6 TCP/UDP. It measures the
// per-socket kernel cost of whatever creation hooks are loaded (none, the
// old sb_sockowner module, or the bridge plus creator producer), so the same
// binary is run once per state and the states are compared.
func runSockBench(args []string) error {
	flags := flag.NewFlagSet("sockbench", flag.ExitOnError)
	iterations := flags.Int("n", 20000, "sockets per round and kind")
	rounds := flags.Int("rounds", 5, "rounds")
	label := flags.String("label", "", "state label")
	_ = flags.Parse(args)
	runtime.LockOSThread()
	kinds := []struct {
		name           string
		family, socket int
	}{
		{"tcp4", unix.AF_INET, unix.SOCK_STREAM}, {"udp4", unix.AF_INET, unix.SOCK_DGRAM},
		{"tcp6", unix.AF_INET6, unix.SOCK_STREAM}, {"udp6", unix.AF_INET6, unix.SOCK_DGRAM},
	}
	for _, kind := range kinds {
		perOp := make([]float64, 0, *rounds)
		for round := 0; round < *rounds; round++ {
			start := time.Now()
			for i := 0; i < *iterations; i++ {
				fd, err := unix.Socket(kind.family, kind.socket|unix.SOCK_CLOEXEC, 0)
				if err != nil {
					return err
				}
				_ = unix.Close(fd)
			}
			perOp = append(perOp, float64(time.Since(start).Nanoseconds())/float64(*iterations))
		}
		sorted := append([]float64(nil), perOp...)
		sort.Float64s(sorted)
		fmt.Printf("SOCKBENCH label=%s kind=%s n=%d rounds=%d ns_per_socket_close median=%.0f min=%.0f max=%.0f all=%.0f\n",
			*label, kind.name, *iterations, *rounds, sorted[len(sorted)/2], sorted[0], sorted[len(sorted)-1], perOp)
	}
	return nil
}
