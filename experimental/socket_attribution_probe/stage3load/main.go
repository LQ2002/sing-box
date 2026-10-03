// stage3load drives a native socket workload through the test eBPF inbound
// for the stage 3 paired performance check (ANDROID_ATTRIBUTION_PLAN.md).
//
// It can join an existing app process's cgroup and switch to that app's UID
// before opening sockets. The load process is still a distinct process:
// sharing the app's cgroup is not proof that the app created the sockets.
// The default connect mode closes each connection as soon as connect()
// returns. With TC interception this measures the local interception/accept
// path, not remote forwarding. Echo mode additionally sends and verifies
// payload against a controlled echo server, measuring actual data delivery.
//
// It reports separate connect, data round-trip and complete-transaction
// distributions. sing-box's CPU time and memory
// are sampled by the caller as root before and after: once this process has
// switched UID it can no longer read /proc of a root process. Run as root:
//
//	stage3load -cgroup /sys/fs/cgroup/apps/uid_10309/pid_1234 -uid 10309 \
//	    -target 223.5.5.5:443 -conns 1000 -label x
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
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
	target := flag.String("target", "", "destination host:port; ensure the test configuration actually intercepts it")
	conns := flag.Int("conns", 1000, "connections to open")
	label := flag.String("label", "", "label printed with the result")
	mode := flag.String("mode", "connect", "connect (local TCP establishment only) or echo (verified payload forwarding)")
	listen := flag.String("listen", "", "run a controlled TCP echo server at this address instead of a load client")
	payloadBytes := flag.Int("bytes", 65536, "bytes sent and verified per connection in echo mode")
	timeout := flag.Duration("timeout", 5*time.Second, "connect timeout and complete payload exchange deadline")
	expect := flag.String("expect", "success", "success or blocked; blocked requires echo mode and zero verified replies")
	flag.Parse()
	if *listen != "" {
		if *timeout <= 0 {
			fmt.Fprintln(os.Stderr, "timeout must be positive")
			os.Exit(2)
		}
		if err := serveEcho(*listen, *timeout); err != nil {
			fmt.Fprintln(os.Stderr, "echo server:", err)
			os.Exit(1)
		}
		return
	}
	if *target == "" || *conns <= 0 || *timeout <= 0 || *payloadBytes <= 0 || *payloadBytes > 64*1024*1024 || (*mode != "connect" && *mode != "echo") || (*expect != "success" && *expect != "blocked") || (*expect == "blocked" && *mode != "echo") {
		fmt.Fprintln(os.Stderr, "invalid options: target required, positive conns/timeout, bytes in 1..67108864, mode connect|echo, expect success|blocked (echo only)")
		os.Exit(2)
	}

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
	roundTrips := make([]time.Duration, 0, *conns)
	transactions := make([]time.Duration, 0, *conns)
	failures := 0
	connectFailures := 0
	var firstError error
	payload := make([]byte, *payloadBytes)
	for index := range payload {
		payload[index] = byte(index*31 + 17)
	}
	start := time.Now()
	for range *conns {
		begin := time.Now()
		conn, err := net.DialTimeout("tcp", *target, *timeout)
		elapsed := time.Since(begin)
		if err != nil {
			if firstError == nil {
				firstError = err
			}
			failures++
			connectFailures++
			continue
		}
		durations = append(durations, elapsed)
		if *mode == "echo" {
			exchangeStart := time.Now()
			err = exchange(conn, payload, *timeout)
			if err != nil {
				if firstError == nil {
					firstError = err
				}
				failures++
			} else {
				roundTrips = append(roundTrips, time.Since(exchangeStart))
				transactions = append(transactions, time.Since(begin))
			}
		}
		_ = conn.Close()
	}
	wall := time.Since(start)
	fmt.Printf("RESULT label=%s mode=%s conns=%d connected=%d connect_fail=%d ok=%d fail=%d wall=%v connect_p50=%v connect_p90=%v connect_p99=%v connect_max=%v",
		*label, *mode, *conns, len(durations), connectFailures, *conns-failures, failures, wall.Round(time.Millisecond), quantile(durations, 0.5), quantile(durations, 0.9), quantile(durations, 0.99), quantile(durations, 1))
	if *mode == "echo" {
		// Count only bytes whose entire echoed payload was verified. This is
		// sequential request/response goodput, not maximum link capacity.
		verifiedBytes := int64(len(roundTrips)) * int64(*payloadBytes)
		fmt.Printf(" bytes_per_conn=%d verified_echo_bytes=%d echo_mib_per_s=%.3f data_rtt_p50=%v data_rtt_p90=%v data_rtt_p99=%v data_rtt_max=%v transaction_p50=%v transaction_p90=%v transaction_p99=%v transaction_max=%v",
			*payloadBytes, verifiedBytes, float64(verifiedBytes)/wall.Seconds()/(1024*1024), quantile(roundTrips, 0.5), quantile(roundTrips, 0.9), quantile(roundTrips, 0.99), quantile(roundTrips, 1), quantile(transactions, 0.5), quantile(transactions, 0.9), quantile(transactions, 0.99), quantile(transactions, 1))
	}
	passed := (*expect == "success" && failures == 0) || (*expect == "blocked" && failures == *conns)
	fmt.Printf(" expected=%s pass=%t first_error=%q\n", *expect, passed, fmt.Sprint(firstError))
	if !passed {
		os.Exit(1)
	}
}

// exchange handles writing concurrently with reading so large payloads do not
// deadlock when both client and echo server fill their socket send buffers.
func exchange(conn net.Conn, payload []byte, timeout time.Duration) error {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	written := make(chan error, 1)
	go func() {
		_, err := io.Copy(conn, bytes.NewReader(payload))
		written <- err
	}()
	reply := make([]byte, len(payload))
	_, readErr := io.ReadFull(conn, reply)
	if readErr != nil {
		_ = conn.Close()
	}
	writeErr := <-written
	if readErr != nil {
		return readErr
	}
	if writeErr != nil {
		return writeErr
	}
	if !bytes.Equal(payload, reply) {
		return fmt.Errorf("echo payload mismatch")
	}
	return nil
}

func serveEcho(address string, timeout time.Duration) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Printf("ECHO_LISTEN address=%s\n", listener.Addr())
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(timeout))
			_, _ = io.Copy(conn, conn)
		}()
	}
}

func quantile(values []time.Duration, percentile float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return values[int(float64(len(values)-1)*percentile)]
}
