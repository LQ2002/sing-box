// UDP GSO on sing-box's real downlink write-back shape: an IP_TRANSPARENT
// socket bound to a foreign server address (as newTCUDPReplySocket does)
// sending to the app's local address, received by a socket connected to
// that server address (as a QUIC client is). Reports which interfaces the
// datagrams crossed via /proc/net/dev deltas.
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const segSize = 1200

func cpu() time.Duration {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func devCounters() map[string][2]uint64 {
	f, _ := os.Open("/proc/net/dev")
	defer f.Close()
	r := map[string][2]uint64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		i := strings.Index(l, ":")
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(l[:i])
		fs := strings.Fields(l[i+1:])
		rx, _ := strconv.ParseUint(fs[1], 10, 64)
		tx, _ := strconv.ParseUint(fs[9], 10, 64)
		r[name] = [2]uint64{rx, tx}
	}
	return r
}

func main() {
	total, _ := strconv.Atoi(os.Args[1])
	local := net.ParseIP(os.Args[2]).To4()
	server := net.ParseIP("8.8.8.8").To4()
	// app side: bound to local address, connected to the server
	app, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		panic(err)
	}
	syscall.SetsockoptInt(app, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 8<<20)
	var la, sa syscall.SockaddrInet4
	copy(la.Addr[:], local)
	la.Port = 39997
	copy(sa.Addr[:], server)
	sa.Port = 443
	if err := syscall.Bind(app, &la); err != nil {
		panic(err)
	}
	if err := syscall.Connect(app, &sa); err != nil {
		panic(err)
	}
	var received atomic.Int64
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := syscall.Recvfrom(app, buf, 0)
			if err != nil {
				return
			}
			received.Add(int64(n / segSize))
		}
	}()
	for _, batch := range []int{1, 8, 16, 32} {
		// write-back side: transparent socket bound to the server address
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
		if err != nil {
			panic(err)
		}
		syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		if err := syscall.SetsockoptInt(fd, syscall.SOL_IP, 19 /* IP_TRANSPARENT */, 1); err != nil {
			panic(err)
		}
		if err := syscall.Bind(fd, &sa); err != nil {
			panic(fmt.Sprint("bind foreign: ", err))
		}
		if batch > 1 {
			if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_UDP, 103, segSize); err != nil {
				fmt.Println("UDP_SEGMENT:", err)
				return
			}
		}
		payload := make([]byte, segSize*batch)
		sends := total / batch
		for i := 0; i < 100; i++ {
			syscall.Sendto(fd, payload, 0, &la)
		}
		time.Sleep(200 * time.Millisecond)
		d0, r0 := devCounters(), received.Load()
		c0, t0 := cpu(), time.Now()
		fails := 0
		for i := 0; i < sends; i++ {
			if err := syscall.Sendto(fd, payload, 0, &la); err != nil {
				fails++
			}
		}
		c1, t1 := cpu(), time.Now()
		time.Sleep(300 * time.Millisecond)
		d1 := devCounters()
		dg := sends * batch
		paths := []string{}
		for name, v := range d1 {
			if dt := v[1] - d0[name][1]; dt > uint64(sends/2) {
				paths = append(paths, fmt.Sprintf("%s tx+%d", name, dt))
			}
		}
		fmt.Printf("batch=%-3d datagrams=%d wall=%-12v cpu_per_datagram=%-9v received=%d send_errors=%d path=%v\n",
			batch, dg, t1.Sub(t0), (c1-c0)/time.Duration(dg), received.Load()-r0, fails, paths)
		syscall.Close(fd)
	}
}
