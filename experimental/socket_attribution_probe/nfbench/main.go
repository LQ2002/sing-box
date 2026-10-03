// Per-packet CPU cost of sending UDP to a local address as root, i.e. the
// path sing-box's downlink write-back takes (OUTPUT/POSTROUTING, loopback,
// PREROUTING/INPUT). Run once plain and once with an early ACCEPT for a
// socket mark to see what the netfilter traversal costs on this ruleset.
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

func cpu() time.Duration {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func main() {
	n, _ := strconv.Atoi(os.Args[1])
	mark, _ := strconv.ParseUint(os.Args[2], 0, 32)
	dst := os.Args[3] // e.g. 192.168.10.160 (own wlan0 address -> routed via lo)
	rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(dst), Port: 39999})
	if err != nil {
		panic(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := rx.ReadFromUDP(buf); err != nil {
				return
			}
		}
	}()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		panic(err)
	}
	if mark != 0 {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, int(mark)); err != nil {
			panic(err)
		}
	}
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], net.ParseIP(dst).To4())
	sa.Port = 39999
	payload := make([]byte, 1200)
	for i := 0; i < 2000; i++ { // warm up
		syscall.Sendto(fd, payload, 0, &sa)
	}
	c0, t0 := cpu(), time.Now()
	for i := 0; i < n; i++ {
		syscall.Sendto(fd, payload, 0, &sa)
	}
	c1, t1 := cpu(), time.Now()
	fmt.Printf("mark=0x%x packets=%d wall=%v process_cpu=%v cpu_per_packet=%v\n", mark, n, t1.Sub(t0), c1-c0, (c1-c0)/time.Duration(n))
}
