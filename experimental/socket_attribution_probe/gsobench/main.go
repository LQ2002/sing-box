// Per-datagram CPU cost of root UDP to a local address, one datagram per
// sendto versus UDP_SEGMENT (GSO) batches. Same path as sing-box's
// downlink write-back: OUTPUT/POSTROUTING, loopback, PREROUTING/INPUT.
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
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

func main() {
	total, _ := strconv.Atoi(os.Args[1])
	dst := os.Args[2]
	rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(dst), Port: 39998})
	if err != nil {
		panic(err)
	}
	rx.SetReadBuffer(8 << 20)
	var received atomic.Int64
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := rx.ReadFromUDP(buf)
			if err != nil {
				return
			}
			received.Add(int64(n / segSize))
		}
	}()
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], net.ParseIP(dst).To4())
	sa.Port = 39998
	for _, batch := range []int{1, 8, 16, 32, 53} {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
		if err != nil {
			panic(err)
		}
		if batch > 1 {
			if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_UDP, 103 /* UDP_SEGMENT */, segSize); err != nil {
				fmt.Println("UDP_SEGMENT unsupported:", err)
				return
			}
		}
		payload := make([]byte, segSize*batch)
		sends := total / batch
		for i := 0; i < 200; i++ {
			syscall.Sendto(fd, payload, 0, &sa)
		}
		time.Sleep(200 * time.Millisecond)
		r0 := received.Load()
		c0, t0 := cpu(), time.Now()
		failed := 0
		for i := 0; i < sends; i++ {
			if err := syscall.Sendto(fd, payload, 0, &sa); err != nil {
				failed++
			}
		}
		c1, t1 := cpu(), time.Now()
		time.Sleep(300 * time.Millisecond)
		dg := sends * batch
		fmt.Printf("batch=%-3d datagrams=%d wall=%-12v cpu=%-12v cpu_per_datagram=%-9v received=%d send_errors=%d\n",
			batch, dg, t1.Sub(t0), c1-c0, (c1-c0)/time.Duration(dg), received.Load()-r0, failed)
		syscall.Close(fd)
	}
}
