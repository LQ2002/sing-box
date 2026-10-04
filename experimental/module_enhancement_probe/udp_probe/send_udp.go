package main

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

func main() {
	target := "223.5.5.5:53"

	// 1. 发送 3 个独立的单包 UDP 流 (每流发 1 包即关)
	fmt.Println("Triggering 3 single-packet UDP flows...")
	for i := 0; i < 3; i++ {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
		if err == nil {
			sa := &syscall.SockaddrInet4{Port: 53, Addr: [4]byte{223, 5, 5, 5}}
			_ = syscall.Sendto(fd, []byte(fmt.Sprintf("single-probe-%d", i)), 0, sa)
			syscall.Close(fd)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 2. 发送 2 个多包 UDP 流 (每流在同一个 socket 上连续发送 5 包)
	fmt.Println("Triggering 2 multi-packet UDP flows (5 packets each)...")
	for flow := 0; flow < 2; flow++ {
		conn, err := net.Dial("udp", target)
		if err == nil {
			for pkt := 0; pkt < 5; pkt++ {
				_, _ = conn.Write([]byte(fmt.Sprintf("multi-flow-%d-pkt-%d", flow, pkt)))
				time.Sleep(10 * time.Millisecond)
			}
			conn.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}

	fmt.Println("UDP workload completed successfully.")
}
