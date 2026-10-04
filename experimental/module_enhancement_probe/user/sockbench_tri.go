package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"syscall"
	"time"
)

func runRound(iterations int) time.Duration {
	// 预热 2000 次
	for i := 0; i < 2000; i++ {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
		if err == nil {
			syscall.Close(fd)
		}
	}

	t0 := time.Now()
	for i := 0; i < iterations; i++ {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
		if err == nil {
			syscall.Close(fd)
		}
	}
	return time.Since(t0)
}

func main() {
	tag := "BASELINE"
	if len(os.Args) > 1 {
		tag = os.Args[1]
	}
	n := 20000
	if len(os.Args) > 2 {
		n, _ = strconv.Atoi(os.Args[2])
	}
	rounds := 3

	var perSockNs []int64
	for r := 0; r < rounds; r++ {
		dur := runRound(n)
		avgNs := dur.Nanoseconds() / int64(n)
		perSockNs = append(perSockNs, avgNs)
		time.Sleep(100 * time.Millisecond)
	}

	sort.Slice(perSockNs, func(i, j int) bool { return perSockNs[i] < perSockNs[j] })
	medianNs := perSockNs[len(perSockNs)/2]

	fmt.Printf("[%s] 20000次*3轮 (中位数): %d ns/socket (各轮: %v ns)\n",
		tag, medianNs, perSockNs)
}
