// Command udp-gso-probe measures what one locally delivered UDP datagram
// costs on the downlink path sing-box's TC data plane uses
// (protocol/ebpf/tc_connection.go tcPacketWriter.WritePacket): an
// IP_TRANSPARENT socket bound to a foreign source address sends to an app
// socket on this host, so every datagram goes ip_output -> netfilter ->
// loopback_xmit -> softirq -> ip_rcv -> netfilter -> udp_rcv in the sender's
// syscall.
//
//	udp-gso-probe -dst 192.168.3.6 -mode single|mmsg|gso -batch 16 -pps 20000 -duration 10s [-gro]
//
// single: one sendto per datagram (what sing-box does today)
// mmsg:   sendmmsg of -batch datagrams (sing-box's WritePacketBatch path)
// gso:    one sendmsg carrying UDP_SEGMENT, -batch datagrams per call
// -gro:   the receiver enables UDP_GRO (Chromium's choice is unknown; test both)
//
// The sender is paced at -pps in 1 ms ticks. Reported CPU is this process's
// utime+stime plus the system-wide softirq delta, divided by datagrams the
// receiver actually got, so work deferred to ksoftirqd is not lost.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const payloadSize = 1350 // a typical QUIC datagram

func main() {
	dst := flag.String("dst", "", "local IPv4 the receiver binds (the phone's wlan0 address)")
	src := flag.String("src", "203.0.113.7:443", "foreign source the sender binds with IP_TRANSPARENT")
	port := flag.Int("port", 41999, "receiver port")
	mode := flag.String("mode", "single", "single|mmsg|gso")
	batch := flag.Int("batch", 16, "datagrams per mmsg/gso call")
	pps := flag.Int("pps", 20000, "target datagrams per second")
	duration := flag.Duration("duration", 10*time.Second, "send duration")
	gro := flag.Bool("gro", false, "enable UDP_GRO on the receiver")
	flag.Parse()
	if err := run(*dst, *src, *port, *mode, *batch, *pps, *duration, *gro); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func run(dstText, srcText string, port int, mode string, batch, pps int, duration time.Duration, gro bool) error {
	dstAddr := netip.MustParseAddr(dstText)
	srcAddrPort := netip.MustParseAddrPort(srcText)
	if mode == "single" {
		batch = 1
	}

	// Receiver.
	rfd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	_ = unix.SetsockoptInt(rfd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 64<<20)
	if gro {
		if err := unix.SetsockoptInt(rfd, unix.IPPROTO_UDP, unix.UDP_GRO, 1); err != nil {
			return fmt.Errorf("UDP_GRO: %w", err)
		}
	}
	if err := unix.Bind(rfd, &unix.SockaddrInet4{Port: port, Addr: dstAddr.As4()}); err != nil {
		return fmt.Errorf("bind receiver: %w", err)
	}
	rconn, err := net.FilePacketConn(os.NewFile(uintptr(rfd), "recv"))
	if err != nil {
		return err
	}
	var received atomic.Uint64
	go func() {
		pc := ipv4.NewPacketConn(rconn)
		msgs := make([]ipv4.Message, 64)
		for i := range msgs {
			msgs[i].Buffers = [][]byte{make([]byte, 65536)}
		}
		for {
			n, err := pc.ReadBatch(msgs, 0)
			if err != nil {
				return
			}
			for i := 0; i < n; i++ {
				// With UDP_GRO one read may carry several coalesced datagrams.
				received.Add(uint64((msgs[i].N + payloadSize - 1) / payloadSize))
			}
		}
	}()

	// Sender: same socket shape as newTCUDPReplySocket.
	sfd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	if err := unix.SetsockoptInt(sfd, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		return fmt.Errorf("IP_TRANSPARENT: %w", err)
	}
	_ = unix.SetsockoptInt(sfd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, 16<<20)
	if err := unix.Bind(sfd, &unix.SockaddrInet4{Port: int(srcAddrPort.Port()), Addr: srcAddrPort.Addr().As4()}); err != nil {
		return fmt.Errorf("bind transparent sender: %w", err)
	}
	to := &unix.SockaddrInet4{Port: port, Addr: dstAddr.As4()}
	toUDP := &net.UDPAddr{IP: net.IP(dstAddr.AsSlice()), Port: port}
	// FilePacketConn dups the descriptor; keep the original File reachable so
	// its finalizer cannot close sfd while the raw sendto/sendmsg loop uses it.
	sfile := os.NewFile(uintptr(sfd), "send")
	defer runtime.KeepAlive(sfile)
	sconn, err := net.FilePacketConn(sfile)
	if err != nil {
		return err
	}
	spc := ipv4.NewPacketConn(sconn)
	payload := make([]byte, payloadSize)
	gsoPayload := make([]byte, payloadSize*batch)
	msgs := make([]ipv4.Message, batch)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{payload}
		msgs[i].Addr = toUDP
	}
	gsoOOB := make([]byte, unix.CmsgSpace(2))
	h := (*unix.Cmsghdr)(unsafePointer(&gsoOOB[0]))
	h.Level, h.Type = unix.SOL_UDP, unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	binary.LittleEndian.PutUint16(gsoOOB[unix.CmsgLen(0):], payloadSize)

	runtime.LockOSThread()
	time.Sleep(200 * time.Millisecond)
	cpu0, soft0 := selfCPUTicks(), softirqTicks()
	sent, calls := 0, 0
	perTick := pps / 1000
	if perTick < batch {
		perTick = batch
	}
	start := time.Now()
	next := start
	for time.Since(start) < duration {
		for n := 0; n < perTick; n += batch {
			switch mode {
			case "single":
				err = unix.Sendto(sfd, payload, 0, to)
				calls++
			case "mmsg":
				// sendmmsg may send fewer than asked; finish the batch.
				for off := 0; off < len(msgs) && err == nil; {
					var n int
					n, err = spc.WriteBatch(msgs[off:], 0)
					off += n
					calls++
				}
			case "gso":
				err = unix.Sendmsg(sfd, gsoPayload, gsoOOB, to, 0)
				calls++
			default:
				return fmt.Errorf("unknown mode %q", mode)
			}
			if err != nil {
				return fmt.Errorf("send: %w", err)
			}
			sent += batch
		}
		next = next.Add(time.Millisecond)
		if d := time.Until(next); d > 0 {
			time.Sleep(d)
		}
	}
	elapsed := time.Since(start)
	time.Sleep(300 * time.Millisecond)
	cpu1, soft1 := selfCPUTicks(), softirqTicks()
	got := received.Load()
	cpuNs := float64(cpu1-cpu0) * 1e7 // 100 Hz ticks
	softNs := float64(soft1-soft0) * 1e7
	fmt.Printf("RESULT mode=%s batch=%d gro=%v calls=%d sent=%d received=%d pps=%.0f proc_cpu=%.1f%% softirq_all=%.1f%% ns_per_datagram=%.0f (incl softirq %.0f)\n",
		mode, batch, gro, calls, sent, got, float64(got)/elapsed.Seconds(),
		cpuNs/float64(elapsed.Nanoseconds())*100, softNs/float64(elapsed.Nanoseconds())*100,
		cpuNs/float64(max(got, 1)), (cpuNs+softNs)/float64(max(got, 1)))
	return nil
}

func selfCPUTicks() uint64 {
	raw, _ := os.ReadFile("/proc/self/stat")
	fields := strings.Fields(string(raw[strings.LastIndexByte(string(raw), ')')+2:]))
	u, _ := strconv.ParseUint(fields[11], 10, 64)
	s, _ := strconv.ParseUint(fields[12], 10, 64)
	return u + s
}

// softirqTicks is the system-wide softirq column of /proc/stat's cpu line.
// Softirq run inline in our syscalls is already in our stime; this catches
// the part deferred to ksoftirqd (and adds unrelated background noise).
func softirqTicks() uint64 {
	raw, _ := os.ReadFile("/proc/stat")
	fields := strings.Fields(strings.SplitN(string(raw), "\n", 2)[0])
	v, _ := strconv.ParseUint(fields[7], 10, 64)
	return v
}
