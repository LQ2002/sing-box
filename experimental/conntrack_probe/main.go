// Command conntrack-probe: read-only check of conntrack as the signal that a
// packet leaving the phone is the reply of a connection the peer opened.
//
//	observe -iface wlan0 -watch <peer IPv4> -duration 60s
//	        attach bpf/ct.bpf.o at TCX egress head (returns TCX_NEXT, never
//	        changes traffic), print per-packet detail for the peer and every
//	        TCP SYN/SYN-ACK, then totals and the mean lookup cost
//	tcpserve -port P   accept, write a line, close (phone as TCP server)
//	udpserve -port P   answer every datagram (phone as UDP server)
//	tcpdial -addr A    open and close connections (phone as client)
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type event struct {
	Saddr, Daddr             [4]byte
	Sport, Dport             uint16
	Proto, Flags, Found, Dir uint8
	Error                    int32
	SkState                  uint32
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: conntrack-probe observe|tcpserve|udpserve|tcpdial ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "observe":
		err = observe(os.Args[2:])
	case "tcpserve":
		err = tcpServe(os.Args[2:])
	case "udpserve":
		err = udpServe(os.Args[2:])
	case "tcpdial":
		err = tcpDial(os.Args[2:])
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func flagsString(f uint8) string {
	s := ""
	for i, n := range []string{"F", "S", "R", "P", "A"} {
		if f&(1<<i) != 0 {
			s += n
		}
	}
	return s
}

func observe(args []string) error {
	fs := flag.NewFlagSet("observe", flag.ExitOnError)
	object := fs.String("object", "ct.bpf.o", "BPF object")
	iface := fs.String("iface", "wlan0", "interface")
	watch := fs.String("watch", "", "peer IPv4 for per-packet detail")
	duration := fs.Duration("duration", time.Minute, "duration")
	_ = fs.Parse(args)
	spec, err := ebpf.LoadCollectionSpec(*object)
	if err != nil {
		return err
	}
	if *watch != "" {
		ip := netip.MustParseAddr(*watch).As4()
		if err := spec.Variables["watch_ip"].Set(binary.LittleEndian.Uint32(ip[:])); err != nil {
			return err
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("VERIFIER_REJECTED\n%+v\n", verr)
		}
		return err
	}
	defer coll.Close()
	ifc, err := net.InterfaceByName(*iface)
	if err != nil {
		return err
	}
	l, err := link.AttachTCX(link.TCXOptions{Interface: ifc.Index, Program: coll.Programs["observe"], Attach: ebpf.AttachTCXEgress, Anchor: link.Head()})
	if err != nil {
		return fmt.Errorf("attach tcx: %w", err)
	}
	defer l.Close()
	reader, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return err
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-stop:
		case <-time.After(*duration):
		}
		reader.Close()
	}()
	fmt.Printf("OBSERVING iface=%s watch=%s duration=%s\n", *iface, *watch, *duration)
	for {
		rec, err := reader.Read()
		if err != nil {
			break
		}
		var e event
		if binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e) != nil {
			continue
		}
		proto := map[uint8]string{6: "tcp", 17: "udp"}[e.Proto]
		dir := "-"
		if e.Found != 0 {
			dir = map[uint8]string{0: "ORIGINAL", 1: "REPLY"}[e.Dir]
		}
		sk := fmt.Sprint(e.SkState)
		if e.SkState == 255 {
			sk = "none"
		}
		fmt.Printf("PKT %s %s:%d -> %s:%d flags=%s ct=%s err=%d sk_state=%s\n", proto,
			netip.AddrFrom4(e.Saddr), e.Sport, netip.AddrFrom4(e.Daddr), e.Dport, flagsString(e.Flags), dir, e.Error, sk)
	}
	var values []uint64
	sum := func(key uint32) uint64 {
		if coll.Maps["stats"].Lookup(key, &values) != nil {
			return 0
		}
		var s uint64
		for _, v := range values {
			s += v
		}
		return s
	}
	names := []string{"original", "reply", "miss"}
	for p, proto := range []string{"tcp", "udp"} {
		line := "TOTAL " + proto
		for o, n := range names {
			line += fmt.Sprintf(" %s=%d", n, sum(uint32(p*3+o)))
		}
		fmt.Println(line)
	}
	ns, lookups := sum(6), sum(7)
	if lookups > 0 {
		fmt.Printf("COST lookups=%d mean_ns=%d (includes one ktime pair, 52 ns tick)\n", lookups, ns/lookups)
	}
	return nil
}

func tcpServe(args []string) error {
	fs := flag.NewFlagSet("tcpserve", flag.ExitOnError)
	port := fs.Int("port", 18080, "port")
	count := fs.Int("count", 3, "connections to serve")
	_ = fs.Parse(args)
	ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", *port))
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Println("TCPSERVE listening", *port)
	for i := 0; i < *count; i++ {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		fmt.Fprintf(c, "hello %d from phone\n", i)
		line, _ := bufio.NewReader(c).ReadString('\n')
		fmt.Printf("TCPSERVE served %s said %q\n", c.RemoteAddr(), line)
		c.Close()
	}
	return nil
}

func udpServe(args []string) error {
	fs := flag.NewFlagSet("udpserve", flag.ExitOnError)
	port := fs.Int("port", 18081, "port")
	count := fs.Int("count", 3, "datagrams to answer")
	_ = fs.Parse(args)
	c, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", *port))
	if err != nil {
		return err
	}
	defer c.Close()
	fmt.Println("UDPSERVE listening", *port)
	buf := make([]byte, 1500)
	for i := 0; i < *count; i++ {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			return err
		}
		_, _ = c.WriteTo(append([]byte("reply:"), buf[:n]...), from)
		fmt.Printf("UDPSERVE answered %s\n", from)
	}
	return nil
}

func tcpDial(args []string) error {
	fs := flag.NewFlagSet("tcpdial", flag.ExitOnError)
	addr := fs.String("addr", "", "host:port")
	count := fs.Int("count", 2, "connections")
	_ = fs.Parse(args)
	for i := 0; i < *count; i++ {
		c, err := net.DialTimeout("tcp4", *addr, 3*time.Second)
		if err != nil {
			fmt.Println("TCPDIAL error", err)
			continue
		}
		fmt.Fprintf(c, "hello %d from phone\n", i)
		time.Sleep(200 * time.Millisecond)
		c.Close()
		fmt.Println("TCPDIAL ok", *addr)
	}
	return nil
}
