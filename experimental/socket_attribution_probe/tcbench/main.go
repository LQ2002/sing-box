// Micro-benchmark the live sing-box TC egress program with BPF_PROG_TEST_RUN.
// Test skbs carry no socket, so this times the uncached decision chain that
// every UDP packet pays today, against the rules currently loaded. Nothing
// is transmitted: a redirect in test-run only returns a verdict.
package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"strconv"

	"github.com/cilium/ebpf"
)

func packet(proto byte, dst string, dport uint16) []byte {
	l4 := 8
	if proto == 6 {
		l4 = 20
	}
	b := make([]byte, 14+20+l4+32)
	copy(b[0:6], []byte{2, 0, 0, 0, 0, 1})
	copy(b[6:12], []byte{2, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	ip := b[14:]
	ip[0], ip[8], ip[9] = 0x45, 64, proto
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+l4+32))
	copy(ip[12:16], netip.MustParseAddr("192.168.10.160").AsSlice())
	copy(ip[16:20], netip.MustParseAddr(dst).AsSlice())
	l := ip[20:]
	binary.BigEndian.PutUint16(l[0:2], 40000)
	binary.BigEndian.PutUint16(l[2:4], dport)
	if proto == 6 {
		l[12] = 5 << 4
		l[13] = 0x18
	} else {
		binary.BigEndian.PutUint16(l[4:6], uint16(8+32))
	}
	return b
}

func main() {
	id, _ := strconv.Atoi(os.Args[1])
	prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
	if err != nil {
		panic(err)
	}
	info, _ := prog.Info()
	fmt.Println("program", info.Name)
	cases := []struct {
		name  string
		proto byte
		dst   string
		port  uint16
	}{
		{"UDP 443 -> 8.8.8.8 (foreign)", 17, "8.8.8.8", 443},
		{"UDP 443 -> 114.114.114.114 (CN)", 17, "114.114.114.114", 443},
		{"UDP 443 -> 223.5.5.5 (CN)", 17, "223.5.5.5", 443},
		{"TCP 443 -> 8.8.8.8 (foreign)", 6, "8.8.8.8", 443},
		{"TCP 443 -> 114.114.114.114 (CN)", 6, "114.114.114.114", 443},
		{"UDP 53 -> 192.168.10.1 (DNS)", 17, "192.168.10.1", 53},
		{"TCP 443 -> 192.168.10.5 (LAN)", 6, "192.168.10.5", 443},
	}
	for _, c := range cases {
		ret, dur, err := prog.Benchmark(packet(c.proto, c.dst, c.port), 200000, nil)
		if err != nil {
			fmt.Printf("%-34s ERROR %v\n", c.name, err)
			continue
		}
		verdict := map[uint32]string{0: "OK/pass", 2: "SHOT", 7: "REDIRECT", 0xffffffff: "UNSPEC"}[ret]
		fmt.Printf("%-34s ret=%-10s avg=%v\n", c.name, verdict, dur)
	}
}
