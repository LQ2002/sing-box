//go:build linux

// Diagnostic: enumerate inet socket cookies with SOCK_DIAG, query the existing
// module, and emit identities only (no IP addresses or traffic contents).
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

type query struct {
	Cookie   uint64
	PID      int32
	UID      uint32
	Start    uint64
	Family   uint16
	Reserved uint16
	Comm     [16]byte
}

var _ [48]byte = [unsafe.Sizeof(query{})]byte{}

type diag struct {
	cookie uint64
	state  byte
	sport  uint16
	uid    uint32
	inode  uint32
	proto  byte
	family byte
}

func dump(family, protocol byte) ([]diag, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, 4)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	if err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 5}); err != nil {
		return nil, err
	}
	if err = syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, err
	}
	// nlmsghdr (16) + inet_diag_req_v2 (56); SOCK_DIAG_BY_FAMILY=20.
	req := make([]byte, 72)
	binary.LittleEndian.PutUint32(req[0:4], uint32(len(req)))
	binary.LittleEndian.PutUint16(req[4:6], 20)
	binary.LittleEndian.PutUint16(req[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	binary.LittleEndian.PutUint32(req[8:12], 1)
	req[16], req[17] = family, protocol
	binary.LittleEndian.PutUint32(req[20:24], ^uint32(0))
	binary.LittleEndian.PutUint64(req[64:72], ^uint64(0))
	if err = syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, err
	}
	buf := make([]byte, 256*1024)
	var cookies []diag
	for {
		n, _, flags, _, err := syscall.Recvmsg(fd, buf, nil, 0)
		if err != nil {
			return nil, err
		}
		if flags&syscall.MSG_TRUNC != 0 {
			return nil, fmt.Errorf("netlink datagram truncated")
		}
		messages, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, msg := range messages {
			if msg.Header.Seq != 1 {
				continue
			}
			if msg.Header.Flags&0x10 != 0 {
				return nil, fmt.Errorf("netlink dump interrupted")
			}
			switch msg.Header.Type {
			case syscall.NLMSG_DONE:
				if len(msg.Data) >= 4 && int32(binary.LittleEndian.Uint32(msg.Data[:4])) != 0 {
					return nil, fmt.Errorf("netlink dump failed")
				}
				return cookies, nil
			case syscall.NLMSG_ERROR:
				if len(msg.Data) < 4 {
					return nil, fmt.Errorf("short netlink error")
				}
				code := int32(binary.LittleEndian.Uint32(msg.Data[:4]))
				if code != 0 {
					return nil, syscall.Errno(-code)
				}
			default:
				if msg.Header.Type == 20 && len(msg.Data) >= 72 {
					// inet_diag_msg.id.idiag_cookie begins at offset 44.
					cookie := binary.LittleEndian.Uint64(msg.Data[44:52])
					if cookie != ^uint64(0) && cookie != 0 {
						d := msg.Data
						cookies = append(cookies, diag{cookie: cookie, state: d[1], sport: binary.BigEndian.Uint16(d[4:6]), uid: binary.LittleEndian.Uint32(d[64:68]), inode: binary.LittleEndian.Uint32(d[68:72]), proto: protocol, family: family})
					}
				}
			}
		}
	}
}

func ticks(pid int32) string {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/stat")
	if err != nil {
		return "unavailable"
	}
	end := bytes.LastIndexByte(raw, ')')
	if end < 0 {
		return "unavailable"
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 {
		return "unavailable"
	}
	return fields[19]
}

func exe(pid int32) string {
	if pid == 0 {
		return "-"
	}
	l, err := os.Readlink("/proc/" + strconv.Itoa(int(pid)) + "/exe")
	if err != nil {
		return "?"
	}
	if strings.Contains(l, "app_process") {
		c, _ := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/cmdline")
		c, _, _ = bytes.Cut(c, []byte{0})
		return "app:" + string(c)
	}
	return l
}

func inodeOwners() map[uint32]int32 {
	m := map[uint32]int32{}
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		fds, _ := os.ReadDir("/proc/" + p.Name() + "/fd")
		for _, f := range fds {
			l, err := os.Readlink("/proc/" + p.Name() + "/fd/" + f.Name())
			if err != nil || !strings.HasPrefix(l, "socket:[") {
				continue
			}
			n, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]"), 10, 32)
			if err == nil {
				if _, ok := m[uint32(n)]; !ok {
					m[uint32(n)] = int32(pid)
				}
			}
		}
	}
	return m
}

func main() {
	dev, err := os.OpenFile("/dev/sb_sockowner_probe", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer dev.Close()
	seen := make(map[uint64]bool)
	inodePID := inodeOwners()
	var all []diag
	listen := map[uint16]bool{}
	hits, misses, errors := 0, 0, 0
	for _, family := range []byte{syscall.AF_INET, syscall.AF_INET6} {
		for _, protocol := range []byte{syscall.IPPROTO_TCP, syscall.IPPROTO_UDP} {
			cookies, err := dump(family, protocol)
			if err != nil {
				fmt.Printf("DUMP_ERROR\tfamily=%d\tprotocol=%d\terror=%v\n", family, protocol, err)
				errors++
				continue
			}
			for _, d := range cookies {
				if d.proto == syscall.IPPROTO_TCP && d.state == 10 {
					listen[d.sport] = true
				}
				all = append(all, d)
			}
		}
	}
	for _, d := range all {
				cookie := d.cookie
				if seen[cookie] {
					continue
				}
				seen[cookie] = true
				q := query{Cookie: cookie}
				_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, dev.Fd(), 0xc0305301, uintptr(unsafe.Pointer(&q)))
				if errno != 0 {
					misses++
					if errno != syscall.ENOENT {
						fmt.Printf("QUERY_ERROR\tcookie=%x\terror=%v\n", cookie, errno)
						errors++
					}
					pid := inodePID[d.inode]
					fmt.Printf("MISS\tcookie=%x\tproto=%d\tfam=%d\tstate=%d\tuid=%d\taccepted_like=%v\tpid=%d\tstart=%s\texe=%s\n", cookie, d.proto, d.family, d.state, d.uid, d.proto == syscall.IPPROTO_TCP && d.state != 10 && listen[d.sport], pid, ticks(pid), exe(pid))
					continue
				}
				hits++
				live := ticks(q.PID)
								fmt.Printf("OWNER\tcookie=%x\tpid=%d\tuid=%d\tstart_ns=%d\tstart_ticks=%d\tlive_ticks=%s\tfamily=%d\n", cookie, q.PID, q.UID, q.Start, q.Start/10000000, live, q.Family)
	}
	fmt.Printf("SCAN_END\tcookies=%d\thits=%d\tmisses=%d\terrors=%d\n", len(seen), hits, misses, errors)
	if errors != 0 {
		os.Exit(1)
	}
}
