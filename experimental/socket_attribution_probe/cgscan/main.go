// Does the socket's own cgroup v2 id (INET_DIAG_CGROUP_ID, recorded by the
// kernel at socket creation) identify the creating process instance on
// Android, where every app process gets /…/uid_<uid>/pid_<pid>?
// Compares against the sb_sockowner_probe module for the sockets it knows.
package main

import (
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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

type sock struct {
	cookie uint64
	cg     uint64
	uid    uint32
	state  byte
	proto  byte
}

func dump(family, protocol byte) ([]sock, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, 4)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
	req := make([]byte, 72)
	binary.LittleEndian.PutUint32(req[0:4], 72)
	binary.LittleEndian.PutUint16(req[4:6], 20)
	binary.LittleEndian.PutUint16(req[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	binary.LittleEndian.PutUint32(req[8:12], 1)
	req[16], req[17] = family, protocol
	binary.LittleEndian.PutUint32(req[20:24], ^uint32(0))
	if err = syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, err
	}
	buf := make([]byte, 256*1024)
	var out []sock
	for {
		n, _, _, _, err := syscall.Recvmsg(fd, buf, nil, 0)
		if err != nil {
			return nil, err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case syscall.NLMSG_DONE:
				return out, nil
			case syscall.NLMSG_ERROR:
				return nil, fmt.Errorf("netlink error")
			}
			d := m.Data
			if len(d) < 72 {
				continue
			}
			s := sock{cookie: binary.LittleEndian.Uint64(d[44:52]), uid: binary.LittleEndian.Uint32(d[64:68]), state: d[1], proto: protocol}
			for a := d[72:]; len(a) >= 4; {
				l := int(binary.LittleEndian.Uint16(a[0:2]))
				t := binary.LittleEndian.Uint16(a[2:4])
				if l < 4 || l > len(a) {
					break
				}
				if t == 21 && l >= 12 {
					s.cg = binary.LittleEndian.Uint64(a[4:12])
				}
				a = a[(l+3)&^3:]
				if (l+3)&^3 > len(a)+((l+3)&^3) {
					break
				}
			}
			out = append(out, s)
		}
	}
}

var pidRe = regexp.MustCompile(`uid_(\d+)/pid_(\d+)$`)

func main() {
	// cgroup v2 id == kernfs inode number
	paths := map[uint64]string{}
	filepath.WalkDir("/sys/fs/cgroup", func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		var st syscall.Stat_t
		if syscall.Stat(p, &st) == nil {
			paths[st.Ino] = p
		}
		return nil
	})
	dev, _ := os.OpenFile("/dev/sb_sockowner_probe", os.O_RDWR, 0)
	var total, withCG, resolved, perPID, modHit, agree, disagree, cgOnly int
	for _, fam := range []byte{syscall.AF_INET, syscall.AF_INET6} {
		for _, pr := range []byte{syscall.IPPROTO_TCP, syscall.IPPROTO_UDP} {
			ss, err := dump(fam, pr)
			if err != nil {
				fmt.Println("DUMP_ERROR", err)
				continue
			}
			for _, s := range ss {
				total++
				if s.cg == 0 {
					continue
				}
				withCG++
				p, ok := paths[s.cg]
				if !ok {
					fmt.Printf("UNRESOLVED\tcg=%d\tuid=%d\tstate=%d\n", s.cg, s.uid, s.state)
					continue
				}
				resolved++
				mm := pidRe.FindStringSubmatch(p)
				cgPID := -1
				if mm != nil {
					perPID++
					cgPID, _ = strconv.Atoi(mm[2])
				}
				q := query{Cookie: s.cookie}
				hit := false
				if dev != nil {
					_, _, e := syscall.Syscall(syscall.SYS_IOCTL, dev.Fd(), 0xc0305301, uintptr(unsafe.Pointer(&q)))
					hit = e == 0
				}
				verdict := "MODULE_MISS"
				if hit {
					modHit++
					if int(q.PID) == cgPID {
						agree++
						verdict = "AGREE"
					} else {
						disagree++
						verdict = "DISAGREE"
					}
				} else if cgPID > 0 {
					cgOnly++
				}
				fmt.Printf("%s\tproto=%d\tstate=%d\tuid=%d\tmodpid=%d\tcg=%s\n", verdict, s.proto, s.state, s.uid, q.PID, p[len("/sys/fs/cgroup"):])
			}
		}
	}
	fmt.Printf("SUMMARY total=%d with_cgroup=%d resolved=%d per_pid_cgroup=%d module_hit=%d agree=%d disagree=%d cgroup_only=%d\n",
		total, withCG, resolved, perPID, modHit, agree, disagree, cgOnly)
}
