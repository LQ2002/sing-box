// (diag helper) Does the socket's own cgroup v2 id (INET_DIAG_CGROUP_ID, recorded by the
// kernel at socket creation) identify the creating process instance on
// Android, where every app process gets /…/uid_<uid>/pid_<pid>?
// Compares against the sb_sockowner_probe module for the sockets it knows.
package main

import (
	"encoding/binary"
	"fmt"
	"syscall"
)


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

