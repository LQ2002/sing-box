package main

import (
	"encoding/binary"
	"fmt"
	"sort"
	"syscall"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// diagSocket is one live inet socket from NETLINK_SOCK_DIAG.
type diagSocket struct {
	UID      uint32
	Protocol string
	Remote   string
}

// dumpInetSockets lists every TCP/UDP IPv4/IPv6 socket in this network
// namespace with its cookie and sk_uid (struct inet_diag_msg).
func dumpInetSockets() (map[uint64]diagSocket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	sockets := map[uint64]diagSocket{}
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		for _, protocol := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			// nlmsghdr(16) + inet_diag_req_v2(56)
			request := make([]byte, 72)
			binary.LittleEndian.PutUint32(request[0:], 72)
			binary.LittleEndian.PutUint16(request[4:], 20) // SOCK_DIAG_BY_FAMILY
			binary.LittleEndian.PutUint16(request[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
			request[16], request[17] = family, protocol
			binary.LittleEndian.PutUint32(request[20:], 0xffffffff) // all states
			if err = unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
				return nil, err
			}
			buffer := make([]byte, 1<<16)
		receive:
			for {
				n, _, err := unix.Recvfrom(fd, buffer, 0)
				if err != nil {
					return nil, err
				}
				messages, err := syscall.ParseNetlinkMessage(buffer[:n])
				if err != nil {
					return nil, err
				}
				for _, message := range messages {
					if message.Header.Type == unix.NLMSG_DONE {
						break receive
					}
					if message.Header.Type == unix.NLMSG_ERROR {
						return nil, fmt.Errorf("sock_diag error")
					}
					data := message.Data
					if len(data) < 72 {
						continue
					}
					// inet_diag_msg: family,state,timer,retrans (4) + sockid(48) + expires,rqueue,wqueue,uid,inode
					cookie := binary.LittleEndian.Uint64(data[4+40:])
					uid := binary.LittleEndian.Uint32(data[64:])
					name := "tcp"
					if protocol == unix.IPPROTO_UDP {
						name = "udp"
					}
					if family == unix.AF_INET6 {
						name += "6"
					}
					sockets[cookie] = diagSocket{UID: uid, Protocol: name}
				}
			}
		}
	}
	return sockets, nil
}

// runNetdScan joins netd's cookie_tag_map (read-only) with live sockets and
// reports how often the charge UID differs from the socket's own UID.
func runNetdScan() error {
	tags, err := ebpf.LoadPinnedMap(netdCookieTagPin, &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tags.Close()
	sockets, err := dumpInetSockets()
	if err != nil {
		return err
	}
	var cookie uint64
	var value uidTag
	entries, live, differ := 0, 0, 0
	pairs := map[string]int{}
	iterator := tags.Iterate()
	for iterator.Next(&cookie, &value) {
		entries++
		socket, ok := sockets[cookie]
		if !ok {
			continue
		}
		live++
		if socket.UID != value.UID {
			differ++
			pairs[fmt.Sprintf("sk_uid=%d charge_uid=%d tag=%#x %s", socket.UID, value.UID, value.Tag, socket.Protocol)]++
		}
	}
	if err = iterator.Err(); err != nil {
		return err
	}
	fmt.Printf("NETD_SCAN inet_sockets=%d tag_entries=%d tagged_live_inet=%d charge_differs=%d\n", len(sockets), entries, live, differ)
	keys := make([]string, 0, len(pairs))
	for key := range pairs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Printf("  %dx %s\n", pairs[key], key)
	}
	return nil
}
