//go:build linux

package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const probePayload = "identity-carrier-probe"

func selfStartTicks() (uint64, error) {
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, err
	}
	end := bytes.LastIndexByte(raw, ')')
	if end < 0 {
		return 0, fmt.Errorf("bad proc stat")
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 {
		return 0, fmt.Errorf("short proc stat")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

func socketAddress(family uint16, address string) (unix.Sockaddr, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid target port")
	}
	ip := net.ParseIP(host)
	if family == unix.AF_INET {
		v := ip.To4()
		if v == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("IPv4 destination is not loopback")
		}
		sa := &unix.SockaddrInet4{Port: port}
		copy(sa.Addr[:], v)
		return sa, nil
	}
	if family != unix.AF_INET6 || ip.To16() == nil || ip.To4() != nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("IPv6 destination is not loopback")
	}
	sa := &unix.SockaddrInet6{Port: port}
	copy(sa.Addr[:], ip.To16())
	return sa, nil
}

func sendSocket(fd int, family, sockType uint16, address string) error {
	sa, err := socketAddress(family, address)
	if err != nil {
		return err
	}
	tv := unix.NsecToTimeval(int64(5 * time.Second))
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv); err != nil {
		return err
	}
	if sockType == unix.SOCK_STREAM {
		if err = unix.Connect(fd, sa); err != nil {
			return err
		}
		sa = nil
	} else if sockType != unix.SOCK_DGRAM {
		return fmt.Errorf("unsupported socket type")
	}
	n, err := unix.SendmsgN(fd, []byte(probePayload), nil, sa, unix.MSG_NOSIGNAL)
	if err != nil {
		return err
	}
	if n != len(probePayload) {
		return fmt.Errorf("short network write: %d", n)
	}
	return nil
}

func workerMain(uid int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	const ipc = 3
	defer unix.Close(ipc)
	if err := configureIPC(ipc); err != nil {
		return err
	}
	if uid != 0 && uid != 2000 {
		return fmt.Errorf("worker UID must be root or shell")
	}
	if uid != os.Getuid() {
		if err := unix.Setgroups(nil); err != nil {
			return err
		}
		if err := unix.Setresgid(uid, uid, uid); err != nil {
			return err
		}
		if err := unix.Setresuid(uid, uid, uid); err != nil {
			return err
		}
	}
	if os.Getuid() != uid {
		return fmt.Errorf("worker credential transition failed")
	}
	ticks, err := selfStartTicks()
	if err != nil {
		return err
	}
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return fmt.Errorf("self pidfd_open: %w", err)
	}
	if err = sendMessage(ipc, message{Op: "hello", PID: uint32(os.Getpid()), TID: uint32(unix.Gettid()), UID: uint32(os.Getuid()), StartTicks: ticks}, pidfd); err != nil {
		_ = unix.Close(pidfd)
		return err
	}
	_ = unix.Close(pidfd)
	type socketRecord struct {
		fd           int
		family, kind uint16
	}
	sockets := make(map[uint32]socketRecord)
	defer func() {
		for _, s := range sockets {
			_ = unix.Close(s.fd)
		}
	}()
	for {
		m, extra, err := receiveMessage(ipc)
		if extra >= 0 {
			_ = unix.Close(extra)
			return fmt.Errorf("parent supplied unexpected descriptor")
		}
		if err != nil {
			return err
		}
		response := message{Op: m.Op, SocketID: m.SocketID, PID: uint32(os.Getpid()), UID: uint32(os.Getuid())}
		passFD := -1
		switch m.Op {
		case "create":
			if _, exists := sockets[m.SocketID]; exists || (m.Family != unix.AF_INET && m.Family != unix.AF_INET6) || (m.SockType != unix.SOCK_STREAM && m.SockType != unix.SOCK_DGRAM) {
				err = fmt.Errorf("invalid or duplicate create")
				break
			}
			type created struct {
				fd  int
				tid uint32
				err error
			}
			create := func() created {
				tid := uint32(unix.Gettid())
				if m.Nonleader && tid == uint32(os.Getpid()) {
					return created{-1, tid, fmt.Errorf("requested nonleader ran on leader")}
				}
				fd, e := unix.Socket(int(m.Family), int(m.SockType)|unix.SOCK_CLOEXEC, 0)
				return created{fd, tid, e}
			}
			var result created
			if m.Nonleader {
				ch := make(chan created, 1)
				go func() { runtime.LockOSThread(); defer runtime.UnlockOSThread(); ch <- create() }()
				result = <-ch
			} else {
				result = create()
			}
			if result.err != nil {
				err = result.err
				break
			}
			sockets[m.SocketID] = socketRecord{result.fd, m.Family, m.SockType}
			response.Cookie, err = unix.GetsockoptUint64(result.fd, unix.SOL_SOCKET, unix.SO_COOKIE)
			if err == nil && response.Cookie == 0 {
				err = fmt.Errorf("zero SO_COOKIE")
			}
			response.TID, response.Family, response.SockType = result.tid, m.Family, m.SockType
			passFD = result.fd
		case "send":
			s, ok := sockets[m.SocketID]
			if !ok {
				err = fmt.Errorf("unknown socket")
				break
			}
			err = sendSocket(s.fd, s.family, s.kind, m.Address)
		case "exit":
			return sendMessage(ipc, response, -1)
		default:
			err = fmt.Errorf("unknown worker operation %q", m.Op)
		}
		if err != nil {
			response.Error = err.Error()
			passFD = -1
		}
		if e := sendMessage(ipc, response, passFD); e != nil {
			return e
		}
		if err != nil {
			return err
		}
	}
}
