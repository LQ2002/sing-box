//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/sys/unix"
)

const maxMessage = 4096

type message struct {
	Op               string `json:"op"`
	Error            string `json:"error,omitempty"`
	PID, TID, UID    uint32
	StartTicks       uint64
	SocketID         uint32
	Family, SockType uint16
	Cookie           uint64
	Address          string `json:"address,omitempty"`
	Nonleader        bool   `json:"nonleader,omitempty"`
}

func configureIPC(fd int) error {
	tv := unix.NsecToTimeval(15_000_000_000)
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	return unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
}

func sendMessage(fd int, m message, passFD int) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(raw) > maxMessage {
		return fmt.Errorf("oversized IPC message")
	}
	var oob []byte
	if passFD >= 0 {
		oob = unix.UnixRights(passFD)
	}
	for {
		n, err := unix.SendmsgN(fd, raw, oob, nil, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n != len(raw) {
			return io.ErrShortWrite
		}
		return nil
	}
}

func receiveMessage(fd int) (message, int, error) {
	var raw [maxMessage]byte
	oob := make([]byte, unix.CmsgSpace(4*4))
	var n, oobn, flags int
	var err error
	for {
		n, oobn, flags, _, err = unix.Recvmsg(fd, raw[:], oob, unix.MSG_CMSG_CLOEXEC)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		return message{}, -1, err
	}
	if n == 0 {
		return message{}, -1, io.EOF
	}
	var fds []int
	controls, controlErr := unix.ParseSocketControlMessage(oob[:oobn])
	if controlErr == nil {
		for _, c := range controls {
			if c.Header.Level != unix.SOL_SOCKET || c.Header.Type != unix.SCM_RIGHTS {
				controlErr = fmt.Errorf("unexpected IPC ancillary type")
				break
			}
			got, e := unix.ParseUnixRights(&c)
			if e != nil {
				controlErr = e
				break
			}
			fds = append(fds, got...)
		}
	}
	closeFDs := func() {
		for _, f := range fds {
			_ = unix.Close(f)
		}
	}
	if controlErr != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || len(fds) > 1 {
		closeFDs()
		return message{}, -1, fmt.Errorf("invalid IPC controls/truncation: flags=%d fds=%d error=%v", flags, len(fds), controlErr)
	}
	var m message
	d := json.NewDecoder(strings.NewReader(string(raw[:n])))
	d.DisallowUnknownFields()
	if err = d.Decode(&m); err != nil {
		closeFDs()
		return m, -1, err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		closeFDs()
		return m, -1, fmt.Errorf("trailing IPC JSON")
	}
	passFD := -1
	if len(fds) == 1 {
		passFD = fds[0]
	}
	return m, passFD, nil
}
