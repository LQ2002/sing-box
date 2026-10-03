//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type nativeWorker struct {
	root  *child
	hello message
	pidfd int
}

func (n *nativeWorker) close() error {
	// All native descendants stay in this dedicated process group. On errors
	// or cancellation, kill the whole group, not only the fork's waiting parent.
	if n.root.cmd != nil && n.root.cmd.Process != nil && !n.root.waited {
		_ = unix.Kill(-n.root.cmd.Process.Pid, unix.SIGKILL)
	}
	return n.root.close()
}

func (n *nativeWorker) command(command string) error {
	written, err := unix.SendmsgN(n.root.ipc, []byte(command), nil, nil, unix.MSG_NOSIGNAL)
	if err != nil {
		return err
	}
	if written != len(command) {
		return io.ErrShortWrite
	}
	return nil
}

func (n *nativeWorker) receive(op string, withFD, samePID bool) (message, int, error) {
	m, fd, err := receiveMessage(n.root.ipc)
	if err != nil {
		return m, -1, err
	}
	if m.Op != op || m.Error != "" || (fd >= 0) != withFD || (samePID && m.PID != n.hello.PID) {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		return m, -1, fmt.Errorf("native response mismatch: expected=%s received=%+v fd=%d", op, m, fd)
	}
	if fd >= 0 {
		n.root.sockets = append(n.root.sockets, fd)
	}
	return m, fd, nil
}

func (n *nativeWorker) receiveHello(op string) error {
	m, fd, err := n.receive(op, true, false)
	if err != nil {
		return err
	}
	if m.PID <= 1 || m.TID == 0 || m.UID != 2000 || m.StartTicks == 0 {
		return fmt.Errorf("invalid native process metadata: %+v", m)
	}
	if err = unix.PidfdSendSignal(fd, 0, nil, 0); err != nil {
		return err
	}
	// Check the received descriptor's kernel identity, without reopening a PID.
	info, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		return err
	}
	found := false
	for _, line := range strings.Split(string(info), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "Pid:" {
			found = fields[1] == strconv.FormatUint(uint64(m.PID), 10)
		}
	}
	if !found {
		return fmt.Errorf("native pidfd does not bind reported process: %s", info)
	}
	n.hello, n.pidfd = m, fd
	return setTarget(n.root.moduleParameter, m.PID)
}

func (r *runner) spawnNative(ctx context.Context) (_ *nativeWorker, err error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	n := &nativeWorker{root: &child{ipc: pair[0], pidfd: -1, moduleParameter: r.moduleParameter}, pidfd: -1}
	end := os.NewFile(uintptr(pair[1]), "native-ipc")
	defer end.Close()
	defer func() {
		if err != nil {
			_ = n.close()
		}
	}()
	if err = configureIPC(n.root.ipc); err != nil {
		return nil, err
	}
	n.root.cmd = exec.CommandContext(ctx, r.nativeWorker, "start")
	n.root.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	n.root.cmd.Cancel = func() error { return unix.Kill(-n.root.cmd.Process.Pid, unix.SIGKILL) }
	n.root.cmd.ExtraFiles = []*os.File{end}
	n.root.cmd.Stdout, n.root.cmd.Stderr = &n.root.output, &n.root.output
	if err = n.root.cmd.Start(); err != nil {
		return nil, err
	}
	_ = end.Close()
	if err = n.receiveHello("hello"); err != nil {
		return nil, err
	}
	if n.hello.PID != uint32(n.root.cmd.Process.Pid) {
		return nil, fmt.Errorf("native worker hello PID mismatch")
	}
	emit("native_ready", map[string]any{"pid": n.hello.PID, "uid": n.hello.UID, "start_ticks": n.hello.StartTicks})
	return n, nil
}

func (n *nativeWorker) registrationTarget() *child {
	return &child{hello: n.hello, pidfd: n.pidfd}
}

func (n *nativeWorker) exit() error {
	if err := n.command("EXIT"); err != nil {
		return err
	}
	if _, _, err := n.receive("exit", false, true); err != nil {
		return err
	}
	err := n.root.cmd.Wait()
	n.root.waited = true
	if err != nil {
		return fmt.Errorf("native worker exit: %w; output=%s", err, n.root.output.String())
	}
	if err = unix.PidfdSendSignal(n.pidfd, 0, nil, 0); !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("native exited pidfd expected ESRCH, got %v", err)
	}
	return nil
}

func (r *runner) nativeCreate(n *nativeWorker, id uint32, reg registration, registered, listen bool) (testSocket, message, error) {
	op, command, kind := "create", "CREATE", uint16(unix.SOCK_DGRAM)
	if listen {
		op, command, kind = "listen", "LISTEN", unix.SOCK_STREAM
	}
	if err := n.command(fmt.Sprintf("%s %d", command, id)); err != nil {
		return testSocket{}, message{}, err
	}
	reply, fd, err := n.receive(op, true, true)
	if err != nil {
		return testSocket{}, reply, err
	}
	s, err := r.verifyCreated(n.hello, reply, fd, id, unix.AF_INET, kind, reg, registered, false)
	return s, reply, err
}

func (r *runner) nativeExisting(n *nativeWorker, s testSocket) error {
	if err := n.command(fmt.Sprintf("REPORT %d", s.id)); err != nil {
		return err
	}
	reply, fd, err := n.receive("report", true, true)
	if err != nil {
		return err
	}
	if reply.Cookie != s.want.Cookie || reply.SocketID != s.id {
		return fmt.Errorf("inherited socket cookie changed")
	}
	key := uint32(fd)
	var value identity
	if err = r.coll.Maps["socket_identity"].Lookup(&key, &value); err != nil {
		return err
	}
	if err = validateIdentity(value, s.want); err != nil {
		return err
	}
	var observed observation
	if err = r.coll.Maps["observed_by_cookie"].Lookup(&s.want.Cookie, &observed); !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("inherited socket already sent before test: %v", err)
	}
	emit("inherited_socket", map[string]any{"holder_pid": n.hello.PID, "identity": value, "first_send_pending": true})
	return nil
}

func (r *runner) nativeSend(n *nativeWorker, s testSocket) error {
	address, wait, closeListener, err := destination(s.family, s.kind)
	if err != nil {
		return err
	}
	defer closeListener()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if err = n.command(fmt.Sprintf("SEND %d %s", s.id, port)); err != nil {
		return err
	}
	sent, _, err := n.receive("sent", false, true)
	if err != nil {
		return err
	}
	if sent.Cookie != s.want.Cookie || sent.SocketID != s.id {
		return fmt.Errorf("native send used a different socket")
	}
	if err = wait(); err != nil {
		return err
	}
	var observed observation
	if err = r.coll.Maps["observed_by_cookie"].Lookup(&s.want.Cookie, &observed); err != nil {
		return err
	}
	if err = validateObservation(observed, s.want, packetUDP, r.ifindex); err != nil {
		return err
	}
	if observed.PacketCount != 1 {
		return fmt.Errorf("native UDP observation count %d", observed.PacketCount)
	}
	emit("first_packet", map[string]any{"native": true, "sender_pid": sent.PID, "observation": observed, "destination": address})
	return nil
}

func (r *runner) checkTask(pidfd int, expected *registration) error {
	key := uint32(pidfd)
	var got registration
	err := r.coll.Maps["task_identity"].Lookup(&key, &got)
	if expected == nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("TASK_STORAGE expected ENOENT, got=%+v err=%v", got, err)
		}
	} else if err != nil || got != *expected {
		return fmt.Errorf("TASK_STORAGE mismatch: got=%+v expected=%+v err=%v", got, *expected, err)
	}
	return nil
}

func (r *runner) runNativeCase(ctx context.Context, name string) (err error) {
	n, err := r.spawnNative(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, n.close()) }()
	reg, err := r.register(n.registrationTarget())
	if err != nil {
		return err
	}
	if name == "native_accept" {
		return r.nativeAccept(n, reg)
	}
	a, _, err := r.nativeCreate(n, 1, reg, true, false)
	if err != nil {
		return err
	}
	original, oldPidfd := n.hello, n.pidfd
	switch name {
	case "native_fork":
		if err = n.command("FORK"); err != nil {
			return err
		}
		if err = n.receiveHello("fork_hello"); err != nil {
			return err
		}
		if n.hello.PID == original.PID || n.hello.UID != original.UID {
			return fmt.Errorf("fork did not produce a distinct same-UID process")
		}
		if err = r.checkTask(n.pidfd, nil); err != nil {
			return err
		}
		if err = r.nativeExisting(n, a); err != nil {
			return err
		}
		if err = r.nativeSend(n, a); err != nil {
			return err
		}
		b, _, e := r.nativeCreate(n, 2, registration{}, false, false)
		if e != nil {
			return e
		}
		if e = r.nativeSend(n, b); e != nil {
			return e
		}
		childReg, e := r.register(n.registrationTarget())
		if e != nil {
			return e
		}
		c, _, e := r.nativeCreate(n, 3, childReg, true, false)
		if e != nil {
			return e
		}
		if e = r.nativeSend(n, c); e != nil {
			return e
		}
		emit("lifecycle_finding", map[string]any{"case": name, "parent_pid": original.PID, "child_pid": n.hello.PID, "task_registration_inherited": false, "inherited_socket_keeps_parent": true, "child_registration_restores_new_sockets": true})
		if err = n.command("EXIT"); err != nil {
			return err
		}
		if _, _, err = n.receive("exit", false, true); err != nil {
			return err
		}
		if err = n.receiveHello("parent_resumed"); err != nil {
			return err
		}
		if n.hello.PID != original.PID || n.hello.StartTicks != original.StartTicks {
			return fmt.Errorf("fork parent did not resume")
		}
		if err = r.checkTask(n.pidfd, &reg); err != nil {
			return err
		}
	case "native_leader_exec", "native_nonleader_exec":
		nonleader := name == "native_nonleader_exec"
		if nonleader {
			if err = n.command("THREAD_EXEC"); err != nil {
				return err
			}
			thread, _, e := n.receive("exec_thread", false, true)
			if e != nil {
				return e
			}
			if thread.TID == original.PID {
				return fmt.Errorf("nonleader exec used group leader")
			}
			emit("exec_thread", map[string]any{"pid": thread.PID, "tid": thread.TID})
			if err = n.command("CONTINUE"); err != nil {
				return err
			}
		} else if err = n.command("EXEC"); err != nil {
			return err
		}
		if err = n.receiveHello("exec_hello"); err != nil {
			return err
		}
		if n.hello.PID != original.PID || n.hello.TID != original.PID || n.hello.StartTicks != original.StartTicks {
			return fmt.Errorf("exec process instance changed unexpectedly: before=%+v after=%+v", original, n.hello)
		}
		expected := &reg
		if nonleader {
			expected = nil
		}
		if err = r.checkTask(oldPidfd, expected); err != nil {
			return err
		}
		if err = r.checkTask(n.pidfd, expected); err != nil {
			return err
		}
		if err = r.nativeExisting(n, a); err != nil {
			return err
		}
		b, _, e := r.nativeCreate(n, 2, reg, !nonleader, false)
		if e != nil {
			return e
		}
		var recovered *testSocket
		if nonleader {
			newReg, e := r.register(n.registrationTarget())
			if e != nil {
				return e
			}
			c, _, e := r.nativeCreate(n, 3, newReg, true, false)
			if e != nil {
				return e
			}
			recovered = &c
		}
		if err = r.nativeSend(n, a); err != nil {
			return err
		}
		if err = r.nativeSend(n, b); err != nil {
			return err
		}
		if recovered != nil {
			if err = r.nativeSend(n, *recovered); err != nil {
				return err
			}
		}
		emit("lifecycle_finding", map[string]any{"case": name, "pid": n.hello.PID, "same_pid_and_birth_ticks": true, "task_registration_retained": !nonleader, "old_socket_keeps_creator": true, "automatic_new_socket_attribution": !nonleader})
	default:
		return fmt.Errorf("unknown native case %q", name)
	}
	return n.exit()
}

func (r *runner) nativeAccept(n *nativeWorker, reg registration) error {
	listener, reply, err := r.nativeCreate(n, 1, reg, true, true)
	if err != nil {
		return err
	}
	if _, err = socketAddress(unix.AF_INET, reply.Address); err != nil {
		return err
	}
	client, err := net.DialTimeout("tcp4", reply.Address, 5*time.Second)
	if err != nil {
		return err
	}
	defer client.Close()
	if err = n.command("ACCEPT 1 2"); err != nil {
		return err
	}
	accepted, fd, err := n.receive("accept", true, true)
	if err != nil {
		return err
	}
	if accepted.SocketID != 2 || accepted.Cookie == 0 || accepted.Cookie == listener.want.Cookie {
		return fmt.Errorf("invalid accepted socket cookie")
	}
	key := uint32(fd)
	var missing identity
	if err = r.coll.Maps["socket_identity"].Lookup(&key, &missing); !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("no-CLONE accepted socket unexpectedly has storage: %+v %v", missing, err)
	}
	if err = n.command("WRITE 2"); err != nil {
		return err
	}
	sent, _, err := n.receive("sent", false, true)
	if err != nil {
		return err
	}
	if sent.Cookie != accepted.Cookie {
		return fmt.Errorf("accepted sender socket mismatch")
	}
	if err = client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	payload := make([]byte, len(probePayload))
	if _, err = io.ReadFull(client, payload); err != nil {
		return err
	}
	if string(payload) != probePayload {
		return fmt.Errorf("accepted socket payload mismatch")
	}
	var observed observation
	if err = r.coll.Maps["observed_by_cookie"].Lookup(&accepted.Cookie, &observed); !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("unattributed accepted socket acquired an observation: %+v %v", observed, err)
	}
	emit("lifecycle_finding", map[string]any{"case": "native_accept", "listener_cookie": listener.want.Cookie, "accepted_cookie": accepted.Cookie, "payload_verified": true, "socket_storage_present": false, "automatic_attribution_supported": false, "reason": "accepted child bypasses socket-create producer and this map has no CLONE flag"})
	return n.exit()
}
