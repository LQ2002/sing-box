//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type runner struct {
	coll                *ebpf.Collection
	ifindex             uint32
	moduleParameter     string
	generation          uint64
	created, registered uint64
	mismatched          uint64
	nativeWorker        string
	seenCookies         map[uint64]bool
	seenTokens          map[[2]uint64]bool
}

type child struct {
	cmd             *exec.Cmd
	ipc, pidfd      int
	hello           message
	output          bytes.Buffer
	waited          bool
	moduleParameter string
	sockets         []int
}

func setTarget(path string, pid uint32) error {
	return os.WriteFile(path, []byte(strconv.FormatUint(uint64(pid), 10)+"\n"), 0600)
}

func (r *runner) spawn(ctx context.Context, uid int) (_ *child, err error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	c := &child{ipc: pair[0], pidfd: -1, moduleParameter: r.moduleParameter}
	childEnd := os.NewFile(uintptr(pair[1]), "worker-ipc")
	defer childEnd.Close()
	defer func() {
		if err != nil {
			_ = c.close()
		}
	}()
	if err = configureIPC(c.ipc); err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	c.cmd = exec.CommandContext(ctx, executable, "-worker", "-worker-uid", strconv.Itoa(uid))
	c.cmd.ExtraFiles = []*os.File{childEnd}
	c.cmd.Stdout, c.cmd.Stderr = &c.output, &c.output
	if err = c.cmd.Start(); err != nil {
		return nil, err
	}
	_ = childEnd.Close()
	c.hello, c.pidfd, err = receiveMessage(c.ipc)
	if err != nil {
		return nil, fmt.Errorf("worker hello: %w", err)
	}
	if c.hello.Op != "hello" || c.hello.PID != uint32(c.cmd.Process.Pid) || c.hello.UID != uint32(uid) || c.hello.StartTicks == 0 || c.pidfd < 0 {
		return nil, fmt.Errorf("invalid worker hello/pidfd: %+v fd=%d", c.hello, c.pidfd)
	}
	if err = unix.PidfdSendSignal(c.pidfd, 0, nil, 0); err != nil {
		return nil, fmt.Errorf("received pidfd is not live: %w", err)
	}
	if err = setTarget(r.moduleParameter, c.hello.PID); err != nil {
		return nil, err
	}
	emit("worker_ready", map[string]any{"pid": c.hello.PID, "uid": uid, "start_ticks": c.hello.StartTicks, "pidfd_source": "worker pidfd_open(self), passed with SCM_RIGHTS"})
	return c, nil
}

func (c *child) request(m message, expectFD bool) (message, int, error) {
	if err := sendMessage(c.ipc, m, -1); err != nil {
		return message{}, -1, err
	}
	reply, fd, err := receiveMessage(c.ipc)
	if err != nil {
		return reply, -1, err
	}
	if reply.Op != m.Op || reply.SocketID != m.SocketID || reply.PID != c.hello.PID || reply.Error != "" || ((fd >= 0) != expectFD) {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		return reply, -1, fmt.Errorf("worker response mismatch: request=%+v reply=%+v fd=%d", m, reply, fd)
	}
	if fd >= 0 {
		c.sockets = append(c.sockets, fd)
	}
	return reply, fd, nil
}

func (c *child) exit() error {
	if c.waited {
		return nil
	}
	if _, _, err := c.request(message{Op: "exit"}, false); err != nil {
		return err
	}
	err := c.cmd.Wait()
	c.waited = true
	if err != nil {
		return fmt.Errorf("worker exit: %w; output=%s", err, c.output.String())
	}
	if err = unix.PidfdSendSignal(c.pidfd, 0, nil, 0); !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("exited worker pidfd expected ESRCH, got %v", err)
	}
	return setTarget(c.moduleParameter, 0)
}

func (c *child) close() error {
	var cleanup []error
	if c.moduleParameter != "" {
		cleanup = append(cleanup, setTarget(c.moduleParameter, 0))
	}
	if c.cmd != nil && c.cmd.Process != nil && !c.waited {
		_ = c.cmd.Process.Kill()
		_ = c.cmd.Wait()
		c.waited = true
	}
	if c.ipc >= 0 {
		_ = unix.Close(c.ipc)
		c.ipc = -1
	}
	if c.pidfd >= 0 {
		_ = unix.Close(c.pidfd)
		c.pidfd = -1
	}
	for _, fd := range c.sockets {
		_ = unix.Close(fd)
	}
	c.sockets = nil
	return errors.Join(cleanup...)
}

func (r *runner) register(c *child) (registration, error) {
	r.generation++
	reg, err := newRegistration(c.hello.PID, c.hello.UID, r.generation)
	if err != nil {
		return reg, err
	}
	token := [2]uint64{reg.TokenLo, reg.TokenHi}
	if r.seenTokens[token] {
		return reg, fmt.Errorf("duplicate random token")
	}
	key := uint32(c.pidfd)
	if err = r.coll.Maps["task_identity"].Update(&key, &reg, ebpf.UpdateAny); err != nil {
		return reg, fmt.Errorf("TASK_STORAGE update using worker's pidfd: %w", err)
	}
	var readback registration
	if err = r.coll.Maps["task_identity"].Lookup(&key, &readback); err != nil || readback != reg {
		return reg, fmt.Errorf("TASK_STORAGE readback mismatch: got=%+v error=%v", readback, err)
	}
	r.seenTokens[token] = true
	emit("registered", map[string]any{"registration": reg, "synthetic_test_identity": true})
	return reg, nil
}

type testSocket struct {
	id           uint32
	fd           int
	family, kind uint16
	want         expectedIdentity
}

func (r *runner) create(c *child, id uint32, family, kind uint16, reg registration, registered, nonleader bool) (testSocket, error) {
	reply, fd, err := c.request(message{Op: "create", SocketID: id, Family: family, SockType: kind, Nonleader: nonleader}, true)
	if err != nil {
		return testSocket{}, err
	}
	return r.verifyCreated(c.hello, reply, fd, id, family, kind, reg, registered, nonleader)
}

func (r *runner) verifyCreated(hello, reply message, fd int, id uint32, family, kind uint16, reg registration, registered, nonleader bool) (testSocket, error) {
	s := testSocket{id: id, fd: fd, family: family, kind: kind}
	var err error
	if reply.PID != hello.PID || reply.UID != hello.UID || reply.SocketID != id || reply.Family != family || reply.SockType != kind {
		return s, fmt.Errorf("created socket metadata mismatch: %+v", reply)
	}
	if reply.Cookie == 0 || r.seenCookies[reply.Cookie] {
		return s, fmt.Errorf("zero or repeated SO_COOKIE %d", reply.Cookie)
	}
	if nonleader && reply.TID == hello.PID {
		return s, fmt.Errorf("nonleader case ran on leader")
	}
	s.want = expectedIdentity{Registration: reg, Cookie: reply.Cookie, TGID: hello.PID, TID: reply.TID, UID: hello.UID, StartTicks: hello.StartTicks, Family: family, Registered: registered}
	key := uint32(fd)
	var captured identity
	if err = r.coll.Maps["socket_identity"].Lookup(&key, &captured); err != nil {
		return s, fmt.Errorf("SK_STORAGE absent before any network send: %w", err)
	}
	if err = validateIdentity(captured, s.want); err != nil {
		return s, err
	}
	var observed observation
	if err = r.coll.Maps["observed_by_cookie"].Lookup(&reply.Cookie, &observed); !errors.Is(err, ebpf.ErrKeyNotExist) {
		return s, fmt.Errorf("observation unexpectedly exists before first send, error=%v value=%+v", err, observed)
	}
	r.seenCookies[reply.Cookie] = true
	r.created++
	if registered {
		r.registered++
	}
	emit("socket_before_send", map[string]any{"identity": captured, "socket_id": id, "nonleader": nonleader, "storage_source": "SCM_RIGHTS socket FD"})
	return s, nil
}

// A private listener supplies network truth independently of the BPF record.
func destination(family, kind uint16) (address string, wait func() error, closeListener func(), err error) {
	network, host := "4", "127.0.0.1:0"
	if family == unix.AF_INET6 {
		network, host = "6", "[::1]:0"
	}
	if kind == unix.SOCK_DGRAM {
		conn, e := net.ListenPacket("udp"+network, host)
		if e != nil {
			return "", nil, nil, e
		}
		return conn.LocalAddr().String(), func() error {
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			var b [128]byte
			n, _, e := conn.ReadFrom(b[:])
			if e != nil {
				return e
			}
			if string(b[:n]) != probePayload {
				return fmt.Errorf("UDP payload mismatch")
			}
			return nil
		}, func() { _ = conn.Close() }, nil
	}
	l, e := net.Listen("tcp"+network, host)
	if e != nil {
		return "", nil, nil, e
	}
	return l.Addr().String(), func() error {
		_ = l.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
		conn, e := l.Accept()
		if e != nil {
			return e
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, len(probePayload))
		if _, e = io.ReadFull(conn, b); e != nil {
			return e
		}
		if string(b) != probePayload {
			return fmt.Errorf("TCP payload mismatch")
		}
		return nil
	}, func() { _ = l.Close() }, nil
}

func (r *runner) sendAndObserve(c *child, s testSocket, afterExit bool) error {
	address, wait, closeListener, err := destination(s.family, s.kind)
	if err != nil {
		return err
	}
	defer closeListener()
	if afterExit {
		err = sendSocket(s.fd, s.family, s.kind, address)
	} else {
		_, _, err = c.request(message{Op: "send", SocketID: s.id, Address: address}, false)
	}
	if err != nil {
		return err
	}
	if err = wait(); err != nil {
		return fmt.Errorf("loopback receiver: %w", err)
	}
	var observed observation
	// The TC program runs synchronously before these local sends complete. A
	// missing entry is a failure, not a reason to wait for a later packet.
	if err = r.coll.Maps["observed_by_cookie"].Lookup(&s.want.Cookie, &observed); err != nil {
		return fmt.Errorf("first-packet TC observation: %w", err)
	}
	flag := uint32(packetUDP)
	if s.kind == unix.SOCK_STREAM {
		flag = packetTCPSYN
	}
	if err = validateObservation(observed, s.want, flag, r.ifindex); err != nil {
		return err
	}
	if s.kind == unix.SOCK_DGRAM && observed.PacketCount != 1 {
		return fmt.Errorf("one UDP datagram produced %d egress observations", observed.PacketCount)
	}
	if s.kind == unix.SOCK_STREAM && observed.PacketFlags&(1<<5) != 0 {
		return fmt.Errorf("first TCP packet was SYN+ACK, not client's initial SYN")
	}
	emit("first_packet", map[string]any{"observation": observed, "destination": address, "transport": s.kind, "creator_exited": afterExit, "sender_pid": func() uint32 {
		if afterExit {
			return uint32(os.Getpid())
		}
		return c.hello.PID
	}()})
	return nil
}

func (r *runner) runCase(ctx context.Context, name string) (err error) {
	if strings.HasPrefix(name, "native_") {
		return r.runNativeCase(ctx, name)
	}
	uid := 2000
	if name == "root_matrix" {
		uid = 0
	}
	c, err := r.spawn(ctx, uid)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, c.close()) }()
	var reg registration
	registered := name != "unregistered" && name != "late_registration"
	if registered {
		reg, err = r.register(c)
		if err != nil {
			return err
		}
	}
	switch name {
	case "registration_uid_mismatch", "registration_tgid_mismatch", "registration_deleted", "late_registration":
		return r.registrationBoundary(c, name, reg)
	case "root_matrix", "shell_matrix_a", "shell_matrix_b":
		id := uint32(0)
		for _, family := range []uint16{unix.AF_INET, unix.AF_INET6} {
			for _, kind := range []uint16{unix.SOCK_STREAM, unix.SOCK_DGRAM} {
				id++
				s, e := r.create(c, id, family, kind, reg, true, false)
				if e != nil {
					return e
				}
				if e = r.sendAndObserve(c, s, false); e != nil {
					return e
				}
			}
		}
	case "token_snapshot":
		a, e := r.create(c, 1, unix.AF_INET, unix.SOCK_DGRAM, reg, true, false)
		if e != nil {
			return e
		}
		reg, e = r.register(c)
		if e != nil {
			return e
		}
		b, e := r.create(c, 2, unix.AF_INET, unix.SOCK_DGRAM, reg, true, false)
		if e != nil {
			return e
		}
		if e = r.sendAndObserve(c, a, false); e != nil {
			return e
		}
		if e = r.sendAndObserve(c, b, false); e != nil {
			return e
		}
	case "unregistered", "nonleader":
		s, e := r.create(c, 1, unix.AF_INET, unix.SOCK_DGRAM, reg, registered, name == "nonleader")
		if e != nil {
			return e
		}
		if e = r.sendAndObserve(c, s, false); e != nil {
			return e
		}
	case "creator_exit":
		var sockets []testSocket
		for n, kind := range []uint16{unix.SOCK_STREAM, unix.SOCK_DGRAM} {
			s, e := r.create(c, uint32(n+1), unix.AF_INET, kind, reg, true, false)
			if e != nil {
				return e
			}
			sockets = append(sockets, s)
		}
		if err = c.exit(); err != nil {
			return err
		}
		key := uint32(c.pidfd)
		var gone registration
		if e := r.coll.Maps["task_identity"].Lookup(&key, &gone); !errors.Is(e, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("exited/reaped creator TASK_STORAGE expected ENOENT, got %v", e)
		}
		for _, s := range sockets {
			if err = r.sendAndObserve(c, s, true); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unknown test case %q", name)
	}
	return c.exit()
}

var caseNames = []string{"root_matrix", "shell_matrix_a", "shell_matrix_b", "token_snapshot", "unregistered", "nonleader", "creator_exit",
	"registration_uid_mismatch", "registration_tgid_mismatch", "registration_deleted", "late_registration",
	"native_fork", "native_leader_exec", "native_nonleader_exec", "native_accept"}

func run(ctx context.Context, object, moduleParameter, nativeWorker string) (err error) {
	completed := make(map[string]bool)
	notRunReason := "setup failed before this case"
	defer func() {
		for _, name := range caseNames {
			if !completed[name] {
				emit("case_result", map[string]any{"name": name, "status": "not_run", "reason": notRunReason})
			}
		}
	}()
	if os.Geteuid() != 0 {
		return fmt.Errorf("root parent required")
	}
	selfNS, e := os.Readlink("/proc/self/ns/net")
	if e != nil {
		return e
	}
	initNS, e := os.Readlink("/proc/1/ns/net")
	if e != nil {
		return e
	}
	if selfNS == initNS {
		return fmt.Errorf("refusing to attach in PID 1's network namespace; run under external unshare -n")
	}
	iface, e := net.InterfaceByName("lo")
	if e != nil {
		return e
	}
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("private namespace lo is not up; external wrapper must configure it")
	}
	initial, e := os.ReadFile(moduleParameter)
	if e != nil {
		return e
	}
	if strings.TrimSpace(string(initial)) != "0" {
		return fmt.Errorf("bridge target_tgid must initially be zero")
	}
	defer func() { err = errors.Join(err, setTarget(moduleParameter, 0)) }()
	spec, e := ebpf.LoadCollectionSpec(object)
	if e != nil {
		return fmt.Errorf("read BPF object: %w", e)
	}
	coll, e := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 1 << 20}})
	if e != nil {
		return fmt.Errorf("BPF collection load: %+v", e)
	}
	defer coll.Close()
	for _, name := range []string{"task_identity", "socket_identity", "observed_by_cookie", "capture_stats", "filtered_families"} {
		if coll.Maps[name] == nil {
			return fmt.Errorf("missing BPF map %s", name)
		}
	}
	producer, e := link.AttachTracing(link.TracingOptions{Program: coll.Programs["capture_identity"]})
	if e != nil {
		return fmt.Errorf("attach module creation tracepoint: %w", e)
	}
	defer func() { err = errors.Join(err, producer.Close()) }()
	observer, e := link.AttachTCX(link.TCXOptions{Interface: iface.Index, Program: coll.Programs["observe_identity"], Attach: ebpf.AttachTCXEgress, Anchor: link.Head()})
	if e != nil {
		return fmt.Errorf("attach private lo observer: %w", e)
	}
	defer func() { err = errors.Join(err, observer.Close()) }()
	emit("setup", map[string]any{"network_namespace": selfNS, "init_network_namespace": initNS, "ifindex": iface.Index, "pinned": false, "object": object, "scope": "synthetic process-instance token transport; no APK attribution or throughput claim"})
	r := &runner{coll: coll, ifindex: uint32(iface.Index), moduleParameter: moduleParameter, nativeWorker: nativeWorker, seenCookies: map[uint64]bool{}, seenTokens: map[[2]uint64]bool{}}
	var failures []error
	for _, name := range caseNames {
		if ctx.Err() != nil {
			notRunReason = "run context ended before this case: " + ctx.Err().Error()
			failures = append(failures, ctx.Err())
			break
		}
		emit("case_begin", map[string]any{"name": name})
		e := r.runCase(ctx, name)
		completed[name] = true
		status := "pass"
		if e != nil {
			status = "fail"
			failures = append(failures, fmt.Errorf("%s: %w", name, e))
		}
		emit("case_result", map[string]any{"name": name, "status": status, "error": errorText(e)})
	}
	var stats [10]uint64
	for k := range stats {
		key := uint32(k)
		if e := coll.Maps["capture_stats"].Lookup(&key, &stats[k]); e != nil {
			failures = append(failures, e)
		}
	}
	filtered := make(map[uint32]uint64)
	var filteredTotal uint64
	for key := uint32(0); key < 64; key++ {
		var count uint64
		if e := coll.Maps["filtered_families"].Lookup(&key, &count); e != nil {
			failures = append(failures, e)
		} else if count > 0 {
			filtered[key] = count
			filteredTotal += count
		}
	}
	emit("filtered_socket_families", map[string]any{"counts": filtered, "total": filteredTotal, "meaning": "non-INET sockets intentionally excluded; family 1 is AF_UNIX"})
	if filteredTotal != stats[6] {
		failures = append(failures, fmt.Errorf("unaccounted filtered socket family: histogram=%d counter=%d", filteredTotal, stats[6]))
	}
	emit("capture_stats", map[string]any{"values": stats, "expected_created": r.created, "expected_registered": r.registered, "expected_mismatched": r.mismatched, "keys": []string{"hook_calls", "storage_create_failed", "registered", "unregistered", "registration_mismatch", "observation_insert_failed", "unsupported_family", "missing_birth", "duplicate_create", "missing_cookie"}})
	if stats[0] != r.created || stats[2] != r.registered || stats[3] != r.created-r.registered || stats[4] != r.mismatched {
		failures = append(failures, fmt.Errorf("capture totals disagree with verified sockets"))
	}
	for _, k := range []int{1, 5, 7, 8, 9} {
		if stats[k] != 0 {
			failures = append(failures, fmt.Errorf("capture error counter %d=%d", k, stats[k]))
		}
	}
	return errors.Join(failures...)
}
