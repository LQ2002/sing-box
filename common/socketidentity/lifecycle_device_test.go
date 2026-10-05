//go:build linux && arm64 && integration

package socketidentity

// Opt-in creator lifecycle acceptance (ANDROID_ATTRIBUTION_PLAN.md decision 3),
// run by experimental/identity_carrier_probe/run-creator-integration-device.sh
// in the same private mount/network namespace and bpffs as
// TestDeviceCollectorPersistence:
//
//   - a child process's own socket records the child, and the snapshot
//     survives the child's exit;
//   - a socket inherited across fork keeps its creator's snapshot;
//   - exec: a socket created before exec keeps the pre-exec name hash and
//     exe inode, one created after records the new program;
//   - accept: the accepted child socket has no snapshot (no BPF_F_CLONE);
//   - io_uring IORING_OP_SOCKET, inline and forced to an io-wq worker
//     (IOSQE_ASYNC), records the submitting process.
//
// Children are this test binary re-executed in TestDeviceCreatorLifecycleHelper
// and hand their sockets back over a socketpair with SCM_RIGHTS, because
// SK_STORAGE is looked up by a descriptor of the caller.

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const lifecycleRoleEnv = "SBO_SOCKET_CREATOR_LIFECYCLE_ROLE"

// lifecycleReport travels with each handed-over socket.
type lifecycleReport struct {
	PID      int    `json:"pid"`
	TID      int    `json:"tid"`
	Argv0    string `json:"argv0"`
	ExeInode uint64 `json:"exe_inode"`
	Stage    string `json:"stage"`
}

func lifecycleSelf(stage string) lifecycleReport {
	cmdline, _ := os.ReadFile("/proc/self/cmdline")
	argv0, _, _ := strings0(cmdline)
	var exe unix.Stat_t
	_ = unix.Stat("/proc/self/exe", &exe)
	return lifecycleReport{PID: os.Getpid(), TID: unix.Gettid(), Argv0: argv0, ExeInode: exe.Ino, Stage: stage}
}

func strings0(raw []byte) (string, []byte, bool) {
	for index, value := range raw {
		if value == 0 {
			return string(raw[:index]), raw[index+1:], true
		}
	}
	return string(raw), nil, false
}

func lifecycleSend(channel int, fd int, report lifecycleReport) error {
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return unix.Sendmsg(channel, data, unix.UnixRights(fd), nil, 0)
}

func lifecycleReceive(t *testing.T, channel int) (int, lifecycleReport) {
	t.Helper()
	data := make([]byte, 4096)
	oob := make([]byte, unix.CmsgSpace(4))
	if err := unix.SetsockoptTimeval(channel, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 20}); err != nil {
		t.Fatal(err)
	}
	n, oobn, _, _, err := unix.Recvmsg(channel, data, oob, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		t.Fatalf("receive handed-over socket: %v", err)
	}
	messages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(messages) != 1 {
		t.Fatalf("control message: %v (%d)", err, len(messages))
	}
	fds, err := unix.ParseUnixRights(&messages[0])
	if err != nil || len(fds) != 1 {
		t.Fatalf("rights: %v %v", fds, err)
	}
	var report lifecycleReport
	if err := json.Unmarshal(data[:n], &report); err != nil {
		t.Fatalf("report %q: %v", data[:n], err)
	}
	return fds[0], report
}

func lifecycleLookup(t *testing.T, creators *ebpf.Map, fd int) (Creator, error) {
	t.Helper()
	var got Creator
	key := uint32(fd)
	return got, creators.Lookup(&key, &got)
}

// lifecycleExpect checks pid/uid/name/exe of one snapshot; tid < 0 skips the
// thread check.
func lifecycleExpect(t *testing.T, label string, got Creator, fd int, pid, tid int, argv0 string, exeInode uint64) {
	t.Helper()
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		t.Fatal(err)
	}
	reference := fnv.New64a()
	_, _ = reference.Write([]byte(argv0))
	switch {
	case !got.Valid() || got.Cookie != cookie:
		t.Fatalf("%s: invalid snapshot %+v (cookie %d)", label, got, cookie)
	case int(got.ProcessID) != pid || (tid >= 0 && int(got.ThreadID) != tid) || got.UserID != 0:
		t.Fatalf("%s: creator pid/tid/uid %d/%d/%d, want %d/%d/0", label, got.ProcessID, got.ThreadID, got.UserID, pid, tid)
	case got.Flags&CreatorNameValid == 0 || got.Flags&CreatorNameTruncated != 0 || got.NameLength() != len(argv0) || got.ProcessNameHash != reference.Sum64():
		t.Fatalf("%s: name evidence flags=%#x len=%d hash=%#x, want FNV(%q)=%#x", label, got.Flags, got.NameLength(), got.ProcessNameHash, argv0, reference.Sum64())
	case got.Flags&CreatorExeValid == 0 || got.ExeInode != exeInode:
		t.Fatalf("%s: exe inode %d flags=%#x, want %d", label, got.ExeInode, got.Flags, exeInode)
	}
	t.Logf("LIFECYCLE %s pid=%d tid=%d birth_ns=%d flags=%#x name_len=%d argv0=%q exe_inode=%d", label, got.ProcessID, got.ThreadID, got.StartTimeNs, got.Flags, got.NameLength(), argv0, got.ExeInode)
}

func lifecycleChild(t *testing.T, role string, channel *os.File, extra ...*os.File) (*exec.Cmd, *bytesBuffer) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestDeviceCreatorLifecycleHelper$", "-test.v", "-test.timeout=30s")
	cmd.Env = deviceReplaceEnv(os.Environ(), map[string]string{lifecycleRoleEnv: role})
	cmd.ExtraFiles = append([]*os.File{channel}, extra...)
	output := &bytesBuffer{}
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd, output
}

type bytesBuffer struct{ data []byte }

func (b *bytesBuffer) Write(p []byte) (int, error) { b.data = append(b.data, p...); return len(p), nil }
func (b *bytesBuffer) String() string              { return string(b.data) }

func lifecycleSocketPair(t *testing.T) (int, *os.File) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(pair[0]) })
	return pair[0], os.NewFile(uintptr(pair[1]), "lifecycle-channel")
}

func TestDeviceCreatorLifecycle(t *testing.T) {
	pinPath := requireDeviceCollectorPath(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	collector, err := Open(Config{PinPath: pinPath})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := collector.Close(); err != nil {
			t.Error(err)
		}
		if err := Remove(pinPath); err != nil {
			t.Error(err)
		}
	}()
	creators := collector.Map()
	// Subtests run on their own goroutines: each locks its thread and takes
	// its own truth, so the recorded TID can be compared.

	t.Run("child-socket-survives-exit", func(t *testing.T) {
		parent, channel := lifecycleSocketPair(t)
		cmd, output := lifecycleChild(t, "create-and-exit", channel)
		_ = channel.Close()
		fd, report := lifecycleReceive(t, parent)
		defer unix.Close(fd)
		if err := cmd.Wait(); err != nil {
			t.Fatalf("child: %v\n%s", err, output)
		}
		if _, err := os.Stat("/proc/" + strconv.Itoa(report.PID)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("creator %d still present: %v", report.PID, err)
		}
		got, err := lifecycleLookup(t, creators, fd)
		if err != nil {
			t.Fatal(err)
		}
		lifecycleExpect(t, "child-after-exit", got, fd, report.PID, report.TID, report.Argv0, report.ExeInode)
	})

	t.Run("fork-inherited-socket-keeps-parent", func(t *testing.T) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		self := lifecycleSelf("parent")
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		inherited := os.NewFile(uintptr(fd), "inherited")
		defer inherited.Close()
		before, err := lifecycleLookup(t, creators, fd)
		if err != nil {
			t.Fatal(err)
		}
		parent, channel := lifecycleSocketPair(t)
		cmd, output := lifecycleChild(t, "use-inherited", channel, inherited)
		_ = channel.Close()
		_ = parent
		if err := cmd.Wait(); err != nil {
			t.Fatalf("child: %v\n%s", err, output)
		}
		after, err := lifecycleLookup(t, creators, fd)
		if err != nil || after != before {
			t.Fatalf("inherited socket snapshot changed: before=%+v after=%+v err=%v", before, after, err)
		}
		lifecycleExpect(t, "fork-inherited", after, fd, self.PID, self.TID, self.Argv0, self.ExeInode)
	})

	t.Run("exec-before-and-after", func(t *testing.T) {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		// A copy has its own inode, so exe evidence can tell the programs apart.
		target := filepath.Join(filepath.Dir(executable), "lifecycle-exec-target")
		source, err := os.ReadFile(executable)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, source, 0o700); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(target)
		var targetStat unix.Stat_t
		if err := unix.Stat(target, &targetStat); err != nil {
			t.Fatal(err)
		}
		parent, channel := lifecycleSocketPair(t)
		cmd, output := lifecycleChild(t, "exec-first", channel)
		_ = channel.Close()
		first, firstReport := lifecycleReceive(t, parent)
		defer unix.Close(first)
		second, secondReport := lifecycleReceive(t, parent)
		defer unix.Close(second)
		if err := cmd.Wait(); err != nil {
			t.Fatalf("child: %v\n%s", err, output)
		}
		if firstReport.PID != secondReport.PID || secondReport.ExeInode != targetStat.Ino || secondReport.Argv0 != "sbo-exec-target" {
			t.Fatalf("exec did not happen as planned: %+v %+v target_inode=%d", firstReport, secondReport, targetStat.Ino)
		}
		before, err := lifecycleLookup(t, creators, first)
		if err != nil {
			t.Fatal(err)
		}
		after, err := lifecycleLookup(t, creators, second)
		if err != nil {
			t.Fatal(err)
		}
		lifecycleExpect(t, "pre-exec-socket", before, first, firstReport.PID, firstReport.TID, firstReport.Argv0, firstReport.ExeInode)
		lifecycleExpect(t, "post-exec-socket", after, second, secondReport.PID, -1, secondReport.Argv0, secondReport.ExeInode)
		if before.StartTimeNs != after.StartTimeNs {
			t.Fatalf("exec changed the leader birth time: %d -> %d", before.StartTimeNs, after.StartTimeNs)
		}
	})

	t.Run("accepted-socket-has-no-snapshot", func(t *testing.T) {
		self := lifecycleSelf("parent")
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		client, err := net.Dial("tcp4", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		accepted, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer accepted.Close()
		for label, conn := range map[string]syscall.Conn{"listener": listener.(*net.TCPListener), "client": client.(*net.TCPConn), "accepted": accepted.(*net.TCPConn)} {
			raw, err := conn.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var lookupErr error
			var got Creator
			if err := raw.Control(func(fd uintptr) { got, lookupErr = lifecycleLookup(t, creators, int(fd)) }); err != nil {
				t.Fatal(err)
			}
			switch {
			case label == "accepted" && !errors.Is(lookupErr, ebpf.ErrKeyNotExist):
				t.Fatalf("accepted socket has a snapshot: %+v %v", got, lookupErr)
			case label != "accepted" && (lookupErr != nil || int(got.ProcessID) != self.PID):
				t.Fatalf("%s snapshot: %+v %v", label, got, lookupErr)
			}
			t.Logf("LIFECYCLE accept %s lookup_error=%v pid=%d", label, lookupErr, got.ProcessID)
		}
	})

	t.Run("io_uring-socket", func(t *testing.T) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		self := lifecycleSelf("parent")
		ring, err := newLifecycleRing()
		if err != nil {
			t.Fatalf("io_uring setup: %v", err)
		}
		defer ring.close()
		for _, async := range []bool{false, true} {
			fd, err := ring.socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, async)
			if err != nil {
				t.Fatalf("IORING_OP_SOCKET async=%v: %v", async, err)
			}
			got, lookupErr := lifecycleLookup(t, creators, fd)
			if lookupErr != nil {
				_ = unix.Close(fd)
				t.Fatalf("io_uring socket async=%v has no snapshot: %v", async, lookupErr)
			}
			// Inline issue runs in the submitting thread; IOSQE_ASYNC runs in
			// an io-wq worker of this thread group (kernel/fork.c
			// CLONE_THREAD), so only the TGID is fixed.
			tid := self.TID
			if async {
				tid = -1
			}
			lifecycleExpect(t, fmt.Sprintf("io_uring async=%v", async), got, fd, self.PID, tid, self.Argv0, self.ExeInode)
			if async && int(got.ThreadID) == unix.Gettid() {
				t.Logf("LIFECYCLE io_uring async ran on the submitting thread %d", got.ThreadID)
			}
			_ = unix.Close(fd)
		}
	})
}

// TestDeviceCreatorLifecycleHelper is the child side; it does nothing unless
// started by TestDeviceCreatorLifecycle.
func TestDeviceCreatorLifecycleHelper(t *testing.T) {
	role := os.Getenv(lifecycleRoleEnv)
	if role == "" {
		t.Skip("helper process only")
	}
	runtime.LockOSThread()
	channel := 3
	switch role {
	case "create-and-exit":
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := lifecycleSend(channel, fd, lifecycleSelf("child")); err != nil {
			t.Fatal(err)
		}
	case "use-inherited":
		// fd 4 is the parent's socket; using it must not relabel it.
		if _, err := unix.Getsockname(4); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(fd)
	case "exec-first":
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := lifecycleSend(channel, fd, lifecycleSelf("pre-exec")); err != nil {
			t.Fatal(err)
		}
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(filepath.Dir(executable), "lifecycle-exec-target")
		environment := deviceReplaceEnv(os.Environ(), map[string]string{lifecycleRoleEnv: "exec-second"})
		err = unix.Exec(target, []string{"sbo-exec-target", "-test.run=^TestDeviceCreatorLifecycleHelper$", "-test.v", "-test.timeout=30s"}, environment)
		t.Fatalf("exec: %v", err)
	case "exec-second":
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := lifecycleSend(channel, fd, lifecycleSelf("post-exec")); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown role %q", role)
	}
}

// lifecycleRing is the smallest io_uring needed to submit one
// IORING_OP_SOCKET at a time (include/uapi/linux/io_uring.h, ACK 6.12).
type lifecycleRing struct {
	fd             int
	ring, sqes     []byte
	params         ioUringParams
	sqTail, sqMask *uint32
	sqArray        unsafe.Pointer
	cqHead, cqTail *uint32
	cqMask         *uint32
	cqes           unsafe.Pointer
}

type ioUringParams struct {
	SQEntries, CQEntries, Flags, SQThreadCPU, SQThreadIdle, Features, WQFD uint32
	Resv                                                                   [3]uint32
	SQOff                                                                  struct {
		Head, Tail, RingMask, RingEntries, Flags, Dropped, Array, Resv1 uint32
		UserAddr                                                        uint64
	}
	CQOff struct {
		Head, Tail, RingMask, RingEntries, Overflow, CQEs, Flags, Resv1 uint32
		UserAddr                                                        uint64
	}
}

const (
	sysIoUringSetup      = 425
	sysIoUringEnter      = 426
	ioringOpSocket       = 45
	ioringEnterGetevents = 1
	ioringFeatSingleMmap = 1
	iosqeAsync           = 1 << 4
	ioringOffSQES        = 0x10000000
	ioUringSQESize       = 64
	ioUringCQESize       = 16
)

func newLifecycleRing() (*lifecycleRing, error) {
	r := &lifecycleRing{}
	fd, _, errno := unix.Syscall(sysIoUringSetup, 4, uintptr(unsafe.Pointer(&r.params)), 0)
	if errno != 0 {
		return nil, errno
	}
	r.fd = int(fd)
	if r.params.Features&ioringFeatSingleMmap == 0 {
		_ = unix.Close(r.fd)
		return nil, errors.New("kernel lacks IORING_FEAT_SINGLE_MMAP")
	}
	size := max(r.params.SQOff.Array+r.params.SQEntries*4, r.params.CQOff.CQEs+r.params.CQEntries*ioUringCQESize)
	var err error
	if r.ring, err = unix.Mmap(r.fd, 0, int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE); err != nil {
		_ = unix.Close(r.fd)
		return nil, err
	}
	if r.sqes, err = unix.Mmap(r.fd, ioringOffSQES, int(r.params.SQEntries*ioUringSQESize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE); err != nil {
		r.close()
		return nil, err
	}
	base := unsafe.Pointer(&r.ring[0])
	r.sqTail = (*uint32)(unsafe.Add(base, r.params.SQOff.Tail))
	r.sqMask = (*uint32)(unsafe.Add(base, r.params.SQOff.RingMask))
	r.sqArray = unsafe.Add(base, r.params.SQOff.Array)
	r.cqHead = (*uint32)(unsafe.Add(base, r.params.CQOff.Head))
	r.cqTail = (*uint32)(unsafe.Add(base, r.params.CQOff.Tail))
	r.cqMask = (*uint32)(unsafe.Add(base, r.params.CQOff.RingMask))
	r.cqes = unsafe.Add(base, r.params.CQOff.CQEs)
	return r, nil
}

func (r *lifecycleRing) close() {
	if r.sqes != nil {
		_ = unix.Munmap(r.sqes)
	}
	if r.ring != nil {
		_ = unix.Munmap(r.ring)
	}
	_ = unix.Close(r.fd)
}

// socket submits one IORING_OP_SOCKET (domain in fd, type in off, protocol
// in len; io_uring/net.c io_socket_prep) and waits for its completion.
func (r *lifecycleRing) socket(domain, socketType int, async bool) (int, error) {
	tail := *r.sqTail
	index := tail & *r.sqMask
	sqe := r.sqes[index*ioUringSQESize : (index+1)*ioUringSQESize]
	clear(sqe)
	sqe[0] = ioringOpSocket
	if async {
		sqe[1] = iosqeAsync
	}
	*(*int32)(unsafe.Pointer(&sqe[4])) = int32(domain)
	*(*uint64)(unsafe.Pointer(&sqe[8])) = uint64(socketType)
	*(*uint64)(unsafe.Pointer(&sqe[32])) = 0x5b0 // user_data
	*(*uint32)(unsafe.Add(r.sqArray, index*4)) = index
	// The kernel reads the tail with acquire semantics; Go's atomic store
	// gives the matching release.
	atomic.StoreUint32(r.sqTail, tail+1)
	if _, _, errno := unix.Syscall6(sysIoUringEnter, uintptr(r.fd), 1, 1, ioringEnterGetevents, 0, 0); errno != 0 {
		return -1, errno
	}
	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadUint32(r.cqHead) == atomic.LoadUint32(r.cqTail) {
		if time.Now().After(deadline) {
			return -1, io.ErrNoProgress
		}
		time.Sleep(time.Millisecond)
	}
	head := atomic.LoadUint32(r.cqHead)
	cqe := unsafe.Add(r.cqes, (head&*r.cqMask)*ioUringCQESize)
	result := *(*int32)(unsafe.Add(cqe, 8))
	atomic.StoreUint32(r.cqHead, head+1)
	if result < 0 {
		return -1, syscall.Errno(-result)
	}
	return int(result), nil
}
