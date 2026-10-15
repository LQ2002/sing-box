//go:build linux

package udpio

import (
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

// UringPacketBatchWriter writes a batch of datagrams with io_uring
// IORING_OP_SENDMSG instead of sendmmsg (experiment, opt-in:
// default on; SB_UDP_IOURING_SEND=0 turns it off and
// NewUringPacketBatchWriter returns nil).
//
// The batching is the one sing's syscall batch writer does
// (bufio packet_batch_offload_linux.go): consecutive datagrams with the same
// destination and size (the last of a run may be shorter) become one sendmsg
// with a UDP_SEGMENT control message, up to 64 segments and 65507 bytes. All
// messages of a batch are queued as SQEs and submitted with one
// io_uring_enter that also waits for their completions, so a batch costs one
// syscall, as sendmmsg does. Whether that is cheaper is what the experiment
// measures.
//
// The ring belongs to the writer and is guarded by its mutex: reply sockets
// are shared between sessions, so writes come from several goroutines. A
// send that cannot complete at once (full socket buffer) is retried by
// io_uring itself and completes before the wait returns.

// On by default since 2026-10-16 (measured 2026-10-15: sing-box CPU per MB
// of a download 12.7% below sendmmsg); falls back to sendmmsg when the ring
// cannot be set up. SB_UDP_IOURING_SEND=0 turns it off.
var EnableUDPIOUringSend = os.Getenv("SB_UDP_IOURING_SEND") != "0"

const (
	uringSendSQEntries = 64
	uringSendCQEntries = 128
	uringOpSendMsg     = 9
	uringSendMaxSegs   = 64
	uringSendMaxBytes  = 65507
)

type UringPacketBatchWriter struct {
	conn    *net.UDPConn
	rawConn syscall.RawConn
	access  sync.Mutex
	fd      int
	ipv6    bool
	noGSO   bool
	closed  bool

	ringFD  int
	ringMem []byte
	sqesMem []byte
	sqHead  *uint32
	sqTail  *uint32
	sqMask  uint32
	sqArray unsafe.Pointer
	sqes    unsafe.Pointer
	cqHead  *uint32
	cqTail  *uint32
	cqMask  uint32
	cqes    unsafe.Pointer

	names    []unix.RawSockaddrAny
	iovecs   []unix.Iovec
	messages []unix.Msghdr
	controls [][24]byte
	runs     [][2]int
	results  []int32
	// fallback is sing's sendmmsg writer, used after the ring could not be
	// set up
	fallback N.PacketBatchWriter
}

// NewUringPacketBatchWriter returns nil when SB_UDP_IOURING_SEND=0.
func NewUringPacketBatchWriter(conn *net.UDPConn) *UringPacketBatchWriter {
	if !EnableUDPIOUringSend || conn == nil || !uringAvailable() {
		return nil
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil
	}
	fd := -1
	var ipv6 bool
	_ = rawConn.Control(func(rawFD uintptr) {
		fd = int(rawFD)
		if name, nameErr := unix.Getsockname(fd); nameErr == nil {
			_, ipv6 = name.(*unix.SockaddrInet6)
		}
	})
	if fd < 0 {
		return nil
	}
	return &UringPacketBatchWriter{conn: conn, rawConn: rawConn, fd: fd, ipv6: ipv6, ringFD: -1}
}

func (w *UringPacketBatchWriter) setup() error {
	if uringSetupFault != nil {
		return uringSetupFault
	}
	var params uringParams
	params.flags = uringSetupCQSize
	params.cqEntries = uringSendCQEntries
	ringFD, _, errno := unix.RawSyscall(sysIOURingSetup, uringSendSQEntries, uintptr(unsafe.Pointer(&params)), 0)
	if errno != 0 {
		return os.NewSyscallError("io_uring_setup", errno)
	}
	w.ringFD = int(ringFD)
	if params.features&uringFeatSingleMmap == 0 {
		return E.New("io_uring without SINGLE_MMAP")
	}
	size := max(params.sqOff.array+params.sqEntries*4, params.cqOff.cqes+params.cqEntries*uint32(unsafe.Sizeof(uringCQE{})))
	ringMem, err := unix.Mmap(w.ringFD, 0, int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return E.Cause(err, "mmap io_uring rings")
	}
	w.ringMem = ringMem
	sqesMem, err := unix.Mmap(w.ringFD, uringOffSQEs, int(params.sqEntries)*int(unsafe.Sizeof(uringSQE{})), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return E.Cause(err, "mmap io_uring sqes")
	}
	w.sqesMem = sqesMem
	base := unsafe.Pointer(&ringMem[0])
	w.sqHead = (*uint32)(unsafe.Add(base, params.sqOff.head))
	w.sqTail = (*uint32)(unsafe.Add(base, params.sqOff.tail))
	w.sqMask = *(*uint32)(unsafe.Add(base, params.sqOff.ringMask))
	w.sqArray = unsafe.Add(base, params.sqOff.array)
	w.sqes = unsafe.Pointer(&sqesMem[0])
	w.cqHead = (*uint32)(unsafe.Add(base, params.cqOff.head))
	w.cqTail = (*uint32)(unsafe.Add(base, params.cqOff.tail))
	w.cqMask = *(*uint32)(unsafe.Add(base, params.cqOff.ringMask))
	w.cqes = unsafe.Add(base, params.cqOff.cqes)
	return nil
}

func (w *UringPacketBatchWriter) pushSQE(entry uringSQE) {
	tail := *w.sqTail
	index := tail & w.sqMask
	*(*uringSQE)(unsafe.Add(w.sqes, uintptr(index)*unsafe.Sizeof(uringSQE{}))) = entry
	*(*uint32)(unsafe.Add(w.sqArray, uintptr(index)*4)) = index
	atomic.StoreUint32(w.sqTail, tail+1)
}

// submitAndWait submits every queued SQE and waits until count completions
// are reaped into w.results (indexed by user_data).
func (w *UringPacketBatchWriter) submitAndWait(count int) error {
	toSubmit := atomic.LoadUint32(w.sqTail) - atomic.LoadUint32(w.sqHead)
	reaped := 0
	for reaped < count {
		need := count - reaped
		_, _, errno := unix.Syscall6(sysIOURingEnter, uintptr(w.ringFD), uintptr(toSubmit), uintptr(need), uringEnterGetEvents, 0, 0)
		switch errno {
		case 0, unix.EINTR, unix.EAGAIN, unix.EBUSY:
		default:
			return os.NewSyscallError("io_uring_enter", errno)
		}
		toSubmit = atomic.LoadUint32(w.sqTail) - atomic.LoadUint32(w.sqHead)
		head := atomic.LoadUint32(w.cqHead)
		tail := atomic.LoadUint32(w.cqTail)
		for ; head != tail; head++ {
			cqe := (*uringCQE)(unsafe.Add(w.cqes, uintptr(head&w.cqMask)*unsafe.Sizeof(uringCQE{})))
			if int(cqe.userData) < len(w.results) {
				w.results[cqe.userData] = cqe.res
				reaped++
			}
		}
		atomic.StoreUint32(w.cqHead, head)
	}
	return nil
}

// WritePacketBatch takes ownership of the buffers. destinations nil means a
// connected socket.
func (w *UringPacketBatchWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	w.access.Lock()
	if w.fallback == nil && !w.closed && w.ringFD < 0 {
		if err := w.setup(); err != nil {
			// keep the reply socket working without io_uring
			w.release()
			w.fallback = bufio.NewPacketBatchWriter(bufio.NewPacketConn(w.conn))
		}
	}
	if fallback := w.fallback; fallback != nil && !w.closed {
		w.access.Unlock()
		if destinations == nil {
			// connected socket (not used by the eBPF reply sockets): one
			// write per datagram
			defer buf.ReleaseMulti(buffers)
			for _, buffer := range buffers {
				if _, err := w.conn.Write(buffer.Bytes()); err != nil {
					return err
				}
			}
			return nil
		}
		return fallback.WritePacketBatch(buffers, destinations)
	}
	defer w.access.Unlock()
	defer buf.ReleaseMulti(buffers)
	if w.closed {
		return net.ErrClosed
	}
	count := len(buffers)
	w.names = growSlice(w.names, count)
	w.iovecs = growSlice(w.iovecs, count)
	w.messages = growSlice(w.messages, count)
	w.controls = growSlice(w.controls, count)
	w.runs = w.runs[:0]
	// Runs of GSO-mergeable datagrams, as sing's offload groups them.
	for start := 0; start < count; {
		end := start + 1
		if !w.noGSO {
			segment := buffers[start].Len()
			total := segment
			for end < count && end-start < uringSendMaxSegs {
				next := buffers[end].Len()
				if next == 0 || next > segment || total+next > uringSendMaxBytes {
					break
				}
				if destinations != nil && destinations[end] != destinations[start] {
					break
				}
				total += next
				end++
				if next < segment {
					break
				}
			}
		}
		w.runs = append(w.runs, [2]int{start, end})
		start = end
	}
	if err := w.sendRuns(buffers, destinations); err != nil {
		return err
	}
	return nil
}

func (w *UringPacketBatchWriter) sendRuns(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	for offset := 0; offset < len(w.runs); offset += uringSendSQEntries {
		runs := w.runs[offset:min(len(w.runs), offset+uringSendSQEntries)]
		w.results = growSlice(w.results, len(runs))
		for index, run := range runs {
			start, end := run[0], run[1]
			for i := start; i < end; i++ {
				w.iovecs[i] = buffers[i].Iovec(buffers[i].Len())
			}
			message := &w.messages[index]
			*message = unix.Msghdr{}
			message.Iov = &w.iovecs[start]
			message.SetIovlen(end - start)
			if destinations != nil {
				w.names[index] = unix.RawSockaddrAny{}
				message.Name = (*byte)(unsafe.Pointer(&w.names[index]))
				message.Namelen = M.AddrPortToRawSockaddrAny(&w.names[index], destinations[start].AddrPort(), w.ipv6)
			}
			if end-start > 1 {
				control := w.controls[index][:unix.CmsgSpace(2)]
				clear(control)
				header := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
				header.Level = unix.IPPROTO_UDP
				header.Type = unix.UDP_SEGMENT
				header.SetLen(unix.CmsgLen(2))
				*(*uint16)(unsafe.Pointer(&control[unix.CmsgLen(0)])) = uint16(buffers[start].Len())
				message.Control = &control[0]
				message.SetControllen(len(control))
			}
			w.pushSQE(uringSQE{
				opcode:   uringOpSendMsg,
				fd:       int32(w.fd),
				addr:     uint64(uintptr(unsafe.Pointer(message))),
				len:      1,
				userData: uint64(index),
			})
		}
		if err := w.submitAndWait(len(runs)); err != nil {
			return err
		}
		for index, run := range runs {
			res := w.results[index]
			if res >= 0 {
				continue
			}
			errno := syscall.Errno(-res)
			if run[1]-run[0] > 1 && (errno == unix.EINVAL || errno == unix.EIO || errno == unix.ENOPROTOOPT || errno == unix.EOPNOTSUPP) {
				// No GSO on this socket: send the rest one by one from now on.
				w.noGSO = true
				for i := run[0]; i < run[1]; i++ {
					if err := w.sendOne(buffers[i], destinations, i); err != nil {
						return err
					}
				}
				continue
			}
			return os.NewSyscallError("io_uring sendmsg", errno)
		}
	}
	return nil
}

func (w *UringPacketBatchWriter) sendOne(buffer *buf.Buffer, destinations []M.Socksaddr, index int) error {
	if destinations == nil {
		_, err := w.conn.Write(buffer.Bytes())
		return err
	}
	address := destinations[index].AddrPort()
	if w.ipv6 && address.Addr().Is4() {
		address = netip.AddrPortFrom(netip.AddrFrom16(address.Addr().As16()), address.Port())
	}
	_, err := w.conn.WriteToUDPAddrPort(buffer.Bytes(), address)
	return err
}

// Close releases the ring; later writes fail with net.ErrClosed.
func (w *UringPacketBatchWriter) Close() {
	w.access.Lock()
	defer w.access.Unlock()
	w.closed = true
	w.release()
}

func (w *UringPacketBatchWriter) release() {
	if w.ringFD >= 0 {
		_ = unix.Close(w.ringFD)
		w.ringFD = -1
	}
	if w.ringMem != nil {
		_ = unix.Munmap(w.ringMem)
		w.ringMem = nil
	}
	if w.sqesMem != nil {
		_ = unix.Munmap(w.sqesMem)
		w.sqesMem = nil
	}
}

var _ N.PacketBatchWriter = (*UringPacketBatchWriter)(nil)
