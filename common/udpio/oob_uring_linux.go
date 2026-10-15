//go:build linux

package udpio

import (
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

// uringOOBReadWaiter is an io_uring alternative to oobPacketBatchReadWaiter
// (experiment, opt-in: SB_UDP_IOURING=1), for listener sockets that need the
// source address and ancillary data of every datagram (the eBPF inbound's
// UDP listener).
//
// It is the same design as sing-shadowsocks2's uringBatchReader: one
// multishot IORING_OP_RECVMSG with a provided buffer ring stays armed; the
// receive runs in task_work of the thread that armed it, so the reading
// goroutine is locked to its OS thread; with the completion queue empty it
// blocks in io_uring_enter(GETEVENTS) and an arriving datagram wakes that
// thread. On the phone (2026-10-15) the client-side reader cut sing-box CPU
// during an HTTP/3 download by ~60% against recvmmsg, mostly by removing the
// netpoller -> goroutine wake chain per batch.
//
// Each ring buffer holds struct io_uring_recvmsg_out, the source sockaddr
// (uringOOBNameLen bytes), the control area (oobSize) and the payload. A
// datagram that does not fit is dropped (MSG_TRUNC) instead of failing the
// whole listener as the recvmmsg reader does; truncated control data
// (MSG_CTRUNC) is dropped the same way.
//
// Shutdown must be called before the socket closes: io_uring holds its own
// file reference, so a closed fd would not end the armed receive.

var EnableUDPIOUring = os.Getenv("SB_UDP_IOURING") == "1"

// Wait variants (experiment), as in sing-shadowsocks2's reader.
// SB_UDP_IOURING_WAIT=netpoll: no locked thread and no blocking
// io_uring_enter; the ring fd goes to the Go netpoller and the goroutine
// parks there. The receive task_work runs on whichever thread armed the
// multishot receive, which the kernel wakes for every batch.
// SB_UDP_IOURING_COOP=1 adds IORING_SETUP_COOP_TASKRUN.
var (
	udpIOUringNetpoll = os.Getenv("SB_UDP_IOURING_WAIT") == "netpoll"
	udpIOUringCoop    = os.Getenv("SB_UDP_IOURING_COOP") == "1"
)

const (
	uringOOBRecvTag     = 1
	uringOOBCancelTag   = 2
	uringOOBBufferGroup = 9
	uringOOBBufferCount = 128 // power of two
	uringOOBBufferSize  = 4096
	uringOOBNameLen     = unix.SizeofSockaddrInet6
	uringRecvOutSize    = 16
	uringSQEntries      = 8
	uringCQEntries      = 512
	sysIOURingSetup     = 425
	sysIOURingEnter     = 426
	sysIOURingRegister  = 427
	uringSetupCQSize    = 1 << 3
	uringSetupCoop      = 1 << 8
	uringSQCQOverflow   = 1 << 1
	uringFeatSingleMmap = 1 << 0
	uringEnterGetEvents = 1 << 0
	uringOpRecvMsg      = 10
	uringOpAsyncCancel  = 14
	uringSQEBufSelect   = 1 << 5
	uringRecvMultishot  = 1 << 1
	uringCQEFBuffer     = 1 << 0
	uringCQEFMore       = 1 << 1
	uringCQEBufShift    = 16
	uringRegPbufRing    = 22
	uringOffSQEs        = 0x10000000
)

type uringSQOffsets struct {
	head, tail, ringMask, ringEntries, flags, dropped, array, resv1 uint32
	userAddr                                                        uint64
}

type uringCQOffsets struct {
	head, tail, ringMask, ringEntries, overflow, cqes, flags, resv1 uint32
	userAddr                                                        uint64
}

type uringParams struct {
	sqEntries, cqEntries, flags, sqThreadCPU, sqThreadIdle, features, wqFD uint32
	resv                                                                   [3]uint32
	sqOff                                                                  uringSQOffsets
	cqOff                                                                  uringCQOffsets
}

type uringSQE struct {
	opcode      uint8
	flags       uint8
	ioprio      uint16
	fd          int32
	off         uint64
	addr        uint64
	len         uint32
	opFlags     uint32
	userData    uint64
	bufGroup    uint16
	personality uint16
	spliceFD    int32
	addr3       uint64
	pad         uint64
}

type uringCQE struct {
	userData uint64
	res      int32
	flags    uint32
}

type uringBufRegister struct {
	ringAddr    uint64
	ringEntries uint32
	bgid        uint16
	flags       uint16
	resv        [3]uint64
}

type uringBuf struct {
	addr uint64
	len  uint32
	bid  uint16
	tail uint16
}

func init() {
	if unsafe.Sizeof(uringParams{}) != 120 || unsafe.Sizeof(uringSQE{}) != 64 ||
		unsafe.Sizeof(uringBufRegister{}) != 40 || unsafe.Sizeof(uringCQE{}) != 16 ||
		unsafe.Sizeof(uringBuf{}) != 16 {
		panic("udpio: io_uring ABI size mismatch")
	}
}

type uringOOBReadWaiter struct {
	rawConn syscall.RawConn
	fd      int
	oobSize int
	options N.ReadWaitOptions

	access  sync.Mutex
	inEnter bool
	closed  atomic.Bool
	cancel  sync.Once

	ringFD  int
	ringMem []byte
	sqesMem []byte
	bufRing []byte
	slab    []byte
	sqHead  *uint32
	sqTail  *uint32
	sqMask  uint32
	sqArray unsafe.Pointer
	sqes    unsafe.Pointer
	cqHead  *uint32
	cqTail  *uint32
	cqMask  uint32
	cqes    unsafe.Pointer
	sqFlags *uint32
	bufTail uint16
	msghdr  unix.Msghdr
	// netpoll variant: the ring fd as an *os.File in the Go netpoller
	ringFile *os.File
	ringRaw  syscall.RawConn
	armed    bool
	locked   bool
	eof      bool

	pending        []*buf.Buffer
	pendingSources []M.Socksaddr
	pendingOOB     [][]byte
	oobArena       []byte
	returnedOOB    [][]byte
	// fallback is the recvmmsg reader used after the ring could not be set
	// up; only the reading goroutine touches it.
	fallback OOBPacketBatchReadWaiter
}

// newUringOOBReadWaiter returns nil unless SB_UDP_IOURING=1.
func newUringOOBReadWaiter(conn *net.UDPConn, oobSize int) OOBPacketBatchReadWaiter {
	if !EnableUDPIOUring || conn == nil || oobSize <= 0 || uringRecvOutSize+uringOOBNameLen+oobSize >= uringOOBBufferSize || !uringAvailable() {
		return nil
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil
	}
	fd := -1
	_ = rawConn.Control(func(rawFD uintptr) { fd = int(rawFD) })
	if fd < 0 {
		return nil
	}
	return &uringOOBReadWaiter{rawConn: rawConn, fd: fd, oobSize: oobSize, ringFD: -1}
}

func (w *uringOOBReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	if options.BatchSize <= 0 {
		options.BatchSize = 1
	}
	w.options = options
	return false
}

// Shutdown wakes a reader blocked in io_uring_enter with an ASYNC_CANCEL of
// its receive, or releases the ring of a reader that is not.
func (w *uringOOBReadWaiter) Shutdown() {
	w.closed.Store(true)
	w.access.Lock()
	defer w.access.Unlock()
	if !w.inEnter {
		w.release()
		return
	}
	w.cancel.Do(func() {
		w.pushSQE(uringSQE{opcode: uringOpAsyncCancel, fd: -1, addr: uringOOBRecvTag, userData: uringOOBCancelTag})
		toSubmit := atomic.LoadUint32(w.sqTail) - atomic.LoadUint32(w.sqHead)
		_, _, _ = unix.Syscall6(sysIOURingEnter, uintptr(w.ringFD), uintptr(toSubmit), 0, 0, 0, 0)
	})
}

func (w *uringOOBReadWaiter) setup() error {
	if uringSetupFault != nil {
		return uringSetupFault
	}
	var params uringParams
	params.flags = uringSetupCQSize
	if udpIOUringCoop {
		params.flags |= uringSetupCoop
	}
	params.cqEntries = uringCQEntries
	ringFD, _, errno := unix.RawSyscall(sysIOURingSetup, uringSQEntries, uintptr(unsafe.Pointer(&params)), 0)
	if errno != 0 {
		return os.NewSyscallError("io_uring_setup", errno)
	}
	w.ringFD = int(ringFD)
	if udpIOUringNetpoll {
		if err := unix.SetNonblock(w.ringFD, true); err != nil {
			return E.Cause(err, "set io_uring fd non-blocking")
		}
		// os.File owns the fd from here on; release closes it through the
		// file so the netpoller lets go of it first.
		w.ringFile = os.NewFile(uintptr(w.ringFD), "io_uring")
		ringRaw, err := w.ringFile.SyscallConn()
		if err != nil {
			return E.Cause(err, "io_uring fd raw conn")
		}
		w.ringRaw = ringRaw
	}
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
	w.sqFlags = (*uint32)(unsafe.Add(base, params.sqOff.flags))

	bufRing, err := unix.Mmap(-1, 0, uringOOBBufferCount*int(unsafe.Sizeof(uringBuf{})), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return E.Cause(err, "mmap io_uring buffer ring")
	}
	w.bufRing = bufRing
	w.slab = make([]byte, uringOOBBufferCount*uringOOBBufferSize)
	reg := uringBufRegister{
		ringAddr:    uint64(uintptr(unsafe.Pointer(&bufRing[0]))),
		ringEntries: uringOOBBufferCount,
		bgid:        uringOOBBufferGroup,
	}
	_, _, errno = unix.Syscall6(sysIOURingRegister, uintptr(w.ringFD), uringRegPbufRing, uintptr(unsafe.Pointer(&reg)), 1, 0, 0)
	if errno != 0 {
		return os.NewSyscallError("io_uring_register(PBUF_RING)", errno)
	}
	for bid := range uringOOBBufferCount {
		w.provide(uint16(bid))
	}
	w.publishBuffers()
	w.msghdr.Namelen = uringOOBNameLen
	w.msghdr.SetControllen(w.oobSize)
	return nil
}

func (w *uringOOBReadWaiter) provide(bid uint16) {
	entry := (*uringBuf)(unsafe.Add(unsafe.Pointer(&w.bufRing[0]), uintptr(w.bufTail&(uringOOBBufferCount-1))*unsafe.Sizeof(uringBuf{})))
	entry.addr = uint64(uintptr(unsafe.Pointer(&w.slab[int(bid)*uringOOBBufferSize])))
	entry.len = uringOOBBufferSize
	// Entry 0's bid shares a 32-bit word with the ring tail; publishBuffers
	// stores that word whole.
	entry.bid = bid
	w.bufTail++
}

func (w *uringOOBReadWaiter) publishBuffers() {
	first := (*uringBuf)(unsafe.Pointer(&w.bufRing[0]))
	atomic.StoreUint32((*uint32)(unsafe.Add(unsafe.Pointer(&w.bufRing[0]), 12)), uint32(first.bid)|uint32(w.bufTail)<<16)
}

func (w *uringOOBReadWaiter) pushSQE(entry uringSQE) {
	tail := *w.sqTail
	index := tail & w.sqMask
	*(*uringSQE)(unsafe.Add(w.sqes, uintptr(index)*unsafe.Sizeof(uringSQE{}))) = entry
	*(*uint32)(unsafe.Add(w.sqArray, uintptr(index)*4)) = index
	atomic.StoreUint32(w.sqTail, tail+1)
}

func (w *uringOOBReadWaiter) arm() {
	w.pushSQE(uringSQE{
		opcode:   uringOpRecvMsg,
		flags:    uringSQEBufSelect,
		ioprio:   uringRecvMultishot,
		fd:       int32(w.fd),
		addr:     uint64(uintptr(unsafe.Pointer(&w.msghdr))),
		userData: uringOOBRecvTag,
		bufGroup: uringOOBBufferGroup,
	})
	w.armed = true
}

func (w *uringOOBReadWaiter) enter() error {
	toSubmit := atomic.LoadUint32(w.sqTail) - atomic.LoadUint32(w.sqHead)
	if w.ringRaw != nil {
		return w.enterNetpoll(toSubmit)
	}
	for {
		ringFD := w.ringFD
		w.inEnter = true
		w.access.Unlock()
		_, _, errno := unix.Syscall6(sysIOURingEnter, uintptr(ringFD), uintptr(toSubmit), 1, uringEnterGetEvents, 0, 0)
		w.access.Lock()
		w.inEnter = false
		if w.ringFD < 0 {
			return io.EOF
		}
		switch errno {
		case 0:
			return nil
		case unix.EINTR, unix.EAGAIN, unix.EBUSY:
			toSubmit = atomic.LoadUint32(w.sqTail) - atomic.LoadUint32(w.sqHead)
			continue
		default:
			return os.NewSyscallError("io_uring_enter", errno)
		}
	}
}

// enterNetpoll is enter for the netpoll variant: submit without waiting,
// then park in the Go netpoller until the ring fd reports completions.
func (w *uringOOBReadWaiter) enterNetpoll(toSubmit uint32) error {
	for toSubmit > 0 {
		_, _, errno := unix.Syscall6(sysIOURingEnter, uintptr(w.ringFD), uintptr(toSubmit), 0, 0, 0, 0)
		if errno == unix.EINTR {
			continue
		}
		if errno != 0 && errno != unix.EAGAIN && errno != unix.EBUSY {
			return os.NewSyscallError("io_uring_enter", errno)
		}
		break
	}
	ringFD := w.ringFD
	w.inEnter = true
	w.access.Unlock()
	err := w.ringRaw.Read(func(uintptr) bool {
		if atomic.LoadUint32(w.cqHead) != atomic.LoadUint32(w.cqTail) {
			return true
		}
		// Completions that did not fit the CQ wait in the kernel's
		// overflow list until an io_uring_enter(GETEVENTS) flushes them.
		if atomic.LoadUint32(w.sqFlags)&uringSQCQOverflow != 0 {
			_, _, _ = unix.Syscall6(sysIOURingEnter, uintptr(ringFD), 0, 0, uringEnterGetEvents, 0, 0)
			return atomic.LoadUint32(w.cqHead) != atomic.LoadUint32(w.cqTail)
		}
		return false
	})
	w.access.Lock()
	w.inEnter = false
	if w.ringFD < 0 {
		return io.EOF
	}
	if err != nil {
		return E.Cause(err, "wait io_uring completions")
	}
	return nil
}

func (w *uringOOBReadWaiter) reap() error {
	head := atomic.LoadUint32(w.cqHead)
	tail := atomic.LoadUint32(w.cqTail)
	provided := false
	var reapErr error
	for ; head != tail; head++ {
		cqe := (*uringCQE)(unsafe.Add(w.cqes, uintptr(head&w.cqMask)*unsafe.Sizeof(uringCQE{})))
		if cqe.userData != uringOOBRecvTag {
			continue // the cancel's own completion
		}
		if cqe.flags&uringCQEFMore == 0 {
			w.armed = false
		}
		if cqe.flags&uringCQEFBuffer != 0 {
			bid := uint16(cqe.flags >> uringCQEBufShift)
			w.takeDatagram(bid, int(cqe.res))
			w.provide(bid)
			provided = true
			continue
		}
		switch {
		case cqe.res == 0, cqe.res == -int32(unix.ECANCELED):
			w.eof = true
		case cqe.res == -int32(unix.ENOBUFS):
			// every ring buffer was in use; they are back now, re-arm
		case cqe.res < 0:
			if reapErr == nil {
				reapErr = os.NewSyscallError("io_uring recvmsg", syscall.Errno(-cqe.res))
			}
		}
	}
	atomic.StoreUint32(w.cqHead, head)
	if provided {
		w.publishBuffers()
	}
	return reapErr
}

// takeDatagram copies one completed datagram (payload, source, control) out
// of ring buffer bid.
func (w *uringOOBReadWaiter) takeDatagram(bid uint16, res int) {
	if res < uringRecvOutSize {
		return
	}
	data := w.slab[int(bid)*uringOOBBufferSize : int(bid)*uringOOBBufferSize+res]
	nameLen := int(*(*uint32)(unsafe.Pointer(&data[0])))
	controlLen := int(*(*uint32)(unsafe.Pointer(&data[4])))
	payloadLen := int(*(*uint32)(unsafe.Pointer(&data[8])))
	msgFlags := *(*uint32)(unsafe.Pointer(&data[12]))
	if msgFlags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return
	}
	nameOffset := uringRecvOutSize
	controlOffset := nameOffset + uringOOBNameLen
	payloadOffset := controlOffset + w.oobSize
	if nameLen > uringOOBNameLen || controlLen > w.oobSize || payloadOffset+payloadLen > len(data) {
		return
	}
	buffer := w.options.NewPacketBuffer()
	if payloadLen > buffer.FreeLen() {
		buffer.Release()
		return
	}
	copy(buffer.Extend(payloadLen), data[payloadOffset:payloadOffset+payloadLen])
	w.options.PostReturn(buffer)
	var name unix.RawSockaddrAny
	copy((*[unix.SizeofSockaddrAny]byte)(unsafe.Pointer(&name))[:nameLen], data[nameOffset:nameOffset+nameLen])
	start := len(w.oobArena)
	w.oobArena = append(w.oobArena, data[controlOffset:controlOffset+controlLen]...)
	w.pending = append(w.pending, buffer)
	w.pendingSources = append(w.pendingSources, M.SocksaddrFromRawSockaddrAny(&name))
	// Offsets for now: oobArena may grow; slices are cut in WaitReadOOBPackets.
	w.pendingOOB = append(w.pendingOOB, w.oobArena[start:start+controlLen:start+controlLen])
}

func (w *uringOOBReadWaiter) WaitReadOOBPackets() (buffers []*buf.Buffer, oobs [][]byte, sources []M.Socksaddr, err error) {
	for {
		if w.fallback != nil {
			// outside access: Shutdown must not wait for a netpoller read
			return w.fallback.WaitReadOOBPackets()
		}
		var retry bool
		buffers, oobs, sources, err, retry = w.waitRing()
		if !retry {
			return
		}
	}
}

// waitRing is WaitReadOOBPackets on the ring. When the ring cannot be set
// up it switches the reader to the recvmmsg reader and asks for a retry
// (the listener keeps working without io_uring).
func (w *uringOOBReadWaiter) waitRing() (buffers []*buf.Buffer, oobs [][]byte, sources []M.Socksaddr, err error, retry bool) {
	w.access.Lock()
	defer w.access.Unlock()
	if w.ringFD < 0 {
		if w.closed.Load() {
			w.unlockThread()
			return nil, nil, nil, net.ErrClosed, false
		}
		// The receive task_work runs on the thread that armed it; the
		// blocking variant keeps the reader on that thread.
		if !udpIOUringNetpoll {
			runtime.LockOSThread()
			w.locked = true
		}
		if err = w.setup(); err != nil {
			closed := w.closed.Load()
			w.closeLocked()
			if !closed {
				fallback := &oobPacketBatchReadWaiter{rawConn: w.rawConn, oobSize: w.oobSize}
				fallback.InitializeReadWaiter(w.options)
				w.fallback = fallback
				return nil, nil, nil, nil, true
			}
			return nil, nil, nil, err, false
		}
	}
	// The control bytes handed out last time stay valid until this call.
	w.oobArena = w.oobArena[:0]
	w.pendingOOB = w.pendingOOB[:0]
	for {
		if err = w.reap(); err != nil {
			w.closeLocked()
			return nil, nil, nil, err, false
		}
		if len(w.pending) > 0 {
			// pendingOOB slices point into oobArena as it was when appended;
			// re-cut them from the final arena so a reallocation during reap
			// cannot leave stale slices.
			oobs = w.returnOOB()
			buffers = w.pending
			sources = w.pendingSources
			w.pending = nil
			w.pendingSources = nil
			return buffers, oobs, sources, nil, false
		}
		if w.eof || w.closed.Load() {
			w.closeLocked()
			// Shutdown is the listener closing; report it as such.
			return nil, nil, nil, net.ErrClosed, false
		}
		if !w.armed {
			w.arm()
		}
		if err = w.enter(); err != nil {
			w.closeLocked()
			return nil, nil, nil, err, false
		}
	}
}

func (w *uringOOBReadWaiter) returnOOB() [][]byte {
	w.returnedOOB = w.returnedOOB[:0]
	offset := 0
	for _, control := range w.pendingOOB {
		w.returnedOOB = append(w.returnedOOB, w.oobArena[offset:offset+len(control):offset+len(control)])
		offset += len(control)
	}
	return w.returnedOOB
}

func (w *uringOOBReadWaiter) closeLocked() {
	w.release()
	w.unlockThread()
}

func (w *uringOOBReadWaiter) unlockThread() {
	if w.locked {
		w.locked = false
		runtime.UnlockOSThread()
	}
}

func (w *uringOOBReadWaiter) release() {
	if w.ringFile != nil {
		_ = w.ringFile.Close()
		w.ringFile = nil
		w.ringRaw = nil
		w.ringFD = -1
	} else if w.ringFD >= 0 {
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
	if w.bufRing != nil {
		_ = unix.Munmap(w.bufRing)
		w.bufRing = nil
	}
	buf.ReleaseMulti(w.pending)
	w.pending = nil
	w.pendingSources = nil
	w.closed.Store(true)
}
