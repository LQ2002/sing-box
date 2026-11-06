//go:build linux

package udpio

import (
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

// LanePacketBatchWriter hands datagrams for an app to the sbfl kernel module
// (experimental/kernel_fastlane), which queues them straight on the app's UDP
// socket: no ip_output, netfilter, cgroup programs, backlog or ip_rcv. The
// app still reads them with recvmsg and sees the reply source as the sender.
//
// Experiment, opt-in with SB_UDP_FASTLANE=1 and only with /dev/sbfl present.
// The module queues nothing on error, so a batch it refuses goes through next
// unchanged: a socket it cannot find (bound to a device, for example), a
// socket with a filter, or IPv6.
var enableUDPFastLane = os.Getenv("SB_UDP_FASTLANE") == "1"

const (
	sbflMaxBatch = 64
	// SBFL_IOC_DELIVER: _IOWR(0x53, 1, struct sbfl_batch), 32 bytes
	sbflIOCDeliver = 0xC0205301
)

// Same layout as module/sbfl_abi.h
type sbflIOV struct {
	base uint64
	len  uint32
	_    uint32
}

type sbflBatch struct {
	iov       uint64
	count     uint32
	delivered uint32
	dropped   uint32
	saddr     [4]byte
	daddr     [4]byte
	sport     [2]byte
	dport     [2]byte
}

var (
	laneOnce sync.Once
	laneFD   = -1
	// laneDeliver is replaced in tests
	laneDeliver = func(batch *sbflBatch) error {
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(laneFD), sbflIOCDeliver, uintptr(unsafe.Pointer(batch)))
		if errno != 0 {
			return errno
		}
		return nil
	}
)

// LaneStats counts what the lane did, for the A/B logs.
var LaneStats struct {
	Delivered, Dropped, Refused atomic.Uint64
}

func laneAvailable() bool {
	if !enableUDPFastLane {
		return false
	}
	laneOnce.Do(func() {
		fd, err := unix.Open("/dev/sbfl", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err == nil {
			laneFD = fd
		}
	})
	return laneFD >= 0
}

type LanePacketBatchWriter struct {
	source netip.AddrPort
	next   N.PacketBatchWriter
}

// NewLanePacketBatchWriter returns nil without the module or for a source
// that is not IPv4.
func NewLanePacketBatchWriter(source netip.AddrPort, next N.PacketBatchWriter) *LanePacketBatchWriter {
	source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
	if !source.Addr().Is4() || !laneAvailable() {
		return nil
	}
	return &LanePacketBatchWriter{source: source, next: next}
}

func (w *LanePacketBatchWriter) deliver(packets [][]byte, destination netip.AddrPort) error {
	var iov [sbflMaxBatch]sbflIOV
	for index, packet := range packets {
		iov[index].base = uint64(uintptr(unsafe.Pointer(unsafe.SliceData(packet))))
		iov[index].len = uint32(len(packet))
	}
	batch := sbflBatch{
		iov:   uint64(uintptr(unsafe.Pointer(&iov))),
		count: uint32(len(packets)),
		saddr: w.source.Addr().As4(),
		daddr: destination.Addr().As4(),
		sport: [2]byte{byte(w.source.Port() >> 8), byte(w.source.Port())},
		dport: [2]byte{byte(destination.Port() >> 8), byte(destination.Port())},
	}
	err := laneDeliver(&batch)
	if err != nil {
		LaneStats.Refused.Add(1)
		return err
	}
	LaneStats.Delivered.Add(uint64(batch.delivered))
	LaneStats.Dropped.Add(uint64(batch.dropped))
	return nil
}

// WriteOne reports whether the module took the datagram.
func (w *LanePacketBatchWriter) WriteOne(packet []byte, destination netip.AddrPort) bool {
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	if !destination.Addr().Is4() {
		return false
	}
	return w.deliver([][]byte{packet}, destination) == nil
}

// WritePacketBatch takes ownership of the buffers, as next does.
func (w *LanePacketBatchWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	destination, ok := laneDestination(destinations)
	if !ok {
		return w.next.WritePacketBatch(buffers, destinations)
	}
	var packets [sbflMaxBatch][]byte
	done := 0
	for done < len(buffers) {
		end := min(done+sbflMaxBatch, len(buffers))
		for index := done; index < end; index++ {
			packets[index-done] = buffers[index].Bytes()
		}
		if w.deliver(packets[:end-done], destination) != nil {
			break
		}
		buf.ReleaseMulti(buffers[done:end])
		done = end
	}
	if done == len(buffers) {
		return nil
	}
	return w.next.WritePacketBatch(buffers[done:], destinations[done:])
}

// laneDestination returns the one IPv4 destination of a batch.
func laneDestination(destinations []M.Socksaddr) (netip.AddrPort, bool) {
	if len(destinations) == 0 {
		return netip.AddrPort{}, false
	}
	first := destinations[0].AddrPort()
	for _, destination := range destinations[1:] {
		if destination.AddrPort() != first {
			return netip.AddrPort{}, false
		}
	}
	first = netip.AddrPortFrom(first.Addr().Unmap(), first.Port())
	return first, first.Addr().Is4()
}

var _ N.PacketBatchWriter = (*LanePacketBatchWriter)(nil)
