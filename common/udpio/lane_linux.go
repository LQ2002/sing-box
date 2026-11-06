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

// EnableUDPFastLaneUp also takes over app sockets for the other direction.
// Opt-in, needs the module too.
var EnableUDPFastLaneUp = os.Getenv("SB_UDP_FASTLANE_UP") == "1"

const (
	sbflMaxBatch = 64
	// SBFL_IOC_DELIVER: _IOWR(0x53, 1, struct sbfl_batch), 32 bytes
	sbflIOCDeliver = 0xC0205301
	// SBFL_IOC_ATTACH, SBFL_IOC_DETACH: _IOW(0x53, 2 and 3, struct sbfl_attach), 20 bytes
	sbflIOCAttach = 0x40145302
	sbflIOCDetach = 0x40145303
	// SBFL_IOC_UID: _IOWR(0x53, 4, struct sbfl_uid), 16 bytes
	sbflIOCUID = 0xC0105304
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

type sbflAttach struct {
	appAddr  [4]byte
	peerAddr [4]byte
	lisAddr  [4]byte
	appPort  [2]byte
	peerPort [2]byte
	lisPort  [2]byte
	_        uint16
}

type sbflUID struct {
	appAddr  [4]byte
	peerAddr [4]byte
	appPort  [2]byte
	peerPort [2]byte
	uid      uint32
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

func beBytes(port uint16) [2]byte {
	return [2]byte{byte(port >> 8), byte(port)}
}

func laneAttachRequest(request uintptr, app, peer, listener netip.AddrPort) error {
	app = netip.AddrPortFrom(app.Addr().Unmap(), app.Port())
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	if !app.Addr().Is4() || !peer.Addr().Is4() {
		return unix.EAFNOSUPPORT
	}
	attach := sbflAttach{
		appAddr:  app.Addr().As4(),
		peerAddr: peer.Addr().As4(),
		appPort:  beBytes(app.Port()),
		peerPort: beBytes(peer.Port()),
	}
	if listener.IsValid() {
		attach.lisAddr = listener.Addr().Unmap().As4()
		attach.lisPort = beBytes(listener.Port())
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(laneFD), request, uintptr(unsafe.Pointer(&attach)))
	if errno != 0 {
		return errno
	}
	return nil
}

// LaneSocketUID returns the uid of the socket that owns app, the one netd
// matches its rules against.
func LaneSocketUID(app, peer netip.AddrPort) (uint32, error) {
	if !EnableUDPFastLaneUp || !laneAvailable() {
		return 0, unix.ENODEV
	}
	app = netip.AddrPortFrom(app.Addr().Unmap(), app.Port())
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	if !app.Addr().Is4() || !peer.Addr().Is4() {
		return 0, unix.EAFNOSUPPORT
	}
	query := sbflUID{
		appAddr:  app.Addr().As4(),
		peerAddr: peer.Addr().As4(),
		appPort:  beBytes(app.Port()),
		peerPort: beBytes(peer.Port()),
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(laneFD), sbflIOCUID, uintptr(unsafe.Pointer(&query)))
	if errno != 0 {
		return 0, errno
	}
	return query.uid, nil
}

// LaneAttach takes over the app socket for one peer. listener is the IPv4
// address of the sing-box listener that reads what TC delivers.
func LaneAttach(app, peer, listener netip.AddrPort) error {
	if !EnableUDPFastLaneUp || !laneAvailable() {
		return unix.ENODEV
	}
	return laneAttachRequest(sbflIOCAttach, app, peer, listener)
}

// LaneDetach gives the socket back to the normal path.
func LaneDetach(app, peer netip.AddrPort) error {
	if laneFD < 0 {
		return unix.ENODEV
	}
	return laneAttachRequest(sbflIOCDetach, app, peer, netip.AddrPort{})
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
