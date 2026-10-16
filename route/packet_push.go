package route

import (
	"context"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Push mode for the upload direction of UDP sessions (SB_UDP_PUSH=0 turns it
// off).
//
// Normally the app -> server direction runs in its own goroutine: the inbound
// reader queues every datagram on the session's channel and the copy goroutine
// (bufio.CopyPacket) wakes up to read and forward it. On the phone (2026-10-17,
// production 7ef6e15af, cpu0-5) that hand-off dominated UDP uploads: per MB
// sing-box spent ~27 ms against ~8 ms for downloads, and ~45-50% of the upload
// cycles were Go scheduling plus futex wake-ups (runtime.send.goready from the
// channel send, runtime.resetspinning waking another thread), while AES-GCM was
// under 3%. The eBPF inbound reads on a locked io_uring thread, so every
// readied copy goroutine needs another thread woken to run it.
//
// In push mode the inbound reader calls the session's handler directly: the
// datagram is counted, its destination is rewritten as the read wrappers would
// have, and it is written to the outbound from the reader's goroutine. Packets
// of one inbound read batch are collected and flushed together, so the
// outbound still sees batch writes (sendmmsg / UDP GSO). Only sessions whose
// read side is made of wrappers understood here are pushed; anything else keeps
// the copy goroutine.
var udpPushEnabled = os.Getenv("SB_UDP_PUSH") != "0"

// packetPushSource is implemented by inbound session connections that can
// deliver datagrams synchronously to a handler instead of queueing them.
// SetPacketPushHandler drains already queued datagrams into the handler before
// it returns; it returns false when the connection is already closed.
type packetPushSource interface {
	SetPacketPushHandler(handler N.UDPHandlerEx) bool
}

// pushPacketBatchMax bounds how many datagrams a handler holds before it
// flushes on its own, matching bufio's default read batch.
const pushPacketBatchMax = 64

type packetPushUpload struct {
	destination   N.PacketWriter
	batchWriter   N.PacketBatchWriter
	fakeIP        *fakeIPNATPacketConn
	readCounters  []N.CountFunc
	writeCounters []N.CountFunc
	frontHeadroom int
	rearHeadroom  int
	finish        func(error)

	pendingAccess sync.Mutex
	pending       []*buf.Buffer
	destinations  []M.Socksaddr
	writeAccess   sync.Mutex
	closed        atomic.Bool
}

// unwrapPacketPushSource walks the read side of conn the way bufio.CopyPacket
// would see it and returns the push-capable source underneath, or false if a
// wrapper on the way would change the data in a way push does not reproduce.
func unwrapPacketPushSource(conn N.PacketConn) (source packetPushSource, fakeIP *fakeIPNATPacketConn, cached []N.CachedPacketReader, readCounters []N.CountFunc, ok bool) {
	var reader any = conn
	for {
		if pushSource, isPushSource := reader.(packetPushSource); isPushSource {
			return pushSource, fakeIP, cached, readCounters, true
		}
		if readCounter, isReadCounter := reader.(N.PacketReadCounter); isReadCounter {
			var counters []N.CountFunc
			reader, counters = readCounter.UnwrapPacketReader()
			readCounters = append(readCounters, counters...)
			continue
		}
		switch typed := reader.(type) {
		case *fakeIPNATPacketConn:
			if fakeIP != nil {
				return nil, nil, nil, nil, false
			}
			fakeIP = typed
			reader = typed.NetPacketConn
			continue
		case *cachedPacketConn:
			cached = append(cached, typed.CachedPacketConn)
			reader = typed.CachedPacketConn.PacketConn
			continue
		}
		if cachedReader, isCached := reader.(N.CachedPacketReader); isCached {
			cached = append(cached, cachedReader)
		} else {
			replaceable, isReplaceable := reader.(N.ReaderWithUpstream)
			if !isReplaceable || !replaceable.ReaderReplaceable() {
				return nil, nil, nil, nil, false
			}
		}
		withUpstream, hasUpstream := reader.(common.WithUpstream)
		if !hasUpstream {
			return nil, nil, nil, nil, false
		}
		reader = withUpstream.Upstream()
		if reader == nil {
			return nil, nil, nil, nil, false
		}
	}
}

// pushPacketUpload replaces the upload copy goroutine with push delivery when
// the session allows it. finish must run the same close sequence the copy
// goroutine would on exit.
func (m *ConnectionManager) pushPacketUpload(ctx context.Context, conn N.PacketConn, destination N.PacketWriter, finish func(error)) bool {
	if !udpPushEnabled {
		return false
	}
	source, fakeIP, cached, readCounters, ok := unwrapPacketPushSource(conn)
	if !ok {
		return false
	}
	writer, writeCounters := N.UnwrapCountPacketWriter(destination, nil)
	// A destination that still upgrades itself on its first write needs the
	// copy session's handshake handling.
	if N.NewPacketHandshakeState(conn, writer).Upgradable() {
		return false
	}
	upload := &packetPushUpload{
		destination:   writer,
		fakeIP:        fakeIP,
		readCounters:  readCounters,
		writeCounters: writeCounters,
		frontHeadroom: N.CalculateFrontHeadroom(writer),
		rearHeadroom:  N.CalculateRearHeadroom(writer),
		finish:        finish,
	}
	if batchWriter, isBatchWriter := bufio.CreatePacketBatchWriter(writer); isBatchWriter {
		upload.batchWriter = batchWriter
	}
	// Packets read while sniffing go first, in the order they arrived.
	options := N.NewReadWaitOptions(nil, writer)
	for _, cachedReader := range cached {
		for {
			packet := cachedReader.ReadCachedPacket()
			if packet == nil {
				break
			}
			if packet.Buffer != nil {
				upload.NewPacketEx(options.Copy(packet.Buffer), packet.Destination)
			}
			N.PutPacketBuffer(packet)
		}
	}
	// The cached replay stays pending and goes out in one flush with the
	// datagrams SetPacketPushHandler drains from the session queue, in
	// arrival order: cached, then queued, then newly pushed.
	if !source.SetPacketPushHandler(upload) {
		upload.Close()
	} else {
		upload.FlushPushedPackets()
	}
	m.logger.TraceContext(ctx, "packet upload pushed")
	return true
}

func (u *packetPushUpload) FrontHeadroom() int {
	return u.frontHeadroom
}

func (u *packetPushUpload) RearHeadroom() int {
	return u.rearHeadroom
}

func (u *packetPushUpload) NewPacketEx(buffer *buf.Buffer, destination M.Socksaddr) {
	if u.closed.Load() {
		buffer.Release()
		return
	}
	if u.fakeIP != nil {
		destination = u.fakeIP.rewriteReadDestination(destination)
	}
	u.pendingAccess.Lock()
	u.pending = append(u.pending, buffer)
	u.destinations = append(u.destinations, destination)
	full := len(u.pending) >= pushPacketBatchMax
	u.pendingAccess.Unlock()
	if full {
		u.FlushPushedPackets()
	}
}

// FlushPushedPackets writes everything collected since the last flush. The
// inbound calls it at the end of each read batch.
func (u *packetPushUpload) FlushPushedPackets() {
	u.writeAccess.Lock()
	defer u.writeAccess.Unlock()
	u.pendingAccess.Lock()
	buffers, destinations := u.pending, u.destinations
	u.pending, u.destinations = nil, nil
	u.pendingAccess.Unlock()
	if len(buffers) == 0 {
		return
	}
	if u.closed.Load() {
		buf.ReleaseMulti(buffers)
		return
	}
	dataLens := make([]int, len(buffers))
	for index, buffer := range buffers {
		dataLens[index] = buffer.Len()
	}
	var err error
	if u.batchWriter != nil && len(buffers) > 1 {
		// The batch writer owns the buffers whether or not it fails, as in
		// bufio's batch copy.
		err = u.batchWriter.WritePacketBatch(buffers, destinations)
		if err != nil {
			dataLens = nil
		}
	} else {
		for index, buffer := range buffers {
			err = u.destination.WritePacket(buffer, destinations[index])
			if err != nil {
				buffer.Leak()
				buf.ReleaseMulti(buffers[index+1:])
				dataLens = dataLens[:index]
				break
			}
		}
	}
	for _, dataLen := range dataLens {
		n := int64(dataLen)
		for _, counter := range u.readCounters {
			counter(n)
		}
		for _, counter := range u.writeCounters {
			counter(n)
		}
	}
	if err != nil {
		u.closeWith(E.Cause(err, "packet upload"))
	}
}

// Close is called by the source when the session closes. It ends the upload
// direction the way the copy goroutine's read of a closed session did
// (io.ErrClosedPipe). finish closes the source again, so it runs on its own
// goroutine: the source may still be inside its own close path here.
func (u *packetPushUpload) Close() error {
	u.closeWithAsync(io.ErrClosedPipe)
	return nil
}

func (u *packetPushUpload) closeWithAsync(err error) {
	if !u.release() {
		return
	}
	go u.finish(err)
}

// closeWith ends the upload after a write error, on the reader goroutine
// (not inside the source's close path).
func (u *packetPushUpload) closeWith(err error) {
	if !u.release() {
		return
	}
	u.finish(err)
}

// release marks the upload closed and drops what is still pending; it reports
// whether this call did it.
func (u *packetPushUpload) release() bool {
	if !u.closed.CompareAndSwap(false, true) {
		return false
	}
	u.pendingAccess.Lock()
	buffers := u.pending
	u.pending, u.destinations = nil, nil
	u.pendingAccess.Unlock()
	buf.ReleaseMulti(buffers)
	return true
}
