//go:build with_ebpf && (linux || android)

package ebpf

import (
	"sync"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// udpNATBatch holds the session hand-offs of one received batch so they can
// happen back to back.
//
// Each uplink datagram reaches its session's copy goroutine through the
// session's channel. When that goroutine is parked, the send readies it and
// the Go scheduler wakes an idle thread to run it (runtime.wakep → futex). The
// listener used to send each datagram right after resolving it. Between two
// sends it did a few microseconds of per-datagram work (assignment, binding,
// session lookup), enough for the woken goroutine to take the one datagram and
// park again. So every datagram paid a wakeup.
//
// On the daily phone (2026-10-08, QUIC upload through SS2022 UDP, symbolized
// profile): runtime.wakep was 7.5% of sing-box cycles. About 55% of it came
// from this send (udpNATConn.enqueuePacketLocked via selectnbsend). A 20 MB
// upload made ~7.6k recvmmsg calls for ~16.6k datagrams.
//
// NewOOBPacketBatch now resolves every datagram first and flushes afterwards.
// The sends are then nanoseconds apart, so a session woken by the first one
// finds the rest already queued and drains them in the same wakeup.
// Per-session order is unchanged (flush keeps arrival order). A datagram is
// still dropped exactly where it was before: when its session cannot be
// prepared, or when the queue is full at flush time.
type udpNATBatch struct {
	conns        []*udpNATConn
	buffers      []*buf.Buffer
	destinations []M.Socksaddr
}

var udpNATBatchPool = sync.Pool{New: func() any { return new(udpNATBatch) }}

func getUDPNATBatch() *udpNATBatch {
	return udpNATBatchPool.Get().(*udpNATBatch)
}

func (b *udpNATBatch) add(conn *udpNATConn, buffer *buf.Buffer, destination M.Socksaddr) {
	b.conns = append(b.conns, conn)
	b.buffers = append(b.buffers, buffer)
	b.destinations = append(b.destinations, destination)
}

// flush hands every held datagram to its session, in arrival order, and
// returns b to the pool.
func (b *udpNATBatch) flush() {
	for index, conn := range b.conns {
		conn.newPacketBuffer(b.buffers[index], b.destinations[index])
	}
	clear(b.conns)
	clear(b.buffers)
	clear(b.destinations)
	b.conns, b.buffers, b.destinations = b.conns[:0], b.buffers[:0], b.destinations[:0]
	udpNATBatchPool.Put(b)
}

// newPacketBufferInBatch is NewPacketBuffer with the hand-off deferred to
// batch.flush; a nil batch hands off immediately. It takes ownership of
// buffer either way.
func (s *udpNATService) newPacketBufferInBatch(
	batch *udpNATBatch,
	key udpSessionKey,
	buffer *buf.Buffer,
	source M.Socksaddr,
	destination M.Socksaddr,
	userData any,
) {
	if batch == nil {
		s.NewPacketBuffer(key, buffer, source, destination, userData)
		return
	}
	conn, loaded := s.connection(key, source, destination, userData)
	if !loaded {
		buffer.Release()
		return
	}
	batch.add(conn, buffer, destination)
}
