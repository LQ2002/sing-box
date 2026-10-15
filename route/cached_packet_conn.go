package route

import (
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// cachedPacketConn is bufio.CachedPacketConn (the packets read while
// sniffing, replayed before the connection's own) that also offers read
// waiters, batch and single.
//
// bufio.CachedPacketConn reports ReaderReplaceable() == false until its
// packet has been read, so a copy that starts before that (always: the copy
// is what reads it) cannot see the batch read waiter underneath and falls
// back to bufio's copyPacketWithPool, one ReadPacket and one WritePacket per
// datagram, for the whole session; the copy never re-selects its path. On
// the device that put every sniffed UDP session (all QUIC) on the per-packet
// path in the app -> server direction: during an HTTP/3 download the uplink
// ACKs alone, one write(2) each through the SS2022 client, were 12% of
// sing-box's CPU (2026-10-15 profile of 66c791baa). The waiters here hand
// out the cached packet first and then delegate to the waiter of the wrapped
// connection, so the copy keeps the batch path from the first packet on.
type cachedPacketConn struct {
	*bufio.CachedPacketConn
}

func newCachedPacketConn(conn N.PacketConn, buffer *buf.Buffer, destination M.Socksaddr) N.PacketConn {
	return &cachedPacketConn{bufio.NewCachedPacketConn(conn, buffer, destination)}
}

func (c *cachedPacketConn) CreatePacketBatchReadWaiter() (N.PacketBatchReadWaiter, bool) {
	waiter, created := bufio.CreatePacketBatchReadWaiter(c.CachedPacketConn.PacketConn)
	if !created {
		return nil, false
	}
	return &cachedPacketBatchReadWaiter{conn: c, upstream: waiter}, true
}

func (c *cachedPacketConn) CreateReadWaiter() (N.PacketReadWaiter, bool) {
	waiter, created := bufio.CreatePacketReadWaiter(c.CachedPacketConn.PacketConn)
	if !created {
		return nil, false
	}
	return &cachedPacketReadWaiter{conn: c, upstream: waiter}, true
}

// takeCached returns the cached packet once, copied into a buffer with the
// headroom the reader asked for (as the wrapped waiters do).
func (c *cachedPacketConn) takeCached(options N.ReadWaitOptions) (*buf.Buffer, M.Socksaddr, bool) {
	packet := c.ReadCachedPacket()
	if packet == nil {
		return nil, M.Socksaddr{}, false
	}
	destination := packet.Destination
	buffer := packet.Buffer
	N.PutPacketBuffer(packet)
	if buffer == nil {
		return nil, M.Socksaddr{}, false
	}
	return options.Copy(buffer), destination, true
}

type cachedPacketBatchReadWaiter struct {
	conn     *cachedPacketConn
	upstream N.PacketBatchReadWaiter
	options  N.ReadWaitOptions
}

func (w *cachedPacketBatchReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	w.options = options
	return w.upstream.InitializeReadWaiter(options)
}

func (w *cachedPacketBatchReadWaiter) WaitReadPackets() ([]*buf.Buffer, []M.Socksaddr, error) {
	if buffer, destination, loaded := w.conn.takeCached(w.options); loaded {
		return []*buf.Buffer{buffer}, []M.Socksaddr{destination}, nil
	}
	return w.upstream.WaitReadPackets()
}

type cachedPacketReadWaiter struct {
	conn     *cachedPacketConn
	upstream N.PacketReadWaiter
	options  N.ReadWaitOptions
}

func (w *cachedPacketReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	w.options = options
	return w.upstream.InitializeReadWaiter(options)
}

func (w *cachedPacketReadWaiter) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	if buffer, destination, loaded := w.conn.takeCached(w.options); loaded {
		return buffer, destination, nil
	}
	return w.upstream.WaitReadPacket()
}

var (
	_ N.PacketBatchReadWaitCreator = (*cachedPacketConn)(nil)
	_ N.PacketReadWaitCreator      = (*cachedPacketConn)(nil)
	_ N.CachedPacketReader         = (*cachedPacketConn)(nil)
)
