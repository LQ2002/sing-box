package route

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// batchSourceConn hands out its packets in batches of two and records
// whether anything read it one packet at a time.
type batchSourceConn struct {
	payloads  []string
	single    int
	batchSize int
}

func (c *batchSourceConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	c.single++
	if len(c.payloads) == 0 {
		return M.Socksaddr{}, io.EOF
	}
	buffer.WriteString(c.payloads[0])
	c.payloads = c.payloads[1:]
	return M.ParseSocksaddr("1.1.1.1:443"), nil
}

func (c *batchSourceConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (c *batchSourceConn) Close() error                       { return nil }
func (c *batchSourceConn) LocalAddr() net.Addr                { return nil }
func (c *batchSourceConn) SetDeadline(t time.Time) error      { return nil }
func (c *batchSourceConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *batchSourceConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *batchSourceConn) CreatePacketBatchReadWaiter() (N.PacketBatchReadWaiter, bool) {
	return c, true
}

func (c *batchSourceConn) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	c.batchSize = options.BatchSize
	return false
}

func (c *batchSourceConn) WaitReadPackets() ([]*buf.Buffer, []M.Socksaddr, error) {
	if len(c.payloads) == 0 {
		return nil, nil, io.EOF
	}
	var (
		buffers      []*buf.Buffer
		destinations []M.Socksaddr
	)
	for len(c.payloads) > 0 && len(buffers) < 2 {
		buffers = append(buffers, newTestBuffer(c.payloads[0]))
		destinations = append(destinations, M.ParseSocksaddr("1.1.1.1:443"))
		c.payloads = c.payloads[1:]
	}
	return buffers, destinations, nil
}

// batchSinkConn records how the copy wrote to it.
type batchSinkConn struct {
	batchSourceConn
	written []string
	batches int
	singles int
}

func (c *batchSinkConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.singles++
	c.written = append(c.written, string(buffer.Bytes()))
	buffer.Release()
	return nil
}

func (c *batchSinkConn) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	c.batches++
	for _, buffer := range buffers {
		c.written = append(c.written, string(buffer.Bytes()))
	}
	buf.ReleaseMulti(buffers)
	return nil
}

func newTestBuffer(payload string) *buf.Buffer {
	buffer := buf.New()
	buffer.WriteString(payload)
	return buffer
}

func wrapCached(conn N.PacketConn, payloads ...string) N.PacketConn {
	// route.go wraps the sniffed packets back to front, so the first packet
	// is the outermost.
	for index := len(payloads) - 1; index >= 0; index-- {
		buffer := newTestBuffer(payloads[index])
		conn = newCachedPacketConn(conn, buffer, M.ParseSocksaddr("1.1.1.1:443"))
	}
	return conn
}

// fakeIPWrapped puts the sniff-cached connection under the fakeip NAT
// wrapper, as route.go does for fakeip destinations. sing's CopyPacket only
// drains cached packets of a source that is itself a CachedPacketReader, so
// under a wrapper the copy selects its path while the cache is still full.
func fakeIPWrapped(conn N.PacketConn) N.PacketConn {
	return newFakeIPNATPacketConn(bufio.NewNetPacketConn(conn), M.ParseSocksaddr("198.18.0.1:443"), M.ParseSocksaddr("1.1.1.1:443"))
}

func TestCachedPacketConnKeepsBatchPath(t *testing.T) {
	source := &batchSourceConn{payloads: []string{"c", "d", "e"}}
	sink := &batchSinkConn{}
	_, err := bufio.CopyPacket(sink, fakeIPWrapped(wrapCached(source, "a", "b")))
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, []string{"a", "b", "c", "d", "e"}, sink.written)
	require.Zero(t, sink.singles, "copy fell back to per-packet writes")
	require.Zero(t, source.single, "copy read the source one packet at a time")
	require.Equal(t, bufio.DefaultPacketReadBatchSize, source.batchSize)
}

func TestBufioCachedPacketConnKeepsBatchPath(t *testing.T) {
	// cachedPacketConn was written because sing's own wrapper used to send the
	// whole session down the per-packet path (one ReadPacket and one WritePacket
	// per datagram). reF1nd/sing d4dda9140 ("cached packet read waiters",
	// sing-box f4c1dd68b) gives bufio.CachedPacketConn batch read waiters too,
	// so both wrappers now keep the batch path. cachedPacketConn is kept until a
	// device A/B shows the upstream wrapper costs no more on the hot path.
	source := &batchSourceConn{payloads: []string{"c", "d"}}
	sink := &batchSinkConn{}
	var conn N.PacketConn = source
	conn = bufio.NewCachedPacketConn(conn, newTestBuffer("a"), M.ParseSocksaddr("1.1.1.1:443"))
	_, err := bufio.CopyPacket(sink, fakeIPWrapped(conn))
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, []string{"a", "c", "d"}, sink.written)
	require.Zero(t, sink.singles)
	require.NotZero(t, sink.batches)
}

func TestCachedPacketConnReadCachedPacket(t *testing.T) {
	// protocol/dns and route/splice take the cached packets out through
	// N.CachedPacketReader; the wrapper must still offer it.
	conn := wrapCached(&batchSourceConn{}, "a")
	reader, isCached := conn.(N.CachedPacketReader)
	require.True(t, isCached)
	packet := reader.ReadCachedPacket()
	require.NotNil(t, packet)
	require.Equal(t, "a", string(packet.Buffer.Bytes()))
	packet.Buffer.Release()
	N.PutPacketBuffer(packet)
	require.Nil(t, reader.ReadCachedPacket())
}
