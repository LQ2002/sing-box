package route

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// pushSourceConn stands in for the eBPF inbound session: push capable, and
// failing any test that falls back to reading it.
type pushSourceConn struct {
	t       *testing.T
	handler N.UDPHandlerEx
	queued  []*N.PacketBuffer
	closed  bool
}

func (c *pushSourceConn) SetPacketPushHandler(handler N.UDPHandlerEx) bool {
	if c.closed {
		_ = handler.(io.Closer).Close()
		return false
	}
	c.handler = handler
	for _, packet := range c.queued {
		handler.NewPacketEx(packet.Buffer, packet.Destination)
		N.PutPacketBuffer(packet)
	}
	c.queued = nil
	if flusher, isFlusher := handler.(interface{ FlushPushedPackets() }); isFlusher {
		flusher.FlushPushedPackets()
	}
	return true
}

func (c *pushSourceConn) push(payload string, destination M.Socksaddr) {
	c.handler.NewPacketEx(buf.As([]byte(payload)).ToOwned(), destination)
}

func (c *pushSourceConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	c.t.Error("pushed session was read")
	return M.Socksaddr{}, io.EOF
}

func (c *pushSourceConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (c *pushSourceConn) Close() error {
	c.closed = true
	if closer, isCloser := c.handler.(io.Closer); isCloser {
		_ = closer.Close()
	}
	return nil
}
func (c *pushSourceConn) LocalAddr() net.Addr                { return nil }
func (c *pushSourceConn) SetDeadline(t time.Time) error      { return nil }
func (c *pushSourceConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *pushSourceConn) SetWriteDeadline(t time.Time) error { return nil }

type pushSink struct {
	access       sync.Mutex
	payloads     []string
	destinations []M.Socksaddr
	batches      []int
	fail         error
}

func (s *pushSink) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if s.fail != nil {
		return s.fail
	}
	s.access.Lock()
	defer s.access.Unlock()
	s.payloads = append(s.payloads, string(buffer.Bytes()))
	s.destinations = append(s.destinations, destination)
	s.batches = append(s.batches, 1)
	buffer.Release()
	return nil
}

func (s *pushSink) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	s.access.Lock()
	defer s.access.Unlock()
	for index, buffer := range buffers {
		s.payloads = append(s.payloads, string(buffer.Bytes()))
		s.destinations = append(s.destinations, destinations[index])
	}
	s.batches = append(s.batches, len(buffers))
	buf.ReleaseMulti(buffers)
	return nil
}

func (s *pushSink) FrontHeadroom() int { return 40 }

func newPushTestManager() *ConnectionManager {
	return &ConnectionManager{logger: log.NewNOPFactory().Logger()}
}

func TestPacketPushUploadReplaysCachedThenPushesBatches(t *testing.T) {
	source := &pushSourceConn{t: t}
	app := M.ParseSocksaddr("198.18.0.7:443")
	source.queued = []*N.PacketBuffer{{Buffer: buf.As([]byte("queued")).ToOwned(), Destination: app}}
	var counted atomic.Int64
	var conn N.PacketConn = source
	// Sniffed packets: first one outermost, as route.go builds them.
	conn = newCachedPacketConn(conn, buf.As([]byte("sniff2")).ToOwned(), app)
	conn = newCachedPacketConn(conn, buf.As([]byte("sniff1")).ToOwned(), app)
	conn = bufio.NewCounterPacketConn(conn, []N.CountFunc{func(n int64) { counted.Add(n) }}, nil)
	conn = newFakeIPNATPacketConn(bufio.NewNetPacketConn(conn), app, M.ParseSocksaddr("example.com:443"))
	sink := &pushSink{}
	var finished atomic.Int32
	var finishErr error
	pushed := newPushTestManager().pushPacketUpload(context.Background(), conn, sink, func(err error) {
		finished.Add(1)
		finishErr = err
	})
	require.True(t, pushed)
	require.Equal(t, []string{"sniff1", "sniff2", "queued"}, sink.payloads)
	// The cached replay and the drained queue are flushed together.
	require.Equal(t, []int{3}, sink.batches)
	for _, destination := range sink.destinations {
		require.Equal(t, "example.com", destination.Fqdn)
		require.Equal(t, uint16(443), destination.Port)
	}

	source.push("a", app)
	source.push("bb", app)
	require.Len(t, sink.payloads, 3, "pushed packets wait for the batch flush")
	source.handler.(interface{ FlushPushedPackets() }).FlushPushedPackets()
	require.Equal(t, []string{"sniff1", "sniff2", "queued", "a", "bb"}, sink.payloads)
	require.Equal(t, []int{3, 2}, sink.batches)
	require.Equal(t, int64(len("sniff1sniff2queuedabb")), counted.Load())

	source.push("c", app)
	require.NoError(t, source.Close())
	require.Equal(t, int32(1), finished.Load())
	require.ErrorIs(t, finishErr, io.ErrClosedPipe)
	require.Len(t, sink.payloads, 5, "packets pending at close are released, not sent")
	source.push("late", app)
	source.handler.(interface{ FlushPushedPackets() }).FlushPushedPackets()
	require.Len(t, sink.payloads, 5)
}

func TestPacketPushUploadSingleWriteAndFailure(t *testing.T) {
	source := &pushSourceConn{t: t}
	sink := &pushSink{}
	var finishErr error
	var finished atomic.Int32
	// A plain PacketWriter: no batch writer, one WritePacket per datagram.
	writer := struct{ N.PacketWriter }{sink}
	pushed := newPushTestManager().pushPacketUpload(context.Background(), source, writer, func(err error) {
		finished.Add(1)
		finishErr = err
	})
	require.True(t, pushed)
	destination := M.ParseSocksaddr("1.1.1.1:53")
	source.push("x", destination)
	source.push("y", destination)
	source.handler.(interface{ FlushPushedPackets() }).FlushPushedPackets()
	require.Equal(t, []string{"x", "y"}, sink.payloads)
	require.Equal(t, []int{1, 1}, sink.batches)
	require.Equal(t, destination, sink.destinations[0], "no fakeip wrapper, destination unchanged")

	sink.fail = errors.New("boom")
	source.push("z", destination)
	source.handler.(interface{ FlushPushedPackets() }).FlushPushedPackets()
	require.Equal(t, int32(1), finished.Load())
	require.ErrorContains(t, finishErr, "boom")
	require.NoError(t, source.Close())
	require.Equal(t, int32(1), finished.Load(), "finish runs once")
}

// opaqueReadConn rewrites what it reads in an unknown way, so push must not
// bypass it.
type opaqueReadConn struct {
	N.PacketConn
}

func (c *opaqueReadConn) Upstream() any { return c.PacketConn }

func TestPacketPushUploadKeepsCopyForUnknownWrappers(t *testing.T) {
	source := &pushSourceConn{t: t}
	pushed := newPushTestManager().pushPacketUpload(context.Background(), &opaqueReadConn{source}, &pushSink{}, func(error) {
		t.Error("finish called for a session that was not pushed")
	})
	require.False(t, pushed)
	require.Nil(t, source.handler)
}

func TestPacketPushUploadRespectsSwitch(t *testing.T) {
	saved := udpPushEnabled
	udpPushEnabled = false
	defer func() { udpPushEnabled = saved }()
	source := &pushSourceConn{t: t}
	require.False(t, newPushTestManager().pushPacketUpload(context.Background(), source, &pushSink{}, func(error) {}))
	require.Nil(t, source.handler)
}
