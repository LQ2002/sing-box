package dialer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// countingConn serves data in the given segments, one per Read, and counts
// the Reads that reached it.
type countingConn struct {
	net.Conn
	segments [][]byte
	err      error
	reads    int
}

func (c *countingConn) Read(p []byte) (int, error) {
	c.reads++
	if len(c.segments) == 0 {
		return 0, c.err
	}
	n := copy(p, c.segments[0])
	c.segments[0] = c.segments[0][n:]
	if len(c.segments[0]) == 0 {
		c.segments = c.segments[1:]
	}
	if len(c.segments) == 0 && c.err != nil {
		return n, c.err
	}
	return n, nil
}

func (c *countingConn) Close() error { return nil }

func newTestReadBufferedConn(t *testing.T, inner net.Conn) *readBufferedConn {
	t.Helper()
	conn, isBuffered := newReadBufferedConn(inner).(*readBufferedConn)
	require.True(t, isBuffered)
	return conn
}

// Chunk-sized reads of bytes that arrived together cost one socket read, and
// the buffer is returned once drained.
func TestReadBufferedConnCoalescesSmallReads(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789abcdef"), 600) // 9600 bytes in one segment
	inner := &countingConn{segments: [][]byte{append([]byte(nil), data...)}, err: io.EOF}
	conn := newTestReadBufferedConn(t, inner)
	var got []byte
	for _, size := range []int{18, 1514, 18, 1514, 18, 6518} {
		p := make([]byte, size)
		_, err := io.ReadFull(conn, p)
		require.NoError(t, err)
		got = append(got, p...)
	}
	require.Equal(t, data, got)
	require.Equal(t, 1, inner.reads)
	require.Nil(t, conn.buffer, "drained buffer returned to the pool")
	_, err := conn.Read(make([]byte, 18))
	require.ErrorIs(t, err, io.EOF)
}

// A read error that arrives together with data is reported only after the
// data is consumed, and the conn is not replaceable until then.
func TestReadBufferedConnErrorAfterData(t *testing.T) {
	failure := errors.New("reset")
	inner := &countingConn{segments: [][]byte{[]byte("abcdef")}, err: failure}
	conn := newTestReadBufferedConn(t, inner)
	p := make([]byte, 4)
	n, err := conn.Read(p)
	require.NoError(t, err)
	require.Equal(t, "abcd", string(p[:n]))
	require.False(t, conn.ReaderReplaceable())
	n, err = conn.Read(p)
	require.NoError(t, err)
	require.Equal(t, "ef", string(p[:n]))
	require.False(t, conn.ReaderReplaceable(), "deferred error still pending")
	_, err = conn.Read(p)
	require.ErrorIs(t, err, failure)
	require.True(t, conn.ReaderReplaceable())
}

// Reads at least as large as the buffer bypass it unchanged.
func TestReadBufferedConnLargeReadBypasses(t *testing.T) {
	data := bytes.Repeat([]byte{7}, readBufferSize+100)
	inner := &countingConn{segments: [][]byte{append([]byte(nil), data...)}, err: io.EOF}
	conn := newTestReadBufferedConn(t, inner)
	p := make([]byte, readBufferSize+100)
	n, err := conn.Read(p)
	// Passed through unchanged: the socket may return EOF with the last bytes.
	if err != nil {
		require.ErrorIs(t, err, io.EOF)
	}
	require.Equal(t, len(data), n)
	require.Equal(t, 1, inner.reads)
	require.Nil(t, conn.buffer)
}

// sing's unwrapping (copy, splice, kTLS) may reach the socket only while
// nothing is buffered.
func TestReadBufferedConnUnwrapOnlyWhenEmpty(t *testing.T) {
	inner := &countingConn{segments: [][]byte{[]byte("abcdef")}}
	conn := newTestReadBufferedConn(t, inner)
	require.Equal(t, io.Reader(inner), N.UnwrapReader(conn))
	_, isCountingConn := N.CastReader[*countingConn](conn)
	require.True(t, isCountingConn)

	p := make([]byte, 2)
	_, err := conn.Read(p)
	require.NoError(t, err)
	require.Equal(t, io.Reader(conn), N.UnwrapReader(conn), "bytes buffered: must not unwrap")
	_, isCountingConn = N.CastReader[*countingConn](conn)
	require.False(t, isCountingConn)

	_, err = io.ReadFull(conn, make([]byte, 4))
	require.NoError(t, err)
	require.Equal(t, io.Reader(inner), N.UnwrapReader(conn))
	require.Equal(t, net.Conn(inner), conn.Upstream())
}

// ReaderReplaceable must not wait for a Read blocked in the socket.
func TestReadBufferedConnReplaceableDuringBlockedRead(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	conn := newTestReadBufferedConn(t, client)
	defer conn.Close()
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = conn.Read(make([]byte, 16))
	}()
	time.Sleep(20 * time.Millisecond) // let the Read block in the pipe
	answered := make(chan bool, 1)
	go func() { answered <- conn.ReaderReplaceable() }()
	select {
	case replaceable := <-answered:
		require.True(t, replaceable)
	case <-time.After(time.Second):
		t.Fatal("ReaderReplaceable blocked behind a pending Read")
	}
	_, err := server.Write([]byte("x"))
	require.NoError(t, err)
	<-readDone
}

// Proxy dialers wrap TCP conns; the direct outbound's dialer does not.
func TestReadBufferDialerScope(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			conn.Close()
		}
	}()
	destination := M.SocksaddrFromNet(listener.Addr())
	for _, direct := range []bool{false, true} {
		dialer, err := NewWithOptions(Options{Context: context.Background(), Options: option.DialerOptions{}, DirectOutbound: direct})
		require.NoError(t, err)
		conn, err := dialer.DialContext(context.Background(), N.NetworkTCP, destination)
		require.NoError(t, err)
		require.Equal(t, !direct, hasReadBuffer(conn), "direct=%v", direct)
		conn.Close()
		udpConn, err := dialer.DialContext(context.Background(), N.NetworkUDP, destination)
		require.NoError(t, err)
		require.False(t, hasReadBuffer(udpConn), "UDP must not be wrapped")
		udpConn.Close()
	}
}

// hasReadBuffer walks plain upstream links, which every tracking wrapper
// exposes, looking for the read buffer.
func hasReadBuffer(conn any) bool {
	for conn != nil {
		if _, isBuffered := conn.(*readBufferedConn); isBuffered {
			return true
		}
		upstream, hasUpstream := conn.(interface{ Upstream() any })
		if !hasUpstream {
			return false
		}
		conn = upstream.Upstream()
	}
	return false
}
