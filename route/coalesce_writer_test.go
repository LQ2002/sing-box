package route

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// recordingConn records each Write as one call.
type recordingConn struct {
	net.Conn
	access sync.Mutex
	writes [][]byte
	err    error
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.err != nil {
		return 0, c.err
	}
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (c *recordingConn) snapshot() [][]byte {
	c.access.Lock()
	defer c.access.Unlock()
	return append([][]byte(nil), c.writes...)
}

func joined(writes [][]byte) []byte { return bytes.Join(writes, nil) }

func chunk(i, size int) []byte { return bytes.Repeat([]byte{byte('a' + i%26)}, size) }

// Small writes gather until the read hook flushes them, as one write, in order.
func TestCoalescingWriterFlushBeforeRead(t *testing.T) {
	destination := &recordingConn{}
	w := newCoalescingWriter(destination)
	defer w.Close()
	var want []byte
	for i := range 5 {
		p := chunk(i, 1500)
		n, err := w.Write(p)
		require.NoError(t, err)
		require.Equal(t, len(p), n)
		want = append(want, p...)
	}
	require.Empty(t, destination.snapshot())
	w.FlushBeforeRead()
	require.Equal(t, [][]byte{want}, destination.snapshot())
}

// Reaching coalesceFlushSize writes out without waiting for the hook.
func TestCoalescingWriterFlushesAtThreshold(t *testing.T) {
	destination := &recordingConn{}
	w := newCoalescingWriter(destination)
	defer w.Close()
	var want []byte
	for i := 0; len(want) < coalesceFlushSize; i++ {
		p := chunk(i, 1500)
		_, err := w.Write(p)
		require.NoError(t, err)
		want = append(want, p...)
	}
	writes := destination.snapshot()
	require.Len(t, writes, 1)
	require.Equal(t, want, writes[0])
	require.GreaterOrEqual(t, len(writes[0]), coalesceFlushSize)
}

// A large write first flushes what is pending, keeping order.
func TestCoalescingWriterLargeWriteKeepsOrder(t *testing.T) {
	destination := &recordingConn{}
	w := newCoalescingWriter(destination)
	defer w.Close()
	small, large := chunk(0, 100), chunk(1, coalesceFlushSize+1)
	_, err := w.Write(small)
	require.NoError(t, err)
	_, err = w.Write(large)
	require.NoError(t, err)
	require.Equal(t, [][]byte{small, large}, destination.snapshot())
}

// Without the hook firing, the timer bounds the delay.
func TestCoalescingWriterTimerFlush(t *testing.T) {
	destination := &recordingConn{}
	w := newCoalescingWriter(destination)
	defer w.Close()
	p := chunk(0, 10)
	_, err := w.Write(p)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return len(destination.snapshot()) == 1 }, time.Second, time.Millisecond)
	require.Equal(t, [][]byte{p}, destination.snapshot())
}

// Close writes the tail; a write error sticks.
func TestCoalescingWriterCloseAndError(t *testing.T) {
	destination := &recordingConn{}
	w := newCoalescingWriter(destination)
	p := chunk(0, 10)
	_, err := w.Write(p)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.Equal(t, [][]byte{p}, destination.snapshot())

	failure := errors.New("broken")
	failing := &recordingConn{err: failure}
	w = newCoalescingWriter(failing)
	defer w.Close()
	_, err = w.Write(p)
	require.NoError(t, err)
	w.FlushBeforeRead()
	_, err = w.Write(p)
	require.ErrorIs(t, err, failure)
}

// The read hook never waits for the lock (a mux reader must not stall).
func TestCoalescingWriterFlushBeforeReadDoesNotWait(t *testing.T) {
	w := newCoalescingWriter(&recordingConn{})
	defer w.Close()
	w.access.Lock()
	returned := make(chan struct{})
	go func() {
		w.FlushBeforeRead()
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("FlushBeforeRead waited for the lock")
	}
	w.access.Unlock()
}

// countingWriteConn counts Writes reaching the client side of the copy.
type countingWriteConn struct {
	net.Conn
	writes atomic.Int64
}

func (c *countingWriteConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(p)
}

// End to end: an outbound conn from a proxy dialer feeds the download copy in
// 1500-byte pieces; the client gets every byte, in far fewer writes, and a
// lone message that follows a pause arrives without waiting for more.
func TestConnectionCopyCoalescesDownload(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	const pieces = 400
	burst := make([]byte, 0, pieces*1500)
	for i := range pieces {
		burst = append(burst, chunk(i, 1500)...)
	}
	lone := []byte("late message")
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		// Many small writes back to back, like a server sending chunks.
		for i := 0; i < len(burst); i += 1500 {
			if _, writeErr := conn.Write(burst[i : i+1500]); writeErr != nil {
				return
			}
		}
		time.Sleep(300 * time.Millisecond)
		_, _ = conn.Write(lone)
		time.Sleep(300 * time.Millisecond)
	}()

	ctx, hook := dialer.WithReadFlushHook(context.Background())
	proxyDialer, err := dialer.NewWithOptions(dialer.Options{Context: context.Background(), Options: option.DialerOptions{}})
	require.NoError(t, err)
	remote, err := proxyDialer.DialContext(ctx, N.NetworkTCP, M.SocksaddrFromNet(listener.Addr()))
	require.NoError(t, err)
	require.True(t, hook.Attached())

	clientSide, appSide := net.Pipe()
	counted := &countingWriteConn{Conn: clientSide}
	manager := NewConnectionManager(log.NewNOPFactory().NewLogger("test"))
	var done atomic.Bool
	copyDone := make(chan struct{})
	go func() {
		defer close(copyDone)
		manager.connectionCopy(ctx, remote, counted, true, &done, nil)
	}()

	received := make([]byte, len(burst))
	_, err = io.ReadFull(appSide, received)
	require.NoError(t, err)
	require.Equal(t, burst, received)
	burstWrites := counted.writes.Load()
	require.Less(t, burstWrites, int64(pieces/2), "writes should be coalesced")

	start := time.Now()
	late := make([]byte, len(lone))
	_, err = io.ReadFull(appSide, late)
	require.NoError(t, err)
	require.Equal(t, lone, late)
	// Sent 300 ms after the burst; delivered without waiting for more data.
	require.Less(t, time.Since(start), 330*time.Millisecond)

	appSide.Close()
	<-serverDone
	<-copyDone
	t.Logf("burst of %d pieces reached the client in %d writes", pieces, burstWrites)
}
