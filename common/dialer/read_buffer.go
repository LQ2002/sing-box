package dialer

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

// readBufferedConn coalesces small reads on an outbound TCP connection into
// one read of the socket.
//
// Proxy protocols parse their stream in small pieces: an SS2022/AEAD chunk is
// read as an 18-byte length and then the payload (sing-shadowsocks2 shadowio),
// VMess AEAD chunks and mux frame headers likewise. Each piece is a read(2).
// On the daily phone (2026-10-07, 4 x 9 MB HTTPS through an SS2022 outbound,
// raw_syscalls traced on the sing-box pid) that was 52,262 reads for 36 MB, the
// server sending ~1.5 KB chunks. An SS-only version of this buffer, A/B tested
// on the device (alternating on/off, 2 x 8 x 9 MB per phase, simpleperf on the
// sing-box pid), cut sing-box syscalls per MB from 2276-2793 to 1291-1484 and
// cycles per MB from a mean of 36.3M to 33.7M (ranges overlap). It lives here
// so every protocol gets it, not only Shadowsocks. The generic version, same
// method on the device: SS2022 syscalls per MB 1263-1565 vs 2334-2580,
// cycles per MB mean 32.8M vs 35.8M; through the AnyTLS node (TLS already
// reads large records) no measurable change either way, 32/32 downloads ok.
//
// Reads smaller than readBufferSize are served from a pooled buffer filled by
// one Read of whatever the socket holds (never waiting for more); the buffer
// goes back to the pool as soon as it is drained, so an idle connection holds
// none. Larger reads, as crypto/tls often issues, go straight to the socket.
// Writes are untouched.
//
// Unwrapping: sing's copy, splice and kTLS paths reach the socket through
// N.UnwrapReader/N.CastReader, which honour ReaderReplaceable; it is true only
// while nothing is buffered, so no path can read past buffered bytes. There is
// no SyscallConn on the wrapper itself. Upstream is exposed for common.Cast
// users such as tls_spoof that need the *net.TCPConn for its addresses and
// writes, not for reading.
//
// Not applied to the direct outbound, whose raw socket feeds splice.
type readBufferedConn struct {
	net.Conn
	access  sync.Mutex
	buffer  []byte
	start   int
	end     int
	readErr error
	// holding is set while bytes or a deferred error are buffered. It is
	// atomic so ReaderReplaceable never waits on a Read blocked in the socket.
	holding atomic.Bool
}

const readBufferSize = 32 * 1024

func newReadBufferedConn(conn net.Conn) net.Conn {
	return &readBufferedConn{Conn: conn}
}

func (c *readBufferedConn) Read(p []byte) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.start == c.end {
		if c.readErr != nil {
			err := c.readErr
			c.readErr = nil
			c.holding.Store(false)
			return 0, err
		}
		if len(p) >= readBufferSize {
			return c.Conn.Read(p)
		}
		if c.buffer == nil {
			c.buffer = buf.Get(readBufferSize)
		}
		n, err := c.Conn.Read(c.buffer)
		c.start, c.end = 0, n
		if n == 0 {
			c.release()
			return 0, err
		}
		// Hand out the bytes first; an error that came with them is returned
		// once they are consumed, as io.Reader allows.
		c.readErr = err
		c.holding.Store(true)
	}
	n := copy(p, c.buffer[c.start:c.end])
	c.start += n
	if c.start == c.end {
		c.release()
		c.holding.Store(c.readErr != nil)
	}
	return n, nil
}

func (c *readBufferedConn) release() {
	if c.buffer != nil {
		buf.Put(c.buffer)
		c.buffer = nil
	}
	c.start, c.end = 0, 0
}

func (c *readBufferedConn) Close() error {
	err := c.Conn.Close()
	c.access.Lock()
	c.release()
	c.access.Unlock()
	return err
}

func (c *readBufferedConn) ReaderReplaceable() bool {
	return !c.holding.Load()
}

func (c *readBufferedConn) UpstreamReader() any { return c.Conn }

func (c *readBufferedConn) WriterReplaceable() bool { return true }

func (c *readBufferedConn) UpstreamWriter() any { return c.Conn }

func (c *readBufferedConn) Upstream() any { return c.Conn }

var (
	_ N.ReaderWithUpstream = (*readBufferedConn)(nil)
	_ N.WithUpstreamReader = (*readBufferedConn)(nil)
	_ N.WriterWithUpstream = (*readBufferedConn)(nil)
	_ N.WithUpstreamWriter = (*readBufferedConn)(nil)
)
