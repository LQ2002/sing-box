package route

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

// coalescingWriter gathers the small writes of a download copy to the local
// client into larger ones.
//
// A proxy protocol hands the copy one decrypted chunk per read: an SS2022
// server sends ~1.5 KB chunks, so the copy wrote ~1.5 KB at a time (24,430
// writes for 36 MB on the daily phone, 2026-10-07). Each write to the
// client's loopback socket runs the whole TCP send and receive path. A
// loopback benchmark on the same phone (72 MB, cycles of sender and
// receiver) measured 16.9-17.4M cycles per MB in 1.5 KB writes, 4.4-6.4M in
// 4 KB, 3.7-3.9M in 8 KB and 1.4-1.9M in 32 KB.
//
// Writes are copied into a pending buffer and written out when
//   - it reaches coalesceFlushSize,
//   - the outbound is about to read its socket (dialer.ReadFlushHook calls
//     Flush there; only then can the copy block), so nothing waits on a
//     read while data sits here, or
//   - coalesceMaxDelay passed since the first pending byte. With the hook in
//     place this does not fire; it bounds the delay if the hook belongs to a
//     conn that is not the one being read (a mux session whose first stream
//     ended, an auxiliary dial under the same context).
//
// Device A/B on the daily phone (2026-10-07, same binary with an env toggle,
// alternating on/off, 2 x 8 x 9 MB HTTPS per phase, simpleperf on the
// sing-box pid): SS2022 cycles per MB 13.1-18.7M on vs 23.7-29.8M off
// (~36% less over 5 alternations), syscalls ~30% fewer, small-request TTFB
// unchanged (p50 150-165 ms both). Through AnyTLS no change (its streams
// share one mux conn, so only the first stream's copy gets the hook), 32/32
// downloads ok and TTFB unchanged.
//
// The hook may run on another goroutine (a mux session's reader), hence the
// lock (see FlushBeforeRead). It is opaque on purpose: sing's copy must not
// unwrap past it to the client socket while bytes are pending.
type coalescingWriter struct {
	writer  N.ExtendedWriter
	access  sync.Mutex
	pending *buf.Buffer
	timer   *time.Timer
	armed   bool
	err     error
}

const (
	coalesceBufferSize = 64 * 1024
	coalesceFlushSize  = 32 * 1024
	coalesceMaxDelay   = time.Millisecond
)

func newCoalescingWriter(destination net.Conn) *coalescingWriter {
	w := &coalescingWriter{writer: bufio.NewExtendedWriter(destination)}
	w.timer = time.AfterFunc(time.Hour, w.Flush)
	w.timer.Stop()
	return w
}

func (w *coalescingWriter) Write(p []byte) (int, error) {
	w.access.Lock()
	defer w.access.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	if len(p) >= coalesceFlushSize {
		if err := w.flushLocked(); err != nil {
			return 0, err
		}
		n, err := w.writer.Write(p)
		if err != nil {
			w.err = err
		}
		return n, err
	}
	if w.pending == nil {
		w.pending = buf.NewSize(coalesceBufferSize)
	}
	if w.pending.FreeLen() < len(p) {
		if err := w.flushLocked(); err != nil {
			return 0, err
		}
		w.pending = buf.NewSize(coalesceBufferSize)
	}
	n, _ := w.pending.Write(p)
	if w.pending.Len() >= coalesceFlushSize {
		return n, w.flushLocked()
	}
	if !w.armed {
		w.armed = true
		w.timer.Reset(coalesceMaxDelay)
	}
	return n, nil
}

func (w *coalescingWriter) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	_, err := w.Write(buffer.Bytes())
	return err
}

// Flush writes out whatever is pending. Safe from any goroutine.
func (w *coalescingWriter) Flush() {
	w.access.Lock()
	_ = w.flushLocked()
	w.access.Unlock()
}

// FlushBeforeRead is what the outbound's read hook runs. It never waits: on
// a mux session the hook runs on the session's reader, and waiting here
// behind a copy blocked on a slow client would stall every stream of the
// session. If the lock is taken, the copy goroutine is in Write or a flush
// is under way; anything left pending is written by the next flush or by
// the coalesceMaxDelay timer. Without mux the hook runs on the copy
// goroutine itself, between Writes, so the lock is free.
func (w *coalescingWriter) FlushBeforeRead() {
	if !w.access.TryLock() {
		return
	}
	_ = w.flushLocked()
	w.access.Unlock()
}

func (w *coalescingWriter) flushLocked() error {
	if w.armed {
		w.armed = false
		w.timer.Stop()
	}
	if w.err != nil {
		return w.err
	}
	if w.pending == nil || w.pending.IsEmpty() {
		return nil
	}
	pending := w.pending
	w.pending = nil
	// WriteBuffer takes ownership of pending.
	err := w.writer.WriteBuffer(pending)
	if err != nil {
		w.err = err
	}
	return err
}

// Close flushes and stops the timer; it does not close the destination.
func (w *coalescingWriter) Close() error {
	w.access.Lock()
	defer w.access.Unlock()
	err := w.flushLocked()
	w.timer.Stop()
	if w.pending != nil {
		w.pending.Release()
		w.pending = nil
	}
	if w.err == nil {
		w.err = io.ErrClosedPipe
	}
	return err
}

var _ N.ExtendedWriter = (*coalescingWriter)(nil)
