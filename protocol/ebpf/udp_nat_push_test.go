package ebpf

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// udpNATPushRecorder is a push handler like route's packet push upload: it
// holds datagrams until FlushPushedPackets.
type udpNATPushRecorder struct {
	access  sync.Mutex
	pending []string
	flushed [][]string
	closed  bool
}

func (r *udpNATPushRecorder) NewPacketEx(buffer *buf.Buffer, _ M.Socksaddr) {
	r.access.Lock()
	r.pending = append(r.pending, string(buffer.Bytes()))
	r.access.Unlock()
	buffer.Release()
}

func (r *udpNATPushRecorder) FlushPushedPackets() {
	r.access.Lock()
	if len(r.pending) > 0 {
		r.flushed = append(r.flushed, r.pending)
		r.pending = nil
	}
	r.access.Unlock()
}

func (r *udpNATPushRecorder) Close() error {
	r.access.Lock()
	r.closed = true
	r.access.Unlock()
	return nil
}

func (r *udpNATPushRecorder) snapshot() ([][]string, []string, bool) {
	r.access.Lock()
	defer r.access.Unlock()
	return append([][]string(nil), r.flushed...), append([]string(nil), r.pending...), r.closed
}

func newUDPNATPushTest(t *testing.T) (*udpNATService, udpSessionKey, M.Socksaddr, M.Socksaddr, chan udpNATTestConnection) {
	connections := make(chan udpNATTestConnection, 1)
	service := newUDPNATService(
		&udpNATTestHandler{connections: connections},
		func(key udpSessionKey, _ M.Socksaddr, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.WithValue(context.Background(), udpNATContextKey{}, key), udpNATTestWriter{}, nil
		},
		time.Minute,
	)
	t.Cleanup(func() { _ = service.Close() })
	source := M.ParseSocksaddr("192.0.2.10:53000")
	destination := M.ParseSocksaddr("1.1.1.1:443")
	key := udpSessionKey{Source: source.AddrPort(), Scope: udpSessionScopeLocalTC}
	return service, key, source, destination, connections
}

func pushTestPacket(payload string) *buf.Buffer {
	buffer := buf.NewPacket()
	_, _ = buffer.WriteString(payload)
	return buffer
}

func TestUDPNATPushDrainsQueueAndFlushesPerReadBatch(t *testing.T) {
	service, key, source, destination, connections := newUDPNATPushTest(t)
	service.NewPacketBuffer(key, pushTestPacket("queued"), source, destination, nil)
	natConn := receiveUDPNATTestConnection(t, connections).conn.(*udpNATConn)
	recorder := &udpNATPushRecorder{}
	if !natConn.SetPacketPushHandler(recorder) {
		t.Fatal("open session refused push")
	}
	flushed, pending, _ := recorder.snapshot()
	if len(pending) != 0 || len(flushed) != 1 || flushed[0][0] != "queued" {
		t.Fatalf("queued packet not drained and flushed: flushed=%v pending=%v", flushed, pending)
	}

	// One inbound read batch: everything is pushed, nothing written until
	// the batch ends, then a single flush.
	service.beginPushBatch()
	service.NewPacketBuffer(key, pushTestPacket("a"), source, destination, nil)
	service.NewPacket(key, [][]byte{[]byte("b")}, source, destination, nil)
	flushed, pending, _ = recorder.snapshot()
	if len(flushed) != 1 || len(pending) != 2 {
		t.Fatalf("batch flushed early: flushed=%v pending=%v", flushed, pending)
	}
	service.endPushBatch()
	flushed, pending, _ = recorder.snapshot()
	if len(pending) != 0 || len(flushed) != 2 || len(flushed[1]) != 2 || flushed[1][0] != "a" || flushed[1][1] != "b" {
		t.Fatalf("read batch not flushed once in order: flushed=%v pending=%v", flushed, pending)
	}

	// Outside a read batch every datagram is flushed at once.
	service.NewPacketBuffer(key, pushTestPacket("c"), source, destination, nil)
	flushed, _, _ = recorder.snapshot()
	if len(flushed) != 3 || flushed[2][0] != "c" {
		t.Fatalf("unbatched packet not flushed: %v", flushed)
	}

	_ = natConn.Close()
	if _, _, closed := recorder.snapshot(); !closed {
		t.Fatal("closing the session did not close its push handler")
	}
}

func TestUDPNATPushRefusedAfterClose(t *testing.T) {
	service, key, source, destination, connections := newUDPNATPushTest(t)
	service.NewPacketBuffer(key, pushTestPacket("x"), source, destination, nil)
	natConn := receiveUDPNATTestConnection(t, connections).conn.(*udpNATConn)
	_ = natConn.Close()
	recorder := &udpNATPushRecorder{}
	if natConn.SetPacketPushHandler(recorder) {
		t.Fatal("closed session accepted push")
	}
	if _, _, closed := recorder.snapshot(); !closed {
		t.Fatal("refused push handler was not closed")
	}
}

// udpNATSelfClosingPushHandler closes its session from Close, as route's
// packet push upload does through its finish callback.
type udpNATSelfClosingPushHandler struct {
	conn *udpNATConn
}

func (h *udpNATSelfClosingPushHandler) NewPacketEx(buffer *buf.Buffer, _ M.Socksaddr) {
	buffer.Release()
}

func (h *udpNATSelfClosingPushHandler) Close() error {
	return h.conn.Close()
}

// Regression for the 2026-10-17 shutdown hang: closing the handler inside
// closeOnce deadlocked when the handler closed the connection again.
func TestUDPNATPushHandlerMayCloseSessionFromClose(t *testing.T) {
	service, key, source, destination, connections := newUDPNATPushTest(t)
	service.NewPacketBuffer(key, pushTestPacket("x"), source, destination, nil)
	natConn := receiveUDPNATTestConnection(t, connections).conn.(*udpNATConn)
	natConn.SetPacketPushHandler(&udpNATSelfClosingPushHandler{conn: natConn})
	done := make(chan struct{})
	go func() {
		_ = natConn.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("session close deadlocked on a handler that closes the session")
	}
	closed := make(chan struct{})
	go func() {
		_ = service.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("service close deadlocked")
	}
}
