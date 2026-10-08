//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// A batch resolves sessions immediately but queues nothing until flush; flush
// delivers every datagram to its own session in arrival order.
func TestUDPNATBatchDefersHandOffAndKeepsOrder(t *testing.T) {
	connections := make(chan udpNATTestConnection, 2)
	service := newUDPNATService(
		&udpNATTestHandler{connections: connections},
		func(key udpSessionKey, _ M.Socksaddr, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.WithValue(context.Background(), udpNATContextKey{}, key), udpNATTestWriter{}, nil
		},
		time.Minute,
	)
	t.Cleanup(func() { _ = service.Close() })

	destination := M.ParseSocksaddr("1.1.1.1:443")
	sourceA := M.ParseSocksaddr("192.0.2.10:53000")
	sourceB := M.ParseSocksaddr("192.0.2.10:53001")
	keyA := udpSessionKey{Source: sourceA.AddrPort(), Scope: udpSessionScopeLocalTC}
	keyB := udpSessionKey{Source: sourceB.AddrPort(), Scope: udpSessionScopeLocalTC}
	packet := func(payload string) *buf.Buffer {
		buffer := buf.NewPacket()
		_, _ = buffer.WriteString(payload)
		return buffer
	}

	batch := getUDPNATBatch()
	service.newPacketBufferInBatch(batch, keyA, packet("a1"), sourceA, destination, nil)
	service.newPacketBufferInBatch(batch, keyB, packet("b1"), sourceB, destination, nil)
	service.newPacketBufferInBatch(batch, keyA, packet("a2"), sourceA, destination, nil)
	service.newPacketBufferInBatch(batch, keyB, packet("b2"), sourceB, destination, nil)
	service.newPacketBufferInBatch(batch, keyA, packet("a3"), sourceA, destination, nil)

	sessions := make(map[udpSessionKey]*udpNATConn)
	for range 2 {
		connection := receiveUDPNATTestConnection(t, connections)
		sessions[connection.key] = connection.conn.(*udpNATConn)
	}
	for key, conn := range sessions {
		if queued := len(conn.packetChan); queued != 0 {
			t.Fatalf("session %v has %d datagrams queued before flush", key.Source, queued)
		}
	}

	batch.flush()

	want := map[udpSessionKey][]string{keyA: {"a1", "a2", "a3"}, keyB: {"b1", "b2"}}
	for key, payloads := range want {
		conn := sessions[key]
		conn.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 8})
		buffers, destinations, err := conn.WaitReadPackets()
		if err != nil {
			t.Fatal(err)
		}
		if len(buffers) != len(payloads) {
			t.Fatalf("session %v: %d datagrams, want %d", key.Source, len(buffers), len(payloads))
		}
		for index, buffer := range buffers {
			if string(buffer.Bytes()) != payloads[index] || destinations[index] != destination {
				t.Fatalf("session %v datagram %d: %q to %v", key.Source, index, buffer.Bytes(), destinations[index])
			}
			buffer.Release()
		}
	}
}

// A datagram whose session cannot be prepared is released, not held.
func TestUDPNATBatchReleasesRejectedPacket(t *testing.T) {
	service := newUDPNATService(
		&udpNATTestHandler{connections: make(chan udpNATTestConnection, 1)},
		func(udpSessionKey, M.Socksaddr, M.Socksaddr, any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return false, nil, nil, nil
		},
		time.Minute,
	)
	t.Cleanup(func() { _ = service.Close() })

	source := M.ParseSocksaddr("192.0.2.10:53000")
	key := udpSessionKey{Source: source.AddrPort(), Scope: udpSessionScopeLocalTC}
	buffer := buf.NewPacket()
	_, _ = buffer.WriteString("rejected")
	batch := getUDPNATBatch()
	service.newPacketBufferInBatch(batch, key, buffer, source, M.ParseSocksaddr("1.1.1.1:443"), nil)
	// The release itself is the same code as NewPacketBuffer's, covered by
	// TestUDPNATOwnedPacketReleasedWhenPrepareRejects.
	if len(batch.conns) != 0 {
		t.Fatal("rejected datagram was held")
	}
	batch.flush()
}
