//go:build linux

package udpio

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

// TestOOBPacketBatchReadReusesBuffers: buffers that recvmmsg left empty stay
// with the reader, across a read and across a wait on an empty socket, and
// a reused buffer returns exactly the new payload.
func TestOOBPacketBatchReadReusesBuffers(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	if err = enableIPv4PacketInfo(receiver); err != nil {
		t.Fatal(err)
	}
	if err = receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	created, ok := NewOOBPacketBatchReadWaiter(receiver, 256)
	if !ok {
		t.Fatal("OOB packet batch reader was not created")
	}
	reader := created.(*oobPacketBatchReadWaiter)
	const batchSize = 8
	reader.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: batchSize})

	sender, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	send := func(payloads ...[]byte) {
		t.Helper()
		for _, payload := range payloads {
			if _, err := sender.Write(payload); err != nil {
				t.Fatal(err)
			}
		}
	}
	read := func(want ...[]byte) {
		t.Helper()
		buffers, oobs, sources, err := reader.WaitReadOOBPackets()
		if err != nil {
			t.Fatal(err)
		}
		defer buf.ReleaseMulti(buffers)
		if len(buffers) != len(want) || len(oobs) != len(want) || len(sources) != len(want) {
			t.Fatalf("read %d packets, want %d", len(buffers), len(want))
		}
		for index, buffer := range buffers {
			if !bytes.Equal(buffer.Bytes(), want[index]) {
				t.Fatalf("packet %d = %q, want %q", index, buffer.Bytes(), want[index])
			}
		}
	}
	held := func() []*buf.Buffer {
		return append([]*buf.Buffer(nil), reader.buffers...)
	}

	long := bytes.Repeat([]byte{'L'}, 1200)
	send(long, []byte("b"), []byte("c"))
	time.Sleep(50 * time.Millisecond)
	read(long, []byte("b"), []byte("c"))
	afterFirst := held()
	for index, buffer := range afterFirst {
		if (index < 3) != (buffer == nil) {
			t.Fatalf("slot %d: handed-out slots must be empty and the rest kept: %v", index, afterFirst)
		}
	}

	// Wait on the empty socket first: EAGAIN must not drop the kept buffers.
	go func() {
		time.Sleep(100 * time.Millisecond)
		send([]byte("short"))
	}()
	read([]byte("short"))
	afterWait := held()
	for index := 3; index < batchSize; index++ {
		if afterWait[index] != afterFirst[index] {
			t.Fatalf("slot %d was reallocated", index)
		}
	}

	// Slots refilled after the first read go first; a later batch reaches
	// the kept buffers and must see only the new bytes.
	payloads := make([][]byte, batchSize)
	for index := range payloads {
		payloads[index] = []byte{byte('0' + index)}
	}
	send(payloads...)
	time.Sleep(50 * time.Millisecond)
	read(payloads...)
	for index, buffer := range reader.buffers {
		if buffer != nil {
			t.Fatalf("slot %d still held after a full batch", index)
		}
	}
}
