//go:build linux

package udpio

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

// The recvmmsg reader's tests, run against the io_uring reader.
func TestUringOOBReadWriteIPv4(t *testing.T) {
	EnableUDPIOUring = true
	defer func() { EnableUDPIOUring = false }()
	TestOOBPacketBatchReadWriteIPv4(t)
}

func TestUringOOBReadWriteIPv6(t *testing.T) {
	EnableUDPIOUring = true
	defer func() { EnableUDPIOUring = false }()
	TestOOBPacketBatchReadWriteIPv6(t)
}

func newUringOOBTestReader(t *testing.T) (*net.UDPConn, *net.UDPConn, *uringOOBReadWaiter) {
	t.Helper()
	EnableUDPIOUring = true
	t.Cleanup(func() { EnableUDPIOUring = false })
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err = enableIPv4PacketInfo(receiver); err != nil {
		t.Fatal(err)
	}
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	waiter, created := NewOOBPacketBatchReadWaiter(receiver, 1024)
	if !created {
		t.Fatal("reader was not created")
	}
	reader, isUring := waiter.(*uringOOBReadWaiter)
	if !isUring {
		t.Skip("io_uring reader unavailable")
	}
	reader.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 64})
	return receiver, sender, reader
}

func TestUringOOBShutdownWakesBlockedReader(t *testing.T) {
	receiver, sender, reader := newUringOOBTestReader(t)
	defer sender.Close()
	if _, err := sender.WriteTo([]byte("x"), receiver.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buffers, oobs, sources, err := reader.WaitReadOOBPackets()
	if err != nil || len(buffers) != 1 || len(oobs) != 1 || len(sources) != 1 {
		t.Fatalf("first read: %d buffers, err %v", len(buffers), err)
	}
	if sources[0].String() != sender.LocalAddr().String() {
		t.Fatalf("source %s, want %s", sources[0], sender.LocalAddr())
	}
	buf.ReleaseMulti(buffers)
	go func() {
		time.Sleep(100 * time.Millisecond)
		reader.Shutdown()
		receiver.Close()
	}()
	start := time.Now()
	_, _, _, err = reader.WaitReadOOBPackets()
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("after Shutdown: %v, want net.ErrClosed", err)
	}
	if waited := time.Since(start); waited < 50*time.Millisecond || waited > 3*time.Second {
		t.Fatalf("returned after %s", waited)
	}
	if reader.ringFD >= 0 {
		t.Fatal("ring not released")
	}
}

func TestUringOOBShutdownWhileIdleReleasesRing(t *testing.T) {
	receiver, sender, reader := newUringOOBTestReader(t)
	defer sender.Close()
	defer receiver.Close()
	if _, err := sender.WriteTo([]byte("x"), receiver.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		buffers, _, _, err := reader.WaitReadOOBPackets()
		if err != nil {
			t.Error(err)
		}
		buf.ReleaseMulti(buffers)
		close(done)
	}()
	<-done
	if reader.ringFD < 0 {
		t.Fatal("ring not created")
	}
	reader.Shutdown()
	if reader.ringFD >= 0 {
		t.Fatal("Shutdown left the ring of an idle reader open")
	}
}

// A burst larger than the buffer ring: every datagram arrives once, with its
// control data, across ENOBUFS re-arms.
func TestUringOOBBurst(t *testing.T) {
	receiver, sender, reader := newUringOOBTestReader(t)
	defer sender.Close()
	defer receiver.Close()
	_ = receiver.SetReadBuffer(4 << 20)
	const count = 300
	for i := range count {
		payload := make([]byte, 100+i)
		payload[0] = byte(i)
		payload[1] = byte(i >> 8)
		if _, err := sender.WriteTo(payload, receiver.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	seen := make([]bool, count)
	got := 0
	deadline := time.Now().Add(5 * time.Second)
	for got < count && time.Now().Before(deadline) {
		buffers, oobs, sources, err := reader.WaitReadOOBPackets()
		if err != nil {
			t.Fatal(err)
		}
		for index, buffer := range buffers {
			i := int(buffer.Byte(0)) | int(buffer.Byte(1))<<8
			if i >= count || seen[i] || buffer.Len() != 100+i {
				t.Fatalf("bad or duplicate datagram %d (length %d)", i, buffer.Len())
			}
			if !containsPacketInfo(oobs[index], 0, 8) { // IPPROTO_IP, IP_PKTINFO
				t.Fatalf("datagram %d without IP_PKTINFO", i)
			}
			if sources[index].String() != sender.LocalAddr().String() {
				t.Fatalf("datagram %d source %s", i, sources[index])
			}
			seen[i] = true
			got++
		}
		buf.ReleaseMulti(buffers)
	}
	if got != count {
		t.Fatalf("got %d of %d", got, count)
	}
	reader.Shutdown()
}

// The netpoll wait variant (with and without COOP_TASKRUN) must pass the
// same tests.
func TestUringOOBNetpollVariants(t *testing.T) {
	for _, variant := range []struct {
		name string
		coop bool
	}{{"netpoll", false}, {"netpoll-coop", true}} {
		t.Run(variant.name, func(t *testing.T) {
			oldNetpoll, oldCoop := udpIOUringNetpoll, udpIOUringCoop
			udpIOUringNetpoll, udpIOUringCoop = true, variant.coop
			defer func() { udpIOUringNetpoll, udpIOUringCoop = oldNetpoll, oldCoop }()
			t.Run("ipv4", TestUringOOBReadWriteIPv4)
			t.Run("ipv6", TestUringOOBReadWriteIPv6)
			t.Run("shutdown-blocked", TestUringOOBShutdownWakesBlockedReader)
			t.Run("shutdown-idle", TestUringOOBShutdownWhileIdleReleasesRing)
			t.Run("burst", TestUringOOBBurst)
		})
	}
}
