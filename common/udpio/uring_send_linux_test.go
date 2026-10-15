//go:build linux

package udpio

import (
	"errors"
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// sendBatch writes count datagrams in batches: runs of equal size (GSO
// merged) mixed with odd sizes, so both single and segmented sendmsg are
// used.
func uringSendPayload(i int) []byte {
	size := 1200
	if i%7 == 6 {
		size = 300 + i
	}
	payload := bytes.Repeat([]byte{byte(i)}, size)
	payload[0] = byte(i)
	payload[1] = byte(i >> 8)
	return payload
}

func testUringSend(t *testing.T, connected bool) {
	testUringSendWith(t, connected, false)
}

// A ring that cannot be set up leaves the reply socket on sing's sendmmsg
// writer: every datagram still arrives.
func TestUringSendFallsBackWhenSetupFails(t *testing.T) {
	t.Run("unconnected", func(t *testing.T) { testUringSendWith(t, false, true) })
	t.Run("connected", func(t *testing.T) { testUringSendWith(t, true, true) })
}

func testUringSendWith(t *testing.T, connected bool, failSetup bool) {
	useURing(t, false, true)
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	_ = receiver.SetReadBuffer(8 << 20)
	var sender *net.UDPConn
	if connected {
		sender, err = net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	} else {
		sender, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	writer := NewUringPacketBatchWriter(sender)
	if writer == nil {
		t.Skip("io_uring writer unavailable")
	}
	defer writer.Close()
	if failSetup {
		uringSetupFault = errors.New("injected io_uring setup failure")
		defer func() { uringSetupFault = nil }()
	}
	const count = 400
	destination := M.SocksaddrFromNet(receiver.LocalAddr())
	for start := 0; start < count; start += 40 {
		var buffers []*buf.Buffer
		var destinations []M.Socksaddr
		for i := start; i < start+40; i++ {
			buffers = append(buffers, buf.As(uringSendPayload(i)).ToOwned())
			destinations = append(destinations, destination)
		}
		if connected {
			destinations = nil
		}
		if err = writer.WritePacketBatch(buffers, destinations); err != nil {
			t.Fatal(err)
		}
	}
	seen := make([]bool, count)
	readBuffer := make([]byte, 65536)
	_ = receiver.SetReadDeadline(time.Now().Add(3 * time.Second))
	for got := 0; got < count; got++ {
		n, err := receiver.Read(readBuffer)
		if err != nil {
			t.Fatalf("after %d datagrams: %v", got, err)
		}
		i := int(readBuffer[0]) | int(readBuffer[1])<<8
		if i >= count || seen[i] || !bytes.Equal(readBuffer[:n], uringSendPayload(i)) {
			t.Fatalf("bad or duplicate datagram %d (length %d)", i, n)
		}
		seen[i] = true
	}
	if writer.noGSO {
		t.Log("GSO was refused; sent one by one")
	}
}

func TestUringSendUnconnected(t *testing.T) { testUringSend(t, false) }

func TestUringSendConnected(t *testing.T) { testUringSend(t, true) }
