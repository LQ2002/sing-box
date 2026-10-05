//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// fakeDownlinkWriter records every call. While gate is non-nil, the first
// call blocks on it, so later datagrams pile up in the batcher's queue.
type fakeDownlinkWriter struct {
	access  sync.Mutex
	calls   [][]string // payloads per call
	sources [][]M.Socksaddr
	gate    chan struct{}
	gated   bool
	entered chan struct{}
	err     error
}

func (w *fakeDownlinkWriter) record(buffers []*buf.Buffer, sources []M.Socksaddr) error {
	w.access.Lock()
	gate := w.gate
	first := !w.gated
	w.gated = true
	w.access.Unlock()
	if gate != nil && first {
		close(w.entered)
		<-gate
	}
	payloads := make([]string, len(buffers))
	for index, buffer := range buffers {
		payloads[index] = string(buffer.Bytes())
	}
	buf.ReleaseMulti(buffers)
	w.access.Lock()
	defer w.access.Unlock()
	w.calls = append(w.calls, payloads)
	w.sources = append(w.sources, append([]M.Socksaddr(nil), sources...))
	return w.err
}

func (w *fakeDownlinkWriter) WritePacket(buffer *buf.Buffer, source M.Socksaddr) error {
	return w.record([]*buf.Buffer{buffer}, []M.Socksaddr{source})
}

func (w *fakeDownlinkWriter) WritePacketBatch(buffers []*buf.Buffer, sources []M.Socksaddr) error {
	return w.record(buffers, sources)
}

func (w *fakeDownlinkWriter) snapshot() [][]string {
	w.access.Lock()
	defer w.access.Unlock()
	return append([][]string(nil), w.calls...)
}

func packet(text string) *buf.Buffer { return buf.As([]byte(text)).ToOwned() }

func waitDrained(t *testing.T, b *downlinkBatcher) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b.access.Lock()
		idle := !b.running && len(b.buffers) == 0
		b.access.Unlock()
		if idle {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("batcher did not drain")
}

var (
	sourceA = M.SocksaddrFromNetIP(netip.MustParseAddrPort("203.0.113.1:443"))
	sourceB = M.SocksaddrFromNetIP(netip.MustParseAddrPort("203.0.113.2:443"))
)

// Datagrams that arrive while a write is in flight leave as one batch call,
// split only where the reply source changes, in arrival order.
func TestDownlinkBatcherBatchesWhileWriteInFlight(t *testing.T) {
	writer := &fakeDownlinkWriter{gate: make(chan struct{}), entered: make(chan struct{})}
	b := newDownlinkBatcher(writer)
	if err := b.WritePacket(packet("0"), sourceA); err != nil {
		t.Fatal(err)
	}
	<-writer.entered // the drain goroutine is now blocked writing "0"
	order := []M.Socksaddr{sourceA, sourceA, sourceA, sourceB, sourceB, sourceA}
	for index, source := range order {
		if err := b.WritePacket(packet(strconv.Itoa(index+1)), source); err != nil {
			t.Fatal(err)
		}
	}
	close(writer.gate)
	waitDrained(t, b)
	got := writer.snapshot()
	want := [][]string{{"0"}, {"1", "2", "3"}, {"4", "5"}, {"6"}}
	if len(got) != len(want) {
		t.Fatalf("calls = %v, want %v", got, want)
	}
	for index := range want {
		if len(got[index]) != len(want[index]) {
			t.Fatalf("calls = %v, want %v", got, want)
		}
		for j := range want[index] {
			if got[index][j] != want[index][j] {
				t.Fatalf("calls = %v, want %v", got, want)
			}
		}
	}
}

// An idle batcher writes each datagram on its own: nothing waits for a batch.
func TestDownlinkBatcherIdleWritesImmediately(t *testing.T) {
	writer := &fakeDownlinkWriter{}
	b := newDownlinkBatcher(writer)
	for index := range 3 {
		if err := b.WritePacket(packet(strconv.Itoa(index)), sourceA); err != nil {
			t.Fatal(err)
		}
		waitDrained(t, b)
	}
	if got := writer.snapshot(); len(got) != 3 {
		t.Fatalf("calls = %v, want three single writes", got)
	}
}

// A write error ends the session: the next WritePacket returns it and
// releases its buffer, and queued datagrams are dropped, not written.
func TestDownlinkBatcherReportsWriteError(t *testing.T) {
	failure := errors.New("reply socket gone")
	writer := &fakeDownlinkWriter{err: failure}
	b := newDownlinkBatcher(writer)
	if err := b.WritePacket(packet("0"), sourceA); err != nil {
		t.Fatal(err)
	}
	waitDrained(t, b)
	if err := b.WritePacket(packet("1"), sourceA); !errors.Is(err, failure) {
		t.Fatalf("err = %v, want %v", err, failure)
	}
	if got := writer.snapshot(); len(got) != 1 {
		t.Fatalf("calls after error = %v", got)
	}
}

// A full queue makes the copy goroutine wait instead of dropping.
func TestDownlinkBatcherBackpressure(t *testing.T) {
	writer := &fakeDownlinkWriter{gate: make(chan struct{}), entered: make(chan struct{})}
	b := newDownlinkBatcher(writer)
	if err := b.WritePacket(packet("first"), sourceA); err != nil {
		t.Fatal(err)
	}
	<-writer.entered
	for index := range downlinkBatchLimit {
		if err := b.WritePacket(packet(strconv.Itoa(index)), sourceA); err != nil {
			t.Fatal(err)
		}
	}
	blocked := make(chan error, 1)
	go func() { blocked <- b.WritePacket(packet("over"), sourceA) }()
	select {
	case err := <-blocked:
		t.Fatalf("WritePacket over the limit returned early: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(writer.gate)
	if err := <-blocked; err != nil {
		t.Fatal(err)
	}
	waitDrained(t, b)
	total := 0
	for _, call := range writer.snapshot() {
		total += len(call)
	}
	if total != downlinkBatchLimit+2 {
		t.Fatalf("delivered %d datagrams, want %d", total, downlinkBatchLimit+2)
	}
}

// Closing releases what is queued and refuses later writes.
func TestDownlinkBatcherClose(t *testing.T) {
	writer := &fakeDownlinkWriter{gate: make(chan struct{}), entered: make(chan struct{})}
	b := newDownlinkBatcher(writer)
	_ = b.WritePacket(packet("in-flight"), sourceA)
	<-writer.entered
	queued := packet("queued")
	_ = b.WritePacket(queued, sourceA)
	b.close()
	close(writer.gate)
	waitDrained(t, b)
	if err := b.WritePacket(packet("late"), sourceA); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("err after close = %v", err)
	}
	for _, call := range writer.snapshot() {
		for _, payload := range call {
			if payload != "in-flight" {
				t.Fatalf("written after close: %q", payload)
			}
		}
	}
}

// End to end through the real tcPacketWriter and reply sockets: every
// datagram arrives, from the right reply source.
//
// Order is asserted by TestDownlinkBatcherBatchesWhileWriteInFlight, not
// here: loopback delivery itself can reorder. netif_rx queues on the sending
// CPU's backlog, so two writes made from different CPUs can be processed in
// either order. A control run on 2026-10-05 (WSL, -race, 15 rounds of 400
// datagrams) reordered 6 of 15 rounds with the original per-datagram
// WritePacket and 6 of 15 with WritePacketBatch, i.e. the batcher adds no
// reordering of its own. Reorders are logged for information.
func TestDownlinkBatcherThroughTCPacketWriter(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	_ = receiver.SetReadBuffer(4 << 20)
	client := receiver.LocalAddr().(*net.UDPAddr).AddrPort()
	firstSource := reserveUDPSource(t)
	secondSource := reserveUDPSource(t)
	for secondSource == firstSource {
		secondSource = reserveUDPSource(t)
	}
	key := udpSessionKey{Source: client, Scope: udpSessionScopeLocalTC}
	inbound := &Inbound{}
	inbound.udpClientTable.setDirectBinding(key, firstSource, nil, 0)
	state, loaded := inbound.udpClientTable.load(key)
	if !loaded {
		t.Fatal("UDP client state is missing")
	}
	writer := &tcPacketWriter{
		inbound: inbound, key: key, clientState: state,
		newReplySocket: func(source netip.AddrPort) (*net.UDPConn, func(), error) {
			socket, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(source))
			return socket, nil, err
		},
	}
	defer inbound.udpReplySockets.close()
	b := newDownlinkBatcher(writer)
	const count = 400
	sources := []netip.AddrPort{firstSource, secondSource}
	for index := range count {
		source := sources[(index/7)%2] // runs of 7 per source
		if err = b.WritePacket(packet(strconv.Itoa(index)), M.SocksaddrFromNetIP(source)); err != nil {
			t.Fatal(err)
		}
	}
	waitDrained(t, b)
	_ = receiver.SetReadDeadline(time.Now().Add(2 * time.Second))
	last := map[netip.AddrPort]int{firstSource: -1, secondSource: -1}
	reorders := 0
	buffer := make([]byte, 64)
	for range count {
		n, from, readErr := receiver.ReadFromUDPAddrPort(buffer)
		if readErr != nil {
			t.Fatal(readErr)
		}
		index, _ := strconv.Atoi(string(buffer[:n]))
		if want := sources[(index/7)%2]; from != want {
			t.Fatalf("datagram %d came from %v, want %v", index, from, want)
		}
		if index <= last[from] {
			reorders++
		}
		last[from] = max(last[from], index)
	}
	t.Logf("loopback reorders: %d of %d", reorders, count)
}

var _ N.PacketBatchWriter = (*fakeDownlinkWriter)(nil)
