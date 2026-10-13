//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"os"
	"sync"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// downlinkBatcher lets the UDP downlink use the batch/GSO write path that
// tcPacketWriter.WritePacketBatch already has but nothing ever reached.
//
// The downlink copy (sing bufio copyPacketWaitWithPool) reads one datagram
// from the outbound and calls WritePacket, then reads the next: the Shadowsocks
// UDP source yields one datagram per read, so the batch path is never used and
// every datagram pays a full sendto through ip_output, Android's iptables,
// loopback and the inline receive softirq.
//
// Here WritePacket only queues the buffer and returns, so the copy goroutine
// goes straight back to reading while the session's drain goroutine writes. Whatever
// accumulates while a write is in flight goes out as one WritePacketBatch,
// which sing's syscall batch writer turns into sendmmsg with UDP_SEGMENT
// (packet_batch_offload_linux.go). Nothing ever waits to fill a batch: an
// idle session writes each datagram as soon as it arrives, so latency only
// gains one goroutine wakeup.
//
// Measured on the daily phone (experimental/udp_gso_probe in ebpf_sing-box,
// 2026-10-05): one locally delivered 1350-byte datagram costs 16.9 us with
// sendto, 11.4 us in UDP_SEGMENT batches of 4 and 7.7 us in batches of 16;
// during a saturated QUIC download ~80% of downlink datagrams arrived back to
// back in runs of 9 or more and 99.3% of consecutive pairs were GSO-mergeable.
//
// Ordering: one drain goroutine per session, FIFO. A drained batch is split into
// consecutive runs with the same reply source, because WritePacketBatch
// groups by source through a map and would otherwise reorder datagrams from
// different sources.
//
// Ownership: as with WritePacket everywhere in sing, a buffer handed in
// belongs to the writer, error or not (the copy loop only calls Leak, a
// debug assertion, on failure). Queued buffers are released on close.
type downlinkBatcher struct {
	writer downlinkWriter

	access   sync.Mutex
	notFull  *sync.Cond
	hasData  *sync.Cond
	buffers  []*buf.Buffer
	sources  []M.Socksaddr
	spare    []*buf.Buffer
	spareSrc []M.Socksaddr
	running  bool
	waiting  bool
	closed   bool
	err      error
}

// downlinkWriter is what tcPacketWriter provides; tests substitute a fake.
type downlinkWriter interface {
	N.PacketWriter
	N.PacketBatchWriter
}

// downlinkBatchLimit bounds the queue per session. When it is full the copy
// goroutine waits: backpressure instead of loss.
//
// 16, not more: a 2026-10-05 device A/B with 64 measured an average GSO batch
// of ~6 datagrams (Udp OutDatagrams fell ~5.8x), while the heap profile showed
// the extra queued buffers as +2.6 MB in use in sing's 16 KiB buffer class
// (RSS +1.5 MB on average) under looping HTTP/3 downloads. 16 bounds a
// saturated session at 256 KiB and keeps the probe's x16 GSO cost
// (7.7 us/datagram vs 16.9 for sendto).
const downlinkBatchLimit = 16

func newDownlinkBatcher(writer downlinkWriter) *downlinkBatcher {
	b := &downlinkBatcher{writer: writer}
	b.notFull = sync.NewCond(&b.access)
	b.hasData = sync.NewCond(&b.access)
	return b
}

func (b *downlinkBatcher) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	b.access.Lock()
	for len(b.buffers) >= downlinkBatchLimit && !b.closed && b.err == nil {
		b.notFull.Wait()
	}
	if b.closed || b.err != nil {
		err := b.err
		b.access.Unlock()
		buffer.Release()
		if err == nil {
			err = net.ErrClosed
		}
		return err
	}
	b.buffers = append(b.buffers, buffer)
	b.sources = append(b.sources, destination)
	if !b.running {
		b.running = true
		go b.drain()
	} else if b.waiting {
		b.hasData.Signal()
	}
	b.access.Unlock()
	return nil
}

// drain is started by the first WritePacket and then lives as long as the
// session: while the queue is empty it parks on hasData, and close (or a write
// error) ends it.
//
// It used to exit whenever the queue ran dry and be restarted by the next
// WritePacket. The 2026-10-07 device profile (QUIC download through SS2022 UDP)
// put ~2% of sing-box CPU in runtime.newproc for those restarts plus thread
// wakeups around them. Device A/B the same day (WiFi, HTTP/3 downloads of
// 8 x 9 MB, alternating on/off/on/off, 3 reps each, simpleperf on the sing-box
// pid): cycles per MB 49.2-52.2M parked (mean 50.5M) vs 52.4-54.6M restarted
// (mean 53.1M), ~5% less; instructions ~3% and syscalls ~6% fewer.
func (b *downlinkBatcher) drain() {
	for {
		b.access.Lock()
		for len(b.buffers) == 0 && !b.closed && b.err == nil {
			b.waiting = true
			b.hasData.Wait()
			b.waiting = false
		}
		if b.closed || b.err != nil {
			// Closed, or after a write error the session is ending; drop the rest.
			leftover := b.buffers
			b.buffers, b.sources = nil, nil
			b.running = false
			b.access.Unlock()
			buf.ReleaseMulti(leftover)
			return
		}
		buffers, sources := b.buffers, b.sources
		b.buffers, b.sources = b.spare[:0], b.spareSrc[:0]
		b.notFull.Broadcast()
		b.access.Unlock()

		err := b.write(buffers, sources)

		clear(buffers)
		clear(sources)
		b.access.Lock()
		b.spare, b.spareSrc = buffers[:0], sources[:0]
		if err != nil && b.err == nil {
			// Reported to the copy goroutine on its next WritePacket, which
			// then ends the session the way a synchronous failure did.
			b.err = err
			b.notFull.Broadcast()
		}
		b.access.Unlock()
	}
}

// write sends one drained batch, preserving order across reply sources.
func (b *downlinkBatcher) write(buffers []*buf.Buffer, sources []M.Socksaddr) error {
	var firstErr error
	for start := 0; start < len(buffers); {
		end := start + 1
		for end < len(buffers) && sources[end] == sources[start] {
			end++
		}
		var err error
		if end-start == 1 {
			err = b.writer.WritePacket(buffers[start], sources[start])
		} else {
			// WritePacketBatch takes ownership of the buffers, not of the
			// slices: it regroups them into its own slices and never keeps
			// these, so the drain can reuse its backing arrays afterwards.
			err = b.writer.WritePacketBatch(buffers[start:end], sources[start:end])
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
		start = end
	}
	return firstErr
}

// CreatePacketBatchWriter serves copies that already read in batches.
//
// sing's packet copy takes its single-goroutine batch loop
// (bufio copyPacketBatchWaitWithPool) only when the source can read batches
// and the destination can write them; udpNATConn asks this batcher for the
// latter. With an SS2022 outbound that reads with recvmmsg
// (LQ2002/sing-shadowsocks2 packet_batch_read.go), each batch the copy
// goroutine read is written here at once, on that goroutine: no queue, no
// drain goroutine, no wakeups. Those hand-offs (hasData.Signal per datagram,
// notFull.Broadcast per drained batch) were ~9% of sing-box CPU in an
// HTTP/3 download on the daily phone (2026-10-13, symbolized profile:
// runtime.ready <- sync.Cond in WritePacket and drain).
//
// Device A/B (2026-10-14, rebuilt kernel, HTTP/3 downloads of 2 x 9 MB,
// alternating builds with verified switches, 3 rounds x 2 runs): sing-box
// CPU ticks per run 48-54 (mean 51.8) with the queue vs 15-43 (mean 30.2)
// with this path, rates 87-104 vs 92-108 Mbit/s, no slow runs in either.
//
// Sources that cannot read batches keep using WritePacket and the queue.
// Should a session ever mix the two, a batch goes through the queue while it
// holds data or a drain goroutine exists, so order is kept.
func (b *downlinkBatcher) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	return (*downlinkDirectBatchWriter)(b), true
}

type downlinkDirectBatchWriter downlinkBatcher

func (w *downlinkDirectBatchWriter) WritePacketBatch(buffers []*buf.Buffer, sources []M.Socksaddr) error {
	b := (*downlinkBatcher)(w)
	if len(buffers) != len(sources) {
		buf.ReleaseMulti(buffers)
		return os.ErrInvalid
	}
	b.access.Lock()
	if b.closed || b.err != nil {
		err := b.err
		b.access.Unlock()
		buf.ReleaseMulti(buffers)
		if err == nil {
			err = net.ErrClosed
		}
		return err
	}
	queued := b.running || len(b.buffers) > 0
	b.access.Unlock()
	if queued {
		for index, buffer := range buffers {
			if err := b.WritePacket(buffer, sources[index]); err != nil {
				buf.ReleaseMulti(buffers[index+1:])
				return err
			}
		}
		return nil
	}
	// write splits the batch into runs of one reply source, as the drain does.
	return b.write(buffers, sources)
}

// close drops whatever has not been handed to the kernel yet. A batch the
// drain goroutine already took finishes on its own; the tcPacketWriter fails
// harmlessly if the session state is already gone.
func (b *downlinkBatcher) close() {
	b.access.Lock()
	b.closed = true
	buffers := b.buffers
	b.buffers, b.sources = nil, nil
	b.notFull.Broadcast()
	b.hasData.Broadcast()
	b.access.Unlock()
	buf.ReleaseMulti(buffers)
}

// M.Socksaddr (netip.Addr, port, FQDN) is comparable, so write splits runs
// with ==; reply sources here are always IP addresses.
var (
	_ N.PacketWriter            = (*downlinkBatcher)(nil)
	_ N.PacketBatchWriteCreator = (*downlinkBatcher)(nil)
)
