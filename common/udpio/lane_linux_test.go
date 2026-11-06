//go:build linux

package udpio

import (
	"net/netip"
	"testing"
	"unsafe"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type laneNext struct {
	packets      int
	destinations []M.Socksaddr
}

func (n *laneNext) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	n.packets += len(buffers)
	n.destinations = destinations
	buf.ReleaseMulti(buffers)
	return nil
}

func laneFixture(t *testing.T, count int, destination string) ([]*buf.Buffer, []M.Socksaddr) {
	t.Helper()
	buffers := make([]*buf.Buffer, count)
	destinations := make([]M.Socksaddr, count)
	for index := range buffers {
		buffers[index] = buf.New()
		_, err := buffers[index].Write([]byte{byte(index), 1, 2, 3})
		require.NoError(t, err)
		destinations[index] = M.SocksaddrFromNetIP(netip.MustParseAddrPort(destination))
	}
	return buffers, destinations
}

func stubDeliver(t *testing.T, fn func(batch *sbflBatch) error) {
	t.Helper()
	old := laneDeliver
	laneDeliver = fn
	t.Cleanup(func() { laneDeliver = old })
}

func TestSbflABI(t *testing.T) {
	require.EqualValues(t, 32, unsafe.Sizeof(sbflBatch{}))
	require.EqualValues(t, 16, unsafe.Sizeof(sbflIOV{}))
	require.EqualValues(t, 20, unsafe.Sizeof(sbflAttach{}))
	require.EqualValues(t, 16, unsafe.Sizeof(sbflUID{}))
}

func TestLaneBatch(t *testing.T) {
	next := &laneNext{}
	writer := &LanePacketBatchWriter{source: netip.MustParseAddrPort("198.18.0.9:443"), next: next}
	var counts []uint32
	stubDeliver(t, func(batch *sbflBatch) error {
		counts = append(counts, batch.count)
		require.Equal(t, [4]byte{198, 18, 0, 9}, batch.saddr)
		require.Equal(t, [4]byte{192, 168, 3, 6}, batch.daddr)
		require.Equal(t, [2]byte{1, 187}, batch.sport)
		require.Equal(t, [2]byte{0x30, 0x39}, batch.dport)
		iov := unsafe.Slice((*sbflIOV)(unsafe.Pointer(uintptr(batch.iov))), batch.count)
		for _, entry := range iov {
			require.EqualValues(t, 4, entry.len)
		}
		batch.delivered = batch.count
		return nil
	})
	buffers, destinations := laneFixture(t, 70, "192.168.3.6:12345")
	require.NoError(t, writer.WritePacketBatch(buffers, destinations))
	require.Equal(t, []uint32{64, 6}, counts)
	require.Zero(t, next.packets)
}

func TestLaneRefusedGoesToNext(t *testing.T) {
	next := &laneNext{}
	writer := &LanePacketBatchWriter{source: netip.MustParseAddrPort("198.18.0.9:443"), next: next}
	calls := 0
	stubDeliver(t, func(batch *sbflBatch) error {
		calls++
		if calls == 2 {
			return unix.ENOENT
		}
		batch.delivered = batch.count
		return nil
	})
	buffers, destinations := laneFixture(t, 70, "192.168.3.6:12345")
	require.NoError(t, writer.WritePacketBatch(buffers, destinations))
	require.Equal(t, 2, calls)
	require.Equal(t, 6, next.packets)
	require.Len(t, next.destinations, 6)
}

func TestLaneNotForIt(t *testing.T) {
	stubDeliver(t, func(*sbflBatch) error {
		t.Fatal("must not reach the module")
		return nil
	})
	next := &laneNext{}
	writer := &LanePacketBatchWriter{source: netip.MustParseAddrPort("198.18.0.9:443"), next: next}
	buffers, destinations := laneFixture(t, 2, "[2001:db8::1]:1000")
	require.NoError(t, writer.WritePacketBatch(buffers, destinations))
	require.Equal(t, 2, next.packets)

	buffers, destinations = laneFixture(t, 2, "192.168.3.6:1000")
	destinations[1] = M.SocksaddrFromNetIP(netip.MustParseAddrPort("192.168.3.6:1001"))
	require.NoError(t, writer.WritePacketBatch(buffers, destinations))
	require.Equal(t, 4, next.packets)
	require.False(t, writer.WriteOne([]byte{1}, netip.MustParseAddrPort("[2001:db8::1]:1000")))
}

func TestLaneOffByDefault(t *testing.T) {
	require.Nil(t, NewLanePacketBatchWriter(netip.MustParseAddrPort("198.18.0.9:443"), &laneNext{}))
}
