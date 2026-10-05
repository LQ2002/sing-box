//go:build with_ebpf && (linux || android)

package ebpf

// Measurement only (branch claude/udp-batch-measure, not for the daily build
// as is): how many downlink datagrams a tcPacketWriter could have sent in one
// batch, had the copy loop handed it everything already available.
//
// Why timing: the downlink copy (sing bufio copyPacketWaitWithPool) reads one
// datagram, writes it, reads the next. When the next datagram is already
// queued on the upstream socket, the read returns at once and the next
// WritePacket starts a few microseconds after the previous one ended; when it
// is not, the goroutine parks in netpoll and the gap is tens of microseconds
// or more. A run of back-to-back writes is therefore the batch an
// opportunistic batcher would have seen. Gaps are bucketed so the threshold
// can be read off the distribution instead of assumed; runs are counted at
// two thresholds (10 us and 30 us) to show how sensitive the answer is.
//
// GSO (sing's packet_batch_offload_linux.go) only merges consecutive
// datagrams of equal size to the same destination (the last may be
// shorter), so pairs inside a run are also classified by that rule.
//
// Output: one Info line per 10 s with traffic, readable through the Clash API
// /logs stream even when the configured log level is error.

import (
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var downlinkGapBoundsUs = [...]int64{2, 5, 10, 20, 30, 50, 100, 1000}

type downlinkBatchStats struct {
	access sync.Mutex
	downlinkCounters
}

type downlinkCounters struct {
	packets   uint64
	batchCall uint64
	gaps      [len(downlinkGapBoundsUs) + 1]uint64
	// runs[t][b]: runs at threshold t whose length falls in bucket b
	// (1, 2, 3-4, 5-8, 9-16, 17-32, 33-64, >64). Weighted by packets so
	// the shares read as "fraction of datagrams sent in a run of this size".
	runPackets [2][8]uint64
	gsoPairs   uint64 // consecutive (gap < 30 us) pairs GSO could merge
	pairs      uint64 // consecutive (gap < 30 us) pairs
}

var (
	downlinkStats       downlinkBatchStats
	downlinkStatsLogged atomic.Int64
)

var downlinkRunThresholds = [2]time.Duration{10 * time.Microsecond, 30 * time.Microsecond}

type downlinkBatchProbe struct {
	access      sync.Mutex
	lastEnd     time.Time
	lastSize    int
	lastDest    netip.AddrPort
	runs        [2]int
	initialized bool
}

func runBucket(n int) int {
	switch {
	case n <= 1:
		return 0
	case n == 2:
		return 1
	case n <= 4:
		return 2
	case n <= 8:
		return 3
	case n <= 16:
		return 4
	case n <= 32:
		return 5
	case n <= 64:
		return 6
	}
	return 7
}

// begin is called at the start of WritePacket; the returned func at its end.
func (p *downlinkBatchProbe) begin(w *tcPacketWriter, size int, destination netip.AddrPort) func() {
	now := time.Now()
	p.access.Lock()
	stats := &downlinkStats
	stats.access.Lock()
	stats.packets++
	if p.initialized {
		gap := now.Sub(p.lastEnd)
		bucket := len(downlinkGapBoundsUs)
		for index, bound := range downlinkGapBoundsUs {
			if gap < time.Duration(bound)*time.Microsecond {
				bucket = index
				break
			}
		}
		stats.gaps[bucket]++
		for t, threshold := range downlinkRunThresholds {
			if gap < threshold {
				p.runs[t]++
			} else {
				stats.runPackets[t][runBucket(p.runs[t])] += uint64(p.runs[t])
				p.runs[t] = 1
			}
		}
		if gap < downlinkRunThresholds[1] {
			stats.pairs++
			if destination == p.lastDest && size <= p.lastSize {
				stats.gsoPairs++
			}
		}
	} else {
		p.runs = [2]int{1, 1}
		p.initialized = true
	}
	stats.access.Unlock()
	p.lastSize, p.lastDest = size, destination
	p.access.Unlock()
	maybeLogDownlinkStats(w)
	return func() {
		p.access.Lock()
		p.lastEnd = time.Now()
		p.access.Unlock()
	}
}

func maybeLogDownlinkStats(w *tcPacketWriter) {
	now := time.Now().UnixNano()
	last := downlinkStatsLogged.Load()
	if now-last < int64(10*time.Second) || !downlinkStatsLogged.CompareAndSwap(last, now) {
		return
	}
	stats := &downlinkStats
	stats.access.Lock()
	snapshot := stats.downlinkCounters
	stats.downlinkCounters = downlinkCounters{}
	stats.access.Unlock()
	if snapshot.packets == 0 {
		return
	}
	var line strings.Builder
	line.WriteString("udp downlink batch probe: packets=")
	line.WriteString(strconv.FormatUint(snapshot.packets, 10))
	line.WriteString(" batch_calls=")
	line.WriteString(strconv.FormatUint(snapshot.batchCall, 10))
	line.WriteString(" gap_us")
	for index, count := range snapshot.gaps {
		if index < len(downlinkGapBoundsUs) {
			line.WriteString(" <" + strconv.FormatInt(downlinkGapBoundsUs[index], 10) + "=")
		} else {
			line.WriteString(" >=1000=")
		}
		line.WriteString(strconv.FormatUint(count, 10))
	}
	labels := [...]string{"1", "2", "3-4", "5-8", "9-16", "17-32", "33-64", ">64"}
	for t, threshold := range downlinkRunThresholds {
		line.WriteString(" run_pkts@" + strconv.Itoa(int(threshold/time.Microsecond)) + "us")
		for bucket, count := range snapshot.runPackets[t] {
			line.WriteString(" " + labels[bucket] + "=" + strconv.FormatUint(count, 10))
		}
	}
	line.WriteString(" pairs=" + strconv.FormatUint(snapshot.pairs, 10))
	line.WriteString(" gso_pairs=" + strconv.FormatUint(snapshot.gsoPairs, 10))
	w.inbound.logger.Info(line.String())
}

func countDownlinkBatchCall() {
	downlinkStats.access.Lock()
	downlinkStats.batchCall++
	downlinkStats.access.Unlock()
}
