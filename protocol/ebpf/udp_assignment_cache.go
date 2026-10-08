//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"sync"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

// udpAssignmentCache keeps recent uplink UDP assignments so that steady
// traffic does not cost a bpf(2) lookup per datagram.
//
// newTCPacket needs the flow's TC assignment (socket cookie, path, interface)
// for every datagram, and a flow key's value can change: a new socket reusing
// the five-tuple (a new cookie), fchown, or the delivery path filling in the
// interface. The TC programs therefore publish a write generation
// (TCBackend.AssignmentGeneration, sing-ebpf tc_assign_generation). They bump
// it after every tc_assignment write and before the packet that caused the
// write reaches the listener. An entry stores the generation read *before*
// its lookup, so it is used only while no assignment at all has been written
// since. Any write, of any flow, sends every flow back to one real lookup.
//
// Measured on the daily phone (2026-10-08): about one bpf(2) per uplink
// datagram (~21k per 25 MB upload, ~36% of sing-box's syscalls), and 3.4% of
// sing-box cycles for the lookup path.
//
// When the kernel cannot map the generation, nothing is cached and every
// datagram is looked up as before.
type udpAssignmentCache struct {
	access  sync.Mutex
	owner   any
	entries map[udpAssignmentCacheKey]udpAssignmentCacheEntry
}

type udpAssignmentCacheKey struct {
	client         netip.AddrPort
	destination    netip.AddrPort
	interfaceIndex uint32
}

type udpAssignmentCacheEntry struct {
	assignment commonEBPF.TCAssignment
	generation uint64
}

// udpAssignmentCacheLimit bounds the table: short-lived flows (one DNS query
// per source port) would otherwise accumulate. Reaching it starts over, which
// costs each live flow one lookup.
const udpAssignmentCacheLimit = 4096

// get returns the assignment for key. On a miss it calls lookup and keeps
// the result under generation, which the caller must have read before
// calling. owner identifies the backend; a different one discards everything.
func (c *udpAssignmentCache) get(
	owner any,
	key udpAssignmentCacheKey,
	generation uint64,
	lookup func() (commonEBPF.TCAssignment, error),
) (commonEBPF.TCAssignment, error) {
	c.access.Lock()
	if c.owner == owner {
		if entry, loaded := c.entries[key]; loaded && entry.generation == generation {
			c.access.Unlock()
			return entry.assignment, nil
		}
	}
	c.access.Unlock()
	assignment, err := lookup()
	if err != nil {
		return assignment, err
	}
	c.access.Lock()
	if c.owner != owner || c.entries == nil || len(c.entries) >= udpAssignmentCacheLimit {
		c.owner = owner
		c.entries = make(map[udpAssignmentCacheKey]udpAssignmentCacheEntry)
	}
	c.entries[key] = udpAssignmentCacheEntry{assignment: assignment, generation: generation}
	c.access.Unlock()
	return assignment, nil
}

// cachedUDPAssignment is lookupUDPAssignment behind udpAssignCache.
func (i *Inbound) cachedUDPAssignment(backend *commonEBPF.TCBackend, client, destination netip.AddrPort, interfaceIndex uint32) (commonEBPF.TCAssignment, error) {
	generation, cacheable := backend.AssignmentGeneration()
	if !cacheable {
		return i.lookupUDPAssignment(backend, client, destination, interfaceIndex)
	}
	key := udpAssignmentCacheKey{client: client, destination: destination, interfaceIndex: interfaceIndex}
	return i.udpAssignCache.get(backend, key, generation, func() (commonEBPF.TCAssignment, error) {
		return i.lookupUDPAssignment(backend, client, destination, interfaceIndex)
	})
}
