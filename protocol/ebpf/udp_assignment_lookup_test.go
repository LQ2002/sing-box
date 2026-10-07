//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net/netip"
	"sync"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

// fakeAssignments serves assignments keyed by (client, interface index) and
// counts lookups, like the TC assignment map.
type fakeAssignments struct {
	entries map[netip.AddrPort]map[uint32]uint64 // client -> index -> socket cookie
	lookups int
}

var errNoAssignment = errors.New("no such key")

func (f *fakeAssignments) lookup(_ uint8, source, _ netip.AddrPort, interfaceIndex uint32, _ bool) (commonEBPF.TCAssignment, error) {
	f.lookups++
	cookie, found := f.entries[source][interfaceIndex]
	if !found {
		return commonEBPF.TCAssignment{}, errNoAssignment
	}
	return commonEBPF.TCAssignment{SocketCookie: cookie}, nil
}

func TestLookupUDPAssignmentLearnsLocalOrder(t *testing.T) {
	local := netip.MustParseAddrPort("192.168.10.156:40000")
	hotspot := netip.MustParseAddrPort("10.41.0.7:50000")
	destination := netip.MustParseAddrPort("142.250.1.1:443")
	const deliveryIndex, hotspotIndex = 1, 42
	fake := &fakeAssignments{entries: map[netip.AddrPort]map[uint32]uint64{
		local:   {0: 11},            // local app: keyed with 0
		hotspot: {hotspotIndex: 22}, // shared path: keyed with the interface
	}}
	var zeroFirst sync.Map

	// First local datagram: miss under the index, hit under 0 (old cost).
	assignment, err := lookupUDPAssignmentOrdered(&zeroFirst, fake.lookup, local, destination, deliveryIndex)
	if err != nil || assignment.SocketCookie != 11 || fake.lookups != 2 {
		t.Fatalf("first local: cookie=%d err=%v lookups=%d", assignment.SocketCookie, err, fake.lookups)
	}
	// Every later local datagram: one lookup.
	for range 100 {
		assignment, err = lookupUDPAssignmentOrdered(&zeroFirst, fake.lookup, local, destination, deliveryIndex)
		if err != nil || assignment.SocketCookie != 11 {
			t.Fatalf("local: cookie=%d err=%v", assignment.SocketCookie, err)
		}
	}
	if fake.lookups != 102 {
		t.Fatalf("local lookups = %d, want 102", fake.lookups)
	}

	// Hotspot client: found under its interface first, never learned as zero.
	before := fake.lookups
	for range 10 {
		assignment, err = lookupUDPAssignmentOrdered(&zeroFirst, fake.lookup, hotspot, destination, hotspotIndex)
		if err != nil || assignment.SocketCookie != 22 {
			t.Fatalf("hotspot: cookie=%d err=%v", assignment.SocketCookie, err)
		}
	}
	if fake.lookups-before != 10 {
		t.Fatalf("hotspot lookups = %d, want 10", fake.lookups-before)
	}
	if _, learned := zeroFirst.Load(hotspot.Addr()); learned {
		t.Fatal("hotspot client must not prefer interface 0")
	}

	// If a learned client's entry moves to the interface key, the order flips back.
	fake.entries[local] = map[uint32]uint64{deliveryIndex: 33}
	assignment, err = lookupUDPAssignmentOrdered(&zeroFirst, fake.lookup, local, destination, deliveryIndex)
	if err != nil || assignment.SocketCookie != 33 {
		t.Fatalf("moved: cookie=%d err=%v", assignment.SocketCookie, err)
	}
	if _, learned := zeroFirst.Load(local.Addr()); learned {
		t.Fatal("order did not flip back")
	}

	// Both missing: an error, as before.
	missing := netip.MustParseAddrPort("192.168.10.156:40001")
	if _, err = lookupUDPAssignmentOrdered(&zeroFirst, fake.lookup, missing, destination, deliveryIndex); !errors.Is(err, errNoAssignment) {
		t.Fatalf("missing: err=%v", err)
	}
	// Interface index 0: a single lookup under 0, as before.
	before = fake.lookups
	fake.entries[local] = map[uint32]uint64{0: 11}
	if _, err = lookupUDPAssignmentOrdered(&zeroFirst, fake.lookup, local, destination, 0); err != nil || fake.lookups-before != 1 {
		t.Fatalf("index 0: err=%v lookups=%d", err, fake.lookups-before)
	}
}
