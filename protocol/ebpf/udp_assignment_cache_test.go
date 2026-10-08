//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net/netip"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

func TestUDPAssignmentCache(t *testing.T) {
	var cache udpAssignmentCache
	owner := new(int)
	key := udpAssignmentCacheKey{
		client:         netip.MustParseAddrPort("10.0.0.2:40000"),
		destination:    netip.MustParseAddrPort("1.2.3.4:443"),
		interfaceIndex: 7,
	}
	lookups := 0
	cookie := uint64(100)
	lookup := func() (commonEBPF.TCAssignment, error) {
		lookups++
		return commonEBPF.TCAssignment{SocketCookie: cookie}, nil
	}
	get := func(owner any, key udpAssignmentCacheKey, generation uint64) uint64 {
		t.Helper()
		assignment, err := cache.get(owner, key, generation, lookup)
		if err != nil {
			t.Fatal(err)
		}
		return assignment.SocketCookie
	}

	// First datagram looks up; further ones at the same generation do not.
	if get(owner, key, 5) != 100 || lookups != 1 {
		t.Fatalf("first: lookups %d", lookups)
	}
	for range 3 {
		if get(owner, key, 5) != 100 {
			t.Fatal("cached value changed")
		}
	}
	if lookups != 1 {
		t.Fatalf("steady datagrams looked up %d times", lookups-1)
	}

	// Any write moves the generation: the next datagram sees the new value
	// (here a new socket on the same five-tuple).
	cookie = 200
	if get(owner, key, 6) != 200 || lookups != 2 {
		t.Fatalf("after a generation change: lookups %d", lookups)
	}

	// Another flow is cached on its own.
	other := key
	other.client = netip.MustParseAddrPort("10.0.0.2:40001")
	if get(owner, other, 6) != 200 || lookups != 3 {
		t.Fatalf("other flow: lookups %d", lookups)
	}
	if get(owner, key, 6) != 200 || lookups != 3 {
		t.Fatal("first flow lost its entry")
	}

	// A failed lookup is reported and not cached.
	failure := errors.New("ENOENT")
	missing := key
	missing.interfaceIndex = 8
	for range 2 {
		if _, err := cache.get(owner, missing, 6, func() (commonEBPF.TCAssignment, error) {
			lookups++
			return commonEBPF.TCAssignment{}, failure
		}); !errors.Is(err, failure) {
			t.Fatalf("error %v", err)
		}
	}
	if lookups != 5 {
		t.Fatalf("failed lookups: %d", lookups)
	}

	// A different backend never sees the old backend's entries.
	if get(new(int), key, 6) != 200 || lookups != 6 {
		t.Fatalf("new owner: lookups %d", lookups)
	}

	// The table starts over at its limit instead of growing.
	for index := range udpAssignmentCacheLimit + 10 {
		flow := key
		flow.client = netip.AddrPortFrom(key.client.Addr(), uint16(index))
		get(owner, flow, 9)
	}
	if len(cache.entries) > udpAssignmentCacheLimit {
		t.Fatalf("cache grew to %d", len(cache.entries))
	}
}
