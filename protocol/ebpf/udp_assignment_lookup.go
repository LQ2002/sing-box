//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"sync"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

// lookupUDPAssignment finds the TC assignment for an uplink UDP datagram.
//
// The TC program keys UDP assignments with the packet's interface index only
// on the shared path (hotspot clients); local apps' flows are keyed with 0
// (sing-ebpf native/tc.bpf.c: assignment_key.interface_index = skb->ifindex
// only when path == SB_TC_PATH_SHARED). newTCPacket used to look up with the
// received interface index first and retry with 0, so every uplink datagram
// of a local app cost a failed bpf(2) lookup before the one that hits. On the
// daily phone (2026-10-07) a Google Photos upload over QUIC (SS2022 UDP)
// made ~2 bpf calls per datagram (997,033 for 493,033 writes), and during an
// HTTP/3 download 2138 of 4284 sing-box bpf calls returned -ENOENT.
//
// The order is remembered per client address: a client whose assignment was
// found under 0 is looked up under 0 first from then on, and the other way
// round. Results are the same as before: a client address is either a local
// one (keys with 0) or a hotspot client (keys with the interface index),
// never both, so whichever key exists is the one the old order found.
func (i *Inbound) lookupUDPAssignment(backend *commonEBPF.TCBackend, client, destination netip.AddrPort, interfaceIndex uint32) (commonEBPF.TCAssignment, error) {
	return lookupUDPAssignmentOrdered(&i.udpAssignZeroFirst, backend.LookupAssignment, client, destination, interfaceIndex)
}

type udpAssignmentLookupFunc func(protocol uint8, source, destination netip.AddrPort, interfaceIndex uint32, remove bool) (commonEBPF.TCAssignment, error)

func lookupUDPAssignmentOrdered(zeroFirst *sync.Map, lookup udpAssignmentLookupFunc, client, destination netip.AddrPort, interfaceIndex uint32) (commonEBPF.TCAssignment, error) {
	if interfaceIndex == 0 {
		return lookup(commonEBPF.ProtocolUDP, client, destination, 0, false)
	}
	first, second := interfaceIndex, uint32(0)
	if _, preferZero := zeroFirst.Load(client.Addr()); preferZero {
		first, second = 0, interfaceIndex
	}
	assignment, firstErr := lookup(commonEBPF.ProtocolUDP, client, destination, first, false)
	if firstErr == nil {
		return assignment, nil
	}
	assignment, secondErr := lookup(commonEBPF.ProtocolUDP, client, destination, second, false)
	if secondErr != nil {
		// As before, report the failure of the interface-index-0 lookup.
		if first == 0 {
			return assignment, firstErr
		}
		return assignment, secondErr
	}
	if second == 0 {
		zeroFirst.Store(client.Addr(), struct{}{})
	} else {
		zeroFirst.Delete(client.Addr())
	}
	return assignment, nil
}
