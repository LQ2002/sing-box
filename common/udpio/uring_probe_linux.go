//go:build linux

package udpio

import "sync"

// io_uring is probed once per process with the listener reader's own setup
// (ring, mmaps, PBUF_RING registration): when the kernel lacks it, has it
// disabled (io_uring_disabled) or the process may not use it, the io_uring
// reader and writer constructors return nil and the recvmmsg reader and
// sendmmsg writer are used from the start.
var uringProbe struct {
	once sync.Once
	ok   bool
}

// uringSetupFault makes every io_uring setup fail (tests only).
var uringSetupFault error

func uringAvailable() bool {
	uringProbe.once.Do(func() {
		probe := &uringOOBReadWaiter{ringFD: -1, oobSize: 64}
		uringProbe.ok = probe.setup() == nil
		probe.release()
	})
	return uringProbe.ok
}
