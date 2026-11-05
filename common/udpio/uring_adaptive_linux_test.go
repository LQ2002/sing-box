package udpio

import (
	"testing"
	"time"
)

// A reader that went active must leave the timed wait after uringActiveWait
// (ETIME) and still deliver a datagram that arrives during the untimed wait.
func TestUringOOBAdaptiveWait(t *testing.T) {
	saved := udpIOUringAdaptive
	udpIOUringAdaptive = true
	defer func() { udpIOUringAdaptive = saved }()

	receiver, sender, reader := newUringOOBTestReader(t)
	defer sender.Close()
	defer receiver.Close()
	send := func() {
		if _, err := sender.WriteTo([]byte("x"), receiver.LocalAddr()); err != nil {
			t.Error(err)
		}
	}
	send()
	if _, _, _, err := reader.WaitReadOOBPackets(); err != nil {
		t.Fatal(err)
	}
	if !reader.adaptive {
		t.Skip("kernel lacks EXT_ARG or NO_IOWAIT")
	}
	if !reader.active {
		t.Fatal("reader not active after a completion")
	}
	timer := time.AfterFunc(uringActiveWait+300*time.Millisecond, send)
	defer timer.Stop()
	start := time.Now()
	if _, _, _, err := reader.WaitReadOOBPackets(); err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(start); waited < uringActiveWait {
		t.Fatalf("returned after %s, before the datagram was sent", waited)
	}
	if !reader.active {
		t.Fatal("reader not active after the second completion")
	}
}
