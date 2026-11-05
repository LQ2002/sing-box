package udpio

import "testing"

func TestUringWaitFlags(t *testing.T) {
	saved := udpIOUringIOWait
	defer func() { udpIOUringIOWait = saved }()

	udpIOUringIOWait = false
	if got := uringWaitFlags(uringFeatNoIOWait); got != uringEnterGetEvents|uringEnterNoIOWait {
		t.Fatalf("feature present: flags %#x", got)
	}
	if got := uringWaitFlags(0); got != uringEnterGetEvents {
		t.Fatalf("feature absent (EINVAL if the flag were passed): flags %#x", got)
	}
	udpIOUringIOWait = true
	if got := uringWaitFlags(uringFeatNoIOWait); got != uringEnterGetEvents {
		t.Fatalf("switched off: flags %#x", got)
	}
}
