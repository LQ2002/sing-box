//go:build linux

package main

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestKernelABI(t *testing.T) {
	if unsafe.Sizeof(registration{}) != 32 || unsafe.Sizeof(identity{}) != 64 || unsafe.Sizeof(observation{}) != 88 {
		t.Fatal("kernel ABI size drift")
	}
	if unsafe.Offsetof(identity{}.TGID) != 48 || unsafe.Offsetof(identity{}.Family) != 60 || unsafe.Offsetof(observation{}.FirstNS) != 64 || unsafe.Offsetof(observation{}.PacketFlags) != 80 {
		t.Fatal("kernel ABI offset drift")
	}
}

func TestExpectedIdentitySnapshot(t *testing.T) {
	want := expectedIdentity{Registration: registration{TokenLo: 11, TokenHi: 22, Generation: 3}, Cookie: 4, TGID: 123, TID: 124, UID: 2000, StartTicks: 12345, Family: unix.AF_INET, Registered: true}
	good := identity{Cookie: 4, TokenLo: 11, TokenHi: 22, Generation: 3, StartNS: 123450000000, ObservedNS: 999, TGID: 123, TID: 124, UID: 2000, Family: unix.AF_INET, Flags: identityRegistered}
	if err := validateIdentity(good, want); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*identity){func(i *identity) { i.TokenLo++ }, func(i *identity) { i.Generation++ }, func(i *identity) { i.TID = i.TGID }, func(i *identity) { i.StartNS += 10_000_000 }, func(i *identity) { i.Flags = 0 }, func(i *identity) { i.Cookie++ }} {
		got := good
		mutate(&got)
		if validateIdentity(got, want) == nil {
			t.Fatalf("accepted wrong snapshot: %+v", got)
		}
	}
	want.Registered = false
	if validateIdentity(good, want) == nil {
		t.Fatal("accepted a token for unregistered task")
	}
	good.TokenLo, good.TokenHi, good.Generation, good.Flags = 0, 0, 0, 0
	if err := validateIdentity(good, want); err != nil {
		t.Fatal(err)
	}
}

func TestFirstPacketEvidence(t *testing.T) {
	want := expectedIdentity{Cookie: 1, TGID: 2, TID: 3, UID: 2000, StartTicks: 4, Family: unix.AF_INET}
	good := observation{Identity: identity{Cookie: 1, TGID: 2, TID: 3, UID: 2000, StartNS: 40_000_000, ObservedNS: 100, Family: unix.AF_INET}, FirstNS: 101, PacketCount: 1, PacketFlags: 1 | 4 | packetTCPSYN, Ifindex: 1}
	if err := validateObservation(good, want, packetTCPSYN, 1); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*observation){func(o *observation) { o.PacketFlags |= 1 << 5 }, func(o *observation) { o.PacketFlags = 2 | 4 | packetTCPSYN }, func(o *observation) { o.FirstNS = 99 }, func(o *observation) { o.Ifindex = 2 }, func(o *observation) { o.PacketFlags = 1 | 4 }, func(o *observation) { o.PacketCount = 0 }} {
		got := good
		mutate(&got)
		if validateObservation(got, want, packetTCPSYN, 1) == nil {
			t.Fatalf("accepted invalid first packet: %+v", got)
		}
	}
}

func TestSeqpacketFDProtocol(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	want := message{Op: "hello", PID: 123, UID: 2000, StartTicks: 456}
	if err = sendMessage(pair[0], want, fd); err != nil {
		t.Fatal(err)
	}
	got, received, err := receiveMessage(pair[1])
	if err != nil {
		t.Fatal(err)
	}
	if received < 0 {
		t.Fatal("descriptor missing")
	}
	defer unix.Close(received)
	if got != want {
		t.Fatalf("message mismatch: %+v", got)
	}
	flags, err := unix.FcntlInt(uintptr(received), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("received descriptor lacks CLOEXEC: %d %v", flags, err)
	}
	if _, err = unix.SendmsgN(pair[0], []byte(`{"op":"hello","unknown":1}`), nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err = receiveMessage(pair[1]); err == nil {
		t.Fatal("accepted unknown protocol field")
	}
}

func TestOnlyLoopbackDestination(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "192.0.2.1:80", "[::1]:80"} {
		if _, err := socketAddress(unix.AF_INET, address); err == nil {
			t.Fatalf("accepted invalid IPv4 destination %q", address)
		}
	}
	if _, err := socketAddress(unix.AF_INET, "127.0.0.1:12345"); err != nil {
		t.Fatal(err)
	}
	if _, err := socketAddress(unix.AF_INET6, "[::1]:12345"); err != nil {
		t.Fatal(err)
	}
}
