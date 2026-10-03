//go:build linux

package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"unsafe"
)

const (
	identityRegistered = 1
	packetTCPSYN       = 1 << 3
	packetUDP          = 1 << 4
)

type registration struct {
	TokenLo, TokenHi, Generation uint64
	TGID, UID                    uint32
}

type identity struct {
	Cookie, TokenLo, TokenHi, StartNS, ObservedNS, Generation uint64
	TGID, TID, UID                                            uint32
	Family, Flags                                             uint16
}

type observation struct {
	Identity             identity
	FirstNS, PacketCount uint64
	PacketFlags, Ifindex uint32
}

var _ [32]byte = [unsafe.Sizeof(registration{})]byte{}
var _ [64]byte = [unsafe.Sizeof(identity{})]byte{}
var _ [88]byte = [unsafe.Sizeof(observation{})]byte{}

func newRegistration(pid, uid uint32, generation uint64) (registration, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return registration{}, err
	}
	r := registration{TokenLo: binary.LittleEndian.Uint64(random[:8]), TokenHi: binary.LittleEndian.Uint64(random[8:]), Generation: generation, TGID: pid, UID: uid}
	if r.TokenLo == 0 && r.TokenHi == 0 {
		return registration{}, fmt.Errorf("random token was zero")
	}
	return r, nil
}

type expectedIdentity struct {
	Registration   registration
	Cookie         uint64
	TGID, TID, UID uint32
	StartTicks     uint64
	Family         uint16
	Registered     bool
}

func validateIdentity(got identity, want expectedIdentity) error {
	if got.Cookie != want.Cookie || got.TGID != want.TGID || got.TID != want.TID || got.UID != want.UID || got.Family != want.Family {
		return fmt.Errorf("creator mismatch: got %+v, want %+v", got, want)
	}
	if got.StartNS == 0 || got.StartNS/10_000_000 != want.StartTicks || got.ObservedNS == 0 {
		return fmt.Errorf("missing or wrong creator birth/observation time: %+v", got)
	}
	if want.Registered {
		if got.Flags&identityRegistered == 0 || got.TokenLo != want.Registration.TokenLo || got.TokenHi != want.Registration.TokenHi || got.Generation != want.Registration.Generation {
			return fmt.Errorf("registered token mismatch: got %+v, want %+v", got, want.Registration)
		}
	} else if got.Flags&identityRegistered != 0 || got.TokenLo != 0 || got.TokenHi != 0 || got.Generation != 0 {
		return fmt.Errorf("unregistered socket acquired a token: %+v", got)
	}
	return nil
}

func validateObservation(got observation, want expectedIdentity, packetFlag, ifindex uint32) error {
	if err := validateIdentity(got.Identity, want); err != nil {
		return err
	}
	if got.PacketCount == 0 || got.FirstNS < got.Identity.ObservedNS || got.PacketFlags&packetFlag == 0 || got.Ifindex != ifindex {
		return fmt.Errorf("first packet evidence mismatch: %+v", got)
	}
	ipFlags := got.PacketFlags & 3
	if (want.Family == 2 && ipFlags != 1) || (want.Family == 10 && ipFlags != 2) {
		return fmt.Errorf("first packet IP family mismatch: flags=%d family=%d", got.PacketFlags, want.Family)
	}
	if packetFlag == packetTCPSYN && (got.PacketFlags&(1<<2) == 0 || got.PacketFlags&(1<<5) != 0) {
		return fmt.Errorf("first TCP packet was not a client SYN: flags=%d", got.PacketFlags)
	}
	return nil
}
