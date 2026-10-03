// Package socketidentity maintains a persistent socket-creator BPF collector.
// Closing a Collector releases local descriptors; only Remove unpins it.
package socketidentity

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
)

const (
	DefaultPinPath = "/sys/fs/bpf/sing-box/socket-creator-v1"
	MapSymbol      = "socket_creators"
	MapName        = "sb_sk_creator"
	CreatorValid   = uint32(1)
	ValueSize      = uint32(48)

	moduleName  = "sbo_identity_bridge"
	traceName   = "sbo_identity_socket_create"
	programName = "sb_sk_create"
	abiVersion  = uint32(1)
)

var (
	ErrUnsupported = errors.New("socket creator collection requires Linux/Android arm64 little-endian")
	ErrBusy        = errors.New("socket creator collector is open; close all collectors before removing pins")
)

// Creator is the immutable creation-time snapshot shared with sing-ebpf.
// UserID is the creating task's UID; zero is a valid root UID.
type Creator struct {
	Cookie      uint64
	StartTimeNs uint64
	ProcessID   uint32
	ThreadID    uint32
	UserID      uint32
	Flags       uint32
	Comm        [16]byte
}

func (c Creator) Valid() bool {
	return c.Flags == CreatorValid && c.Cookie != 0 && c.StartTimeNs != 0 && c.ProcessID != 0 && c.ThreadID != 0
}

var _ [48]byte = [unsafe.Sizeof(Creator{})]byte{}

type Config struct {
	// PinPath is a root-owned private directory on an already mounted bpffs.
	// Empty selects DefaultPinPath. No mount or module operation is performed.
	PinPath string
}

// Collector owns userspace descriptors and a shared directory lease. Map returns
// a borrowed descriptor, valid until Close; consumers must close before it does.
type Collector struct {
	mu       sync.Mutex
	creators *ebpf.Map
	closeFDs func() error
}

func (c *Collector) Map() *ebpf.Map {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.creators
}

// Close is idempotent and never unpins objects or changes module parameters.
func (c *Collector) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closeFDs == nil {
		return nil
	}
	closeFDs := c.closeFDs
	c.closeFDs, c.creators = nil, nil
	return closeFDs()
}

// The object has BTF and CO-RE relocations and arm64 tracing conventions.
// It is deliberately not advertised as a portable producer for every kernel.
//
//go:embed bpf/creator.bpf.o
var producerObject []byte

var producerSHA = sha256.Sum256(producerObject)
var traceSHA = sha256.Sum256([]byte(moduleName + ":" + traceName))
var metadataMagic = [16]byte{'s', 'b', 'o', '.', 'c', 'r', 'e', 'a', 't', 'o', 'r', '.', 'v', '1'}

// Stored in a frozen, pinned Array map: bpffs does not support ordinary files.
type metadata struct {
	Magic       [16]byte
	Version     uint32
	ValueSize   uint32
	BootID      [16]byte
	ProducerSHA [32]byte
	TraceSHA    [32]byte
	MapID       uint32
	LinkID      uint32
	ProgramID   uint32
	ProgramTag  [8]byte
	Reserved    [4]byte
}

const metadataSize = 128

var _ [metadataSize]byte = [unsafe.Sizeof(metadata{})]byte{}

func (m metadata) validate(bootID [16]byte) error {
	switch {
	case m.Magic != metadataMagic || m.Version != abiVersion || m.ValueSize != ValueSize || m.Reserved != [4]byte{}:
		return errors.New("metadata owner or ABI mismatch")
	case m.BootID != bootID || bootID == [16]byte{}:
		return errors.New("metadata belongs to another boot")
	case m.ProducerSHA != producerSHA:
		return errors.New("producer build changed; remove the old collector using its matching binary before upgrading")
	case m.TraceSHA != traceSHA:
		return errors.New("metadata tracepoint mismatch")
	case m.MapID == 0 || m.LinkID == 0 || m.ProgramID == 0 || m.ProgramTag == [8]byte{}:
		return errors.New("metadata has incomplete kernel object identities")
	}
	return nil
}

func loadSpec() (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(producerObject))
	if err != nil {
		return nil, fmt.Errorf("read embedded socket creator BPF: %w", err)
	}
	if len(spec.Maps) != 1 || len(spec.Programs) != 1 || spec.Maps[MapSymbol] == nil || spec.Programs["capture_creator"] == nil {
		return nil, errors.New("embedded socket creator object has an unexpected collection")
	}
	m := spec.Maps[MapSymbol]
	if m.Type != ebpf.SkStorage || m.KeySize != 4 || m.ValueSize != ValueSize || m.MaxEntries != 0 || m.Flags != 1 {
		return nil, errors.New("embedded socket creator map ABI mismatch")
	}
	m.Name = MapName
	p := spec.Programs["capture_creator"]
	if p.Type != ebpf.Tracing || p.AttachType != ebpf.AttachTraceRawTp || p.AttachTo != traceName {
		return nil, errors.New("embedded socket creator attachment mismatch")
	}
	p.Name = programName
	return spec, nil
}
