// Package socketidentity maintains a persistent socket-creator BPF collector.
// Closing a Collector releases local descriptors; only Remove unpins it.
//
// The producer has two sources (Source). SourceLSM attaches to BPF LSM
// socket_post_create and needs no kernel module, only a kernel that runs BPF
// trampolines with "bpf" in its LSM list. SourceModule attaches to the
// tracepoint of the sbo_identity module (kernel/sbo_identity), for kernels
// without trampolines such as the stock Android 16 6.12 GKI. Both write the
// same snapshots and path entries.
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
	DefaultPinPath = "/sys/fs/bpf/sing-box/socket-creator-v4"
	MapSymbol      = "socket_creators"
	MapName        = "sb_sk_creator"
	ValueSize      = uint32(64)
	// PathMapSymbol holds each executable's path once, keyed by ExeKey; a
	// snapshot with CreatorExeKey carries that key in ExeInode.
	PathMapSymbol    = "exe_paths"
	PathMapName      = "sb_sk_exe_path"
	PathValueSize    = uint32(280)
	PathMapEntries   = uint32(1024)
	scratchMapSymbol = "exe_path_scratch"
	scratchMapName   = "sb_sk_exe_tmp"

	// Flag bits, shared with sing-ebpf's SocketCreator* constants and
	// bpf/creator.bpf.c.
	CreatorValid         = uint32(1 << 0)
	CreatorNameValid     = uint32(1 << 1)
	CreatorExeValid      = uint32(1 << 2)
	CreatorNameTruncated = uint32(1 << 3)
	// Set by the v3 and v4 producers. CreatorExeKey: ExeInode is the
	// key of the creator's executable in the path map (ExeKey), whose path
	// was resolved in the kernel at creation. CreatorPathTooLong: the path
	// did not fit 256 bytes and was not stored. CreatorExeDeleted: the
	// executable had been unlinked. CreatorKernel: no mm (kernel thread).
	CreatorExeKey      = uint32(1 << 4)
	CreatorPathTooLong = uint32(1 << 5)
	CreatorExeDeleted  = uint32(1 << 6)
	CreatorKernel      = uint32(1 << 7)
	nameLengthShift    = 8
	knownFlags         = CreatorValid | CreatorNameValid | CreatorExeValid | CreatorNameTruncated |
		CreatorExeKey | CreatorPathTooLong | CreatorExeDeleted | CreatorKernel | 0xff<<nameLengthShift

	moduleName  = "sbo_identity"
	traceName   = "sbo_identity_socket"
	programName = "sb_sk_create"
	// lsmHook is the LSM hook of SourceLSM; the kernel names its attach
	// target bpf_lsm_<hook> (lsmTarget).
	lsmHook    = "socket_post_create"
	lsmTarget  = "bpf_lsm_" + lsmHook
	abiVersion = uint32(4)
)

// Source is the kernel hook a collector's producer is attached to.
type Source string

const (
	// SourceLSM: BPF LSM socket_post_create, no kernel module.
	SourceLSM Source = "lsm"
	// SourceModule: tp_btf on the sbo_identity module's tracepoint.
	SourceModule Source = "module"
)

// LegacyPinPaths are where earlier collectors pinned themselves (v1: 48-byte
// snapshots; v2: bridge-module producer; v3: sbo_identity module producer
// only, before the LSM source). Their producer links keep capturing
// after sing-box exits, so a collector at the default path refuses to start
// while their pins remain: two global producers would double the per-socket
// cost and the old one would never be cleaned up. Remove them with the
// matching old binary's maintenance command.
var LegacyPinPaths = []string{
	"/sys/fs/bpf/sing-box/socket-creator-v1",
	"/sys/fs/bpf/sing-box/socket-creator-v2",
	"/sys/fs/bpf/sing-box/socket-creator-v3",
}

var (
	ErrUnsupported = errors.New("socket creator collection requires Linux/Android arm64 little-endian")
	ErrBusy        = errors.New("socket creator collector is open; close all collectors before removing pins")
)

// Creator is the immutable creation-time snapshot shared with sing-ebpf.
// UserID is the creating task's UID; zero is a valid root UID.
//
// ProcessNameHash is FNV-1a 64 over argv[0] at creation (the ActivityManager
// process record name for zygote children), covering NameLength bytes; with
// CreatorNameTruncated those bytes may be a prefix of the real name. ExeInode
// is the inode of the creating process's executable.
type Creator struct {
	Cookie          uint64
	StartTimeNs     uint64
	ProcessID       uint32
	ThreadID        uint32
	UserID          uint32
	Flags           uint32
	Comm            [16]byte
	ProcessNameHash uint64
	ExeInode        uint64
}

// Valid requires the complete identity and rejects flag bits this build
// does not define, so a value from an unknown producer is never trusted.
func (c Creator) Valid() bool {
	return c.Flags&CreatorValid != 0 && c.Flags&^knownFlags == 0 &&
		c.Cookie != 0 && c.StartTimeNs != 0 && c.ProcessID != 0 && c.ThreadID != 0
}

// NameLength is the number of argv[0] bytes covered by ProcessNameHash.
func (c Creator) NameLength() int {
	return int(c.Flags >> nameLengthShift & 0xff)
}

// PathValue mirrors struct exe_path in bpf/creator_common.h: one executable,
// resolved in the kernel (d_path) when one of its sockets was made.
type PathValue struct {
	Dev        uint32
	Generation uint32
	Inode      uint64
	Length     uint32
	Flags      uint32 // CreatorExeDeleted
	Path       [256]byte
}

var _ [280]byte = [unsafe.Sizeof(PathValue{})]byte{}

// String returns the stored path.
func (v PathValue) String() string {
	n := int(v.Length)
	if n > len(v.Path) {
		n = len(v.Path)
	}
	if i := bytes.IndexByte(v.Path[:n], 0); i >= 0 {
		n = i
	}
	return string(v.Path[:n])
}

// ExeKey is the path map key of an executable: FNV-1a 64 over dev and
// generation (one little-endian u64, dev in the low half) followed by the
// inode (little-endian u64). bpf/creator_common.h exe_key computes the same.
func ExeKey(dev, generation uint32, inode uint64) uint64 {
	hash := uint64(0xcbf29ce484222325)
	for _, word := range [2]uint64{uint64(dev) | uint64(generation)<<32, inode} {
		for b := 0; b < 8; b++ {
			hash ^= word >> (8 * b) & 0xff
			hash *= 0x100000001b3
		}
	}
	return hash
}

var _ [64]byte = [unsafe.Sizeof(Creator{})]byte{}

type Config struct {
	// PinPath is a root-owned private directory on an already mounted bpffs.
	// Empty selects DefaultPinPath. No mount or module operation is performed.
	PinPath string
}

// Collector owns userspace descriptors and a shared directory lease. Map returns
// a borrowed descriptor, valid until Close; consumers must close before it does.
type Collector struct {
	mu       sync.Mutex
	source   Source
	skipped  error
	creators *ebpf.Map
	paths    *ebpf.Map
	closeFDs func() error
}

// Source reports which kernel hook the producer is attached to.
func (c *Collector) Source() Source {
	return c.source
}

// SkippedSources tells why sources preferred over Source were not used when
// this collector was created (for example "lsm source: ... not supported" on
// a kernel without BPF trampolines). nil when the first source was used or
// the collector was reopened from pins.
func (c *Collector) SkippedSources() error {
	return c.skipped
}

func (c *Collector) Map() *ebpf.Map {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.creators
}

// LookupPath returns the executable path stored under key (a snapshot's
// ExeInode when it has CreatorExeKey). false if absent (evicted, or never
// stored because it was too long) or the collector is closed.
func (c *Collector) LookupPath(key uint64) (PathValue, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var value PathValue
	if c.paths == nil || c.paths.Lookup(&key, &value) != nil {
		return PathValue{}, false
	}
	return value, true
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
	c.closeFDs, c.creators, c.paths = nil, nil, nil
	return closeFDs()
}

// The objects have BTF and CO-RE relocations and arm64 tracing conventions.
// They are deliberately not advertised as portable producers for every kernel.
//
//go:embed bpf/creator.bpf.o
var moduleProducerObject []byte

//go:embed bpf/creator_lsm.bpf.o
var lsmProducerObject []byte

// producerSource is everything that differs between the two producers.
// target is stored in metadata (TraceSHA) and selects the source again when
// pins are reopened; sha pins the exact embedded object.
type producerSource struct {
	source      Source
	object      []byte
	sha         [32]byte
	target      [32]byte
	programType ebpf.ProgramType
	attachType  ebpf.AttachType
	attachTo    string
	// traceTarget is what inspectResources reports for a correct link.
	traceTarget string
}

var (
	lsmSource = &producerSource{
		source: SourceLSM, object: lsmProducerObject, sha: sha256.Sum256(lsmProducerObject),
		target:      sha256.Sum256([]byte("lsm:" + lsmHook)),
		programType: ebpf.LSM, attachType: ebpf.AttachLSMMac, attachTo: lsmHook,
		traceTarget: lsmTarget,
	}
	moduleSource = &producerSource{
		source: SourceModule, object: moduleProducerObject, sha: sha256.Sum256(moduleProducerObject),
		// Unchanged from v3, which had only this source.
		target:      sha256.Sum256([]byte(moduleName + ":" + traceName)),
		programType: ebpf.Tracing, attachType: ebpf.AttachTraceRawTp, attachTo: traceName,
		traceTarget: traceName,
	}
	// producerSources is the order Open tries when it creates a collector:
	// the LSM needs no module; the module is the fallback.
	producerSources = []*producerSource{lsmSource, moduleSource}
)

var metadataMagic = [16]byte{'s', 'b', 'o', '.', 'c', 'r', 'e', 'a', 't', 'o', 'r', '.', 'v', '4'}

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
	PathMapID   uint32
}

const metadataSize = 128

var _ [metadataSize]byte = [unsafe.Sizeof(metadata{})]byte{}

// validate checks the metadata against this build and returns the source it
// was created with.
func (m metadata) validate(bootID [16]byte) (*producerSource, error) {
	var source *producerSource
	for _, candidate := range producerSources {
		if m.TraceSHA == candidate.target {
			source = candidate
		}
	}
	switch {
	case m.Magic != metadataMagic || m.Version != abiVersion || m.ValueSize != ValueSize:
		return nil, errors.New("metadata owner or ABI mismatch")
	case m.BootID != bootID || bootID == [16]byte{}:
		return nil, errors.New("metadata belongs to another boot")
	case source == nil:
		return nil, errors.New("metadata names an unknown producer source")
	case m.ProducerSHA != source.sha:
		return nil, errors.New("producer build changed; remove the old collector using its matching binary before upgrading")
	case m.MapID == 0 || m.PathMapID == 0 || m.LinkID == 0 || m.ProgramID == 0 || m.ProgramTag == [8]byte{}:
		return nil, errors.New("metadata has incomplete kernel object identities")
	}
	return source, nil
}

func loadSpec(source *producerSource) (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(source.object))
	if err != nil {
		return nil, fmt.Errorf("read embedded socket creator BPF: %w", err)
	}
	if len(spec.Maps) != 3 || len(spec.Programs) != 1 || spec.Maps[MapSymbol] == nil || spec.Maps[PathMapSymbol] == nil ||
		spec.Maps[scratchMapSymbol] == nil || spec.Programs["capture_creator"] == nil {
		return nil, errors.New("embedded socket creator object has an unexpected collection")
	}
	m := spec.Maps[MapSymbol]
	if m.Type != ebpf.SkStorage || m.KeySize != 4 || m.ValueSize != ValueSize || m.MaxEntries != 0 || m.Flags != 1 {
		return nil, errors.New("embedded socket creator map ABI mismatch")
	}
	m.Name = MapName
	paths := spec.Maps[PathMapSymbol]
	if paths.Type != ebpf.LRUHash || paths.KeySize != 8 || paths.ValueSize != PathValueSize || paths.MaxEntries != PathMapEntries || paths.Flags != 0 {
		return nil, errors.New("embedded socket creator path map ABI mismatch")
	}
	paths.Name = PathMapName
	scratch := spec.Maps[scratchMapSymbol]
	if scratch.Type != ebpf.PerCPUArray || scratch.KeySize != 4 || scratch.ValueSize != PathValueSize || scratch.MaxEntries != 1 {
		return nil, errors.New("embedded socket creator scratch map ABI mismatch")
	}
	scratch.Name = scratchMapName
	p := spec.Programs["capture_creator"]
	if p.Type != source.programType || p.AttachType != source.attachType || p.AttachTo != source.attachTo {
		return nil, errors.New("embedded socket creator attachment mismatch")
	}
	p.Name = programName
	return spec, nil
}
