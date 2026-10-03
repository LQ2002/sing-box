//go:build linux

package socketidentity

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type resources struct {
	creators *ebpf.Map
	producer *ebpf.Program
	attached link.Link
	meta     *ebpf.Map
}

func (r *resources) close() error {
	var result error
	if r.meta != nil {
		result = errors.Join(result, r.meta.Close())
	}
	if r.attached != nil {
		result = errors.Join(result, r.attached.Close())
	}
	if r.producer != nil {
		result = errors.Join(result, r.producer.Close())
	}
	if r.creators != nil {
		result = errors.Join(result, r.creators.Close())
	}
	return result
}

func readBootID() ([16]byte, error) {
	var id [16]byte
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return id, err
	}
	value := strings.TrimSpace(string(data))
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return id, errors.New("invalid kernel boot ID")
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(decoded) != len(id) {
		return id, errors.New("invalid kernel boot ID")
	}
	copy(id[:], decoded)
	if id == [16]byte{} {
		return id, errors.New("zero kernel boot ID")
	}
	return id, nil
}

func checkBridge() error {
	data, err := os.ReadFile("/sys/module/" + moduleName + "/parameters/capture_all")
	if err != nil {
		return fmt.Errorf("socket creator bridge must already be loaded with capture_all=1: %w", err)
	}
	value := strings.TrimSpace(string(data))
	if value != "Y" && value != "1" {
		return errors.New("socket creator bridge capture_all must be 1; collector does not change module parameters")
	}
	if _, err := os.Stat("/sys/kernel/btf/" + moduleName); err != nil {
		return fmt.Errorf("socket creator bridge module BTF is unavailable: %w", err)
	}
	return nil
}

// checkLegacyCollector refuses to start next to a v1 collector that still
// has pins: its producer link stays attached and keeps capturing globally.
// An absent or empty directory is fine (v1's Remove leaves the directory).
func checkLegacyCollector(path string) error {
	entries, err := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect legacy socket creator pins %s: %w", path, err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("legacy v1 socket creator pins remain in %s; remove them with the v1 build before starting v2", path)
	}
	return nil
}

// Open creates or validates and reuses a pinned map and a pinned producer link.
// It never loads a module, enables capture, mounts bpffs, or replaces partial pins.
func Open(config Config) (_ *Collector, result error) {
	if runtime.GOARCH != "arm64" {
		return nil, ErrUnsupported
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("socket creator collection requires root")
	}
	if err := checkBridge(); err != nil {
		return nil, err
	}
	if config.PinPath == "" || config.PinPath == DefaultPinPath {
		if err := checkLegacyCollector(LegacyPinPath); err != nil {
			return nil, err
		}
	}
	bootID, err := readBootID()
	if err != nil {
		return nil, err
	}
	directory, err := openPinDirectory(config.PinPath, true)
	if err != nil {
		return nil, err
	}
	var opened *resources
	created := false
	ok := false
	defer func() {
		if !ok {
			if created {
				result = errors.Join(result, rollbackPins([]string{directory.objectPath(mapPin), directory.objectPath(linkPin), directory.objectPath(metadataPin)}, os.Remove))
			}
			if opened != nil {
				result = errors.Join(result, opened.close())
			}
			result = errors.Join(result, directory.Close())
		}
	}()
	exclusive, err := acquireOpenLease(directory.file)
	if err != nil {
		return nil, fmt.Errorf("lock collector %s: %w", directory.path, err)
	}
	empty, err := directory.empty()
	if err != nil {
		return nil, fmt.Errorf("inspect collector %s: %w", directory.path, err)
	}
	if empty {
		if !exclusive {
			return nil, fmt.Errorf("collector %s initialization changed; retry Open: %w", directory.path, ErrBusy)
		}
		opened, err = createResources(directory, bootID)
		created = err == nil
	} else {
		opened, err = loadResources(directory, bootID)
	}
	if err != nil {
		return nil, fmt.Errorf("open collector %s: %w", directory.path, err)
	}
	if exclusive {
		if err := unix.Flock(int(directory.file.Fd()), unix.LOCK_SH); err != nil {
			return nil, fmt.Errorf("retain shared collector lease: %w", err)
		}
	}
	ok = true
	return &Collector{creators: opened.creators, closeFDs: func() error {
		return errors.Join(opened.close(), directory.Close())
	}}, nil
}

// Remove validates and unpins this build's complete collector. Active Collector
// leases make it return ErrBusy. It leaves the directory and module unchanged.
// Unknown, incompatible, or partial pins are never deleted automatically.
func Remove(pinPath string) (result error) {
	if os.Geteuid() != 0 {
		return errors.New("removing socket creator pins requires root")
	}
	directory, err := openPinDirectory(pinPath, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, directory.Close()) }()
	if err := acquireRemoveLease(directory.file); err != nil {
		return fmt.Errorf("remove collector %s: %w", directory.path, err)
	}
	empty, err := directory.empty()
	if err != nil || empty {
		return err
	}
	bootID, err := readBootID()
	if err != nil {
		return err
	}
	opened, err := loadResources(directory, bootID)
	if err != nil {
		return fmt.Errorf("refusing to remove unverified collector %s: %w", directory.path, err)
	}
	defer func() { result = errors.Join(result, opened.close()) }()
	// Validate the complete set before the first mutation. Unpin the producer
	// first; held FDs keep this exact object set alive until the operation ends.
	return removeOwnedPins([]pinRemoval{
		{linkPin, opened.attached.Unpin, func() error { return opened.attached.Pin(directory.objectPath(linkPin)) }},
		{mapPin, opened.creators.Unpin, func() error { return opened.creators.Pin(directory.objectPath(mapPin)) }},
		{metadataPin, opened.meta.Unpin, func() error { return opened.meta.Pin(directory.objectPath(metadataPin)) }},
	})
}

func createResources(directory *pinDirectory, bootID [16]byte) (_ *resources, result error) {
	r := new(resources)
	ok := false
	var pinned []string
	defer func() {
		if !ok {
			result = errors.Join(result, rollbackPins(pinned, os.Remove), r.close())
		}
	}()
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	var objects struct {
		Creators *ebpf.Map     `ebpf:"socket_creators"`
		Producer *ebpf.Program `ebpf:"capture_creator"`
	}
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return nil, fmt.Errorf("load socket creator BPF: %w", err)
	}
	r.creators, r.producer = objects.Creators, objects.Producer
	r.attached, err = link.AttachTracing(link.TracingOptions{Program: r.producer, AttachType: ebpf.AttachTraceRawTp})
	if err != nil {
		return nil, fmt.Errorf("attach socket creator typed tracepoint: %w", err)
	}
	actual, err := inspectResources(r)
	if err != nil {
		return nil, err
	}
	meta := metadata{
		Magic: metadataMagic, Version: abiVersion, ValueSize: ValueSize,
		BootID: bootID, ProducerSHA: producerSHA, TraceSHA: traceSHA,
		MapID: actual.MapID, LinkID: actual.LinkID, ProgramID: actual.ProgramID, ProgramTag: actual.ProgramTag,
	}
	if err := meta.validate(bootID); err != nil {
		return nil, err
	}
	if err := validateKernelObjects(meta, actual); err != nil {
		return nil, err
	}
	r.meta, err = ebpf.NewMap(&ebpf.MapSpec{Name: "sb_creator_meta", Type: ebpf.Array, KeySize: 4, ValueSize: metadataSize, MaxEntries: 1})
	if err != nil {
		return nil, err
	}
	zero := uint32(0)
	if err := r.meta.Update(&zero, &meta, ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err := r.meta.Freeze(); err != nil {
		return nil, fmt.Errorf("freeze creator metadata: %w", err)
	}
	if err := checkBridge(); err != nil {
		return nil, err
	}
	for _, object := range []struct {
		name string
		pin  func(string) error
	}{{mapPin, r.creators.Pin}, {linkPin, r.attached.Pin}, {metadataPin, r.meta.Pin}} {
		path := directory.objectPath(object.name)
		if err := object.pin(path); err != nil {
			return nil, fmt.Errorf("pin %s: %w", object.name, err)
		}
		pinned = append(pinned, path)
		if err := os.Chmod(path, 0600); err != nil {
			return nil, fmt.Errorf("protect pin %s: %w", object.name, err)
		}
	}
	ok = true
	return r, nil
}

func loadResources(directory *pinDirectory, bootID [16]byte) (_ *resources, result error) {
	r := new(resources)
	ok := false
	defer func() {
		if !ok {
			result = errors.Join(result, r.close())
		}
	}()
	var err error
	r.meta, err = ebpf.LoadPinnedMap(directory.objectPath(metadataPin), nil)
	if err != nil {
		return nil, err
	}
	info, err := r.meta.Info()
	if err != nil {
		return nil, err
	}
	if info.Type != ebpf.Array || info.KeySize != 4 || info.ValueSize != metadataSize || info.MaxEntries != 1 || info.Flags != 0 || info.Name != "sb_creator_meta" || !info.Frozen() {
		return nil, errors.New("metadata pin has an unexpected map shape or owner")
	}
	var meta metadata
	zero := uint32(0)
	if err := r.meta.Lookup(&zero, &meta); err != nil {
		return nil, err
	}
	if err := meta.validate(bootID); err != nil {
		return nil, err
	}
	r.creators, err = ebpf.LoadPinnedMap(directory.objectPath(mapPin), nil)
	if err != nil {
		return nil, err
	}
	r.attached, err = link.LoadPinnedLink(directory.objectPath(linkPin), nil)
	if err != nil {
		return nil, err
	}
	linkInfo, err := r.attached.Info()
	if err != nil {
		return nil, err
	}
	if uint32(linkInfo.ID) != meta.LinkID || uint32(linkInfo.Program) != meta.ProgramID {
		return nil, errors.New("pinned producer link identity differs from metadata")
	}
	r.producer, err = ebpf.NewProgramFromID(linkInfo.Program)
	if err != nil {
		return nil, err
	}
	actual, err := inspectResources(r)
	if err != nil {
		return nil, err
	}
	if err := validateKernelObjects(meta, actual); err != nil {
		return nil, err
	}
	ok = true
	return r, nil
}

type kernelObjects struct {
	MapID, LinkID, ProgramID uint32
	MapType                  ebpf.MapType
	KeySize, ValueSize       uint32
	MaxEntries, MapFlags     uint32
	MapName                  string
	ProgramType              ebpf.ProgramType
	ProgramName              string
	ProgramTag               [8]byte
	ProgramRootOwned         bool
	ProgramHasBTF            bool
	ReferencedMaps           []uint32
	TraceTarget              string
}

func validateKernelObjects(meta metadata, actual kernelObjects) error {
	if actual.MapType != ebpf.SkStorage || actual.KeySize != 4 || actual.ValueSize != ValueSize || actual.MaxEntries != 0 || actual.MapFlags != 1 || actual.MapName != MapName {
		return errors.New("pinned creator map ABI or owner mismatch")
	}
	if actual.MapID != meta.MapID || actual.LinkID != meta.LinkID || actual.ProgramID != meta.ProgramID {
		return errors.New("pinned kernel object IDs differ from metadata")
	}
	if actual.ProgramType != ebpf.Tracing || actual.ProgramName != programName || actual.ProgramTag != meta.ProgramTag || !actual.ProgramRootOwned || !actual.ProgramHasBTF {
		return errors.New("pinned producer program identity mismatch")
	}
	if len(actual.ReferencedMaps) != 1 || actual.ReferencedMaps[0] != meta.MapID {
		return errors.New("pinned producer does not reference exactly the pinned creator map")
	}
	if actual.TraceTarget != traceName {
		return errors.New("pinned producer is attached to a different tracepoint")
	}
	return nil
}

func inspectResources(r *resources) (kernelObjects, error) {
	var actual kernelObjects
	mapInfo, err := r.creators.Info()
	if err != nil {
		return actual, err
	}
	mapID, present := mapInfo.ID()
	if !present || mapID == 0 {
		return actual, errors.New("kernel did not report the creator map ID")
	}
	actual.MapID = uint32(mapID)
	actual.MapType, actual.MapName = mapInfo.Type, mapInfo.Name
	actual.KeySize, actual.ValueSize = mapInfo.KeySize, mapInfo.ValueSize
	actual.MaxEntries, actual.MapFlags = mapInfo.MaxEntries, mapInfo.Flags
	programInfo, err := r.producer.Info()
	if err != nil {
		return actual, err
	}
	programID, present := programInfo.ID()
	if !present || programID == 0 {
		return actual, errors.New("kernel did not report the creator program ID")
	}
	actual.ProgramID = uint32(programID)
	actual.ProgramType, actual.ProgramName = programInfo.Type, programInfo.Name
	uid, present := programInfo.CreatedByUID()
	actual.ProgramRootOwned = present && uid == 0
	_, actual.ProgramHasBTF = programInfo.BTFID()
	decodedTag, err := hex.DecodeString(programInfo.Tag)
	if err != nil || len(decodedTag) != len(actual.ProgramTag) {
		return actual, errors.New("kernel did not report a valid producer tag")
	}
	copy(actual.ProgramTag[:], decodedTag)
	mapIDs, present := programInfo.MapIDs()
	if !present {
		return actual, errors.New("kernel did not report producer map references")
	}
	for _, id := range mapIDs {
		actual.ReferencedMaps = append(actual.ReferencedMaps, uint32(id))
	}
	linkInfo, err := r.attached.Info()
	if err != nil {
		return actual, err
	}
	actual.LinkID = uint32(linkInfo.ID)
	if linkInfo.Program != programID {
		return actual, errors.New("producer link points to a different program")
	}
	if raw := linkInfo.RawTracepoint(); raw != nil {
		actual.TraceTarget = raw.Name
	} else if tracing := linkInfo.Tracing(); tracing != nil {
		if uint32(tracing.AttachType) != uint32(ebpf.AttachTraceRawTp) {
			return actual, errors.New("producer link has an unexpected tracing attachment")
		}
		handle, err := btf.NewHandleFromID(btf.ID(tracing.TargetObjectId))
		if err != nil {
			return actual, err
		}
		defer handle.Close()
		info, err := handle.Info()
		if err != nil || !info.IsKernel || info.Name != moduleName {
			return actual, errors.New("producer link targets a different module BTF")
		}
		base, err := btf.LoadKernelSpec()
		if err != nil {
			return actual, err
		}
		spec, err := handle.Spec(base)
		if err != nil {
			return actual, err
		}
		typ, err := spec.TypeByID(btf.TypeID(tracing.TargetBtfId))
		if err != nil || typ.TypeName() != "btf_trace_"+traceName {
			return actual, errors.New("producer link targets a different module tracepoint type")
		}
		actual.TraceTarget = traceName
	} else {
		return actual, errors.New("kernel did not report the producer tracepoint target")
	}
	return actual, nil
}
