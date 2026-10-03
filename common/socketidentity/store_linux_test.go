//go:build linux

package socketidentity

import (
	"errors"
	"os"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestPinnedObjectsMustReferenceTheSameStorage(t *testing.T) {
	meta, _ := validMetadata()
	actual := kernelObjects{
		MapID: meta.MapID, LinkID: meta.LinkID, ProgramID: meta.ProgramID,
		MapType: ebpf.SkStorage, KeySize: 4, ValueSize: ValueSize, MapFlags: 1, MapName: MapName,
		ProgramType: ebpf.Tracing, ProgramName: programName, ProgramTag: meta.ProgramTag,
		ProgramRootOwned: true, ProgramHasBTF: true,
		ReferencedMaps: []uint32{meta.MapID}, TraceTarget: traceName,
	}
	if err := validateKernelObjects(meta, actual); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*kernelObjects){
		"different map":      func(k *kernelObjects) { k.ReferencedMaps = []uint32{meta.MapID + 1} },
		"extra map":          func(k *kernelObjects) { k.ReferencedMaps = []uint32{meta.MapID, 99} },
		"no map evidence":    func(k *kernelObjects) { k.ReferencedMaps = nil },
		"unrelated link":     func(k *kernelObjects) { k.LinkID++ },
		"unrelated map":      func(k *kernelObjects) { k.MapID++ },
		"unrelated program":  func(k *kernelObjects) { k.ProgramID++ },
		"different bytecode": func(k *kernelObjects) { k.ProgramTag[0]++ },
		"different target":   func(k *kernelObjects) { k.TraceTarget = "sched_switch" },
		"clone semantics":    func(k *kernelObjects) { k.MapFlags |= 1 << 9 },
		"foreign name":       func(k *kernelObjects) { k.MapName = "foreign" },
		"foreign creator":    func(k *kernelObjects) { k.ProgramRootOwned = false },
		"no BTF":             func(k *kernelObjects) { k.ProgramHasBTF = false },
		"wrong value ABI":    func(k *kernelObjects) { k.ValueSize++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := actual
			mutate(&changed)
			if err := validateKernelObjects(meta, changed); err == nil {
				t.Fatal("accepted a mismatched kernel object set")
			}
		})
	}
}

func TestPartialOrForeignPinsAreNotClaimed(t *testing.T) {
	if empty, err := pinSetState(nil); !empty || err != nil {
		t.Fatalf("empty directory: %t %v", empty, err)
	}
	if empty, err := pinSetState([]string{metadataPin, mapPin, linkPin}); empty || err != nil {
		t.Fatalf("complete directory: %t %v", empty, err)
	}
	for _, names := range [][]string{{mapPin}, {mapPin, linkPin}, {metadataPin}, {metadataPin, mapPin, "foreign"}, {metadataPin, mapPin, linkPin, "foreign"}} {
		if _, err := pinSetState(names); err == nil {
			t.Fatalf("claimed incomplete or foreign pins: %v", names)
		}
	}
}

func TestPinDirectoryOwnershipAndPermissions(t *testing.T) {
	valid := unix.Stat_t{Mode: unix.S_IFDIR | 0700, Uid: 0}
	if err := checkDirectoryStat(&valid, true); err != nil {
		t.Fatal(err)
	}
	for _, stat := range []unix.Stat_t{
		{Mode: unix.S_IFDIR | 0700, Uid: 1000}, {Mode: unix.S_IFDIR | 0770},
		{Mode: unix.S_IFDIR | 0707}, {Mode: unix.S_IFDIR | 0755},
		{Mode: unix.S_IFLNK | 0700}, {Mode: unix.S_IFREG | 0700},
	} {
		if err := checkDirectoryStat(&stat, true); err == nil {
			t.Fatalf("accepted unsafe collector directory: %+v", stat)
		}
	}
	parent := unix.Stat_t{Mode: unix.S_IFDIR | 0755}
	if err := checkDirectoryStat(&parent, false); err != nil {
		t.Fatal("root-owned read-only-to-others parent should be usable", err)
	}
	stickyParent := unix.Stat_t{Mode: unix.S_IFDIR | unix.S_ISVTX | 0777}
	if err := checkDirectoryStat(&stickyParent, false); err != nil {
		t.Fatal("Android's root-owned sticky bpffs ancestor should be usable", err)
	}
	if err := checkDirectoryStat(&stickyParent, true); err == nil {
		t.Fatal("sticky bit must not relax the private collector's permissions")
	}
	for _, stat := range []unix.Stat_t{
		{Mode: unix.S_IFDIR | 0777},
		{Mode: unix.S_IFDIR | unix.S_ISVTX | 0777, Uid: 1000},
		{Mode: unix.S_IFDIR | 0700, Uid: 1000},
	} {
		if err := checkDirectoryStat(&stat, false); err == nil {
			t.Fatalf("accepted replaceable or non-root ancestor: %+v", stat)
		}
	}
	for _, path := range []string{"relative", "/", "/sys/fs/bpf/../foreign"} {
		if _, err := openPinDirectory(path, true); err == nil {
			t.Fatalf("accepted noncanonical pin directory: %q", path)
		}
	}
	if _, err := openPinDirectory(t.TempDir(), false); err == nil {
		t.Fatal("accepted ordinary filesystem directory instead of bpffs")
	}
}

func TestRollbackOnlyRemovesSuccessfullyCreatedPins(t *testing.T) {
	failure := errors.New("unlink failed")
	var removed []string
	err := rollbackPins([]string{"owned-map", "owned-link"}, func(path string) error {
		removed = append(removed, path)
		if path == "owned-link" {
			return failure
		}
		return nil
	})
	if !errors.Is(err, failure) || !reflect.DeepEqual(removed, []string{"owned-link", "owned-map"}) {
		t.Fatalf("rollback lost errors or touched wrong pins: %v %v", removed, err)
	}
}

func TestRemoveFailureRestoresOnlyRemovedObjects(t *testing.T) {
	failure := errors.New("unpin failed")
	restoreFailure := errors.New("restore failed")
	var calls []string
	objects := []pinRemoval{
		{"link", func() error { calls = append(calls, "unpin link"); return nil }, func() error { calls = append(calls, "restore link"); return restoreFailure }},
		{"map", func() error { calls = append(calls, "unpin map"); return failure }, func() error { t.Fatal("must not restore untouched map"); return nil }},
		{"metadata", func() error { t.Fatal("must not continue after failure"); return nil }, nil},
	}
	err := removeOwnedPins(objects)
	if !errors.Is(err, failure) || !errors.Is(err, restoreFailure) || !reflect.DeepEqual(calls, []string{"unpin link", "unpin map", "restore link"}) {
		t.Fatalf("unsafe removal recovery: calls=%v error=%v", calls, err)
	}
}

func openLeaseFile(t *testing.T, path string) *os.File {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

// These tests exercise real Linux flock on an ordinary temporary filesystem.
// They do not claim that bpffs pinning or kernel BPF loading has been exercised.
func TestLiveCollectorLeasesBlockRemove(t *testing.T) {
	path := t.TempDir()
	first, second, remover := openLeaseFile(t, path), openLeaseFile(t, path), openLeaseFile(t, path)
	if exclusive, err := acquireOpenLease(first); !exclusive || err != nil {
		t.Fatalf("first initializer lease: %t %v", exclusive, err)
	}
	if err := unix.Flock(int(first.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	if exclusive, err := acquireOpenLease(second); exclusive || err != nil {
		t.Fatalf("second collector reuse lease: %t %v", exclusive, err)
	}
	if err := acquireRemoveLease(remover); !errors.Is(err, ErrBusy) {
		t.Fatalf("removed pins with two live collectors: %v", err)
	}
	_ = first.Close()
	if err := acquireRemoveLease(remover); !errors.Is(err, ErrBusy) {
		t.Fatalf("removed pins with one live collector: %v", err)
	}
	_ = second.Close()
	if err := acquireRemoveLease(remover); err != nil {
		t.Fatalf("closed collectors retained the lease: %v", err)
	}
}

func TestInitializationExcludesConcurrentReuse(t *testing.T) {
	path := t.TempDir()
	initializer, reuser := openLeaseFile(t, path), openLeaseFile(t, path)
	if exclusive, err := acquireOpenLease(initializer); !exclusive || err != nil {
		t.Fatalf("initialization lease: %t %v", exclusive, err)
	}
	done := make(chan error, 1)
	go func() {
		exclusive, err := acquireOpenLease(reuser)
		if exclusive && err == nil {
			err = errors.New("reuser unexpectedly became initializer")
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("reuse crossed an uncommitted initialization: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if err := unix.Flock(int(initializer.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("reuse remained blocked after initialization completed")
	}
}

func TestConcurrentCloseReleasesDescriptorsOnce(t *testing.T) {
	var closed atomic.Int32
	collector := &Collector{closeFDs: func() error { closed.Add(1); return nil }}
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			if err := collector.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	if closed.Load() != 1 || collector.Map() != nil {
		t.Fatalf("concurrent close released descriptors %d times", closed.Load())
	}
}

func TestUnsupportedArchitectureDoesNotCreatePins(t *testing.T) {
	if runtime.GOARCH == "arm64" {
		t.Skip("this check exercises rejection on non-target architectures")
	}
	path := t.TempDir() + "/must-not-create"
	if _, err := Open(Config{PinPath: path}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported producer architecture was accepted: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported Open modified pin storage: %v", err)
	}
}

func TestLegacyCollectorPinsBlockDefaultV2(t *testing.T) {
	directory := t.TempDir()
	if err := checkLegacyCollector(directory + "/missing"); err != nil {
		t.Fatalf("absent v1 directory rejected: %v", err)
	}
	if err := checkLegacyCollector(directory); err != nil {
		t.Fatalf("empty v1 directory (left by v1 Remove) rejected: %v", err)
	}
	if err := os.WriteFile(directory+"/producer", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkLegacyCollector(directory); err == nil {
		t.Fatal("remaining v1 pins accepted")
	}
}
