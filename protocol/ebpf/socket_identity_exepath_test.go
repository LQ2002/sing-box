//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/cilium/ebpf"
	"github.com/sagernet/sing-box/common/socketidentity"
)

// Snapshots from the sbo_identity producer carry an exe key; the path the
// kernel resolved at creation comes from the collector's path map, so the
// owner needs no /proc entry: it holds after the creator has exited.

type fakePathCollector struct {
	paths map[uint64]socketidentity.PathValue
}

func (f *fakePathCollector) Map() *ebpf.Map { return nil }
func (f *fakePathCollector) Close() error   { return nil }
func (f *fakePathCollector) LookupPath(key uint64) (socketidentity.PathValue, bool) {
	value, found := f.paths[key]
	return value, found
}

func pathValue(path string, flags uint32) socketidentity.PathValue {
	var value socketidentity.PathValue
	copy(value.Path[:], path)
	value.Length = uint32(len(path))
	value.Flags = flags
	return value
}

func exeKeyCreator(cookie uint64, pid, uid uint32, key uint64, flags uint32) commonEBPF.SocketCreator {
	return commonEBPF.SocketCreator{
		Cookie: cookie, StartTimeNs: 1234567 * 10000000, ProcessID: pid, ThreadID: pid, UserID: uid,
		Flags: socketidentity.CreatorValid | socketidentity.CreatorExeKey | flags, ExeInode: key,
	}
}

func TestSnapshotPathSurvivesCreatorExit(t *testing.T) {
	tree := newFakeCgroupTree(t)
	inbound := newIdentityTestInbound(t, tree, nil)
	key := socketidentity.ExeKey(266338314, 0, 10830611)
	collector := &fakePathCollector{paths: map[uint64]socketidentity.PathValue{key: pathValue("/system/bin/iptables", 0)}}
	inbound.socketCreator = collector
	// No /proc/900 at all: the short-lived creator is gone.
	owner := inbound.resolveSocketOwner(context.Background(), socketOwnerFromCreator(exeKeyCreator(5, 900, 0, key, 0)))
	if owner.ProcessID != 900 || owner.UserId != 0 || !slices.Equal(owner.ProcessPaths, []string{"/system/bin/iptables"}) {
		t.Fatalf("owner: %+v", owner)
	}
	if inbound.identityCounters.exePathFromSnapshot.Load() != 1 {
		t.Fatal("not counted")
	}
}

func TestSnapshotPathFallsBackToProcWhenEvicted(t *testing.T) {
	tree := newFakeCgroupTree(t)
	inbound := newIdentityTestInbound(t, tree, nil)
	inbound.socketCreator = &fakePathCollector{paths: map[uint64]socketidentity.PathValue{}}
	creator := tree.addCreator(t, 0, 901, "/system/bin/netd", "", 1234567)
	snapshot := exeKeyCreator(6, creator.ProcessID, 0, 42, 0)
	owner := inbound.resolveSocketOwner(context.Background(), socketOwnerFromCreator(snapshot))
	if !slices.Equal(owner.ProcessPaths, []string{"/system/bin/netd"}) {
		t.Fatalf("owner: %+v", owner)
	}
	if inbound.identityCounters.exePathMissing.Load() != 1 {
		t.Fatal("missing path not counted")
	}
	if err := os.RemoveAll(filepath.Join(tree.proc, "901")); err != nil {
		t.Fatal(err)
	}
}

// An app_process path from the map still goes through the E1 rule (ordinary
// app UID with one package), exactly like a /proc-verified one.
func TestSnapshotPathAppProcessUsesUID(t *testing.T) {
	tree := newFakeCgroupTree(t)
	inbound := newIdentityTestInbound(t, tree, nil)
	f := newSnapshotFixture(t)
	inbound.networkManager = &testNetworkManager{packageManager: f.packages}
	key := socketidentity.ExeKey(266338314, 0, 10829601)
	inbound.socketCreator = &fakePathCollector{paths: map[uint64]socketidentity.PathValue{key: pathValue("/system/bin/app_process64", 0)}}
	owner := inbound.resolveSocketOwner(context.Background(), socketOwnerFromCreator(exeKeyCreator(7, 902, 10050, key, 0)))
	if !slices.Equal(owner.PackageNames, []string{"com.example.app"}) || len(owner.ProcessPaths) != 0 {
		t.Fatalf("owner: %+v", owner)
	}
}

func TestExeKeyIsFNVOverDevGenerationInode(t *testing.T) {
	// Recomputed byte by byte: dev and generation as one little-endian u64
	// (dev low), then the inode; bpf/creator.bpf.c exe_key hashes the same.
	bytes := []byte{0x0a, 0x00, 0xe0, 0x0f, 0x07, 0x00, 0x00, 0x00, 0x13, 0x41, 0xa5, 0x00, 0x00, 0x00, 0x00, 0x00}
	hash := uint64(0xcbf29ce484222325)
	for _, b := range bytes {
		hash ^= uint64(b)
		hash *= 0x100000001b3
	}
	if got := socketidentity.ExeKey(0x0fe0000a, 7, 0xa54113); got != hash {
		t.Fatalf("ExeKey = %#x, want %#x", got, hash)
	}
}
