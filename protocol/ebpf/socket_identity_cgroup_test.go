//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Sockets the producer left out (creator in its own pid_<pid> cgroup) are
// attributed to that cgroup's process, with name and package from /proc.

func newCgroupProcessInbound(t *testing.T, tree *fakeCgroupTree, active bool) (*Inbound, *snapshotFixture) {
	t.Helper()
	previous := cgroupProcRoot
	cgroupProcRoot = tree.root
	t.Cleanup(func() { cgroupProcRoot = previous })
	inbound := newIdentityTestInbound(t, tree, nil)
	f := newSnapshotFixture(t)
	inbound.networkManager = &testNetworkManager{packageManager: f.packages}
	inbound.processIndex.Store(f.index)
	inbound.socketCreatorActive.Store(active)
	return inbound, f
}

func TestCgroupProcessNamesSharedUIDPackage(t *testing.T) {
	tree := newFakeCgroupTree(t)
	group := tree.addProcess(t, "apps", 10060, 500, "/system/bin/app_process64")
	writeCmdline(t, tree, 500, "com.shared.a:remote")
	inbound, f := newCgroupProcessInbound(t, tree, true)
	if got := waitLookup(t, f.index, 10060, "com.shared.a:remote"); got != "com.shared.a" {
		t.Fatalf("prepare index: %q", got)
	}
	owner := inbound.ownerFromIdentity(context.Background(), socketIdentity{valid: true, cookie: 5, uid: 10060, cgroupID: group})
	if owner.ProcessID != 500 || owner.UserId != 10060 || !slices.Equal(owner.PackageNames, []string{"com.shared.a"}) {
		t.Fatalf("owner: %+v", owner)
	}
	if got := inbound.identityCounters.resolvedByCgroupProcess.Load(); got != 1 {
		t.Fatalf("resolved by cgroup process = %d", got)
	}
}

// Without the producer a forked child shares its parent's cgroup, so the
// cgroup must stay a UID label: no PID, no name.
func TestCgroupProcessRequiresActiveProducer(t *testing.T) {
	tree := newFakeCgroupTree(t)
	group := tree.addProcess(t, "apps", 10060, 500, "/system/bin/app_process64")
	writeCmdline(t, tree, 500, "com.shared.a:remote")
	inbound, _ := newCgroupProcessInbound(t, tree, false)
	owner := inbound.ownerFromIdentity(context.Background(), socketIdentity{valid: true, cookie: 5, uid: 10060, cgroupID: group})
	if owner.ProcessID == 500 || len(owner.PackageNames) != 0 {
		t.Fatalf("inactive producer still used the cgroup process: %+v", owner)
	}
	if inbound.identityCounters.resolvedByCgroupProcess.Load() != 0 {
		t.Fatal("counted")
	}
}

// netd lives in its own cgroup labelled uid_0 and fchown()s its DNS sockets
// to the requesting app: the sender is netd, the app only the requester.
func TestCgroupProcessSenderIsNetdNotRequester(t *testing.T) {
	tree := newFakeCgroupTree(t)
	group := tree.addProcess(t, "system", 0, 200, "/system/bin/netd")
	inbound, _ := newCgroupProcessInbound(t, tree, true)
	owner := inbound.ownerFromIdentity(context.Background(), socketIdentity{valid: true, cookie: 6, uid: 10050, cgroupID: group})
	if owner.ProcessID != 200 || owner.UserId != 0 || !slices.Equal(owner.ProcessPaths, []string{"/system/bin/netd"}) || len(owner.PackageNames) != 0 {
		t.Fatalf("owner: %+v", owner)
	}
	if inbound.identityCounters.requesterDiffers.Load() != 1 {
		t.Fatal("requester not counted")
	}
}

// init services' directories are labelled uid_0 whatever they run as; the
// UID comes from the process.
func TestCgroupProcessUIDFromProcessNotLabel(t *testing.T) {
	tree := newFakeCgroupTree(t)
	group := tree.addProcess(t, "system", 0, 700, "/vendor/bin/qms")
	tree.addCreator(t, 1001, 700, "/vendor/bin/qms", "", 1234567)
	inbound, _ := newCgroupProcessInbound(t, tree, true)
	owner := inbound.ownerFromIdentity(context.Background(), socketIdentity{valid: true, cookie: 7, uid: 1001, cgroupID: group})
	if owner.ProcessID != 700 || owner.UserId != 1001 || !slices.Equal(owner.ProcessPaths, []string{"/vendor/bin/qms"}) {
		t.Fatalf("owner: %+v", owner)
	}
}

// A process that is no longer in the socket's cgroup (moved, or its PID
// reused by a process in another cgroup) is not the creator.
func TestCgroupProcessRejectsMovedProcess(t *testing.T) {
	tree := newFakeCgroupTree(t)
	group := tree.addProcess(t, "apps", 10060, 600, "/system/bin/app_process64")
	tree.addProcess(t, "apps", 10060, 601, "/system/bin/app_process64")
	writeCmdline(t, tree, 600, "com.shared.a:remote")
	writeCreatorCgroup(t, tree, 10060, 601, 600, "apps")
	inbound, _ := newCgroupProcessInbound(t, tree, true)
	owner := inbound.ownerFromIdentity(context.Background(), socketIdentity{valid: true, cookie: 8, uid: 10060, cgroupID: group})
	if owner.ProcessID == 600 || len(owner.PackageNames) != 0 {
		t.Fatalf("moved process attributed: %+v", owner)
	}
	if inbound.identityCounters.cgroupProcessGone.Load() != 1 {
		t.Fatal("gone not counted")
	}
	if err := os.RemoveAll(filepath.Join(tree.proc, "600")); err != nil {
		t.Fatal(err)
	}
}
