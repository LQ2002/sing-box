//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/common/socketidentity"
	"github.com/sagernet/sing-box/option"

	"github.com/cilium/ebpf"
)

func assignmentCreator(cookie uint64, owner SocketOwner) commonEBPF.SocketCreator {
	creator := commonEBPF.SocketCreator{
		Cookie: cookie, StartTimeNs: owner.StartTimeNs, ProcessID: owner.ProcessID,
		ThreadID: owner.ProcessID + 1, UserID: owner.UserID, Flags: commonEBPF.SocketCreatorValid,
	}
	copy(creator.Comm[:], owner.Comm)
	return creator
}

func TestAssignmentCreatorSeparatesSharedUIDWithoutCookieLookup(t *testing.T) {
	tree := newFakeCgroupTree(t)
	group := tree.addProcess(t, "apps", 10060, 400, "/system/bin/app_process64")
	first := tree.addCreator(t, 10060, 410, "/system/bin/app_process64", firstCreatorProcess, 100)
	second := tree.addCreator(t, 10060, 420, "/system/bin/app_process64", secondCreatorProcess, 101)
	inbound := newCreatorIdentityTestInbound(t, tree, 10060)
	// Conflicting legacy data must never override a valid creation snapshot.
	source := &testCookieOwnerSource{owners: map[uint64]SocketOwner{1: second, 2: first}}
	inbound.processTracker = source
	inbound.socketCreatorActive.Store(true)
	for index, creator := range []SocketOwner{first, second} {
		cookie := uint64(index + 1)
		assignment := commonEBPF.TCAssignment{
			SocketCookie: cookie, SocketUID: 10060, SocketCgroupID: group,
			IdentityFlags: commonEBPF.TCIdentityUIDValid | commonEBPF.TCIdentityCgroupValid,
			Creator:       assignmentCreator(cookie, creator),
		}
		owner := inbound.ownerFromIdentity(context.Background(), identityFromAssignment(assignment))
		wantPackage := []string{firstCreatorPackage, secondCreatorPackage}[index]
		if owner.ProcessID != creator.ProcessID || !slices.Equal(owner.PackageNames, []string{wantPackage}) {
			t.Fatalf("creator snapshot selected another shared-UID process: %+v", owner)
		}
	}
	if source.lookups != 0 || inbound.identityCounters.creatorSnapshots.Load() != 2 {
		t.Fatalf("lookups=%d snapshots=%d", source.lookups, inbound.identityCounters.creatorSnapshots.Load())
	}
}

func TestAssignmentCreatorWorksWithoutBillingIdentity(t *testing.T) {
	tree := newFakeCgroupTree(t)
	creator := tree.addCreator(t, 0, 410, "/system/bin/native", "native", 100)
	inbound := newIdentityTestInbound(t, tree, nil)
	identity := identityFromAssignment(commonEBPF.TCAssignment{
		SocketCookie: 9, Creator: assignmentCreator(9, creator),
	})
	owner := inbound.ownerFromIdentity(context.Background(), identity)
	if owner.ProcessID != 410 || owner.UserId != 0 || !slices.Equal(owner.ProcessPaths, []string{"/system/bin/native"}) {
		t.Fatalf("missing UID/cgroup hid the independent creator: %+v", owner)
	}
}

func TestAssignmentCreatorOverridesConflictingBillingGroup(t *testing.T) {
	tree := newFakeCgroupTree(t)
	// Even if both billing UID and group label name an app, explicit creator
	// evidence from another UID wins. This also exercises root's valid UID=0.
	group := tree.addProcess(t, "apps", 10050, 400, "/system/bin/app_process64")
	netd := tree.addCreator(t, 0, 410, "/system/bin/netd", "netd", 100)
	inbound := newIdentityTestInbound(t, tree, &testPackageManager{
		idByPackage:  map[string]uint32{firstCreatorPackage: 10050},
		packagesByID: map[uint32][]string{10050: {firstCreatorPackage}},
	})
	owner := inbound.ownerFromIdentity(context.Background(), socketIdentity{
		cookie: 1, uid: 10050, cgroupID: group, valid: true, creator: assignmentCreator(1, netd),
	})
	if owner.ProcessID != 410 || owner.UserId != 0 || len(owner.PackageNames) != 0 || !slices.Equal(owner.ProcessPaths, []string{"/system/bin/netd"}) {
		t.Fatalf("billing metadata overrode actual creator: %+v", owner)
	}
}

func TestAssignmentCreatorKeepsOrdinaryAppFastPath(t *testing.T) {
	tree := newFakeCgroupTree(t)
	group := tree.addProcess(t, "apps", 10050, 400, "/system/bin/app_process64")
	creator := tree.addCreator(t, 10050, 410, "/data/local/tmp/native_child", "native_child", 100)
	inbound := newIdentityTestInbound(t, tree, &testPackageManager{
		idByPackage:  map[string]uint32{firstCreatorPackage: 10050},
		packagesByID: map[uint32][]string{10050: {firstCreatorPackage}},
	})
	source := &testCookieOwnerSource{}
	inbound.processTracker = source
	if err := os.RemoveAll(tree.proc); err != nil {
		t.Fatal(err)
	}
	owner := inbound.ownerFromIdentity(context.Background(), socketIdentity{
		cookie: 1, uid: 10050, cgroupID: group, valid: true, creator: assignmentCreator(1, creator),
	})
	if owner.ProcessID != 410 || len(owner.ProcessPaths) != 0 || !slices.Equal(owner.PackageNames, []string{firstCreatorPackage}) || source.lookups != 0 {
		t.Fatalf("ordinary app lost fast attribution or claimed an executable: %+v (lookups=%d)", owner, source.lookups)
	}
}

func TestAssignmentCreatorMissOrReusedCookieFallsBack(t *testing.T) {
	for _, missing := range []bool{true, false} {
		t.Run(map[bool]string{true: "missing", false: "reused_cookie"}[missing], func(t *testing.T) {
			tree := newFakeCgroupTree(t)
			old := tree.addCreator(t, 0, 400, "/system/bin/old", "old", 100)
			current := tree.addCreator(t, 0, 410, "/system/bin/current", "current", 101)
			inbound := newIdentityTestInbound(t, tree, nil)
			inbound.socketCreatorActive.Store(true)
			source := &testCookieOwnerSource{owners: map[uint64]SocketOwner{2: current}}
			inbound.processTracker = source
			assignment := commonEBPF.TCAssignment{SocketCookie: 2}
			if !missing {
				assignment.Creator = assignmentCreator(1, old)
			}
			owner := inbound.ownerFromIdentity(context.Background(), identityFromAssignment(assignment))
			if owner.ProcessID != 410 || source.lookups != 1 || inbound.identityCounters.creatorFallbacks.Load() != 1 {
				t.Fatalf("missing/mismatched snapshot did not use matching cookie: %+v (lookups=%d)", owner, source.lookups)
			}
			if missing && inbound.identityCounters.creatorMissing.Load() != 1 || !missing && inbound.identityCounters.creatorInvalid.Load() != 1 {
				t.Fatal("missing and invalid snapshots were not diagnosed separately")
			}
		})
	}
}

func TestAssignmentCreatorExitDoesNotInventPackage(t *testing.T) {
	tree := newFakeCgroupTree(t)
	creator := SocketOwner{ProcessID: 410, UserID: 10060, StartTimeNs: 1000000000, Comm: "com.shared.hint"}
	inbound := newIdentityTestInbound(t, tree, &testPackageManager{
		packagesByID: map[uint32][]string{10060: {firstCreatorPackage, secondCreatorPackage}},
	})
	owner := inbound.ownerFromIdentity(context.Background(), socketIdentity{cookie: 1, creator: assignmentCreator(1, creator)})
	if owner.ProcessID != 410 || owner.UserId != 10060 || len(owner.PackageNames) != 0 {
		t.Fatalf("exited creator lost identity or comm became package proof: %+v", owner)
	}
}

func TestAssignmentCreatorSharedPathCannotClaimLocalIdentity(t *testing.T) {
	assignment := commonEBPF.TCAssignment{
		Path: commonEBPF.TCPathShared, SocketCookie: 1, SocketUID: 10050,
		IdentityFlags: commonEBPF.TCIdentityUIDValid | commonEBPF.TCIdentityCgroupValid,
		Creator:       assignmentCreator(1, SocketOwner{ProcessID: 410, UserID: 10050, StartTimeNs: 1000000000}),
	}
	identity := identityFromAssignment(assignment)
	if identity.valid || identity.cookie != 0 || identity.hasCreator() {
		t.Fatalf("shared path consumed local identity: %+v", identity)
	}
}

func TestSocketCreatorConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name       string
		options    *option.EBPFSocketCreatorOptions
		local      bool
		plane      string
		want       string
		wantRemove bool
		invalid    bool
	}{
		{"omitted", nil, true, localDataPlaneTC, "", false, false},
		{"disabled", &option.EBPFSocketCreatorOptions{}, true, localDataPlaneTC, "", false, false},
		{"default_path", &option.EBPFSocketCreatorOptions{Enabled: true}, true, localDataPlaneTC, socketidentity.DefaultPinPath, false, false},
		{"remove_on_stop", &option.EBPFSocketCreatorOptions{Enabled: true, RemoveOnStop: true}, true, localDataPlaneTC, socketidentity.DefaultPinPath, true, false},
		{"remove_on_stop_disabled", &option.EBPFSocketCreatorOptions{RemoveOnStop: true}, true, localDataPlaneTC, "", false, true},
		{"custom_path", &option.EBPFSocketCreatorOptions{Enabled: true, PinPath: "/sys/fs/bpf/custom/"}, true, localDataPlaneTC, "/sys/fs/bpf/custom", false, false},
		{"not_local", &option.EBPFSocketCreatorOptions{Enabled: true}, false, localDataPlaneTC, "", false, true},
		{"cgroup", &option.EBPFSocketCreatorOptions{Enabled: true}, true, localDataPlaneCgroup, "", false, true},
		{"relative", &option.EBPFSocketCreatorOptions{Enabled: true, PinPath: "relative"}, true, localDataPlaneTC, "", false, true},
		{"root", &option.EBPFSocketCreatorOptions{Enabled: true, PinPath: "/"}, true, localDataPlaneTC, "", false, true},
		{"path_disabled", &option.EBPFSocketCreatorOptions{PinPath: "/sys/fs/bpf/custom"}, true, localDataPlaneTC, "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, removeOnStop, err := normalizeSocketCreator(tc.options, tc.local, tc.plane)
			if (err != nil) != tc.invalid || !tc.invalid && (path != tc.want || removeOnStop != tc.wantRemove) {
				t.Fatalf("path=%q removeOnStop=%v err=%v", path, removeOnStop, err)
			}
		})
	}
	if err := validateLocalOptions(false, option.EBPFLocalOptions{SocketCreator: &option.EBPFSocketCreatorOptions{Enabled: true}}); err == nil {
		t.Fatal("disabled local accepted collector configuration")
	}
}

type testSocketCreatorCollector struct {
	closes int
	fail   bool
}

func (*testSocketCreatorCollector) Map() *ebpf.Map { return nil }
func (c *testSocketCreatorCollector) Close() error {
	c.closes++
	if c.fail {
		return errors.New("injected close error")
	}
	return nil
}

func TestSocketCreatorCloseWaitsForTCAndRetainsFailedReference(t *testing.T) {
	collector := &testSocketCreatorCollector{fail: true}
	inbound := &Inbound{socketCreator: collector}
	inbound.socketCreatorActive.Store(true)
	dataPlane := &retryTestTCRuntime{}
	inbound.setTCDataPlane(dataPlane)
	if err := inbound.closeSocketCreator(); err == nil || collector.closes != 0 {
		t.Fatal("borrowed map reference closed before TC")
	}
	if err := inbound.closeTCDataPlane(); err == nil {
		t.Fatal("expected TC cleanup failure")
	}
	if err := inbound.closeSocketCreator(); err == nil || collector.closes != 0 {
		t.Fatal("collector closed while failed TC cleanup retained its reference")
	}
	if err := inbound.closeTCDataPlane(); err != nil {
		t.Fatal(err)
	}
	if err := inbound.closeSocketCreator(); err == nil || inbound.socketCreator != collector {
		t.Fatal("collector close failure discarded retryable reference")
	}
	collector.fail = false
	if err := inbound.closeSocketCreator(); err != nil || inbound.socketCreator != nil || inbound.socketCreatorActive.Load() {
		t.Fatalf("collector did not finish closing: %v", err)
	}
	if err := inbound.closeSocketCreator(); err != nil || collector.closes != 2 {
		t.Fatal("collector close was not idempotent")
	}
}

func TestSocketCreatorRestartRejectsClosedMap(t *testing.T) {
	inbound := &Inbound{
		socketCreatorPinPath: socketidentity.DefaultPinPath,
		socketCreator:        &testSocketCreatorCollector{},
	}
	if err := inbound.startSocketCreator(); err == nil {
		t.Fatal("configured creator silently restarted with a closed or missing map")
	}
}
