//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/common/androidpackages"
)

const (
	firstCreatorPackage  = "com.example.first"
	secondCreatorPackage = "com.example.second"
	firstCreatorProcess  = firstCreatorPackage + ":worker"
	secondCreatorProcess = secondCreatorPackage + ":worker"
)

// Both packages share the same UID, but declare different process names.
// Prebuild the index so these tests exercise creator selection, not timing.
func newCreatorIdentityTestInbound(t *testing.T, tree *fakeCgroupTree, uid uint32) *Inbound {
	t.Helper()
	packages := &testPackageManager{
		idByPackage:     map[string]uint32{firstCreatorPackage: uid, secondCreatorPackage: uid},
		packagesByID:    map[uint32][]string{uid: {firstCreatorPackage, secondCreatorPackage}},
		sharedPackageID: map[uint32]string{uid: "shared.creator.test"},
	}
	inbound := newIdentityTestInbound(t, tree, packages)
	table := &atomic.Pointer[fakeProcessTable]{}
	table.Store(&fakeProcessTable{
		packages: packages.packagesByID,
		code: map[string]androidpackages.PackageCode{
			firstCreatorPackage:  {Path: "first", Stamp: "1"},
			secondCreatorPackage: {Path: "second", Stamp: "1"},
		},
	})
	index := newTestIndex(t, table, &fakeManifests{processes: map[string][]string{
		"first": {firstCreatorProcess}, "second": {secondCreatorProcess},
	}})
	inbound.processIndex.Store(index)
	if got := waitLookup(t, index, uid, firstCreatorProcess); got != firstCreatorPackage {
		t.Fatalf("prepare process index: got %q", got)
	}
	return inbound
}

func writeCreatorCgroup(t *testing.T, tree *fakeCgroupTree, uid, groupPID, creatorPID uint32, kind string) {
	t.Helper()
	content := "0::/" + kind + "/uid_" + strconv.FormatUint(uint64(uid), 10) + "/pid_" + strconv.FormatUint(uint64(groupPID), 10) + "\n"
	path := filepath.Join(tree.proc, strconv.FormatUint(uint64(creatorPID), 10), "cgroup")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityCookieSeparatesCreatorsInSameGroup(t *testing.T) {
	for _, tc := range []struct {
		name, kind string
		uid        uint32
	}{
		{"shared_app", "apps", 10060},
		{"system", "system", 1000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := newFakeCgroupTree(t)
			group := tree.addProcess(t, tc.kind, tc.uid, 400, "/system/bin/app_process64")
			writeCmdline(t, tree, 400, firstCreatorProcess)
			first := tree.addCreator(t, tc.uid, 410, "/system/bin/app_process64", firstCreatorProcess, 100)
			second := tree.addCreator(t, tc.uid, 420, "/system/bin/app_process64", secondCreatorProcess, 101)
			writeCreatorCgroup(t, tree, tc.uid, 400, 410, tc.kind)
			writeCreatorCgroup(t, tree, tc.uid, 400, 420, tc.kind)
			inbound := newCreatorIdentityTestInbound(t, tree, tc.uid)
			source := &testCookieOwnerSource{owners: map[uint64]SocketOwner{1: first, 2: second}}
			inbound.processTracker = source
			for _, want := range []struct {
				cookie      uint64
				pid         uint32
				packageName string
			}{{1, 410, firstCreatorPackage}, {2, 420, secondCreatorPackage}, {1, 410, firstCreatorPackage}} {
				owner := inbound.ownerFromIdentity(context.Background(), socketIdentity{valid: true, cookie: want.cookie, uid: tc.uid, cgroupID: group})
				if owner == nil || owner.ProcessID != want.pid || owner.UserId != int32(tc.uid) || !slices.Equal(owner.PackageNames, []string{want.packageName}) || len(owner.ProcessPaths) != 0 {
					t.Fatalf("cookie %d inherited another group member: %+v", want.cookie, owner)
				}
			}
			if source.lookups != 3 {
				t.Fatalf("cookie creator cached by group: got %d lookups, want 3", source.lookups)
			}
		})
	}
}

func TestIdentityCreatorSurvivesGroupLeaderExit(t *testing.T) {
	tree := newFakeCgroupTree(t)
	group := tree.addProcess(t, "system", 1000, 400, "/system/bin/app_process64")
	writeCmdline(t, tree, 400, firstCreatorProcess)
	child := tree.addCreator(t, 1000, 410, "/system/bin/app_process64", secondCreatorProcess, 101)
	writeCreatorCgroup(t, tree, 1000, 400, 410, "system")
	if err := os.RemoveAll(filepath.Join(tree.proc, "400")); err != nil {
		t.Fatal(err)
	}
	inbound := newCreatorIdentityTestInbound(t, tree, 1000)
	inbound.processTracker = &testCookieOwnerSource{owners: map[uint64]SocketOwner{1: child}}
	owner := inbound.ownerFromIdentity(context.Background(), socketIdentity{valid: true, cookie: 1, uid: 1000, cgroupID: group})
	if owner == nil || owner.ProcessID != 410 || !slices.Equal(owner.PackageNames, []string{secondCreatorPackage}) {
		t.Fatalf("surviving child not resolved independently of group leader: %+v", owner)
	}

	// A new process can also reuse the directory PID and join that same
	// group. Without a cookie record its metadata is still not evidence.
	tree.addCreator(t, 1000, 400, "/system/bin/app_process64", firstCreatorProcess, 102)
	writeCreatorCgroup(t, tree, 1000, 400, 400, "system")
	inbound.processTracker = nil
	owner = inbound.ownerFromIdentity(context.Background(), socketIdentity{valid: true, cookie: 2, uid: 1000, cgroupID: group})
	if owner == nil || owner.ProcessID != 0 || len(owner.PackageNames) != 0 || len(owner.ProcessPaths) != 0 {
		t.Fatalf("reused directory PID supplied creator metadata: %+v", owner)
	}
}

func TestIdentityCreatorRejectsPIDReuseWithinSameGroup(t *testing.T) {
	tree := newFakeCgroupTree(t)
	group := tree.addProcess(t, "system", 1000, 400, "/system/bin/app_process64")
	old := tree.addCreator(t, 1000, 410, "/system/bin/app_process64", firstCreatorProcess, 100)
	writeCreatorCgroup(t, tree, 1000, 400, 410, "system")
	// Simulate PID reuse without changing cgroup membership. Only the
	// cookie creator's start time can distinguish these process instances.
	current := tree.addCreator(t, 1000, 410, "/system/bin/app_process64", secondCreatorProcess, 101)
	inbound := newCreatorIdentityTestInbound(t, tree, 1000)
	inbound.processTracker = &testCookieOwnerSource{owners: map[uint64]SocketOwner{1: old, 2: current}}
	owner := inbound.ownerFromIdentity(context.Background(), socketIdentity{valid: true, cookie: 1, uid: 1000, cgroupID: group})
	if owner == nil || owner.ProcessID != 410 || len(owner.PackageNames) != 0 || len(owner.ProcessPaths) != 0 {
		t.Fatalf("old socket was refined using a new process: %+v", owner)
	}
	owner = inbound.ownerFromIdentity(context.Background(), socketIdentity{valid: true, cookie: 2, uid: 1000, cgroupID: group})
	if owner == nil || owner.ProcessID != 410 || !slices.Equal(owner.PackageNames, []string{secondCreatorPackage}) {
		t.Fatalf("new creator did not get its own metadata: %+v", owner)
	}
}

func TestIdentityMissingCookieEvidenceDoesNotUseGroupPID(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source SocketOwnerSource
		cookie uint64
	}{
		{"no_module", nil, 1},
		{"module_miss", &testCookieOwnerSource{}, 1},
		{"zero_cookie", &testCookieOwnerSource{}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := newFakeCgroupTree(t)
			group := tree.addProcess(t, "system", 1000, 400, "/system/bin/app_process64")
			writeCmdline(t, tree, 400, firstCreatorProcess)
			inbound := newCreatorIdentityTestInbound(t, tree, 1000)
			inbound.processTracker = tc.source
			owner := inbound.ownerFromIdentity(context.Background(), socketIdentity{valid: true, cookie: tc.cookie, uid: 1000, cgroupID: group})
			if owner == nil || owner.ProcessID != 0 || owner.UserId != 1000 || len(owner.PackageNames) != 0 || len(owner.ProcessPaths) != 0 {
				t.Fatalf("missing cookie creator guessed group PID/package: %+v", owner)
			}
			owner = inbound.ownerFromIdentity(context.Background(), socketIdentity{valid: true, cookie: tc.cookie, uid: 10050, cgroupID: group})
			if owner == nil || owner.UserId != -1 || owner.ProcessID != 0 || len(owner.PackageNames) != 0 || len(owner.ProcessPaths) != 0 {
				t.Fatalf("conflicting socket/group UID became creator identity: %+v", owner)
			}
		})
	}
}

func TestIdentityUnverifiedCreatorCannotUseManifestName(t *testing.T) {
	for _, tc := range []string{"no_start_time", "uid_mismatch", "start_time_mismatch", "missing_cmdline", "empty_cmdline", "unterminated_cmdline"} {
		t.Run(tc, func(t *testing.T) {
			tree := newFakeCgroupTree(t)
			group := tree.addProcess(t, "system", 1000, 400, "/system/bin/app_process64")
			creator := tree.addCreator(t, 1000, 410, "/system/bin/app_process64", firstCreatorProcess, 100)
			// A matching comm must never substitute for the complete,
			// verified cmdline, even when the package index knows that name.
			creator.Comm = firstCreatorProcess
			switch tc {
			case "no_start_time":
				creator.StartTimeNs = 0
			case "uid_mismatch":
				tree.addCreator(t, 1001, 410, "/system/bin/app_process64", firstCreatorProcess, 100)
			case "start_time_mismatch":
				creator.StartTimeNs += 10000000
			case "missing_cmdline":
				if err := os.Remove(filepath.Join(tree.proc, "410", "cmdline")); err != nil {
					t.Fatal(err)
				}
			case "empty_cmdline":
				writeCmdline(t, tree, 410, "")
			case "unterminated_cmdline":
				if err := os.WriteFile(filepath.Join(tree.proc, "410", "cmdline"), []byte(firstCreatorProcess), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			inbound := newCreatorIdentityTestInbound(t, tree, 1000)
			inbound.processTracker = &testCookieOwnerSource{owners: map[uint64]SocketOwner{1: creator}}
			owner := inbound.ownerFromIdentity(context.Background(), socketIdentity{valid: true, cookie: 1, uid: 1000, cgroupID: group})
			if owner == nil || owner.ProcessID != 410 || owner.UserId != 1000 || len(owner.PackageNames) != 0 || !slices.Equal(owner.ProcessPaths, []string{creator.Comm}) {
				t.Fatalf("unverified creator was refined: %+v", owner)
			}
			key := socketOwnerCacheKey{ProcessID: creator.ProcessID, UserID: creator.UserID, StartTimeNs: creator.StartTimeNs}
			if _, found := socketOwnerCache().Get(key); found {
				t.Fatal("incomplete creator metadata was cached")
			}
		})
	}
}

func TestIdentityOrdinaryGroupDoesNotClaimEitherCreator(t *testing.T) {
	tree := newFakeCgroupTree(t)
	group := tree.addProcess(t, "apps", 10050, 400, "/system/bin/app_process64")
	first := tree.addCreator(t, 10050, 410, "/data/local/tmp/first", "first", 100)
	second := tree.addCreator(t, 10050, 420, "/data/local/tmp/second", "second", 101)
	writeCreatorCgroup(t, tree, 10050, 400, 410, "apps")
	writeCreatorCgroup(t, tree, 10050, 400, 420, "apps")
	inbound := newIdentityTestInbound(t, tree, &testPackageManager{
		idByPackage:  map[string]uint32{firstCreatorPackage: 10050},
		packagesByID: map[uint32][]string{10050: {firstCreatorPackage}},
	})
	source := &testCookieOwnerSource{owners: map[uint64]SocketOwner{1: first, 2: second}}
	inbound.processTracker = source
	// No proc metadata is needed for UID/group-level package attribution,
	// including after the original group leader exits.
	if err := os.RemoveAll(tree.proc); err != nil {
		t.Fatal(err)
	}
	for _, cookie := range []uint64{1, 2} {
		owner := inbound.ownerFromIdentity(context.Background(), socketIdentity{valid: true, cookie: cookie, uid: 10050, cgroupID: group})
		if owner == nil || owner.ProcessID != 0 || owner.UserId != 10050 || len(owner.ProcessPaths) != 0 || !slices.Equal(owner.PackageNames, []string{firstCreatorPackage}) {
			t.Fatalf("ordinary UID group claimed a process identity: %+v", owner)
		}
	}
	if source.lookups != 0 {
		t.Fatalf("ordinary UID fast path performed %d creator lookups", source.lookups)
	}
}

func TestIdentityDelegatedSocketUsesCookieCreator(t *testing.T) {
	tree := newFakeCgroupTree(t)
	group := tree.addProcess(t, "system", 0, 200, "/system/bin/other_daemon")
	netd := tree.addCreator(t, 0, 210, "/system/bin/netd", "netd", 100)
	inbound := newIdentityTestInbound(t, tree, &testPackageManager{
		idByPackage:  map[string]uint32{firstCreatorPackage: 10050},
		packagesByID: map[uint32][]string{10050: {firstCreatorPackage}},
	})
	source := &testCookieOwnerSource{owners: map[uint64]SocketOwner{1: netd}}
	inbound.processTracker = source
	owner := inbound.ownerFromIdentity(context.Background(), socketIdentity{valid: true, cookie: 1, uid: 10050, cgroupID: group})
	if owner == nil || owner.ProcessID != 210 || owner.UserId != 0 || len(owner.PackageNames) != 0 || !slices.Equal(owner.ProcessPaths, []string{"/system/bin/netd"}) {
		t.Fatalf("fchown accounting UID or group PID replaced cookie creator: %+v", owner)
	}
	if source.lookups != 1 {
		t.Fatalf("creator lookups = %d, want 1", source.lookups)
	}
}
