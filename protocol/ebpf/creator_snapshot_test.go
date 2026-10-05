//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"hash/fnv"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/common/androidpackages"
	"golang.org/x/sys/unix"
)

// The producer's BPF loop and this function must agree byte for byte; the
// device probe compared 865 real argv[0] values against Go's hash/fnv, so
// fnv1a64 is checked against the same reference here.
func TestFNV1a64MatchesReference(t *testing.T) {
	for _, value := range []string{"", "a", "system_server", "com.tencent.mm:push", strings.Repeat("x", 127)} {
		reference := fnv.New64a()
		_, _ = reference.Write([]byte(value))
		if got, want := fnv1a64(value), reference.Sum64(); got != want {
			t.Fatalf("fnv1a64(%q) = %#x, want %#x", value, got, want)
		}
	}
}

func snapshotOf(name string, truncatedAt int) snapshotName {
	if truncatedAt > 0 {
		return snapshotName{hash: fnv1a64(name[:truncatedAt]), length: truncatedAt, truncated: true}
	}
	return snapshotName{hash: fnv1a64(name), length: len(name)}
}

func TestSnapshotNameMatches(t *testing.T) {
	long := "com.google.android.accessibility.switchaccess:playcore_missing_splits_activity" // 78 bytes, seen on the device
	for _, tc := range []struct {
		name     string
		snapshot snapshotName
		declared string
		want     bool
	}{
		{"exact", snapshotOf("com.example:remote", 0), "com.example:remote", true},
		{"other name", snapshotOf("com.example:remote", 0), "com.example:push", false},
		// Without the truncation flag a longer declared name sharing the
		// prefix is a different process (com.foo vs com.foo:bar).
		{"untruncated prefix", snapshotOf("com.example", 0), "com.example:remote", false},
		// 78-byte usap block: argv[0] holds 77 bytes.
		{"truncated prefix", snapshotOf(long, 77), long, true},
		{"truncated shorter declared", snapshotOf(long, 77), long[:70], false},
		// A name that exactly filled its block is flagged but complete.
		{"filled block", snapshotOf(long, 78), long, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.snapshot.matches(tc.declared); got != tc.want {
				t.Fatalf("matches(%q) = %v, want %v", tc.declared, got, tc.want)
			}
		})
	}
	if snapshotOf("a", 0).memoKey("") == snapshotOf("a", 1).memoKey("") {
		t.Fatal("truncated and complete snapshots share a memo key")
	}
}

func TestCreatorSnapshotNameFromFlags(t *testing.T) {
	creator := commonEBPF.SocketCreator{Flags: commonEBPF.SocketCreatorValid}
	if _, ok := creatorSnapshotName(creator); ok {
		t.Fatal("name accepted without NAME_VALID")
	}
	creator.Flags |= commonEBPF.SocketCreatorNameValid | commonEBPF.SocketCreatorNameTruncated | 77<<8
	creator.ProcessNameHash = 42
	name, ok := creatorSnapshotName(creator)
	if !ok || name != (snapshotName{hash: 42, length: 77, truncated: true}) {
		t.Fatalf("snapshot name = %+v %v", name, ok)
	}
}

type snapshotFixture struct {
	packages *testPackageManager
	index    *processPackageIndex
}

// Layout modelled on the device census: a shared UID with distinct process
// names, a name declared by two packages, system's "system" declared by
// several, an app UID that literally declares "system", and SDK sandboxes of
// a single-package and a shared-UID host.
func newSnapshotFixture(t *testing.T) *snapshotFixture {
	t.Helper()
	long := "com.shared.a:" + strings.Repeat("p", 65) // 78 bytes
	packages := &testPackageManager{
		idByPackage: map[string]uint32{
			"com.example.app": 10050, "com.shared.a": 10060, "com.shared.b": 10060,
			"android": 1000, "com.android.settings": 1000, "com.miui.rom": 10088,
		},
		packagesByID: map[uint32][]string{
			10050: {"com.example.app"}, 10060: {"com.shared.a", "com.shared.b"},
			1000: {"android", "com.android.settings"}, 10088: {"com.miui.rom"},
		},
		sharedPackageID: map[uint32]string{10060: "shared.user", 1000: "android.uid.system"},
	}
	table := &atomic.Pointer[fakeProcessTable]{}
	code := map[string]androidpackages.PackageCode{}
	for name := range packages.idByPackage {
		code[name] = androidpackages.PackageCode{Path: name, Stamp: "1"}
	}
	table.Store(&fakeProcessTable{packages: packages.packagesByID, code: code})
	manifests := &fakeManifests{processes: map[string][]string{
		"com.example.app": {"com.example.app"},
		"com.shared.a":    {"com.shared.a", "com.shared.a:remote", "shared.common", long},
		// Like com.miui.rom on the device, an app UID declaring "system".
		"com.shared.b":         {"com.shared.b", "shared.common", "system", "com.shared.a:" + strings.Repeat("p", 64) + "q"},
		"android":              {"system"},
		"com.android.settings": {"com.android.settings"},
		"com.miui.rom":         {"system"},
	}}
	return &snapshotFixture{packages: packages, index: newTestIndex(t, table, manifests)}
}

func (f *snapshotFixture) resolve(t *testing.T, uid uint32, name snapshotName) (string, processLookupOutcome) {
	t.Helper()
	unique := func(uid uint32) string { return uniqueApplicationPackage(f.packages, uid) }
	deadline := time.Now().Add(2 * time.Second)
	for {
		packageName, outcome := snapshotPackage(uid, name, true, unique, f.index)
		if outcome != processLookupPending || time.Now().After(deadline) {
			return packageName, outcome
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestSnapshotPackageEvidenceLevels(t *testing.T) {
	f := newSnapshotFixture(t)
	long := "com.shared.a:" + strings.Repeat("p", 65)
	for _, tc := range []struct {
		name    string
		uid     uint32
		process snapshotName
		want    string
		outcome processLookupOutcome
	}{
		{"E1 single package", 10050, snapshotOf("anything", 0), "com.example.app", processLookupFoundByUID},
		{"E1 other user", 1010050, snapshotOf("anything", 0), "com.example.app", processLookupFoundByUID},
		{"E2 unique name", 10060, snapshotOf("com.shared.a:remote", 0), "com.shared.a", processLookupFound},
		{"E2 other package", 10060, snapshotOf("com.shared.b", 0), "com.shared.b", processLookupFound},
		{"name declared twice", 10060, snapshotOf("shared.common", 0), "", processLookupMultiPackage},
		{"undeclared", 10060, snapshotOf("com.shared.c", 0), "", processLookupUndeclared},
		// Cut to 77 bytes: a's 78-byte name and b's differ only in the
		// last byte, so the prefix fits both.
		{"truncated ambiguous", 10060, snapshotOf(long, 77), "", processLookupMultiPackage},
		{"truncated unique", 10060, snapshotOf(long, 78), "com.shared.a", processLookupFound},
		{"system_server alias", 1000, snapshotOf("system_server", 0), "android", processLookupFound},
		{"system name in app UID", 10088, snapshotOf("system", 0), "com.miui.rom", processLookupFoundByUID},
		{"SDK sandbox, single-package host", 20050, snapshotOf("com.example.app_sdk_sandbox", 0), "com.example.app", processLookupFoundByUID},
		{"SDK sandbox, shared host", 20060, snapshotOf("com.shared.b_sdk_sandbox", 0), "com.shared.b", processLookupFound},
		{"SDK sandbox instrumentation", 20060, snapshotOf("com.shared.a_sdk_sandbox_instr", 0), "com.shared.a", processLookupFound},
		{"SDK sandbox, unknown host process", 20060, snapshotOf("com.shared.c_sdk_sandbox", 0), "", processLookupUndeclared},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, outcome := f.resolve(t, tc.uid, tc.process)
			if got != tc.want || outcome != tc.outcome {
				t.Fatalf("got %q outcome %d, want %q outcome %d", got, outcome, tc.want, tc.outcome)
			}
		})
	}
	// "system_server" is only an alias in UID 1000; in an app UID it is an
	// ordinary, undeclared name, even though com.shared.b declares "system"
	// (shared UID, so the UID alone cannot decide).
	if got, outcome := f.resolve(t, 10060, snapshotOf("system_server", 0)); got != "" || outcome != processLookupUndeclared {
		t.Fatalf("system_server outside UID 1000 = %q outcome %d", got, outcome)
	}
	if got, outcome := snapshotPackage(10060, snapshotOf("com.shared.a", 0), true,
		func(uint32) string { return "" }, nil); got != "" || outcome != processLookupPending {
		t.Fatalf("without an index = %q outcome %d", got, outcome)
	}
}

// A name lookup and a snapshot lookup for the same app ID must not share
// memo entries.
func TestSnapshotLookupMemoSeparateFromNames(t *testing.T) {
	f := newSnapshotFixture(t)
	if got := waitLookup(t, f.index, 10060, "com.shared.a:remote"); got != "com.shared.a" {
		t.Fatalf("name lookup = %q", got)
	}
	if got, _ := f.resolve(t, 10060, snapshotOf("com.shared.b", 0)); got != "com.shared.b" {
		t.Fatalf("snapshot lookup = %q", got)
	}
	if got := f.index.lookup(10060, "com.shared.a:remote"); got != "com.shared.a" {
		t.Fatalf("name lookup after snapshot lookup = %q", got)
	}
}

func v2Creator(owner SocketOwner, cookie uint64, name string, exeInode uint64) commonEBPF.SocketCreator {
	creator := commonEBPF.SocketCreator{
		Cookie: cookie, StartTimeNs: owner.StartTimeNs, ProcessID: owner.ProcessID,
		ThreadID: owner.ProcessID, UserID: owner.UserID, Flags: commonEBPF.SocketCreatorValid,
	}
	if name != "" {
		creator.ProcessNameHash = fnv1a64(name)
		creator.Flags |= commonEBPF.SocketCreatorNameValid | uint32(len(name))<<8
	}
	if exeInode != 0 {
		creator.ExeInode = exeInode
		creator.Flags |= commonEBPF.SocketCreatorExeValid
	}
	return creator
}

// The creation-time name decides the package without /proc: the creator
// may have exited, or its PID may now belong to another process.
func TestIdentityV2SnapshotNamesPackageAfterCreatorExit(t *testing.T) {
	tree := newFakeCgroupTree(t)
	group := tree.addProcess(t, "apps", 10060, 400, "/system/bin/app_process64")
	creator := tree.addCreator(t, 10060, 410, "/system/bin/app_process64", "com.shared.b", 100)
	writeCreatorCgroup(t, tree, 10060, 400, 410, "apps")
	inbound := newIdentityTestInbound(t, tree, nil)
	f := newSnapshotFixture(t)
	inbound.networkManager = &testNetworkManager{packageManager: f.packages}
	inbound.processIndex.Store(f.index)
	if got := waitLookup(t, f.index, 10060, "com.shared.a:remote"); got != "com.shared.a" {
		t.Fatalf("prepare index: %q", got)
	}
	// The process now running as PID 410 calls itself something else; it
	// must not matter, and neither must its disappearance.
	writeCmdline(t, tree, 410, "com.shared.a:remote")
	identity := socketIdentity{valid: true, cookie: 7, uid: 10060, cgroupID: group,
		creator: v2Creator(creator, 7, "com.shared.a:remote", 0)}
	owner := inbound.ownerFromIdentity(context.Background(), identity)
	if owner == nil || owner.ProcessID != 410 || !slices.Equal(owner.PackageNames, []string{"com.shared.a"}) {
		t.Fatalf("live creator: %+v", owner)
	}
	if err := os.RemoveAll(filepath.Join(tree.proc, "410")); err != nil {
		t.Fatal(err)
	}
	socketOwnerCache().Purge()
	owner = inbound.ownerFromIdentity(context.Background(), identity)
	if owner == nil || owner.ProcessID != 410 || !slices.Equal(owner.PackageNames, []string{"com.shared.a"}) {
		t.Fatalf("exited creator: %+v", owner)
	}
	if got := inbound.identityCounters.resolvedByProcess.Load(); got != 2 {
		t.Fatalf("resolved by process = %d, want 2", got)
	}

	identity.cookie, identity.creator = 8, v2Creator(creator, 8, "shared.common", 0)
	if owner = inbound.ownerFromIdentity(context.Background(), identity); len(owner.PackageNames) != 0 {
		t.Fatalf("name declared by two packages resolved: %+v", owner)
	}
	if inbound.identityCounters.multiPackageProcess.Load() != 1 {
		t.Fatal("multi-package outcome not counted")
	}
	identity.cookie, identity.creator = 9, v2Creator(creator, 9, "", 0)
	inbound.ownerFromIdentity(context.Background(), identity)
	if inbound.identityCounters.nameUnavailable.Load() != 1 {
		t.Fatal("snapshot without a name not counted")
	}
}

// A native creator's path is shown only while /proc/<pid>/exe is still the
// program that created the socket (same inode); after exec it is withheld.
func TestIdentityV2ExeInodeGuardsProcessPath(t *testing.T) {
	tree := newFakeCgroupTree(t)
	binaries := t.TempDir()
	daemon := filepath.Join(binaries, "daemon")
	replacement := filepath.Join(binaries, "replacement")
	for _, path := range []string{daemon, replacement} {
		if err := os.WriteFile(path, nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var stat unix.Stat_t
	if err := unix.Stat(daemon, &stat); err != nil {
		t.Fatal(err)
	}
	group := tree.addProcess(t, "system", 0, 200, daemon)
	creator := tree.addCreator(t, 0, 210, daemon, "daemon", 100)
	inbound := newIdentityTestInbound(t, tree, &testPackageManager{})
	identity := socketIdentity{valid: true, cookie: 5, uid: 0, cgroupID: group, creator: v2Creator(creator, 5, daemon, stat.Ino)}
	owner := inbound.ownerFromIdentity(context.Background(), identity)
	if owner == nil || !slices.Equal(owner.ProcessPaths, []string{daemon}) {
		t.Fatalf("matching exe inode: %+v", owner)
	}
	// exec: same PID and start time, different program. While the verified
	// entry for this (process, exe inode) is cached, the daemon path stays
	// correct for its sockets; a fresh check must withhold the new path.
	tree.addCreator(t, 0, 210, replacement, "replacement", 100)
	socketOwnerCache().Purge()
	identity.cookie, identity.creator = 6, v2Creator(creator, 6, daemon, stat.Ino)
	owner = inbound.ownerFromIdentity(context.Background(), identity)
	if owner == nil || slices.Contains(owner.ProcessPaths, replacement) {
		t.Fatalf("post-exec path shown for a pre-exec socket: %+v", owner)
	}
	if inbound.identityCounters.exeMismatch.Load() != 1 {
		t.Fatal("exe mismatch not counted")
	}
}

func TestRequesterUID(t *testing.T) {
	for _, tc := range []struct {
		name     string
		identity socketIdentity
		sender   uint32
		want     uint32
		differs  bool
	}{
		{"none", socketIdentity{valid: true, uid: 10050}, 10050, 0, false},
		{"netd charge for an app", socketIdentity{valid: true, uid: 1000, chargeValid: true, chargeUID: 10123}, 1000, 10123, true},
		{"charge equals sender", socketIdentity{valid: true, uid: 1000, chargeValid: true, chargeUID: 1000}, 1000, 0, false},
		{"fchown by netd", socketIdentity{valid: true, uid: 10123}, 1051, 10123, true},
		{"charge wins over sk_uid", socketIdentity{valid: true, uid: 10200, chargeValid: true, chargeUID: 10123}, 1000, 10123, true},
		{"no identity", socketIdentity{uid: 10123}, 1000, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, differs := tc.identity.requesterUID(tc.sender)
			if got != tc.want || differs != tc.differs {
				t.Fatalf("requester = %d %v, want %d %v", got, differs, tc.want, tc.differs)
			}
		})
	}
	identity := identityFromAssignment(commonEBPF.TCAssignment{
		SocketCookie: 1, ChargeUID: 10123, ChargeTag: 7,
		IdentityFlags: commonEBPF.TCIdentityChargeChecked | commonEBPF.TCIdentityChargeValid,
	})
	if !identity.chargeChecked || !identity.chargeValid || identity.chargeUID != 10123 {
		t.Fatalf("charge not carried from the assignment: %+v", identity)
	}
	if shared := identityFromAssignment(commonEBPF.TCAssignment{Path: commonEBPF.TCPathShared, ChargeUID: 1,
		IdentityFlags: commonEBPF.TCIdentityChargeValid}); shared.chargeValid {
		t.Fatal("shared-path assignment produced a requester")
	}
}
