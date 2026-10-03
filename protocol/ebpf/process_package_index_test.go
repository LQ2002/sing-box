//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/androidpackages"
)

type fakeProcessTable struct {
	packages map[uint32][]string
	code     map[string]androidpackages.PackageCode
}

func (t *fakeProcessTable) Loaded() bool { return true }
func (t *fakeProcessTable) PackagesByID(id uint32) ([]string, bool) {
	names, loaded := t.packages[id]
	return names, loaded
}
func (t *fakeProcessTable) PackageCode(name string) (androidpackages.PackageCode, bool) {
	code, loaded := t.code[name]
	return code, loaded
}

type fakeManifests struct {
	access    sync.Mutex
	processes map[string][]string // codePath -> processes
	failing   map[string]bool
	reads     atomic.Int32
}

func (m *fakeManifests) read(_ string, codePath string) ([]string, error) {
	m.reads.Add(1)
	m.access.Lock()
	defer m.access.Unlock()
	if m.failing[codePath] {
		return nil, errors.New("unreadable")
	}
	return m.processes[codePath], nil
}

func newTestIndex(t *testing.T, table *atomic.Pointer[fakeProcessTable], manifests *fakeManifests) *processPackageIndex {
	t.Helper()
	index := newProcessPackageIndex(func() processPackageTable { return table.Load() }, nil)
	index.readPackage = manifests.read
	index.start()
	t.Cleanup(index.close)
	return index
}

func waitLookup(t *testing.T, index *processPackageIndex, appID uint32, name string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		result := index.lookup(appID, name) // queues the UID when incomplete
		index.access.Lock()
		building := index.queued[appID]
		index.access.Unlock()
		if !building {
			return index.lookup(appID, name)
		}
		_ = result
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("index did not settle")
	return ""
}

// The shapes measured on the phone: a process declared by one package of a
// shared UID resolves; one declared by several ("system", "com.android.phone")
// stays unknown; an unreadable package makes the answer unknown rather than
// silently excluding it; an upgrade is re-read.
func TestProcessPackageIndex(t *testing.T) {
	table := &atomic.Pointer[fakeProcessTable]{}
	table.Store(&fakeProcessTable{
		packages: map[uint32][]string{1000: {"android", "com.android.settings", "com.miui.securitycenter"}},
		code: map[string]androidpackages.PackageCode{
			"android":                 {Path: "/system/framework", Stamp: "1"},
			"com.android.settings":    {Path: "/system/priv-app/Settings", Stamp: "1"},
			"com.miui.securitycenter": {Path: "/product/priv-app/SC", Stamp: "1"},
		},
	})
	manifests := &fakeManifests{
		processes: map[string][]string{
			"/system/framework":         {"system"},
			"/system/priv-app/Settings": {"system", "com.android.settings"},
			"/product/priv-app/SC":      {"com.miui.securitycenter.remote"},
		},
		failing: map[string]bool{},
	}
	index := newTestIndex(t, table, manifests)

	// Not indexed yet: unknown now, never blocks, queues the UID.
	if got := index.lookup(1000, "com.miui.securitycenter.remote"); got != "" {
		t.Fatalf("an unindexed UID resolved to %q", got)
	}
	if got := waitLookup(t, index, 1000, "com.miui.securitycenter.remote"); got != "com.miui.securitycenter" {
		t.Fatalf("unique process = %q", got)
	}
	if got := index.lookup(1000, "system"); got != "" {
		t.Fatalf("a process several packages declare resolved to %q", got)
	}
	if got := index.lookup(1000, "undeclared"); got != "" {
		t.Fatalf("an undeclared process resolved to %q", got)
	}
	reads := manifests.reads.Load()
	for range 100 {
		index.lookup(1000, "com.miui.securitycenter.remote")
	}
	if manifests.reads.Load() != reads {
		t.Fatal("lookups re-read manifests")
	}

	// Upgrade of securitycenter: a new stamp is re-read, and its new process
	// name takes effect; the other packages are not re-read.
	manifests.access.Lock()
	manifests.processes["/product/priv-app/SC"] = []string{"com.miui.securitycenter.remote2"}
	manifests.access.Unlock()
	next := *table.Load()
	next.code = map[string]androidpackages.PackageCode{
		"android":                 {Path: "/system/framework", Stamp: "1"},
		"com.android.settings":    {Path: "/system/priv-app/Settings", Stamp: "1"},
		"com.miui.securitycenter": {Path: "/product/priv-app/SC", Stamp: "2"},
	}
	table.Store(&next)
	if got := waitLookup(t, index, 1000, "com.miui.securitycenter.remote2"); got != "com.miui.securitycenter" {
		t.Fatalf("after upgrade = %q", got)
	}
	if got := index.lookup(1000, "com.miui.securitycenter.remote"); got != "" {
		t.Fatalf("the old process name survived the upgrade: %q", got)
	}
	if delta := manifests.reads.Load() - reads; delta != 1 {
		t.Fatalf("upgrade re-read %d packages, want 1", delta)
	}

	// An unreadable package might declare the name: unknown.
	manifests.access.Lock()
	manifests.failing["/system/priv-app/Settings"] = true
	manifests.access.Unlock()
	next2 := next
	next2.code = map[string]androidpackages.PackageCode{
		"android":                 {Path: "/system/framework", Stamp: "1"},
		"com.android.settings":    {Path: "/system/priv-app/Settings", Stamp: "3"},
		"com.miui.securitycenter": {Path: "/product/priv-app/SC", Stamp: "2"},
	}
	table.Store(&next2)
	waitLookup(t, index, 1000, "com.miui.securitycenter.remote2")
	if got := index.lookup(1000, "com.miui.securitycenter.remote2"); got != "" {
		t.Fatalf("resolved %q although a package of the UID could not be read", got)
	}
}

// End to end through ownerFromIdentity: a shared-UID process named by the
// manifest index, and system_server, whose cmdline differs from its record
// name, staying unknown because several packages declare "system".
func TestOwnerFromIdentityUsesProcessIndex(t *testing.T) {
	tree := newFakeCgroupTree(t)
	securityCenter := tree.addProcess(t, "system", 1000, 400, "/system/bin/app_process64")
	systemServer := tree.addProcess(t, "system", 1000, 401, "/system/bin/app_process64")
	writeCmdline(t, tree, 400, "com.miui.securitycenter.remote")
	writeCmdline(t, tree, 401, "system_server")
	packages := &testPackageManager{
		idByPackage:     map[string]uint32{"android": 1000, "com.miui.securitycenter": 1000},
		packagesByID:    map[uint32][]string{1000: {"android", "com.miui.securitycenter"}},
		sharedPackageID: map[uint32]string{1000: "android.uid.system"},
	}
	inbound := newIdentityTestInbound(t, tree, packages)
	table := &atomic.Pointer[fakeProcessTable]{}
	table.Store(&fakeProcessTable{
		packages: map[uint32][]string{1000: {"android", "com.miui.securitycenter"}},
		code: map[string]androidpackages.PackageCode{
			"android": {Path: "a", Stamp: "1"}, "com.miui.securitycenter": {Path: "s", Stamp: "1"},
		},
	})
	manifests := &fakeManifests{processes: map[string][]string{
		"a": {"system"}, "s": {"com.miui.securitycenter.remote", "system"},
	}}
	index := newTestIndex(t, table, manifests)
	inbound.processIndex.Store(index)
	ctx := context.Background()

	inbound.ownerFromIdentity(ctx, socketIdentity{valid: true, uid: 1000, cgroupID: securityCenter})
	waitLookup(t, index, 1000, "com.miui.securitycenter.remote")
	owner := inbound.ownerFromIdentity(ctx, socketIdentity{valid: true, uid: 1000, cgroupID: securityCenter})
	if len(owner.PackageNames) != 1 || owner.PackageNames[0] != "com.miui.securitycenter" || owner.ProcessID != 400 {
		t.Fatalf("securitycenter.remote owner = %+v", owner)
	}
	owner = inbound.ownerFromIdentity(ctx, socketIdentity{valid: true, uid: 1000, cgroupID: systemServer})
	if len(owner.PackageNames) != 0 || owner.ProcessID != 401 {
		t.Fatalf("system_server must stay unknown: %+v", owner)
	}
	if inbound.identityCounters.resolvedByProcess.Load() != 1 {
		t.Fatalf("resolvedByProcess = %d", inbound.identityCounters.resolvedByProcess.Load())
	}
}
