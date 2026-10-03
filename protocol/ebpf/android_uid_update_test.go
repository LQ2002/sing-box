//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
)

type fakeUIDPolicyBackend struct {
	access          sync.Mutex
	calls           []uidPolicyDecisions
	failures        int
	requiresRebuild bool
	holding         uidPolicyDecisions
	updateStarted   chan struct{}
	resumeUpdates   <-chan struct{}
}

func (b *fakeUIDPolicyBackend) UpdateUIDPolicy(decisions []commonEBPF.UIDDecision, defaultAction commonEBPF.Decision) (bool, error) {
	b.access.Lock()
	defer b.access.Unlock()
	if b.resumeUpdates != nil {
		select {
		case b.updateStarted <- struct{}{}:
		default:
		}
		<-b.resumeUpdates
	}
	next := uidPolicyDecisions{decisions: slices.Clone(decisions), defaultAction: defaultAction}
	b.calls = append(b.calls, next)
	if b.failures > 0 {
		b.failures--
		return false, errors.New("injected UpdateUIDPolicy failure")
	}
	changed := !b.holding.equal(next)
	b.holding = next
	return changed, nil
}

func (b *fakeUIDPolicyBackend) RequiresRebuild() bool {
	b.access.Lock()
	defer b.access.Unlock()
	return b.requiresRebuild
}

func (b *fakeUIDPolicyBackend) callCount() int {
	b.access.Lock()
	defer b.access.Unlock()
	return len(b.calls)
}

func (b *fakeUIDPolicyBackend) last() uidPolicyDecisions {
	b.access.Lock()
	defer b.access.Unlock()
	return b.calls[len(b.calls)-1]
}

// updaterFixture drives an updater with a swappable package table and a
// captured subscription, without a real package manager or kernel.
type updaterFixture struct {
	inbound *Inbound
	backend *fakeUIDPolicyBackend
	table   atomic.Pointer[testPackageManager]
	notify  atomic.Pointer[func()]
}

func newUpdaterFixture(t *testing.T, startup *testPackageManager, options *androidUIDOptions, configuredInclude bool) *updaterFixture {
	t.Helper()
	fixture := &updaterFixture{backend: &fakeUIDPolicyBackend{}}
	fixture.table.Store(startup)
	inbound := &Inbound{
		logger:            log.NewNOPFactory().Logger(),
		localEnabled:      true,
		networkManager:    &testNetworkManager{packageManager: startup},
		androidUIDOptions: options,
		localPolicy:       localUIDPolicy{IncludeUIDConfigured: configuredInclude},
	}
	if err := inbound.resolveAndroidUIDPolicy(); err != nil {
		t.Fatal(err)
	}
	fixture.inbound = inbound
	fixture.backend.holding.decisions, fixture.backend.holding.defaultAction = compileUIDDecisions(inbound.localPolicy)
	snapshot := func() (tun.PackageManager, bool) { return fixture.table.Load(), true }
	subscribe := func(notify func()) func() {
		fixture.notify.Store(&notify)
		return func() { fixture.notify.Store(nil) }
	}
	inbound.runAndroidUIDUpdater(newAndroidUIDUpdater(inbound, snapshot, fixture.backend), subscribe)
	t.Cleanup(inbound.stopAndroidUIDUpdater)
	return fixture
}

// publish swaps the table and notifies, as androidpackages.Manager does.
func (f *updaterFixture) publish(table *testPackageManager) {
	f.table.Store(table)
	if notify := f.notify.Load(); notify != nil {
		(*notify)()
	}
}

func (f *updaterFixture) waitSettled(t *testing.T) *AndroidUIDPolicyDiagnostics {
	t.Helper()
	var status *AndroidUIDPolicyDiagnostics
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		status = f.inbound.androidUIDPolicyDiagnostics()
		if status != nil && status.InSync && len(f.inbound.androidUIDUpdater.signal) == 0 {
			// One more beat so an in-flight apply finishes.
			time.Sleep(20 * time.Millisecond)
			return f.inbound.androidUIDPolicyDiagnostics()
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("updater did not settle: %+v", status)
	return nil
}

func packageTable(packages map[string]uint32) *testPackageManager {
	table := &testPackageManager{idByPackage: map[string]uint32{}, packagesByID: map[uint32][]string{}}
	for name, uid := range packages {
		table.idByPackage[name] = uid
		table.packagesByID[uid] = append(table.packagesByID[uid], name)
	}
	return table
}

// interceptsUID evaluates decisions the way the data plane does for
// compiled, non-overlapping decisions: a matching decision's action, else the
// default.
func interceptsUID(decisions uidPolicyDecisions, uid uint32) bool {
	for _, decision := range decisions.decisions {
		if decision.Start <= uid && uid <= decision.End {
			return decision.Action == commonEBPF.DecisionIntercept
		}
	}
	return decisions.defaultAction == commonEBPF.DecisionIntercept
}

// An include_package app installed after startup is intercepted without a
// restart; a same-UID reinstall changes nothing in the kernel; uninstalling it
// leaves an empty include set (everything bypassed), not capture-all.
func TestAndroidUIDUpdaterFollowsInstallUpgradeUninstall(t *testing.T) {
	options := &androidUIDOptions{includePackage: []string{"com.example.app"}}
	f := newUpdaterFixture(t, packageTable(nil), options, true)
	f.waitSettled(t)
	if calls := f.backend.callCount(); calls != 0 {
		t.Fatalf("startup state was rewritten %d times", calls)
	}

	f.publish(packageTable(map[string]uint32{"com.example.app": 10050}))
	status := f.waitSettled(t)
	if f.backend.callCount() != 1 || !interceptsUID(f.backend.last(), 10050) || status.KernelUpdates != 1 {
		t.Fatalf("install not applied: calls=%d status=%+v", f.backend.callCount(), status)
	}

	// Reinstall/upgrade keeping the UID: recomputed, but no kernel write.
	f.publish(packageTable(map[string]uint32{"com.example.app": 10050, "com.other": 10060}))
	status = f.waitSettled(t)
	if f.backend.callCount() != 1 || status.Recomputations < 2 {
		t.Fatalf("unchanged decisions reached the kernel: calls=%d status=%+v", f.backend.callCount(), status)
	}

	f.publish(packageTable(map[string]uint32{"com.other": 10060}))
	f.waitSettled(t)
	last := f.backend.last()
	if f.backend.callCount() != 2 || len(last.decisions) != 0 || last.defaultAction != commonEBPF.DecisionPass {
		t.Fatalf("uninstall should leave an empty include set with default pass: %+v", last)
	}
	if interceptsUID(last, 10050) || interceptsUID(last, 10060) {
		t.Fatal("the uninstalled app's UID is still intercepted")
	}
}

func TestAndroidUIDUpdaterCoalescesBursts(t *testing.T) {
	options := &androidUIDOptions{includePackage: []string{"com.example.app"}}
	f := newUpdaterFixture(t, packageTable(nil), options, true)
	f.waitSettled(t)
	// Hold one actual write while publishing the burst. Without this gate,
	// the producer and consumer may interleave arbitrarily: a one-slot
	// notification queue does not promise at most N writes over wall time.
	entered := make(chan struct{}, 1)
	resume := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(resume) })
	t.Cleanup(unblock)
	f.backend.access.Lock()
	f.backend.updateStarted, f.backend.resumeUpdates = entered, resume
	f.backend.access.Unlock()
	f.publish(packageTable(map[string]uint32{"com.example.app": 10099}))
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first update did not enter backend")
	}
	for uid := uint32(10100); uid < 10150; uid++ {
		f.publish(packageTable(map[string]uint32{"com.example.app": uid}))
	}
	unblock()
	f.waitSettled(t)
	if calls := f.backend.callCount(); calls != 2 {
		t.Fatalf("one in-flight write plus a pending burst produced %d kernel updates, want 2", calls)
	}
	if !interceptsUID(f.backend.last(), 10149) || interceptsUID(f.backend.last(), 10148) {
		t.Fatalf("final state is not the last table: %+v", f.backend.last())
	}
}

// A failed update leaves Applied at the old rules (InSync false) and is
// retried on its own.
func TestAndroidUIDUpdaterRetriesFailures(t *testing.T) {
	previous := androidUIDRetryBackoff
	androidUIDRetryBackoff = []time.Duration{50 * time.Millisecond}
	t.Cleanup(func() { androidUIDRetryBackoff = previous })
	options := &androidUIDOptions{includePackage: []string{"com.example.app"}}
	f := newUpdaterFixture(t, packageTable(nil), options, true)
	f.waitSettled(t)
	f.backend.access.Lock()
	f.backend.failures = 1
	f.backend.access.Unlock()
	f.publish(packageTable(map[string]uint32{"com.example.app": 10050}))

	deadline := time.Now().Add(time.Second)
	sawPending := false
	for time.Now().Before(deadline) {
		status := f.inbound.androidUIDPolicyDiagnostics()
		if status.Failures == 1 && !status.InSync {
			sawPending = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !sawPending {
		t.Fatal("a failed update was not reported as out of sync")
	}
	status := f.waitSettled(t)
	if f.backend.callCount() != 2 || status.Failures != 1 || !interceptsUID(f.backend.last(), 10050) {
		t.Fatalf("retry did not apply the update: calls=%d status=%+v", f.backend.callCount(), status)
	}
}

// A backend that needs a rebuild refuses everything; the updater must not
// spin retrying it.
func TestAndroidUIDUpdaterStopsRetryingWhenBackendNeedsRebuild(t *testing.T) {
	previous := androidUIDRetryBackoff
	androidUIDRetryBackoff = []time.Duration{10 * time.Millisecond}
	t.Cleanup(func() { androidUIDRetryBackoff = previous })
	options := &androidUIDOptions{includePackage: []string{"com.example.app"}}
	f := newUpdaterFixture(t, packageTable(nil), options, true)
	f.waitSettled(t)
	f.backend.access.Lock()
	f.backend.failures = 1000
	f.backend.requiresRebuild = true
	f.backend.access.Unlock()
	f.publish(packageTable(map[string]uint32{"com.example.app": 10050}))
	time.Sleep(200 * time.Millisecond)
	if calls := f.backend.callCount(); calls != 1 {
		t.Fatalf("updater retried a backend that requires a rebuild %d times", calls)
	}
	if status := f.inbound.androidUIDPolicyDiagnostics(); status.InSync {
		t.Fatal("diagnostics claim the update is in effect")
	}
}

// exclude_package inside an included range wins on the update path too.
func TestAndroidUIDUpdaterKeepsExcludePrecedence(t *testing.T) {
	options := &androidUIDOptions{
		configuredIncludeUID: []uidRange{{Start: 10000, End: 19999}},
		configuredCaptured:   true,
		excludePackage:       []string{"com.example.excluded"},
	}
	f := newUpdaterFixture(t, packageTable(nil), options, true)
	f.waitSettled(t)
	f.publish(packageTable(map[string]uint32{"com.example.excluded": 10077}))
	f.waitSettled(t)
	last := f.backend.last()
	if interceptsUID(last, 10077) || !interceptsUID(last, 10076) || !interceptsUID(last, 10078) {
		t.Fatalf("excluded package is not carved out of the include range: %+v", last)
	}
}

func TestAndroidUIDUpdaterStopsCleanly(t *testing.T) {
	options := &androidUIDOptions{includePackage: []string{"com.example.app"}}
	f := newUpdaterFixture(t, packageTable(nil), options, true)
	f.waitSettled(t)
	f.inbound.stopAndroidUIDUpdater()
	if f.notify.Load() != nil {
		t.Fatal("subscription survived stop")
	}
	f.table.Store(packageTable(map[string]uint32{"com.example.app": 10050}))
	time.Sleep(50 * time.Millisecond)
	if calls := f.backend.callCount(); calls != 0 {
		t.Fatalf("stopped updater still wrote the kernel %d times", calls)
	}
	if f.inbound.androidUIDPolicyDiagnostics() != nil {
		t.Fatal("stopped updater still reports diagnostics")
	}
}
