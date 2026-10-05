//go:build with_ebpf && (linux || android)

package ebpf

// Package-driven UID rule updates (ANDROID_ATTRIBUTION_PLAN.md stage 3).
//
// include_package / exclude_package are resolved to UIDs. Before this file
// they were resolved once at startup, so a package installed later was never
// intercepted (or excluded) and an uninstalled one kept its UID in the rules
// until restart. Now every published package table drives the same pure
// resolution startup uses (resolveAndroidUIDRanges + compileUIDDecisions),
// and the TC backend is updated in place with UpdateUIDPolicy only when the
// final decisions differ from what the kernel already holds.
//
// Efficiency: the package manager's notification only drops a token into a
// one-slot channel, so a burst of package writes collapses into one
// recomputation, and the recomputation never touches the kernel unless the
// decisions changed (a same-UID upgrade, for example, changes nothing).
// All kernel writes happen on one goroutine, so updates are serialised.
//
// Only the TC data plane can be updated in place (sing-ebpf has no hot update
// for the cgroup backend's UID policy); with the cgroup data plane, package
// changes are reported as needing a restart instead of being applied.

import (
	"slices"
	"sync"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/common/androidpackages"
	"github.com/sagernet/sing-tun"
)

// androidPackageSource is what the updater needs from the package manager:
// a consistent table per computation, and a change notification.
type androidPackageSource interface {
	Snapshot() androidpackages.View
	Subscribe(notify func()) (cancel func())
}

var androidUIDRetryBackoff = []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second}

// AndroidUIDPolicyDiagnostics separates the rules the package table asks for
// (Target) from the rules the kernel holds (Applied). They differ while an
// update is pending or after a failure; InSync is false then, so the
// diagnostics never claim a rule is in effect before UpdateUIDPolicy
// returned success for it.
type AndroidUIDPolicyDiagnostics struct {
	Following       bool       `json:"following_package_changes"`
	InSync          bool       `json:"in_sync"`
	TargetRanges    int        `json:"target_ranges"`
	AppliedRanges   int        `json:"applied_ranges"`
	TargetDefault   string     `json:"target_default"`
	AppliedDefault  string     `json:"applied_default"`
	Recomputations  uint64     `json:"recomputations"`
	KernelUpdates   uint64     `json:"kernel_updates"`
	Failures        uint64     `json:"failures"`
	LastError       string     `json:"last_error,omitempty"`
	LastErrorAt     *time.Time `json:"last_error_at,omitempty"`
	LastUpdateAt    *time.Time `json:"last_update_at,omitempty"`
	RestartRequired bool       `json:"restart_required"`
}

type uidPolicyDecisions struct {
	decisions     []commonEBPF.UIDDecision
	defaultAction commonEBPF.Decision
}

func (d uidPolicyDecisions) equal(other uidPolicyDecisions) bool {
	return d.defaultAction == other.defaultAction && slices.Equal(d.decisions, other.decisions)
}

// uidPolicyBackend is the part of *commonEBPF.TCBackend the updater uses.
type uidPolicyBackend interface {
	UpdateUIDPolicy(decisions []commonEBPF.UIDDecision, defaultAction commonEBPF.Decision) (bool, error)
	RequiresRebuild() bool
}

type androidUIDUpdater struct {
	inbound *Inbound
	// snapshot returns one consistent package table, or false before the
	// first table was read.
	snapshot func() (tun.PackageManager, bool)
	// backend is nil when the local data plane is cgroup: then changes are
	// only reported.
	backend uidPolicyBackend
	base    localUIDPolicy

	cancel   func()
	signal   chan struct{}
	done     chan struct{}
	finished chan struct{}

	access sync.Mutex
	status AndroidUIDPolicyDiagnostics
	target uidPolicyDecisions
	// applied is what the kernel holds: the startup decisions until an
	// update succeeds.
	applied uidPolicyDecisions
}

// followsAndroidPackageChanges reports whether this inbound's local UID rules
// depend on the package table, i.e. whether there is anything to follow.
func (i *Inbound) followsAndroidPackageChanges() bool {
	return i.localEnabled && i.androidUIDOptions != nil &&
		len(i.androidUIDOptions.includePackage)+len(i.androidUIDOptions.excludePackage) > 0
}

// startAndroidUIDUpdater runs at the end of startInbound, after the backend
// holds the startup decisions.
func (i *Inbound) startAndroidUIDUpdater(backend *commonEBPF.TCBackend) {
	if !i.followsAndroidPackageChanges() || i.networkManager == nil {
		return
	}
	source, loaded := i.networkManager.PackageManager().(androidPackageSource)
	if !loaded {
		i.logger.Warn("Android package manager cannot report changes; include_package/exclude_package apply only at startup")
		return
	}
	var policyBackend uidPolicyBackend
	if backend != nil {
		policyBackend = backend
	} else {
		i.logger.Warn("the cgroup eBPF data plane cannot update UID rules in place; package changes that affect include_package/exclude_package need a restart")
	}
	snapshot := func() (tun.PackageManager, bool) {
		view := source.Snapshot()
		return view, view.Loaded()
	}
	i.runAndroidUIDUpdater(newAndroidUIDUpdater(i, snapshot, policyBackend), source.Subscribe)
}

func newAndroidUIDUpdater(i *Inbound, snapshot func() (tun.PackageManager, bool), backend uidPolicyBackend) *androidUIDUpdater {
	startup := uidPolicyDecisions{}
	startup.decisions, startup.defaultAction = compileUIDDecisions(i.localPolicy)
	updater := &androidUIDUpdater{
		inbound:  i,
		snapshot: snapshot,
		backend:  backend,
		base:     localUIDPolicy{IncludeUIDConfigured: i.localPolicy.IncludeUIDConfigured},
		signal:   make(chan struct{}, 1),
		done:     make(chan struct{}),
		finished: make(chan struct{}),
		target:   startup,
		applied:  startup,
	}
	updater.status.Following = true
	return updater
}

func (i *Inbound) runAndroidUIDUpdater(updater *androidUIDUpdater, subscribe func(func()) func()) {
	i.androidUIDUpdaterAccess.Lock()
	i.androidUIDUpdater = updater
	i.androidUIDUpdaterAccess.Unlock()
	updater.cancel = subscribe(updater.notify)
	go updater.loop()
	// A change published between the startup resolution and Subscribe would
	// otherwise wait for the next one.
	updater.notify()
}

func (i *Inbound) stopAndroidUIDUpdater() {
	i.androidUIDUpdaterAccess.Lock()
	updater := i.androidUIDUpdater
	i.androidUIDUpdater = nil
	i.androidUIDUpdaterAccess.Unlock()
	if updater == nil {
		return
	}
	updater.cancel()
	close(updater.done)
	<-updater.finished
}

func (i *Inbound) androidUIDPolicyDiagnostics() *AndroidUIDPolicyDiagnostics {
	i.androidUIDUpdaterAccess.Lock()
	updater := i.androidUIDUpdater
	i.androidUIDUpdaterAccess.Unlock()
	if updater == nil {
		return nil
	}
	return updater.diagnostics()
}

// notify is called on the package manager's goroutine; it must not block.
func (u *androidUIDUpdater) notify() {
	select {
	case u.signal <- struct{}{}:
	default:
	}
}

func (u *androidUIDUpdater) loop() {
	defer close(u.finished)
	retry := time.NewTimer(time.Hour)
	retry.Stop()
	defer retry.Stop()
	failures := 0
	for {
		select {
		case <-u.done:
			return
		case <-u.signal:
		case <-retry.C:
		}
		if u.apply() {
			failures = 0
			retry.Stop()
			continue
		}
		delay := androidUIDRetryBackoff[min(failures, len(androidUIDRetryBackoff)-1)]
		failures++
		retry.Reset(delay)
	}
}

// apply recomputes the target from one package table and pushes it to the
// kernel if it differs from what is applied. It reports false only for a
// failure worth retrying.
func (u *androidUIDUpdater) apply() bool {
	view, loaded := u.snapshot()
	if !loaded {
		return true
	}
	policy := u.base
	policy.IncludeUID, policy.ExcludeUID = resolveAndroidUIDRanges(u.inbound.androidUIDOptions, view, nil)
	target := uidPolicyDecisions{}
	target.decisions, target.defaultAction = compileUIDDecisions(policy)

	u.access.Lock()
	u.target = target
	u.status.Recomputations++
	applied := u.applied
	u.access.Unlock()
	if target.equal(applied) {
		return true
	}
	if u.backend == nil {
		u.access.Lock()
		u.status.RestartRequired = true
		u.access.Unlock()
		return true
	}
	changed, err := u.backend.UpdateUIDPolicy(target.decisions, target.defaultAction)
	now := time.Now()
	u.access.Lock()
	defer u.access.Unlock()
	if err != nil {
		u.status.Failures++
		u.status.LastError = err.Error()
		u.status.LastErrorAt = &now
		u.inbound.logger.Warn("update eBPF UID rules after a package change: ", err)
		// A backend that needs a rebuild refuses every operation; retrying
		// would only repeat the error. The TC health machinery reports it.
		return u.backend.RequiresRebuild()
	}
	u.applied = target
	u.status.LastUpdateAt = &now
	if changed {
		u.status.KernelUpdates++
		u.inbound.logger.Info("eBPF UID rules follow the package table: ",
			len(target.decisions), " UID range(s), default ", decisionName(target.defaultAction))
	}
	return true
}

func (u *androidUIDUpdater) diagnostics() *AndroidUIDPolicyDiagnostics {
	u.access.Lock()
	defer u.access.Unlock()
	status := u.status
	status.TargetRanges = len(u.target.decisions)
	status.AppliedRanges = len(u.applied.decisions)
	status.TargetDefault = decisionName(u.target.defaultAction)
	status.AppliedDefault = decisionName(u.applied.defaultAction)
	status.InSync = u.target.equal(u.applied)
	return &status
}

func decisionName(decision commonEBPF.Decision) string {
	if decision == commonEBPF.DecisionPass {
		return "pass"
	}
	return "intercept"
}
