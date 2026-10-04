//go:build with_ebpf && (linux || android)

package ebpf

// Attribution from the socket identity the TC local egress program records
// (sing-ebpf TCConfig.RecordSocketIdentity): the socket's UID (sk_uid) and
// the cgroup v2 id it was created in. ANDROID_ATTRIBUTION_PLAN.md stage 3.
//
// Android's /apps/uid_X/pid_Y and /system/uid_X/pid_Y directories identify
// process GROUPS, not socket creators: forked children inherit the group,
// and other processes can migrate into it. The directory PID must never
// become ConnectionOwner.ProcessID or be used to read exe/cmdline.
//
// An ordinary app can still be named at UID/group level when the socket UID
// agrees with the group's UID and that UID maps to one package. This fast
// path supplies a PID only when the assignment carries a creation snapshot;
// it never reads an executable. Precise creator metadata and shared/system
// UID refinement use that snapshot or the optional cookie owner source.
// A disagreement (for example netd fchown()ing an app's DNS socket) never
// attributes the connection to the socket UID's package without that source.
//
// Cost: an ordinary app needs one cache lookup per connection after its
// first one. A cgroup id is resolved once: first by listing the one
// directory sk_uid points at (a few entries), and only if that misses (sk_uid
// changed by fchown) by one scan of the uid directories. There is no
// per-connection /proc access for the ordinary app fast path. Resolution by file handle
// (open_by_handle_at on the kernfs id) would be O(1), but the test device's
// GKI kernel is built without CONFIG_FHANDLE (ENOSYS; checked in
// /proc/config.gz).

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/androidpackages"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
	"golang.org/x/sys/unix"
)

const (
	cgroupRoot                = "/sys/fs/cgroup"
	rootCgroupID              = 1
	cgroupOwnerCacheCapacity  = 4096
	cgroupOwnerLifetime       = 10 * time.Minute
	cgroupOwnerMissedLifetime = 2 * time.Second
)

// socketIdentity is what the data plane recorded for one flow.
type socketIdentity struct {
	cookie   uint64
	uid      uint32
	cgroupID uint64
	valid    bool
	creator  commonEBPF.SocketCreator
	// netd's cookie_tag_map entry, read by TC once per cookie. chargeChecked
	// without chargeValid means netd had no tag; without chargeChecked the
	// lookup never ran (no creator variant, or no full-socket packet yet).
	chargeChecked bool
	chargeValid   bool
	chargeUID     uint32
}

func identityFromAssignment(assignment commonEBPF.TCAssignment) socketIdentity {
	// Downstream packets do not originate from a local socket. Never consume
	// even malformed/stale creator fields on the shared path.
	if assignment.Path == commonEBPF.TCPathShared {
		return socketIdentity{}
	}
	return socketIdentity{
		cookie:   assignment.SocketCookie,
		uid:      assignment.SocketUID,
		cgroupID: assignment.SocketCgroupID,
		valid:    assignment.HasSocketIdentity(),
		creator:  assignment.Creator,

		chargeChecked: assignment.IdentityFlags&commonEBPF.TCIdentityChargeChecked != 0,
		chargeValid:   assignment.HasCharge(),
		chargeUID:     assignment.ChargeUID,
	}
}

// requesterUID names the UID a socket works for when that differs from its
// sender: netd's charge UID (a service tagging its socket for an app, which
// netd allows only with UPDATE_DEVICE_STATS, Connectivity BpfHandler.cpp
// tagSocket), else the socket UID when something privileged fchown()ed it
// (netd's DNS sockets for an app). It is diagnostic only: the user routes by
// the sending process (ANDROID_ATTRIBUTION_PLAN.md decision 1), so the
// requester never enters ConnectionOwner.
func (identity socketIdentity) requesterUID(senderUID uint32) (uint32, bool) {
	if identity.chargeValid && identity.chargeUID != senderUID {
		return identity.chargeUID, true
	}
	if identity.valid && identity.uid != senderUID {
		return identity.uid, true
	}
	return 0, false
}

func (identity socketIdentity) hasCreator() bool {
	return identity.creator.IsValid() && identity.creator.Cookie == identity.cookie
}

// cgroupOwner is an Android process cgroup .../uid_<uid>/pid_<pid>. uid is
// the directory's label (init services are all labelled uid_0, whatever they
// run as), pid the process the directory was created for. Whether that
// process created a given socket is decided in ownerFromProcessCgroup.
type cgroupOwner struct {
	found bool
	uid   uint32
	pid   uint32
	// Set once ownerFromProcessCgroup has checked the directory's process
	// against /proc: its UID and start time. A cgroup ID is never reused
	// within a boot, so this stays true for the directory's lifetime.
	procVerified bool
	procUID      uint32
	procStartNs  uint64
	// logged and loggedPackage remember what was last logged for this
	// group. Cookie-derived creator metadata is never cached here.
	logged        bool
	loggedPackage string
}

type cgroupOwnerResolver struct {
	cache *freelru.Cache[uint64, cgroupOwner]
	// scanAccess serialises directory scans, so a burst of new connections
	// from one new process scans once.
	scanAccess sync.Mutex
	// scanRoot is cgroupRoot outside tests.
	scanRoot string
}

func newCgroupOwnerResolver(root string) *cgroupOwnerResolver {
	cache, err := freelru.New[uint64, cgroupOwner](cgroupOwnerCacheCapacity, maphash.NewHasher[uint64]().Hash32, true)
	if err != nil {
		return nil
	}
	cache.SetLifetime(cgroupOwnerLifetime)
	return &cgroupOwnerResolver{cache: cache, scanRoot: root}
}

// lookup returns the Android UID label for cgroup id, using uidHint (sk_uid)
// to pick the first directory to look in.
func (r *cgroupOwnerResolver) lookup(cgroupID uint64, uidHint uint32) cgroupOwner {
	owner, loaded := r.cache.Get(cgroupID)
	if !loaded {
		owner = r.scan(cgroupID, uidHint)
	}
	return owner
}

// markLogged reports whether the attribution of this UID group should
// be logged now: the first time, or when its package changed since. Entries
// are updated without a lock; a race can only log a line twice.
func (r *cgroupOwnerResolver) markLogged(cgroupID uint64, packageName string) bool {
	owner, loaded := r.cache.Peek(cgroupID)
	if !loaded || !owner.found || (owner.logged && owner.loggedPackage == packageName) {
		return false
	}
	owner.logged = true
	owner.loggedPackage = packageName
	r.cache.Add(cgroupID, owner)
	return true
}

func (r *cgroupOwnerResolver) scan(cgroupID uint64, uidHint uint32) cgroupOwner {
	r.scanAccess.Lock()
	defer r.scanAccess.Unlock()
	if owner, loaded := r.cache.Get(cgroupID); loaded {
		return owner
	}
	for _, kind := range []string{"apps", "system"} {
		if owner, found := r.scanUIDDirectory(kind, "uid_"+strconv.FormatUint(uint64(uidHint), 10), uidHint, cgroupID); found {
			return owner
		}
	}
	for _, kind := range []string{"apps", "system"} {
		entries, err := os.ReadDir(filepath.Join(r.scanRoot, kind))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			uid, ok := parseCgroupComponent(entry.Name(), "uid_")
			if !ok || uid == uidHint {
				continue
			}
			if owner, found := r.scanUIDDirectory(kind, entry.Name(), uid, cgroupID); found {
				return owner
			}
		}
	}
	// Gone (the process exited between the packet and this lookup) or not
	// an Android process cgroup. Remember briefly, so a closing app's last
	// connections do not each rescan.
	r.cache.AddWithLifetime(cgroupID, cgroupOwner{}, cgroupOwnerMissedLifetime)
	return cgroupOwner{}
}

// scanUIDDirectory caches every process cgroup under one uid directory and
// reports whether target was among them. Caching the siblings costs one stat
// each and saves a scan when the app's other processes connect.
func (r *cgroupOwnerResolver) scanUIDDirectory(kind, uidDir string, uid uint32, target uint64) (cgroupOwner, bool) {
	dir := filepath.Join(r.scanRoot, kind, uidDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return cgroupOwner{}, false
	}
	var result cgroupOwner
	found := false
	for _, entry := range entries {
		pid, ok := parseCgroupComponent(entry.Name(), "pid_")
		if !ok {
			continue
		}
		var stat unix.Stat_t
		if unix.Stat(filepath.Join(dir, entry.Name()), &stat) != nil {
			continue
		}
		if _, loaded := r.cache.Peek(stat.Ino); loaded && stat.Ino != target {
			continue
		}
		owner := cgroupOwner{found: true, uid: uid, pid: pid}
		r.cache.Add(stat.Ino, owner)
		if stat.Ino == target {
			result, found = owner, true
		}
	}
	return result, found
}

func parseCgroupComponent(name, prefix string) (uint32, bool) {
	digits, ok := strings.CutPrefix(name, prefix)
	if !ok {
		return 0, false
	}
	value, err := strconv.ParseUint(digits, 10, 32)
	return uint32(value), err == nil
}

// Reasons an identity did not yield a package, counted for diagnostics.
type identityCounters struct {
	resolvedPackage atomic.Uint64
	// resolvedByProcess counts shared/system UID processes named through
	// the (process name, UID) manifest index.
	resolvedByProcess atomic.Uint64
	// resolvedByCgroupProcess counts flows without a snapshot attributed to
	// the process their cgroup was created for (the producer skips sockets
	// whose creator is that process).
	resolvedByCgroupProcess atomic.Uint64
	cgroupProcessGone       atomic.Uint64
	noIdentity              atomic.Uint64
	rootCgroup              atomic.Uint64
	cgroupGone              atomic.Uint64
	// unknownPackage counts flows with no package result (including absent
	// creator evidence, shared processes, and native daemons).
	unknownPackage atomic.Uint64
	// creatorUnavailable counts flows needing a cookie creator record for
	// which the optional source is absent or has no matching record.
	creatorUnavailable atomic.Uint64
	uidMismatch        atomic.Uint64
	creatorSnapshots   atomic.Uint64
	creatorMissing     atomic.Uint64
	creatorInvalid     atomic.Uint64
	creatorFallbacks   atomic.Uint64
	// v2 snapshot outcomes (creator_snapshot.go): why a recorded name did
	// not single out a package, a snapshot without a readable name, and a
	// creator that exec'd after creating the socket (path withheld).
	multiPackageProcess atomic.Uint64
	undeclaredProcess   atomic.Uint64
	indexFailedLookups  atomic.Uint64
	indexPendingLookups atomic.Uint64
	nameUnavailable     atomic.Uint64
	exeMismatch         atomic.Uint64
	// netd cookie_tag_map charge (the requester) as recorded by TC.
	chargeChecked    atomic.Uint64
	chargeFound      atomic.Uint64
	requesterDiffers atomic.Uint64
}

var userNameCache sync.Map // uint32 -> string

func cachedUserName(uid uint32) string {
	if name, loaded := userNameCache.Load(uid); loaded {
		return name.(string)
	}
	name, ok := androidUserName(uid)
	if !ok {
		if osUser, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
			name = osUser.Username
		}
	}
	userNameCache.Store(uid, name)
	return name
}

// androidUserName names app and isolated UIDs the way bionic's getpwuid does
// (libc/bionic/grp_pwd.cpp print_app_name_from_uid): u<user>_a<n> for app
// ids 10000-19999 and u<user>_i<n> for isolated ids 90000-99999; other
// ranges (SDK sandbox included) have no passwd entry there.
//
// Go cannot ask bionic: os/user is not implemented on android whether or not
// cgo is enabled (src/os/user/lookup_android.go; the cgo implementation is
// built with !android). LookupId only succeeds for the current user, which
// is why only root ever resolved. The names are a pure function of the UID,
// so computing them costs nothing.
func androidUserName(uid uint32) (string, bool) {
	if runtime.GOOS != "android" {
		return "", false
	}
	user, appID := uid/androidUserRange, uid%androidUserRange
	switch {
	case appID >= 10000 && appID <= 19999:
		return "u" + strconv.FormatUint(uint64(user), 10) + "_a" + strconv.FormatUint(uint64(appID-10000), 10), true
	case appID >= 90000 && appID <= 99999:
		return "u" + strconv.FormatUint(uint64(user), 10) + "_i" + strconv.FormatUint(uint64(appID-90000), 10), true
	}
	return "", false
}

// ownerFromIdentity is the stage 3 attribution. It never returns nil: an
// unknown owner must still be a non-nil ConnectionOwner, or
// Router.searchProcessInfo would fill in the whole candidate package list of
// a shared UID.
func (i *Inbound) ownerFromIdentity(ctx context.Context, identity socketIdentity) *adapter.ConnectionOwner {
	hasCreator := identity.hasCreator()
	if identity.chargeChecked {
		i.identityCounters.chargeChecked.Add(1)
		if identity.chargeValid {
			i.identityCounters.chargeFound.Add(1)
		}
	}
	if hasCreator {
		i.identityCounters.creatorSnapshots.Add(1)
		if !identity.creator.HasProcessName() {
			i.identityCounters.nameUnavailable.Add(1)
		}
		if requester, differs := identity.requesterUID(identity.creator.UserID); differs {
			i.identityCounters.requesterDiffers.Add(1)
			i.logger.DebugContext(ctx, "socket of uid ", identity.creator.UserID, " works for uid ", requester,
				" (", i.packageForApplicationUID(requester), "); routed by the sender")
		}
	} else if identity.creator.Flags != 0 {
		i.identityCounters.creatorInvalid.Add(1)
	} else if i.socketCreatorActive.Load() && identity.cookie != 0 {
		i.identityCounters.creatorMissing.Add(1)
	}
	if !identity.valid {
		i.identityCounters.noIdentity.Add(1)
		return i.creatorFromIdentity(ctx, identity)
	}
	var group cgroupOwner
	resolver := i.cgroupOwners.Load()
	if identity.cgroupID == rootCgroupID {
		i.identityCounters.rootCgroup.Add(1)
	} else {
		if resolver != nil {
			group = resolver.lookup(identity.cgroupID, identity.uid)
		}
		if !group.found {
			i.identityCounters.cgroupGone.Add(1)
		}
	}
	if group.found && group.uid == identity.uid && (!hasCreator || identity.creator.UserID == group.uid) {
		if packageName := i.packageForApplicationUID(group.uid); packageName != "" {
			// UID-level package attribution. A creation snapshot may supply
			// the PID; a group directory must never supply PID or executable.
			owner := &adapter.ConnectionOwner{
				UserId: int32(group.uid), UserName: cachedUserName(group.uid),
				PackageNames: []string{packageName},
			}
			if hasCreator {
				owner.ProcessID = identity.creator.ProcessID
			}
			i.identityCounters.resolvedPackage.Add(1)
			if resolver.markLogged(identity.cgroupID, packageName) {
				logResolvedOwner(ctx, i.logger, owner)
			}
			return owner
		}
	} else if group.found {
		i.identityCounters.uidMismatch.Add(1)
	}
	// The producer leaves out exactly the sockets whose creator is the process
	// its cgroup is named after, so with the producer active a socket without
	// a snapshot in a process cgroup belongs to that process. Without the
	// producer this would not hold (a forked child shares the cgroup), and
	// the cgroup stays a UID label only.
	if !hasCreator && group.found && group.pid != 0 && i.socketCreatorActive.Load() {
		if owner := i.ownerFromProcessCgroup(ctx, identity, group, resolver); owner != nil {
			return owner
		}
	}
	// This query must remain per cookie, since several creators can share
	// one group.
	owner := i.creatorFromIdentity(ctx, identity)
	if owner.UserId == -1 {
		i.identityCounters.creatorUnavailable.Add(1)
		// Preserve only corroborated UID-level information. In particular,
		// netd's fchown'ed socket UID must not become the sender's UID.
		if group.found && group.uid == identity.uid {
			owner.UserId = int32(group.uid)
			owner.UserName = cachedUserName(group.uid)
		}
	}
	if len(owner.PackageNames) == 0 {
		i.identityCounters.unknownPackage.Add(1)
	}
	return owner
}

// ownerFromProcessCgroup attributes a socket to the process its cgroup was
// created for. The process must still be that cgroup's process: its
// /proc/<pid>/cgroup must name a directory whose inode is the socket's
// cgroup ID (the ID is the kernfs inode, kernfs_id_ino, and is not reused
// within a boot, so a recycled PID in a new pid_<pid> directory cannot
// match). The UID is the process's own: init services' directories are all
// labelled uid_0, and netd fchown()s its DNS sockets to the requesting app,
// whose UID stays a diagnostic requester. Name (argv[0]), executable and
// package then come from resolveSocketOwner exactly as for a snapshot
// without a recorded name. nil when the process is gone or moved.
func (i *Inbound) ownerFromProcessCgroup(ctx context.Context, identity socketIdentity, group cgroupOwner, resolver *cgroupOwnerResolver) *adapter.ConnectionOwner {
	if !group.procVerified {
		uid, startNs, ok := verifyCgroupProcess(group.pid, identity.cgroupID)
		if !ok {
			i.identityCounters.cgroupProcessGone.Add(1)
			return nil
		}
		group.procVerified, group.procUID, group.procStartNs = true, uid, startNs
		resolver.cache.Add(identity.cgroupID, group)
	}
	if requester, differs := identity.requesterUID(group.procUID); differs {
		i.identityCounters.requesterDiffers.Add(1)
		i.logger.DebugContext(ctx, "socket of uid ", group.procUID, " works for uid ", requester,
			" (", i.packageForApplicationUID(requester), "); routed by the sender")
	}
	owner := i.resolveSocketOwner(ctx, SocketOwner{ProcessID: group.pid, UserID: group.procUID, StartTimeNs: group.procStartNs})
	if owner.UserId == -1 {
		i.identityCounters.cgroupProcessGone.Add(1)
		return nil
	}
	i.identityCounters.resolvedByCgroupProcess.Add(1)
	if len(owner.PackageNames) == 0 {
		i.identityCounters.unknownPackage.Add(1)
	}
	return owner
}

// verifyCgroupProcess checks that pid still lives in the cgroup with inode
// cgroupID and returns its UID and start time.
func verifyCgroupProcess(pid uint32, cgroupID uint64) (uint32, uint64, bool) {
	dir, err := os.Open(filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10)))
	if err != nil {
		return 0, 0, false
	}
	defer dir.Close()
	dirFD := int(dir.Fd())
	raw, err := readFileAt(dirFD, "cgroup")
	if err != nil {
		return 0, 0, false
	}
	path := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, found := strings.CutPrefix(line, "0::"); found {
			path = rest
			break
		}
	}
	var stat unix.Stat_t
	if path == "" || unix.Stat(filepath.Join(cgroupProcRoot, path), &stat) != nil || stat.Ino != cgroupID {
		return 0, 0, false
	}
	status, err := readFileAt(dirFD, "status")
	if err != nil {
		return 0, 0, false
	}
	uid, ok := parseProcessUID(status)
	if !ok {
		return 0, 0, false
	}
	statRaw, err := readFileAt(dirFD, "stat")
	if err != nil {
		return 0, 0, false
	}
	ticks, ok := parseStartTicks(statRaw)
	if !ok {
		return 0, 0, false
	}
	return uid, ticks * (1e9 / userHZ), true
}

// cgroupProcRoot is where /proc/<pid>/cgroup paths are resolved; tests
// replace it.
var cgroupProcRoot = cgroupRoot

// The creation snapshot and UID/group fields are independently valid. In
// particular, a missing cgroup or fchown'ed sk_uid must not hide a creator.
func (i *Inbound) creatorFromIdentity(ctx context.Context, identity socketIdentity) *adapter.ConnectionOwner {
	if identity.hasCreator() {
		return i.resolveSocketOwner(ctx, socketOwnerFromCreator(identity.creator))
	}
	if i.socketCreatorActive.Load() && identity.cookie != 0 && i.processTracker != nil {
		i.identityCounters.creatorFallbacks.Add(1)
	}
	return i.lookupProcessInfo(ctx, identity.cookie)
}

// packageForApplicationUID names the package only when the UID alone decides it:
// an ordinary app UID with exactly one installed package, or an SDK sandbox
// UID, whose host is the app UID 10000 below it
// (Process.getAppUidForSdkSandboxUid). Shared UIDs, system UIDs and isolated
// processes get no package here.
func (i *Inbound) packageForApplicationUID(uid uint32) string {
	if i.networkManager == nil {
		return ""
	}
	var packageManager tun.PackageManager = i.networkManager.PackageManager()
	if snapshotter, loaded := packageManager.(interface{ Snapshot() androidpackages.View }); loaded {
		packageManager = snapshotter.Snapshot()
	}
	appID := uid % androidUserRange
	if appID >= 20000 && appID <= 29999 {
		uid -= 10000
	}
	return uniqueApplicationPackage(packageManager, uid)
}

// recordsSocketIdentity reports whether the TC program should record socket
// identity: local interception on TC, and routing that needs process data.
func (i *Inbound) recordsSocketIdentity() bool {
	return i.localTCEnabled() && !i.usePlatformProcessFinder &&
		(i.socketCreator != nil || runtime.GOOS == "android" && i.router != nil && i.router.NeedFindProcess())
}

// AttributionDiagnostics counts how connections were attributed since start
// and why the rest are unknown, without per-connection logging.
type AttributionDiagnostics struct {
	Mode string `json:"mode"`
	// PackageTableLoaded and Packages describe the package table the
	// attribution reads.
	PackageTableLoaded bool `json:"package_table_loaded"`
	Packages           int  `json:"packages"`
	// By UID alone (ordinary app or SDK sandbox) / by (process name, UID).
	ResolvedByUID     uint64 `json:"resolved_by_uid"`
	ResolvedByProcess uint64 `json:"resolved_by_process"`
	// Without a snapshot, by the process its cgroup was created for; and
	// such cgroups whose process was gone or moved.
	ResolvedByCgroupProcess uint64 `json:"resolved_by_cgroup_process"`
	CgroupProcessGone       uint64 `json:"cgroup_process_gone"`
	// Unknown reasons.
	UnknownPackage     uint64 `json:"unknown_package"`
	RootCgroup         uint64 `json:"root_cgroup"`
	GroupUnresolved    uint64 `json:"group_unresolved"`
	NoIdentity         uint64 `json:"no_identity"`
	CreatorUnavailable uint64 `json:"creator_unavailable"`
	UIDMismatch        uint64 `json:"uid_mismatch"`
	CreatorSnapshots   uint64 `json:"creator_snapshots"`
	CreatorMissing     uint64 `json:"creator_snapshot_missing"`
	CreatorInvalid     uint64 `json:"creator_snapshot_invalid"`
	CreatorFallbacks   uint64 `json:"creator_cookie_fallbacks"`
	// v2 snapshot outcomes: the recorded name is declared by several
	// packages of the app ID, by none, or the index could not decide yet;
	// snapshots without a readable name; creators that exec'd since.
	MultiPackageProcess uint64 `json:"multi_package_process"`
	UndeclaredProcess   uint64 `json:"undeclared_process"`
	IndexFailedLookups  uint64 `json:"index_failed_lookups"`
	IndexPendingLookups uint64 `json:"index_pending_connections"`
	NameUnavailable     uint64 `json:"creator_name_unavailable"`
	ExeMismatch         uint64 `json:"creator_exe_mismatch"`
	// netd cookie_tag_map: consulted, found, and requester != sender.
	ChargeChecked    uint64 `json:"charge_checked"`
	ChargeFound      uint64 `json:"charge_found"`
	RequesterDiffers uint64 `json:"requester_differs"`
	// Manifest index.
	IndexedPackages uint64 `json:"indexed_packages"`
	IndexFailures   uint64 `json:"index_failures"`
	IndexPending    uint64 `json:"index_pending_lookups"`
}

func (i *Inbound) attributionDiagnostics() *AttributionDiagnostics {
	if !i.socketIdentityActive.Load() {
		return nil
	}
	counters := &i.identityCounters
	diagnostics := &AttributionDiagnostics{
		Mode:              i.processTrackingMode(),
		ResolvedByUID:     counters.resolvedPackage.Load(),
		ResolvedByProcess: counters.resolvedByProcess.Load(),

		ResolvedByCgroupProcess: counters.resolvedByCgroupProcess.Load(),
		CgroupProcessGone:       counters.cgroupProcessGone.Load(),
		UnknownPackage:          counters.unknownPackage.Load(),
		RootCgroup:              counters.rootCgroup.Load(),
		GroupUnresolved:         counters.cgroupGone.Load(),
		NoIdentity:              counters.noIdentity.Load(),
		CreatorUnavailable:      counters.creatorUnavailable.Load(),
		UIDMismatch:             counters.uidMismatch.Load(),
		CreatorSnapshots:        counters.creatorSnapshots.Load(),
		CreatorMissing:          counters.creatorMissing.Load(),
		CreatorInvalid:          counters.creatorInvalid.Load(),
		CreatorFallbacks:        counters.creatorFallbacks.Load(),

		MultiPackageProcess: counters.multiPackageProcess.Load(),
		UndeclaredProcess:   counters.undeclaredProcess.Load(),
		IndexFailedLookups:  counters.indexFailedLookups.Load(),
		IndexPendingLookups: counters.indexPendingLookups.Load(),
		NameUnavailable:     counters.nameUnavailable.Load(),
		ExeMismatch:         counters.exeMismatch.Load(),
		ChargeChecked:       counters.chargeChecked.Load(),
		ChargeFound:         counters.chargeFound.Load(),
		RequesterDiffers:    counters.requesterDiffers.Load(),
	}
	if i.networkManager != nil {
		if source, loaded := i.networkManager.PackageManager().(interface{ Snapshot() androidpackages.View }); loaded {
			view := source.Snapshot()
			diagnostics.PackageTableLoaded = view.Loaded()
			diagnostics.Packages = view.PackageCount()
		}
	}
	if index := i.processIndex.Load(); index != nil {
		index.access.Lock()
		diagnostics.IndexedPackages = index.parsedTotal
		diagnostics.IndexFailures = index.failedTotal
		diagnostics.IndexPending = index.pendingTotal
		index.access.Unlock()
	}
	return diagnostics
}
