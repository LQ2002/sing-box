//go:build with_ebpf && (linux || android)

package ebpf

// Attribution from the socket identity the TC local egress program records
// (sing-ebpf TCConfig.RecordSocketIdentity): the socket's UID (sk_uid) and
// the cgroup v2 id it was created in. ANDROID_ATTRIBUTION_PLAN.md stage 3.
//
// Android gives every process its own cgroup, /apps/uid_X/pid_Y or
// /system/uid_X/pid_Y, created by zygote before the app runs any code
// (Zygote.cpp SpecializeCommon); KernelSU/root processes stay in the root
// cgroup (id 1). So the cgroup id names the creating process instance:
// kernfs ids are 64-bit and never reused within a boot (fs/kernfs/dir.c:
// cyclic low 32 bits, high 32 bits bumped on wrap), and the directory goes
// away with the process. That makes it a birth token, unlike a PID.
//
// Routing follows the sender (the user's choice): the creator's UID decides,
// not sk_uid. netd fchown()s DNS sockets it opens for an app to that app's
// UID (ResolverOptionsParcel default), so sk_uid alone would attribute
// netd's traffic to the app.
//
// Cost: an ordinary app needs one cache lookup per connection after its
// first one. A cgroup id is resolved once: first by listing the one
// directory sk_uid points at (a few entries), and only if that misses (sk_uid
// changed by fchown) by one scan of the uid directories. There is no
// per-connection /proc access for app processes. Resolution by file handle
// (open_by_handle_at on the kernfs id) would be O(1), but the test device's
// GKI kernel is built without CONFIG_FHANDLE (ENOSYS; checked in
// /proc/config.gz).

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/androidmanifest"
	"github.com/sagernet/sing-box/common/androidpackages"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
	"golang.org/x/sys/unix"
)

// procRoot is a variable only so tests can point it at a fake tree.
var procRoot = "/proc"

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
}

func identityFromAssignment(assignment commonEBPF.TCAssignment) socketIdentity {
	return socketIdentity{
		cookie:   assignment.SocketCookie,
		uid:      assignment.SocketUID,
		cgroupID: assignment.SocketCgroupID,
		valid:    assignment.HasSocketIdentity(),
	}
}

// cgroupOwner is the process a cgroup id belongs to.
type cgroupOwner struct {
	found bool
	uid   uint32
	pid   uint32
	// system is true for /system/uid_X/pid_Y. Only those can be native
	// daemons worth a process path; everything under /apps is forked from
	// zygote and runs app_process.
	system bool
	// executable is read lazily (exeLoaded), only for system processes, and
	// only once per process instance.
	executable string
	exeLoaded  bool
	// processName is the cmdline's argv[0], read lazily (nameLoaded) and
	// only for processes whose package is not decided by the UID alone.
	processName string
	nameLoaded  bool
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

// lookup returns the process that created cgroup id, using uidHint (sk_uid)
// to pick the first directory to look in.
func (r *cgroupOwnerResolver) lookup(cgroupID uint64, uidHint uint32) cgroupOwner {
	owner, loaded := r.cache.Get(cgroupID)
	if !loaded {
		owner = r.scan(cgroupID, uidHint)
	}
	if owner.found && owner.system && !owner.exeLoaded {
		owner.executable = readProcessInstance(owner.pid, cgroupID, r.scanRoot, func(procDir string) (string, error) {
			return os.Readlink(procDir + "/exe")
		})
		owner.exeLoaded = true
		r.cache.Add(cgroupID, owner)
	}
	return owner
}

// processName returns owner's argv[0], reading it once per process instance.
func (r *cgroupOwnerResolver) processName(cgroupID uint64, owner cgroupOwner) string {
	if owner.nameLoaded {
		return owner.processName
	}
	owner.processName = readProcessInstance(owner.pid, cgroupID, r.scanRoot, func(procDir string) (string, error) {
		content, err := os.ReadFile(procDir + "/cmdline")
		name, _, _ := strings.Cut(string(content), "\x00")
		return name, err
	})
	owner.nameLoaded = true
	r.cache.Add(cgroupID, owner)
	return owner.processName
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
		owner := cgroupOwner{found: true, uid: uid, pid: pid, system: kind == "system"}
		r.cache.Add(stat.Ino, owner)
		if stat.Ino == target {
			result, found = owner, true
		}
	}
	return result, found
}

// readProcessInstance reads something from /proc/<pid> and keeps it only if
// the process is still the one in that cgroup afterwards: its
// /proc/<pid>/cgroup must still resolve to the same cgroup id. A PID reused
// between the directory scan and the read lives in a different cgroup, so
// it fails this check.
func readProcessInstance(pid uint32, cgroupID uint64, root string, read func(procDir string) (string, error)) string {
	procDir := procRoot + "/" + strconv.FormatUint(uint64(pid), 10)
	value, err := read(procDir)
	if err != nil {
		return ""
	}
	content, err := os.ReadFile(procDir + "/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(content), "\n") {
		relative, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		var stat unix.Stat_t
		if unix.Stat(root+relative, &stat) != nil || stat.Ino != cgroupID {
			return ""
		}
		return value
	}
	return ""
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
	noIdentity      atomic.Uint64
	rootCgroup      atomic.Uint64
	cgroupGone      atomic.Uint64
	// unknownPackage counts creators found whose package the UID and the
	// process name do not decide (shared or system UID, native daemon).
	unknownPackage atomic.Uint64
}

var userNameCache sync.Map // uint32 -> string

func cachedUserName(uid uint32) string {
	if name, loaded := userNameCache.Load(uid); loaded {
		return name.(string)
	}
	name := ""
	if osUser, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		name = osUser.Username
	}
	userNameCache.Store(uid, name)
	return name
}

// ownerFromIdentity is the stage 3 attribution. It never returns nil: an
// unknown owner must still be a non-nil ConnectionOwner, or
// Router.searchProcessInfo would fill in the whole candidate package list of
// a shared UID.
func (i *Inbound) ownerFromIdentity(ctx context.Context, identity socketIdentity) *adapter.ConnectionOwner {
	if !identity.valid {
		i.identityCounters.noIdentity.Add(1)
		return i.lookupProcessInfo(ctx, identity.cookie)
	}
	if identity.cgroupID == rootCgroupID {
		// Root (KernelSU/init) processes share the root cgroup: no PID here.
		// The optional socket owner module can still name the process.
		i.identityCounters.rootCgroup.Add(1)
		if i.processTracker != nil {
			owner := i.lookupProcessInfo(ctx, identity.cookie)
			if owner.UserId != -1 {
				return owner
			}
		}
		return &adapter.ConnectionOwner{UserId: int32(identity.uid), UserName: cachedUserName(identity.uid)}
	}
	var creator cgroupOwner
	resolver := i.cgroupOwners.Load()
	if resolver != nil {
		creator = resolver.lookup(identity.cgroupID, identity.uid)
	}
	if !creator.found {
		i.identityCounters.cgroupGone.Add(1)
		return &adapter.ConnectionOwner{UserId: int32(identity.uid), UserName: cachedUserName(identity.uid)}
	}
	owner := &adapter.ConnectionOwner{
		ProcessID: creator.pid,
		UserId:    int32(creator.uid),
		UserName:  cachedUserName(creator.uid),
	}
	if creator.executable != "" && !isAndroidApplicationExecutable(strings.TrimSuffix(creator.executable, deletedPathSuffix)) {
		owner.ProcessPaths = []string{creator.executable}
	}
	if packageName := i.packageForCreatorUID(creator.uid); packageName != "" {
		owner.PackageNames = []string{packageName}
		i.identityCounters.resolvedPackage.Add(1)
		return owner
	}
	// Not decided by the UID: a shared or system UID. Only zygote children
	// have manifest-declared process names; a native daemon keeps its path.
	index := i.processIndex.Load()
	if index != nil && (!creator.system || isAndroidApplicationExecutable(strings.TrimSuffix(creator.executable, deletedPathSuffix))) {
		name := androidmanifest.ProcessRecordName(resolver.processName(identity.cgroupID, creator))
		if name != "" {
			if packageName := index.lookup(creator.uid%androidUserRange, name); packageName != "" {
				owner.PackageNames = []string{packageName}
				i.identityCounters.resolvedByProcess.Add(1)
				return owner
			}
		}
	}
	i.identityCounters.unknownPackage.Add(1)
	return owner
}

// packageForCreatorUID names the package only when the UID alone decides it:
// an ordinary app UID with exactly one installed package, or an SDK sandbox
// UID, whose host is the app UID 10000 below it
// (Process.getAppUidForSdkSandboxUid). Shared UIDs, system UIDs and isolated
// processes get no package here.
func (i *Inbound) packageForCreatorUID(uid uint32) string {
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
	return i.localTCEnabled() && i.router != nil && i.router.NeedFindProcess() && !i.usePlatformProcessFinder
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
	// Unknown reasons.
	UnknownPackage uint64 `json:"unknown_package"`
	RootCgroup     uint64 `json:"root_cgroup"`
	CreatorGone    uint64 `json:"creator_gone"`
	NoIdentity     uint64 `json:"no_identity"`
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
		UnknownPackage:    counters.unknownPackage.Load(),
		RootCgroup:        counters.rootCgroup.Load(),
		CreatorGone:       counters.cgroupGone.Load(),
		NoIdentity:        counters.noIdentity.Load(),
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
