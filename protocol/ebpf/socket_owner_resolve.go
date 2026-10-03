//go:build with_ebpf && (linux || android)

package ebpf

// cmdline/comm are process names, not package identities. Even a Framework
// process-start package is not necessarily the package behind every later
// socket: two APKs can execute inside one shared-UID process.
//
// Verified application runtimes may also use the manifest process index for
// shared/system UIDs. The name must come from the cookie creator's proc dir,
// never from a cgroup directory PID or the truncated kernel comm hint.

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/androidmanifest"
	"github.com/sagernet/sing-box/common/androidpackages"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
	"golang.org/x/sys/unix"
)

const (
	deletedPathSuffix        = " (deleted)"
	socketOwnerCacheCapacity = 1024
	userHZ                   = 100
)

type socketOwnerCacheKey struct {
	ProcessID   uint32
	UserID      uint32
	StartTimeNs uint64
	// exec keeps PID and start time but replaces the executable; a snapshot's
	// exe inode decides which program's path may be shown.
	ExeInode uint64
}

// procRoot is replaceable only by tests. Every metadata read uses one open
// directory FD so PID reuse cannot redirect subsequent reads to a new task.
var procRoot = "/proc"

type socketOwnerMetadata struct {
	*adapter.ConnectionOwner
	processName string
	// exeMismatch: the snapshot's exe inode differs from the live process's
	// (it exec'd after creating the socket); its path was withheld.
	exeMismatch bool
}

// Only verified procfs metadata is cached. Package membership is checked on
// each lookup; incomplete reads are retried instead of cached indefinitely.
var socketOwnerCache = sync.OnceValue(func() *freelru.Cache[socketOwnerCacheKey, *socketOwnerMetadata] {
	cache, err := freelru.New[socketOwnerCacheKey, *socketOwnerMetadata](
		socketOwnerCacheCapacity, maphash.NewHasher[socketOwnerCacheKey]().Hash32, true,
	)
	if err != nil {
		return nil
	}
	// exec can change the path without changing PID/start_time.
	cache.SetLifetime(processInfoCacheLifetime)
	return cache
})

func (i *Inbound) resolveSocketOwner(ctx context.Context, owner SocketOwner) *adapter.ConnectionOwner {
	key := socketOwnerCacheKey{ProcessID: owner.ProcessID, UserID: owner.UserID, StartTimeNs: owner.StartTimeNs, ExeInode: owner.exeInode}
	cache := socketOwnerCache()
	var rawInfo *socketOwnerMetadata
	var cached bool
	if owner.StartTimeNs != 0 && cache != nil {
		rawInfo, cached = cache.Get(key)
	}
	if cached && !owner.hasName && i.processIndex.Load() != nil && rawInfo.processName == "" &&
		len(rawInfo.ProcessPaths) > 0 && isAndroidApplicationExecutable(strings.TrimSuffix(rawInfo.ProcessPaths[0], deletedPathSuffix)) {
		// An index may have started after this raw entry was cached.
		cached = false
	}
	verified := cached
	if !cached {
		rawInfo, verified = i.resolveThroughProcDir(owner)
		if verified && cache != nil {
			cache.Add(key, rawInfo)
		}
	}
	if !cached && rawInfo.exeMismatch {
		i.identityCounters.exeMismatch.Add(1)
	}
	// Refinement must not mutate the cache's raw executable classification.
	info := *rawInfo.ConnectionOwner
	if verified {
		var packageManager tun.PackageManager
		if i.networkManager != nil {
			packageManager = i.networkManager.PackageManager()
		}
		if snapshotter, ok := packageManager.(interface{ Snapshot() androidpackages.View }); ok {
			packageManager = snapshotter.Snapshot()
		}
		refineConnectionOwner(&info, owner, packageManager)
		if !owner.hasName && len(info.PackageNames) > 0 {
			i.identityCounters.resolvedPackage.Add(1)
		}
		if index := i.processIndex.Load(); index != nil && !owner.hasName && len(info.PackageNames) == 0 && rawInfo.processName != "" {
			name := androidmanifest.ProcessRecordName(rawInfo.processName)
			if packageName := index.lookup(owner.UserID%androidUserRange, name); packageName != "" {
				info.PackageNames = []string{packageName}
				i.identityCounters.resolvedByProcess.Add(1)
			}
		}
	}
	if owner.hasName {
		// The creation-time name decides the package, whether or not the
		// creator is still alive: no /proc read is involved.
		info.PackageNames = nil
		if packageName := i.packageFromSnapshot(owner); packageName != "" {
			info.PackageNames = []string{packageName}
		}
	}
	if !cached {
		logResolvedOwner(ctx, i.logger, &info)
	}
	return &info
}

// packageFromSnapshot applies E1-E3 (creator_snapshot.go) and counts why a
// snapshot did not name a package.
func (i *Inbound) packageFromSnapshot(owner SocketOwner) string {
	var view tun.PackageManager
	if i.networkManager != nil {
		view = i.networkManager.PackageManager()
		if snapshotter, ok := view.(interface{ Snapshot() androidpackages.View }); ok {
			view = snapshotter.Snapshot()
		}
	}
	packageName, outcome := snapshotPackage(owner.UserID, owner.name, owner.hasName,
		func(uid uint32) string { return uniqueApplicationPackage(view, uid) }, i.processIndex.Load())
	counters := &i.identityCounters
	switch outcome {
	case processLookupFoundByUID:
		counters.resolvedPackage.Add(1)
	case processLookupFound:
		counters.resolvedByProcess.Add(1)
	case processLookupMultiPackage:
		counters.multiPackageProcess.Add(1)
	case processLookupUndeclared:
		counters.undeclaredProcess.Add(1)
	case processLookupFailed:
		counters.indexFailedLookups.Add(1)
	case processLookupPending:
		counters.indexPendingLookups.Add(1)
	}
	return packageName
}

// The router skips its own search/logging when ProcessInfo is already present.
func logResolvedOwner(ctx context.Context, logger log.ContextLogger, info *adapter.ConnectionOwner) {
	if info == nil {
		return
	}
	var attribution []string
	if len(info.PackageNames) > 0 {
		attribution = append(attribution, "package name: "+strings.Join(info.PackageNames, ", "))
	}
	if len(info.ProcessPaths) > 0 {
		attribution = append(attribution, "process path: "+strings.Join(info.ProcessPaths, ", "))
	}
	if info.UserName != "" {
		attribution = append(attribution, "user: "+info.UserName)
	} else if info.UserId != -1 {
		attribution = append(attribution, "user id: "+strconv.Itoa(int(info.UserId)))
	}
	if len(attribution) > 0 {
		logger.InfoContext(ctx, "found ", strings.Join(attribution, ", "))
	}
}

// One proc directory FD keeps stat/status/exe reads on the same process
// instance; later PID reuse does not retarget that FD. The proc start time is
// only available in USER_HZ ticks, not nanoseconds.
func (i *Inbound) resolveThroughProcDir(owner SocketOwner) (*socketOwnerMetadata, bool) {
	unknown := func() (*socketOwnerMetadata, bool) {
		return &socketOwnerMetadata{ConnectionOwner: ownerFromCommOnly(owner)}, false
	}
	if owner.StartTimeNs == 0 {
		return unknown()
	}
	dir, err := os.Open(filepath.Join(procRoot, strconv.FormatUint(uint64(owner.ProcessID), 10)))
	if err != nil {
		i.logger.Trace("open eBPF socket owner proc dir: ", err)
		return unknown()
	}
	defer dir.Close()
	dirFD := int(dir.Fd())
	raw, err := readFileAt(dirFD, "stat")
	if err != nil {
		return unknown()
	}
	ticks, ok := parseStartTicks(raw)
	if !ok || !startTicksMatch(ticks, owner.StartTimeNs) {
		i.logger.Trace("eBPF socket owner pid ", owner.ProcessID, " start time no longer matches")
		return unknown()
	}
	status, err := readFileAt(dirFD, "status")
	uid, ok := parseProcessUID(status)
	if err != nil || !ok || uid != owner.UserID {
		return unknown()
	}
	executable, err := readLinkAt(dirFD, "exe")
	if err != nil || !filepath.IsAbs(executable) {
		return unknown()
	}
	exeMismatch := false
	if owner.hasExe {
		// The path names whatever the process runs now. Show it only when it
		// is still the program that created the socket.
		var stat unix.Stat_t
		if unix.Fstatat(dirFD, "exe", &stat, 0) != nil || stat.Ino != owner.exeInode {
			executable, exeMismatch = "", true
		}
	}
	info := &adapter.ConnectionOwner{ProcessID: owner.ProcessID, UserId: int32(owner.UserID)}
	if executable != "" {
		info.ProcessPaths = []string{executable}
	}
	completeOwnerUser(info)
	metadata := &socketOwnerMetadata{ConnectionOwner: info, exeMismatch: exeMismatch}
	// A snapshot that carries the creation-time name needs no cmdline read.
	if !owner.hasName && i.processIndex.Load() != nil && isAndroidApplicationExecutable(strings.TrimSuffix(executable, deletedPathSuffix)) {
		cmdline, err := readFileAt(dirFD, "cmdline")
		if err != nil {
			// Keep the creator evidence but retry incomplete metadata on the
			// next connection; never cache a missing name as authoritative.
			return unknown()
		}
		name, _, terminated := bytes.Cut(cmdline, []byte{0})
		if !terminated || len(name) == 0 {
			return unknown()
		}
		metadata.processName = string(name)
	}
	return metadata, true
}

func completeOwnerUser(info *adapter.ConnectionOwner) {
	if info.UserId != -1 && info.UserName == "" {
		info.UserName = cachedUserName(uint32(info.UserId))
	}
}

func readFileAt(dirFD int, name string) ([]byte, error) {
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	return io.ReadAll(file)
}

func readLinkAt(dirFD int, name string) (string, error) {
	buffer := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(dirFD, name, buffer)
	if err != nil {
		return "", err
	}
	return string(buffer[:n]), nil
}

func parseProcessUID(raw []byte) (uint32, bool) {
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 5 {
			return 0, false
		}
		uid, err := strconv.ParseUint(fields[1], 10, 32)
		return uint32(uid), err == nil
	}
	return 0, false
}

func startTicksMatch(ticks uint64, startTimeNs uint64) bool {
	// Both sides convert group_leader.start_boottime. Adjacent ticks only
	// broaden the reuse window, so require exact equality at procfs precision.
	return ticks == startTimeNs/(1_000_000_000/userHZ)
}

func parseStartTicks(raw []byte) (uint64, bool) {
	end := bytes.LastIndexByte(raw, ')')
	if end < 0 {
		return 0, false
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 {
		return 0, false
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	return ticks, err == nil
}

func ownerFromCommOnly(owner SocketOwner) *adapter.ConnectionOwner {
	info := &adapter.ConnectionOwner{ProcessID: owner.ProcessID, UserId: int32(owner.UserID)}
	if owner.Comm != "" {
		// Captured (possibly truncated) process-name hint only.
		info.ProcessPaths = []string{owner.Comm}
	}
	completeOwnerUser(info)
	return info
}

// Called only with verified procfs data, never with the comm-only fallback.
func refineConnectionOwner(info *adapter.ConnectionOwner, owner SocketOwner, packageManager tun.PackageManager) {
	if info == nil {
		return
	}
	executable := ""
	if len(info.ProcessPaths) > 0 {
		executable = strings.TrimSuffix(info.ProcessPaths[0], deletedPathSuffix)
	}
	info.PackageNames = nil
	switch {
	case executable == "":
		info.ProcessPaths = nil
		if owner.Comm != "" {
			info.ProcessPaths = []string{owner.Comm}
		}
	case isAndroidApplicationExecutable(executable):
		info.ProcessPaths = nil
		if packageName := uniqueApplicationPackage(packageManager, owner.UserID); packageName != "" {
			info.PackageNames = []string{packageName}
		}
	default:
		info.ProcessPaths = []string{executable}
	}
}

func isAndroidApplicationExecutable(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	switch filepath.Base(path) {
	case "app_process", "app_process32", "app_process64":
		return true
	default:
		return false
	}
}

func uniqueApplicationPackage(packageManager tun.PackageManager, uid uint32) string {
	appID := uid % 100000
	// System, SDK-sandbox and isolated UIDs need a different attribution source.
	if packageManager == nil || appID < 10000 || appID > 19999 {
		return ""
	}
	if _, shared := packageManager.SharedPackageByID(appID); shared {
		return ""
	}
	packages, loaded := packageManager.PackagesByID(appID)
	if !loaded || len(packages) != 1 || packages[0] == "" {
		return ""
	}
	if packageID, loaded := packageManager.IDByPackage(packages[0]); !loaded || packageID != appID {
		return ""
	}
	return packages[0]
}
