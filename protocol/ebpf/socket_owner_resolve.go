//go:build with_ebpf && (linux || android)

package ebpf

// cmdline/comm are process names, not package identities. Even a Framework
// process-start package is not necessarily the package behind every later
// socket: two APKs can execute inside one shared-UID process.
//
// Only verified application runtimes with ordinary, non-shared UIDs mapped to
// one installed package receive PackageNames. Other cases retain PID/UID.

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
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
}

// Only verified procfs metadata is cached. Package membership is checked on
// each lookup; incomplete reads are retried instead of cached indefinitely.
var socketOwnerCache = sync.OnceValue(func() *freelru.Cache[socketOwnerCacheKey, *adapter.ConnectionOwner] {
	cache, err := freelru.New[socketOwnerCacheKey, *adapter.ConnectionOwner](
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
	key := socketOwnerCacheKey{ProcessID: owner.ProcessID, UserID: owner.UserID, StartTimeNs: owner.StartTimeNs}
	cache := socketOwnerCache()
	var rawInfo *adapter.ConnectionOwner
	var cached bool
	if owner.StartTimeNs != 0 && cache != nil {
		rawInfo, cached = cache.Get(key)
	}
	verified := cached
	if !cached {
		rawInfo, verified = i.resolveThroughProcDir(owner)
		if verified && cache != nil {
			cache.Add(key, rawInfo)
		}
	}
	// Refinement must not mutate the cache's raw executable classification.
	info := *rawInfo
	if verified {
		var packageManager tun.PackageManager
		if i.networkManager != nil {
			packageManager = i.networkManager.PackageManager()
		}
		refineConnectionOwner(&info, owner, packageManager)
	}
	if !cached {
		logResolvedOwner(ctx, i.logger, &info)
	}
	return &info
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
func (i *Inbound) resolveThroughProcDir(owner SocketOwner) (*adapter.ConnectionOwner, bool) {
	if owner.StartTimeNs == 0 {
		return ownerFromCommOnly(owner), false
	}
	dir, err := os.Open(filepath.Join("/proc", strconv.FormatUint(uint64(owner.ProcessID), 10)))
	if err != nil {
		i.logger.Trace("open eBPF socket owner proc dir: ", err)
		return ownerFromCommOnly(owner), false
	}
	defer dir.Close()
	dirFD := int(dir.Fd())
	raw, err := readFileAt(dirFD, "stat")
	if err != nil {
		return ownerFromCommOnly(owner), false
	}
	ticks, ok := parseStartTicks(raw)
	if !ok || !startTicksMatch(ticks, owner.StartTimeNs) {
		i.logger.Trace("eBPF socket owner pid ", owner.ProcessID, " start time no longer matches")
		return ownerFromCommOnly(owner), false
	}
	status, err := readFileAt(dirFD, "status")
	uid, ok := parseProcessUID(status)
	if err != nil || !ok || uid != owner.UserID {
		return ownerFromCommOnly(owner), false
	}
	executable, err := readLinkAt(dirFD, "exe")
	if err != nil || !filepath.IsAbs(executable) {
		return ownerFromCommOnly(owner), false
	}
	info := &adapter.ConnectionOwner{
		ProcessID: owner.ProcessID, UserId: int32(owner.UserID), ProcessPaths: []string{executable},
	}
	completeOwnerUser(info)
	return info, true
}

func completeOwnerUser(info *adapter.ConnectionOwner) {
	if info.UserId != -1 && info.UserName == "" {
		if osUser, err := user.LookupId(strconv.FormatInt(int64(info.UserId), 10)); err == nil {
			info.UserName = osUser.Username
		}
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
