//go:build android && with_ebpf && attribution_query_device

package ebpf

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"golang.org/x/sys/unix"
)

func init() { queryBenchCurrentTargets = queryBenchTCUIDTargets }

func queryBenchTCUIDTargets(t *testing.T, inbound *Inbound, packages tun.PackageManager) []queryBenchTarget {
	t.Helper()
	packageName := os.Getenv("SBO_QUERY_PACKAGE")
	if packageName == "" {
		packageName = "com.android.chrome"
	}
	uid, found := packages.IDByPackage(packageName)
	if !found || uniqueApplicationPackage(packages, uid) != packageName {
		queryBenchEmit(t, map[string]any{"kind": "unavailable", "query": "tc_uid_controlled_input", "reason": "requested package has no unique ordinary user-0 UID", "package": packageName})
		return nil
	}
	uidDirectory := filepath.Join(cgroupRoot, "apps", "uid_"+strconv.FormatUint(uint64(uid), 10))
	entries, err := os.ReadDir(uidDirectory)
	if err != nil {
		queryBenchEmit(t, map[string]any{"kind": "unavailable", "query": "tc_uid_controlled_input", "reason": err.Error(), "package": packageName})
		return nil
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "pid_") {
			continue
		}
		path := filepath.Join(uidDirectory, entry.Name())
		var stat unix.Stat_t
		if unix.Stat(path, &stat) != nil {
			continue
		}
		resolver := newCgroupOwnerResolver(cgroupRoot)
		if resolver == nil {
			t.Fatal("cgroup owner cache unavailable")
		}
		inbound.cgroupOwners.Store(resolver)
		// This is deliberately not presented as a TC-captured socket identity:
		// the package table, UID and directory inode are real, but this input
		// has no socket/cookie provenance. It times the UID/group function path.
		identity := socketIdentity{uid: uid, cgroupID: stat.Ino, valid: true}
		return []queryBenchTarget{{
			name:    "tc_uid_controlled_input",
			fixture: map[string]any{"source": "controlled_input_from_real_user0_package_and_cgroup_directory", "uid": uid, "cgroup_id": stat.Ino, "cgroup_path": path, "package": packageName, "socket_cookie": 0, "no_actual_app_socket_or_tc_assignment": true},
			call:    func() *adapter.ConnectionOwner { return inbound.ownerFromIdentity(context.Background(), identity) },
			reset:   func() { resolver.cache.Remove(identity.cgroupID) },
			validate: func(owner *adapter.ConnectionOwner) bool {
				return owner != nil && owner.ProcessID == 0 && owner.UserId == int32(uid) && len(owner.ProcessPaths) == 0 && len(owner.PackageNames) == 1 && owner.PackageNames[0] == packageName
			},
		}}
	}
	queryBenchEmit(t, map[string]any{"kind": "unavailable", "query": "tc_uid_controlled_input", "reason": "no process group directory for requested package", "package": packageName})
	return nil
}
