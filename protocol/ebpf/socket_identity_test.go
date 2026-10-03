//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/sagernet/sing-box/log"

	"golang.org/x/sys/unix"
)

// fakeCgroupTree builds an Android-shaped cgroup v2 tree and /proc under a
// temporary directory. The cgroup "ids" are the directories' real inode
// numbers, exactly what the resolver compares against.
type fakeCgroupTree struct {
	root string
	proc string
}

func newFakeCgroupTree(t *testing.T) *fakeCgroupTree {
	t.Helper()
	base := t.TempDir()
	tree := &fakeCgroupTree{root: filepath.Join(base, "cgroup"), proc: filepath.Join(base, "proc")}
	previous := procRoot
	procRoot = tree.proc
	t.Cleanup(func() { procRoot = previous })
	return tree
}

// addProcess creates <kind>/uid_<uid>/pid_<pid> and a matching /proc entry
// whose exe points at executable, and returns the cgroup id.
func (f *fakeCgroupTree) addProcess(t *testing.T, kind string, uid, pid uint32, executable string) uint64 {
	t.Helper()
	relative := filepath.Join("/", kind, "uid_"+strconv.FormatUint(uint64(uid), 10), "pid_"+strconv.FormatUint(uint64(pid), 10))
	dir := filepath.Join(f.root, relative)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	procDir := filepath.Join(f.proc, strconv.FormatUint(uint64(pid), 10))
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(procDir, "exe"))
	if err := os.Symlink(executable, filepath.Join(procDir, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "cgroup"), []byte("0::"+filepath.ToSlash(relative)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(dir, &stat); err != nil {
		t.Fatal(err)
	}
	return stat.Ino
}

func TestCgroupOwnerResolverFindsCreator(t *testing.T) {
	tree := newFakeCgroupTree(t)
	appID := tree.addProcess(t, "apps", 10050, 100, "/system/bin/app_process64")
	sibling := tree.addProcess(t, "apps", 10050, 101, "/system/bin/app_process64")
	netd := tree.addProcess(t, "system", 0, 200, "/system/bin/netd")
	resolver := newCgroupOwnerResolver(tree.root)

	owner := resolver.lookup(appID, 10050)
	if !owner.found || owner.uid != 10050 || owner.pid != 100 || owner.system || owner.executable != "" {
		t.Fatalf("app owner = %+v", owner)
	}
	// The sibling was cached by the same directory scan: it still resolves
	// after its directory is gone.
	if err := os.Remove(filepath.Join(tree.root, "apps", "uid_10050", "pid_101")); err != nil {
		t.Fatal(err)
	}
	if owner = resolver.lookup(sibling, 10050); !owner.found || owner.pid != 101 {
		t.Fatalf("sibling not cached by the first scan: %+v", owner)
	}

	// sk_uid says 10050 (netd fchown()ed the DNS socket to the app), but the
	// socket was created in netd's cgroup: the creator wins.
	owner = resolver.lookup(netd, 10050)
	if !owner.found || owner.uid != 0 || owner.pid != 200 || !owner.system || owner.executable != "/system/bin/netd" {
		t.Fatalf("netd owner = %+v", owner)
	}

	if owner = resolver.lookup(1<<40, 10050); owner.found {
		t.Fatalf("a nonexistent cgroup resolved: %+v", owner)
	}
}

// A PID reused between the directory scan and the exe read lives in another
// cgroup; its executable must not be attributed to the old process.
func TestCgroupOwnerResolverRejectsReusedPID(t *testing.T) {
	tree := newFakeCgroupTree(t)
	id := tree.addProcess(t, "system", 1000, 300, "/system/bin/old_daemon")
	// PID 300 now belongs to a different process in a different cgroup.
	tree.addProcess(t, "system", 1001, 300, "/system/bin/new_daemon")
	resolver := newCgroupOwnerResolver(tree.root)
	owner := resolver.lookup(id, 1000)
	if !owner.found || owner.uid != 1000 {
		t.Fatalf("owner = %+v", owner)
	}
	if owner.executable != "" {
		t.Fatalf("executable of a reused PID was attributed: %q", owner.executable)
	}
}

func newIdentityTestInbound(t *testing.T, tree *fakeCgroupTree, packages *testPackageManager) *Inbound {
	t.Helper()
	inbound := &Inbound{
		logger:         log.NewNOPFactory().Logger(),
		networkManager: &testNetworkManager{packageManager: packages},
	}
	inbound.cgroupOwners.Store(newCgroupOwnerResolver(tree.root))
	return inbound
}

func TestOwnerFromIdentity(t *testing.T) {
	tree := newFakeCgroupTree(t)
	app := tree.addProcess(t, "apps", 10050, 100, "/system/bin/app_process64")
	shared := tree.addProcess(t, "apps", 10060, 110, "/system/bin/app_process64")
	sandbox := tree.addProcess(t, "apps", 20050, 120, "/system/bin/app_process64")
	systemServer := tree.addProcess(t, "system", 1000, 130, "/system/bin/app_process64")
	netd := tree.addProcess(t, "system", 0, 200, "/system/bin/netd")
	packages := &testPackageManager{
		idByPackage: map[string]uint32{"com.example.app": 10050, "com.shared.a": 10060, "com.shared.b": 10060},
		idByShared:  map[string]uint32{"shared.user": 10060},
		packagesByID: map[uint32][]string{
			10050: {"com.example.app"},
			10060: {"com.shared.a", "com.shared.b"},
		},
		sharedPackageID: map[uint32]string{10060: "shared.user"},
	}
	inbound := newIdentityTestInbound(t, tree, packages)
	ctx := context.Background()

	owner := inbound.ownerFromIdentity(ctx, socketIdentity{valid: true, uid: 10050, cgroupID: app})
	if len(owner.PackageNames) != 1 || owner.PackageNames[0] != "com.example.app" || owner.UserId != 10050 || owner.ProcessID != 100 || len(owner.ProcessPaths) != 0 {
		t.Fatalf("unique app owner = %+v", owner)
	}

	owner = inbound.ownerFromIdentity(ctx, socketIdentity{valid: true, uid: 10060, cgroupID: shared})
	if len(owner.PackageNames) != 0 || owner.UserId != 10060 || owner.ProcessID != 110 {
		t.Fatalf("a shared-UID process must stay unknown, got %+v", owner)
	}

	owner = inbound.ownerFromIdentity(ctx, socketIdentity{valid: true, uid: 20050, cgroupID: sandbox})
	if len(owner.PackageNames) != 1 || owner.PackageNames[0] != "com.example.app" || owner.UserId != 20050 {
		t.Fatalf("SDK sandbox should map to its host package, got %+v", owner)
	}

	owner = inbound.ownerFromIdentity(ctx, socketIdentity{valid: true, uid: 1000, cgroupID: systemServer})
	if len(owner.PackageNames) != 0 || owner.UserId != 1000 || len(owner.ProcessPaths) != 0 {
		t.Fatalf("system_server (app_process) owner = %+v", owner)
	}

	// netd's DNS socket chowned to the app: attributed to netd (the sender).
	owner = inbound.ownerFromIdentity(ctx, socketIdentity{valid: true, uid: 10050, cgroupID: netd})
	if len(owner.PackageNames) != 0 || owner.UserId != 0 || owner.ProcessID != 200 ||
		len(owner.ProcessPaths) != 1 || owner.ProcessPaths[0] != "/system/bin/netd" {
		t.Fatalf("delegated DNS must follow the sender, got %+v", owner)
	}

	// Root cgroup (KernelSU/init processes): socket UID only, no package.
	owner = inbound.ownerFromIdentity(ctx, socketIdentity{valid: true, uid: 0, cgroupID: rootCgroupID})
	if owner == nil || owner.UserId != 0 || len(owner.PackageNames) != 0 {
		t.Fatalf("root cgroup owner = %+v", owner)
	}

	// Gone before lookup: UID kept, no package, never nil.
	owner = inbound.ownerFromIdentity(ctx, socketIdentity{valid: true, uid: 10050, cgroupID: 1 << 40})
	if owner == nil || owner.UserId != 10050 || len(owner.PackageNames) != 0 {
		t.Fatalf("vanished creator owner = %+v", owner)
	}

	// No identity recorded and no tracker: the old explicit-unknown result.
	owner = inbound.ownerFromIdentity(ctx, socketIdentity{cookie: 7})
	if owner == nil || owner.UserId != -1 {
		t.Fatalf("identity-less owner = %+v", owner)
	}

	counters := &inbound.identityCounters
	if counters.resolvedPackage.Load() != 2 || counters.unknownPackage.Load() != 3 ||
		counters.rootCgroup.Load() != 1 || counters.cgroupGone.Load() != 1 || counters.noIdentity.Load() != 1 {
		t.Fatalf("counters: resolved=%d unknownPackage=%d root=%d gone=%d none=%d",
			counters.resolvedPackage.Load(), counters.unknownPackage.Load(), counters.rootCgroup.Load(),
			counters.cgroupGone.Load(), counters.noIdentity.Load())
	}
}

func writeCmdline(t *testing.T, tree *fakeCgroupTree, pid uint32, name string) {
	t.Helper()
	path := filepath.Join(tree.proc, strconv.FormatUint(uint64(pid), 10), "cmdline")
	if err := os.WriteFile(path, append([]byte(name), 0), 0o644); err != nil {
		t.Fatal(err)
	}
}

// An instance's attribution is logged once, and again only when its package
// changes (unknown until the manifest index is built, then known).
func TestCgroupOwnerResolverLogsOncePerInstance(t *testing.T) {
	tree := newFakeCgroupTree(t)
	id := tree.addProcess(t, "apps", 10050, 100, "/system/bin/app_process64")
	resolver := newCgroupOwnerResolver(tree.root)
	if !resolver.lookup(id, 10050).found {
		t.Fatal("not found")
	}
	if !resolver.markLogged(id, "") {
		t.Fatal("first attribution not logged")
	}
	if resolver.markLogged(id, "") {
		t.Fatal("unchanged attribution logged twice")
	}
	if !resolver.markLogged(id, "com.example.app") {
		t.Fatal("package becoming known not logged")
	}
	if resolver.markLogged(id, "com.example.app") {
		t.Fatal("logged again without a change")
	}
	if resolver.markLogged(1<<40, "") {
		t.Fatal("an unknown cgroup was logged")
	}
}

func TestAndroidUserName(t *testing.T) {
	if runtime.GOOS != "android" {
		if _, ok := androidUserName(10460); ok {
			t.Fatal("named an Android UID on a non-Android OS")
		}
		return
	}
	for uid, want := range map[uint32]string{
		10460: "u0_a460", 1010460: "u10_a460", 99001: "u0_i9001", 10000: "u0_a0", 19999: "u0_a9999",
	} {
		if got, ok := androidUserName(uid); !ok || got != want {
			t.Fatalf("androidUserName(%d) = %q, %v; want %q", uid, got, ok, want)
		}
	}
	for _, uid := range []uint32{0, 1000, 20050, 9999} {
		if got, ok := androidUserName(uid); ok {
			t.Fatalf("androidUserName(%d) = %q, want none", uid, got)
		}
	}
}
