//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"os"
	"slices"
	"strconv"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/androidpackages"
	"github.com/sagernet/sing-box/log"
)

func TestUniqueApplicationPackage(t *testing.T) {
	for _, tc := range []struct {
		name     string
		uid      uint32
		packages []string
		shared   string
		reverse  uint32
		want     string
	}{
		{"ordinary", 10100, []string{"real.package"}, "", 10100, "real.package"},
		{"secondary_user", 1010100, []string{"real.package"}, "", 10100, "real.package"},
		{"multiple_packages", 10100, []string{"package.a", "package.b"}, "", 10100, ""},
		{"declared_shared_even_with_one_package", 10100, []string{"package.a"}, "shared.user", 10100, ""},
		{"system_uid", 1000, []string{"android"}, "", 1000, ""},
		{"isolated_uid", 99000, []string{"guessed.parent"}, "", 99000, ""},
		{"sdk_sandbox_uid", 20100, []string{"guessed.parent"}, "", 20100, ""},
		{"unknown", 10100, nil, "", 10100, ""},
		{"empty_package", 10100, []string{""}, "", 10100, ""},
		{"reverse_mismatch", 10100, []string{"real.package"}, "", 10101, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pm := &testPackageManager{
				packagesByID:    map[uint32][]string{tc.uid % 100000: tc.packages},
				idByPackage:     make(map[string]uint32),
				sharedPackageID: make(map[uint32]string),
			}
			for _, name := range tc.packages {
				pm.idByPackage[name] = tc.reverse
			}
			if tc.shared != "" {
				pm.sharedPackageID[tc.uid%100000] = tc.shared
			}
			if got := uniqueApplicationPackage(pm, tc.uid); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	if got := uniqueApplicationPackage(nil, 10100); got != "" {
		t.Fatal(got)
	}
}

func TestRefineConnectionOwnerDoesNotGuessPackages(t *testing.T) {
	pm := &testPackageManager{
		packagesByID: map[uint32][]string{10100: {"real.package"}, 10101: {"package.a", "package.b"}},
		idByPackage:  map[string]uint32{"real.package": 10100, "package.a": 10101, "package.b": 10101},
	}
	for _, tc := range []struct {
		name, executable, comm  string
		uid                     uint32
		wantPaths, wantPackages []string
	}{
		{"native", "/system/bin/netd", "fake.package", 1000, []string{"/system/bin/netd"}, nil},
		{"unique_64bit", "/system/bin/app_process64", "unrelated.name", 10100, nil, []string{"real.package"}},
		{"unique_32bit", "/system/bin/app_process32", "unrelated.name", 10100, nil, []string{"real.package"}},
		{"shared_uid", "/system/bin/app_process64", "package.a", 10101, nil, nil},
		{"missing_membership", "/system/bin/app_process64", "fake.package", 10102, nil, nil},
		{"missing_exe", "", "fake.package", 10100, []string{"fake.package"}, nil},
		{"similar_native_name", "/data/local/tmp/app_process64-other", "", 10100, []string{"/data/local/tmp/app_process64-other"}, nil},
		{"deleted_native", "/data/local/tmp/probe (deleted)", "", 10100, []string{"/data/local/tmp/probe"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := &adapter.ConnectionOwner{UserId: int32(tc.uid), PackageNames: []string{"stale.guess"}}
			if tc.executable != "" {
				info.ProcessPaths = []string{tc.executable}
			}
			refineConnectionOwner(info, SocketOwner{UserID: tc.uid, Comm: tc.comm}, pm)
			if !slices.Equal(info.ProcessPaths, tc.wantPaths) || !slices.Equal(info.PackageNames, tc.wantPackages) {
				t.Fatalf("paths=%v packages=%v", info.ProcessPaths, info.PackageNames)
			}
		})
	}
	refineConnectionOwner(nil, SocketOwner{}, nil)
}

func TestSocketOwnerCacheDoesNotFreezePackageMembership(t *testing.T) {
	cache := socketOwnerCache()
	if cache == nil {
		t.Fatal("cache unavailable")
	}
	owner := SocketOwner{ProcessID: 4000000000, UserID: 10100, StartTimeNs: 1234567890}
	key := socketOwnerCacheKey{ProcessID: owner.ProcessID, UserID: owner.UserID, StartTimeNs: owner.StartTimeNs}
	cache.Add(key, &socketOwnerMetadata{ConnectionOwner: &adapter.ConnectionOwner{ProcessID: owner.ProcessID, UserId: 10100, ProcessPaths: []string{"/system/bin/app_process64"}}})
	defer cache.Remove(key)
	pm := &testPackageManager{packagesByID: map[uint32][]string{10100: {"package.a"}}, idByPackage: map[string]uint32{"package.a": 10100, "package.b": 10100}}
	inbound := &Inbound{logger: log.NewNOPFactory().Logger(), networkManager: &testNetworkManager{packageManager: pm}}
	first := inbound.resolveSocketOwner(context.Background(), owner)
	if !slices.Equal(first.PackageNames, []string{"package.a"}) {
		t.Fatal(first)
	}
	pm.packagesByID[10100] = []string{"package.a", "package.b"}
	next := inbound.resolveSocketOwner(context.Background(), owner)
	if len(next.PackageNames) != 0 {
		t.Fatalf("cached an earlier single package: %+v", next)
	}
	if !slices.Equal(first.PackageNames, []string{"package.a"}) {
		t.Fatal("mutated previously returned metadata")
	}
	raw, _ := cache.Get(key)
	if len(raw.PackageNames) != 0 || !slices.Equal(raw.ProcessPaths, []string{"/system/bin/app_process64"}) {
		t.Fatalf("cache was refined in place: %+v", raw)
	}
}

// The coherent snapshot is empty, but the live methods can already expose
// a new package table. A multi-query decision must use exactly one view.
type snapshotTestPackageManager struct {
	*testPackageManager
	snapshots int
}

func (m *snapshotTestPackageManager) Snapshot() androidpackages.View {
	m.snapshots++
	return androidpackages.View{}
}

func TestSocketOwnerRefinementUsesOnePackageSnapshot(t *testing.T) {
	owner := SocketOwner{ProcessID: 4000000002, UserID: 10100, StartTimeNs: 1234567890}
	key := socketOwnerCacheKey{ProcessID: owner.ProcessID, UserID: owner.UserID, StartTimeNs: owner.StartTimeNs}
	socketOwnerCache().Add(key, &socketOwnerMetadata{ConnectionOwner: &adapter.ConnectionOwner{
		ProcessID: owner.ProcessID, UserId: 10100, ProcessPaths: []string{"/system/bin/app_process64"},
	}})
	t.Cleanup(func() { socketOwnerCache().Remove(key) })
	packages := &snapshotTestPackageManager{testPackageManager: &testPackageManager{
		packagesByID: map[uint32][]string{10100: {"new.package"}}, idByPackage: map[string]uint32{"new.package": 10100},
	}}
	inbound := &Inbound{logger: log.NewNOPFactory().Logger(), networkManager: &testNetworkManager{packageManager: packages}}
	info := inbound.resolveSocketOwner(context.Background(), owner)
	if len(info.PackageNames) != 0 || packages.snapshots != 1 {
		t.Fatalf("refinement mixed live package methods with snapshot: %+v, snapshots=%d", info, packages.snapshots)
	}
}

func TestSocketOwnerWithoutStartTimeKeepsPackageUnknown(t *testing.T) {
	inbound := &Inbound{logger: log.NewNOPFactory().Logger(), networkManager: &testNetworkManager{
		packageManager: &testPackageManager{packagesByID: map[uint32][]string{10100: {"real.package"}}, idByPackage: map[string]uint32{"real.package": 10100}},
	}}
	info := inbound.resolveSocketOwner(context.Background(), SocketOwner{ProcessID: 1, UserID: 10100, Comm: "/app_process64"})
	if len(info.PackageNames) != 0 || info.UserId != 10100 {
		t.Fatalf("comm was treated as verified exe: %+v", info)
	}
}

func TestSocketOwnerIncompleteReadIsNotCached(t *testing.T) {
	inbound := &Inbound{logger: log.NewNOPFactory().Logger()}
	owner := SocketOwner{ProcessID: 4000000001, UserID: 10100, StartTimeNs: 1234567890, Comm: "package.guess"}
	info := inbound.resolveSocketOwner(context.Background(), owner)
	if len(info.PackageNames) != 0 || info.UserId != 10100 {
		t.Fatal(info)
	}
	key := socketOwnerCacheKey{ProcessID: owner.ProcessID, UserID: owner.UserID, StartTimeNs: owner.StartTimeNs}
	if _, loaded := socketOwnerCache().Get(key); loaded {
		t.Fatal("incomplete metadata was cached")
	}
}

func TestSocketOwnerProcValidationChecksUIDAndStart(t *testing.T) {
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	ticks, ok := parseStartTicks(raw)
	if !ok {
		t.Fatal("could not parse own start time")
	}
	inbound := &Inbound{logger: log.NewNOPFactory().Logger()}
	owner := SocketOwner{ProcessID: uint32(os.Getpid()), UserID: uint32(os.Getuid()), StartTimeNs: ticks * 10000000}
	if _, verified := inbound.resolveThroughProcDir(owner); !verified {
		t.Fatal("own process did not verify")
	}
	owner.UserID++
	if _, verified := inbound.resolveThroughProcDir(owner); verified {
		t.Fatal("accepted a different creator UID")
	}
	owner.UserID--
	owner.StartTimeNs += 10000000
	if _, verified := inbound.resolveThroughProcDir(owner); verified {
		t.Fatal("accepted an adjacent start tick")
	}
}

type missingSocketOwnerSource struct{}

func (missingSocketOwnerSource) LookupSocketOwner(uint64) (SocketOwner, error) {
	return SocketOwner{}, os.ErrNotExist
}
func (missingSocketOwnerSource) TrackingMode() string { return "test" }
func (missingSocketOwnerSource) IsClosed() bool       { return false }
func (missingSocketOwnerSource) Close() error         { return nil }

func TestUnknownSocketOwnerStopsGenericPackageFallback(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cookie uint64
		source SocketOwnerSource
	}{
		{"no_cookie", 0, missingSocketOwnerSource{}},
		{"no_source", 1, nil},
		{"lookup_miss", 1, missingSocketOwnerSource{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inbound := &Inbound{logger: log.NewNOPFactory().Logger(), processTracker: tc.source}
			info := inbound.lookupProcessInfo(context.Background(), tc.cookie)
			if info == nil || info.UserId != -1 || info.ProcessID != 0 || len(info.PackageNames) != 0 {
				t.Fatalf("unknown result permits fallback or asserts identity: %+v", info)
			}
		})
	}
}

func TestStartTicksMatchRequiresExactTick(t *testing.T) {
	if !startTicksMatch(123, 1239999999) || startTicksMatch(122, 1239999999) || startTicksMatch(124, 1239999999) {
		t.Fatal("adjacent ticks accepted, or exact conversion rejected")
	}
}

func TestParseProcessUID(t *testing.T) {
	for _, tc := range []struct {
		raw string
		uid uint32
		ok  bool
	}{
		{"Name:\ttest\nUid:\t10100\t10100\t10100\t10100\n", 10100, true},
		{"Uid:\t1000\t0\t0\t0\n", 1000, true},
		{"Uid:\tinvalid\t0\t0\t0\n", 0, false},
		{"Uid:\t1000\n", 0, false},
		{"", 0, false},
	} {
		uid, ok := parseProcessUID([]byte(tc.raw))
		if uid != tc.uid || ok != tc.ok {
			t.Fatalf("%q: %d %v", tc.raw, uid, ok)
		}
	}
}
func TestParseStartTicks(t *testing.T) {
	t.Parallel()

	// 真实 /proc/<pid>/stat 的形状：第 22 个字段是 starttime。
	// 这里把它设为 1234567，前面按真实格式补齐 21 个字段。
	const startTicks = 1234567
	build := func(comm string) []byte {
		return []byte("4242 (" + comm + ") S 1 4242 4242 0 -1 4194560 " +
			"100 0 0 0 10 20 0 0 20 0 1 0 " +
			strconv.Itoa(startTicks) + " 123456 789 18446744073709551615")
	}

	for _, testCase := range []struct {
		name string
		raw  []byte
		want uint64
		ok   bool
	}{
		{"普通进程名", build("netd"), startTicks, true},
		// 进程名里含空格：不能按空格直接切分整行。
		{"进程名含空格", build("Binder:1234 5"), startTicks, true},
		// 进程名里含右括号：必须从最后一个 ')' 之后开始切分。
		{"进程名含右括号", build("weird)name"), startTicks, true},
		{"两者兼有", build("a ) b"), startTicks, true},
		{"没有右括号", []byte("4242 no parens here"), 0, false},
		{"字段不足", []byte("4242 (x) S 1 2 3"), 0, false},
		{"空输入", []byte(""), 0, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseStartTicks(testCase.raw)
			if ok != testCase.ok {
				t.Fatalf("ok = %v, want %v", ok, testCase.ok)
			}
			if got != testCase.want {
				t.Errorf("ticks = %d, want %d", got, testCase.want)
			}
		})
	}
}
