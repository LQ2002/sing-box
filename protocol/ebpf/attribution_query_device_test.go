//go:build android && with_ebpf && attribution_query_device

package ebpf

// Query-only device microbenchmark. This shared file also builds unchanged
// in the exact pre-stage-3 tree (7c12b1de); copy only this file there. The
// current-tree companion adds the TC UID/group fast path without emulating
// either production resolver. Normal tests cannot run this accidentally:
// both the attribution_query_device build tag and SBO_QUERY_BENCH=1 are needed.
//
// The module fixture is one real, unconnected native TCP socket owned by this
// root test process. No packet, BPF attachment, namespace, UID or service is
// changed. Package-manager initialization and logger output are outside the
// measurement; a NOP logger is used. "cache_miss" removes only the resolver's
// entry before each timed call, not OS caches, and is not an App cold start.
// A warm phase primes the same query 128 times. Raw timings include the Go
// time.Now/Since measurement cost; an empty timer distribution is also saved.
//
// Run the compiled Android test as root, redirecting stdout to a result file:
// SBO_QUERY_BENCH=1 SBO_QUERY_BUILD=<revision> ./query.test \
//   -test.v -test.run '^TestDeviceAttributionQuery$' -test.timeout 2m
// SBO_QUERY_PACKAGE defaults to com.android.chrome for the optional current
// fast-path input. It must already be installed/running; no App is launched.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/androidpackages"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"golang.org/x/sys/unix"
)

type queryBenchNetworkManager struct {
	adapter.NetworkManager
	packages tun.PackageManager
}

func (m *queryBenchNetworkManager) PackageManager() tun.PackageManager { return m.packages }

type queryBenchTarget struct {
	name     string
	fixture  map[string]any
	call     func() *adapter.ConnectionOwner
	reset    func()
	validate func(*adapter.ConnectionOwner) bool
}

// Nil in the archived old tree. No current-only symbol is used by this file.
var queryBenchCurrentTargets func(*testing.T, *Inbound, tun.PackageManager) []queryBenchTarget

func queryBenchEmit(t *testing.T, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("QUERY_BENCH " + string(encoded))
}

func TestDeviceAttributionQuery(t *testing.T) {
	if os.Getenv("SBO_QUERY_BENCH") != "1" {
		t.Skip("set SBO_QUERY_BENCH=1 for the explicit query-only device benchmark")
	}
	if os.Geteuid() != 0 {
		t.Fatal("module query requires root")
	}
	packages := androidpackages.New(androidpackages.Options{})
	if err := packages.Start(); err != nil {
		t.Fatal(err)
	}
	defer packages.Close()
	module, err := OpenSocketOwnerModule()
	if err != nil {
		t.Fatal(err)
	}
	defer module.Close()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		t.Fatal(err)
	}
	creator, err := module.LookupSocketOwner(cookie)
	if err != nil {
		t.Fatal(err)
	}
	if creator.ProcessID != uint32(os.Getpid()) || creator.UserID != uint32(os.Getuid()) || creator.StartTimeNs == 0 {
		t.Fatalf("module fixture does not match this process: %+v", creator)
	}
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	ticks, valid := parseStartTicks(stat)
	if !valid || !startTicksMatch(ticks, creator.StartTimeNs) {
		t.Fatal("module creator start time does not match /proc/self/stat")
	}
	executable, err := os.Readlink("/proc/self/exe")
	if err != nil || !filepath.IsAbs(executable) {
		t.Fatalf("read actual native executable: path=%q error=%v", executable, err)
	}
	inbound := &Inbound{
		logger:         log.NewNOPFactory().Logger(),
		processTracker: module,
		networkManager: &queryBenchNetworkManager{packages: packages},
	}
	ctx := context.Background()
	cacheKey := socketOwnerCacheKey{ProcessID: creator.ProcessID, UserID: creator.UserID, StartTimeNs: creator.StartTimeNs}
	cache := socketOwnerCache()
	if cache == nil {
		t.Fatal("socket owner metadata cache unavailable")
	}
	defer cache.Remove(cacheKey)
	targets := []queryBenchTarget{{
		name:    "module_production_lookup_self_native",
		fixture: map[string]any{"source": "real_unconnected_native_tcp_socket", "cookie": cookie, "creator": creator, "expected_executable": executable},
		call:    func() *adapter.ConnectionOwner { return inbound.lookupProcessInfo(ctx, cookie) },
		reset:   func() { cache.Remove(cacheKey) },
		validate: func(owner *adapter.ConnectionOwner) bool {
			return owner != nil && owner.ProcessID == creator.ProcessID && owner.UserId == int32(creator.UserID) && len(owner.ProcessPaths) == 1 && owner.ProcessPaths[0] == executable && len(owner.PackageNames) == 0
		},
	}}
	if queryBenchCurrentTargets != nil {
		targets = append(targets, queryBenchCurrentTargets(t, inbound, packages)...)
	}
	build := os.Getenv("SBO_QUERY_BUILD")
	if build == "" {
		t.Fatal("SBO_QUERY_BUILD must identify the compiled source revision")
	}
	queryBenchEmit(t, map[string]any{"kind": "configuration", "build": build, "pid": os.Getpid(), "rounds": 5, "cache_miss_iterations": 500, "warm_iterations": 5000, "logger": "nop", "scope": "userspace production query only; no TC acquisition, packet forwarding, App startup or module unload"})
	for _, target := range targets {
		target.reset()
		begin := time.Now()
		owner := target.call()
		first := time.Since(begin).Nanoseconds()
		if !target.validate(owner) {
			t.Fatalf("%s fixture output invalid: %+v", target.name, owner)
		}
		queryBenchEmit(t, map[string]any{"kind": "fixture", "build": build, "query": target.name, "input": target.fixture, "first_lookup_ns": first, "output": owner})
	}
	for round := 1; round <= 5; round++ {
		empty := make([]int64, 5000)
		for index := range empty {
			begin := time.Now()
			empty[index] = time.Since(begin).Nanoseconds()
		}
		queryBenchEmit(t, map[string]any{"kind": "samples", "build": build, "round": round, "query": "timer_only", "state": "warm", "durations_ns": empty})
		for targetIndex := range targets {
			// Alternate method order between rounds inside the current build.
			if round%2 == 0 {
				targetIndex = len(targets) - 1 - targetIndex
			}
			target := targets[targetIndex]
			for _, state := range []string{"cache_miss", "warm"} {
				count := 500
				if state == "warm" {
					count = 5000
					for range 128 {
						_ = target.call()
					}
				}
				durations := make([]int64, count)
				for sample := range durations {
					if state == "cache_miss" {
						target.reset()
					}
					begin := time.Now()
					owner := target.call()
					durations[sample] = time.Since(begin).Nanoseconds()
					if !target.validate(owner) {
						t.Fatalf("%s/%s output changed: %+v", target.name, state, owner)
					}
				}
				queryBenchEmit(t, map[string]any{"kind": "samples", "build": build, "round": round, "query": target.name, "state": state, "durations_ns": durations})
			}
		}
	}
}
