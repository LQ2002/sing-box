//go:build android

package androidmanifest

// On-device check against the live system. Skipped unless SBO_DEVICE_TEST=1.
//
//	GOOS=android GOARCH=arm64 CGO_ENABLED=0 go test -c -o androidmanifest.test ./common/androidmanifest/
//	su -c 'SBO_DEVICE_TEST=1 ./androidmanifest.test -test.v -test.run Device'
//
// For every running zygote child (cgroup apps/uid_X/pid_Y or
// system/uid_X/pid_Y, exe app_process*), its process name (cmdline) must be
// declared by at least one package of its UID, exactly as ActivityManager
// keys processes by (name, uid). A process no package declares means this
// parser or the naming rules miss something.

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/androidpackages"
)

func TestDeviceProcessNamesMatchManifests(t *testing.T) {
	if os.Getenv("SBO_DEVICE_TEST") != "1" {
		t.Skip("set SBO_DEVICE_TEST=1 to run on a device")
	}
	manager := androidpackages.New(androidpackages.Options{})
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	view := manager.Snapshot()

	type process struct {
		pid  string
		uid  uint32
		name string
	}
	var running []process
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		exe, _ := os.Readlink("/proc/" + entry.Name() + "/exe")
		if !strings.HasPrefix(filepath.Base(exe), "app_process") {
			continue
		}
		cgroup, _ := os.ReadFile("/proc/" + entry.Name() + "/cgroup")
		uid := uint32(0)
		ok := false
		for _, line := range strings.Split(string(cgroup), "\n") {
			relative, found := strings.CutPrefix(line, "0::")
			if !found {
				continue
			}
			for _, part := range strings.Split(relative, "/") {
				if value, cut := strings.CutPrefix(part, "uid_"); cut {
					parsed, err := strconv.ParseUint(value, 10, 32)
					uid, ok = uint32(parsed), err == nil
				}
			}
		}
		cmdline, _ := os.ReadFile("/proc/" + entry.Name() + "/cmdline")
		name, _, _ := strings.Cut(string(cmdline), "\x00")
		// Zygotes (zygote, webview_zygote, <package>_zygote app zygotes,
		// usap pool) fork processes but never open network sockets.
		if ok && name != "" && !strings.HasPrefix(name, "zygote") && !strings.HasSuffix(name, "_zygote") && !strings.HasPrefix(name, "usap") {
			running = append(running, process{pid: entry.Name(), uid: uid, name: ProcessRecordName(name)})
		}
	}

	cache := map[string][]string{}
	parseErrors := map[string]string{}
	start := time.Now()
	processesOf := func(packageName string) ([]string, bool) {
		if processes, loaded := cache[packageName]; loaded {
			return processes, true
		}
		if _, failed := parseErrors[packageName]; failed {
			return nil, false
		}
		code, loaded := view.PackageCode(packageName)
		if !loaded {
			parseErrors[packageName] = "no codePath"
			return nil, false
		}
		processes, err := PackageProcesses(packageName, code.Path)
		if err != nil {
			parseErrors[packageName] = err.Error()
			return nil, false
		}
		cache[packageName] = processes
		return processes, true
	}

	unique, multi, none, sandboxOrIsolated := 0, 0, 0, 0
	var missing []string
	for _, p := range running {
		appID := p.uid % 100000
		if appID >= 20000 { // SDK sandbox / isolated: no own packages
			sandboxOrIsolated++
			continue
		}
		packages, _ := view.PackagesByID(appID)
		var matches []string
		for _, packageName := range packages {
			processes, ok := processesOf(packageName)
			if !ok {
				continue
			}
			for _, name := range processes {
				if name == p.name {
					matches = append(matches, packageName)
					break
				}
			}
		}
		switch len(matches) {
		case 0:
			none++
			missing = append(missing, p.name+" uid="+strconv.FormatUint(uint64(p.uid), 10)+" candidates="+strings.Join(packages, ","))
		case 1:
			unique++
		default:
			multi++
			t.Logf("MULTI %s uid=%d: %s", p.name, p.uid, strings.Join(matches, ","))
		}
	}
	sort.Strings(missing)
	for _, line := range missing {
		t.Logf("NONE %s", line)
	}
	for packageName, err := range parseErrors {
		t.Logf("PARSE_ERROR %s: %s", packageName, err)
	}
	t.Logf("running=%d unique=%d multi=%d none=%d sandbox_or_isolated=%d parsed_packages=%d parse_errors=%d parse_time=%v",
		len(running), unique, multi, none, sandboxOrIsolated, len(cache), len(parseErrors), time.Since(start))

	// Cost of parsing every installed package once (the worst case for a
	// cold index).
	all := 0
	failed := 0
	start = time.Now()
	for id := uint32(0); id < 20000; id++ {
		packages, loaded := view.PackagesByID(id)
		if !loaded {
			continue
		}
		for _, packageName := range packages {
			code, loaded := view.PackageCode(packageName)
			if !loaded {
				continue
			}
			all++
			if _, err := PackageProcesses(packageName, code.Path); err != nil {
				failed++
			}
		}
	}
	t.Logf("all installed packages: %d parsed in %v, %d failed", all, time.Since(start), failed)
	if none > 0 {
		t.Errorf("%d running processes are declared by no package of their UID", none)
	}
}

// TestDeviceProcessNameHashes checks the socket creator v2 name evidence
// (ANDROID_ATTRIBUTION_PLAN.md, Claude 目标设计) over every installed
// package: per app ID, FNV-1a 64 of each manifest process name must not
// collide with a different name, and names declared by more than one package
// of the same app ID are counted, because such a name cannot single out a
// package. Names at or beyond the zygote argument block limits are counted
// too: setArgv0 strlcpy's into the zygote's original argv block
// (AndroidRuntime::setArgv0, app_main.cpp computeArgBlockSize), so a longer
// name reaches argv[0] truncated. The block sizes are read from the running
// zygote and USAP processes.
func TestDeviceProcessNameHashes(t *testing.T) {
	if os.Getenv("SBO_DEVICE_TEST") != "1" {
		t.Skip("set SBO_DEVICE_TEST=1 to run on a device")
	}
	manager := androidpackages.New(androidpackages.Options{})
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	view := manager.Snapshot()

	fnv := func(value string) uint64 {
		hash := uint64(0xcbf29ce484222325)
		for index := 0; index < len(value); index++ {
			hash ^= uint64(value[index])
			hash *= 0x100000001b3
		}
		return hash
	}
	// Argument block sizes of every running zygote-like parent.
	blocks := map[int]bool{}
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		cmdline, err := os.ReadFile("/proc/" + entry.Name() + "/cmdline")
		if err != nil {
			continue
		}
		name, _, _ := strings.Cut(string(cmdline), "\x00")
		if !strings.HasPrefix(name, "zygote") && !strings.HasSuffix(name, "_zygote") && !strings.HasPrefix(name, "usap") {
			continue
		}
		stat, err := os.ReadFile("/proc/" + entry.Name() + "/stat")
		if err != nil {
			continue
		}
		fields := strings.Fields(string(stat)[strings.LastIndexByte(string(stat), ')')+2:])
		if len(fields) < 47 {
			continue
		}
		start, _ := strconv.ParseUint(fields[45], 10, 64)
		end, _ := strconv.ParseUint(fields[46], 10, 64)
		t.Logf("ZYGOTE pid=%s name=%s arg_block=%d", entry.Name(), name, end-start)
		blocks[int(end-start)] = true
	}
	limit := 1 << 30
	for size := range blocks {
		limit = min(limit, size-1)
	}

	names, collisions, ambiguous, longest, overLimit, appIDs, failed := 0, 0, 0, 0, 0, 0, 0
	for id := uint32(0); id < 20000; id++ {
		packages, loaded := view.PackagesByID(id)
		if !loaded {
			continue
		}
		appIDs++
		owners := map[string]map[string]bool{}
		for _, packageName := range packages {
			code, loaded := view.PackageCode(packageName)
			if !loaded {
				continue
			}
			processes, err := PackageProcesses(packageName, code.Path)
			if err != nil {
				failed++
				continue
			}
			for _, process := range processes {
				if owners[process] == nil {
					owners[process] = map[string]bool{}
				}
				owners[process][packageName] = true
			}
		}
		hashes := map[uint64]string{}
		for process, packageSet := range owners {
			names++
			longest = max(longest, len(process))
			if len(process) >= limit {
				overLimit++
				t.Logf("AT_OR_OVER_BLOCK app_id=%d len=%d %s", id, len(process), process)
			}
			if len(packageSet) > 1 {
				ambiguous++
				list := make([]string, 0, len(packageSet))
				for packageName := range packageSet {
					list = append(list, packageName)
				}
				sort.Strings(list)
				t.Logf("AMBIGUOUS app_id=%d %s: %s", id, process, strings.Join(list, ","))
			}
			hash := fnv(process)
			if other, exists := hashes[hash]; exists && other != process {
				collisions++
				t.Errorf("FNV collision app_id=%d %q %q", id, process, other)
			}
			hashes[hash] = process
		}
	}
	t.Logf("app_ids=%d process_names=%d ambiguous_names=%d hash_collisions=%d longest=%d smallest_block_limit=%d at_or_over_limit=%d parse_failures=%d",
		appIDs, names, ambiguous, collisions, longest, limit, overLimit, failed)
}
