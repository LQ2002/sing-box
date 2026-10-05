//go:build android

package androidmanifest

// On-device measurement of the "colon prefix" shortcut proposed as a
// replacement for the manifest index: for a process name "<a>:<b>", take <a>
// as the package. Skipped unless SBO_DEVICE_TEST=1.
//
//	GOOS=android GOARCH=arm64 CGO_ENABLED=0 go test -c -o androidmanifest.test ./common/androidmanifest/
//	su -c 'SBO_DEVICE_TEST=1 ./androidmanifest.test -test.v -test.run ColonPrefix'
//
// Only shared UIDs (more than one package per app ID) use the manifest index
// at all; every other UID maps to its single package directly. So the rule is
// measured against the declarations of every package of every shared app ID,
// and against the running zygote children of those app IDs.

import (
	"bufio"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/androidpackages"
)

func TestDeviceColonPrefixRule(t *testing.T) {
	if os.Getenv("SBO_DEVICE_TEST") != "1" {
		t.Skip("set SBO_DEVICE_TEST=1 to run on a device")
	}
	manager := androidpackages.New(androidpackages.Options{})
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	view := manager.Snapshot()

	file, err := os.Open("/data/system/packages.list")
	if err != nil {
		t.Fatal(err)
	}
	byApp := map[uint32][]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		uid, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			continue
		}
		byApp[uint32(uid)%100000] = append(byApp[uint32(uid)%100000], fields[0])
	}
	file.Close()

	// Cost of the index this shortcut would replace: parse time and the heap
	// the resulting name -> packages tables keep alive.
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	parseStart := time.Now()
	// declared[appID][name] = packages declaring that process name
	declared := map[uint32]map[string][]string{}
	parseFailures := 0
	for appID, packages := range byApp {
		if len(packages) < 2 {
			continue
		}
		names := map[string][]string{}
		for _, packageName := range packages {
			code, ok := view.PackageCode(packageName)
			if !ok {
				parseFailures++
				continue
			}
			processes, err := PackageProcesses(packageName, code.Path)
			if err != nil {
				parseFailures++
				continue
			}
			for _, name := range processes {
				names[name] = append(names[name], packageName)
			}
		}
		declared[appID] = names
	}

	member := func(appID uint32, packageName string) bool {
		for _, p := range byApp[appID] {
			if p == packageName {
				return true
			}
		}
		return false
	}
	// judge applies the rule to one (app ID, name) and compares it with the
	// manifest answer: the single declaring package, or none if ambiguous.
	judge := func(appID uint32, name string) (string, string) {
		declarers := declared[appID][name]
		truth := ""
		if len(declarers) == 1 {
			truth = declarers[0]
		}
		prefix, _, colon := strings.Cut(name, ":")
		switch {
		case !colon && len(declarers) > 1:
			return "no_colon_multi_package", ""
		case !colon && len(declarers) == 1:
			return "no_colon_unique", ""
		case !colon:
			return "no_colon_undeclared", ""
		case !member(appID, prefix):
			return "colon_prefix_not_a_package_of_uid", prefix + " vs " + strings.Join(declarers, ",")
		case len(declarers) > 1:
			return "colon_but_multi_package", prefix + " vs " + strings.Join(declarers, ",")
		case truth == prefix:
			return "colon_correct", ""
		case truth == "":
			return "colon_undeclared", prefix
		default:
			return "colon_wrong", prefix + " vs " + truth
		}
	}

	report := func(label string, counts map[string]int, examples map[string][]string) {
		keys := make([]string, 0, len(counts))
		total := 0
		for k, v := range counts {
			keys = append(keys, k)
			total += v
		}
		sort.Strings(keys)
		for _, k := range keys {
			t.Logf("%s %s=%d/%d", label, k, counts[k], total)
			for _, e := range examples[k] {
				t.Logf("%s   %s", label, e)
			}
		}
	}

	counts := map[string]int{}
	examples := map[string][]string{}
	sharedApps, sharedPackages := 0, 0
	for appID, names := range declared {
		sharedApps++
		sharedPackages += len(byApp[appID])
		for name := range names {
			verdict, detail := judge(appID, name)
			counts[verdict]++
			if verdict != "colon_correct" && verdict != "no_colon_unique" && len(examples[verdict]) < 8 {
				examples[verdict] = append(examples[verdict], "app "+strconv.Itoa(int(appID))+" "+name+" "+detail)
			}
		}
	}
	parseTime := time.Since(parseStart)
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(declared)
	t.Logf("COST parse=%s retained_heap_bytes=%d", parseTime.Round(time.Millisecond), int64(after.HeapAlloc)-int64(before.HeapAlloc))
	t.Logf("SHARED app_ids=%d packages=%d parse_failures=%d", sharedApps, sharedPackages, parseFailures)
	report("DECLARED", counts, examples)

	running := map[string]int{}
	runningExamples := map[string][]string{}
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		exe, _ := os.Readlink("/proc/" + entry.Name() + "/exe")
		if !strings.HasSuffix(exe, "/app_process64") && !strings.HasSuffix(exe, "/app_process32") {
			continue
		}
		var st os.FileInfo
		if st, err = os.Stat("/proc/" + entry.Name()); err != nil {
			continue
		}
		_ = st
		status, _ := os.ReadFile("/proc/" + entry.Name() + "/status")
		uid := uint32(0)
		for _, line := range strings.Split(string(status), "\n") {
			if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
				if f := strings.Fields(rest); len(f) > 0 {
					v, _ := strconv.ParseUint(f[0], 10, 32)
					uid = uint32(v)
				}
			}
		}
		appID := uid % 100000
		if _, shared := declared[appID]; !shared {
			continue
		}
		cmdline, _ := os.ReadFile("/proc/" + entry.Name() + "/cmdline")
		name, _, _ := strings.Cut(string(cmdline), "\x00")
		if name == "" || strings.HasPrefix(name, "zygote") || strings.HasSuffix(name, "_zygote") || strings.HasPrefix(name, "usap") {
			continue
		}
		name = ProcessRecordName(name)
		verdict, detail := judge(appID, name)
		running[verdict]++
		if len(runningExamples[verdict]) < 12 {
			runningExamples[verdict] = append(runningExamples[verdict], "uid "+strconv.Itoa(int(uid))+" "+name+" "+detail)
		}
	}
	report("RUNNING", running, runningExamples)
}
