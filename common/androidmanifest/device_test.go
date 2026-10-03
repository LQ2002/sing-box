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
