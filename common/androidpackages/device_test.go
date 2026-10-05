//go:build android

package androidpackages

// On-device acceptance for stage 1 of ANDROID_ATTRIBUTION_PLAN.md. Skipped
// unless SBO_DEVICE_TEST=1; it installs and removes throwaway test packages,
// so it only runs when asked to, as root, on a phone.
//
//	GOOS=android GOARCH=arm64 CGO_ENABLED=0 go test -c -o androidpackages.test ./common/androidpackages/
//	adb push androidpackages.test test-single.apk test-a.apk test-b.apk /data/local/tmp/<dir>/
//	su -c 'cd /data/local/tmp/<dir> && SBO_DEVICE_TEST=1 SBO_APK_DIR=$PWD ./androidpackages.test -test.v -test.run Device'
//
// The APKs are the diagnostic packages built in experimental/first_connection_probe:
// dev.sbo.firstconnection.single (own UID), and .a / .b, which share the UID
// "dev.sbo.firstconnection.shared".

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

const (
	devicePackageSingle = "dev.sbo.firstconnection.single"
	devicePackageA      = "dev.sbo.firstconnection.a"
	devicePackageB      = "dev.sbo.firstconnection.b"
	deviceRounds        = 10
	deviceWait          = 15 * time.Second
)

func requireDevice(t *testing.T) string {
	if os.Getenv("SBO_DEVICE_TEST") != "1" {
		t.Skip("set SBO_DEVICE_TEST=1 to run on a device")
	}
	apkDir := os.Getenv("SBO_APK_DIR")
	require.NotEmpty(t, apkDir, "SBO_APK_DIR must point at the test APKs")
	return apkDir
}

func pm(t *testing.T, args ...string) string {
	t.Helper()
	output, err := exec.Command("pm", args...).CombinedOutput()
	require.NoError(t, err, "pm %v: %s", args, output)
	return string(output)
}

// pmUID asks PackageManager itself (a synchronous binder query) for a
// package's UID; 0 means not installed.
func pmUID(t *testing.T, name string) uint32 {
	t.Helper()
	for _, line := range strings.Split(pm(t, "list", "packages", "-U", name), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 || fields[0] != "package:"+name {
			continue
		}
		uid, err := strconv.ParseUint(strings.Split(strings.TrimPrefix(fields[1], "uid:"), ",")[0], 10, 32)
		require.NoError(t, err)
		return uint32(uid)
	}
	return 0
}

type nopCallback struct{}

func (nopCallback) OnPackagesUpdated(int, int) {}

// The local parser must answer exactly like sing-tun's on the live file.
func TestDeviceParityWithSingTun(t *testing.T) {
	requireDevice(t)
	local, err := (&Manager{path: DefaultPath, backupPath: strings.TrimSuffix(DefaultPath, ".xml") + "-backup.xml"}).read()
	require.NoError(t, err)
	reference, err := tun.NewPackageManager(tun.PackageManagerOptions{Callback: nopCallback{}, Logger: logger.NOP()})
	require.NoError(t, err)
	require.NoError(t, reference.Start())
	defer reference.Close()

	for name, id := range local.idByPackage {
		referenceID, loaded := reference.IDByPackage(name)
		require.True(t, loaded, name)
		require.Equal(t, referenceID, id, name)
	}
	for name, id := range local.sharedByPackage {
		referenceID, loaded := reference.IDBySharedPackage(name)
		require.True(t, loaded, name)
		require.Equal(t, referenceID, id, name)
	}
	for id, names := range local.packageByID {
		referenceNames, loaded := reference.PackagesByID(id)
		require.True(t, loaded, id)
		require.ElementsMatch(t, referenceNames, names, id)
		first, _ := reference.PackageByID(id)
		require.Equal(t, first, names[0], "PackageByID order for %d", id)
	}
	for id, name := range local.sharedByID {
		referenceName, loaded := reference.SharedPackageByID(id)
		require.True(t, loaded, id)
		require.Equal(t, referenceName, name)
	}
	t.Logf("parity: %d packages, %d UIDs, %d shared users identical to sing-tun",
		len(local.idByPackage), len(local.packageByID), len(local.sharedByID))
}

func openFDs(t *testing.T) int {
	entries, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	return len(entries)
}

func TestDeviceRefreshAcrossInstalls(t *testing.T) {
	apkDir := requireDevice(t)
	for _, name := range []string{devicePackageSingle, devicePackageA, devicePackageB} {
		require.Zero(t, pmUID(t, name), "%s is already installed; remove it before running", name)
	}
	t.Cleanup(func() {
		for _, name := range []string{devicePackageSingle, devicePackageB, devicePackageA} {
			exec.Command("pm", "uninstall", name).Run()
		}
	})

	callback := &recorder{}
	manager := New(Options{Callback: callback})
	require.NoError(t, manager.Start())
	defer manager.Close()

	// Settle, then take the resource baseline with the manager running.
	time.Sleep(time.Second)
	runtime.GC()
	baseGoroutines, baseFDs := runtime.NumGoroutine(), openFDs(t)

	apk := func(name string) string { return filepath.Join(apkDir, name) }
	var latencies []time.Duration
	// waitFor polls the manager until check passes and records how long the
	// change took to show up after pm returned.
	waitFor := func(what string, check func() bool) {
		t.Helper()
		start := time.Now()
		require.Eventually(t, check, deviceWait, 5*time.Millisecond, what)
		latencies = append(latencies, time.Since(start))
	}
	sharedID := func() (uint32, bool) { return manager.IDBySharedPackage("dev.sbo.firstconnection.shared") }

	for round := 1; round <= deviceRounds; round++ {
		// Own-UID package: install, in-place reinstall (package replace, the
		// path an update takes; same version, so UID is kept), uninstall.
		pm(t, "install", apk("test-single.apk"))
		uid := pmUID(t, devicePackageSingle)
		require.NotZero(t, uid)
		waitFor("install single", func() bool { id, ok := manager.IDByPackage(devicePackageSingle); return ok && id == uid })

		pm(t, "install", "-r", apk("test-single.apk"))
		require.Equal(t, uid, pmUID(t, devicePackageSingle), "reinstall keeps the UID")
		time.Sleep(300 * time.Millisecond)
		id, ok := manager.IDByPackage(devicePackageSingle)
		require.True(t, ok && id == uid, "round %d: single missing or changed after reinstall", round)

		pm(t, "uninstall", devicePackageSingle)
		waitFor("uninstall single", func() bool { _, ok := manager.IDByPackage(devicePackageSingle); return !ok })
		names, _ := manager.PackagesByID(uid)
		require.NotContains(t, names, devicePackageSingle, "old UID still maps to the removed package")

		// Shared UID: A, then A+B, then A again, then nothing.
		pm(t, "install", apk("test-a.apk"))
		shared := pmUID(t, devicePackageA)
		require.NotZero(t, shared)
		waitFor("install A", func() bool {
			names, ok := manager.PackagesByID(shared)
			id, sharedOK := sharedID()
			return ok && sharedOK && id == shared && slices.Equal(names, []string{devicePackageA})
		})
		pm(t, "install", apk("test-b.apk"))
		require.Equal(t, shared, pmUID(t, devicePackageB), "B joins A's shared UID")
		waitFor("install B (A+B)", func() bool {
			names, _ := manager.PackagesByID(shared)
			return len(names) == 2 && slices.Contains(names, devicePackageA) && slices.Contains(names, devicePackageB)
		})
		pm(t, "uninstall", devicePackageB)
		waitFor("uninstall B (A)", func() bool {
			names, _ := manager.PackagesByID(shared)
			return slices.Equal(names, []string{devicePackageA})
		})
		pm(t, "uninstall", devicePackageA)
		waitFor("uninstall A", func() bool {
			_, ok := manager.IDByPackage(devicePackageA)
			_, sharedOK := sharedID()
			return !ok && !sharedOK
		})
		t.Logf("round %d ok: single uid %d, shared uid %d", round, uid, shared)
	}

	time.Sleep(time.Second)
	runtime.GC()
	goroutines, fds := runtime.NumGoroutine(), openFDs(t)
	t.Logf("goroutines %d -> %d, fds %d -> %d, callbacks %d", baseGoroutines, goroutines, baseFDs, fds, callback.calls.Load())
	require.LessOrEqual(t, goroutines, baseGoroutines+2, "goroutines grew")
	require.LessOrEqual(t, fds, baseFDs+2, "file descriptors grew")

	slices.Sort(latencies)
	t.Logf("change visible after pm returned (n=%d): min %v, median %v, max %v",
		len(latencies), latencies[0], latencies[len(latencies)/2], latencies[len(latencies)-1])
}
