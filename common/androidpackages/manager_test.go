package androidpackages

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testQuietPeriod = 20 * time.Millisecond

type recorder struct {
	calls atomic.Int32
}

func (r *recorder) OnPackagesUpdated(packages int, sharedUsers int) {
	r.calls.Add(1)
}

func packagesDocument(names ...string) string {
	var builder strings.Builder
	builder.WriteString("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<packages>\n")
	for index, name := range names {
		fmt.Fprintf(&builder, "    <package name=%q userId=\"%d\">\n        <perms />\n    </package>\n", name, 10100+index)
	}
	builder.WriteString("    <shared-user name=\"android.uid.system\" userId=\"1000\" />\n</packages>\n")
	return builder.String()
}

type testTable struct {
	dir    string
	path   string
	backup string
}

func newTestTable(t *testing.T, initial string) testTable {
	t.Helper()
	dir := t.TempDir()
	table := testTable{
		dir:    dir,
		path:   filepath.Join(dir, "packages.xml"),
		backup: filepath.Join(dir, "packages-backup.xml"),
	}
	require.NoError(t, os.WriteFile(table.path, []byte(initial), 0o644))
	return table
}

// rewrite replays AOSP ResilientAtomicFile.startWrite/finishWrite: rename the
// file to the backup, write the new content into a fresh file in several
// chunks, then delete the backup. stopBeforeFinish leaves the write as a
// failed one would (failWrite deletes the partial file, the backup stays).
func (table testTable) rewrite(t *testing.T, content string, chunkDelay time.Duration, failWrite bool) {
	t.Helper()
	require.NoError(t, os.Rename(table.path, table.backup))
	file, err := os.Create(table.path)
	require.NoError(t, err)
	chunk := len(content)/5 + 1
	for start := 0; start < len(content); start += chunk {
		end := min(start+chunk, len(content))
		_, err = file.WriteString(content[start:end])
		require.NoError(t, err)
		time.Sleep(chunkDelay)
		if failWrite && end >= len(content)/2 {
			break
		}
	}
	require.NoError(t, file.Close())
	if failWrite {
		require.NoError(t, os.Remove(table.path))
		return
	}
	require.NoError(t, os.Remove(table.backup))
}

func startManager(t *testing.T, path string, callback *recorder) *Manager {
	t.Helper()
	manager := New(Options{Path: path, Callback: callback, QuietPeriod: testQuietPeriod})
	require.NoError(t, manager.Start())
	t.Cleanup(func() { manager.Close() })
	return manager
}

func hasPackage(manager *Manager, name string) bool {
	_, loaded := manager.IDByPackage(name)
	return loaded
}

func TestManagerFollowsAndroidStyleRewrite(t *testing.T) {
	table := newTestTable(t, packagesDocument("a.app"))
	callback := &recorder{}
	manager := startManager(t, table.path, callback)
	require.True(t, hasPackage(manager, "a.app"))
	require.Equal(t, int32(1), callback.calls.Load())

	// Lookups must never lose a.app while the file is half written, even
	// though the chunks are slower than the quiet period.
	stop := make(chan struct{})
	var lostDuringWrite atomic.Bool
	var watching sync.WaitGroup
	watching.Add(1)
	go func() {
		defer watching.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if !hasPackage(manager, "a.app") {
				lostDuringWrite.Store(true)
			}
			time.Sleep(time.Millisecond)
		}
	}()
	table.rewrite(t, packagesDocument("a.app", "b.app"), 2*testQuietPeriod, false)
	require.Eventually(t, func() bool { return hasPackage(manager, "b.app") }, 3*time.Second, 5*time.Millisecond)
	close(stop)
	watching.Wait()
	require.False(t, lostDuringWrite.Load(), "a partially written file was published")
	require.Equal(t, int32(2), callback.calls.Load())

	// Uninstall: the table shrinks again.
	table.rewrite(t, packagesDocument("a.app"), 0, false)
	require.Eventually(t, func() bool { return !hasPackage(manager, "b.app") }, 3*time.Second, 5*time.Millisecond)
	require.True(t, hasPackage(manager, "a.app"))
}

func TestManagerKeepsLastGoodAfterFailedWrite(t *testing.T) {
	table := newTestTable(t, packagesDocument("a.app"))
	callback := &recorder{}
	manager := startManager(t, table.path, callback)

	// A failed write leaves only the backup; AOSP reads the backup then.
	table.rewrite(t, packagesDocument("a.app", "b.app"), 0, true)
	time.Sleep(10 * testQuietPeriod)
	require.True(t, hasPackage(manager, "a.app"))
	require.False(t, hasPackage(manager, "b.app"))
	require.Equal(t, int32(1), callback.calls.Load(), "re-reading the unchanged backup must not notify")

	// Recover the way PackageManager would: the backup becomes the file and
	// a later successful write lands.
	require.NoError(t, os.Rename(table.backup, table.path))
	table.rewrite(t, packagesDocument("a.app", "c.app"), 0, false)
	require.Eventually(t, func() bool { return hasPackage(manager, "c.app") }, 3*time.Second, 5*time.Millisecond)
}

func TestManagerRetriesAfterCorruptFile(t *testing.T) {
	table := newTestTable(t, packagesDocument("a.app"))
	manager := startManager(t, table.path, &recorder{})

	// A truncated file with no backup (not what AOSP produces, but what any
	// interrupted writer could leave) must not replace the table.
	full := packagesDocument("a.app", "b.app")
	require.NoError(t, os.WriteFile(table.path, []byte(full[:len(full)/2]), 0o644))
	time.Sleep(10 * testQuietPeriod)
	require.True(t, hasPackage(manager, "a.app"))
	require.False(t, hasPackage(manager, "b.app"))

	// The retry loop picks up the repaired file on its own.
	require.NoError(t, os.WriteFile(table.path, []byte(full), 0o644))
	require.Eventually(t, func() bool { return hasPackage(manager, "b.app") }, 5*time.Second, 5*time.Millisecond)
}

func TestManagerNoCallbackForUnchangedRewrite(t *testing.T) {
	document := packagesDocument("a.app", "b.app")
	table := newTestTable(t, document)
	callback := &recorder{}
	startManager(t, table.path, callback)
	for range 3 {
		table.rewrite(t, document, 0, false)
	}
	time.Sleep(10 * testQuietPeriod)
	require.Equal(t, int32(1), callback.calls.Load())
}

func TestManagerCoalescesBursts(t *testing.T) {
	table := newTestTable(t, packagesDocument("a.app"))
	callback := &recorder{}
	manager := startManager(t, table.path, callback)
	names := []string{"a.app"}
	for index := range 40 {
		names = append(names, fmt.Sprintf("burst%d.app", index))
		require.NoError(t, os.WriteFile(table.path, []byte(packagesDocument(names...)), 0o644))
	}
	require.Eventually(t, func() bool { return hasPackage(manager, "burst39.app") }, 3*time.Second, 5*time.Millisecond)
	time.Sleep(5 * testQuietPeriod)
	require.LessOrEqual(t, callback.calls.Load(), int32(4), "a burst of writes should be read a few times, not forty")
}

// Writes arriving faster than the quiet period must not postpone the read
// forever: the change has to show up while the writes are still going on.
func TestManagerReadsDuringContinuousWrites(t *testing.T) {
	table := newTestTable(t, packagesDocument("a.app"))
	manager := startManager(t, table.path, &recorder{})
	require.NoError(t, os.WriteFile(table.path, []byte(packagesDocument("a.app", "b.app")), 0o644))
	// A fixed window, independent of maxPendingDelay, so a broken cap fails
	// the assertion below instead of stretching the test.
	const writeWindow = 1600 * time.Millisecond
	start := time.Now()
	seenAt := time.Duration(0)
	for time.Since(start) < writeWindow {
		// Rewrite the same content well inside the quiet period.
		require.NoError(t, os.WriteFile(table.path, []byte(packagesDocument("a.app", "b.app")), 0o644))
		if seenAt == 0 && hasPackage(manager, "b.app") {
			seenAt = time.Since(start)
		}
		time.Sleep(testQuietPeriod / 2)
	}
	require.NotZero(t, seenAt, "the change never showed up while writes continued")
	require.Less(t, seenAt, maxPendingDelay+300*time.Millisecond)
}

func TestManagerCloseStopsCallbacksAndGoroutines(t *testing.T) {
	baseline := runtime.NumGoroutine()
	for range 20 {
		table := newTestTable(t, packagesDocument("a.app"))
		callback := &recorder{}
		manager := New(Options{Path: table.path, Callback: callback, QuietPeriod: testQuietPeriod})
		require.NoError(t, manager.Start())
		require.NoError(t, manager.Close())
		require.NoError(t, manager.Close(), "Close must be idempotent")
		table.rewrite(t, packagesDocument("a.app", "b.app"), 0, false)
		time.Sleep(3 * testQuietPeriod)
		require.Equal(t, int32(1), callback.calls.Load(), "no callback after Close")
		require.Error(t, manager.Start(), "a closed manager cannot restart")
	}
	require.Eventually(t, func() bool { return runtime.NumGoroutine() <= baseline+2 }, 3*time.Second, 20*time.Millisecond,
		"goroutines leaked: baseline %d, now %d", baseline, runtime.NumGoroutine())
}

func TestManagerStartFailsWithoutFile(t *testing.T) {
	manager := New(Options{Path: filepath.Join(t.TempDir(), "packages.xml"), QuietPeriod: testQuietPeriod})
	require.Error(t, manager.Start())
	require.NoError(t, manager.Close())
}

func TestManagerReadsBackupOnStart(t *testing.T) {
	// Starting while a write is in progress: the backup holds the complete
	// table and the main file is partial.
	table := newTestTable(t, packagesDocument("a.app"))
	require.NoError(t, os.Rename(table.path, table.backup))
	require.NoError(t, os.WriteFile(table.path, []byte("<packages><package name=\"half"), 0o644))
	manager := startManager(t, table.path, &recorder{})
	require.True(t, hasPackage(manager, "a.app"))
}

func TestPackagesByIDReturnsCopy(t *testing.T) {
	table := newTestTable(t, `<packages><package name="x" sharedUserId="1000"/><package name="y" sharedUserId="1000"/></packages>`)
	manager := startManager(t, table.path, &recorder{})
	names, loaded := manager.PackagesByID(1000)
	require.True(t, loaded)
	names[0] = "mutated"
	again, _ := manager.PackagesByID(1000)
	require.Equal(t, []string{"x", "y"}, again)
	first, loaded := manager.PackageByID(1000)
	require.True(t, loaded)
	require.Equal(t, "x", first)
}

func TestConcurrentLookupsDuringUpdates(t *testing.T) {
	table := newTestTable(t, packagesDocument("a.app"))
	manager := startManager(t, table.path, &recorder{})
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				manager.IDByPackage("a.app")
				manager.PackagesByID(10100)
				manager.SharedPackageByID(1000)
			}
		}()
	}
	for index := range 10 {
		table.rewrite(t, packagesDocument("a.app", fmt.Sprintf("n%d.app", index)), 0, false)
		time.Sleep(2 * testQuietPeriod)
	}
	close(stop)
	readers.Wait()
	require.Eventually(t, func() bool { return hasPackage(manager, "n9.app") }, 3*time.Second, 5*time.Millisecond)
}

// A View keeps answering from the table it was taken from, even after the
// manager publishes a new one.
func TestSnapshotViewIsStable(t *testing.T) {
	table := newTestTable(t, packagesDocument("a.app"))
	manager := startManager(t, table.path, &recorder{})
	view := manager.Snapshot()
	require.True(t, view.Loaded())
	table.rewrite(t, packagesDocument("b.app"), 0, false)
	require.Eventually(t, func() bool { return hasPackage(manager, "b.app") }, 3*time.Second, 5*time.Millisecond)
	_, loaded := view.IDByPackage("a.app")
	require.True(t, loaded, "the old view lost its table")
	_, loaded = view.IDByPackage("b.app")
	require.False(t, loaded, "the old view sees the new table")
	require.False(t, View{}.Loaded())
	_, loaded = View{}.IDByPackage("a.app")
	require.False(t, loaded)
}

func TestSubscribeNotifiesOnChangeAndStopsAfterCancel(t *testing.T) {
	document := packagesDocument("a.app")
	table := newTestTable(t, document)
	manager := startManager(t, table.path, &recorder{})
	var notified atomic.Int32
	cancel := manager.Subscribe(func() { notified.Add(1) })

	table.rewrite(t, document, 0, false) // semantically unchanged
	time.Sleep(10 * testQuietPeriod)
	require.Zero(t, notified.Load(), "an unchanged table notified subscribers")

	table.rewrite(t, packagesDocument("a.app", "b.app"), 0, false)
	require.Eventually(t, func() bool { return notified.Load() == 1 }, 3*time.Second, 5*time.Millisecond)

	cancel()
	table.rewrite(t, packagesDocument("a.app"), 0, false)
	require.Eventually(t, func() bool { return !hasPackage(manager, "b.app") }, 3*time.Second, 5*time.Millisecond)
	time.Sleep(5 * testQuietPeriod)
	require.Equal(t, int32(1), notified.Load(), "a cancelled subscription was notified")
}
