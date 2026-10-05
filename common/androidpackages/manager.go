package androidpackages

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	"github.com/fsnotify/fsnotify"
)

const (
	// DefaultPath is where Android keeps the package table.
	DefaultPath = "/data/system/packages.xml"

	// defaultQuietPeriod is how long the file must stay unchanged before it is
	// read. Android writes packages.xml in about thirty chunks after creating
	// it; reading only after a quiet period avoids parsing a half-written file
	// on every chunk. A read that still sees a partial file fails validation
	// and is retried, so this is an efficiency measure, not a correctness one.
	defaultQuietPeriod = 100 * time.Millisecond

	// maxPendingDelay bounds how long continuous events can postpone a read.
	maxPendingDelay = time.Second
)

// retryBackoff is the delay before re-reading after a failed read, by number
// of consecutive failures; the last value repeats. While failing, the last
// good snapshot keeps being served.
var retryBackoff = []time.Duration{
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
	2 * time.Second,
	5 * time.Second,
}

type Options struct {
	// Path of packages.xml; DefaultPath when empty. The temporary backup is
	// expected next to it as "<name>-backup.xml", as AOSP names it.
	Path string
	// Callback is told about every successfully published change.
	Callback tun.PackageManagerCallback
	Logger   logger.Logger
	// QuietPeriod overrides defaultQuietPeriod (tests).
	QuietPeriod time.Duration
}

// Manager implements tun.PackageManager on top of immutable snapshots.
//
// It watches the parent directory instead of the file, because Android
// replaces the file on every write; the directory watch survives that and
// reports the new file's create and write events by name. All reads run on a
// single goroutine, so reads are serialised; events that arrive while a read
// is in progress are queued and cause another read afterwards.
type Manager struct {
	path        string
	backupPath  string
	callback    tun.PackageManagerCallback
	logger      logger.Logger
	quietPeriod time.Duration

	current atomic.Pointer[snapshot]

	access   sync.Mutex
	started  bool
	closed   bool
	done     chan struct{}
	finished chan struct{}

	subscribersAccess sync.Mutex
	subscribers       map[uint64]func()
	nextSubscriber    uint64
}

var _ tun.PackageManager = (*Manager)(nil)

func New(options Options) *Manager {
	path := options.Path
	if path == "" {
		path = DefaultPath
	}
	quietPeriod := options.QuietPeriod
	if quietPeriod <= 0 {
		quietPeriod = defaultQuietPeriod
	}
	path = filepath.Clean(path)
	return &Manager{
		path:        path,
		backupPath:  strings.TrimSuffix(path, ".xml") + "-backup.xml",
		callback:    options.Callback,
		logger:      options.Logger,
		quietPeriod: quietPeriod,
	}
}

// Start subscribes to changes first and only then reads the initial table, so
// a rewrite that lands between the two is not missed: it is either already in
// the initial read or it produces an event that triggers another read.
func (m *Manager) Start() error {
	m.access.Lock()
	defer m.access.Unlock()
	if m.started || m.closed {
		return os.ErrInvalid
	}
	watcher, err := m.newWatcher()
	if err != nil {
		return err
	}
	initial, err := m.read()
	if err != nil {
		watcher.Close()
		return E.Cause(err, "read packages list")
	}
	m.publish(initial)
	m.done = make(chan struct{})
	m.finished = make(chan struct{})
	m.started = true
	go m.loop(watcher)
	return nil
}

// Close stops watching. When it returns, the callback is not invoked again
// and the watcher has been closed by the loop that owns it.
func (m *Manager) Close() error {
	m.access.Lock()
	if m.closed {
		m.access.Unlock()
		return nil
	}
	m.closed = true
	started := m.started
	m.access.Unlock()
	if !started {
		return nil
	}
	close(m.done)
	<-m.finished
	return nil
}

func (m *Manager) newWatcher() (*fsnotify.Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, E.Cause(err, "create packages watcher")
	}
	if err = watcher.Add(filepath.Dir(m.path)); err != nil {
		watcher.Close()
		return nil, E.Cause(err, "watch ", filepath.Dir(m.path))
	}
	return watcher, nil
}

// read follows AOSP's own reader for this file. PackageManager writes
// packages.xml through ResilientAtomicFile (Settings.getSettingsFile in
// services/core/java/com/android/server/pm/Settings.java): startWrite()
// renames packages.xml to packages-backup.xml and writes the new content
// directly into a fresh packages.xml, and finishWrite() deletes the backup
// only after the new file is flushed. So while the backup exists, a write is
// in progress or has failed, packages.xml may be partial, and the backup is
// the last complete version; ResilientAtomicFile.openRead() prefers it for
// exactly that reason. parsePackages still rejects a partial document, which
// covers a new write starting between the existence check and the read.
func (m *Manager) read() (*snapshot, error) {
	content, err := os.ReadFile(m.backupPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		content, err = os.ReadFile(m.path)
		if err != nil {
			return nil, err
		}
	}
	return parsePackages(content)
}

// publish installs next if it differs from the current table and reports
// whether it did. Only real changes reach the callback.
func (m *Manager) publish(next *snapshot) bool {
	previous := m.current.Load()
	if previous != nil && previous.equal(next) {
		if !previous.codeEqual(next) {
			// Same UIDs, new code locations or stamps (an upgrade): publish
			// silently so manifest readers see the new APKs.
			m.current.Store(next)
		}
		return false
	}
	m.current.Store(next)
	if m.callback != nil {
		m.callback.OnPackagesUpdated(len(next.packageByID), len(next.sharedByID))
	}
	m.notifySubscribers()
	return true
}

// loop owns the watcher: it replaces it if it stops unexpectedly and closes
// it on exit.
func (m *Manager) loop(watcher *fsnotify.Watcher) {
	defer close(m.finished)
	defer func() {
		if watcher != nil {
			watcher.Close()
		}
	}()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	failures := 0
	// pendingSince is when the oldest unread change arrived. Each new event
	// restarts the quiet period, but never beyond maxPendingDelay after it, so
	// a stream of writes cannot postpone the read indefinitely.
	var pendingSince time.Time
	schedule := func(delay time.Duration) {
		now := time.Now()
		if pendingSince.IsZero() {
			pendingSince = now
		} else if deadline := pendingSince.Add(maxPendingDelay); now.Add(delay).After(deadline) {
			delay = max(deadline.Sub(now), 0)
		}
		timer.Stop()
		select {
		case <-timer.C:
		default:
		}
		timer.Reset(delay)
	}
	for {
		select {
		case <-m.done:
			return
		case event, loaded := <-watcher.Events:
			if !loaded {
				// The watcher stopped on its own; changes may have been
				// missed while it was down, so re-read after replacing it.
				watcher = m.rewatch(watcher)
				if watcher == nil {
					return
				}
				schedule(m.quietPeriod)
				continue
			}
			// The backup's removal marks the end of a write, so it matters as
			// much as events on packages.xml itself.
			if name := filepath.Clean(event.Name); name == m.path || name == m.backupPath {
				schedule(m.quietPeriod)
			}
		case err, loaded := <-watcher.Errors:
			if !loaded {
				watcher = m.rewatch(watcher)
				if watcher == nil {
					return
				}
				schedule(m.quietPeriod)
				continue
			}
			// An error such as a queue overflow means events may have been
			// lost, so re-read rather than trust the current table.
			m.logWarn("packages watcher: ", err, "; re-reading")
			schedule(m.quietPeriod)
		case <-timer.C:
			pendingSince = time.Time{}
			next, err := m.read()
			if err != nil {
				delay := retryBackoff[min(failures, len(retryBackoff)-1)]
				failures++
				m.logWarn("update packages list: ", err, "; keeping the previous list, retrying in ", delay)
				schedule(delay)
				continue
			}
			failures = 0
			m.publish(next)
		}
	}
}

// rewatch closes a watcher that stopped unexpectedly and creates a new one,
// retrying with backoff. It returns nil only when the manager is closing.
func (m *Manager) rewatch(stopped *fsnotify.Watcher) *fsnotify.Watcher {
	stopped.Close()
	for attempt := 0; ; attempt++ {
		watcher, err := m.newWatcher()
		if err == nil {
			return watcher
		}
		delay := retryBackoff[min(attempt, len(retryBackoff)-1)]
		m.logWarn("recreate packages watcher: ", err, "; retrying in ", delay)
		select {
		case <-m.done:
			return nil
		case <-time.After(delay):
		}
	}
}

func (m *Manager) logWarn(args ...any) {
	if m.logger != nil {
		m.logger.Warn(args...)
	}
}

func (m *Manager) IDByPackage(packageName string) (uint32, bool) {
	return m.Snapshot().IDByPackage(packageName)
}

func (m *Manager) IDBySharedPackage(sharedPackage string) (uint32, bool) {
	return m.Snapshot().IDBySharedPackage(sharedPackage)
}

func (m *Manager) PackageByID(id uint32) (string, bool) {
	return m.Snapshot().PackageByID(id)
}

// PackagesByID returns a copy, so callers cannot modify the published
// snapshot through the slice.
func (m *Manager) PackagesByID(id uint32) ([]string, bool) {
	return m.Snapshot().PackagesByID(id)
}

func (m *Manager) SharedPackageByID(id uint32) (string, bool) {
	return m.Snapshot().SharedPackageByID(id)
}

// Subscribe registers notify to run after every published change, on the
// manager's own goroutine, after the tun.PackageManagerCallback. notify must
// not block: it delays the next read of packages.xml. The returned function
// removes the subscription; after it returns, notify is not called again.
//
// This exists beside the callback because the callback slot belongs to the
// router (route/network.go); consumers inside sing-box that need to react to
// package changes, such as the eBPF inbound's package-based UID rules,
// subscribe here instead of taking it over.
func (m *Manager) Subscribe(notify func()) (cancel func()) {
	m.subscribersAccess.Lock()
	defer m.subscribersAccess.Unlock()
	if m.subscribers == nil {
		m.subscribers = make(map[uint64]func())
	}
	m.nextSubscriber++
	id := m.nextSubscriber
	m.subscribers[id] = notify
	return func() {
		m.subscribersAccess.Lock()
		delete(m.subscribers, id)
		m.subscribersAccess.Unlock()
	}
}

func (m *Manager) notifySubscribers() {
	// Holding the lock while calling keeps "cancel returned" meaning "never
	// called again"; notify is required to be non-blocking.
	m.subscribersAccess.Lock()
	defer m.subscribersAccess.Unlock()
	for _, notify := range m.subscribers {
		notify()
	}
}
