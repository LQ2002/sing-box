//go:build with_ebpf && (linux || android)

package ebpf

// Package attribution for processes of shared and system UIDs
// (ANDROID_ATTRIBUTION_PLAN.md stage 3).
//
// ActivityManager keys a running process by (process name, UID)
// (ProcessList.mProcessNames.get(name, uid)). So when exactly one package of
// the creator's UID declares the creator's process name, that package owns
// the process, provided its identity came from a socket cookie creator
// record and its name from a birth-time-verified proc directory. When
// several do (com.android.phone hosts eleven packages on
// the test device, "system" five), the answer stays unknown. Measured on the
// phone: 65 of 78 running app processes unique, 7 multi, 0 unexplained
// (common/androidmanifest TestDeviceProcessNamesMatchManifests).
//
// am_proc_start events are deliberately not used. They name the package of
// the component that started a process, but later components of other
// packages load into the same process (the stage 1 probe saw a second
// package's connections attributed to the first), so they carry no
// discriminating power beyond (name, uid), and their PID-only join has no
// birth token. The optional socket owner source supplies the creator's PID
// and start_boottime; a cgroup ID alone cannot identify a process instance.
//
// Efficiency: parsing manifests costs milliseconds per package (112
// packages of the running shared/system UIDs took 0.5 s on the phone), so it
// never happens on a connection. One background goroutine builds the index
// per appId; a connection whose UID is not indexed yet gets an unknown
// package and queues the UID. Results are memoised per (appId, process name,
// package table), so the connection path is a map lookup. Each package's
// processes are cached against its code path and stamp, so an upgrade is
// re-read and nothing else is.

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/sagernet/sing-box/common/androidmanifest"
	"github.com/sagernet/sing-box/common/androidpackages"
	"github.com/sagernet/sing/common/logger"
)

type packageProcesses struct {
	code      androidpackages.PackageCode
	processes map[string]struct{}
	failed    bool
}

type processLookupKey struct {
	appID   uint32
	process string
}

// processPackageTable is what the index reads from a package table;
// androidpackages.View implements it. Implementations must be comparable:
// memoised results are only reused while the same table is current.
type processPackageTable interface {
	Loaded() bool
	PackagesByID(id uint32) ([]string, bool)
	PackageCode(packageName string) (androidpackages.PackageCode, bool)
}

type processLookupResult struct {
	view        processPackageTable
	packageName string
	complete    bool
}

type processPackageIndex struct {
	snapshot     func() processPackageTable
	readPackage  func(packageName, codePath string) ([]string, error)
	logger       logger.Logger
	access       sync.Mutex
	packages     map[string]packageProcesses
	memo         map[processLookupKey]processLookupResult
	queued       map[uint32]bool
	queue        chan uint32
	done         chan struct{}
	finished     chan struct{}
	parsedTotal  uint64
	failedTotal  uint64
	pendingTotal uint64
}

func newProcessPackageIndex(snapshot func() processPackageTable, logger logger.Logger) *processPackageIndex {
	return &processPackageIndex{
		snapshot:    snapshot,
		readPackage: androidmanifest.PackageProcesses,
		logger:      logger,
		packages:    make(map[string]packageProcesses),
		memo:        make(map[processLookupKey]processLookupResult),
		queued:      make(map[uint32]bool),
		queue:       make(chan uint32, 256),
		done:        make(chan struct{}),
		finished:    make(chan struct{}),
	}
}

func (x *processPackageIndex) start() {
	go x.loop()
}

func (x *processPackageIndex) close() {
	close(x.done)
	<-x.finished
}

// lookup names the package owning process name in appID, or "" when it is
// not unique, not declared, or not indexed yet (the latter queues appID).
func (x *processPackageIndex) lookup(appID uint32, processName string) string {
	view := x.snapshot()
	if !view.Loaded() {
		return ""
	}
	key := processLookupKey{appID: appID, process: processName}
	x.access.Lock()
	defer x.access.Unlock()
	if result, loaded := x.memo[key]; loaded && result.view == view && result.complete {
		return result.packageName
	}
	packages, _ := view.PackagesByID(appID)
	match := ""
	matches := 0
	complete := true
	for _, packageName := range packages {
		code, loaded := view.PackageCode(packageName)
		entry, parsed := x.packages[packageName]
		if !loaded || !parsed || entry.code != code {
			complete = false
			continue
		}
		if entry.failed {
			// An unreadable package might declare the name: unknown.
			matches = 2
			continue
		}
		if _, declared := entry.processes[processName]; declared {
			match = packageName
			matches++
		}
	}
	if !complete {
		x.pendingTotal++
		x.enqueueLocked(appID)
		return ""
	}
	if matches != 1 {
		match = ""
	}
	x.memo[key] = processLookupResult{view: view, packageName: match, complete: true}
	return match
}

func (x *processPackageIndex) enqueue(appID uint32) {
	x.access.Lock()
	defer x.access.Unlock()
	x.enqueueLocked(appID)
}

func (x *processPackageIndex) enqueueLocked(appID uint32) {
	if x.queued[appID] {
		return
	}
	select {
	case x.queue <- appID:
		x.queued[appID] = true
	default:
		// Full: the UID is retried on its next lookup.
	}
}

func (x *processPackageIndex) loop() {
	defer close(x.finished)
	for {
		select {
		case <-x.done:
			return
		case appID := <-x.queue:
			x.build(appID)
		}
	}
}

// build parses every package of appID whose cached entry is missing or
// stale. Parsing happens without the lock; lookups keep answering meanwhile.
func (x *processPackageIndex) build(appID uint32) {
	view := x.snapshot()
	packages, _ := view.PackagesByID(appID)
	for _, packageName := range packages {
		select {
		case <-x.done:
			return
		default:
		}
		code, loaded := view.PackageCode(packageName)
		if !loaded {
			continue
		}
		x.access.Lock()
		entry, parsed := x.packages[packageName]
		x.access.Unlock()
		if parsed && entry.code == code {
			continue
		}
		next := packageProcesses{code: code, processes: make(map[string]struct{})}
		processes, err := x.readPackage(packageName, code.Path)
		if err != nil {
			next.failed = true
			if x.logger != nil {
				x.logger.Debug("read process names of ", packageName, ": ", err)
			}
		}
		for _, process := range processes {
			next.processes[process] = struct{}{}
		}
		x.access.Lock()
		x.packages[packageName] = next
		x.parsedTotal++
		if next.failed {
			x.failedTotal++
		}
		x.access.Unlock()
	}
	x.access.Lock()
	delete(x.queued, appID)
	x.access.Unlock()
}

// prewarm queues the shared and system UIDs that have running processes now,
// so their first connections need not wait for a build. It reads only the
// uid_* directory names under /apps and /system: a bounded, one-time cost.
func (x *processPackageIndex) prewarm(root string, unique func(uid uint32) bool) {
	for _, kind := range []string{"apps", "system"} {
		entries, err := os.ReadDir(filepath.Join(root, kind))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			uid, ok := parseCgroupComponent(entry.Name(), "uid_")
			if !ok || unique(uid) {
				continue
			}
			x.enqueue(uid % androidUserRange)
		}
	}
}

// startProcessIndex runs only with a cookie owner source. Group labels alone
// cannot supply a process name, so parsing manifests without a source would
// waste startup work.
func (i *Inbound) startProcessIndex() {
	if i.processIndex.Load() != nil || i.networkManager == nil || i.processTracker == nil {
		return
	}
	source, loaded := i.networkManager.PackageManager().(interface{ Snapshot() androidpackages.View })
	if !loaded {
		return
	}
	index := newProcessPackageIndex(func() processPackageTable { return source.Snapshot() }, i.logger)
	index.start()
	i.processIndex.Store(index)
	index.prewarm(cgroupRoot, func(uid uint32) bool { return i.packageForApplicationUID(uid) != "" })
}

func (i *Inbound) stopProcessIndex() {
	if index := i.processIndex.Swap(nil); index != nil {
		index.close()
	}
}
