package androidpackages

import (
	"slices"

	"github.com/sagernet/sing-tun"
)

// View is one published package table. Every lookup on a View answers from
// the same table, which a caller that combines several lookups needs: the
// Manager's own methods each load whatever is current, so a computation that
// calls them one after another can straddle a publish and mix two tables.
// A View is immutable and safe for concurrent use. The zero View is an empty
// table.
type View struct {
	table *snapshot
}

var _ tun.PackageManager = View{}

// Snapshot returns the table currently published. It is a pointer load; the
// table itself is never copied or modified.
func (m *Manager) Snapshot() View {
	return View{table: m.current.Load()}
}

// Loaded reports whether the view holds a parsed table at all.
func (v View) Loaded() bool { return v.table != nil }

// Start and Close exist so a View can stand in for tun.PackageManager in
// functions that only read; there is nothing to start or stop.
func (v View) Start() error { return nil }
func (v View) Close() error { return nil }

func (v View) IDByPackage(packageName string) (uint32, bool) {
	if v.table == nil {
		return 0, false
	}
	id, loaded := v.table.idByPackage[packageName]
	return id, loaded
}

func (v View) IDBySharedPackage(sharedPackage string) (uint32, bool) {
	if v.table == nil {
		return 0, false
	}
	id, loaded := v.table.sharedByPackage[sharedPackage]
	return id, loaded
}

func (v View) PackageByID(id uint32) (string, bool) {
	if v.table == nil {
		return "", false
	}
	names := v.table.packageByID[id]
	if len(names) == 0 {
		return "", false
	}
	return names[0], true
}

// PackagesByID returns a copy, so callers cannot modify the published table
// through the slice.
func (v View) PackagesByID(id uint32) ([]string, bool) {
	if v.table == nil {
		return nil, false
	}
	names, loaded := v.table.packageByID[id]
	if !loaded {
		return nil, false
	}
	return slices.Clone(names), true
}

func (v View) SharedPackageByID(id uint32) (string, bool) {
	if v.table == nil {
		return "", false
	}
	name, loaded := v.table.sharedByID[id]
	return name, loaded
}

// PackageCode returns where a package's APKs are, for reading its manifest.
func (v View) PackageCode(packageName string) (PackageCode, bool) {
	if v.table == nil {
		return PackageCode{}, false
	}
	code, loaded := v.table.codeByPackage[packageName]
	return code, loaded
}

// PackageCount is the number of installed packages in the table.
func (v View) PackageCount() int {
	if v.table == nil {
		return 0
	}
	return len(v.table.idByPackage)
}
