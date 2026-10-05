//go:build linux

package socketidentity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	mapPin      = "creators"
	pathsPin    = "exe-paths"
	linkPin     = "producer"
	metadataPin = "metadata"
)

type pinDirectory struct {
	file *os.File
	path string
}

func (d *pinDirectory) objectPath(name string) string {
	// Resolve relative to the inspected, locked directory inode, never by
	// re-walking a configurable pathname after validating it.
	return fmt.Sprintf("/proc/self/fd/%d/%s", d.file.Fd(), name)
}

func (d *pinDirectory) Close() error { return d.file.Close() }

func checkDirectoryStat(stat *unix.Stat_t, private bool) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 {
		return errors.New("path components must be root-owned directories")
	}
	if private && stat.Mode&0777 != 0700 {
		return errors.New("collector directory must have mode 0700")
	}
	// Android's shared bpffs mount is commonly 01777. Sticky ancestors cannot
	// let an unprivileged owner replace our root-owned child. Every child is
	// still opened without following symlinks and independently checked for
	// root ownership; a pre-created unprivileged directory is rejected.
	if stat.Mode&0022 != 0 && stat.Mode&unix.S_ISVTX == 0 {
		return errors.New("writable ancestor directories must have the sticky bit")
	}
	return nil
}

func openPinDirectory(path string, create bool) (*pinDirectory, error) {
	if path == "" {
		path = DefaultPinPath
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("pin path must be a clean absolute directory path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, part := range parts {
		child, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			var fs unix.Statfs_t
			if err = unix.Fstatfs(fd, &fs); err != nil {
				return nil, err
			}
			if uint64(fs.Type) != uint64(unix.BPF_FS_MAGIC) {
				return nil, errors.New("missing pin path component is outside mounted bpffs")
			}
			if err = unix.Mkdirat(fd, part, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
				return nil, err
			}
			child, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if openErr != nil {
			return nil, fmt.Errorf("open pin path component %q: %w", part, openErr)
		}
		_ = unix.Close(fd)
		fd = child
		var stat unix.Stat_t
		if err = unix.Fstat(fd, &stat); err != nil {
			return nil, err
		}
		if err = checkDirectoryStat(&stat, index == len(parts)-1); err != nil {
			return nil, fmt.Errorf("pin path component %q: %w", part, err)
		}
	}
	var fs unix.Statfs_t
	if err = unix.Fstatfs(fd, &fs); err != nil {
		return nil, err
	}
	if uint64(fs.Type) != uint64(unix.BPF_FS_MAGIC) {
		return nil, errors.New("collector pin directory is not on bpffs")
	}
	file := os.NewFile(uintptr(fd), path)
	fd = -1
	return &pinDirectory{file: file, path: path}, nil
}

// acquireOpenLease returns true for an exclusive initialization lease, or false
// for a shared reuse lease. Each Collector retains a shared lease until Close.
func acquireOpenLease(file *os.File) (bool, error) {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, unix.EWOULDBLOCK) {
		return false, err
	}
	return false, unix.Flock(int(file.Fd()), unix.LOCK_SH)
}

func acquireRemoveLease(file *os.File) error {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return ErrBusy
	}
	return err
}

func pinSetState(names []string) (empty bool, err error) {
	if len(names) == 0 {
		return true, nil
	}
	seen := map[string]bool{}
	for _, name := range names {
		if name != mapPin && name != pathsPin && name != linkPin && name != metadataPin {
			return false, fmt.Errorf("unrecognized entry %q in collector directory", name)
		}
		if seen[name] {
			return false, fmt.Errorf("duplicate pin %q", name)
		}
		seen[name] = true
	}
	if len(seen) != 4 {
		return false, errors.New("partial collector pins; refusing to replace storage or guess ownership")
	}
	return false, nil
}

func (d *pinDirectory) empty() (bool, error) {
	entries, err := os.ReadDir(d.objectPath(""))
	if err != nil {
		return false, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		var stat unix.Stat_t
		if err := unix.Fstatat(int(d.file.Fd()), entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return false, err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Mode&0077 != 0 {
			return false, fmt.Errorf("pin %q must be a root-owned private regular bpffs object", entry.Name())
		}
		names = append(names, entry.Name())
	}
	return pinSetState(names)
}

func rollbackPins(paths []string, remove func(string) error) error {
	var result error
	for index := len(paths) - 1; index >= 0; index-- {
		if err := remove(paths[index]); err != nil {
			result = errors.Join(result, fmt.Errorf("rollback pin %s: %w", paths[index], err))
		}
	}
	return result
}

type pinRemoval struct {
	name    string
	unpin   func() error
	restore func() error
}

// Keep every object FD open while removing pins. On failure restore only the
// exact already-removed objects, without looking up or replacing other objects.
func removeOwnedPins(objects []pinRemoval) error {
	for index, object := range objects {
		if err := object.unpin(); err != nil {
			result := fmt.Errorf("unpin owned %s: %w", object.name, err)
			for previous := index - 1; previous >= 0; previous-- {
				if err := objects[previous].restore(); err != nil {
					result = errors.Join(result, fmt.Errorf("restore owned %s: %w", objects[previous].name, err))
				}
			}
			return result
		}
	}
	return nil
}
