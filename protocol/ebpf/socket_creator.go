//go:build with_ebpf && (linux || android)

package ebpf

import (
	"path/filepath"
	"runtime"

	"github.com/sagernet/sing-box/common/socketidentity"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/cilium/ebpf"
)

// The collector owns its userspace references. TC borrows the map until the
// data plane has closed. Close keeps the pinned creation hook and storage;
// only the explicit maintenance command removes persistent kernel objects.
type socketCreatorCollector interface {
	Map() *ebpf.Map
	Close() error
}

func normalizeSocketCreator(options *option.EBPFSocketCreatorOptions, localEnabled bool, dataPlane string) (string, error) {
	if options == nil {
		return "", nil
	}
	if !options.Enabled {
		if options.PinPath != "" {
			return "", E.New("local.socket_creator.pin_path requires enabled=true")
		}
		return "", nil
	}
	if !localEnabled || dataPlane != localDataPlaneTC {
		return "", E.New("local.socket_creator requires local.enabled and local.data_plane=tc")
	}
	path := options.PinPath
	if path == "" {
		path = socketidentity.DefaultPinPath
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) {
		return "", E.New("local.socket_creator.pin_path must be an absolute dedicated directory")
	}
	return filepath.Clean(path), nil
}

func (i *Inbound) startSocketCreator() error {
	if i.socketCreatorPinPath == "" {
		return nil
	}
	if i.socketCreator != nil {
		if creatorMap := i.socketCreator.Map(); creatorMap == nil || creatorMap.FD() < 0 {
			return E.New("socket creator collector has a closed map; finish cleanup before restarting")
		}
		return nil
	}
	if !i.localTCEnabled() || runtime.GOARCH != "arm64" || i.usePlatformProcessFinder {
		return E.New("local.socket_creator requires local TC on arm64 without a platform process finder")
	}
	collector, err := socketidentity.Open(socketidentity.Config{PinPath: i.socketCreatorPinPath})
	if err != nil {
		return E.Cause(err, "open persistent socket creator collector")
	}
	i.socketCreator = collector
	i.logger.Debug("eBPF socket creator collector opened at ", i.socketCreatorPinPath)
	return nil
}

func (i *Inbound) closeSocketCreator() error {
	if i.socketCreator == nil {
		return nil
	}
	// A failed TC teardown can retain programs which still use the borrowed
	// map. Keep our reference and retry after the data plane has closed.
	i.tcDataPlaneAccess.RLock()
	dataPlaneRetained := i.tcDataPlane != nil
	i.tcDataPlaneAccess.RUnlock()
	if dataPlaneRetained {
		return E.New("socket creator collector retained until TC data plane closes")
	}
	if err := i.socketCreator.Close(); err != nil {
		return E.Cause(err, "close socket creator collector references")
	}
	i.socketCreator = nil
	i.socketCreatorActive.Store(false)
	return nil
}
