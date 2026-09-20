package route

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/process"
	"github.com/sagernet/sing-box/log"
)

type processCacheKey struct {
	Network     string
	Source      netip.AddrPort
	Destination netip.AddrPort
}

type processCacheEntry struct {
	result *adapter.ConnectionOwner
	err    error
}

func (r *Router) findProcessInfoCached(ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (*adapter.ConnectionOwner, error) {
	key := processCacheKey{
		Network:     network,
		Source:      source,
		Destination: destination,
	}
	if entry, ok := r.processCache.Get(key); ok {
		return entry.result, entry.err
	}
	result, err := process.FindProcessInfo(r.processSearcher, ctx, network, source, destination)
	r.processCache.Add(key, processCacheEntry{result: result, err: err})
	return result, err
}

func (r *Router) searchProcessInfo(ctx context.Context, metadata *adapter.InboundContext) {
	if r.processSearcher == nil || metadata.ProcessInfo != nil || !r.isLocalSource(metadata.Source.Addr) {
		return
	}
	var originDestination netip.AddrPort
	if metadata.OriginDestination.IsValid() {
		originDestination = metadata.OriginDestination.AddrPort()
	} else if metadata.Destination.IsIP() {
		originDestination = metadata.Destination.AddrPort()
	}
	processInfo, err := r.findProcessInfoCached(ctx, metadata.Network, metadata.Source.AddrPort(), originDestination)
	if err != nil {
		r.logger.InfoContext(ctx, "failed to search process: ", err)
		return
	}
	metadata.ProcessInfo = processInfo
	logConnectionOwner(ctx, r.logger, processInfo)
}

// logConnectionOwner prints every identifier that resolved, rather than the
// first one that happened to.
//
// Reporting only the process path and returning, as this did, loses the useful
// half on Android: every app is forked from zygote, so the path is always
// /system/bin/app_process64 and two different apps log identically. The package
// name is what tells them apart -- and package_name routing rules are matching
// on it in the very next line of the log -- yet it never got printed, because a
// path had already been found. On Linux the reverse holds and the path is the
// identifying one. Printing both costs nothing and is right on either platform.
func logConnectionOwner(ctx context.Context, logger log.ContextLogger, processInfo *adapter.ConnectionOwner) {
	if processInfo == nil {
		return
	}
	var attribution []string
	if len(processInfo.PackageNames) > 0 {
		attribution = append(attribution, "package name: "+strings.Join(processInfo.PackageNames, ", "))
	}
	if len(processInfo.ProcessPaths) > 0 {
		attribution = append(attribution, "process path: "+strings.Join(processInfo.ProcessPaths, ", "))
	}
	if processInfo.UserName != "" {
		attribution = append(attribution, "user: "+processInfo.UserName)
	} else if processInfo.UserId != -1 {
		attribution = append(attribution, "user id: "+strconv.Itoa(int(processInfo.UserId)))
	}
	if len(attribution) > 0 {
		logger.InfoContext(ctx, "found ", strings.Join(attribution, ", "))
	}
}

func (r *Router) isLocalSource(source netip.Addr) bool {
	if source.IsLoopback() {
		return true
	}
	if r.platformInterface != nil {
		if slices.Contains(r.platformInterface.MyInterfaceAddress(), source) {
			return true
		}
	}
	for _, netInterface := range r.network.InterfaceFinder().Interfaces() {
		for _, prefix := range netInterface.Addresses {
			if prefix.Addr() == source {
				return true
			}
		}
	}
	return false
}
