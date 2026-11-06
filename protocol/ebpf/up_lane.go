//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/udpio"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/cilium/ebpf"
)

// The sbfl module can take over an app's UDP socket so that what it sends to
// the proxied peer lands on the listener directly (common/udpio/lane_linux.go).
// Those datagrams skip netd's cgroup programs, so only a uid netd would let
// through is attached, and a uid that gets restricted later is detached:
// Android's network switches keep working for attached apps.

// From packages/modules/Connectivity bpf/progs/netd.h
const (
	netdStandbyMatch         = 1 << 3
	netdDozableMatch         = 1 << 2
	netdPowersaveMatch       = 1 << 4
	netdRestrictedMatch      = 1 << 5
	netdLowPowerStandbyMatch = 1 << 6
	netdOEMDeny1Match        = 1 << 9
	netdOEMDeny2Match        = 1 << 10
	netdOEMDeny3Match        = 1 << 11
	netdBackgroundMatch      = 1 << 12

	netdDropIfSet   = netdStandbyMatch | netdOEMDeny1Match | netdOEMDeny2Match | netdOEMDeny3Match
	netdDropIfUnset = netdDozableMatch | netdPowersaveMatch | netdRestrictedMatch | netdLowPowerStandbyMatch | netdBackgroundMatch

	netdMapPath        = "/sys/fs/bpf/netd_shared/map_netd_"
	androidUserOffset  = 100000
	androidAppStart    = 10000
	upLaneRecheckEvery = 5 * time.Second
)

// netdBlockedByUIDRules is isBlockedByUidRules of netd.h.
func netdBlockedByUIDRules(enabledRules, uidRules uint32) bool {
	return enabledRules&(netdDropIfSet|netdDropIfUnset)&(uidRules^netdDropIfUnset) != 0
}

type netdUIDOwner struct {
	IIF  uint32
	Rule uint32
}

type netdPolicy struct {
	configuration *ebpf.Map
	uidOwner      *ebpf.Map
	dataSaver     *ebpf.Map
}

func openNetdPolicy() (*netdPolicy, error) {
	options := &ebpf.LoadPinOptions{ReadOnly: true}
	configuration, err := ebpf.LoadPinnedMap(netdMapPath+"configuration_map", options)
	if err != nil {
		return nil, err
	}
	uidOwner, err := ebpf.LoadPinnedMap(netdMapPath+"uid_owner_map", options)
	if err != nil {
		configuration.Close()
		return nil, err
	}
	dataSaver, err := ebpf.LoadPinnedMap(netdMapPath+"data_saver_enabled_map", options)
	if err != nil {
		configuration.Close()
		uidOwner.Close()
		return nil, err
	}
	return &netdPolicy{configuration: configuration, uidOwner: uidOwner, dataSaver: dataSaver}, nil
}

func (p *netdPolicy) close() {
	p.configuration.Close()
	p.uidOwner.Close()
	p.dataSaver.Close()
}

// allowed fails closed: a read that does not work leaves the app on TC. Data
// Saver depends on the network being metered, which this does not know, so
// nothing is attached while it is on.
func (p *netdPolicy) allowed(uid int32) bool {
	if uid < 0 {
		return false
	}
	var saver uint8
	if p.dataSaver.Lookup(uint32(0), &saver) != nil || saver != 0 {
		return false
	}
	if uid%androidUserOffset < androidAppStart {
		return true
	}
	var enabledRules uint32
	if p.configuration.Lookup(uint32(0), &enabledRules) != nil {
		return false
	}
	var owner netdUIDOwner
	if err := p.uidOwner.Lookup(uint32(uid), &owner); err != nil && err != ebpf.ErrKeyNotExist {
		return false
	}
	return !netdBlockedByUIDRules(enabledRules, owner.Rule)
}

type upLaneFlow struct {
	app  netip.AddrPort
	peer netip.AddrPort
}

// upLane keeps the attached flows and rechecks their uids. The recheck runs
// only while a flow is attached, so an idle phone has no extra timer.
type upLane struct {
	access  sync.Mutex
	policy  *netdPolicy
	flows   map[upLaneFlow]int32
	running bool
}

func (l *upLane) attach(flow upLaneFlow, listener netip.AddrPort, uid int32) error {
	l.access.Lock()
	defer l.access.Unlock()
	if l.policy == nil {
		policy, err := openNetdPolicy()
		if err != nil {
			return E.Cause(err, "open netd maps")
		}
		l.policy = policy
	}
	if !l.policy.allowed(uid) {
		return E.New("uid ", uid, " is restricted or unknown")
	}
	if err := udpio.LaneAttach(flow.app, flow.peer, listener); err != nil {
		return err
	}
	if l.flows == nil {
		l.flows = make(map[upLaneFlow]int32)
	}
	l.flows[flow] = uid
	if !l.running {
		l.running = true
		go l.recheck()
	}
	return nil
}

func (l *upLane) detach(flow upLaneFlow) {
	l.access.Lock()
	defer l.access.Unlock()
	if _, loaded := l.flows[flow]; loaded {
		delete(l.flows, flow)
		_ = udpio.LaneDetach(flow.app, flow.peer)
	}
}

func (l *upLane) recheck() {
	ticker := time.NewTicker(upLaneRecheckEvery)
	defer ticker.Stop()
	for range ticker.C {
		l.access.Lock()
		for flow, uid := range l.flows {
			if !l.policy.allowed(uid) {
				delete(l.flows, flow)
				_ = udpio.LaneDetach(flow.app, flow.peer)
			}
		}
		if len(l.flows) == 0 {
			l.running = false
			l.access.Unlock()
			return
		}
		l.access.Unlock()
	}
}
