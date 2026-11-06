//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/udpio"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

func (i *Inbound) newTCConnection(
	ctx context.Context,
	backend *commonEBPF.TCBackend,
	conn net.Conn,
	metadata adapter.InboundContext,
	onClose N.CloseHandlerFunc,
) {
	source := M.SocksaddrFromNet(conn.RemoteAddr()).AddrPort()
	destination := M.SocksaddrFromNet(conn.LocalAddr()).AddrPort()
	assignment, err := backend.LookupAssignment(commonEBPF.ProtocolTCP, source, destination, 0, true)
	i.requestTCAssignmentMaintenance()
	if err != nil {
		i.counters.assignmentLookupFailures.Add(1)
		i.tcpWarnings.errorContext(i.logger, ctx, "lookup TC eBPF TCP assignment: ", err)
		_ = conn.Close()
		return
	}
	metadata.Inbound = i.Tag()
	metadata.InboundType = i.Type()
	metadata.Source = M.SocksaddrFromNetIP(source)
	metadata.Destination = M.SocksaddrFromNetIP(destination)
	metadata.ProcessInfo = i.ownerFromIdentity(ctx, identityFromAssignment(assignment))
	if assignment.Path == commonEBPF.TCPathShared && assignment.SourceMACValid != 0 {
		metadata.SourceMACAddress = net.HardwareAddr(assignment.SourceMAC[:])
	}
	i.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) newTCPacket(
	backend *commonEBPF.TCBackend,
	buffer *buf.Buffer,
	oob []byte,
	source M.Socksaddr,
	takeOwnership bool,
) bool {
	_, destination, interfaceIndex, err := packetDestinationsFromOOB(oob)
	if err != nil {
		i.udpWarnings.packetInfo.warn(i.logger, "read TC eBPF UDP destination: ", err)
		return false
	}
	if !destination.IsValid() {
		i.udpWarnings.packetInfo.warn(i.logger, "TC eBPF UDP original destination is missing")
		return false
	}
	client := source.AddrPort()
	assignment, assignmentKeyInterfaceIndex, err := i.cachedUDPAssignment(backend, client, destination, interfaceIndex)
	if err != nil {
		i.counters.assignmentLookupFailures.Add(1)
		i.udpWarnings.originalDestination.warn(i.logger, "lookup TC eBPF UDP assignment: ", err)
		return false
	}
	var sourceMAC net.HardwareAddr
	if assignment.Path == commonEBPF.TCPathShared && assignment.SourceMACValid != 0 {
		sourceMAC = net.HardwareAddr(assignment.SourceMAC[:])
	}
	scope := udpSessionScopeLocalTC
	if assignment.Path == commonEBPF.TCPathShared {
		scope = udpSessionScopeSharedTC
	}
	key := udpSessionKey{
		Source:         client,
		Scope:          scope,
		SocketCookie:   assignment.SocketCookie,
		InterfaceIndex: assignment.InterfaceIndex,
	}
	i.udpClientTable.setDirectAssignmentBinding(key, destination, sourceMAC, assignmentKeyInterfaceIndex, assignment)
	if takeOwnership {
		i.udpNat.NewPacketBuffer(key, buffer, source, M.SocksaddrFromNetIP(destination), nil)
		return true
	}
	i.udpNat.NewPacket(key, [][]byte{buffer.Bytes()}, source, M.SocksaddrFromNetIP(destination), nil)
	return false
}

// lookupProcessInfo 把 socket cookie 解析成路由规则可用的归属信息。
//
// socket_owner_resolve.go 使用 (PID, UID, start_boottime) 缓存经核对的 procfs
// 信息，并逐次核对包管理器中的唯一包归属。未知结果也必须显式返回，避免路由器
// 再走通用查询，把共享 UID 的候选包名重新带回来。
func (i *Inbound) lookupProcessInfo(ctx context.Context, socketCookie uint64) *adapter.ConnectionOwner {
	if socketCookie == 0 || i.processTracker == nil {
		return &adapter.ConnectionOwner{UserId: -1}
	}
	owner, err := i.processTracker.LookupSocketOwner(socketCookie)
	if err != nil {
		i.logger.Trace("lookup eBPF socket process owner: ", err)
		// nil would allow Router.searchProcessInfo to reintroduce the generic
		// shared-UID package candidates after this authoritative source missed.
		return &adapter.ConnectionOwner{UserId: -1}
	}
	return i.resolveSocketOwner(ctx, owner)
}

func (i *Inbound) prepareTCPacketConnection(
	_ M.Socksaddr,
	destination M.Socksaddr,
	key udpSessionKey,
) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	ctx := log.ContextWithNewID(i.ctx)
	clientState := i.udpClientTable.loadOrCreate(key)
	// The batcher (udp_downlink_batcher.go) is what reaches tcPacketWriter's
	// batch/GSO path; the downlink copy itself only ever writes one datagram.
	packetWriter := &tcPacketWriter{inbound: i, key: key, clientState: clientState}
	writer := newDownlinkBatcher(packetWriter)
	packetWriter.tryUpLane(destination.AddrPort())
	return true, ctx, writer, func(error) {
		writer.close()
		packetWriter.releaseUpLane()
		cleanup := i.udpClientTable.deleteWithCleanup(key, clientState)
		i.deleteCgroupUDPRedirects(cleanup.cgroupRedirects)
		i.deleteTCAssignments(key, cleanup.tcAssignments)
	}
}

func (i *Inbound) deleteTCAssignments(key udpSessionKey, assignments []tcAssignmentCleanup) {
	if len(assignments) == 0 || (key.Scope != udpSessionScopeLocalTC && key.Scope != udpSessionScopeSharedTC) {
		return
	}
	i.tcDataPlaneAccess.RLock()
	dataPlane := i.tcDataPlane
	i.tcDataPlaneAccess.RUnlock()
	if dataPlane == nil {
		return
	}
	backend := dataPlane.Backend()
	if backend == nil || backend.IsClosed() {
		return
	}
	for _, cleanup := range assignments {
		if _, err := backend.RemoveAssignmentIfMatch(
			commonEBPF.ProtocolUDP,
			key.Source,
			cleanup.destination,
			cleanup.keyInterfaceIndex,
			cleanup.assignment,
		); err != nil && !errors.Is(err, unix.EBADF) {
			i.udpWarnings.cleanup.warn(i.logger, "delete TC eBPF UDP assignment: ", err)
		}
	}
}

type tcPacketWriter struct {
	inbound        *Inbound
	key            udpSessionKey
	clientState    *udpClientState
	newReplySocket func(netip.AddrPort) (*net.UDPConn, func(), error)

	upLaneAccess sync.Mutex
	upLaneTried  bool
	upLaneClosed bool
	upLaneFlow   upLaneFlow
}

// tryUpLane attaches the app socket when its session starts, not at the first
// reply: a flow may never get one. TC has already sent this flow to sing-box
// and the takeover ends at the same listener, so the route decision does not
// depend on it. A socket takes one peer, the first it talks to.
func (w *tcPacketWriter) tryUpLane(peer netip.AddrPort) {
	// A DNS exchange is over before a takeover could pay for itself
	if !udpio.EnableUDPFastLaneUp || w.key.Scope != udpSessionScopeLocalTC || peer.Port() == 53 {
		return
	}
	w.upLaneAccess.Lock()
	defer w.upLaneAccess.Unlock()
	if w.upLaneTried || w.upLaneClosed {
		return
	}
	w.upLaneTried = true
	w.upLaneFlow = upLaneFlow{app: w.key.Source, peer: peer}
	uid, err := udpio.LaneSocketUID(w.key.Source, peer)
	if err != nil {
		// Usually a socket that closed or is bound to a device: it stays on TC
		w.inbound.logger.Debug("sbfl socket uid of ", w.upLaneFlow.app, ": ", err)
		return
	}
	listener := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), w.inbound.listeners.selectedPort())
	if err = w.inbound.upLane.attach(w.upLaneFlow, listener, int32(uid)); err != nil {
		w.inbound.logger.Debug("sbfl attach ", w.upLaneFlow.app, " to ", w.upLaneFlow.peer, " listener ", listener, ": ", err)
	}
}

// releaseUpLane runs when the session closes. An attached socket must not
// keep feeding the listener after that: its next datagram has to take TC,
// which is what starts a new session.
func (w *tcPacketWriter) releaseUpLane() {
	w.upLaneAccess.Lock()
	defer w.upLaneAccess.Unlock()
	w.upLaneClosed = true
	if w.upLaneTried {
		w.inbound.upLane.detach(w.upLaneFlow)
	}
}

func (w *tcPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	destinationAddress := destination.AddrPort()
	binding, err := w.ensureReplyBinding(destinationAddress)
	if err != nil {
		return err
	}
	if w.clientState.isCgroupDataPlane() {
		return w.inbound.listeners.writeUDP(buffer.Bytes(), binding.packetInfo, w.key.Source, binding.redirectAddress)
	}
	entry, release, err := w.inbound.udpReplySockets.get(destinationAddress, w.replySocketFactory())
	if err != nil {
		w.logReplySocketError(err)
		return err
	}
	defer release()
	if entry.lane != nil && entry.lane.WriteOne(buffer.Bytes(), w.key.Source) {
		return nil
	}
	_, err = entry.conn.WriteToUDPAddrPort(buffer.Bytes(), w.key.Source)
	return err
}

func (w *tcPacketWriter) ensureReplyBinding(destinationAddress netip.AddrPort) (udpRedirectBinding, error) {
	binding, loaded := w.clientState.redirectBinding(destinationAddress)
	if !loaded {
		if w.clientState.isCgroupDataPlane() {
			backend := w.inbound.cgroupBackendInstance()
			if backend == nil {
				return udpRedirectBinding{}, E.New("cgroup eBPF backend is closed")
			}
			redirectAddress, err := backend.ReserveUDPReplyRedirect(destinationAddress, w.inbound.listeners.selectedPort())
			if err != nil {
				return udpRedirectBinding{}, err
			}
			if !w.inbound.udpClientTable.setCgroupReplyBinding(w.key, w.clientState, destinationAddress, redirectAddress) {
				_ = backend.DeleteRedirect(
					commonEBPF.ProtocolUDP,
					netip.AddrPortFrom(redirectAddress, w.inbound.listeners.selectedPort()),
				)
				return udpRedirectBinding{}, E.New("cgroup eBPF UDP reply binding was rejected")
			}
			binding, loaded = w.clientState.redirectBinding(destinationAddress)
			if !loaded {
				return udpRedirectBinding{}, E.New("cgroup eBPF UDP reply binding is unavailable")
			}
		}
	}
	if !loaded {
		if !w.clientState.hasAddressFamily(destinationAddress.Addr().Is4()) {
			return udpRedirectBinding{}, E.New("TC eBPF UDP reply alias limit reached or address family unavailable")
		}
		installed := w.inbound.udpClientTable.setDirectReplyBinding(
			w.key,
			w.clientState,
			destinationAddress,
		)
		if !installed {
			return udpRedirectBinding{}, E.New("TC eBPF UDP session closed or reply alias was rejected")
		}
		binding, loaded = w.clientState.redirectBinding(destinationAddress)
		if !loaded {
			return udpRedirectBinding{}, E.New("TC eBPF UDP reply binding is unavailable")
		}
	}
	return binding, nil
}

func (w *tcPacketWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	if len(buffers) == 0 || len(buffers) != len(destinations) {
		buf.ReleaseMulti(buffers)
		return os.ErrInvalid
	}
	if w.clientState.isCgroupDataPlane() {
		packetInfos := make([][]byte, len(buffers))
		sources := make([]netip.Addr, len(buffers))
		for index, destination := range destinations {
			binding, err := w.ensureReplyBinding(destination.AddrPort())
			if err != nil {
				buf.ReleaseMulti(buffers)
				return err
			}
			packetInfos[index] = binding.packetInfo
			sources[index] = binding.redirectAddress
		}
		return w.inbound.listeners.writeUDPBatch(buffers, packetInfos, w.key.Source, sources)
	}
	type packetGroup struct {
		buffers      []*buf.Buffer
		destinations []M.Socksaddr
	}
	groups := make(map[netip.AddrPort]*packetGroup)
	client := M.SocksaddrFromNetIP(w.key.Source)
	for index, destination := range destinations {
		destinationAddress := destination.AddrPort()
		if _, err := w.ensureReplyBinding(destinationAddress); err != nil {
			buf.ReleaseMulti(buffers)
			return err
		}
		group := groups[destinationAddress]
		if group == nil {
			group = &packetGroup{}
			groups[destinationAddress] = group
		}
		group.buffers = append(group.buffers, buffers[index])
		group.destinations = append(group.destinations, client)
	}
	var batchErr error
	for source, group := range groups {
		entry, release, err := w.inbound.udpReplySockets.get(source, w.replySocketFactory())
		if err != nil {
			w.logReplySocketError(err)
			buf.ReleaseMulti(group.buffers)
			batchErr = errors.Join(batchErr, err)
			continue
		}
		err = entry.writer.WritePacketBatch(group.buffers, group.destinations)
		release()
		batchErr = errors.Join(batchErr, err)
	}
	return batchErr
}

func (w *tcPacketWriter) logReplySocketError(err error) {
	if errors.Is(err, errUDPReplySocketCapacity) {
		w.inbound.udpWarnings.replySocketCapacity.warn(
			w.inbound.logger,
			"UDP eBPF reply socket pool reached its global capacity; all sockets are currently in use",
		)
	}
}

func (w *tcPacketWriter) replySocketFactory() func(netip.AddrPort) (*net.UDPConn, func(), error) {
	if w.newReplySocket != nil {
		return w.newReplySocket
	}
	return w.inbound.newTCUDPReplySocket
}

var _ N.PacketBatchWriter = (*tcPacketWriter)(nil)

func (i *Inbound) deleteCgroupUDPRedirects(addresses []netip.Addr) {
	backend := i.cgroupBackendInstance()
	if backend == nil {
		return
	}
	for _, address := range addresses {
		destination := netip.AddrPortFrom(address, i.listeners.selectedPort())
		if err := backend.DeleteRedirect(commonEBPF.ProtocolUDP, destination); err != nil && !errors.Is(err, unix.ENOENT) {
			i.udpWarnings.cleanup.warn(i.logger, "delete cgroup eBPF UDP redirect: ", err)
		}
	}
}

func (i *Inbound) newTCUDPReplySocket(source netip.AddrPort) (*net.UDPConn, func(), error) {
	network := "udp6"
	if source.Addr().Is4() {
		network = "udp4"
	}
	fragmentControl := control.DisableUDPFragment()
	if i.udpFragment {
		fragmentControl = control.EnableUDPFragment()
	}
	listenConfig := net.ListenConfig{Control: control.Append(
		control.UDPSocketBuffer(listener.UDPSocketBufferSize()),
		// This socket is created outside common/listener.Listener, so it
		// must mirror ebpf.udp_fragment explicitly.
		fragmentControl,
	)}
	var selfBypass *commonEBPF.SelfBypass
	if provider, loaded := i.networkManager.(interface {
		EBPFSelfBypass() *commonEBPF.SelfBypass
	}); loaded {
		selfBypass = provider.EBPFSelfBypass()
	}
	listenConfig.Control = control.Append(listenConfig.Control, func(_ string, _ string, rawConn syscall.RawConn) error {
		err := control.Raw(rawConn, func(fd uintptr) error {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
				return err
			}
			if source.Addr().Is4() {
				return unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			}
			if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
				return err
			}
			return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
		})
		if err != nil {
			return err
		}
		if selfBypass != nil {
			return selfBypass.RegisterSocket(rawConn)
		}
		return nil
	})
	packetConnection, err := listenConfig.ListenPacket(i.ctx, network, source.String())
	if err != nil {
		return nil, nil, E.Cause(err, "bind TC eBPF UDP reply socket to ", source)
	}
	udpConnection, loaded := packetConnection.(*net.UDPConn)
	if !loaded {
		_ = packetConnection.Close()
		return nil, nil, E.New("TC eBPF UDP reply socket has unexpected type")
	}
	var cleanup func()
	if selfBypass != nil {
		cleanup = func() {
			rawConn, err := udpConnection.SyscallConn()
			if err == nil {
				_ = selfBypass.UnregisterSocket(rawConn)
			}
		}
	}
	return udpConnection, cleanup, nil
}
