//go:build with_quic

package networkquality

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	sBufio "github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func NewHTTP3MeasurementClientFactory(dialer N.Dialer) (MeasurementClientFactory, error) {
	// singleConnection and disableKeepAlives are not applied:
	// HTTP/3 multiplexes streams over a single QUIC connection by default.
	return func(connectEndpoint string, _, _ bool, readCounters, writeCounters []N.CountFunc) (*http.Client, error) {
		transport := &http3.Transport{
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				dialAddr := addr
				if connectEndpoint != "" {
					dialAddr = rewriteDialAddress(addr, connectEndpoint)
				}
				destination := M.ParseSocksaddr(dialAddr)
				var udpConn net.Conn
				var dialErr error
				if dialer != nil {
					udpConn, dialErr = dialer.DialContext(ctx, N.NetworkUDP, destination)
				} else {
					var netDialer net.Dialer
					udpConn, dialErr = netDialer.DialContext(ctx, N.NetworkUDP, destination.String())
				}
				if dialErr != nil {
					return nil, dialErr
				}
				wrappedConn := udpConn
				if len(readCounters) > 0 || len(writeCounters) > 0 {
					wrappedConn = sBufio.NewCounterConn(udpConn, readCounters, writeCounters)
					qtls.SetDesiredBufferSizes(udpConn)
				}
				quicConn, dialErr := quic.DialEarlyConn(ctx, wrappedConn, tlsCfg, qtls.ConfigWithGSO(qtls.ConfigWithGSO(cfg, dialer), udpConn))
				if dialErr != nil {
					udpConn.Close()
					return nil, dialErr
				}
				// quic-go defaults to the loss-based controller RFC 9002 uses as its
				// reference, which makes this measurement report a number no real
				// traffic would ever see. On a path with 0.28% loss and 40ms of RTT it
				// settled at 25 Mbps of upload, while Google Photos uploading through
				// the very same Shadowsocks tunnel at the same moment sustained 139
				// Mbps on a single QUIC connection -- because its sender uses BBR,
				// which does not halve its window over a loss rate that low. A test
				// whose figure is five times under what the link actually delivers is
				// not measuring the link, so it uses the same controller the traffic
				// it stands in for uses.
				//
				// Only the upload figure moves. Downloads are sent by the far end, so
				// its controller governs them and this changes nothing there.
				//
				// The call mirrors tuic/congestion.go in sing-quic, which already does
				// this on the data plane; ProfileStandard is what "bbr" selects there.
				quicConn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(
					quicConn.InitialPacketSize(), congestion_meta2.ProfileStandard))
				go func() {
					<-quicConn.Context().Done()
					udpConn.Close()
				}()
				return quicConn, nil
			},
		}
		return &http.Client{Transport: transport}, nil
	}, nil
}
