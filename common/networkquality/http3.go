//go:build with_quic

package networkquality

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/qlog"
	qtls "github.com/sagernet/sing-quic"
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
				// qlog is opt-in through QLOGDIR: DefaultConnectionTracer returns nil
				// when that variable is unset, so an ordinary run pays nothing and
				// behaves identically. It is attached here rather than in a shared
				// helper because this built-in measurement owns the only quic.Config
				// sing-box passes to DialEarlyConn; the data plane is untouched.
				if cfg == nil {
					cfg = &quic.Config{}
				}
				cfg.Tracer = qlog.DefaultConnectionTracer
				quicConn, dialErr := quic.DialEarlyConn(ctx, wrappedConn, tlsCfg, cfg)
				if dialErr != nil {
					udpConn.Close()
					return nil, dialErr
				}
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
