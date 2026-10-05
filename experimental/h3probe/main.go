// Command h3probe downloads over HTTP/3 (QUIC) and reports handshake time,
// bytes and throughput. Used on the phone to check that a sing-box build
// still delivers UDP downlink datagrams correctly to a real QUIC client.
//
//	h3probe -url https://speed.cloudflare.com/__down?bytes=20000000 -n 3
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
)

func main() {
	url := flag.String("url", "https://speed.cloudflare.com/__down?bytes=20000000", "URL")
	count := flag.Int("n", 3, "requests (each on a fresh connection)")
	timeout := flag.Duration("timeout", 30*time.Second, "per-request timeout")
	dns := flag.String("dns", "8.8.8.8:53", "DNS server (port 53 is hijacked by sing-box anyway)")
	flag.Parse()
	// Android has no /etc/resolv.conf, so the pure-Go resolver would ask ::1.
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "udp", *dns)
	}}
	failures := 0
	for i := 0; i < *count; i++ {
		transport := &http3.Transport{
			TLSClientConfig: &tls.Config{},
			QUICConfig:      &quic.Config{HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 10 * time.Second},
		}
		client := &http.Client{Transport: transport}
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		start := time.Now()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, *url, nil)
		response, err := client.Do(request)
		if err != nil {
			fmt.Printf("H3 %d ERROR after %s: %v\n", i, time.Since(start).Round(time.Millisecond), err)
			failures++
			cancel()
			transport.Close()
			continue
		}
		firstByte := time.Since(start)
		n, err := io.Copy(io.Discard, response.Body)
		response.Body.Close()
		elapsed := time.Since(start)
		status := "ok"
		if err != nil {
			status = "ERROR " + err.Error()
			failures++
		}
		fmt.Printf("H3 %d %s proto=%s code=%d ttfb=%s bytes=%d time=%s rate=%.1f Mbit/s\n",
			i, status, response.Proto, response.StatusCode, firstByte.Round(time.Millisecond), n,
			elapsed.Round(time.Millisecond), float64(n)*8/elapsed.Seconds()/1e6)
		cancel()
		transport.Close()
	}
	if failures > 0 {
		os.Exit(1)
	}
}
