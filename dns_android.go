//go:build android && !cgo
// +build android,!cgo

package main

import (
	"context"
	"net"
	"sync"
	"time"
)

func init() {
	// On Android, when not using cgo, we need to manually set up the default DNS resolver.
	// This resolver will attempt Cloudflare's DNS over both IPv4 and IPv6.

	var dialer net.Dialer
	dnsServers := []string{
		"[2606:4700:4700::1111]:53", // Cloudflare IPv6
		"[2606:4700:4700::1001]:53", // Cloudflare IPv6
		"1.1.1.1:53",                // Cloudflare IPv4
		"1.0.0.1:53",                // Cloudflare IPv4
	}

	net.DefaultResolver = &net.Resolver{
		PreferGo: false,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			raceCtx, raceCancel := context.WithTimeout(ctx, 2*time.Second)
			defer raceCancel()

			result := make(chan net.Conn, 1)
			errChan := make(chan error, len(dnsServers))
			var winner sync.Once

			for _, ip := range dnsServers {
				go func(ip string) {
					conn, err := dialer.DialContext(raceCtx, "udp", ip)
					if err != nil {
						errChan <- err
						return
					}

					won := false
					winner.Do(func() {
						won = true
						result <- conn
					})
					if !won {
						_ = conn.Close()
					}
				}(ip)
			}

			var lastErr error
			for range dnsServers {
				select {
				case conn := <-result:
					return conn, nil
				case err := <-errChan:
					lastErr = err
				case <-raceCtx.Done():
					select {
					case conn := <-result:
						return conn, nil
					default:
					}
					if ctx.Err() != nil {
						return nil, ctx.Err()
					}
					if lastErr != nil {
						return nil, lastErr
					}
					return nil, raceCtx.Err()
				}
			}
			return nil, lastErr
		},
	}
}
