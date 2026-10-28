// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package derphttp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
)

type androidPreferV6 struct{}

func (androidPreferV6) PreferIPv6() bool { return true }

func TestAndroidDERPTLSRace(t *testing.T) {
	for _, stalledV6 := range []bool{true, false} {
		name := "healthy-v6-remains-supported"
		if stalledV6 {
			name = "stalled-v6-falls-back-to-healthy-v4"
		}
		t.Run(name, func(t *testing.T) {
			// Both families expose the same DERP port. IPv6 wins TCP first,
			// but only a complete TLS handshake may win the relay race.
			v4 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			t.Cleanup(v4.Close)
			port := v4.Listener.Addr().(*net.TCPAddr).Port
			v6, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(port)))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { v6.Close() })
			v6Accepted := make(chan struct{})
			v6Closed := make(chan struct{})
			stop := make(chan struct{})
			t.Cleanup(func() { close(stop) })
			go func() {
				conn, err := v6.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				close(v6Accepted)
				if stalledV6 {
					// Drain ClientHello then wait for the canceled losing handshake to
					// close its connection. This also detects leaked race losers.
					done := make(chan struct{})
					go func() { io.Copy(io.Discard, conn); close(v6Closed); close(done) }()
					select {
					case <-done:
					case <-stop:
					}
					return
				}
				tc := tls.Server(conn, v4.TLS)
				tc.Handshake()
				select {
				case <-stop:
				case <-time.After(5 * time.Second):
				}
			}()
			c := NewNetcheckClient(t.Logf, netmon.NewStatic())
			c.SetAddressFamilySelector(androidPreferV6{})
			node := &tailcfg.DERPNode{HostName: "localhost", IPv4: "127.0.0.1", IPv6: "::1", DERPPort: port, InsecureForTests: true}
			reg := &tailcfg.DERPRegion{RegionID: 999, Nodes: []*tailcfg.DERPNode{node}}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			started := time.Now()
			conn, closer, _, err := c.DialRegionTLS(ctx, reg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closer.Close() })
			addr := conn.RemoteAddr().(*net.TCPAddr)
			if stalledV6 && addr.IP.To4() == nil {
				t.Fatal("stalled IPv6 connection won before TLS completed")
			}
			if !stalledV6 && addr.IP.To4() != nil {
				t.Fatal("healthy preferred IPv6 was not retained")
			}
			if elapsed := time.Since(started); elapsed > 2*time.Second {
				t.Fatalf("TLS race took %v", elapsed)
			}
			select {
			case <-v6Accepted:
			default:
				t.Fatal("IPv6 was never attempted")
			}
			if stalledV6 {
				select {
				case <-v6Closed:
				case <-time.After(time.Second):
					t.Fatal("losing stalled IPv6 connection was not closed")
				}
			}
		})
	}
}

func TestAndroidDERPTLSRaceKeepsCertificateValidation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	c := NewNetcheckClient(t.Logf, netmon.NewStatic())
	node := &tailcfg.DERPNode{HostName: "invalid.example", IPv4: "127.0.0.1", IPv6: "none", DERPPort: server.Listener.Addr().(*net.TCPAddr).Port}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, closer, _, err := c.DialRegionTLS(ctx, &tailcfg.DERPRegion{RegionID: 999, Nodes: []*tailcfg.DERPNode{node}})
	if err == nil {
		closer.Close()
		t.Fatalf("untrusted certificate accepted: %v", conn)
	}
}

func TestAndroidDERPTLSRaceRespectsCallerDeadline(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(io.Discard, conn)
		close(closed)
	}()
	c := NewNetcheckClient(t.Logf, netmon.NewStatic())
	node := &tailcfg.DERPNode{HostName: "localhost", IPv4: "127.0.0.1", IPv6: "none", DERPPort: listener.Addr().(*net.TCPAddr).Port, InsecureForTests: true}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, closer, _, err := c.DialRegionTLS(ctx, &tailcfg.DERPRegion{RegionID: 999, Nodes: []*tailcfg.DERPNode{node}})
	if err == nil {
		closer.Close()
		t.Fatal("stalled TLS unexpectedly succeeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want caller deadline", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("caller deadline exceeded by %v", elapsed)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("canceled TLS connection was not closed")
	}
}
