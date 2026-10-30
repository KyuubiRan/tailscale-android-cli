// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/wgcfg"
)

func TestExitNodeIPv6Routes(t *testing.T) {
	p := netip.MustParsePrefix
	routes := []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6(), p("fd7a:115c:a1e0::/48"), p("2001:db8:1::/64")}
	got := withoutIPv6Default(routes)
	want := []netip.Prefix{tsaddr.AllIPv4(), p("fd7a:115c:a1e0::/48"), p("2001:db8:1::/64")}
	if !slices.Equal(got, want) {
		t.Errorf("withoutIPv6Default = %v, want %v", got, want)
	}
	if routes[1] != tsaddr.AllIPv6() {
		t.Error("withoutIPv6Default modified its input")
	}

	ext := []netip.Prefix{p("192.168.1.0/24"), p("2001:db8::/64"), p("fe80::/64")}
	if got := exitLeakRoutes(ext, true); !slices.Equal(got, ext) {
		t.Errorf("exitLeakRoutes(true) = %v", got)
	}
	if got := exitLeakRoutes(ext, false); !slices.Equal(got, ext[:1]) {
		t.Errorf("exitLeakRoutes(false) = %v", got)
	}
}

func TestRouterConfigExitNodeIPv6(t *testing.T) {
	b := newTestLocalBackend(t)
	// Seed the route manager with an exit peer whose AllowedIPs carry both
	// default routes, as on the device, so osRoutes() already contains ::/0
	// before routerConfigLocked runs.
	exit := (&tailcfg.Node{
		ID:         1,
		StableID:   "exit",
		Key:        key.NewNode().Public(),
		HomeDERP:   1, // required by the route manager's reachability filter
		Addresses:  []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), tsaddr.AllIPv4(), tsaddr.AllIPv6()},
	}).View()
	nb := b.currentNode()
	nb.SetNetMap(&netmap.NetworkMap{Peers: []tailcfg.NodeView{exit}})
	nb.updateRouteManagerPrefs(routePrefs{ExitNodeID: "exit", ExitNodeSelected: true})
	if !slices.Contains(nb.osRoutes(), tsaddr.AllIPv6()) {
		t.Fatalf("test setup: osRoutes() = %v, want ::/0 from the exit peer", nb.osRoutes())
	}

	// takeV6 is the default; false is the exit-node-ipv6-local opt-out.
	for _, takeV6 := range []bool{true, false} {
		tstest.Replace(t, &exitNodeTakesIPv6, func() bool { return takeV6 })
		prefs := ipn.NewPrefs()
		prefs.ExitNodeID = "exit"
		b.mu.Lock()
		rc := b.routerConfigLocked(&wgcfg.Config{}, prefs.View(), &netmap.NetworkMap{})
		b.mu.Unlock()
		if !slices.Contains(rc.Routes, tsaddr.AllIPv4()) {
			t.Errorf("takeV6=%v: missing 0.0.0.0/0 in %v", takeV6, rc.Routes)
		}
		if got := slices.Contains(rc.Routes, tsaddr.AllIPv6()); got != takeV6 {
			t.Errorf("takeV6=%v: ::/0 routed = %v in %v", takeV6, got, rc.Routes)
		}
		if !takeV6 && slices.ContainsFunc(rc.Routes, func(p netip.Prefix) bool { return p.Addr().Is6() && !tsaddr.IsTailscaleIP(p.Addr()) }) {
			t.Errorf("non-tailnet IPv6 route with IPv6 kept local: %v", rc.Routes)
		}
	}
}
