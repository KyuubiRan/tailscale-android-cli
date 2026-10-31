// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"
	"os"
	"runtime"

	"tailscale.com/net/tsaddr"
)

// exitNodeIPv6LocalFile is Shellscaled's per-device opt-out for IPv6 through
// an exit node. If it is absent (the default), a selected exit node also gets
// ::/0 (upstream behaviour). If it exists, only 0.0.0.0/0 goes to the exit node
// and IPv6 stays on the physical network, for exit nodes without IPv6
// internet. The content is ignored. After changing it, POST
// /localapi/v0/debug?action=reconfig so the router is updated.
const exitNodeIPv6LocalFile = "/data/adb/shellscaled/exit-node-ipv6-local"

// exitNodeTakesIPv6 reports whether a selected exit node should receive IPv6.
// It is a variable for tests.
var exitNodeTakesIPv6 = func() bool {
	if runtime.GOOS != "android" {
		return true
	}
	_, err := os.Stat(exitNodeIPv6LocalFile)
	return err != nil
}

// withoutIPv6Default returns routes without ::/0, which the exit node's
// AllowedIPs contribute to the OS routes. It does not modify routes.
func withoutIPv6Default(routes []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(routes))
	for _, r := range routes {
		if r != tsaddr.AllIPv6() {
			out = append(out, r)
		}
	}
	return out
}

// exitLeakRoutes returns the local interface prefixes that are routed into
// the tunnel when LAN access is off. Without IPv6 through the exit node, the
// IPv6 prefixes stay on the physical network like the rest of IPv6.
func exitLeakRoutes(externalIPs []netip.Prefix, exitIPv6 bool) []netip.Prefix {
	if exitIPv6 {
		return externalIPs
	}
	var out []netip.Prefix
	for _, p := range externalIPs {
		if p.Addr().Is4() {
			out = append(out, p)
		}
	}
	return out
}
