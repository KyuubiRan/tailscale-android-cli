// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package osrouter

import (
	"net/netip"
	"testing"

	"github.com/tailscale/netlink"
	"golang.org/x/sys/unix"
	"tailscale.com/tsconst"
)

// Match the kernel's fib_rule_match semantics, including the fact that Invert
// negates the whole predicate, rather than only the mark comparison.
func androidRuleMatches(rule netlink.Rule, dst netip.Addr, mark int) bool {
	family := unix.AF_INET6
	if dst.Is4() {
		family = unix.AF_INET
	}
	if !ruleMatchesFamily(rule, family) {
		return false
	}
	match := (rule.Mark^mark)&ruleMask(rule) == 0
	if rule.Dst != nil {
		prefix, err := netip.ParsePrefix(rule.Dst.String())
		match = match && err == nil && prefix.Contains(dst)
	}
	if rule.Invert {
		match = !match
	}
	return match
}

func TestAndroidRootRulePredicates(t *testing.T) {
	rules := androidIPRules()
	if len(rules) != 3 {
		t.Fatalf("got %d rules, want 3", len(rules))
	}
	for _, rule := range rules {
		if rule.Mark & ^ruleMask(rule) != 0 {
			t.Errorf("unmasked rule mark: %#x/%#x", rule.Mark, ruleMask(rule))
		}
		if rule.Dst != nil && rule.Invert {
			t.Error("destination rule must not invert the entire predicate")
		}
	}
	// netd assigns net IDs and permission bits below bit 21; these must not
	// prevent apps from reaching their tailnet addresses.
	for _, addr := range []string{"100.100.1.2", "fd7a:115c:a1e0::1234"} {
		dst := netip.MustParseAddr(addr)
		for _, mark := range []int{0, 0x10064, 0x60064} {
			matches := 0
			for _, rule := range rules[:2] {
				if androidRuleMatches(rule, dst, mark) {
					matches++
				}
			}
			if matches != 1 {
				t.Errorf("tailnet %s mark %#x matched %d early rules", addr, mark, matches)
			}
		}
	}
	// A protected transport socket must bypass every rule even when its
	// destination happens to overlap Tailscale's address space.
	for _, addr := range []string{"100.100.1.2", "fd7a:115c:a1e0::1234", "8.8.8.8", "2001:4860:4860::8888"} {
		for _, rule := range rules {
			if androidRuleMatches(rule, netip.MustParseAddr(addr), tsconst.LinuxBypassMarkNum|0x64) {
				t.Errorf("daemon transport to %s was captured by %+v", addr, rule)
			}
		}
	}
	// Ordinary internet traffic must reach the other VPN's 13000 policy
	// before the fallback at 13001, rather than matching our early rules.
	for _, addr := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		for _, rule := range rules[:2] {
			if androidRuleMatches(rule, netip.MustParseAddr(addr), 0x10064) {
				t.Errorf("early capture of internet destination %s", addr)
			}
		}
	}
	if got := 5200 + rules[2].Priority; got != 13001 {
		t.Errorf("fallback priority = %d", got)
	}
}
