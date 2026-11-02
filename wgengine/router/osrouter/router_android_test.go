// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package osrouter

import (
	"net/netip"
	"os"
	"slices"
	"strings"
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

// androidLookup walks the rules in priority order as fib_rules_lookup does
// and reports whether table 52 answers. Table 52 holds the tailnet routes,
// 0.0.0.0/0 and, only if exitIPv6, ::/0; a miss continues with the next rule.
func androidLookup(dst netip.Addr, mark int, exitIPv6 bool) bool {
	tableHas := dst.Is4() || exitIPv6 || netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(dst)
	rules := androidIPRules()
	slices.SortStableFunc(rules, func(a, b netlink.Rule) int { return a.Priority - b.Priority })
	for _, rule := range rules {
		if androidRuleMatches(rule, dst, mark) && rule.Table == tailscaleRouteTable.Num && tableHas {
			return true
		}
	}
	return false
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
		if rule.Invert {
			t.Errorf("rule inverts the entire predicate: %+v", rule)
		}
		if rule.Src != nil {
			t.Errorf("rule has a source predicate: %+v", rule)
		}
	}
	if got := 5200 + rules[0].Priority; got != 12500 {
		t.Errorf("tailnet priority = %d", got)
	}
	if got := 5200 + rules[2].Priority; got != 13001 {
		t.Errorf("fallback priority = %d", got)
	}
	if got := rules[2].Mask; got != 0x10030000 {
		t.Errorf("fallback mask = %#x", got)
	}

	// netd fwmark: netId in bits 0-15, explicitlySelected 16,
	// protectedFromVpn 17, permission 18-19.
	const (
		netID      = 0x64
		explicit   = 0x10000 | netID
		protected  = 0x20000 | netID
		permission = 0xc0000 | netID
		own        = tsconst.LinuxBypassMarkNum | netID
	)
	a := netip.MustParseAddr
	cases := []struct {
		name string
		dst  netip.Addr
		mark int
		want bool
	}{
		{"plain v4", a("1.1.1.1"), 0, true},
		{"plain v6", a("2606:4700:4700::1111"), 0, true},
		{"netId v4", a("1.1.1.1"), netID, true},
		{"max netId v6", a("2606:4700:4700::1111"), 0xffff, true},
		{"permission bits v4", a("1.1.1.1"), permission, true},
		{"explicit v4", a("1.1.1.1"), explicit, false},
		{"explicit v6", a("2606:4700:4700::1111"), explicit, false},
		{"protected v4", a("1.1.1.1"), protected, false},
		{"protected v6", a("2606:4700:4700::1111"), protected, false},
		{"own v4", a("1.1.1.1"), own, false},
		{"own v6", a("2606:4700:4700::1111"), own, false},
		{"explicit to tailnet v4", a("100.100.1.2"), explicit, true},
		{"protected to tailnet v6", a("fd7a:115c:a1e0::1234"), protected, true},
		{"plain to tailnet v6", a("fd7a:115c:a1e0::1234"), netID, true},
		{"own to tailnet v4", a("100.100.1.2"), own, false},
		{"own to tailnet v6", a("fd7a:115c:a1e0::1234"), own, false},
	}
	for _, tc := range cases {
		if got := androidLookup(tc.dst, tc.mark, true); got != tc.want {
			t.Errorf("%s: table 52 = %v, want %v", tc.name, got, tc.want)
		}
	}

	// With exit-node IPv6 takeover off, ipnlocal leaves ::/0 out of table
	// 52: IPv6 internet traffic misses at 13001 and falls through to
	// Android's own network rules, while IPv4 and tailnet IPv6 are unaffected.
	offCases := []struct {
		name string
		dst  netip.Addr
		want bool
	}{
		{"v4", a("1.1.1.1"), true},
		{"v6", a("2606:4700:4700::1111"), false},
		{"v6 to tailnet", a("fd7a:115c:a1e0::1234"), true},
	}
	for _, tc := range offCases {
		if got := androidLookup(tc.dst, netID, false); got != tc.want {
			t.Errorf("exit IPv6 off, %s: table 52 = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func newAndroidCommandRouter(t *testing.T) (*linuxRouter, *fakeOS) {
	fake := NewFakeOS(t)
	r := &linuxRouter{
		logf:             t.Logf,
		cmd:              fake,
		nfr:              fake.nfr,
		ipRuleAvailable:  true,
		ipPolicyPrefBase: 5200,
	}
	r.interfaceV6UsableMemo.Store(int32(memoV6Usable))
	r.fwmaskWorksLazy.Set(true)
	return r, fake
}

// androidWantIPCommandRules is what `ip rule` shows for the module's rules
// (as captured by fakeOS, sorted).
var androidWantIPCommandRules = []string{
	"-4 pref 12500 to 100.64.0.0/10 fwmark 0x0/0x1e000000 table 52",
	"-4 pref 13001 fwmark 0x0/0x10030000 table 52",
	"-6 pref 12500 to fd7a:115c:a1e0::/48 fwmark 0x0/0x1e000000 table 52",
	"-6 pref 13001 fwmark 0x0/0x10030000 table 52",
}

func TestAndroidIPCommandRules(t *testing.T) {
	r, fake := newAndroidCommandRouter(t)
	// Upstream's inverted 13001 rule (android-v1.104.4-r5 and earlier), plus
	// a foreign rule at the same priority that must survive.
	fake.rules = []string{
		"-4 pref 13001 not fwmark 0x10000000/0x1e000000 table 52",
		"-6 pref 13001 not fwmark 0x10000000/0x1e000000 table 52",
		"-4 pref 13001 from all fwmark 0x0/0x10000 lookup 1003",
	}
	if err := r.addIPRules(); err != nil {
		t.Fatalf("addIPRules: %v", err)
	}
	want := append([]string{"-4 pref 13001 from all fwmark 0x0/0x10000 lookup 1003"}, androidWantIPCommandRules...)
	slices.Sort(want)
	if !slices.Equal(fake.rules, want) {
		t.Errorf("rules after add:\n%s\nwant:\n%s", strings.Join(fake.rules, "\n"), strings.Join(want, "\n"))
	}
	if err := r.delIPRules(); err != nil {
		t.Fatalf("delIPRules: %v", err)
	}
	if want := []string{"-4 pref 13001 from all fwmark 0x0/0x10000 lookup 1003"}; !slices.Equal(fake.rules, want) {
		t.Errorf("rules after del: %q, want only the foreign rule", fake.rules)
	}
}

func TestAndroidRuleFamilies(t *testing.T) {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		var prefs []int
		for _, rule := range androidIPRules() {
			if ruleMatchesFamily(rule, family) {
				prefs = append(prefs, 5200+rule.Priority)
			}
		}
		if !slices.Equal(prefs, []int{12500, 13001}) {
			t.Errorf("family %d replays prefs %v, want [12500 13001]", family, prefs)
		}
	}
	for _, rule := range androidLegacyIPRules() {
		if !ruleMatchesFamily(rule, unix.AF_INET) || !ruleMatchesFamily(rule, unix.AF_INET6) {
			t.Errorf("legacy rule not deleted in both families: %+v", rule)
		}
	}
}

// TestAndroidNetlinkRules installs and removes the rules through real netlink
// in a scratch network namespace. It needs root and is opt-in:
//
//	SHELLSCALED_NETLINK_TEST=1 ./osrouter.test -test.run AndroidNetlink
func TestAndroidNetlinkRules(t *testing.T) {
	if os.Getenv("SHELLSCALED_NETLINK_TEST") != "1" {
		t.Skip("set SHELLSCALED_NETLINK_TEST=1 in a disposable network namespace")
	}
	r, _ := newAndroidCommandRouter(t)
	r.cmd = osCommandRunner{}
	if r.useIPCommand() {
		t.Fatal("netlink path not selected")
	}
	base := r.ipPolicyPrefBase
	owned := func(f int) []netlink.Rule {
		rules, err := netlink.RuleList(f)
		if err != nil {
			t.Fatalf("RuleList: %v", err)
		}
		var out []netlink.Rule
		for _, ru := range rules {
			if ru.Priority >= base+7000 && ru.Priority < base+8000 {
				out = append(out, ru)
			}
		}
		return out
	}
	families := []int{unix.AF_INET, unix.AF_INET6}

	// Upstream's inverted 13001 rule in both families.
	for _, f := range families {
		legacy := androidLegacyIPRules()[0]
		legacy.Family = f
		legacy.Priority += base
		legacy.Goto, legacy.Flow, legacy.SuppressIfgroup, legacy.SuppressPrefixlen = -1, -1, -1, -1
		if err := netlink.RuleAdd(&legacy); err != nil {
			t.Fatalf("add legacy rule: %v", err)
		}
	}
	if err := r.addIPRules(); err != nil {
		t.Fatalf("addIPRules: %v", err)
	}
	// A second start must be idempotent (delete then add).
	if err := r.addIPRules(); err != nil {
		t.Fatalf("second addIPRules: %v", err)
	}
	for _, f := range families {
		got := owned(f)
		var want []netlink.Rule
		for _, ru := range androidIPRules() {
			if ruleMatchesFamily(ru, f) {
				want = append(want, ru)
			}
		}
		for _, ru := range got {
			t.Logf("installed: family %d pref %d dst %v mark %#x/%#x table %d invert %v",
				f, ru.Priority, ru.Dst, ru.Mark, ru.Mask, ru.Table, ru.Invert)
		}
		if len(got) != len(want) {
			t.Errorf("family %d: got %d owned rules, want %d", f, len(got), len(want))
		}
		for _, w := range want {
			if !slices.ContainsFunc(got, func(ru netlink.Rule) bool {
				return !ru.Invert && ru.Priority == w.Priority+base && (ru.Dst == nil) == (w.Dst == nil) &&
					ru.Table == w.Table && max(ru.Mark, 0) == w.Mark && ru.Mask == w.Mask
			}) {
				t.Errorf("family %d: missing rule pref %d dst %v", f, w.Priority+base, w.Dst)
			}
		}
	}
	if err := r.delIPRules(); err != nil {
		t.Fatalf("delIPRules: %v", err)
	}
	for _, f := range families {
		if left := owned(f); len(left) != 0 {
			t.Errorf("family %d: rules left after delIPRules: %+v", f, left)
		}
	}
}

func TestAndroidLegacyRuleCleanup(t *testing.T) {
	legacy := androidLegacyIPRules()
	if len(legacy) != 1 || !legacy[0].Invert || legacy[0].Mark != 0x10000000 || legacy[0].Mask != 0x1e000000 || 5200+legacy[0].Priority != 13001 {
		t.Fatalf("legacy rule shape changed: %+v", legacy)
	}
	if !slices.ContainsFunc(ipRulesToDelete(), func(r netlink.Rule) bool { return r.Invert }) {
		t.Error("legacy catch-all is not deleted on start")
	}
	for _, r := range androidIPRules() {
		// The kernel tells same-priority rules apart by mark and mask when
		// deleting, so the legacy delete never removes a current rule.
		if r.Priority == legacy[0].Priority && r.Mask == legacy[0].Mask {
			t.Errorf("current rule indistinguishable from legacy: %+v", r)
		}
	}
}
