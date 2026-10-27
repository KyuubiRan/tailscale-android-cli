// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package netmon

import (
	"encoding/binary"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func androidDeletedRuleMessage(t *testing.T, family, headerTable uint8, attrs ...netlink.Attribute) []byte {
	t.Helper()
	header := make([]byte, 12) // struct fib_rule_hdr
	header[0], header[4] = family, headerTable
	body, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		t.Fatal(err)
	}
	return append(header, body...)
}

func androidRuleU32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}

func TestAndroidDeletedRuleParser(t *testing.T) {
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		for _, table := range []uint32{52, 1017, 1000001017} {
			// netd deletes UID-constrained FIB rules with an eight-byte
			// FRA_UID_RANGE. Treating it as RTA_PREF previously failed here.
			uidRange := append(androidRuleU32(10000), androidRuleU32(19999)...)
			msg := androidDeletedRuleMessage(t, family, 0,
				netlink.Attribute{Type: unix.FRA_UID_RANGE, Data: uidRange},
				netlink.Attribute{Type: unix.FRA_PRIORITY, Data: androidRuleU32(12500)},
				netlink.Attribute{Type: unix.FRA_TABLE, Data: androidRuleU32(table)},
				netlink.Attribute{Type: 255, Data: []byte{1, 2, 3}}, // future attribute
			)
			got, err := parseDeletedRule(msg)
			if err != nil {
				t.Fatalf("family %d table %d: %v", family, table, err)
			}
			if want := (RuleDeleted{Table: table, Priority: 12500}); got != want {
				t.Errorf("family %d got %+v, want %+v", family, got, want)
			}
		}
	}
	// Small table IDs can be encoded entirely in fib_rule_hdr; priority 0
	// need not have an attribute. FRA_TABLE, if present, takes precedence.
	msg := androidDeletedRuleMessage(t, unix.AF_INET6, 52)
	if got, err := parseDeletedRule(msg); err != nil || got != (RuleDeleted{Table: 52}) {
		t.Fatalf("header-only rule = %+v, %v", got, err)
	}
}

func TestAndroidDeletedRuleRejectsMalformedMessages(t *testing.T) {
	for size := 0; size < 12; size++ {
		if _, err := parseDeletedRule(make([]byte, size)); err == nil {
			t.Errorf("accepted %d-byte header", size)
		}
	}
	for _, typ := range []uint16{unix.FRA_PRIORITY, unix.FRA_TABLE} {
		for _, size := range []int{0, 1, 3, 8} {
			msg := androidDeletedRuleMessage(t, unix.AF_INET, 52, netlink.Attribute{Type: typ, Data: make([]byte, size)})
			if _, err := parseDeletedRule(msg); err == nil {
				t.Errorf("accepted attr %d with %d bytes", typ, size)
			}
		}
	}
	msg := androidDeletedRuleMessage(t, unix.AF_INET, 52, netlink.Attribute{Type: unix.FRA_PRIORITY, Data: androidRuleU32(12500)})
	if _, err := parseDeletedRule(msg[:len(msg)-1]); err == nil {
		t.Error("accepted truncated attribute")
	}
}

func TestAndroidRuleMonitorSubscribesBothFamilies(t *testing.T) {
	if linuxNetlinkGroups&unix.RTMGRP_IPV4_RULE == 0 {
		t.Error("IPv4 rule notifications missing")
	}
	if linuxNetlinkGroups&(1<<(unix.RTNLGRP_IPV6_RULE-1)) == 0 {
		t.Error("IPv6 rule notifications missing")
	}
}
