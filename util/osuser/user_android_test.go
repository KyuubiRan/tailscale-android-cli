// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package osuser

import "testing"

func TestAndroidLookupDoesNotFallbackToRoot(t *testing.T) {
	for _, identity := range []string{"", "--help", "__shellscaled_unknown_user__"} {
		if u, _, err := androidLookup(identity, true); err == nil || u != nil {
			t.Errorf("lookup(%q) = %v, %v; want unknown user", identity, u, err)
		}
	}
	u, shell, err := androidLookup("root", true)
	if err != nil {
		t.Fatal(err)
	}
	if u.Uid != "0" || u.Gid != "0" || u.Username != "root" || shell != "/system/bin/sh" {
		t.Fatalf("unexpected root identity: %+v shell=%q", u, shell)
	}
	groups, err := GetGroupIds(u)
	if err != nil || len(groups) == 0 {
		t.Fatalf("root groups = %v, %v", groups, err)
	}
}
