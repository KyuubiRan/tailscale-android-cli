// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package osuser

import (
	"context"
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"
)

func init() { overrideLookupFunc = androidLookup }

// androidLookup resolves exactly the requested identity. Unknown names must
// never fall back to the daemon's root account. Shell commands receive the
// identity as a single argument, with options rejected before invocation.
func androidLookup(identity string, wantShell bool) (*user.User, string, error) {
	if identity == "" || strings.HasPrefix(identity, "-") {
		return nil, "", user.UnknownUserError(identity)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lookup := func(flag string) (string, error) {
		out, err := exec.CommandContext(ctx, "/system/bin/id", flag, identity).Output()
		if err != nil {
			return "", user.UnknownUserError(identity)
		}
		return strings.TrimSpace(string(out)), nil
	}
	uid, err := lookup("-u")
	if err != nil {
		return nil, "", err
	}
	gid, err := lookup("-g")
	if err != nil {
		return nil, "", err
	}
	if _, err := strconv.ParseUint(uid, 10, 32); err != nil {
		return nil, "", fmt.Errorf("invalid Android UID: %w", err)
	}
	if _, err := strconv.ParseUint(gid, 10, 32); err != nil {
		return nil, "", fmt.Errorf("invalid Android GID: %w", err)
	}
	name, err := lookup("-un")
	if err != nil {
		return nil, "", err
	}
	shell := ""
	if wantShell {
		shell = "/system/bin/sh"
	}
	home := "/"
	if uid == "2000" {
		home = "/data/local/tmp"
	}
	return &user.User{Uid: uid, Gid: gid, Username: name, Name: name, HomeDir: home}, shell, nil
}
