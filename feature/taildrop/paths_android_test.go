// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
)

type androidInboxBackend struct {
	ipnext.SafeBackend
	root string
}

func (b androidInboxBackend) TailscaleVarRoot() string { return b.root }
func (b androidInboxBackend) Clock() tstime.Clock      { return tstime.StdClock{} }

func TestAndroidTaildropUsesProfileInbox(t *testing.T) {
	root := t.TempDir()
	e := &Extension{sb: androidInboxBackend{root: root}, logf: t.Logf}
	e.setPlatformDefaultDirectFileRoot()
	defer e.Shutdown()
	if e.directFileRoot != "" {
		t.Fatal("Android daemon must not select a shared-storage direct root")
	}
	for _, tc := range []struct {
		uid   tailcfg.UserID
		login string
	}{{41, "first@example.test"}, {42, "second@example.test"}} {
		profile := (&ipn.LoginProfile{UserProfile: tailcfg.UserProfile{ID: tc.uid, LoginName: tc.login}}).View()
		e.onChangeProfile(profile, ipn.PrefsView{}, false)
		m := e.manager()
		if m == nil || m.opts.DirectFileMode {
			t.Fatal("initial profile did not create a buffered inbox")
		}
		m.opts.SendFileNotify = func() {} // No IPN host/account in this fixture.
		const payload = "synthetic inbox payload"
		if _, err := m.PutFile("fixture", "received.txt", strings.NewReader(payload), 0, int64(len(payload))); err != nil {
			t.Fatal(err)
		}
		files, err := m.WaitingFiles()
		if err != nil || len(files) != 1 || files[0].Name != "received.txt" || files[0].Size != int64(len(payload)) {
			t.Fatal("completed file was not available through the waiting-files API")
		}
		path, direct := e.fileRoot(tc.uid, tc.login)
		if direct || !strings.HasPrefix(path, filepath.Join(root, "files")+string(os.PathSeparator)) {
			t.Fatal("inbox escaped the daemon state directory")
		}
		if info, err := os.Stat(path); err != nil || info.Mode().Perm()&0077 != 0 {
			t.Fatal("profile inbox is not private")
		}
		if data, err := os.ReadFile(filepath.Join(path, "received.txt")); err != nil || string(data) != payload {
			t.Fatal("profile inbox content changed")
		}
	}
	if files, err := os.ReadDir(filepath.Join(root, "files")); err != nil || len(files) != 2 {
		t.Fatal("profiles did not keep independent inboxes")
	}
}

func TestAndroidExplicitFileOpsRemainDirect(t *testing.T) {
	root, safRoot := t.TempDir(), t.TempDir()
	ops, err := newFileOps(safRoot) // Synthetic SAF-compatible FileOps; no Android provider.
	if err != nil {
		t.Fatal(err)
	}
	e := &Extension{sb: androidInboxBackend{root: root}, logf: t.Logf}
	e.setPlatformDefaultDirectFileRoot()
	e.SetFileOps(ops)
	defer e.Shutdown()
	profile := (&ipn.LoginProfile{UserProfile: tailcfg.UserProfile{ID: 43, LoginName: "saf@example.test"}}).View()
	e.onChangeProfile(profile, ipn.PrefsView{}, false)
	m := e.manager()
	if m == nil || !m.opts.DirectFileMode || m.opts.fileOps != ops {
		t.Fatal("explicit Android FileOps lost direct mode")
	}
	m.opts.SendFileNotify = func() {}
	const payload = "synthetic SAF payload"
	if _, err := m.PutFile("fixture", "received.txt", strings.NewReader(payload), 0, int64(len(payload))); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(safRoot, "received.txt")); err != nil || string(data) != payload {
		t.Fatal("explicit FileOps were not used for delivery")
	}
	if files, err := m.WaitingFiles(); err != nil || len(files) != 0 {
		t.Fatal("direct delivery unexpectedly entered the waiting queue")
	}
	if _, err := os.Stat(filepath.Join(root, "files")); !os.IsNotExist(err) {
		t.Fatal("explicit FileOps also created a private inbox")
	}
}
