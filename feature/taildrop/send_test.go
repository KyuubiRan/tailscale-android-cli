// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/tstime"
	"tailscale.com/util/must"
)

func TestPutFile(t *testing.T) {
	const content = "hello, world"

	tests := []struct {
		name           string
		directFileMode bool
	}{
		{"DirectFileMode", true},
		{"NonDirectFileMode", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			mgr := managerOptions{
				Logf:           t.Logf,
				Clock:          tstime.DefaultClock{},
				State:          nil,
				fileOps:        must.Get(newFileOps(dir)),
				DirectFileMode: tt.directFileMode,
				SendFileNotify: func() {},
			}.New()

			id := clientID("0")
			n, err := mgr.PutFile(id, "file.txt", strings.NewReader(content), 0, int64(len(content)))
			if err != nil {
				t.Fatalf("PutFile error: %v", err)
			}
			if n != int64(len(content)) {
				t.Errorf("wrote %d bytes; want %d", n, len(content))
			}

			path := filepath.Join(dir, "file.txt")

			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile %q: %v", path, err)
			}
			if string(got) != content {
				t.Errorf("file contents = %q; want %q", string(got), content)
			}

			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.Contains(entry.Name(), ".partial") {
					t.Errorf("unexpected partial file left behind: %s", entry.Name())
				}
			}
		})
	}
}

func TestPutFileRetryAfterInterruptedTransfer(t *testing.T) {
	const original = "old-content-with-a-long-suffix"
	for _, tt := range []struct {
		name    string
		offset  int64
		content string
		want    string
	}{
		{"RestartShorter", 0, "new", "new"},
		{"RestartEmpty", 0, "", ""},
		{"ResumeShorter", 4, "new", "old-new"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			mgr := managerOptions{Logf: t.Logf, fileOps: must.Get(newFileOps(dir)), DirectFileMode: true}.New()
			defer mgr.Shutdown()
			id := clientID("retry")
			const name = "retry.txt"
			// A short body represents an interrupted transfer and leaves a partial.
			if _, err := mgr.PutFile(id, name, strings.NewReader(original), 0, int64(len(original)+1)); err == nil {
				t.Fatal("interrupted transfer unexpectedly succeeded")
			}
			n, err := mgr.PutFile(id, name, strings.NewReader(tt.content), tt.offset, int64(len(tt.content)))
			if err != nil || n != int64(len(tt.want)) {
				t.Fatalf("retry = %d, %v; want %d, nil", n, err, len(tt.want))
			}
			got, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil || string(got) != tt.want {
				t.Fatalf("retry contents = %q, %v; want %q", got, err, tt.want)
			}
			mgr.deleter.mu.Lock()
			_, queued := mgr.deleter.byName[name+id.partialSuffix()]
			mgr.deleter.mu.Unlock()
			if queued {
				t.Fatal("resumed partial remained queued for deletion")
			}
		})
	}
}

type countingFileOps struct {
	FileOps
	opens atomic.Int32
}

func (f *countingFileOps) OpenWriter(name string, offset int64, perm os.FileMode) (io.WriteCloser, string, error) {
	f.opens.Add(1)
	return f.FileOps.OpenWriter(name, offset, perm)
}

type pausedReader struct {
	io.Reader
	ready   chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *pausedReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.ready) })
	<-r.release
	return r.Reader.Read(p)
}

func TestPutFileDuplicateDoesNotTouchActiveTransfer(t *testing.T) {
	dir := t.TempDir()
	fs := &countingFileOps{FileOps: must.Get(newFileOps(dir))}
	mgr := managerOptions{Logf: t.Logf, fileOps: fs, DirectFileMode: true}.New()
	t.Cleanup(mgr.Shutdown)
	const prefix, suffix = "active-prefix", "-suffix"
	const name = "active.txt"
	id := clientID("active")
	paused := &pausedReader{Reader: strings.NewReader(suffix), ready: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(paused.release) }) }
	finished := make(chan struct{})
	var transferErr error
	var transferred int64
	go func() {
		defer close(finished)
		transferred, transferErr = mgr.PutFile(id, name, io.MultiReader(strings.NewReader(prefix), paused), 0, int64(len(prefix+suffix)))
	}()
	t.Cleanup(func() { release(); <-finished })
	select {
	case <-paused.ready: // io.Copy has written the complete prefix before reading this reader.
	case <-time.After(5 * time.Second):
		t.Fatal("active transfer did not reach its pause")
	}
	inFile, ok := mgr.incomingFiles.Load(incomingFileKey{id, name})
	if !ok {
		t.Fatal("active transfer is not registered")
	}
	writer := inFile.w
	for _, offset := range []int64{0, 2} {
		if _, err := mgr.PutFile(id, name, strings.NewReader("duplicate"), offset, 9); !errors.Is(err, ErrFileExists) {
			t.Errorf("duplicate at offset %d = %v; want ErrFileExists", offset, err)
		}
	}
	if got := fs.opens.Load(); got != 1 {
		t.Errorf("OpenWriter called %d times; rejected duplicates must not open the file", got)
	}
	if inFile.w != writer {
		t.Error("duplicate replaced the active transfer's writer")
	}
	partial, err := os.ReadFile(filepath.Join(dir, name+id.partialSuffix()))
	if err != nil || string(partial) != prefix {
		t.Errorf("active partial = %q, %v; want %q", partial, err, prefix)
	}
	release()
	<-finished
	if transferErr != nil || transferred != int64(len(prefix+suffix)) {
		t.Fatalf("active transfer = %d, %v", transferred, transferErr)
	}
	got, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil || string(got) != prefix+suffix {
		t.Fatalf("active result = %q, %v; want %q", got, err, prefix+suffix)
	}
}

func TestPutFileOpenFailureReleasesTransfer(t *testing.T) {
	dir := t.TempDir()
	mgr := managerOptions{Logf: t.Logf, fileOps: must.Get(newFileOps(dir)), DirectFileMode: true}.New()
	defer mgr.Shutdown()
	id := clientID("retry")
	const name = "retry.txt"
	if _, err := mgr.PutFile(id, name, strings.NewReader("bad"), -1, 3); err == nil {
		t.Fatal("negative offset unexpectedly accepted")
	}
	if _, ok := mgr.incomingFiles.Load(incomingFileKey{id, name}); ok {
		t.Fatal("OpenWriter failure left the transfer reserved")
	}
	if _, err := mgr.PutFile(id, name, strings.NewReader("good"), 0, 4); err != nil {
		t.Fatalf("retry after OpenWriter failure: %v", err)
	}
}
