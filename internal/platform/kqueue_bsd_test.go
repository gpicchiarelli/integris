//go:build darwin || freebsd || openbsd || netbsd || dragonfly

package platform_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gpicchiarelli/integris/internal/platform"
)

func TestVNodeWatchWrite(t *testing.T) {
	if !platform.VNodeWatchSupported() {
		t.Fatal("expected kqueue support")
	}
	if platform.VNodeWatchMechanism() != platform.VNodeWatchMechanismKqueue {
		t.Fatalf("mechanism=%q", platform.VNodeWatchMechanism())
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "watched")
	if err := os.WriteFile(path, []byte("seed"), 0o600); err != nil {
		t.Fatal(err)
	}

	w, err := platform.OpenVNodeWatch(path, platform.VNodeNoteWrite)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	errc := make(chan error, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			errc <- err
			return
		}
		_, err = f.Write([]byte("ping"))
		_ = f.Close()
		errc <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ev, err := w.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if ev.Notes&platform.VNodeNoteWrite == 0 {
		t.Fatalf("expected WRITE note, got %#x", ev.Notes)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestVNodeWatchDelete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "doomed")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := platform.OpenVNodeWatch(path, platform.VNodeNoteDelete)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	errc := make(chan error, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		errc <- os.Remove(path)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ev, err := w.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if ev.Notes&platform.VNodeNoteDelete == 0 {
		t.Fatalf("expected DELETE note, got %#x", ev.Notes)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestVNodeWatchRejectsBadArgs(t *testing.T) {
	if _, err := platform.OpenVNodeWatch("", platform.VNodeNoteWrite); err == nil {
		t.Fatal("expected empty path error")
	}
	if _, err := platform.OpenVNodeWatch(t.TempDir(), 0); err == nil {
		t.Fatal("expected zero notes error")
	}
}
